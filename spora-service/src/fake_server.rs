//! An in-process stand-in for spora-web's device and telemetry API on
//! 127.0.0.1, implementing the server rules of the upload protocol
//! (validation, size limits, the line cap of record and log bodies, gzip
//! with a hard cap, the three offset cases, line alignment) with the
//! server's statuses and error codes, so the uploader is tested against the
//! contract rather than against itself. The server's daily quota and its
//! spool's disk guards are left out: a test asks for those answers itself
//! (`fail_next`, `canned`).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

const MAX_RAW: usize = 1024 * 1024;
const MAX_DECODED: usize = 1024 * 1024;
/// Lines in a record or log body (a crash body has no cap).
const MAX_LINES: usize = 20_000;

#[derive(Debug, Clone)]
pub(crate) struct Req {
    /// The base URL of the front it arrived at ([`FakeServer::another_front`]).
    pub(crate) front: String,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: BTreeMap<String, String>,
    pub(crate) gzip: bool,
    pub(crate) app_version: Option<String>,
    pub(crate) authorized: bool,
    /// The bearer token, if any.
    pub(crate) token: Option<String>,
    pub(crate) raw_len: usize,
    pub(crate) status: u16,
    pub(crate) accepted: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct FakeDevice {
    pub(crate) id: String,
    pub(crate) platform: String,
    pub(crate) revoked: bool,
    /// The cert hash it registered with (hex).
    pub(crate) cert_hash: String,
}

/// An answer given as is, whatever the request.
#[derive(Debug, Clone)]
pub(crate) struct Canned {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

/// Called with each request before it is answered (outside the state lock).
pub(crate) type Hook = Box<dyn FnMut(&Req) + Send>;

#[derive(Default)]
pub(crate) struct FakeState {
    /// By token.
    pub(crate) devices: BTreeMap<String, FakeDevice>,
    /// Committed bytes by (device id, stream, file).
    pub(crate) files: BTreeMap<(String, String, String), Vec<u8>>,
    pub(crate) requests: Vec<Req>,
    /// Statuses to answer the next requests with, regardless of content.
    pub(crate) fail_next: Vec<u16>,
    /// From the request with this index on, answer with this status.
    pub(crate) fail_from: Option<(usize, u16)>,
    /// Answers to give the next requests, before anything else.
    pub(crate) canned: Vec<Canned>,
    /// Answer every request for this path with this status and error code.
    pub(crate) path_status: BTreeMap<String, (u16, String)>,
    pub(crate) on_request: Option<Hook>,
    pub(crate) required: bool,
    /// What `GET /v1/relays` hands out: endpoints as `(protocol, host, port)`.
    pub(crate) relays: Vec<(String, String, u16)>,
    /// Whether devices are entitled to a relay token.
    pub(crate) no_token: bool,
    /// The relay tokens minted so far (`value` of each answer).
    pub(crate) minted: Vec<String>,
    next: u32,
}

pub(crate) struct FakeServer {
    addr: SocketAddr,
    state: Arc<Mutex<FakeState>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FakeServer {
    pub(crate) fn start() -> FakeServer {
        FakeServer::listen(Arc::new(Mutex::new(FakeState::default())))
    }

    /// Another address for the same server (its devices, files, requests
    /// and settings): a second front of one API. Dropping either front
    /// closes its own address only.
    pub(crate) fn another_front(&self) -> FakeServer {
        FakeServer::listen(self.state.clone())
    }

    fn listen(state: Arc<Mutex<FakeState>>) -> FakeServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (st, sp) = (state.clone(), stop.clone());
        let front = format!("http://{addr}");
        let handle = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if sp.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(c) = conn {
                    let _ = serve(c, &st, &front);
                }
            }
        });
        FakeServer {
            addr,
            state,
            stop,
            handle: Some(handle),
        }
    }

    pub(crate) fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    pub(crate) fn stored(&self, device: &str, stream: &str, file: &str) -> Vec<u8> {
        self.state()
            .files
            .get(&(device.into(), stream.into(), file.into()))
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn set_stored(&self, device: &str, stream: &str, file: &str, bytes: &[u8]) {
        self.state()
            .files
            .insert((device.into(), stream.into(), file.into()), bytes.to_vec());
    }

    pub(crate) fn uploads(&self) -> Vec<Req> {
        self.state()
            .requests
            .iter()
            .filter(|r| r.path == "/v1/telemetry/upload")
            .cloned()
            .collect()
    }

    pub(crate) fn requests(&self) -> Vec<Req> {
        self.state().requests.clone()
    }

    pub(crate) fn revoke_all(&self) {
        for d in self.state().devices.values_mut() {
            d.revoked = true;
        }
    }

    pub(crate) fn set_required(&self, required: bool) {
        self.state().required = required;
    }

    /// A device the server knows, as if registered: its token.
    pub(crate) fn add_device(&self, id: &str) -> String {
        let token = format!("tok-{id}-{}", "s".repeat(40));
        self.state().devices.insert(
            token.clone(),
            FakeDevice {
                id: id.into(),
                platform: "linux".into(),
                revoked: false,
                cert_hash: "00".repeat(20),
            },
        );
        token
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn serve(mut conn: TcpStream, state: &Mutex<FakeState>, front: &str) -> std::io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h)?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let mut body = Vec::new();
    if let Some(n) = headers.get("content-length") {
        let n: usize = n.parse().unwrap_or(0);
        body.resize(n, 0);
        reader.read_exact(&mut body)?;
    } else if headers
        .get("transfer-encoding")
        .is_some_and(|t| t.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size)?;
            let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            let mut chunk = vec![0; n + 2];
            reader.read_exact(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (target.clone(), BTreeMap::new()),
    };
    let mut req = Req {
        front: front.to_string(),
        method: method.clone(),
        path: path.clone(),
        query,
        gzip: headers
            .get("content-encoding")
            .is_some_and(|e| e.eq_ignore_ascii_case("gzip")),
        app_version: headers.get("x-app-version").cloned(),
        authorized: headers.contains_key("authorization"),
        token: headers
            .get("authorization")
            .and_then(|a| a.strip_prefix("Bearer "))
            .map(str::to_string),
        raw_len: body.len(),
        status: 0,
        accepted: 0,
    };
    let hook = state.lock().unwrap().on_request.take();
    if let Some(mut h) = hook {
        h(&req);
        state.lock().unwrap().on_request.get_or_insert(h);
    }
    let answer = {
        let mut st = state.lock().unwrap();
        let failing = st.fail_from.filter(|(n, _)| st.requests.len() >= *n);
        let json = |(status, v): (u16, serde_json::Value)| Canned {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: v.to_string().into_bytes(),
        };
        let answer = if !st.canned.is_empty() {
            st.canned.remove(0)
        } else if let Some((_, s)) = failing {
            json(err(s, "server_error"))
        } else if let Some((s, code)) = st.path_status.get(&req.path).cloned() {
            json(err(s, &code))
        } else if st.fail_next.is_empty() {
            json(route(&mut st, &mut req, &headers, &body))
        } else {
            let s = st.fail_next.remove(0);
            json(err(s, "server_error"))
        };
        req.status = answer.status;
        st.requests.push(req);
        answer
    };
    write!(conn, "HTTP/1.1 {} X\r\n", answer.status)?;
    for (k, v) in &answer.headers {
        write!(conn, "{k}: {v}\r\n")?;
    }
    write!(
        conn,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        answer.body.len()
    )?;
    conn.write_all(&answer.body)?;
    conn.flush()
}

fn parse_query(q: &str) -> BTreeMap<String, String> {
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn err(status: u16, code: &str) -> (u16, serde_json::Value) {
    (status, serde_json::json!({ "error": code }))
}

fn device(st: &FakeState, headers: &BTreeMap<String, String>) -> Option<FakeDevice> {
    let token = headers.get("authorization")?.strip_prefix("Bearer ")?;
    st.devices.get(token).filter(|d| !d.revoked).cloned()
}

fn valid_file(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn route(
    st: &mut FakeState,
    req: &mut Req,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> (u16, serde_json::Value) {
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/v1/devices") => {
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
                return err(400, "invalid");
            };
            let platform = v["platform"].as_str().unwrap_or("");
            let version = v["app_version"].as_str().unwrap_or("");
            let cert_hash = v["cert_hash"].as_str().unwrap_or("");
            if !["android", "ios", "macos", "windows", "linux"].contains(&platform)
                || version.is_empty()
                || version.len() > 32
                || cert_hash.len() != 40
                || !cert_hash.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return err(400, "invalid");
            }
            st.next += 1;
            let id = format!("00000000-0000-4000-8000-{:012}", st.next);
            // Unique across servers: a test tells one server's token from
            // another's.
            static TOKENS: AtomicU32 = AtomicU32::new(0);
            let n = TOKENS.fetch_add(1, Ordering::Relaxed);
            let token = format!("tok{n}x{}", "s".repeat(40));
            st.devices.insert(
                token.clone(),
                FakeDevice {
                    id: id.clone(),
                    platform: platform.into(),
                    revoked: false,
                    cert_hash: cert_hash.to_ascii_lowercase(),
                },
            );
            (201, serde_json::json!({ "device": id, "token": token }))
        }
        ("GET", "/v1/relays") => match device(st, headers) {
            Some(d) => {
                let relays: Vec<_> = st
                    .relays
                    .iter()
                    .map(|(p, h, port)| serde_json::json!({"protocol": p, "host": h, "port": port}))
                    .collect();
                let token = if st.no_token {
                    serde_json::Value::Null
                } else {
                    // Opaque bytes to the client: unique per answer, naming
                    // the device.
                    let value = format!("relay-token-{}-{}", d.cert_hash, st.minted.len());
                    let b64 = {
                        use base64::Engine;
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
                    };
                    st.minted.push(b64.clone());
                    serde_json::json!({
                        "value": b64,
                        "subject": d.cert_hash,
                        "expires_at": "2999-01-01T00:00:00Z",
                        "renew_after": "2998-01-01T00:00:00Z",
                    })
                };
                (200, serde_json::json!({ "relays": relays, "token": token }))
            }
            None => err(401, "not_authenticated"),
        },
        ("GET", "/v1/devices/me") => match device(st, headers) {
            Some(d) => (
                200,
                serde_json::json!({ "device": d.id, "telemetry_required": st.required }),
            ),
            None => err(401, "not_authenticated"),
        },
        ("POST", "/v1/telemetry/upload") => {
            let Some(dev) = device(st, headers) else {
                return err(401, "not_authenticated");
            };
            let stream = req.query.get("stream").cloned().unwrap_or_default();
            let file = req.query.get("file").cloned().unwrap_or_default();
            let offset = req.query.get("offset").and_then(|o| o.parse::<u64>().ok());
            let Some(offset) = offset else {
                return err(400, "invalid");
            };
            if !["record", "log", "crash"].contains(&stream.as_str()) || !valid_file(&file) {
                return err(400, "invalid");
            }
            if body.len() > MAX_RAW {
                return err(413, "too_large");
            }
            let data = if req.gzip {
                let mut d = Vec::new();
                let mut dec = flate2::read::GzDecoder::new(body).take(MAX_DECODED as u64 + 1);
                if dec.read_to_end(&mut d).is_err() {
                    return err(400, "parse_error");
                }
                if d.len() > MAX_DECODED {
                    return err(413, "too_large");
                }
                d
            } else if headers
                .get("content-encoding")
                .is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity"))
            {
                return err(415, "unsupported_media_type");
            } else {
                body.to_vec()
            };
            if data.is_empty() || data.last() != Some(&b'\n') {
                return err(400, "invalid");
            }
            if stream != "crash" && data.iter().filter(|&&b| b == b'\n').count() > MAX_LINES {
                return err(413, "too_large");
            }
            let key = (dev.id.clone(), stream, file);
            let stored = st.files.entry(key).or_default();
            let l = stored.len() as u64;
            let n = data.len() as u64;
            let mut accepted = 0;
            if offset <= l && l < offset + n {
                let skip = (l - offset) as usize;
                if skip > 0 && data[skip - 1] != b'\n' {
                    return err(400, "misaligned");
                }
                stored.extend_from_slice(&data[skip..]);
                accepted = n - skip as u64;
            }
            let length = stored.len() as u64;
            req.accepted = accepted;
            (
                200,
                serde_json::json!({
                    "length": length,
                    "accepted": accepted,
                    "telemetry_required": st.required,
                }),
            )
        }
        _ => err(404, "not_found"),
    }
}
