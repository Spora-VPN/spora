//! The client of spora-web's device API: registration, the device's status
//! (the force-telemetry flag), and telemetry upload.
//!
//! Blocking (ureq), so it runs on the uploader's own thread under any caller
//! — FFI, CLI — without a tokio runtime. TLS is rustls with the ring
//! provider and the webpki-roots trust anchors. Several base URLs may be
//! configured (fronts of one API): a request moves to the next on a
//! connection failure, a 5xx or a redirect, and the client stays with
//! whichever answered last. These sockets are not protected from a VPN on
//! purpose: with a tunnel up, uploads ride it.
//!
//! Connections go straight to the API: no proxy from the environment
//! (`HTTPS_PROXY`, `ALL_PROXY`), like every other connection Spora makes, so
//! a stale or SOCKS-only proxy setting cannot silently break uploads.
//! Redirects are not followed: the API never redirects, and following one
//! would drop the `Authorization` header (and turn a POST into a GET), so a
//! 3xx is treated as this base not working.
//!
//! An API is one of two kinds. The **built-in** API is what a configuration
//! that names no bases gets: Spora's own, at whatever fronts the running
//! release lists for it ([`DEFAULT_API_BASES`]), which may change from one
//! release to the next while the API stays the same. An **override** is an
//! explicit list of bases (`SPORA_API`, the CLI's `--api`, an app's
//! configured bases), and is that list and nothing else, even when it names
//! a built-in front.
//!
//! The device token goes into the `Authorization` header and nowhere else —
//! not into errors, not into logs — and only to its own API: a device
//! registered with the built-in API to any front of the running release's
//! built-in list (so fronts can be added or swapped with no new registration
//! and nothing sent twice), one registered with an override only to the
//! bases that minted it ([`Device::api_bases`]). Neither ever goes to the
//! other kind.

use std::fmt;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Deserialize;
use ureq::http;

use crate::state::Device;

/// Where the API lives unless configured otherwise.
pub const DEFAULT_API_BASES: &[&str] = &["https://truecdn.net"];

/// The `platform` values the API registers devices for.
pub const PLATFORMS: &[&str] = &["android", "ios", "macos", "windows", "linux"];

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Responses are a few bytes of JSON; anything larger is not ours (an error
/// answer is cut here, its status kept).
const MAX_RESPONSE: u64 = 64 * 1024;
/// The registry's `app_version` column.
const MAX_APP_VERSION: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// 401: the token is unknown or revoked.
    Unauthorized,
    /// Any other non-success status, with the body's `error` code if any and
    /// the `Retry-After` the server asked for (seconds form only).
    Status {
        status: u16,
        code: Option<String>,
        retry_after: Option<Duration>,
    },
    /// No HTTP answer at all: DNS, connect, TLS, timeout.
    Transport(String),
    /// An answer that is not what the protocol says.
    BadResponse(String),
}

impl ApiError {
    /// Worth trying another base URL for.
    fn fails_over(&self) -> bool {
        match self {
            ApiError::Transport(_) => true,
            ApiError::Status { status, .. } => *status >= 500 || (300..400).contains(status),
            _ => false,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Unauthorized => f.write_str("http 401 (device not recognised)"),
            ApiError::Status {
                status,
                code: Some(code),
                ..
            } => write!(f, "http {status} ({code})"),
            ApiError::Status {
                status, code: None, ..
            } => write!(f, "http {status}"),
            ApiError::Transport(e) => write!(f, "no answer: {e}"),
            ApiError::BadResponse(e) => write!(f, "unexpected answer: {e}"),
        }
    }
}

impl std::error::Error for ApiError {}

/// `GET /v1/devices/me`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStatus {
    pub device: String,
    /// `None` when the server did not say.
    pub telemetry_required: Option<bool>,
}

/// `POST /v1/telemetry/upload`: what the server now holds of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadAck {
    /// Bytes of the file the server has committed.
    pub length: u64,
    /// Bytes this request added.
    pub accepted: u64,
    pub telemetry_required: Option<bool>,
}

/// `GET /v1/relays`: the relays to write into new shares, and the device's
/// relay token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAnswer {
    pub relays: Vec<crate::state::AdvisedRelay>,
    /// `None`: the device is not entitled to a token.
    pub token: Option<RelayTokenAnswer>,
}

/// The relay token as the API hands it out. `Debug` leaves the value out.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayTokenAnswer {
    /// base64url, unpadded: opaque bytes for the relays.
    pub value: String,
    /// The device it names (hex cert hash).
    pub subject: String,
    pub expires_unix_ms: u64,
    pub renew_after_unix_ms: u64,
}

impl fmt::Debug for RelayTokenAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayTokenAnswer")
            .field("value", &"<redacted>")
            .field("subject", &self.subject)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .field("renew_after_unix_ms", &self.renew_after_unix_ms)
            .finish()
    }
}

#[derive(Deserialize)]
struct RelaysBody {
    relays: Vec<RelayBody>,
    #[serde(default)]
    token: Option<TokenBody>,
}

#[derive(Deserialize)]
struct RelayBody {
    protocol: String,
    host: String,
    port: u16,
}

#[derive(Deserialize)]
struct TokenBody {
    value: String,
    subject: String,
    expires_at: String,
    renew_after: String,
}

#[derive(Deserialize)]
struct RegisteredBody {
    device: String,
    token: String,
}

#[derive(Deserialize)]
struct MeBody {
    device: String,
    #[serde(default)]
    telemetry_required: Option<bool>,
}

#[derive(Deserialize)]
struct UploadBody {
    length: u64,
    #[serde(default)]
    accepted: u64,
    #[serde(default)]
    telemetry_required: Option<bool>,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

pub struct Api {
    agent: ureq::Agent,
    bases: Vec<String>,
    /// The built-in API (the configuration named no bases), at `bases`.
    builtin: bool,
    current: AtomicUsize,
    app_version: String,
}

enum Payload<'a> {
    None,
    Json(Vec<u8>),
    /// Request bytes, gzip-compressed when that makes them smaller.
    Octets(&'a [u8]),
}

/// An HTTP answer, whatever its status.
struct Answer {
    status: u16,
    /// At most [`MAX_RESPONSE`] bytes of it, decoded lossily.
    text: String,
    /// The body went past [`MAX_RESPONSE`].
    cut: bool,
    retry_after: Option<Duration>,
}

impl Api {
    /// `bases` empty means the built-in API, at [`DEFAULT_API_BASES`]; any
    /// other list is an override, even one naming those same bases. Each
    /// must be an `http://` or `https://` URL with a host and nothing after
    /// the path (plain HTTP only ever when someone configured it: tests, a
    /// local development server).
    pub fn new(bases: &[String], app_version: &str) -> Result<Api, String> {
        if bases.is_empty() {
            let builtin: Vec<String> = DEFAULT_API_BASES.iter().map(|b| b.to_string()).collect();
            return Api::build(builtin, true, app_version);
        }
        Api::build(
            bases.iter().map(|b| normalize_base(b)).collect(),
            false,
            app_version,
        )
    }

    /// The built-in API of a release whose built-in list is `bases`: what
    /// [`Api::new`] makes of an empty list, for tests, which must never
    /// reach the real one.
    #[cfg(test)]
    pub(crate) fn builtin(bases: &[String], app_version: &str) -> Result<Api, String> {
        Api::build(
            bases.iter().map(|b| normalize_base(b)).collect(),
            true,
            app_version,
        )
    }

    fn build(bases: Vec<String>, builtin: bool, app_version: &str) -> Result<Api, String> {
        if bases.is_empty() {
            return Err("no API base".into());
        }
        for b in &bases {
            check_base(b)?;
        }
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::WebPki)
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(REQUEST_TIMEOUT))
            .tls_config(tls)
            .build()
            .into();
        Ok(Api {
            agent,
            bases,
            builtin,
            current: AtomicUsize::new(0),
            app_version: app_version.to_string(),
        })
    }

    /// The base URL requests start from (the last one that answered).
    pub fn current_base(&self) -> &str {
        &self.bases[self.current.load(Ordering::Relaxed) % self.bases.len()]
    }

    /// The base URLs requests go to, normalized as [`Device::api_bases`]
    /// keeps them: the running release's built-in list for the built-in
    /// API.
    pub fn bases(&self) -> &[String] {
        &self.bases
    }

    /// The built-in API: the configuration named no bases.
    pub fn is_builtin(&self) -> bool {
        self.builtin
    }

    /// The API as a log line or a message names it: `the built-in API
    /// (<bases>)`, or an override's bases.
    pub fn describe(&self) -> String {
        if self.builtin {
            format!("the built-in API ({})", self.bases.join(", "))
        } else {
            self.bases.join(", ")
        }
    }

    /// The device was registered with this API, and its token may go to it:
    /// a built-in API serves the devices registered with the built-in API,
    /// whichever fronts they registered at; an override serves those
    /// registered with an override that shares a base with it. (A device
    /// registered before devices remembered their bases goes nowhere.)
    pub fn serves(&self, dev: &Device) -> bool {
        self.bases.iter().any(|b| self.may_send(dev, b))
    }

    /// `dev`'s token may go to `base`, one of this API's bases.
    fn may_send(&self, dev: &Device, base: &str) -> bool {
        match (self.builtin, dev.builtin) {
            (true, true) => true,
            (false, false) => dev.api_bases.iter().any(|b| b == base),
            _ => false,
        }
    }

    /// `POST /v1/devices`, naming the device's cert hash (hex), which the
    /// server keeps for good: the relay tokens it mints name it. The device
    /// belongs to this API: the built-in one, or this override's bases.
    pub fn register(&self, platform: &str, cert_hash: &str) -> Result<Device, ApiError> {
        let mut version = self.app_version.clone();
        crate::diag::cut_at(&mut version, MAX_APP_VERSION);
        let body = serde_json::to_vec(&serde_json::json!({
            "platform": platform,
            "app_version": version,
            "cert_hash": cert_hash,
        }))
        .map_err(|e| ApiError::BadResponse(e.to_string()))?;
        let a = self.request("POST", "/v1/devices", None, Payload::Json(body))?;
        if a.status != 200 && a.status != 201 {
            return Err(status_error(&a));
        }
        let r: RegisteredBody = parse(&a)?;
        if r.token.is_empty() {
            return Err(ApiError::BadResponse("empty token".into()));
        }
        Ok(Device {
            id: r.device,
            token: r.token,
            api_bases: self.bases.clone(),
            builtin: self.builtin,
            extra: serde_json::Map::new(),
        })
    }

    /// `GET /v1/devices/me`.
    pub fn me(&self, dev: &Device) -> Result<DeviceStatus, ApiError> {
        let a = self.request("GET", "/v1/devices/me", Some(dev), Payload::None)?;
        if a.status != 200 {
            return Err(status_error(&a));
        }
        let me: MeBody = parse(&a)?;
        Ok(DeviceStatus {
            device: me.device,
            telemetry_required: me.telemetry_required,
        })
    }

    /// `GET /v1/relays`: the relays this device is to write into new shares,
    /// and a freshly minted relay token (`null` when the device is not
    /// entitled to one). Endpoints of a protocol this build does not know
    /// are left out; timestamps are ISO 8601.
    pub fn relays(&self, dev: &Device) -> Result<RelayAnswer, ApiError> {
        let a = self.request("GET", "/v1/relays", Some(dev), Payload::None)?;
        if a.status != 200 {
            return Err(status_error(&a));
        }
        let b: RelaysBody = parse(&a)?;
        let relays = b
            .relays
            .into_iter()
            .filter(|r| matches!(r.protocol.as_str(), "quic" | "nz" | "tcptls"))
            .map(|r| crate::state::AdvisedRelay {
                protocol: r.protocol,
                host: r.host,
                port: r.port,
            })
            .collect();
        let token = match b.token {
            None => None,
            Some(t) => {
                let when = |s: &str, what: &str| {
                    crate::time::parse_iso_ms(s)
                        .ok_or_else(|| ApiError::BadResponse(format!("token {what}: {s:?}")))
                };
                if t.value.is_empty() {
                    return Err(ApiError::BadResponse("empty relay token".into()));
                }
                Some(RelayTokenAnswer {
                    expires_unix_ms: when(&t.expires_at, "expires_at")?,
                    renew_after_unix_ms: when(&t.renew_after, "renew_after")?,
                    value: t.value,
                    subject: t.subject,
                })
            }
        };
        Ok(RelayAnswer { relays, token })
    }

    /// `POST /v1/telemetry/upload`: `data` is the file's bytes from `offset`.
    pub fn upload(
        &self,
        dev: &Device,
        stream: &str,
        file: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<UploadAck, ApiError> {
        let path = format!("/v1/telemetry/upload?stream={stream}&file={file}&offset={offset}");
        let a = self.request("POST", &path, Some(dev), Payload::Octets(data))?;
        if a.status != 200 {
            return Err(status_error(&a));
        }
        let b: UploadBody = parse(&a)?;
        Ok(UploadAck {
            length: b.length,
            accepted: b.accepted,
            telemetry_required: b.telemetry_required,
        })
    }

    /// One request, tried against each base in turn from the current one —
    /// with a device, only against the bases its token may go to
    /// ([`Api::serves`]). Returns the first answer that is not a 5xx or a
    /// redirect (or the last failure). A 401 becomes
    /// [`ApiError::Unauthorized`].
    fn request(
        &self,
        method: &str,
        path: &str,
        auth: Option<&Device>,
        payload: Payload<'_>,
    ) -> Result<Answer, ApiError> {
        let (body, content_type, encoding) = match payload {
            Payload::None => (Vec::new(), None, None),
            Payload::Json(b) => (b, Some("application/json"), None),
            Payload::Octets(data) => match gzip(data) {
                Some(gz) if gz.len() < data.len() => {
                    (gz, Some("application/octet-stream"), Some("gzip"))
                }
                _ => (data.to_vec(), Some("application/octet-stream"), None),
            },
        };
        let start = self.current.load(Ordering::Relaxed);
        let mut last = ApiError::Transport("no API base this device's token may go to".into());
        for i in 0..self.bases.len() {
            let idx = (start + i) % self.bases.len();
            let base = &self.bases[idx];
            if auth.is_some_and(|d| !self.may_send(d, base)) {
                continue;
            }
            let url = format!("{base}{path}");
            let mut req = http::Request::builder()
                .method(method)
                .uri(&url)
                .header("X-App-Version", &self.app_version);
            if let Some(d) = auth {
                req = req.header("Authorization", format!("Bearer {}", d.token));
            }
            if let Some(ct) = content_type {
                req = req.header("Content-Type", ct);
            }
            if let Some(enc) = encoding {
                req = req.header("Content-Encoding", enc);
            }
            let outcome = match req.body(body.clone()) {
                Ok(r) => match self.send(r) {
                    Ok(a) if a.status == 401 => Err(ApiError::Unauthorized),
                    Ok(a) if a.status >= 500 || (300..400).contains(&a.status) => {
                        Err(status_error(&a))
                    }
                    other => other,
                },
                // Checked in `new`; should a base still not make a request,
                // the next one may.
                Err(e) => Err(ApiError::Transport(format!("building the request: {e}"))),
            };
            match outcome {
                Err(e) if e.fails_over() => {
                    log::debug!("api: {method} {base} failed ({e})");
                    last = e;
                }
                other => {
                    self.current.store(idx, Ordering::Relaxed);
                    return other;
                }
            }
        }
        Err(last)
    }

    fn send(&self, req: http::Request<Vec<u8>>) -> Result<Answer, ApiError> {
        let mut resp = self
            .agent
            .run(req)
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        if (300..400).contains(&status) {
            log::debug!(
                "api: answered {status}, to {}; redirects are not followed",
                header("location").as_deref().unwrap_or("nowhere")
            );
        }
        let retry_after = header("retry-after")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        // The status is the answer; a body too large or not UTF-8 must not
        // turn it into "no answer".
        let mut buf = Vec::new();
        let read = resp
            .body_mut()
            .as_reader()
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut buf);
        if let Err(e) = read
            && (200..300).contains(&status)
        {
            return Err(ApiError::Transport(format!("reading the answer: {e}")));
        }
        let cut = buf.len() as u64 > MAX_RESPONSE;
        buf.truncate(MAX_RESPONSE as usize);
        Ok(Answer {
            status,
            text: String::from_utf8_lossy(&buf).into_owned(),
            cut,
            retry_after,
        })
    }
}

/// As [`Api`] keeps a base: no surrounding space, no trailing slash.
pub(crate) fn normalize_base(b: &str) -> String {
    b.trim().trim_end_matches('/').to_string()
}

fn check_base(b: &str) -> Result<(), String> {
    let bad = || format!("not an http(s) URL: {b:?}");
    // A fragment would swallow every request path appended to the base. A
    // base is ASCII: anything else is a typo or a mangled environment (a
    // non-UTF-8 `SPORA_API` arrives with U+FFFD for each bad byte), and
    // `http` takes UTF-8 in a path.
    if !(b.starts_with("https://") || b.starts_with("http://")) || b.contains('#') || !b.is_ascii()
    {
        return Err(bad());
    }
    let uri: http::Uri = format!("{b}/v1/devices").parse().map_err(|_| bad())?;
    if uri.authority().is_none_or(|a| a.host().is_empty()) || uri.query().is_some() {
        return Err(bad());
    }
    Ok(())
}

fn gzip(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::with_capacity(data.len() / 4), Compression::default());
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

fn status_error(a: &Answer) -> ApiError {
    if a.status == 401 {
        return ApiError::Unauthorized;
    }
    let code = serde_json::from_str::<ErrorBody>(&a.text)
        .ok()
        .map(|b| b.error)
        .filter(|c| c.len() <= 64);
    ApiError::Status {
        status: a.status,
        code,
        retry_after: a.retry_after,
    }
}

fn parse<T: for<'de> Deserialize<'de>>(a: &Answer) -> Result<T, ApiError> {
    if a.cut {
        return Err(ApiError::BadResponse(format!(
            "an answer over {MAX_RESPONSE} bytes"
        )));
    }
    serde_json::from_str(&a.text).map_err(|e| ApiError::BadResponse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, text: &str) -> Answer {
        Answer {
            status,
            text: text.into(),
            cut: false,
            retry_after: None,
        }
    }

    #[test]
    fn bases_are_validated_and_normalised() {
        assert!(Api::new(&["truecdn.net".into()], "1").is_err());
        assert!(Api::new(&["ftp://x".into()], "1").is_err());
        assert!(Api::new(&["https://".into()], "1").is_err());
        assert!(Api::new(&["https://bad host.example".into()], "1").is_err());
        assert!(Api::new(&["https://x.example?a=1".into()], "1").is_err());
        assert!(Api::new(&["https://x.example#a".into()], "1").is_err());
        assert!(Api::new(&["https://x.example/\u{fffd}".into()], "1").is_err());
        assert!(Api::new(&["https://x.example/api".into()], "1").is_ok());
        let api = Api::new(&["http://api.localhost:8000/".into()], "1").unwrap();
        assert_eq!(api.current_base(), "http://api.localhost:8000");
        // Nothing configured is the built-in API; its own address configured
        // is an override. (Building one touches no network.)
        let api = Api::new(&[], "1").unwrap();
        assert_eq!(api.current_base(), DEFAULT_API_BASES[0]);
        assert!(api.is_builtin());
        let same = Api::new(&[format!("{}/", DEFAULT_API_BASES[0])], "1").unwrap();
        assert_eq!(same.bases(), api.bases());
        assert!(!same.is_builtin());
        assert!(Api::builtin(&[], "1").is_err());
    }

    fn dev(builtin: bool, bases: &[&str]) -> Device {
        Device {
            id: "d".into(),
            token: "t".into(),
            api_bases: bases.iter().map(|b| b.to_string()).collect(),
            builtin,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn an_override_serves_the_override_devices_of_its_bases() {
        let api = Api::new(
            &["https://a.example/".into(), "https://b.example".into()],
            "1",
        )
        .unwrap();
        let mut d = dev(false, &["https://b.example", "https://c.example"]);
        assert!(api.serves(&d));
        assert!(!api.may_send(&d, "https://a.example"));
        assert!(api.may_send(&d, "https://b.example"));
        d.api_bases = vec!["https://c.example".into()];
        assert!(!api.serves(&d));
        d.api_bases.clear();
        assert!(!api.serves(&d));
        // A built-in registration is no override's, whatever its bases.
        let b = dev(true, &["https://a.example", "https://b.example"]);
        assert!(!api.serves(&b));
        assert!(!api.may_send(&b, "https://a.example"));
    }

    #[test]
    fn the_builtin_api_serves_its_devices_at_every_front() {
        let fronts = [
            "https://new.example".to_string(),
            "https://b.example".into(),
        ];
        let api = Api::builtin(&fronts, "1").unwrap();
        assert!(api.is_builtin());
        // Registered when the release listed other fronts: still its own,
        // and its token goes to each of today's.
        let b = dev(true, &["https://old.example"]);
        assert!(api.serves(&b));
        assert!(fronts.iter().all(|f| api.may_send(&b, f)));
        assert!(api.serves(&dev(true, &[])));
        // An override's registration is never the built-in API's, not even
        // one that named the built-in fronts.
        let o = dev(false, &["https://new.example", "https://b.example"]);
        assert!(!api.serves(&o));
        assert!(fronts.iter().all(|f| !api.may_send(&o, f)));
    }

    #[test]
    fn errors_never_carry_the_token() {
        let e = status_error(&answer(400, r#"{"error":"misaligned"}"#));
        assert_eq!(e.to_string(), "http 400 (misaligned)");
        assert_eq!(status_error(&answer(401, "")), ApiError::Unauthorized);
        assert_eq!(status_error(&answer(502, "<html>")).to_string(), "http 502");
    }

    #[test]
    fn redirects_and_server_errors_fail_over() {
        let s = |status| ApiError::Status {
            status,
            code: None,
            retry_after: None,
        };
        assert!(s(301).fails_over() && s(308).fails_over() && s(503).fails_over());
        assert!(!s(400).fails_over() && !s(404).fails_over() && !s(429).fails_over());
        assert!(!ApiError::Unauthorized.fails_over());
    }
}
