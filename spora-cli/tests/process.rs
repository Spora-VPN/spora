//! The `spora` binary as a process: how `share` and `use` end (on every stop
//! signal, mid-dial, on a local failure) and what they send as they stop,
//! that a closed stdout does not kill them, that no log output carries the
//! upload token, what `telemetry off` and unreadable directories make of
//! their errors, and where a run with sudo keeps its state. Nothing here
//! leaves the machine: the API is a fake on loopback, the relay a closed
//! local port (or the share a direct endpoint on loopback), and every run
//! that writes gets a scratch state and config directory of its own.
#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// The bearer token seeded into the state: any six characters of it in a
/// log would be a leak.
const TOKEN: &str = "tKn7Qz9VwX2pLm4RbY8sDf3GhJ6cNa5e";
/// The token the fake API issues to a device registering with it.
const MINTED: &str = "mNt4Wq8ZrT2yVb6XcK9pLd3FhG7sJa5u";
/// A closed local port: the relay of every share here, and the API of runs
/// that must not reach one.
const NOWHERE: &str = "127.0.0.1:9";

/// One request the fake API answered.
struct Seen {
    at: Instant,
    method: String,
    path: String,
    auth: Option<String>,
}

/// Just enough of the telemetry API for a device: registration (always as
/// `dev-2`, token [`MINTED`]), `/me` and uploads, every request recorded.
struct FakeApi {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakeApi {
    fn start() -> FakeApi {
        FakeApi::serving(false)
    }

    /// A server that no longer knows the device: `/me` answers 401.
    fn revoked() -> FakeApi {
        FakeApi::serving(true)
    }

    fn serving(revoked: bool) -> FakeApi {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake API");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let log = log.clone();
                std::thread::spawn(move || serve(conn, &log, revoked));
            }
        });
        FakeApi { base, seen }
    }

    fn requests(&self) -> Vec<(Instant, String, String, Option<String>)> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| (s.at, s.method.clone(), s.path.clone(), s.auth.clone()))
            .collect()
    }
}

/// HTTP/1.1 requests on one connection until the client closes it.
fn serve(conn: TcpStream, log: &Mutex<Vec<Seen>>, revoked: bool) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(mut out) = conn.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(conn);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();
        let (mut len, mut auth) = (0usize, None);
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                match name.to_ascii_lowercase().as_str() {
                    "content-length" => len = value.trim().parse().unwrap_or(0),
                    "authorization" => auth = Some(value.trim().to_string()),
                    _ => {}
                }
            }
        }
        let mut body = vec![0; len];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let (status, answer) = if path.starts_with("/v1/devices/me") && revoked {
            (
                "401 Unauthorized",
                r#"{"error":"unauthorized"}"#.to_string(),
            )
        } else if path.starts_with("/v1/devices/me") {
            (
                "200 OK",
                r#"{"device":"dev-1","telemetry_required":false}"#.to_string(),
            )
        } else if method == "POST" && path == "/v1/devices" {
            (
                "201 Created",
                format!(r#"{{"device":"dev-2","token":"{MINTED}"}}"#),
            )
        } else if path.starts_with("/v1/telemetry/upload") {
            // More than any file here holds: the client then takes its own
            // size as what the server has.
            (
                "200 OK",
                format!(r#"{{"length":1000000000,"accepted":{}}}"#, body.len()),
            )
        } else {
            ("404 Not Found", r#"{"error":"not_found"}"#.to_string())
        };
        log.lock().unwrap().push(Seen {
            at: Instant::now(),
            method,
            path,
            auth,
        });
        let reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{answer}",
            answer.len()
        );
        if out.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("spora-cli-process-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The binary with `home` as its whole world (state, config, `HOME`) and
/// `api` as the API base; no `RUST_LOG` from the caller's environment.
fn spora(home: &Path, api: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_spora-cli"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("SPORA_API", api)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// A device registered with `api`, uploads on.
fn seed_registered(home: &Path, api: &str) {
    seed_device(home, api, false);
}

/// A device registered with `api`, uploads on, its account requiring them
/// (`required`) or not.
fn seed_device(home: &Path, api: &str, required: bool) {
    seed_state(home, api, false, required);
}

/// A device registered with `api`, or (`builtin`) with the built-in API at
/// `api`; uploads on, its account requiring them (`required`) or not.
fn seed_state(home: &Path, api: &str, builtin: bool, required: bool) {
    use spora_service::state::{Device, ServiceState};
    let state = ServiceState {
        device: Some(Device {
            id: "dev-1".into(),
            token: TOKEN.into(),
            api_bases: vec![api.into()],
            builtin,
            extra: Default::default(),
        }),
        upload_enabled: true,
        required,
        ..ServiceState::default()
    };
    state
        .save(&home.join("state").join("spora").join("service"))
        .expect("seed the telemetry state");
}

/// Lines of a child's pipe, as they come.
fn lines(pipe: impl std::io::Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

fn wait(child: &mut Child, limit: Duration) -> ExitStatus {
    let end = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > end {
            let _ = child.kill();
            panic!("the process did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn interrupt(child: &Child) {
    send(child, libc::SIGINT);
}

fn send(child: &Child, signal: libc::c_int) {
    // SAFETY: kill(2) on our own child's pid.
    let rc = unsafe { libc::kill(child.id() as libc::pid_t, signal) };
    assert_eq!(rc, 0, "signal {signal}");
}

/// The entries of the one record a run under `home` kept.
fn record_entries(home: &Path) -> Vec<serde_json::Value> {
    let dir = home.join("state").join("spora").join("records");
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    std::fs::read_to_string(&files[0])
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l}: {e}")))
        .collect()
}

/// The `close` entry of that record, which must be its last.
fn record_close(home: &Path) -> serde_json::Value {
    let entries = record_entries(home);
    let last = entries.last().expect("an empty record").clone();
    assert_eq!(last["t"], "close", "the record has no ending: {entries:#?}");
    last
}

/// A UDP port on loopback that nothing uses right now.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A share with uploads on, stopped by Ctrl+C: its record closes as it
/// stops, and that ending (written after the last background pass could
/// have run) still reaches the API before the process exits.
#[test]
fn share_sends_its_ending_as_it_stops() {
    stop_share_with(libc::SIGINT, "final");
}

/// The terminal closing (or the SSH session dropping) stops a share as
/// Ctrl+C does, ending and all, rather than killing it.
#[test]
fn share_stopped_by_sighup_still_ends_and_sends() {
    stop_share_with(libc::SIGHUP, "hup");
}

#[test]
fn share_stopped_by_sigterm_still_ends_and_sends() {
    stop_share_with(libc::SIGTERM, "term");
}

fn stop_share_with(signal: libc::c_int, tag: &str) {
    let api = FakeApi::start();
    let home = scratch(tag);
    seed_registered(&home, &api.base);
    let mut child = spora(&home, &api.base)
        .args(["share", "--relay", NOWHERE, "--no-conn-log"])
        .spawn()
        .expect("spawn spora share");
    let out = lines(child.stdout.take().unwrap());
    let err = lines(child.stderr.take().unwrap());
    let ready = Instant::now() + Duration::from_secs(30);
    let mut printed = Vec::new();
    while !printed.iter().any(|l: &String| l.contains("Press Ctrl+C")) {
        let left = ready.saturating_duration_since(Instant::now());
        match out.recv_timeout(left) {
            Ok(line) => printed.push(line),
            Err(_) => panic!(
                "share never got ready; stdout: {printed:?}; stderr: {:?}",
                err.try_iter().collect::<Vec<_>>()
            ),
        }
    }
    let stopped = Instant::now();
    send(&child, signal);
    let status = wait(&mut child, Duration::from_secs(30));
    printed.extend(out.try_iter());
    assert!(
        status.success(),
        "{status}; stderr: {:?}",
        err.try_iter().collect::<Vec<_>>()
    );
    assert!(
        printed
            .iter()
            .any(|l| l.contains("Sending this run's diagnostics")),
        "{printed:?}"
    );
    let after: Vec<_> = api
        .requests()
        .into_iter()
        .filter(|(at, method, path, _)| {
            *at > stopped && method == "POST" && path.contains("stream=record")
        })
        .collect();
    assert!(
        !after.is_empty(),
        "no record upload after Ctrl+C; requests: {:?}",
        api.requests()
            .iter()
            .map(|r| format!("{} {}", r.1, r.2))
            .collect::<Vec<_>>()
    );
    let bearer = format!("Bearer {TOKEN}");
    assert!(
        after
            .iter()
            .all(|r| r.3.as_deref() == Some(bearer.as_str()))
    );
    let close = record_close(&home);
    assert_eq!(close["outcome"], "never_connected", "{close}");
    assert_eq!(close["reason"], "local_shutdown", "{close}");
    std::fs::remove_dir_all(&home).ok();
}

/// An API that takes connections and never answers: a last upload to it
/// would take its whole allowance.
fn black_hole_api() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the black hole");
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for conn in listener.incoming().flatten() {
            held.push(conn);
        }
    });
    base
}

/// A second Ctrl+C right after the first skips the last upload, wherever
/// the run is by then: tearing down, or sending. (That one pressed before
/// the upload started is kept for it is the unit tests' to show; the
/// timing here cannot pin it.)
#[test]
fn a_second_signal_skips_the_last_upload() {
    let api = black_hole_api();
    let home = scratch("twice");
    seed_registered(&home, &api);
    let mut child = spora(&home, &api)
        .args(["share", "--relay", NOWHERE, "--no-conn-log"])
        .spawn()
        .expect("spawn spora share");
    let out = lines(child.stdout.take().unwrap());
    let err = lines(child.stderr.take().unwrap());
    let ready = Instant::now() + Duration::from_secs(30);
    let mut printed = Vec::new();
    while !printed.iter().any(|l: &String| l.contains("Press Ctrl+C")) {
        let left = ready.saturating_duration_since(Instant::now());
        match out.recv_timeout(left) {
            Ok(line) => printed.push(line),
            Err(_) => panic!(
                "share never got ready; stdout: {printed:?}; stderr: {:?}",
                err.try_iter().collect::<Vec<_>>()
            ),
        }
    }
    let stopped = Instant::now();
    interrupt(&child);
    std::thread::sleep(Duration::from_millis(20));
    interrupt(&child);
    let status = wait(&mut child, Duration::from_secs(30));
    assert!(status.success(), "{status}");
    // The last upload waits up to 5 s for an answer that never comes.
    assert!(
        stopped.elapsed() < Duration::from_secs(4),
        "the second Ctrl+C did not skip the last upload: {:?}",
        stopped.elapsed()
    );
    let close = record_close(&home);
    assert_eq!(close["reason"], "local_shutdown", "{close}");
    std::fs::remove_dir_all(&home).ok();
}

/// Ctrl+C while `use` is still dialing (a relay that never answers takes
/// its full dial timeout, 8 s) stops it there: the process exits normally,
/// the dial's record ends `never_connected` with its unfinished steps
/// `abandoned`, and that ending is sent before the process goes.
#[test]
fn a_dial_stopped_by_a_signal_ends_its_record_and_sends_it() {
    let api = FakeApi::start();
    let home = scratch("dial");
    seed_registered(&home, &api.base);
    // Any 36 bytes make a token; this one leads nowhere but a closed port.
    let url = format!("https://spora.invalid/s/{}?r={NOWHERE}", "A".repeat(48));
    let mut child = spora(&home, &api.base)
        .args(["use", "--tun-name", "nosuchtun", "--stun", NOWHERE, &url])
        .spawn()
        .expect("spawn spora use");
    let out = lines(child.stdout.take().unwrap());
    let err = lines(child.stderr.take().unwrap());
    let records = home.join("state").join("spora").join("records");
    let dialing = Instant::now() + Duration::from_secs(30);
    let started = Instant::now();
    loop {
        let text = std::fs::read_dir(&records)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .collect::<String>();
        if text.contains(r#""kind":"relay_dial""#) {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "use exited early; stderr: {:?}",
            err.try_iter().collect::<Vec<_>>()
        );
        assert!(Instant::now() < dialing, "use never started dialing");
        std::thread::sleep(Duration::from_millis(50));
    }
    let stopped = Instant::now();
    interrupt(&child);
    let status = wait(&mut child, Duration::from_secs(30));
    let printed: Vec<String> = out.try_iter().collect();
    assert!(
        status.success(),
        "{status}; stdout: {printed:?}; stderr: {:?}",
        err.try_iter().collect::<Vec<_>>()
    );
    assert!(
        printed
            .iter()
            .any(|l| l.contains("Stopped before the tunnel came up")),
        "{printed:?}"
    );
    let entries = record_entries(&home);
    let close = record_close(&home);
    assert_eq!(close["outcome"], "never_connected", "{close}");
    assert!(
        close["at_ms"].as_u64().unwrap() < 6000,
        "the dial ran its course instead of stopping: {close}"
    );
    assert!(
        entries
            .iter()
            .any(|e| e["kind"] == "relay_dial" && e["outcome"] == "abandoned"),
        "{entries:#?}"
    );
    assert!(started.elapsed() < Duration::from_secs(25));
    assert!(
        api.requests()
            .iter()
            .any(|(at, method, path, _)| *at > stopped
                && method == "POST"
                && path.contains("stream=record")),
        "no record upload after Ctrl+C"
    );
    std::fs::remove_dir_all(&home).ok();
}

/// A `use` whose tunnel comes up and that this host cannot take (here: no
/// permission to attach a TUN) fails as a local failure, not as a tunnel
/// the network lost. Its record says so. The share is a direct endpoint on
/// loopback, so no relay is involved. Skipped as root, which could attach.
#[test]
fn a_tunnel_this_host_cannot_take_ends_as_a_local_failure() {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root");
        return;
    }
    let sharer = scratch("lf-share");
    let client = scratch("lf-use");
    let direct = format!("127.0.0.1:{}", free_udp_port());
    let mut share = spora(&sharer, &format!("http://{NOWHERE}"))
        .args([
            "share",
            "--direct",
            &direct,
            "--stun",
            NOWHERE,
            "--no-direct-upgrade",
            "--no-conn-log",
        ])
        .spawn()
        .expect("spawn spora share");
    let out = lines(share.stdout.take().unwrap());
    let share_err = lines(share.stderr.take().unwrap());
    let ready = Instant::now() + Duration::from_secs(30);
    let url = loop {
        let left = ready.saturating_duration_since(Instant::now());
        match out.recv_timeout(left) {
            Ok(line) if line.starts_with("https://") => break line,
            Ok(_) => {}
            Err(_) => panic!(
                "share never printed its URL; stderr: {:?}",
                share_err.try_iter().collect::<Vec<_>>()
            ),
        }
    };
    let used = spora(&client, &format!("http://{NOWHERE}"))
        .args([
            "use",
            "--tun-name",
            "nosuchtun",
            "--stun",
            NOWHERE,
            "--no-direct-upgrade",
            &url,
        ])
        .output()
        .expect("run spora use");
    interrupt(&share);
    let share_status = wait(&mut share, Duration::from_secs(30));
    let stderr = String::from_utf8_lossy(&used.stderr);
    assert!(!used.status.success(), "{stderr}");
    assert!(
        stderr.contains("could not attach TUN nosuchtun"),
        "{stderr}"
    );
    let close = record_close(&client);
    assert_eq!(close["outcome"], "closed_locally", "{close}");
    // EPERM without CAP_NET_ADMIN; misconfigured where there is no TUN
    // device to open at all.
    assert!(
        ["permission_denied", "misconfigured"].contains(&close["reason"].as_str().unwrap()),
        "{close}"
    );
    assert!(
        close["detail"].as_str().unwrap().contains("nosuchtun"),
        "{close}"
    );
    assert!(share_status.success(), "{share_status}");
    std::fs::remove_dir_all(&sharer).ok();
    std::fs::remove_dir_all(&client).ok();
}

/// `spora telemetry off` on an account that required telemetry, after the
/// server forgot the device (401): the device and the flag are gone with
/// it, so the switch goes off, with no word of the account requiring
/// anything.
#[test]
fn telemetry_off_after_the_server_forgot_the_device() {
    let api = FakeApi::revoked();
    let home = scratch("revoked");
    seed_device(&home, &api.base, true);
    let out = spora(&home, &api.base)
        .args(["telemetry", "off"])
        .output()
        .expect("run spora telemetry off");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}: {stdout} {stderr}", out.status);
    assert!(stdout.contains("asking again"), "{stdout}");
    assert!(stdout.contains("Uploads off"), "{stdout}");
    let notice = &spora_service::REQUIRED_NOTICE[..40];
    assert!(
        !stdout.contains(notice) && !stderr.contains(notice),
        "{stdout} {stderr}"
    );
    assert!(
        api.requests()
            .iter()
            .any(|r| r.1 == "GET" && r.2.starts_with("/v1/devices/me")),
        "the account was never asked"
    );
    let status = spora(&home, &api.base)
        .args(["telemetry", "status", "--json"])
        .output()
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["upload_enabled"], false);
    assert_eq!(status["required"], false);
    std::fs::remove_dir_all(&home).ok();
}

/// A machine registered with the built-in API, its account requiring
/// telemetry, run with `SPORA_API` naming another API: `telemetry upload`
/// registers it anew there and never sends the built-in token, and
/// `telemetry status` tells the two registrations apart, binding nothing to
/// the built-in account's flag. (The built-in API itself is never built:
/// `SPORA_API` is set, as everywhere here.)
#[test]
fn a_builtin_registration_never_reaches_an_override_api() {
    let api = FakeApi::start();
    let home = scratch("builtin");
    seed_state(&home, "https://old-front.example", true, true);
    let out = spora(&home, &api.base)
        .args(["telemetry", "upload"])
        .output()
        .expect("run spora telemetry upload");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}: {stdout} {stderr}", out.status);
    assert!(
        stdout.contains(&format!(
            "Registered this machine as device dev-2 with {}.",
            api.base
        )),
        "{stdout}"
    );
    let reqs = api.requests();
    assert!(reqs.iter().any(|r| r.1 == "POST" && r.2 == "/v1/devices"));
    let (old, new) = (format!("Bearer {TOKEN}"), format!("Bearer {MINTED}"));
    assert!(reqs.iter().all(|r| r.3.as_deref() != Some(old.as_str())));
    assert!(reqs.iter().any(|r| r.3.as_deref() == Some(new.as_str())));

    let status = spora(&home, &api.base)
        .args(["telemetry", "status", "--json"])
        .output()
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let override_api = serde_json::json!({ "builtin": false, "bases": [api.base] });
    assert_eq!(status["api"], override_api);
    assert_eq!(status["device_id"], "dev-2");
    assert_eq!(status["device_api"], override_api);
    assert_eq!(
        status["other_device_apis"],
        serde_json::json!([{ "builtin": true, "bases": spora_service::DEFAULT_API_BASES }])
    );
    assert_eq!(status["required"], false);

    let status = spora(&home, &api.base)
        .args(["telemetry", "status"])
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&status.stdout);
    for line in [
        format!("api          {} (SPORA_API)", api.base),
        format!("device       dev-2 (registered with {})", api.base),
        "also registered with the built-in API (kept for when that API is used again)".into(),
    ] {
        assert!(status.contains(&line), "{line:?} in {status}");
    }
    std::fs::remove_dir_all(&home).ok();
}

/// A `SPORA_API` that is not UTF-8 is a broken setup like an empty one,
/// never unset: `telemetry status` (which sends nothing, so a regression
/// cannot reach production here) names no API and says why.
#[test]
fn a_spora_api_that_is_not_utf8_never_means_the_builtin_api() {
    use std::os::unix::ffi::OsStrExt as _;
    let home = scratch("not-utf8");
    for env in [&b"\xff"[..], b"http://127.0.0.1:9\xff"] {
        let env = std::ffi::OsStr::from_bytes(env);
        let out = spora(&home, NOWHERE)
            .env("SPORA_API", env)
            .args(["telemetry", "status", "--json"])
            .output()
            .expect("run spora telemetry status");
        assert!(out.status.success(), "{env:?}: {}", out.status);
        let status: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(status["api"], serde_json::Value::Null, "{env:?}: {status}");
        let out = spora(&home, NOWHERE)
            .env("SPORA_API", env)
            .args(["telemetry", "status"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("api          SPORA_API is not usable: not an http(s) URL"),
            "{env:?}: {text}"
        );
    }
    std::fs::remove_dir_all(&home).ok();
}

/// A directory this user may not read outside their own state — root's,
/// a service's — gets no advice to take it over: `record` says the same
/// command with sudo reads it, `report` lists it as unreadable. Skipped as
/// root, which reads it anyway.
#[test]
fn unreadable_directories_elsewhere_get_no_chown_advice() {
    use std::os::unix::fs::PermissionsExt as _;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root");
        return;
    }
    let home = scratch("unread");
    let closed = home.join("closed");
    let records = closed.join("records");
    std::fs::create_dir_all(&records).unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let list = spora(&home, &format!("http://{NOWHERE}"))
        .args(["record", "list", "--dir"])
        .arg(&records)
        .output()
        .unwrap();
    let report = spora(&home, &format!("http://{NOWHERE}"))
        .args(["report", "-o"])
        .arg(home.join("r.zip"))
        .arg("--record-dir")
        .arg(&records)
        .output()
        .unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();

    let stderr = String::from_utf8_lossy(&list.stderr);
    assert!(!list.status.success(), "{stderr}");
    assert!(stderr.contains("Permission denied"), "{stderr}");
    assert!(stderr.contains("the same command with sudo"), "{stderr}");
    assert!(!stderr.contains("chown"), "{stderr}");

    let stdout = String::from_utf8_lossy(&report.stdout);
    let stderr = String::from_utf8_lossy(&report.stderr);
    assert!(report.status.success(), "{stdout} {stderr}");
    assert!(
        stdout.contains(&format!("{}: Permission denied", records.display())),
        "{stdout}"
    );
    assert!(!stdout.contains("chown"), "{stdout}");
    std::fs::remove_dir_all(&home).ok();
}

/// `spora share | head -2`: the reader goes away, and the share carries on
/// (and later stops cleanly) instead of panicking on its next line.
#[test]
fn share_outlives_a_closed_stdout() {
    let home = scratch("pipe");
    let mut child = spora(&home, &format!("http://{NOWHERE}"))
        .args(["share", "--relay", NOWHERE, "--no-conn-log"])
        .spawn()
        .expect("spawn spora share");
    drop(child.stdout.take());
    let err = lines(child.stderr.take().unwrap());
    // The banner follows the record's opening; wait for that, then for
    // the banner to have been written into the closed pipe.
    let records = home.join("state").join("spora").join("records");
    let ready = Instant::now() + Duration::from_secs(30);
    while std::fs::read_dir(&records).map_or(true, |mut d| d.next().is_none()) {
        assert!(
            child.try_wait().unwrap().is_none(),
            "share exited early; stderr: {:?}",
            err.try_iter().collect::<Vec<_>>()
        );
        assert!(Instant::now() < ready, "share never opened its record");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        child.try_wait().unwrap().is_none(),
        "share died when its stdout went away; stderr: {:?}",
        err.try_iter().collect::<Vec<_>>()
    );
    interrupt(&child);
    let status = wait(&mut child, Duration::from_secs(30));
    assert!(status.success(), "{status}");
    let log = home.join("state").join("spora").join("log");
    let crashes: Vec<_> = std::fs::read_dir(&log)
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("crash-"))
                .collect()
        })
        .unwrap_or_default();
    assert!(crashes.is_empty(), "crash reports: {crashes:?}");
    std::fs::remove_dir_all(&home).ok();
}

/// `spora telemetry status | head -c1`: a one-shot command whose reader is
/// gone ends quietly (SIGPIPE's default action) instead of panicking on its
/// first line.
#[test]
fn a_one_shot_command_ends_quietly_when_its_reader_goes() {
    use std::os::unix::process::ExitStatusExt as _;
    for round in 0..5 {
        let home = scratch(&format!("oneshot-pipe-{round}"));
        let mut child = spora(&home, &format!("http://{NOWHERE}"))
            .args(["telemetry", "status"])
            .spawn()
            .expect("spawn spora telemetry status");
        drop(child.stdout.take());
        let mut err = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        let status = wait(&mut child, Duration::from_secs(30));
        assert!(
            !err.contains("panicked"),
            "round {round}: {status}; stderr: {err}"
        );
        assert!(
            status.success() || status.signal() == Some(libc::SIGPIPE),
            "round {round}: {status}; stderr: {err}"
        );
        std::fs::remove_dir_all(&home).ok();
    }
}

/// The binary as root, the way sudo starts it: uid 0 in a user namespace of
/// its own (`unshare -r`), `HOME` as macOS's sudo keeps it (the user's),
/// `XDG_STATE_HOME` only if given. Read-only commands only: root's home is
/// the real one.
fn spora_as_root(home: &Path, sudo_user: Option<&str>, xdg: Option<&Path>) -> Command {
    let mut cmd = Command::new("unshare");
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("SPORA_API", format!("http://{NOWHERE}"))
        .arg("-r")
        .arg(env!("CARGO_BIN_EXE_spora-cli"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(user) = sudo_user {
        cmd.env("SUDO_USER", user);
    }
    if let Some(dir) = xdg {
        cmd.env("XDG_STATE_HOME", dir);
    }
    cmd
}

/// A run with sudo keeps its state in root's home even where sudo kept the
/// user's `HOME`, and never writes into the user's home; root's own runs go
/// by `HOME`, and an `XDG_STATE_HOME` it is handed wins. Skipped where user
/// namespaces are not available, and for a real root, whose home this must
/// not read for a test.
#[test]
fn a_run_with_sudo_keeps_its_state_out_of_the_users_home() {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root");
        return;
    }
    let userns = Command::new("unshare")
        .args(["-r", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !userns.is_ok_and(|s| s.success()) {
        eprintln!("skipped: no unprivileged user namespaces (unshare -r)");
        return;
    }
    let scratch = scratch("sudo");
    let home = scratch.join("home");
    std::fs::create_dir_all(&home).unwrap();
    // The telemetry state directory, as the status names it, or as the
    // error about reading it does (root's home may be closed to the
    // namespace).
    let state_of = |cmd: &mut Command| {
        let out = cmd
            .args(["telemetry", "status", "--json"])
            .output()
            .expect("spawn spora telemetry status");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(!stderr.contains("panicked"), "{stderr}");
        let named = match serde_json::from_str::<serde_json::Value>(&stdout) {
            Ok(v) => v["state_file"].as_str().unwrap().to_string(),
            Err(_) => stderr
                .split_whitespace()
                .find(|w| w.contains("/spora/service"))
                .unwrap_or_else(|| panic!("no state path: {stdout} {stderr}"))
                .trim_end_matches([':', ',', ')', '"'])
                .to_string(),
        };
        let named = PathBuf::from(named);
        match named.file_name() {
            Some(f) if f == "service.json" => named.parent().unwrap().to_path_buf(),
            _ => named,
        }
    };
    let tail = Path::new(".local/state/spora/service");

    let sudo = state_of(&mut spora_as_root(&home, Some("someone"), None));
    assert!(sudo.ends_with(tail), "{}", sudo.display());
    assert!(!sudo.starts_with(&home), "{}", sudo.display());

    for sudo_user in [None, Some(""), Some("root")] {
        assert_eq!(
            state_of(&mut spora_as_root(&home, sudo_user, None)),
            home.join(tail),
            "SUDO_USER={sudo_user:?}"
        );
    }

    let xdg = scratch.join("xdg");
    assert_eq!(
        state_of(&mut spora_as_root(&home, Some("someone"), Some(&xdg))),
        xdg.join("spora/service")
    );

    let left: Vec<_> = std::fs::read_dir(&home).unwrap().flatten().collect();
    assert!(left.is_empty(), "written into HOME: {left:?}");
    std::fs::remove_dir_all(&scratch).ok();
}

/// `RUST_LOG=trace spora telemetry upload`, the way someone chasing an
/// upload problem runs it: the request carries the token, the output never
/// does, even with ureq-proto's raw-request dump asked for by name.
#[test]
fn trace_output_never_carries_the_upload_token() {
    let api = FakeApi::start();
    let home = scratch("trace");
    seed_registered(&home, &api.base);
    let mut child = spora(&home, &api.base)
        .env("RUST_LOG", "trace,ureq_proto::util=trace")
        .args(["telemetry", "upload"])
        .spawn()
        .expect("spawn spora telemetry upload");
    let out = lines(child.stdout.take().unwrap());
    let err = lines(child.stderr.take().unwrap());
    let status = wait(&mut child, Duration::from_secs(60));
    let stdout: Vec<String> = out.iter().collect();
    let stderr = err.iter().collect::<Vec<_>>().join("\n");
    assert!(status.success(), "{status}: {stdout:?} {stderr}");
    let bearer = format!("Bearer {TOKEN}");
    assert!(
        api.requests()
            .iter()
            .any(|r| r.3.as_deref() == Some(bearer.as_str())),
        "the upload never made an authenticated request"
    );
    assert!(stderr.contains("ureq::"), "trace logging was not on");
    assert!(
        !stderr.contains("ureq_proto"),
        "ureq_proto lines reached stderr"
    );
    for window in TOKEN.as_bytes().windows(6) {
        let piece = std::str::from_utf8(window).unwrap();
        assert!(
            !stderr.contains(piece),
            "stderr holds {piece:?} of the token"
        );
        assert!(
            !stdout.iter().any(|l| l.contains(piece)),
            "stdout holds {piece:?} of the token"
        );
    }
    std::fs::remove_dir_all(&home).ok();
}
