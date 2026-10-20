//! The uploader against [`crate::fake_server`]: registration, the switch,
//! the force flag, and every cursor case of the upload protocol.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::api::Api;
use crate::fake_server::{Canned, FakeServer, Req};
use crate::state::{Device, ServiceState, StateStore};
use crate::upload::Pass;
use crate::{ApiError, Error, ServiceConfig, Telemetry, UploadTimings};

struct Env {
    _tmp: tempfile::TempDir,
    server: FakeServer,
    state: PathBuf,
    rec: PathBuf,
    log: PathBuf,
}

const REC: &str = "20261019T100000Z-client-0123abcd.jsonl";
const DIAG: &str = "diag-20261019T100000000Z-77.jsonl";
const CRASH: &str = "crash-20261019T100000000Z-rust.txt";

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("service");
    let rec = tmp.path().join("records");
    let log = tmp.path().join("diag");
    std::fs::create_dir_all(&rec).unwrap();
    std::fs::create_dir_all(&log).unwrap();
    Env {
        server: FakeServer::start(),
        _tmp: tmp,
        state,
        rec,
        log,
    }
}

impl Env {
    fn cfg(&self) -> ServiceConfig {
        let mut c = ServiceConfig::new(&self.state, "linux", "0.1.0-test")
            .with_record_dir(&self.rec)
            .with_log_dir(&self.log)
            .with_api_bases(vec![self.server.base()]);
        c.timings = UploadTimings {
            interval: Duration::from_secs(3600),
            backoff_min: Duration::from_secs(3600),
            backoff_max: Duration::from_secs(3600),
            status_interval: Duration::from_secs(24 * 3600),
            nudge_delay: Duration::from_millis(20),
        };
        c
    }

    fn open(&self) -> Telemetry {
        Telemetry::open(self.cfg()).unwrap()
    }

    /// The configuration that names no API, in a release whose built-in
    /// list is `fronts` (never the real one).
    fn open_builtin(&self, fronts: &[String]) -> Telemetry {
        let api = Api::builtin(fronts, "0.1.0-test").unwrap();
        Telemetry::open_with(self.cfg().with_api_bases(Vec::new()), api).unwrap()
    }

    fn state(&self) -> ServiceState {
        ServiceState::load(&self.state)
    }

    fn device(&self) -> String {
        self.state().device.unwrap().id
    }

    fn cursor(&self, stream: &str, file: &str) -> Option<u64> {
        self.state().cursors.get(stream)?.get(file).copied()
    }

    fn stored(&self, stream: &str, file: &str) -> Vec<u8> {
        self.server.stored(&self.device(), stream, file)
    }
}

fn append(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// How many of `reqs` registered a device.
fn registrations(reqs: &[Req]) -> usize {
    reqs.iter()
        .filter(|r| r.method == "POST" && r.path == "/v1/devices")
        .count()
}

/// One of `reqs` carried `token`.
fn carried(reqs: &[Req], token: &str) -> bool {
    reqs.iter().any(|r| r.token.as_deref() == Some(token))
}

/// JSON-ish lines that compress well.
fn lines(tag: &str, n: usize) -> String {
    (0..n)
        .map(|i| {
            format!("{{\"t\":\"step\",\"tag\":\"{tag}\",\"seq\":{i},\"kind\":\"relay_dial\"}}\n")
        })
        .collect()
}

#[test]
fn notice_is_the_agreed_wording() {
    let verbatim = "Your account requires that telemetry is enabled (most likely because you've signed up to a promotion). You can keep it enabled, sign in to a different account, or contact support.";
    assert_eq!(crate::REQUIRED_NOTICE, verbatim);
}

#[test]
fn off_means_nothing_leaves() {
    let e = env();
    append(&e.rec.join(REC), lines("a", 3).as_bytes());
    let t = e.open();
    assert!(matches!(t.upload_now(), Err(Error::Off)));
    t.start();
    t.nudge();
    std::thread::sleep(Duration::from_millis(300));
    t.stop();
    assert!(e.server.requests().is_empty());
    assert!(!t.status().upload_enabled);
    assert_eq!(t.status().device_id, None);
}

#[test]
fn fresh_upload_resume_and_partial_lines() {
    let e = env();
    let rec = e.rec.join(REC);
    let complete = lines("r", 3);
    append(&rec, complete.as_bytes());
    append(&rec, b"{\"t\":\"sam"); // a line still being written
    append(&e.log.join(DIAG), lines("d", 6000).as_bytes()); // > one chunk
    assert!(std::fs::metadata(e.log.join(DIAG)).unwrap().len() > crate::upload::MAX_CHUNK as u64);
    append(&e.log.join(CRASH), b"{\"src\":\"crash\"}\npanicked\n");
    std::fs::write(e.log.join("notes.txt"), b"not a stream file\n").unwrap();

    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    let s = t.upload_now().unwrap();
    assert!(s.registered && s.status_checked);
    assert_eq!(s.files, 3);
    assert!(s.chunks >= 4, "the log takes more than one chunk: {s:?}");
    assert_eq!(s.bytes_sent, s.bytes_accepted);
    let st = t.status();
    assert!(st.device_id.is_some());
    assert!(st.last_upload_unix_ms.is_some());
    assert_eq!(st.last_error, None);

    // Registration said who we are.
    let reqs = e.server.requests();
    assert_eq!(reqs[0].path, "/v1/devices");
    assert_eq!(reqs[1].path, "/v1/devices/me");
    assert!(
        reqs.iter()
            .all(|r| r.app_version.as_deref() == Some("0.1.0-test"))
    );
    assert!(reqs[1..].iter().all(|r| r.authorized));
    assert_eq!(
        e.server.state().devices.values().next().unwrap().platform,
        "linux"
    );

    // Complete lines only; streams in order crash, record, log.
    assert_eq!(e.stored("record", REC), complete.as_bytes());
    assert_eq!(e.cursor("record", REC), Some(complete.len() as u64));
    assert_eq!(
        e.stored("log", DIAG),
        std::fs::read(e.log.join(DIAG)).unwrap()
    );
    assert_eq!(
        e.stored("crash", CRASH),
        std::fs::read(e.log.join(CRASH)).unwrap()
    );
    let ups = e.server.uploads();
    let order: Vec<&str> = ups.iter().map(|r| r.query["stream"].as_str()).collect();
    let mut sorted = order.clone();
    sorted.sort_by_key(|s| ["crash", "record", "log"].iter().position(|x| x == s));
    assert_eq!(order, sorted);
    // Chunks are bounded and gzip'd when that helps; the server decoded them.
    assert!(ups.iter().all(|r| r.raw_len <= crate::upload::MAX_CHUNK));
    assert!(ups.iter().any(|r| r.gzip));
    assert!(ups.iter().all(|r| r.status == 200));

    // The rest of the line arrives, and more: resume from the cursor.
    append(&rec, b"ple\"}\n");
    append(&rec, lines("r2", 2).as_bytes());
    let before = e.server.uploads().len();
    let s = t.upload_now().unwrap();
    // Someone asked: the flag is fetched too, whatever its schedule.
    assert!(!s.registered && s.status_checked);
    let ups = e.server.uploads();
    assert_eq!(ups.len(), before + 1);
    assert_eq!(ups[before].query["offset"], complete.len().to_string());
    assert_eq!(e.stored("record", REC), std::fs::read(&rec).unwrap());

    // Nothing new: no uploads (and in the background, no requests at all).
    let n = e.server.requests().len();
    let s = t.upload_now().unwrap();
    assert_eq!(s.chunks, 0);
    let reqs = e.server.requests();
    assert_eq!(reqs.len(), n + 1);
    assert_eq!(reqs[n].path, "/v1/devices/me");
    let s = t.background_pass().unwrap();
    assert!(s.chunks == 0 && !s.status_checked);
    assert_eq!(e.server.requests().len(), n + 1);
}

#[test]
fn small_bodies_go_uncompressed() {
    let e = env();
    append(&e.rec.join(REC), b"x\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let ups = e.server.uploads();
    assert_eq!(ups.len(), 1);
    assert!(!ups[0].gzip);
    assert_eq!(e.stored("record", REC), b"x\n");
}

#[test]
fn server_behind_rewinds() {
    let e = env();
    let rec = e.rec.join(REC);
    let first = lines("a", 1);
    append(&rec, first.as_bytes());
    append(&rec, lines("b", 4).as_bytes());
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let old_cursor = e.cursor("record", REC).unwrap();

    // The server lost everything after the first line.
    e.server
        .set_stored(&e.device(), "record", REC, first.as_bytes());
    append(&rec, lines("c", 2).as_bytes());
    let before = e.server.uploads().len();
    let s = t.upload_now().unwrap();
    let ups = &e.server.uploads()[before..];
    assert_eq!(ups[0].query["offset"], old_cursor.to_string());
    assert_eq!(ups[0].accepted, 0);
    assert_eq!(ups[1].query["offset"], first.len().to_string());
    assert_eq!(e.stored("record", REC), std::fs::read(&rec).unwrap());
    assert_eq!(
        e.cursor("record", REC),
        Some(std::fs::metadata(&rec).unwrap().len())
    );
    assert_eq!(s.files, 1);
}

#[test]
fn server_ahead_clamps_to_the_local_size() {
    let e = env();
    let rec = e.rec.join(REC);
    let local = lines("a", 3);
    append(&rec, local.as_bytes());
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    // Register first, then give the server more of this file than exists.
    append(&e.log.join(CRASH), b"x\n");
    t.upload_now().unwrap();
    let ahead = format!("{local}{}", lines("z", 2));
    e.server
        .set_stored(&e.device(), "record", REC, ahead.as_bytes());
    let mut st = e.state();
    st.cursors.clear();
    st.save(&e.state).unwrap();

    let s = t.upload_now().unwrap();
    assert_eq!(s.bytes_accepted, 0);
    assert_eq!(e.cursor("record", REC), Some(local.len() as u64));
    assert_eq!(e.stored("record", REC), ahead.as_bytes());
    // Settled: the next pass sends nothing.
    let n = e.server.uploads().len();
    t.upload_now().unwrap();
    assert_eq!(e.server.uploads().len(), n);
}

#[test]
fn duplicates_are_not_stored_twice() {
    let e = env();
    let rec = e.rec.join(REC);
    append(&rec, lines("a", 5).as_bytes());
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let held = e.stored("record", REC);

    // A lost cursor (or a second process) resends from 0.
    let mut st = e.state();
    st.cursors.clear();
    st.save(&e.state).unwrap();
    let s = t.upload_now().unwrap();
    assert_eq!(s.chunks, 1);
    assert_eq!(s.bytes_accepted, 0);
    assert!(s.bytes_sent > 0);
    assert_eq!(e.stored("record", REC), held);
    assert_eq!(e.cursor("record", REC), Some(held.len() as u64));
}

#[test]
fn unauthorized_drops_the_device_and_registers_again() {
    let e = env();
    let rec = e.rec.join(REC);
    append(&rec, lines("a", 3).as_bytes());
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let first = e.device();

    e.server.revoke_all();
    append(&rec, lines("b", 1).as_bytes());
    let r = t.upload_now();
    assert!(
        matches!(r, Err(Error::Api(ApiError::Unauthorized))),
        "{r:?}"
    );
    let st = e.state();
    assert!(st.device.is_none());
    assert!(st.cursors.is_empty());
    assert!(st.upload_enabled);
    assert!(t.status().last_error.unwrap().contains("401"));
    // The token is in the state file and nowhere else.
    assert!(!t.status().last_error.unwrap().contains("tok"));

    let s = t.upload_now().unwrap();
    assert!(s.registered);
    let second = e.device();
    assert_ne!(first, second);
    // The new device gets everything still on disk.
    assert_eq!(
        e.server.stored(&second, "record", REC),
        std::fs::read(&rec).unwrap()
    );
    assert_eq!(t.status().last_error, None);
}

#[test]
fn cursors_of_deleted_files_are_pruned() {
    let e = env();
    let other = "20261019T090000Z-exit-89abcdef.jsonl";
    append(&e.rec.join(REC), b"a\n");
    append(&e.rec.join(other), b"b\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    assert_eq!(e.cursor("record", other), Some(2));
    std::fs::remove_file(e.rec.join(other)).unwrap();
    t.upload_now().unwrap();
    assert_eq!(e.cursor("record", other), None);
    assert_eq!(e.cursor("record", REC), Some(2));
}

#[test]
fn force_flag() {
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let mut cfg = e.cfg();
    cfg.timings.status_interval = Duration::ZERO;
    let t = Telemetry::open(cfg).unwrap();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    t.set_upload_enabled(false).unwrap();
    assert!(!t.status().upload_enabled);

    // The account starts requiring telemetry: the flag check (which runs
    // for a registered device even while off) switches uploads back on and
    // leaves the UI a notice.
    e.server.set_required(true);
    append(&e.rec.join(REC), b"b\n");
    t.upload_now().unwrap();
    let st = t.status();
    assert!(st.upload_enabled && st.required && st.required_notice_pending);
    assert_eq!(e.stored("record", REC), b"a\nb\n");

    // While required the switch will not turn off, and nothing changes.
    assert!(matches!(t.set_upload_enabled(false), Err(Error::Required)));
    assert!(t.status().upload_enabled);

    // The notice is owed once.
    t.acknowledge_notice().unwrap();
    t.upload_now().unwrap();
    assert!(!t.status().required_notice_pending);
    assert!(t.status().required);

    // No longer required: the switch is left as it is, and works again.
    e.server.set_required(false);
    t.upload_now().unwrap();
    let st = t.status();
    assert!(!st.required && st.upload_enabled);
    t.set_upload_enabled(false).unwrap();
    assert!(!t.status().upload_enabled);
}

#[test]
fn force_flag_from_an_upload_answer() {
    let e = env();
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap(); // registers; the daily check is now done
    assert!(!t.status().required);

    e.server.set_required(true);
    append(&e.rec.join(REC), b"a\n");
    let s = t.background_pass().unwrap();
    assert!(!s.status_checked);
    let st = t.status();
    assert!(st.required && st.required_notice_pending);
}

#[test]
fn a_line_too_long_to_send_stops_its_file_only() {
    let e = env();
    let rec = e.rec.join(REC);
    append(&rec, b"ok\n");
    append(&rec, &vec![b'q'; crate::upload::MAX_LINE + 1]);
    append(&rec, b"\nafter\n");
    let other = "20261019T110000Z-client-ffffffff.jsonl";
    append(&e.rec.join(other), b"fine\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    let s = t.upload_now().unwrap();
    assert_eq!(s.skipped_files, 1);
    assert_eq!(e.stored("record", REC), b"ok\n");
    assert_eq!(e.stored("record", other), b"fine\n");
    assert!(t.status().last_error.unwrap().contains(REC));

    // It rests: the next passes neither read it again nor report it.
    let s = t.background_pass().unwrap();
    assert_eq!(s.skipped_files, 0);
    assert_eq!(t.status().last_error, None);
    assert_eq!(e.state().refusal("record", REC).unwrap().at, 3);
}

#[test]
fn a_refused_file_does_not_stop_the_others() {
    let e = env();
    let rec = e.rec.join(REC);
    append(&rec, b"one\ntwo\n");
    let other = "20261019T110000Z-client-ffffffff.jsonl";
    append(&e.rec.join(other), b"fine\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    append(&e.log.join(CRASH), b"x\n");
    t.upload_now().unwrap();
    // The server holds a length that is not on a line boundary.
    e.server.set_stored(&e.device(), "record", REC, b"one\ntw");
    let mut st = e.state();
    st.cursors.clear();
    st.save(&e.state).unwrap();
    append(&e.rec.join(other), b"more\n");

    let s = t.upload_now().unwrap();
    assert_eq!(s.skipped_files, 1);
    assert_eq!(e.stored("record", other), b"fine\nmore\n");
    assert!(t.status().last_error.unwrap().contains("misaligned"));

    // The refused file rests: a background pass does not send it again.
    let n = e.server.uploads().len();
    assert_eq!(t.background_pass().unwrap().skipped_files, 0);
    assert_eq!(e.server.uploads().len(), n);
    assert_eq!(t.status().last_error, None);
    // Someone asking gets another try (refused again here).
    assert_eq!(t.upload_now().unwrap().skipped_files, 1);
    assert_eq!(e.server.uploads().len(), n + 1);
    // So does a day later; and once the server takes it, the rest is over.
    e.server.set_stored(&e.device(), "record", REC, b"one\n");
    let mut st = e.state();
    st.refused
        .get_mut("record")
        .unwrap()
        .get_mut(REC)
        .unwrap()
        .unix_ms = 1;
    st.save(&e.state).unwrap();
    assert_eq!(t.background_pass().unwrap().skipped_files, 0);
    assert_eq!(e.stored("record", REC), b"one\ntwo\n");
    assert!(e.state().refused.is_empty());
}

#[test]
fn a_failed_pass_keeps_what_it_delivered() {
    let e = env();
    append(&e.log.join(CRASH), b"x\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let mut st = e.state();
    st.last_upload_unix_ms = Some(1);
    st.save(&e.state).unwrap();

    // Two record files; the server answers the flag check and the first
    // upload, then fails.
    let later = "20261019T110000Z-client-ffffffff.jsonl";
    append(&e.rec.join(REC), b"a\n");
    append(&e.rec.join(later), b"b\n");
    let n = e.server.requests().len();
    e.server.state().fail_from = Some((n + 2, 503));
    let r = t.upload_now();
    assert!(
        matches!(r, Err(Error::Api(ApiError::Status { status: 503, .. }))),
        "{r:?}"
    );
    let st = t.status();
    assert!(st.last_upload_unix_ms.unwrap() > 1);
    assert_eq!(st.last_error.as_deref(), Some("http 503 (server_error)"));
    assert_eq!(e.cursor("record", REC), Some(2));
    assert_eq!(e.cursor("record", later), None);

    // The server is back: the rest goes, and the error clears.
    e.server.state().fail_from = None;
    t.upload_now().unwrap();
    assert_eq!(e.cursor("record", later), Some(2));
    assert_eq!(t.status().last_error, None);
}

#[test]
fn bases_fail_over_and_stick() {
    let e = env();
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let busy = FakeServer::start();
    busy.state().fail_next = vec![503; 100];
    append(&e.rec.join(REC), b"a\n");
    let cfg = e
        .cfg()
        .with_api_bases(vec![dead, busy.base(), e.server.base()]);
    let t = Telemetry::open(cfg).unwrap();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    assert_eq!(e.stored("record", REC), b"a\n");
    assert_eq!(busy.requests().len(), 1);

    // The base that answered is where the next request starts.
    append(&e.rec.join(REC), b"b\n");
    t.upload_now().unwrap();
    assert_eq!(busy.requests().len(), 1);
    assert_eq!(e.stored("record", REC), b"a\nb\n");
}

#[test]
fn the_thread_uploads_when_nudged() {
    let _runs = crate::diag::RUNS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    use spora_core::record::{Outcome, RecordConfig, Recorder, Role};
    let e = env();
    let t = e.open();
    t.start();
    // Switching on is itself a nudge: registration happens in the background.
    t.set_upload_enabled(true).unwrap();
    wait_for(|| t.status().device_id.is_some());

    // A record closing nudges the uploader through the subscriber.
    let rec = Recorder::start(
        &RecordConfig::in_dir(&e.rec).with_subscriber(t.record_subscriber()),
        Role::Client,
        None,
        Vec::new(),
        false,
    );
    rec.close(Outcome::NeverConnected, None, None);
    drop(rec); // the record's writer flushes and exits
    let file = crate::fsutil::list_matching(&e.rec, |n| n.ends_with(".jsonl"))
        .pop()
        .unwrap();
    wait_for(|| {
        // The first nudge came from the subscriber; a pass that ran before
        // the close line reached the file is followed up here.
        let done =
            String::from_utf8_lossy(&e.stored("record", &file.name)).contains("\"t\":\"close\"");
        if !done {
            t.nudge();
        }
        done
    });
    t.stop();
    assert_eq!(
        e.stored("record", &file.name),
        std::fs::read(&file.path).unwrap()
    );
}

#[test]
fn bug_report_through_the_handle() {
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let out = e.state.join("report.zip");
    let mut info = std::collections::BTreeMap::new();
    info.insert("model".to_string(), "Pixel 9".to_string());
    let s = t
        .export_bug_report(&out, Some("note".into()), info)
        .unwrap();
    assert_eq!(s.included_files, 1);
    let entries = crate::zip::read_all(&std::fs::read(&out).unwrap()).unwrap();
    let m: serde_json::Value = serde_json::from_slice(
        &entries
            .iter()
            .find(|(n, _)| n == "manifest.json")
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(m["device_id"], e.device().as_str());
    assert_eq!(m["platform"]["model"], "Pixel 9");
    assert_eq!(m["platform"]["platform"], "linux");
    assert_eq!(m["platform"]["app_version"], "0.1.0-test");
    let token = e.state().device.unwrap().token;
    for (name, data) in &entries {
        assert!(!String::from_utf8_lossy(data).contains(&token), "{name}");
    }
}

#[test]
fn a_refusal_of_the_endpoint_ends_the_pass() {
    let e = env();
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap(); // registered, nothing to send
    for n in ["a", "b", "c"] {
        append(
            &e.rec.join(format!("20261019T10000{n}Z-client.jsonl")),
            b"x\n",
        );
    }
    // Not about any one file: the pass ends at the first, with backoff.
    e.server
        .state()
        .path_status
        .insert("/v1/telemetry/upload".into(), (404, "not_found".into()));
    let r = t.upload_now();
    assert!(
        matches!(r, Err(Error::Api(ApiError::Status { status: 404, .. }))),
        "{r:?}"
    );
    assert_eq!(e.server.uploads().len(), 1);
    let st = e.state();
    assert!(st.cursors.is_empty() && st.refused.is_empty());
    assert_eq!(
        t.status().last_error.as_deref(),
        Some("http 404 (not_found)")
    );
}

#[test]
fn a_failed_status_check_does_not_hold_uploads_back() {
    let e = env();
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let me = |e: &Env| {
        e.server
            .requests()
            .iter()
            .filter(|r| r.path == "/v1/devices/me")
            .count()
    };
    e.server
        .state()
        .path_status
        .insert("/v1/devices/me".into(), (500, "server_error".into()));
    append(&e.rec.join(REC), b"a\n");
    let s = t.upload_now().unwrap();
    assert!(!s.status_checked);
    assert_eq!(e.stored("record", REC), b"a\n");
    // The upload's answer carried the flag.
    assert!(e.state().status_checked_unix_ms > 0);

    // Uploads off: a failing check waits for its schedule (daily), not
    // for the failure backoff.
    t.set_upload_enabled(false).unwrap();
    let mut st = e.state();
    st.status_checked_unix_ms = 0;
    st.save(&e.state).unwrap();
    let n = me(&e);
    assert!(!t.background_pass().unwrap().status_checked);
    assert_eq!(me(&e), n + 1);
    assert!(e.state().status_failed_unix_ms > 0);
    t.background_pass().unwrap();
    assert_eq!(me(&e), n + 1);
}

#[test]
fn an_explicit_pass_and_a_refused_switch_off_refresh_the_flag() {
    let e = env();
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    e.server.set_required(true);
    t.upload_now().unwrap();
    assert!(t.status().required && t.status().required_notice_pending);

    // Cleared before the notice was shown: the notice is taken back, and
    // switching off works once the client knows.
    e.server.set_required(false);
    assert!(matches!(t.set_upload_enabled(false), Err(Error::Required)));
    let st = t.refresh_status().unwrap();
    assert!(!st.required && !st.required_notice_pending && st.upload_enabled);
    t.set_upload_enabled(false).unwrap();

    // Without being asked: the uploader thread fetches the flag after a
    // refused switch-off.
    t.set_upload_enabled(true).unwrap();
    e.server.set_required(true);
    t.upload_now().unwrap();
    e.server.set_required(false);
    t.start();
    assert!(matches!(t.set_upload_enabled(false), Err(Error::Required)));
    wait_for(|| !t.status().required);
    t.stop();
    t.set_upload_enabled(false).unwrap();
}

#[test]
fn unauthorized_forgets_the_account_flag_with_the_device() {
    let e = env();
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    e.server.set_required(true);
    t.upload_now().unwrap();
    assert!(t.status().required);
    e.server.revoke_all();
    assert!(matches!(
        t.upload_now(),
        Err(Error::Api(ApiError::Unauthorized))
    ));
    let st = e.state();
    assert!(st.device.is_none() && !st.required && !st.required_notice_pending);
    assert!(st.upload_enabled);
}

#[test]
fn a_401_for_a_token_no_longer_stored_spares_the_new_device() {
    let e = env();
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    e.server.revoke_all();
    // Another process re-registers while this pass still holds the old
    // token.
    let token = e.server.add_device("successor");
    let (dir, base) = (e.state.clone(), e.server.base());
    e.server.state().on_request = Some(Box::new(move |r: &Req| {
        if r.path == "/v1/devices/me" {
            let mut s = ServiceState::read(&dir).unwrap().0;
            s.device = Some(device("successor", &token, &base));
            s.save(&dir).unwrap();
        }
    }));
    assert!(matches!(
        t.upload_now(),
        Err(Error::Api(ApiError::Unauthorized))
    ));
    assert_eq!(e.device(), "successor");
}

#[test]
fn a_registration_adopts_the_device_another_process_saved_first() {
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    let token = e.server.add_device("first");
    let (dir, base) = (e.state.clone(), e.server.base());
    e.server.state().on_request = Some(Box::new(move |r: &Req| {
        if r.path == "/v1/devices" {
            let mut s = ServiceState::read(&dir).unwrap().0;
            s.device = Some(device("first", &token, &base));
            s.save(&dir).unwrap();
        }
    }));
    let s = t.upload_now().unwrap();
    assert!(!s.registered);
    assert_eq!(e.device(), "first");
    assert_eq!(e.server.stored("first", "record", REC), b"a\n");
}

#[test]
fn a_token_goes_only_to_the_api_it_came_from() {
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let first = e.state().device.unwrap();
    assert_eq!(first.api_bases, [e.server.base()]);

    // Pointed at another API: a device of its own there, the first token
    // never sent.
    let other = FakeServer::start();
    let t2 = Telemetry::open(e.cfg().with_api_bases(vec![other.base()])).unwrap();
    let s = t2.upload_now().unwrap();
    assert!(s.registered);
    assert!(
        other
            .requests()
            .iter()
            .all(|r| r.token.as_deref() != Some(first.token.as_str()))
    );
    let second = e.state().device.unwrap();
    assert_eq!(second.api_bases, [other.base()]);
    assert_eq!(other.stored(&second.id, "record", REC), b"a\n");
    assert!(
        e.server
            .requests()
            .iter()
            .all(|r| r.token.as_deref() != Some(second.token.as_str()))
    );
    // The first registration is kept, with its cursors, for its own API.
    let st = e.state();
    assert_eq!(st.parked.len(), 1);
    assert_eq!(st.parked[0].device, first);
    assert_eq!(st.parked[0].cursors["record"][REC], 2);

    // A device saved before devices remembered their API goes nowhere; the
    // first API's own registration is used again.
    let mut st = e.state();
    st.device = Some(device("legacy", "legacy-token", ""));
    st.device.as_mut().unwrap().api_bases.clear();
    st.save(&e.state).unwrap();
    let s = t.upload_now().unwrap();
    assert!(!s.registered);
    assert!(
        e.server
            .requests()
            .iter()
            .all(|r| r.token.as_deref() != Some("legacy-token"))
    );
    assert_eq!(e.state().device.unwrap(), first);
}

/// Two processes sharing the state but configured for different APIs
/// (`SPORA_API` set in one shell only) each keep their registration: one
/// registration per API in all, and every pass sends only what is new.
#[test]
fn two_apis_sharing_a_state_take_turns_with_their_registrations() {
    let e = env();
    let rec = e.rec.join(REC);
    append(&rec, lines("a", 3).as_bytes());
    let other = FakeServer::start();
    let ta = e.open();
    let tb = Telemetry::open(e.cfg().with_api_bases(vec![other.base()])).unwrap();
    ta.set_upload_enabled(true).unwrap();
    for round in 0..4 {
        let new = lines(&format!("r{round}"), 2);
        if round > 0 {
            append(&rec, new.as_bytes());
        }
        // Explicit passes and the uploader thread's alike.
        let (a, b) = if round % 2 == 0 {
            (ta.upload_now().unwrap(), tb.upload_now().unwrap())
        } else {
            (ta.background_pass().unwrap(), tb.background_pass().unwrap())
        };
        if round == 0 {
            assert!(a.registered && b.registered);
            continue;
        }
        for s in [&a, &b] {
            assert!(!s.registered, "round {round}: {s:?}");
            assert_eq!(s.bytes_sent, new.len() as u64, "round {round}: {s:?}");
            assert_eq!(s.bytes_accepted, new.len() as u64, "round {round}: {s:?}");
        }
    }
    assert_eq!(registrations(&e.server.requests()), 1);
    assert_eq!(registrations(&other.requests()), 1);
    let whole = std::fs::read(&rec).unwrap();
    let (da, db) = (
        ta.status().device_id.unwrap(),
        tb.status().device_id.unwrap(),
    );
    assert_eq!(e.server.stored(&da, "record", REC), whole);
    assert_eq!(other.stored(&db, "record", REC), whole);
    // The one used last is active, the other parked; neither token went to
    // the other's API.
    let st = e.state();
    assert_eq!(st.device.as_ref().unwrap().api_bases, [other.base()]);
    assert_eq!(st.parked.len(), 1);
    assert_eq!(st.parked[0].device.api_bases, [e.server.base()]);
    let (ka, kb) = (
        &st.parked[0].device.token,
        &st.device.as_ref().unwrap().token,
    );
    assert!(
        other
            .requests()
            .iter()
            .all(|r| r.token.as_ref() != Some(ka))
    );
    assert!(
        e.server
            .requests()
            .iter()
            .all(|r| r.token.as_ref() != Some(kb))
    );
}

/// A pass whose registration another process parks while it runs keeps
/// what it learns to that registration: the other's cursors are not
/// touched, and its own are there when it is active again.
#[test]
fn a_registration_parked_mid_pass_keeps_its_own_cursors() {
    let e = env();
    let later = "20261019T110000Z-client-ffffffff.jsonl";
    append(&e.rec.join(REC), b"a\n");
    append(&e.rec.join(later), b"b\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    // Right after this pass's first upload, a process configured for
    // another API makes its own registration the active one.
    let other = FakeServer::start();
    let token = other.add_device("other");
    let (dir, base) = (e.state.clone(), other.base());
    let mut fired = false;
    e.server.state().on_request = Some(Box::new(move |r: &Req| {
        if r.path == "/v1/telemetry/upload" && !fired {
            fired = true;
            let mut s = ServiceState::read(&dir).unwrap().0;
            s.park();
            s.device = Some(device("other", &token, &base));
            s.save(&dir).unwrap();
        }
    }));
    let s = t.upload_now().unwrap();
    assert_eq!((s.files, s.chunks), (2, 2));
    let st = e.state();
    assert_eq!(st.device.as_ref().unwrap().id, "other");
    assert!(st.cursors.is_empty() && st.refused.is_empty(), "{st:?}");
    let mine = &st.parked[0];
    assert_eq!(mine.device.api_bases, [e.server.base()]);
    assert_eq!(mine.cursors["record"][REC], 2);
    assert_eq!(mine.cursors["record"][later], 2);

    // Its next pass takes it back as it was: nothing sent twice, no new
    // registration.
    let n = e.server.uploads().len();
    let s = t.upload_now().unwrap();
    assert!(!s.registered && s.chunks == 0, "{s:?}");
    assert_eq!(e.server.uploads().len(), n);
    let st = e.state();
    assert_eq!(st.device.as_ref().unwrap().api_bases, [e.server.base()]);
    assert_eq!(st.cursor("record", later), 2);
    assert_eq!(st.parked[0].device.id, "other");
    assert!(st.parked[0].cursors.is_empty());
}

/// The account's flag binds only where it came from: a registration with
/// another API, whose account requires telemetry, neither keeps this
/// configuration from switching off nor is reported as its account's.
#[test]
fn a_flag_from_another_api_binds_nothing_here() {
    let e = env();
    // A flag stored with no registration at all is nobody else's: it stands
    // (and there is no one to ask).
    let st = ServiceState {
        upload_enabled: true,
        required: true,
        ..ServiceState::default()
    };
    st.save(&e.state).unwrap();
    let t = e.open();
    assert!(t.status().required);
    assert!(matches!(t.set_upload_enabled(false), Err(Error::Required)));
    assert!(t.refresh_status().unwrap().required);
    assert!(e.server.requests().is_empty());
    drop(t);

    let elsewhere = "http://127.0.0.1:9".to_string();
    let mut st = ServiceState {
        upload_enabled: true,
        required: true,
        required_notice_pending: true,
        ..ServiceState::default()
    };
    st.device = Some(device("dev-x", "tok-x", &elsewhere));
    st.save(&e.state).unwrap();

    // Its own configuration is bound (and asks nobody here).
    let theirs = Telemetry::open(e.cfg().with_api_bases(vec![elsewhere])).unwrap();
    assert!(theirs.status().required && theirs.status().required_notice_pending);
    assert!(matches!(
        theirs.set_upload_enabled(false),
        Err(Error::Required)
    ));

    let t = e.open();
    let s = t.status();
    assert!(s.upload_enabled && !s.required && !s.required_notice_pending);
    assert_eq!(s.device_id, None);
    // Nobody to ask: no request at all.
    assert!(!t.refresh_status().unwrap().required);
    assert!(e.server.requests().is_empty());
    t.set_upload_enabled(false).unwrap();
    let st = e.state();
    assert!(!st.upload_enabled);
    // The other API's registration is left as it was.
    assert_eq!(st.device.as_ref().unwrap().id, "dev-x");
    assert!(st.required && st.required_notice_pending);

    // A parked registration with this API is this configuration's: its flag
    // binds, and the notice it owes is the one shown.
    let mut st = e.state();
    st.upload_enabled = true;
    st.device = Some(device(
        "mine",
        &e.server.add_device("mine"),
        &e.server.base(),
    ));
    st.required = true;
    st.required_notice_pending = true;
    st.park();
    st.device = Some(device("dev-x", "tok-x", "http://127.0.0.1:9"));
    st.required = true;
    st.required_notice_pending = true;
    st.save(&e.state).unwrap();
    let s = t.reload().unwrap();
    assert!(s.required && s.required_notice_pending);
    assert_eq!(s.device_id.as_deref(), Some("mine"));
    assert!(matches!(t.set_upload_enabled(false), Err(Error::Required)));
    t.acknowledge_notice().unwrap();
    let st = e.state();
    assert!(!st.parked[0].required_notice_pending);
    assert!(
        st.required_notice_pending,
        "the other API's notice is its own"
    );
    // Asked again (the server no longer requires it), it lets go.
    assert!(!t.refresh_status().unwrap().required);
    t.set_upload_enabled(false).unwrap();
}

/// A device registered with the built-in API keeps working when a later
/// release lists other fronts for it: its token goes to the new front, with
/// no new registration and nothing sent again.
#[test]
fn a_builtin_device_follows_the_releases_fronts() {
    let e = env();
    let rec = e.rec.join(REC);
    append(&rec, b"a\n");
    let a = FakeServer::start();
    let b = a.another_front();
    let t = e.open_builtin(&[a.base()]);
    t.set_upload_enabled(true).unwrap();
    assert!(t.upload_now().unwrap().registered);
    let dev = e.state().device.unwrap();
    assert!(dev.builtin);
    assert_eq!(dev.api_bases, [a.base()]);
    drop(t);

    // The next release lists [A, B], and A no longer answers (blocked,
    // retired).
    let (dead, n) = (a.base(), b.requests().len());
    drop(a);
    append(&rec, b"b\n");
    let t = e.open_builtin(&[dead, b.base()]);
    assert_eq!(t.status().device_id.as_deref(), Some(dev.id.as_str()));
    let s = t.upload_now().unwrap();
    assert!(!s.registered && s.bytes_sent == 2, "{s:?}");
    let reqs = &b.requests()[n..];
    assert_eq!(registrations(reqs), 0);
    assert!(reqs.iter().any(|r| r.path == "/v1/telemetry/upload"));
    assert!(
        reqs.iter()
            .all(|r| r.front == b.base() && r.token.as_deref() == Some(dev.token.as_str())),
        "{reqs:?}"
    );
    assert_eq!(b.stored(&dev.id, "record", REC), b"a\nb\n");
    assert_eq!(e.state().device.unwrap(), dev);
}

/// An override is another API even where it names the built-in front: a
/// device of its own there, the built-in token never sent to it. The
/// built-in registration is parked, and taken back as it was when the
/// configuration that names no API runs again.
#[test]
fn an_override_never_gets_the_builtin_token() {
    let e = env();
    let rec = e.rec.join(REC);
    append(&rec, b"a\n");
    let s = &e.server;
    let builtin = e.open_builtin(&[s.base()]);
    builtin.set_upload_enabled(true).unwrap();
    builtin.upload_now().unwrap();
    let b = e.state().device.unwrap();
    assert!(b.builtin);

    // `SPORA_API` set to that very address.
    let over = e.open();
    assert_eq!(over.status().device_id, None);
    let n = s.requests().len();
    assert!(over.upload_now().unwrap().registered);
    let reqs = &s.requests()[n..];
    assert_eq!(registrations(reqs), 1);
    assert!(!carried(reqs, &b.token));
    let o = e.state().device.unwrap();
    assert!(!o.builtin);
    assert_eq!(o.api_bases, [s.base()]);
    assert_ne!(o.id, b.id);
    assert_eq!(s.stored(&o.id, "record", REC), b"a\n");
    let st = e.state();
    assert_eq!(st.parked.len(), 1);
    assert_eq!(st.parked[0].device, b);
    assert_eq!(st.parked[0].cursors["record"][REC], 2);

    // The built-in configuration again: its own registration, nothing sent
    // twice, the override's token not sent.
    append(&rec, b"b\n");
    let n = s.requests().len();
    let sum = builtin.upload_now().unwrap();
    assert!(!sum.registered && sum.bytes_sent == 2, "{sum:?}");
    let reqs = &s.requests()[n..];
    assert_eq!(registrations(reqs), 0);
    assert!(carried(reqs, &b.token) && !carried(reqs, &o.token));
    assert_eq!(e.state().device.unwrap(), b);
    assert_eq!(s.stored(&b.id, "record", REC), b"a\nb\n");
    assert_eq!(over.reload().unwrap().device_id, Some(o.id));
}

/// The other way round: a device registered with an override — or stored
/// without saying, by a development build — is no built-in device, even
/// one minted at the built-in front. The configuration that names no API
/// registers its own, and the override's token never goes to a built-in
/// front.
#[test]
fn the_builtin_api_never_gets_an_override_token() {
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let s = &e.server;
    let over = e.open();
    over.set_upload_enabled(true).unwrap();
    over.upload_now().unwrap();
    // As a build from before devices said which API they belong to left it.
    let path = ServiceState::path(&e.state);
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(raw["device"]["builtin"], false);
    raw["device"].as_object_mut().unwrap().remove("builtin");
    std::fs::write(&path, raw.to_string()).unwrap();
    let o = e.state().device.unwrap();
    assert!(!o.builtin);

    let front = s.another_front();
    let builtin = e.open_builtin(&[s.base(), front.base()]);
    assert_eq!(builtin.status().device_id, None);
    let n = s.requests().len();
    assert!(builtin.upload_now().unwrap().registered);
    let reqs = &s.requests()[n..];
    assert_eq!(registrations(reqs), 1);
    assert!(!carried(reqs, &o.token));
    let b = e.state().device.unwrap();
    assert!(b.builtin);
    assert_eq!(s.stored(&b.id, "record", REC), b"a\n");
    assert_eq!(e.state().parked[0].device, o);
}

/// Each account's flag binds the configuration of its own API only, both
/// ways between the built-in API and an override.
#[test]
fn builtin_and_override_flags_bind_their_own_configurations() {
    let e = env();
    let other = FakeServer::start();
    let builtin = e.open_builtin(&[e.server.base()]);
    let over = Telemetry::open(e.cfg().with_api_bases(vec![other.base()])).unwrap();
    builtin.set_upload_enabled(true).unwrap();
    builtin.upload_now().unwrap();
    // The override's account requires telemetry.
    other.set_required(true);
    over.upload_now().unwrap();
    let (b, o) = (builtin.reload().unwrap(), over.reload().unwrap());
    assert!(o.required && o.required_notice_pending);
    assert!(!b.required && !b.required_notice_pending);
    assert!(b.device_id.is_some() && o.device_id.is_some());
    assert!(matches!(
        over.set_upload_enabled(false),
        Err(Error::Required)
    ));
    builtin.set_upload_enabled(false).unwrap();

    // Now the built-in account requires it and the override's does not.
    e.server.set_required(true);
    other.set_required(false);
    builtin.refresh_status().unwrap();
    over.refresh_status().unwrap();
    let (b, o) = (builtin.reload().unwrap(), over.reload().unwrap());
    assert!(b.required && b.required_notice_pending);
    assert!(!o.required && !o.required_notice_pending);
    assert!(matches!(
        builtin.set_upload_enabled(false),
        Err(Error::Required)
    ));
    over.set_upload_enabled(false).unwrap();

    // Neither token ever reached the other's server.
    let st = e.state();
    let devices: Vec<&Device> = st
        .device
        .iter()
        .chain(st.parked.iter().map(|p| &p.device))
        .collect();
    let builtin_token = &devices.iter().find(|d| d.builtin).unwrap().token;
    let override_token = &devices.iter().find(|d| !d.builtin).unwrap().token;
    assert!(!carried(&other.requests(), builtin_token));
    assert!(!carried(&e.server.requests(), override_token));
}

#[test]
fn redirects_are_not_followed() {
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let moved = FakeServer::start();
    let location = format!("{}/v1/devices", e.server.base());
    moved.state().canned = vec![Canned {
        status: 301,
        headers: vec![("Location".into(), location)],
        body: b"moved".to_vec(),
    }];
    let t = Telemetry::open(e.cfg().with_api_bases(vec![moved.base(), e.server.base()])).unwrap();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    assert_eq!(moved.requests().len(), 1);
    // A followed 301 would have turned the POST into a GET.
    assert!(
        e.server
            .requests()
            .iter()
            .all(|r| !(r.method == "GET" && r.path == "/v1/devices"))
    );
    assert_eq!(e.stored("record", REC), b"a\n");

    // An authenticated request redirected: the base failed, the device stays.
    // (Alone: two fake servers are not two fronts of one API.)
    let t = e.open();
    let dev = e.device();
    e.server.state().canned = vec![Canned {
        status: 302,
        headers: vec![(
            "Location".into(),
            format!("{}/v1/devices/me", e.server.base()),
        )],
        body: Vec::new(),
    }];
    append(&e.rec.join(REC), b"b\n");
    let s = t.upload_now().unwrap(); // the status check fails; uploads go
    assert!(!s.status_checked);
    assert_eq!(e.device(), dev);
    assert_eq!(e.stored("record", REC), b"a\nb\n");
    assert!(
        e.server
            .requests()
            .iter()
            .filter(|r| r.path != "/v1/devices")
            .all(|r| r.authorized)
    );
}

#[test]
fn an_error_answer_keeps_its_status_whatever_its_body() {
    let e = env();
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    let canned = |status, body: Vec<u8>, headers: Vec<(String, String)>| Canned {
        status,
        headers,
        body,
    };
    e.server.state().canned = vec![
        canned(503, vec![b'x'; 200 * 1024], Vec::new()),
        canned(500, vec![0xff, 0xfe, 0x00, 0xc3], Vec::new()),
        canned(
            429,
            br#"{"error":"throttled"}"#.to_vec(),
            vec![("Retry-After".into(), "120".into())],
        ),
    ];
    let status = |r: Result<crate::PassSummary, Error>| match r {
        Err(Error::Api(ApiError::Status {
            status,
            retry_after,
            ..
        })) => (status, retry_after),
        r => panic!("{r:?}"),
    };
    assert_eq!(status(t.upload_now()), (503, None));
    assert_eq!(status(t.upload_now()), (500, None));
    assert_eq!(
        status(t.upload_now()),
        (429, Some(Duration::from_secs(120)))
    );
    assert_eq!(
        t.status().last_error.as_deref(),
        Some("http 429 (throttled)")
    );
}

#[cfg(unix)]
#[test]
fn a_directory_that_cannot_be_listed_keeps_its_cursors() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    assert_eq!(e.cursor("record", REC), Some(2));
    std::fs::set_permissions(&e.rec, std::fs::Permissions::from_mode(0o000)).unwrap();
    let listable = std::fs::read_dir(&e.rec).is_ok();
    if !listable {
        t.upload_now().unwrap();
    }
    std::fs::set_permissions(&e.rec, std::fs::Permissions::from_mode(0o755)).unwrap();
    if listable {
        return; // root lists anything; nothing to test
    }
    assert_eq!(e.cursor("record", REC), Some(2));
    assert!(t.status().last_error.unwrap().contains("cannot list"));
}

/// The uploader reads the file its listing found, not whatever has taken
/// that name since (a link to a file the directory's owner may not read).
#[cfg(unix)]
#[test]
fn a_listed_file_swapped_for_a_symlink_is_not_read() {
    let e = env();
    let secret = e._tmp.path().join("secret");
    std::fs::write(&secret, b"secret\n").unwrap();
    let later = "20261019T110000Z-client-ffffffff.jsonl";
    append(&e.rec.join(REC), b"a\n");
    append(&e.rec.join(later), b"b\n");
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    // While the first file goes, the second (listed already) becomes a link.
    let path = e.rec.join(later);
    let mut fired = false;
    e.server.state().on_request = Some(Box::new(move |r: &Req| {
        if r.path == "/v1/telemetry/upload" && !fired {
            fired = true;
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&secret, &path).unwrap();
        }
    }));
    let s = t.upload_now().unwrap();
    assert_eq!((s.files, s.skipped_files), (1, 1));
    assert_eq!(e.stored("record", REC), b"a\n");
    assert!(e.server.uploads().iter().all(|r| r.query["file"] != later));
    // The link is no file of the stream: the next listing leaves it out.
    let s = t.upload_now().unwrap();
    assert_eq!((s.chunks, s.skipped_files), (0, 0));
    assert!(e.state().refused.is_empty());
}

#[cfg(unix)]
#[test]
fn no_registration_without_a_state_that_can_keep_it() {
    use std::os::unix::fs::PermissionsExt;
    let e = env();
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    std::fs::set_permissions(&e.state, std::fs::Permissions::from_mode(0o500)).unwrap();
    let writable = std::fs::write(e.state.join("probe"), b"").is_ok();
    let r = t.upload_now();
    std::fs::set_permissions(&e.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    if writable {
        return; // root writes anywhere; nothing to test
    }
    assert!(matches!(r, Err(Error::Io(_))), "{r:?}");
    assert!(e.server.requests().is_empty());
}

#[test]
fn a_crash_file_goes_in_one_request() {
    let e = env();
    let text = lines("c", 5000); // well over one chunk
    assert!(text.len() > crate::upload::MAX_CHUNK);
    append(&e.log.join(CRASH), text.as_bytes());
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap();
    let ups = e.server.uploads();
    assert_eq!(ups.len(), 1);
    assert_eq!(e.stored("crash", CRASH), text.as_bytes());
}

#[test]
fn a_platform_the_api_does_not_know_never_registers() {
    let e = env();
    let mut cfg = e.cfg();
    cfg.platform = "freebsd".into();
    let t = Telemetry::open(cfg).unwrap();
    assert!(matches!(t.set_upload_enabled(true), Err(Error::Config(_))));
    let mut st = e.state();
    st.upload_enabled = true;
    st.save(&e.state).unwrap();
    assert!(matches!(t.upload_now(), Err(Error::Config(_))));
    assert!(e.server.requests().is_empty());
}

#[test]
fn halting_ends_a_pass_between_chunks() {
    let e = env();
    append(&e.log.join(DIAG), lines("d", 6000).as_bytes()); // > one chunk
    let api = Api::new(&[e.server.base()], "0.1.0-test").unwrap();
    let store = StateStore::open(&e.state).unwrap();
    store.modify(|s| s.upload_enabled = true).unwrap();
    let asked = std::cell::Cell::new(0);
    let halt = || {
        asked.set(asked.get() + 1);
        asked.get() > 1
    };
    let pass = Pass {
        api: &api,
        store: &store,
        platform: "linux",
        record_dirs: &[],
        log_dir: Some(&e.log),
        status_interval: Duration::from_secs(3600),
        refresh_status: false,
        halt: &halt,
    };
    let s = pass.run(false).unwrap();
    assert_eq!((s.chunks, s.log_chunks), (1, 1));
    assert_eq!(e.server.uploads().len(), 1);
    // Stopped in the middle of its file, which still counts.
    assert!(s.halted);
    assert_eq!(s.files, 1);
    assert!(s.bytes_sent > 0);
}

#[test]
fn a_pass_stops_when_another_process_switches_uploads_off() {
    let e = env();
    append(&e.rec.join(REC), lines("r", 3).as_bytes());
    append(&e.log.join(DIAG), lines("d", 6000).as_bytes()); // > one chunk
    let t = e.open();
    t.set_upload_enabled(true).unwrap();
    t.upload_now().unwrap(); // registered; both files sent
    append(&e.rec.join(REC), lines("r2", 2).as_bytes());
    append(&e.log.join(DIAG), lines("d2", 6000).as_bytes());

    // Another process sharing the state switches uploads off while this
    // pass is under way (right before its first chunk): the chunk in
    // flight goes, nothing after it.
    let api = Api::new(&[e.server.base()], "0.1.0-test").unwrap();
    let store = StateStore::open(&e.state).unwrap();
    let other = StateStore::open(&e.state).unwrap();
    let asked = std::cell::Cell::new(0);
    let halt = || {
        asked.set(asked.get() + 1);
        if asked.get() == 1 {
            other.modify(|s| s.upload_enabled = false).unwrap();
        }
        false
    };
    let pass = Pass {
        api: &api,
        store: &store,
        platform: "linux",
        record_dirs: std::slice::from_ref(&e.rec),
        log_dir: Some(&e.log),
        status_interval: Duration::from_secs(3600),
        refresh_status: false,
        halt: &halt,
    };
    let before = e.server.uploads().len();
    let s = pass.run(false).unwrap();
    assert_eq!(e.server.uploads().len(), before + 1);
    assert_eq!(s.chunks, 1);
    assert!(s.halted, "{s:?}");
    assert_eq!(s.files, 1);
    assert_eq!(
        e.stored("record", REC),
        std::fs::read(e.rec.join(REC)).unwrap()
    );

    // The same mid-file: switched off after the log's first chunk. A note
    // about a file the pass never reached stays.
    store
        .modify(|s| {
            s.upload_enabled = true;
            s.last_error = Some("record/x: refused".into());
        })
        .unwrap();
    append(&e.log.join(DIAG), lines("d3", 6000).as_bytes());
    asked.set(0);
    let before = e.server.uploads().len();
    let s = pass.run(false).unwrap();
    assert_eq!(e.server.uploads().len(), before + 1);
    assert_eq!((s.chunks, s.log_chunks, s.files), (1, 1, 1));
    assert!(s.halted && s.bytes_sent > 0);
    let st = e.state();
    assert!(!st.upload_enabled);
    assert_eq!(st.last_error.as_deref(), Some("record/x: refused"));

    // A pass that gets through everything was not halted, and clears it.
    t.set_upload_enabled(true).unwrap();
    let s = t.upload_now().unwrap();
    assert!(!s.halted && s.files == 1 && s.chunks >= 1, "{s:?}");
    assert_eq!(
        e.stored("log", DIAG),
        std::fs::read(e.log.join(DIAG)).unwrap()
    );
    assert_eq!(t.status().last_error, None);
}

#[test]
fn dormancy_holds_every_pass_back() {
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let t = e.open();
    t.set_dormant(true);
    t.start();
    t.set_upload_enabled(true).unwrap();
    t.nudge();
    std::thread::sleep(Duration::from_millis(300));
    assert!(e.server.requests().is_empty());
    t.set_dormant(false);
    wait_for(|| t.status().device_id.is_some() && e.stored("record", REC) == b"a\n");
    t.stop();
}

#[test]
fn finish_sends_what_is_left_and_stops_the_thread() {
    let e = env();
    let t = e.open();
    // Not running: nothing to finish.
    assert!(!t.finish(Duration::from_secs(1)));
    t.start();
    t.set_upload_enabled(true).unwrap();
    wait_for(|| t.status().device_id.is_some());
    // What the run wrote last; the thread's next pass is an hour away.
    append(&e.rec.join(REC), lines("r", 3).as_bytes());
    assert!(t.finish(Duration::from_secs(10)));
    assert_eq!(
        e.stored("record", REC),
        std::fs::read(e.rec.join(REC)).unwrap()
    );
    let n = e.server.requests().len();
    t.nudge();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(e.server.requests().len(), n);

    // Uploads off: no pass, and the thread still stops.
    t.start();
    t.set_upload_enabled(false).unwrap();
    assert!(!t.finish(Duration::from_secs(5)));
    assert_eq!(e.server.requests().len(), n);
}

/// A `finish` that ran out of time before the thread took its request
/// leaves nothing behind: a later `start` gets an uploader that keeps
/// going, not one that runs a last pass and exits.
#[test]
fn start_after_a_timed_out_finish_keeps_uploading() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let e = env();
    append(&e.rec.join(REC), b"a\n");
    let t = e.open();
    // The first upload takes a while to be answered.
    let held = Arc::new(AtomicBool::new(false));
    let h = held.clone();
    e.server.state().on_request = Some(Box::new(move |r: &Req| {
        if r.path == "/v1/telemetry/upload" && !h.swap(true, Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(800));
        }
    }));
    t.start();
    t.set_upload_enabled(true).unwrap();
    wait_for(|| held.load(Ordering::SeqCst));
    assert!(!t.finish(Duration::from_millis(100)));
    // The old thread ends after its answer.
    wait_for(|| e.stored("record", REC) == b"a\n");
    std::thread::sleep(Duration::from_millis(100));

    t.start();
    // Its first pass (which a request left standing would make its last).
    std::thread::sleep(Duration::from_millis(200));
    append(&e.rec.join(REC), b"b\n");
    t.nudge();
    wait_for(|| e.stored("record", REC) == b"a\nb\n");
    append(&e.rec.join(REC), b"c\n");
    t.nudge();
    wait_for(|| e.stored("record", REC) == b"a\nb\nc\n");
    t.stop();
}

fn device(id: &str, token: &str, base: &str) -> Device {
    Device {
        id: id.into(),
        token: token.into(),
        api_bases: vec![base.into()],
        builtin: false,
        extra: serde_json::Map::new(),
    }
}

fn wait_for(mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < deadline, "timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
}
