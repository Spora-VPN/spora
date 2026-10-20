use super::*;
use std::sync::mpsc::sync_channel;

const SECRET: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfGhIj"; // 48

fn runs() -> &'static RunList {
    Box::leak(Box::new(RunList(Mutex::new(Vec::new()))))
}

fn lines(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn log_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = list_matching(dir, is_log_file)
        .into_iter()
        .map(|f| f.path)
        .collect();
    v.sort();
    v
}

fn set_age(path: &Path, age: Duration) {
    let f = std::fs::File::options().write(true).open(path).unwrap();
    f.set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() - age))
        .unwrap();
}

#[test]
fn file_filter() {
    assert_eq!(file_level("spora_core::record"), LevelFilter::Debug);
    assert_eq!(file_level("spora_service"), LevelFilter::Debug);
    assert_eq!(file_level("relay_client::register"), LevelFilter::Debug);
    assert_eq!(file_level("app"), LevelFilter::Debug);
    assert_eq!(file_level("quinn_proto::connection"), LevelFilter::Warn);
    assert_eq!(file_level("quinn_udp"), LevelFilter::Warn);
    assert_eq!(file_level("rustls::client"), LevelFilter::Warn);
    assert_eq!(file_level("ureq_proto::client"), LevelFilter::Warn);
    assert_eq!(file_level("smoltcp::iface"), LevelFilter::Warn);
    assert_eq!(file_level("h2"), LevelFilter::Warn);
    assert_eq!(file_level("tokio::runtime"), LevelFilter::Info);
    assert_eq!(file_level("netstack_smoltcp"), LevelFilter::Info);
    // Per-flow lines and periodic statistics never, despite the prefix.
    assert_eq!(file_level(spora_core::FLOW_LOG_TARGET), LevelFilter::Off);
    assert_eq!(file_level(spora_core::STATS_LOG_TARGET), LevelFilter::Off);
    assert_eq!(file_level("spora_core::server"), LevelFilter::Debug);
}

#[test]
fn raw_request_traces_reach_no_sink() {
    let m = |level, target| Metadata::builder().level(level).target(target).build();
    assert!(withheld(&m(Level::Trace, "ureq_proto::util")));
    assert!(withheld(&m(Level::Error, "ureq_proto::client")));
    assert!(!withheld(&m(Level::Trace, "ureq::unversioned")));
    assert!(!withheld(&m(Level::Trace, "spora_core")));
    assert!(!LOGGER.enabled(&m(Level::Trace, "ureq_proto::util")));
    assert!(WITHHELD_TARGETS.contains(&"ureq_proto"));
}

#[test]
fn redaction() {
    let url = format!("https://spora.to/s/{SECRET}?r=167.71.66.250:443");
    assert_eq!(
        redact(&format!("dialing {url} now"), false),
        "dialing https://spora.to/s/<redacted>?r=167.71.66.250:443 now"
    );
    // Two in one message.
    assert_eq!(
        redact(&format!("{url} {url}"), false),
        "https://spora.to/s/<redacted>?r=167.71.66.250:443 \
         https://spora.to/s/<redacted>?r=167.71.66.250:443"
    );
    // Shorter runs are not secrets.
    let short = format!("/s/{}", &SECRET[..39]);
    assert_eq!(redact(&short, false), short);
    assert!(matches!(redact("no urls here", false), Cow::Borrowed(_)));
    // An earlier `/s/` must not hide a later one.
    assert_eq!(redact(&format!("/s/s/{SECRET}"), false), "/s/s/<redacted>");
    // At a cut end, any run may be the head of a secret.
    assert_eq!(redact("see /s/AbCd", true), "see /s/<redacted>");
    assert_eq!(redact("see /s/AbCd", false), "see /s/AbCd");
    assert_eq!(redact("see /s/AbCd x", true), "see /s/AbCd x");
}

#[test]
fn redaction_of_encoded_urls() {
    // JSON-escaped (org.json escapes '/'), twice over.
    assert_eq!(
        redact(
            &format!(r#"{{"url":"https:\/\/spora.to\/s\/{SECRET}?r=x"}}"#),
            false
        ),
        r#"{"url":"https:\/\/spora.to\/s\/<redacted>?r=x"}"#
    );
    assert_eq!(
        redact(&format!(r"https:\\/\\/spora.to\\/s\\/{SECRET}"), false),
        r"https:\\/\\/spora.to\\/s\\/<redacted>"
    );
    // Percent-encoded, either case, once or twice, and mixed.
    for (form, want) in [
        (
            format!("u=https%3A%2F%2Fspora.to%2Fs%2F{SECRET}%3Fr"),
            "u=https%3A%2F%2Fspora.to%2Fs%2F<redacted>%3Fr",
        ),
        (
            format!("u=spora.to%2fs%2f{SECRET}"),
            "u=spora.to%2fs%2f<redacted>",
        ),
        (
            format!("u=spora.to%252Fs%252F{SECRET}"),
            "u=spora.to%252Fs%252F<redacted>",
        ),
        (format!("got /s%2F{SECRET}"), "got /s%2F<redacted>"),
        (format!("got %2Fs/{SECRET}"), "got %2Fs/<redacted>"),
    ] {
        assert_eq!(redact(&form, false), want);
    }
    // Case.
    assert_eq!(
        redact(&format!("HTTPS://SPORA.TO/S/{SECRET}"), false),
        "HTTPS://SPORA.TO/S/<redacted>"
    );
    // Not a path segment: a word ending in s.
    let plain = format!("bytes/{SECRET}");
    assert_eq!(redact(&plain, false), plain);
}

#[test]
fn run_id_only_when_unambiguous() {
    let r = runs();
    assert_eq!(r.current(), None);
    r.opened("aaaa");
    assert_eq!(r.current().as_deref(), Some("aaaa"));
    // A share and a connect at once: a line could be either's.
    r.opened("bbbb");
    assert_eq!(r.current(), None);
    assert_eq!(r.try_current(), None);
    r.closed("aaaa");
    assert_eq!(r.current().as_deref(), Some("bbbb"));
    r.closed("bbbb");
    assert_eq!(r.current(), None);
}

#[test]
fn a_noisy_site_is_held_to_its_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = DiagConfig::in_dir(tmp.path());
    cfg.site_burst = 5;
    cfg.site_refill = Duration::from_secs(3600);
    let sink = FileSink::start(cfg, runs()).unwrap();
    let noisy = Some(("spora_core::server", 126));
    for i in 0..1000 {
        sink.submit(
            Level::Warn,
            "rust",
            "spora_core::server",
            noisy,
            format_args!("full {i}"),
            None,
        );
        if i == 500 {
            // Another site has a budget of its own.
            sink.submit(
                Level::Warn,
                "rust",
                "spora_core::server",
                Some(("spora_core::server", 422)),
                format_args!("other"),
                None,
            );
        }
    }
    // Lines without a site (platform lines) are budgeted per tag.
    for i in 0..100 {
        sink.submit(
            Level::Info,
            "app",
            "Chatty",
            None,
            format_args!("app {i}"),
            None,
        );
    }
    // A flush summarizes at once.
    assert!(sink.flush(Duration::from_secs(5)));
    let ls = lines(&log_files(tmp.path())[0]);
    let msgs: Vec<&str> = ls.iter().map(|l| l["msg"].as_str().unwrap()).collect();
    let full = msgs.iter().filter(|m| m.starts_with("full ")).count();
    assert_eq!(full, 5);
    assert!(msgs.contains(&"other"));
    let app = msgs.iter().filter(|m| m.starts_with("app ")).count();
    assert_eq!(app, 5 * TAG_BUDGET as usize);
    // One summary, or more if the timer fired mid-loop on a slow machine.
    let summaries: Vec<_> = ls
        .iter()
        .filter(|l| l["msg"].as_str().unwrap().contains(":126"))
        .collect();
    assert!(!summaries.is_empty());
    for s in &summaries {
        assert_eq!(s["src"], "diag");
        let n = s["dropped"].as_u64().unwrap();
        assert_eq!(
            s["msg"],
            format!("suppressed {n} lines from spora_core::server:126 (over its rate limit)")
        );
    }
    let held: u64 = summaries
        .iter()
        .map(|s| s["dropped"].as_u64().unwrap())
        .sum();
    assert_eq!(held, 995);
    assert!(
        ls.iter()
            .any(|l| l["msg"].as_str().unwrap().contains("from Chatty"))
    );
}

#[test]
fn held_back_lines_are_summarized_without_a_flush() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = DiagConfig::in_dir(tmp.path());
    cfg.site_burst = 1;
    let sink = FileSink::start(cfg, runs()).unwrap();
    for _ in 0..3 {
        sink.submit(
            Level::Info,
            "rust",
            "spora",
            Some(("spora", 1)),
            format_args!("x"),
            None,
        );
    }
    // Nothing else is logged: the writer wakes for the summary on its own.
    let file = log_files(tmp.path()).remove(0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::fs::read_to_string(&file)
        .unwrap()
        .contains("suppressed")
    {
        assert!(Instant::now() < deadline, "no summary");
        std::thread::sleep(Duration::from_millis(20));
    }
    let ls = lines(&file);
    let summary = ls
        .iter()
        .find(|l| l["src"] == "diag" && l.get("dropped").is_some())
        .unwrap();
    assert_eq!(summary["dropped"], 2);
    assert!(!sink.limiter.pending());
}

#[test]
fn render_bounds_and_marks() {
    let (m, t) = render(format_args!("plain {}", 42), MAX_MSG_BYTES);
    assert_eq!((m.as_str(), t), ("plain 42", false));

    let big = "é".repeat(MAX_MSG_BYTES); // 2 bytes each
    let (m, t) = render(format_args!("{big}"), MAX_MSG_BYTES);
    assert!(t);
    assert!(m.len() <= MAX_MSG_BYTES);
    assert!(m.len() >= MAX_MSG_BYTES - 1);

    // A secret straddling the cut leaves no part of itself behind.
    let pad = "x".repeat(MAX_MSG_BYTES - 20);
    let (m, t) = render(format_args!("{pad}/s/{SECRET}"), MAX_MSG_BYTES);
    assert!(t);
    assert!(!m.contains(&SECRET[..10]), "{}", &m[m.len() - 40..]);
    assert!(m.len() <= MAX_MSG_BYTES);
}

#[test]
fn header_and_line_format() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = DiagConfig::in_dir(tmp.path()).with_platform("android");
    let sink = FileSink::start(cfg, runs()).unwrap();
    sink.submit(
        Level::Warn,
        "rust",
        "spora_core::client",
        Some(("spora_core::client", 7)),
        format_args!("dial https://spora.to/s/{SECRET}?r=x failed"),
        Some("00aa11bb22cc33dd".into()),
    );
    sink.submit(
        Level::Debug,
        "app",
        "MainActivity",
        None,
        format_args!("tap"),
        None,
    );
    let long = "y".repeat(MAX_MSG_BYTES + 100);
    sink.submit(
        Level::Error,
        "rust",
        "t",
        None,
        format_args!("{long}"),
        None,
    );
    // A target is cut like a message.
    let tag = "T".repeat(MAX_TARGET_BYTES * 4);
    sink.submit(Level::Info, "app", &tag, None, format_args!("tagged"), None);
    assert!(sink.flush(Duration::from_secs(5)));

    let files = log_files(tmp.path());
    assert_eq!(files.len(), 1);
    let name = files[0].file_name().unwrap().to_str().unwrap().to_string();
    assert!(name.starts_with("diag-") && name.ends_with(&format!("-{}.jsonl", std::process::id())));
    // diag-YYYYmmddTHHMMSSmmmZ-pid.jsonl
    assert_eq!(name.split('-').nth(1).unwrap().len(), 19);

    let raw = std::fs::read_to_string(&files[0]).unwrap();
    let ls = lines(&files[0]);
    assert_eq!(ls.len(), 5);
    let h = &ls[0];
    assert_eq!(h["src"], "diag");
    assert_eq!(h["msg"], "log opened");
    assert_eq!(h["lvl"], "I");
    assert_eq!(h["platform"], "android");
    assert_eq!(h["pid"], std::process::id());
    assert!(h["build"]["version"].is_string());
    assert!(h["build"]["target"].is_string());

    let w = &ls[1];
    assert_eq!(w["lvl"], "W");
    assert_eq!(w["src"], "rust");
    assert_eq!(w["tgt"], "spora_core::client");
    assert_eq!(w["run"], "00aa11bb22cc33dd");
    assert_eq!(w["msg"], "dial https://spora.to/s/<redacted>?r=x failed");
    assert!(w.get("trunc").is_none());
    let ts = w["ts"].as_str().unwrap();
    assert_eq!(ts.len(), "2026-10-19T12:00:00.123Z".len());
    assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T');
    assert!(!raw.contains(SECRET));
    // Documented key order.
    let second = raw.lines().nth(1).unwrap();
    let pos = |k: &str| second.find(&format!("\"{k}\":")).unwrap();
    assert!(pos("ts") < pos("lvl") && pos("lvl") < pos("src") && pos("src") < pos("tgt"));
    assert!(pos("tgt") < pos("run") && pos("run") < pos("msg"));

    let a = &ls[2];
    assert_eq!(
        (a["lvl"].as_str(), a["src"].as_str()),
        (Some("D"), Some("app"))
    );
    assert_eq!(a["tgt"], "MainActivity");
    assert!(a.get("run").is_none());

    let t = &ls[3];
    assert_eq!(t["trunc"], true);
    assert_eq!(t["msg"].as_str().unwrap().len(), MAX_MSG_BYTES);

    assert_eq!(ls[4]["tgt"].as_str().unwrap().len(), MAX_TARGET_BYTES);
}

#[test]
fn header_is_on_disk_before_any_line() {
    let tmp = tempfile::tempdir().unwrap();
    let _sink = FileSink::start(DiagConfig::in_dir(tmp.path()), runs()).unwrap();
    // No line, no flush: a process that dies now still leaves a header.
    let ls = lines(&log_files(tmp.path())[0]);
    assert_eq!(ls.len(), 1);
    assert_eq!(ls[0]["msg"], "log opened");
}

#[test]
fn a_tiny_rotate_size_is_no_loop() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = DiagConfig::in_dir(tmp.path());
    cfg.rotate_bytes = 0;
    let sink = FileSink::start(cfg, runs()).unwrap();
    for i in 0..10 {
        sink.submit(
            Level::Info,
            "rust",
            "spora",
            None,
            format_args!("n{i}"),
            None,
        );
    }
    assert!(sink.flush(Duration::from_secs(5)));
    let files = log_files(tmp.path());
    assert_eq!(files.len(), 1, "the floor ({MIN_ROTATE_BYTES}) holds");
    assert_eq!(lines(&files[0]).len(), 11);
}

#[test]
fn rotation_and_caps() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::create_dir_all(dir).unwrap();
    // Leftovers: an expired log, an expired crash, 24 recent crashes.
    let stale = dir.join("diag-20200101T000000000Z-1.jsonl");
    std::fs::write(&stale, b"{}\n").unwrap();
    set_age(&stale, Duration::from_secs(15 * 24 * 3600));
    let old_crash = dir.join("crash-20200101T000000000Z-rust.txt");
    std::fs::write(&old_crash, b"x\n").unwrap();
    set_age(&old_crash, Duration::from_secs(31 * 24 * 3600));
    for i in 0..24 {
        let p = dir.join(format!("crash-2026010{}T0000000{i:02}Z-rust.txt", i % 10));
        std::fs::write(&p, b"x\n").unwrap();
        set_age(&p, Duration::from_secs(3600 + i as u64));
    }
    let unrelated = dir.join("notes.txt");
    std::fs::write(&unrelated, b"keep me").unwrap();

    let mut cfg = DiagConfig::in_dir(dir);
    cfg.rotate_bytes = 4096;
    cfg.max_total_bytes = 16 * 1024;
    cfg.site_burst = 10_000;
    let sink = FileSink::start(cfg, runs()).unwrap();
    assert!(!stale.exists());
    assert!(!old_crash.exists());
    assert_eq!(list_matching(dir, crash::is_crash_file).len(), 20);
    assert!(unrelated.exists());

    for i in 0..1000 {
        sink.submit(
            Level::Info,
            "rust",
            "spora",
            None,
            format_args!("line {i:04} {}", "z".repeat(60)),
            None,
        );
        if i % 100 == 0 {
            sink.flush(Duration::from_secs(5));
        }
    }
    assert!(sink.flush(Duration::from_secs(5)));
    let files = log_files(dir);
    assert!(files.len() > 2, "rotated: {files:?}");
    let total: u64 = files
        .iter()
        .map(|f| std::fs::metadata(f).unwrap().len())
        .sum();
    // The cap holds, give or take the file being written.
    assert!(total <= 16 * 1024 + 4096 + 200, "total {total}");
    for f in &files {
        let len = std::fs::metadata(f).unwrap().len();
        assert!(len < 4096 + 200, "{} is {len} bytes", f.display());
        let ls = lines(f);
        assert_eq!(
            ls[0]["msg"], "log opened",
            "every file starts with a header"
        );
    }
    // The newest lines survived; the oldest were swept.
    let last = lines(files.last().unwrap());
    assert!(
        last.last().unwrap()["msg"]
            .as_str()
            .unwrap()
            .starts_with("line 0999")
    );
    let all: String = files
        .iter()
        .map(|f| std::fs::read_to_string(f).unwrap())
        .collect();
    assert!(!all.contains("line 0000"));
}

#[test]
fn overflow_is_counted_in_a_line() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = FileSink::start_with(DiagConfig::in_dir(tmp.path()), runs(), 8).unwrap();
    let (held_tx, held) = sync_channel(1);
    let (release, release_rx) = sync_channel(1);
    sink.tx
        .try_send(Msg::Hold(held_tx, release_rx))
        .ok()
        .unwrap();
    held.recv().unwrap();
    // The writer is parked with an empty queue: 8 fit, 5 do not.
    for i in 0..13 {
        sink.submit(
            Level::Info,
            "rust",
            "spora",
            None,
            format_args!("n{i}"),
            None,
        );
    }
    release.send(()).unwrap();
    assert!(sink.flush(Duration::from_secs(5)));

    let ls = lines(&log_files(tmp.path())[0]);
    let kept: Vec<&str> = ls
        .iter()
        .filter(|l| l["src"] == "rust")
        .map(|l| l["msg"].as_str().unwrap())
        .collect();
    assert_eq!(kept, ["n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7"]);
    let gap = ls.iter().find(|l| l.get("dropped").is_some()).unwrap();
    assert_eq!(gap["src"], "diag");
    assert_eq!(gap["msg"], "dropped 5 lines");
    assert_eq!(gap["dropped"], 5);
    assert_eq!(gap["lvl"], "W");
}

#[test]
fn crash_files() {
    let tmp = tempfile::tempdir().unwrap();
    let meta = crash::CrashMeta {
        source: "kot/lin!",
        platform: "android",
        thread: Some("main"),
        run: Some("0123456789abcdef"),
    };
    let text = format!(
        "java.lang.IllegalStateException: boom at https://spora.to/s/{SECRET}\n\tat a.b(C.kt:1)"
    );
    let p = crash::write_crash_in(tmp.path(), &meta, &text).unwrap();
    let name = p.file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("crash-") && name.ends_with("-kotlin.txt"),
        "{name}"
    );
    assert!(crate::upload::valid_file_name(name));
    let body = std::fs::read_to_string(&p).unwrap();
    assert!(body.ends_with('\n'));
    let mut it = body.lines();
    let h: serde_json::Value = serde_json::from_str(it.next().unwrap()).unwrap();
    assert_eq!(h["src"], "crash");
    assert_eq!(h["source"], "kot/lin!");
    assert_eq!(h["platform"], "android");
    assert_eq!(h["thread"], "main");
    assert_eq!(h["run"], "0123456789abcdef");
    assert!(h["build"]["version"].is_string());
    assert_eq!(
        it.next().unwrap(),
        "java.lang.IllegalStateException: boom at https://spora.to/s/<redacted>"
    );
    assert!(!body.contains(SECRET));

    // A second one in the same millisecond gets its own file.
    let p2 = crash::write_crash_in(tmp.path(), &meta, "again").unwrap();
    assert_ne!(p, p2);

    // Cut at the cap, marked, newline-terminated.
    let huge = "q".repeat(MAX_CRASH_FILE + 1000);
    let p3 = crash::write_crash_in(tmp.path(), &meta, &huge).unwrap();
    let body = std::fs::read_to_string(&p3).unwrap();
    assert!(body.ends_with("\n[truncated]\n"));
    assert_eq!(body.len(), MAX_CRASH_FILE);

    // Sweep keeps the newest.
    crash::sweep(tmp.path(), 1, Duration::from_secs(3600));
    assert_eq!(list_matching(tmp.path(), crash::is_crash_file).len(), 1);
}

#[test]
fn crash_file_fits_one_upload_chunk() {
    let tmp = tempfile::tempdir().unwrap();
    let thread = "t".repeat(10_000);
    let meta = crash::CrashMeta {
        source: "kotlin",
        platform: "android",
        thread: Some(&thread),
        run: None,
    };
    // At the cap, over it by a little and by a lot, and exactly filling it.
    for n in [MAX_CRASH_FILE - 600, MAX_CRASH_FILE, MAX_CRASH_FILE * 3] {
        let p = crash::write_crash_in(tmp.path(), &meta, &"q".repeat(n)).unwrap();
        let body = std::fs::read(&p).unwrap();
        assert!(body.len() <= MAX_CRASH_FILE, "{n}: {}", body.len());
        assert!(body.ends_with(b"\n"));
        let h: serde_json::Value =
            serde_json::from_slice(body.split(|b| *b == b'\n').next().unwrap()).unwrap();
        assert_eq!(h["thread"].as_str().unwrap().len(), MAX_TARGET_BYTES);
        if n > MAX_CRASH_FILE - 600 {
            assert!(body.ends_with(b"\n[truncated]\n"));
            assert_eq!(body.len(), MAX_CRASH_FILE);
        } else {
            assert!(!body.ends_with(b"[truncated]\n"));
        }
    }
    // Whole text that fills the file to the byte is not cut.
    let header_len = {
        let p = crash::write_crash_in(tmp.path(), &meta, "").unwrap();
        std::fs::read(&p).unwrap().len()
    };
    let exact = format!("{}\n", "w".repeat(MAX_CRASH_FILE - header_len - 1));
    let p = crash::write_crash_in(tmp.path(), &meta, &exact).unwrap();
    let body = std::fs::read(&p).unwrap();
    assert_eq!(body.len(), MAX_CRASH_FILE);
    assert!(!body.ends_with(b"[truncated]\n"));
}

#[test]
fn colliding_crash_names_sort_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let meta = crash::CrashMeta {
        source: "kotlin",
        platform: "android",
        thread: None,
        run: None,
    };
    let paths: Vec<PathBuf> = (0..5)
        .map(|i| crash::write_crash_in(tmp.path(), &meta, &format!("crash {i}")).unwrap())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(
        paths, sorted,
        "names sort in the order the crashes happened"
    );
    for (i, p) in paths.iter().enumerate() {
        assert!(
            std::fs::read_to_string(p)
                .unwrap()
                .contains(&format!("crash {i}"))
        );
        assert!(crate::upload::valid_file_name(
            p.file_name().unwrap().to_str().unwrap()
        ));
    }
}

#[test]
fn another_live_writers_file_survives_a_sweep() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::create_dir_all(dir).unwrap();
    let big = "x".repeat(8 * 1024) + "\n";
    // Another process, alive (it holds its live lock), quiet for an hour:
    // its current file is the oldest in the directory.
    let other = 4_000_001u32;
    let older = dir.join(format!("diag-20200101T000000000Z-{other}.jsonl"));
    let live = dir.join(format!("diag-20200101T000000001Z-{other}.jsonl"));
    for p in [&older, &live] {
        std::fs::write(p, &big).unwrap();
        set_age(p, Duration::from_secs(3600));
    }
    let lock = File::create(live_lock_path(dir, other)).unwrap();
    try_lock(&lock).unwrap();
    // A dead one: its lock is free (and goes), its file is fair game.
    let dead = 4_000_002u32;
    let dead_file = dir.join(format!("diag-20200101T000000002Z-{dead}.jsonl"));
    std::fs::write(&dead_file, &big).unwrap();
    set_age(&dead_file, Duration::from_secs(3000));
    std::fs::write(live_lock_path(dir, dead), b"").unwrap();

    let mut cfg = DiagConfig::in_dir(dir);
    cfg.rotate_bytes = 4096;
    cfg.max_total_bytes = 8 * 1024;
    let sink = FileSink::start(cfg, runs()).unwrap();
    assert!(live.exists(), "the file another live process writes stays");
    assert!(!older.exists());
    assert!(!dead_file.exists());
    assert!(!live_lock_path(dir, dead).exists());
    assert!(live_lock_path(dir, other).exists());
    // This process's own lock: held, so others see it alive.
    assert!(writer_alive(dir, std::process::id()));
    drop(sink);
    drop(lock);
    assert!(!writer_alive(dir, other));
}

#[test]
fn where_locks_fail_no_lock_file_stays() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let pid = 4_000_003u32;
    let unsupported = |_: &File| {
        Err(TryLockError::Error(io::Error::from(
            io::ErrorKind::Unsupported,
        )))
    };
    assert!(hold_live_lock(dir, pid, unsupported).is_none());
    assert!(
        !live_lock_path(dir, pid).exists(),
        "one would pile up per start"
    );
    let failing = |_: &File| Err(TryLockError::Error(io::Error::other("no locks today")));
    assert!(hold_live_lock(dir, pid, failing).is_none());
    assert!(!live_lock_path(dir, pid).exists());
    // Locks that work: the file stays, and others see it held.
    let held = hold_live_lock(dir, pid, try_lock).unwrap();
    assert!(writer_alive(dir, pid));
    drop(held);
    assert!(live_lock_path(dir, pid).exists());
    assert!(!writer_alive(dir, pid));

    // A sweep's verdict on another process's lock: free, or a leftover
    // where locks are unsupported, goes; held, or failing otherwise (which
    // says nothing about its holder), stays.
    assert!(lock_abandoned(Ok(())));
    assert!(lock_abandoned(Err(TryLockError::Error(
        io::ErrorKind::Unsupported.into()
    ))));
    assert!(!lock_abandoned(Err(TryLockError::WouldBlock)));
    assert!(!lock_abandoned(Err(TryLockError::Error(io::Error::other(
        "no locks today"
    )))));
}

#[test]
fn failed_writes_are_counted_once_writing_works() {
    let tmp = tempfile::tempdir().unwrap();
    let mut w = Writer::open(DiagConfig::in_dir(tmp.path()), runs()).unwrap();
    let path = w.path.clone();
    // The disk is gone: the file takes nothing (a read-only handle).
    *w.out.get_mut() = File::open(&path).unwrap();
    let line = |i: usize| Line {
        unix_ms: time::unix_ms(),
        level: Level::Info,
        src: "rust",
        tgt: "spora".into(),
        run: None,
        msg: format!("{i} {}", "p".repeat(1000)),
        trunc: false,
    };
    for i in 0..200 {
        w.line(&line(i));
    }
    w.flush_out();
    assert!(w.complained);
    // It comes back.
    *w.out.get_mut() = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    w.line(&line(999));
    w.flush_out();
    assert!(!w.complained);
    let ls = lines(&path);
    let kept = ls.iter().filter(|l| l["src"] == "rust").count();
    let lost = ls
        .iter()
        .find(|l| l["msg"].as_str().unwrap().starts_with("lost "))
        .unwrap();
    assert_eq!(lost["src"], "diag");
    assert_eq!(kept as u64 + lost["dropped"].as_u64().unwrap(), 201);
    assert!(kept > 0 && kept < 201);
}

/// The one test that touches the process-wide logger, run tracker and panic
/// hook (everything else uses private sinks).
#[test]
fn global_logger_end_to_end() {
    struct Capture(Mutex<Vec<String>>);
    impl Log for Capture {
        fn enabled(&self, m: &Metadata) -> bool {
            m.level() <= Level::Info
        }
        fn log(&self, r: &Record) {
            // Other tests log through the process logger too.
            if self.enabled(r.metadata()) && r.target().ends_with("_t") {
                self.0.lock().unwrap().push(format!("{}", r.args()));
            }
        }
        fn flush(&self) {}
    }
    let captured: &'static Capture = Box::leak(Box::new(Capture(Mutex::new(Vec::new()))));
    struct Fwd(&'static Capture);
    impl Log for Fwd {
        fn enabled(&self, m: &Metadata) -> bool {
            self.0.enabled(m)
        }
        fn log(&self, r: &Record) {
            self.0.log(r)
        }
        fn flush(&self) {}
    }

    let _runs = RUNS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("diag");
    // Before init: no file, the bridge is a no-op, crash writing has no home.
    log_line(Level::Info, "Early", "dropped");
    assert!(write_crash("kotlin", "too early").is_err());

    // A directory no log can start in: crash files only go there until one
    // does.
    let blocker = tmp.path().join("not-a-dir");
    std::fs::write(&blocker, b"").unwrap();
    let l = init(Some(DiagConfig::in_dir(blocker.join("diag"))), None);
    assert_eq!(l.dir(), None);

    let l = init(
        Some(DiagConfig::in_dir(&dir).with_platform("linux")),
        Some(Secondary::new(Box::new(Fwd(captured)), LevelFilter::Info)),
    );
    assert!(l.is_installed());
    assert_eq!(l.dir(), Some(dir.as_path()));
    assert_eq!(log::max_level(), LevelFilter::Debug);
    // Idempotent: a second init changes nothing.
    let again = init(Some(DiagConfig::in_dir(tmp.path().join("other"))), None);
    assert!(std::ptr::eq(l, again));
    assert_eq!(log_dir(), Some(dir.clone()));
    assert!(!tmp.path().join("other").exists());

    log::debug!(target: "spora_t", "file only");
    log::debug!(target: "other_t", "neither");
    log::debug!(target: "quinn_proto", "noise");
    log::warn!(target: "quinn_t", "both");
    log_line(
        Level::Info,
        "MainActivity",
        &format!("open https://spora.to/s/{SECRET}"),
    );
    log_line(Level::Trace, "MainActivity", "too chatty");
    // Never in the file: per-flow lines, periodic statistics, raw requests.
    log::info!(target: spora_core::FLOW_LOG_TARGET, "new tcp connection: 10.0.85.1:51234 => 93.184.216.34:443");
    log::warn!(target: spora_core::FLOW_LOG_TARGET, "connect to 93.184.216.34:443 failed");
    log::debug!(target: spora_core::STATS_LOG_TARGET, "QUIC path stats: rtt=1ms");
    log::warn!(target: "ureq_proto::util", "authorization: Bearer TOKSECRET");

    // Lines carry the newest open record's id while it is open.
    let rec = spora_core::record::Recorder::start(
        &spora_core::record::RecordConfig::in_memory().with_subscriber(run_tracker()),
        spora_core::record::Role::Client,
        None,
        Vec::new(),
        false,
    );
    let id = rec.id().unwrap().to_string();
    assert_eq!(active_run().as_deref(), Some(id.as_str()));
    log::info!(target: "spora_test", "inside the run");
    rec.close(spora_core::record::Outcome::ClosedLocally, None, None);
    assert_ne!(active_run().as_deref(), Some(id.as_str()));
    log::info!(target: "spora_test", "after the run");

    // A panic: crash file plus an `E` line, and the previous hook still runs.
    install_panic_hook();
    install_panic_hook();
    fn boom() {
        panic!("kaboom at https://spora.to/s/{SECRET}")
    }
    // The same panic twice: one crash file, the repeat counted in its line.
    for _ in 0..2 {
        let r = std::thread::Builder::new()
            .name("boom-thread".into())
            .spawn(boom)
            .unwrap()
            .join();
        assert!(r.is_err());
    }

    // The platform's crash path gets the lines before it onto disk, with no
    // flush of its own: the process ends right after.
    log::error!(target: "spora_test", "just before the throw");
    let k = write_crash("kotlin", "Exception in thread main").unwrap();
    assert!(k.starts_with(&dir));
    let file = log_files(&dir).into_iter().next().unwrap();
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("just before the throw")
    );
    assert!(!blocker.join("diag").exists());

    assert!(flush(Duration::from_secs(5)));
    let raw = std::fs::read_to_string(&file).unwrap();
    for absent in ["93.184.216.34", "QUIC path stats", "TOKSECRET"] {
        assert!(!raw.contains(absent), "{absent}");
    }
    let ls = lines(&file);
    let find = |msg: &str| ls.iter().find(|l| l["msg"] == msg);
    assert!(find("file only").is_some());
    assert!(
        find("neither").is_none(),
        "other targets are kept from Info up"
    );
    assert!(find("noise").is_none());
    assert!(find("both").is_some());
    let app = find("open https://spora.to/s/<redacted>").unwrap();
    assert_eq!(app["src"], "app");
    assert_eq!(app["tgt"], "MainActivity");
    assert!(find("too chatty").is_none());
    assert!(find("dropped").is_none());
    assert_eq!(find("inside the run").unwrap()["run"], id.as_str());
    assert_ne!(
        find("after the run")
            .unwrap()
            .get("run")
            .and_then(|r| r.as_str()),
        Some(id.as_str())
    );
    let panic_line = ls
        .iter()
        .find(|l| l["tgt"] == "panic" && l["msg"].as_str().unwrap().contains("kaboom"))
        .unwrap();
    assert_eq!(panic_line["lvl"], "E");
    assert!(panic_line["msg"].as_str().unwrap().contains("boom-thread"));
    assert!(ls.iter().any(|l| {
        l["tgt"] == "panic"
            && l["msg"]
                .as_str()
                .unwrap()
                .ends_with("(repeat 1; no new crash file)")
    }));
    assert!(!std::fs::read_to_string(&file).unwrap().contains(SECRET));

    let caught = captured.0.lock().unwrap().clone();
    assert_eq!(
        caught,
        ["both"],
        "the secondary applies its own filter, and app lines skip it"
    );

    let crashes = list_matching(&dir, crash::is_crash_file);
    // Other tests' failures panic through the hook as well: only the files
    // of this test's panic count.
    let kaboom: Vec<String> = crashes
        .iter()
        .filter(|c| c.name.ends_with("-rust.txt"))
        .map(|c| std::fs::read_to_string(&c.path).unwrap())
        .filter(|t| t.contains("kaboom"))
        .collect();
    assert_eq!(kaboom.len(), 1, "one crash file for a repeating panic");
    let rust = &kaboom[0];
    let h: serde_json::Value = serde_json::from_str(rust.lines().next().unwrap()).unwrap();
    assert_eq!(h["source"], "rust");
    assert_eq!(h["thread"], "boom-thread");
    assert_eq!(h["platform"], "linux");
    assert!(rust.contains("kaboom at https://spora.to/s/<redacted>"));
    assert!(rust.contains("stack backtrace:"));
    assert!(!rust.contains(SECRET));
    assert!(rust.ends_with('\n'));
    assert!(crashes.iter().any(|c| c.name.ends_with("-kotlin.txt")));
}
