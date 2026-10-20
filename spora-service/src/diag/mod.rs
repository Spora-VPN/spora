//! The diagnostic log: the prose stream beside the typed connection record.
//!
//! One rolling JSON-Lines file sink behind the `log` crate, so everything the
//! core already logs lands in a file the device owns, and a bridge
//! ([`log_line`]) through which platform code (Kotlin, Swift) joins the same
//! file — one on-device log, not one per language. The process logger is a
//! composite: this file sink plus an optional *secondary* logger (logcat,
//! unified logging, stderr), each applying its own filter.
//!
//! Every line is stamped with the id of the open connection record
//! ([`run_tracker`] keeps the list). With several records open at once a
//! line could belong to any of them, so it carries no id rather than a
//! wrong one. A bug report thus reads as the prose around a typed story.
//!
//! Writing never blocks a caller: lines go through a bounded queue to a
//! writer thread, and a full queue drops lines and says so in the file
//! (`"msg":"dropped N lines"`). Each log call site has a budget of lines
//! (a burst, then a steady trickle), so no single noisy site can replace the
//! file's history; what a site has to hold back is counted in a line of its
//! own (`suppressed N lines from <site>`), as are lines a failing disk could
//! not take (`lost N lines`). Each such line carries its count as `dropped`:
//! the lines the file is missing at that point. Files rotate at a size and
//! the directory is capped in total size and age, sparing the file any
//! other live process is writing; crash files ([`write_crash`],
//! [`install_panic_hook`]) live in the same directory with their own caps.
//!
//! Some lines never reach the file: per-flow lines
//! ([`spora_core::FLOW_LOG_TARGET`]: the connection log is the only per-flow
//! record and it never leaves the machine) and periodic statistics
//! ([`spora_core::STATS_LOG_TARGET`]: the connection record samples them).
//!
//! Share URLs carry their secret in the path (`/s/<base64url>`), and URLs end
//! up in log messages; the sink redacts them before anything reaches disk.

pub mod bundle;
pub(crate) mod crash;

pub use crash::{MAX_CRASH_FILE, install_panic_hook, write_crash};

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::fs::{File, TryLockError};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use log::{Level, LevelFilter, Log, Metadata, Record};
use serde::Serialize;
use spora_core::record::{Build, Entry, RecordSubscriber};

use crate::fsutil::{
    create_private_dir, create_private_file, list_matching, open_lock_file, open_lock_probe,
    try_lock,
};
use crate::time;

/// Messages are cut at this many bytes (UTF-8, on a character boundary) and
/// the line is marked `"trunc":true`.
pub const MAX_MSG_BYTES: usize = 16 * 1024;

/// Targets (and app tags) are cut at this many bytes.
pub const MAX_TARGET_BYTES: usize = 128;

/// Lines in flight toward the writer thread before new ones are dropped.
const CHANNEL_CAPACITY: usize = 4096;

/// Lines written between flushes while the queue stays busy, so a steady
/// stream of lines cannot postpone the flush indefinitely.
const MAX_BATCH: usize = 1024;

/// Room in the writer's buffer for any ordinary line, so a line is either
/// wholly buffered or not written at all (a failed write never leaves half
/// of one behind).
const WRITE_BUFFER: usize = 64 * 1024;

/// Smallest file the writer rotates at, whatever the configuration says.
const MIN_ROTATE_BYTES: u64 = 4096;

/// How long held-back lines wait to be summarized. A flush request
/// (a crash, a bug report) summarizes at once.
const SUMMARY_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(100)
} else {
    Duration::from_secs(60)
};

/// A platform line has no call site, only its tag, and a tag covers every
/// line of a component: its budget is this many sites' worth.
const TAG_BUDGET: u32 = 4;

/// Call sites the rate limiter tracks at most; past it, sites with nothing
/// held back are forgotten (and start over with a full budget).
const MAX_SITES: usize = 4096;

/// Where and how much to keep.
#[derive(Debug, Clone)]
pub struct DiagConfig {
    /// Directory for `diag-*.jsonl` and `crash-*.txt`. Created (0700 on
    /// Unix) if missing.
    pub dir: PathBuf,
    /// Written into each file's header line and each crash file, e.g.
    /// `android`, `linux`.
    pub platform: String,
    /// Start a new file once the current one reaches this size.
    pub rotate_bytes: u64,
    /// Ceiling on all `diag-*.jsonl` files together (oldest deleted first).
    pub max_total_bytes: u64,
    /// `diag-*.jsonl` files older than this are deleted.
    pub max_age: Duration,
    /// Crash files to keep (newest kept).
    pub crash_keep: usize,
    /// Crash files older than this are deleted.
    pub crash_max_age: Duration,
    /// Lines one log call site may write back to back (at least 1)...
    pub site_burst: u32,
    /// ...after which it gets one more per this interval. What it has to
    /// hold back is summarized in a `src:"diag"` line.
    pub site_refill: Duration,
}

impl DiagConfig {
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            platform: default_platform().to_string(),
            rotate_bytes: 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_age: Duration::from_secs(14 * 24 * 60 * 60),
            crash_keep: 20,
            crash_max_age: Duration::from_secs(30 * 24 * 60 * 60),
            // A site logging steadily is held to ~1.7 MB a day, so even a
            // flood takes over a week to cycle the 16 MiB.
            site_burst: 60,
            site_refill: Duration::from_secs(10),
        }
    }

    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = platform.into();
        self
    }
}

/// The OS this was built for, in the vocabulary the API's `platform` field
/// uses (`android`, `ios`, `macos`, `windows`, `linux`).
pub fn default_platform() -> &'static str {
    std::env::consts::OS
}

/// A logger that receives records alongside the file: android_logger,
/// oslog, env_logger. `max_level` is the most verbose level it can want —
/// `log`'s global ceiling must admit it, and a `dyn Log` cannot say.
pub struct Secondary {
    logger: Box<dyn Log>,
    max_level: LevelFilter,
}

impl Secondary {
    pub fn new(logger: Box<dyn Log>, max_level: LevelFilter) -> Self {
        Self { logger, max_level }
    }
}

/// The level the file keeps for a target. Fixed, not configurable: the file
/// is what a bug report contains, so what it holds must not depend on how a
/// user happened to start the process.
pub fn file_level(target: &str) -> LevelFilter {
    // Checked first: both sit under the `spora` prefix kept at Debug.
    const NEVER: &[&str] = &[spora_core::FLOW_LOG_TARGET, spora_core::STATS_LOG_TARGET];
    const DEBUG: &[&str] = &["spora", "relay", "app"];
    const WARN: &[&str] = &[
        "quinn", "smoltcp", "tracing", "rustls", "hyper", "reqwest", "ureq", "h2",
    ];
    if NEVER.iter().any(|p| target.starts_with(p)) {
        LevelFilter::Off
    } else if DEBUG.iter().any(|p| target.starts_with(p)) {
        LevelFilter::Debug
    } else if WARN.iter().any(|p| target.starts_with(p)) {
        LevelFilter::Warn
    } else {
        LevelFilter::Info
    }
}

// ---------------------------------------------------------------------------
// the composite logger

/// The process logger: the file sink plus the secondary, each fed only what
/// its own filter wants. There is one per process ([`init`]).
pub struct Logger {
    file: OnceLock<FileSink>,
    secondary: OnceLock<Secondary>,
    installed: AtomicBool,
    init_lock: Mutex<()>,
}

static LOGGER: Logger = Logger {
    file: OnceLock::new(),
    secondary: OnceLock::new(),
    installed: AtomicBool::new(false),
    init_lock: Mutex::new(()),
};

/// Install the composite as the process logger. Idempotent: each part is
/// set by the first call that supplies it and kept from then on, so a later
/// call can add the file to a logger first installed without one (and is a
/// no-op otherwise). Never fails: a directory that cannot be used leaves the
/// file out and says so through the secondary; a foreign logger already
/// installed leaves `log` records with it ([`Logger::is_installed`] is then
/// false) while [`log_line`] and crash capture still use the file.
pub fn init(file: Option<DiagConfig>, secondary: Option<Secondary>) -> &'static Logger {
    let l = &LOGGER;
    let _g = l.init_lock.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = secondary
        && l.secondary.get().is_none()
    {
        let _ = l.secondary.set(s);
    }
    let mut failed: Option<(PathBuf, io::Error)> = None;
    if let Some(cfg) = file
        && l.file.get().is_none()
    {
        // Crash files follow the log: the first directory that holds one,
        // else (so a crash is still captured) the first one tried.
        let crash_cfg = cfg.clone();
        match FileSink::start(cfg, &RUNS) {
            Ok(sink) => {
                crash::configure(&crash_cfg, true);
                let _ = l.file.set(sink);
            }
            Err(e) => {
                crash::configure(&crash_cfg, false);
                failed = Some((crash_cfg.dir, e));
            }
        }
    }
    if !l.installed.load(Ordering::SeqCst) && log::set_logger(l).is_ok() {
        l.installed.store(true, Ordering::SeqCst);
    }
    if l.installed.load(Ordering::SeqCst) {
        log::set_max_level(l.max_level());
    } else {
        log::warn!(
            "diag: another logger is installed; the log file gets platform lines and panics only"
        );
    }
    if let Some((dir, e)) = failed {
        log::warn!(
            "diag: cannot write a log in {} ({e}); not keeping one",
            dir.display()
        );
    }
    l
}

/// The composite, whether or not [`init`] has run.
pub fn logger() -> &'static Logger {
    &LOGGER
}

impl Logger {
    /// Whether this composite is the process's `log` logger.
    pub fn is_installed(&self) -> bool {
        self.installed.load(Ordering::SeqCst)
    }

    /// The log directory, once a file sink is running.
    pub fn dir(&self) -> Option<&Path> {
        self.file.get().map(|f| f.dir.as_path())
    }

    /// Wait (up to `timeout`) until every line queued so far is on disk.
    pub fn flush_file(&self, timeout: Duration) -> bool {
        self.file.get().is_none_or(|f| f.flush(timeout))
    }

    fn max_level(&self) -> LevelFilter {
        let file = if self.file.get().is_some() {
            LevelFilter::Debug
        } else {
            LevelFilter::Off
        };
        let secondary = self
            .secondary
            .get()
            .map(|s| s.max_level)
            .unwrap_or(LevelFilter::Off);
        file.max(secondary)
    }
}

/// Log targets (prefixes) no sink gets, at any level: ureq-proto traces the
/// raw bytes of every request it writes, the device's bearer token among
/// them (its other lines are state-machine names, nothing lost). A process
/// that logs through a plain logger instead of [`init`]'s composite applies
/// this list itself, e.g. env_logger's `filter_module(t, LevelFilter::Off)`.
pub const WITHHELD_TARGETS: &[&str] = &["ureq_proto"];

pub(crate) fn withheld(m: &Metadata) -> bool {
    WITHHELD_TARGETS.iter().any(|t| m.target().starts_with(t))
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        if withheld(m) {
            return false;
        }
        (self.file.get().is_some() && m.level() <= file_level(m.target()))
            || self.secondary.get().is_some_and(|s| s.logger.enabled(m))
    }

    fn log(&self, r: &Record) {
        if withheld(r.metadata()) {
            return;
        }
        if let Some(f) = self.file.get()
            && r.level() <= file_level(r.target())
        {
            let site = r.module_path().zip(r.line());
            f.submit(
                r.level(),
                "rust",
                r.target(),
                site,
                *r.args(),
                RUNS.current(),
            );
        }
        if let Some(s) = self.secondary.get()
            && s.logger.enabled(r.metadata())
        {
            s.logger.log(r);
        }
    }

    fn flush(&self) {
        if let Some(s) = self.secondary.get() {
            s.logger.flush();
        }
        self.flush_file(Duration::from_secs(1));
    }
}

/// A platform log line (Kotlin, Swift), straight into the file with
/// `"src":"app"` and the tag as its target. Not passed to the secondary: the
/// platform has already logged it natively. Kept at `Debug` and above, like
/// every `app` target. A no-op until [`init`] has set up a file.
pub fn log_line(level: Level, tag: &str, msg: &str) {
    if level > file_level("app") {
        return;
    }
    if let Some(f) = LOGGER.file.get() {
        f.submit(
            level,
            "app",
            tag,
            None,
            format_args!("{msg}"),
            RUNS.current(),
        );
    }
}

/// [`Logger::flush_file`] on the process logger.
pub fn flush(timeout: Duration) -> bool {
    LOGGER.flush_file(timeout)
}

/// The log directory, once [`init`] has one running.
pub fn log_dir() -> Option<PathBuf> {
    LOGGER.dir().map(Path::to_path_buf)
}

// ---------------------------------------------------------------------------
// run-id tracking

/// The connection records open in this process, oldest first.
pub(crate) struct RunList(Mutex<Vec<String>>);

/// A record leaked without ever closing would otherwise grow this forever.
const MAX_RUNS: usize = 256;

pub(crate) static RUNS: RunList = RunList(Mutex::new(Vec::new()));

/// Held by tests that open records through the process-wide run list, so
/// one test's open run cannot stamp another's lines.
#[cfg(test)]
pub(crate) static RUNS_TEST_LOCK: Mutex<()> = Mutex::new(());

impl RunList {
    fn opened(&self, id: &str) {
        let mut runs = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !runs.iter().any(|r| r == id) {
            if runs.len() >= MAX_RUNS {
                runs.remove(0);
            }
            runs.push(id.to_string());
        }
    }

    fn closed(&self, id: &str) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|r| r != id);
    }

    /// The open record, when exactly one is open. Lines are not tagged with
    /// the task that logged them, so with two runs open (a share and a
    /// connect, two shares) any line could be either's: none is named
    /// rather than possibly the wrong one.
    fn current(&self) -> Option<String> {
        Self::only(&self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// [`Self::current`] for a panic hook, which may be running on a thread
    /// that panicked while holding the lock.
    fn try_current(&self) -> Option<String> {
        match self.0.try_lock() {
            Ok(runs) => Self::only(&runs),
            Err(std::sync::TryLockError::Poisoned(e)) => Self::only(&e.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    fn only(runs: &[String]) -> Option<String> {
        match runs {
            [one] => Some(one.clone()),
            _ => None,
        }
    }
}

/// A record subscriber that keeps the list of open records: an `open` entry
/// adds its id, a `close` removes it, and log lines carry the open one as
/// `run` — while it is the only one. Records close on drop, so a run that
/// ends any way at all leaves the list. Cheap and non-blocking, as
/// subscribers must be.
pub fn run_tracker() -> RecordSubscriber {
    Arc::new(|entry: &Entry| match entry {
        Entry::Open(o) => RUNS.opened(&o.id),
        Entry::Close(c) => RUNS.closed(&c.id),
        _ => {}
    })
}

/// The id log lines are being stamped with right now: the open record's,
/// or none when no record or several are open.
pub fn active_run() -> Option<String> {
    RUNS.current()
}

// ---------------------------------------------------------------------------
// redaction and rendering

/// Replace share-URL secrets — an `s` path segment followed by 40 or more
/// base64url characters — with `<redacted>`, keeping the `/s/` before it.
/// The segment is found in the forms a URL takes on its way into a message:
/// either case (`/S/`), JSON-escaped slashes (`\/s\/`), percent-encoded ones
/// (`%2Fs%2F`, `%252F` once more encoded) and any mix of them; the secret
/// itself is base64url, which no encoding changes. `cut` says the text was
/// truncated: a run that reaches its end may be the head of a secret, so it
/// is redacted whatever its length.
pub(crate) fn redact(s: &str, cut: bool) -> Cow<'_, str> {
    const MIN_SECRET: usize = 40;
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !matches!(bytes[i], b's' | b'S') || !slash_ends_at(bytes, i) {
            i += 1;
            continue;
        }
        let Some(after) = slash_len(&bytes[i + 1..]) else {
            i += 1;
            continue;
        };
        let start = i + 1 + after;
        let run = bytes[start..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'-' || **b == b'_')
            .count();
        let at_end = start + run == bytes.len();
        if run >= MIN_SECRET || (cut && at_end && run > 0) {
            out.push_str(&s[copied..start]);
            out.push_str("<redacted>");
            copied = start + run;
            i = copied;
        } else {
            i += 1;
        }
    }
    if copied == 0 {
        return Cow::Borrowed(s);
    }
    out.push_str(&s[copied..]);
    Cow::Owned(out)
}

/// The length of the slash [`redact`] recognizes at the start of `b`: `/`
/// (after any backslashes escaping it), `%2F` or `%252F` (hex in either
/// case).
fn slash_len(b: &[u8]) -> Option<usize> {
    let mut skip = 0;
    while b.get(skip) == Some(&b'\\') {
        skip += 1;
    }
    if b.get(skip) == Some(&b'/') {
        return Some(skip + 1);
    }
    let pct = |p: &[u8]| b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p);
    if pct(b"%2F") {
        Some(3)
    } else if pct(b"%252F") {
        Some(5)
    } else {
        None
    }
}

/// Whether one of [`slash_len`]'s forms ends right before `b[i]`.
fn slash_ends_at(b: &[u8], i: usize) -> bool {
    let ends = |p: &[u8]| i >= p.len() && b[i - p.len()..i].eq_ignore_ascii_case(p);
    ends(b"/") || ends(b"%2F") || ends(b"%252F")
}

/// Cut `s` to at most `max` bytes on a character boundary.
pub(crate) fn cut_at(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
}

/// Formats into a buffer that stops growing at its cap, so an enormous
/// message costs no more memory than a maximal one.
struct Bounded {
    buf: String,
    cap: usize,
    full: bool,
}

impl fmt::Write for Bounded {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.cap - self.buf.len();
        if s.len() <= room {
            self.buf.push_str(s);
            return Ok(());
        }
        let mut end = room;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        self.buf.push_str(&s[..end]);
        self.full = true;
        Err(fmt::Error)
    }
}

/// The message as it will be written: formatted (bounded), redacted, cut.
/// Returns the text and whether it was truncated.
pub(crate) fn render(args: fmt::Arguments<'_>, max: usize) -> (String, bool) {
    let mut b = Bounded {
        buf: String::new(),
        cap: max,
        full: false,
    };
    // A Display impl that fails is reported as a truncated line rather than
    // a panic (which `to_string` would turn it into).
    let failed = fmt::write(&mut b, args).is_err();
    let cut = b.full || failed;
    let mut msg = match redact(&b.buf, cut) {
        Cow::Borrowed(_) => b.buf,
        Cow::Owned(s) => s,
    };
    // Redacting a run at a cut end can lengthen it.
    let recut = cut_at(&mut msg, max);
    (msg, cut || recut)
}

fn level_code(l: Level) -> &'static str {
    match l {
        Level::Error => "E",
        Level::Warn => "W",
        Level::Info => "I",
        Level::Debug => "D",
        Level::Trace => "T",
    }
}

// ---------------------------------------------------------------------------
// the file sink

pub(crate) struct FileSink {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
    limiter: Arc<Limiter>,
    dir: PathBuf,
}

enum Msg {
    Line(Line),
    Flush(SyncSender<()>),
    /// A call site has started holding lines back: wakes the writer so it
    /// schedules a summary.
    Suppressing,
    /// Tests: the writer reports in, then waits until released.
    #[cfg(test)]
    Hold(SyncSender<()>, Receiver<()>),
}

struct Line {
    unix_ms: u64,
    level: Level,
    src: &'static str,
    tgt: String,
    run: Option<String>,
    msg: String,
    trunc: bool,
}

/// One line on disk. Field order is the documented key order.
#[derive(Serialize)]
struct LineOut<'a> {
    ts: String,
    lvl: &'static str,
    src: &'a str,
    tgt: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<&'a str>,
    msg: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    trunc: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    dropped: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build: Option<&'a Build>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: Option<&'a str>,
}

impl FileSink {
    pub(crate) fn start(cfg: DiagConfig, runs: &'static RunList) -> io::Result<FileSink> {
        Self::start_with(cfg, runs, CHANNEL_CAPACITY)
    }

    fn start_with(
        mut cfg: DiagConfig,
        runs: &'static RunList,
        capacity: usize,
    ) -> io::Result<FileSink> {
        create_private_dir(&cfg.dir)?;
        cfg.rotate_bytes = cfg.rotate_bytes.max(MIN_ROTATE_BYTES);
        let dir = cfg.dir.clone();
        let limiter = Arc::new(Limiter::new(cfg.site_burst, cfg.site_refill));
        let writer = Writer::open(cfg, runs)?;
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let counter = dropped.clone();
        let budgets = limiter.clone();
        std::thread::Builder::new()
            .name("spora-diag".into())
            .spawn(move || writer.run(rx, counter, budgets))?;
        Ok(FileSink {
            tx,
            dropped,
            limiter,
            dir,
        })
    }

    /// Queue one line. `site` is the call site (module, line) when known:
    /// lines are budgeted per site, or per target and level without one.
    pub(crate) fn submit(
        &self,
        level: Level,
        src: &'static str,
        tgt: &str,
        site: Option<(&str, u32)>,
        args: fmt::Arguments<'_>,
        run: Option<String>,
    ) {
        let tgt = head(tgt, MAX_TARGET_BYTES);
        if let Admit::No { first } = self.limiter.admit(level, src, tgt, site) {
            if first {
                let _ = self.tx.try_send(Msg::Suppressing);
            }
            return;
        }
        let unix_ms = time::unix_ms();
        let (msg, trunc) = render(args, MAX_MSG_BYTES);
        let line = Line {
            unix_ms,
            level,
            src,
            tgt: tgt.to_string(),
            run,
            msg,
            trunc,
        };
        if self.tx.try_send(Msg::Line(line)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Wait (up to `timeout`) until every line queued so far is on disk,
    /// with whatever the rate limit held back counted.
    pub(crate) fn flush(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let mut msg = Msg::Flush(tx);
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    msg = m;
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok()
    }
}

/// `s` cut to at most `max` bytes on a character boundary.
pub(crate) fn head(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// per-site budgets

/// A token bucket per log call site, so one site in a loop (a per-packet
/// warning, a per-query error a peer can trigger at will) cannot cycle the
/// file's whole history out in seconds. Checked on the caller's thread,
/// before the line is even formatted.
struct Limiter {
    burst: f64,
    refill: Duration,
    state: Mutex<Sites>,
}

struct Sites {
    sites: HashMap<u64, Site>,
    /// Some site holds lines back that no summary has counted yet.
    pending: bool,
}

struct Site {
    tokens: f64,
    at: Instant,
    held: u64,
    /// How the summary names it.
    name: String,
}

enum Admit {
    Yes,
    /// Held back; `first` when nothing was pending before (the writer
    /// needs waking to schedule a summary).
    No {
        first: bool,
    },
}

impl Limiter {
    fn new(burst: u32, refill: Duration) -> Self {
        Self {
            burst: f64::from(burst.max(1)),
            refill: refill.max(Duration::from_millis(1)),
            state: Mutex::new(Sites {
                sites: HashMap::new(),
                pending: false,
            }),
        }
    }

    fn admit(&self, level: Level, src: &str, tgt: &str, site: Option<(&str, u32)>) -> Admit {
        let (burst, refill) = match site {
            Some(_) => (self.burst, self.refill),
            None => (self.burst * f64::from(TAG_BUDGET), self.refill / TAG_BUDGET),
        };
        let mut h = DefaultHasher::new();
        (level, src, tgt, site).hash(&mut h);
        let key = h.finish();
        let now = Instant::now();
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.sites.len() >= MAX_SITES && !s.sites.contains_key(&key) {
            s.sites.retain(|_, v| v.held > 0);
            if s.sites.len() >= MAX_SITES {
                return Admit::Yes;
            }
        }
        let entry = s.sites.entry(key).or_insert_with(|| Site {
            tokens: burst,
            at: now,
            held: 0,
            name: site_name(tgt, site),
        });
        let earned = now.duration_since(entry.at).as_secs_f64() / refill.as_secs_f64();
        entry.tokens = (entry.tokens + earned).min(burst);
        entry.at = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            return Admit::Yes;
        }
        entry.held += 1;
        let first = !s.pending;
        s.pending = true;
        Admit::No { first }
    }

    fn pending(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).pending
    }

    /// Every site's held-back count since the last call (sites that held
    /// nothing back left out).
    fn take_held(&self) -> Vec<(String, u64)> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.pending = false;
        s.sites
            .values_mut()
            .filter(|v| v.held > 0)
            .map(|v| (v.name.clone(), std::mem::take(&mut v.held)))
            .collect()
    }
}

fn site_name(tgt: &str, site: Option<(&str, u32)>) -> String {
    match site {
        Some((module, line)) if module == tgt => format!("{tgt}:{line}"),
        Some((module, line)) => format!("{tgt} ({}:{line})", head(module, MAX_TARGET_BYTES)),
        None => tgt.to_string(),
    }
}

// ---------------------------------------------------------------------------
// the writer thread

struct Writer {
    cfg: DiagConfig,
    runs: &'static RunList,
    pid: u32,
    build: Build,
    path: PathBuf,
    /// The current file's stamp.
    stamp_ms: u64,
    out: BufWriter<File>,
    written: u64,
    /// Lines that could not be written, not yet reported in the file.
    lost: u64,
    complained: bool,
    /// This process's live lock ([`hold_live_lock`]), held for good.
    _live: Option<File>,
}

impl Writer {
    fn open(cfg: DiagConfig, runs: &'static RunList) -> io::Result<Writer> {
        crash::sweep(&cfg.dir, cfg.crash_keep, cfg.crash_max_age);
        let pid = std::process::id();
        // Before the file exists, so no sweep ever sees it unprotected.
        let live = hold_live_lock(&cfg.dir, pid, try_lock);
        let (path, file, stamp_ms) = new_log_file(&cfg.dir, pid, 0)?;
        let mut w = Writer {
            cfg,
            runs,
            pid,
            build: spora_core::record::build_info(),
            path,
            stamp_ms,
            out: BufWriter::with_capacity(WRITE_BUFFER, file),
            written: 0,
            lost: 0,
            complained: false,
            _live: live,
        };
        // On disk before init returns: a process that dies before its first
        // line drains still leaves a file that says what wrote it.
        w.header();
        if let Err(e) = w.out.flush() {
            w.complain(&e);
        }
        sweep_logs(&w.cfg.dir, &w.path, w.cfg.max_total_bytes, w.cfg.max_age);
        Ok(w)
    }

    fn run(mut self, rx: Receiver<Msg>, dropped: Arc<AtomicU64>, limiter: Arc<Limiter>) {
        let mut waiters: Vec<SyncSender<()>> = Vec::new();
        let mut summary_due: Option<Instant> = None;
        loop {
            // Idle, the thread sleeps until a message comes; with a summary
            // pending, no longer than until it is due.
            let first = match summary_due {
                None => match rx.recv() {
                    Ok(m) => Some(m),
                    Err(_) => break,
                },
                Some(due) => match rx.recv_timeout(due.saturating_duration_since(Instant::now())) {
                    Ok(m) => Some(m),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => break,
                },
            };
            let mut next = first;
            let mut batch = 0;
            while let Some(msg) = next {
                match msg {
                    Msg::Line(l) => self.line(&l),
                    Msg::Flush(w) => waiters.push(w),
                    Msg::Suppressing => {}
                    #[cfg(test)]
                    Msg::Hold(held, release) => {
                        let _ = held.send(());
                        let _ = release.recv();
                    }
                }
                batch += 1;
                // Empty or disconnected alike: flush what has been written.
                next = if batch < MAX_BATCH {
                    rx.try_recv().ok()
                } else {
                    None
                };
            }
            if limiter.pending() {
                let due = *summary_due.get_or_insert_with(|| Instant::now() + SUMMARY_DELAY);
                if !waiters.is_empty() || Instant::now() >= due {
                    self.summarize(&limiter);
                    summary_due = None;
                }
            } else {
                summary_due = None;
            }
            let n = dropped.swap(0, Ordering::Relaxed);
            if n > 0 && !self.diag_line(Level::Warn, &format!("dropped {n} lines"), Some(n)) {
                self.lost += n;
            }
            self.flush_out();
            for w in waiters.drain(..) {
                let _ = w.try_send(());
            }
        }
        let _ = self.out.flush();
    }

    fn line(&mut self, l: &Line) {
        let out = LineOut {
            ts: time::iso_ms(l.unix_ms),
            lvl: level_code(l.level),
            src: l.src,
            tgt: &l.tgt,
            run: l.run.as_deref(),
            msg: &l.msg,
            trunc: l.trunc,
            dropped: None,
            build: None,
            pid: None,
            platform: None,
        };
        if !self.write(&out) {
            self.lost += 1;
        }
        self.maybe_rotate();
    }

    /// A line of the sink's own; whether it was written.
    fn diag_line(&mut self, level: Level, msg: &str, dropped: Option<u64>) -> bool {
        let run = self.runs.current();
        let out = LineOut {
            ts: time::iso_ms(time::unix_ms()),
            lvl: level_code(level),
            src: "diag",
            tgt: "diag",
            run: run.as_deref(),
            msg,
            trunc: false,
            dropped,
            build: None,
            pid: None,
            platform: None,
        };
        let written = self.write(&out);
        self.maybe_rotate();
        written
    }

    /// One line per site that held lines back, counting them.
    fn summarize(&mut self, limiter: &Limiter) {
        for (name, n) in limiter.take_held() {
            let msg = format!("suppressed {n} lines from {name} (over its rate limit)");
            if !self.diag_line(Level::Warn, &msg, Some(n)) {
                self.lost += n;
            }
        }
    }

    /// Flush, and once that works again after a failure, say in the file
    /// how many lines the failure cost.
    fn flush_out(&mut self) {
        if let Err(e) = self.out.flush() {
            self.complain(&e);
            return;
        }
        self.complained = false;
        if self.lost > 0 {
            let n = std::mem::take(&mut self.lost);
            let msg = format!("lost {n} lines: the log could not be written");
            if !self.diag_line(Level::Warn, &msg, Some(n)) {
                self.lost += n;
            } else if let Err(e) = self.out.flush() {
                self.complain(&e);
            }
        }
    }

    /// The first line of every file: what wrote it.
    fn header(&mut self) {
        let run = self.runs.current();
        let build = self.build.clone();
        let platform = self.cfg.platform.clone();
        let out = LineOut {
            ts: time::iso_ms(time::unix_ms()),
            lvl: level_code(Level::Info),
            src: "diag",
            tgt: "diag",
            run: run.as_deref(),
            msg: "log opened",
            trunc: false,
            dropped: None,
            build: Some(&build),
            pid: Some(self.pid),
            platform: Some(&platform),
        };
        self.write(&out);
    }

    /// Append one line; whether it went into the buffer. Never rotates, so
    /// writing a header cannot start yet another file.
    fn write(&mut self, out: &LineOut<'_>) -> bool {
        let Ok(mut line) = serde_json::to_string(out) else {
            return false;
        };
        line.push('\n');
        match self.out.write_all(line.as_bytes()) {
            Ok(()) => {
                self.written += line.len() as u64;
                true
            }
            Err(e) => {
                self.complain(&e);
                false
            }
        }
    }

    fn maybe_rotate(&mut self) {
        if self.written >= self.cfg.rotate_bytes {
            self.rotate();
        }
    }

    fn rotate(&mut self) {
        match new_log_file(&self.cfg.dir, self.pid, self.stamp_ms + 1) {
            Ok((path, file, stamp_ms)) => {
                let old =
                    std::mem::replace(&mut self.out, BufWriter::with_capacity(WRITE_BUFFER, file));
                self.leave(old);
                self.path = path;
                self.stamp_ms = stamp_ms;
                self.written = 0;
                self.header();
                sweep_logs(
                    &self.cfg.dir,
                    &self.path,
                    self.cfg.max_total_bytes,
                    self.cfg.max_age,
                );
            }
            Err(e) => {
                // Keep appending to the current file; the next attempt comes
                // after another file's worth of lines.
                self.written = 0;
                self.complain(&e);
            }
        }
    }

    /// Flush the file being left behind; the lines it cannot take now are
    /// lost (and counted).
    fn leave(&mut self, mut old: BufWriter<File>) {
        if let Err(e) = old.flush() {
            self.complain(&e);
            if let (_, Ok(rest)) = old.into_parts() {
                self.lost += rest.iter().filter(|b| **b == b'\n').count() as u64;
            }
        }
    }

    /// Said once per failure (until a flush works again), to the secondary
    /// only in effect: a line about failing to write the file would itself
    /// fail to be written. The file gets its `lost N lines` line once writing
    /// works again.
    fn complain(&mut self, e: &io::Error) {
        if !self.complained {
            self.complained = true;
            log::warn!(
                "diag: writing {} failed ({e}); the log will have holes",
                self.path.display()
            );
        }
    }
}

/// `diag-<stamp>-<pid>.jsonl`, created fresh, stamped no earlier than
/// `min_ms`. Names are the upload order, so a process's files must sort in
/// the order they were written: each stamp is later than the previous file's
/// even when the clock has not moved on.
fn new_log_file(dir: &Path, pid: u32, min_ms: u64) -> io::Result<(PathBuf, File, u64)> {
    let mut ms = time::unix_ms().max(min_ms);
    for _ in 0..1000 {
        let path = dir.join(format!("diag-{}-{pid}.jsonl", time::file_stamp(ms)));
        match create_private_file(&path) {
            Ok(f) => return Ok((path, f, ms)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => ms += 1,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("no free log file name"))
}

pub(crate) fn is_log_file(name: &str) -> bool {
    name.starts_with("diag-") && name.ends_with(".jsonl")
}

/// The pid a `diag-<stamp>-<pid>.jsonl` name ends in.
fn log_file_pid(name: &str) -> Option<u32> {
    name.strip_suffix(".jsonl")?
        .rsplit_once('-')?
        .1
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------
// sweeping, and the files of other processes

/// `diag-<pid>.lock`, locked by a writing process for as long as it lives.
/// Every process sharing the directory sweeps it, and a quiet writer's file
/// is the oldest there: the lock is how the others tell it is still being
/// written. (Not the log file itself: Windows locks are mandatory, and the
/// bundle and the uploader read live files.)
fn live_lock_path(dir: &Path, pid: u32) -> PathBuf {
    dir.join(format!("diag-{pid}.lock"))
}

fn live_lock_pid(name: &str) -> Option<u32> {
    name.strip_prefix("diag-")?
        .strip_suffix(".lock")?
        .parse()
        .ok()
}

/// Take this process's live lock with `lock` ([`try_lock`]; a parameter for
/// the tests). `None` where file locks fail — the file, which would protect
/// nothing, is removed again at once, so no platform gathers one per process
/// start — or when another sink of this same process holds it (its files
/// are this pid's either way). A sweep elsewhere may hold a dead
/// predecessor's lock for a moment (pids are reused), hence the retries.
fn hold_live_lock(
    dir: &Path,
    pid: u32,
    lock: impl Fn(&File) -> Result<(), TryLockError>,
) -> Option<File> {
    let path = live_lock_path(dir, pid);
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        // A lock just removed by a sweep cannot be opened on Windows until
        // that sweep lets go of it: retried like a held one.
        let Ok(f) = open_lock_file(&path) else {
            continue;
        };
        match lock(&f) {
            // Still under its name: a sweep that removed it between the
            // open and the lock would leave this lock on a file nobody
            // checks.
            Ok(()) if path.exists() => return Some(f),
            Ok(()) | Err(TryLockError::WouldBlock) => continue,
            Err(TryLockError::Error(_)) => {
                drop(f);
                let _ = std::fs::remove_file(&path);
                return None;
            }
        }
    }
    None
}

/// Whether process `pid` holds its live lock. A lock that can be taken, or
/// none at all, means no writer is alive there; so do locks that do not
/// work (sweeping is then what it was before live locks).
fn writer_alive(dir: &Path, pid: u32) -> bool {
    open_lock_probe(&live_lock_path(dir, pid))
        .is_ok_and(|f| matches!(try_lock(&f), Err(TryLockError::WouldBlock)))
}

/// Whether another process's live lock, tried with this result, can go:
/// nobody holds it, or locks are unsupported here (a leftover of a build
/// that did not remove its own).
fn lock_abandoned(tried: Result<(), TryLockError>) -> bool {
    match tried {
        Ok(()) => true,
        Err(TryLockError::Error(e)) => e.kind() == io::ErrorKind::Unsupported,
        Err(TryLockError::WouldBlock) => false,
    }
}

/// Delete `diag-*.jsonl` files past `max_age`, then the oldest until the rest
/// fit in `max_total`. Never `current`, nor the file another live process is
/// writing (the newest of its pid's while it holds its live lock). Live locks
/// that nobody holds any more go too.
fn sweep_logs(dir: &Path, current: &Path, max_total: u64, max_age: Duration) {
    let own = std::process::id();
    let mut files = list_matching(dir, is_log_file);
    let mut newest: HashMap<u32, usize> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        if let Some(pid) = log_file_pid(&f.name).filter(|p| *p != own) {
            let n = newest.entry(pid).or_insert(i);
            if files[*n].name < f.name {
                *n = i;
            }
        }
    }
    let live: Vec<PathBuf> = newest
        .into_iter()
        .filter(|(pid, _)| writer_alive(dir, *pid))
        .map(|(_, i)| files[i].path.clone())
        .collect();
    let kept = |p: &Path| p == current || live.iter().any(|l| l == p);

    let now = SystemTime::now();
    files.retain(|f| {
        let too_old = now
            .duration_since(f.modified)
            .is_ok_and(|age| age > max_age);
        if too_old && !kept(&f.path) {
            let _ = std::fs::remove_file(&f.path);
            return false;
        }
        true
    });
    let mut total: u64 = files.iter().map(|f| f.len).sum();
    for f in &files {
        if total <= max_total {
            break;
        }
        if kept(&f.path) {
            continue;
        }
        if std::fs::remove_file(&f.path).is_ok() {
            total = total.saturating_sub(f.len);
        }
    }

    for l in list_matching(dir, |n| live_lock_pid(n).is_some_and(|p| p != own)) {
        // Removed while held here: a process starting with that pid then
        // either got it first (and this lock fails) or retries onto a new one.
        if let Ok(f) = open_lock_probe(&l.path)
            && lock_abandoned(try_lock(&f))
        {
            let _ = std::fs::remove_file(&l.path);
            drop(f);
        }
    }
}

#[cfg(test)]
mod tests;
