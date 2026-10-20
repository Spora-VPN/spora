//! Crash capture: a Rust panic hook and a synchronous crash-file writer for
//! the platform's own uncaught exceptions. Crash files sit next to the log
//! (`crash-<stamp>-<source>.txt`) and travel as their own upload stream.
//!
//! A crash file is a JSON header line (`"src":"crash"`, when, where, which
//! run, which build) followed by free text — the panic message and
//! backtrace, or whatever the platform handed over — always ending in a
//! newline so the uploader, which only ever sends whole lines, sends all of
//! it. The whole file fits in one upload chunk ([`MAX_CRASH_FILE`]), so a
//! crash always arrives as one piece with its header.
//!
//! A panic that repeats (on every redial, every packet) gets one crash file
//! per process and location: the backtrace is the costly part, it runs on
//! the panicking thread (a tokio worker, for a task), and a flood of copies
//! would sweep the first — the informative — crash out of the kept few. The
//! repeats are counted in the log's `E` lines instead.

use std::cell::Cell;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, SystemTime};

use log::Level;
use serde::Serialize;

use super::{DiagConfig, LOGGER, MAX_TARGET_BYTES, RUNS, cut_at, head, redact};
use crate::fsutil::{create_private_dir, create_private_file, list_matching, sync_dir};
use crate::time;

/// A crash file's size, header included, at most: one upload chunk. Text
/// beyond what fits is cut, and the cut is marked.
pub const MAX_CRASH_FILE: usize = crate::upload::MAX_CHUNK;

/// Ends the text of a crash file that was cut.
const TRUNCATED: &str = "\n[truncated]\n";

/// Panic locations a process remembers; a panic at any further one only
/// gets its `E` line (a cascade that wide is captured already).
const MAX_PANIC_SITES: usize = 64;

struct CrashConfig {
    dir: PathBuf,
    platform: String,
    keep: usize,
    max_age: Duration,
}

/// The directory of the first log that started: crash files go next to it,
/// where the bundle and the uploader look.
static USABLE: OnceLock<CrashConfig> = OnceLock::new();
/// The first directory [`super::init`] was given, when no log could start
/// there: a crash is still captured somewhere until one does.
static FALLBACK: OnceLock<CrashConfig> = OnceLock::new();

/// Where crash files go: `cfg.dir` when its log started (`usable`), and
/// otherwise only until a log starts somewhere.
pub(super) fn configure(cfg: &DiagConfig, usable: bool) {
    let c = CrashConfig {
        dir: cfg.dir.clone(),
        platform: head(&cfg.platform, MAX_TARGET_BYTES).to_string(),
        keep: cfg.crash_keep,
        max_age: cfg.crash_max_age,
    };
    let _ = if usable {
        USABLE.set(c)
    } else {
        FALLBACK.set(c)
    };
}

fn config() -> Option<&'static CrashConfig> {
    USABLE.get().or_else(|| FALLBACK.get())
}

#[derive(Serialize)]
struct Header<'a> {
    ts: String,
    src: &'static str,
    source: &'a str,
    pid: u32,
    platform: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<&'a str>,
    build: spora_core::record::Build,
}

pub(crate) struct CrashMeta<'a> {
    pub(crate) source: &'a str,
    pub(crate) platform: &'a str,
    pub(crate) thread: Option<&'a str>,
    pub(crate) run: Option<&'a str>,
}

/// Write a crash file now, synchronously and durably (fsync'd), for a crash
/// the platform caught — e.g. Kotlin's default uncaught-exception handler,
/// with `source` = `"kotlin"`. The log's queued lines go to disk first: the
/// process is usually about to end. The file is cut at [`MAX_CRASH_FILE`].
/// Needs the directory from [`super::init`]; before that it fails with
/// `NotFound`.
pub fn write_crash(source: &str, text: &str) -> io::Result<PathBuf> {
    let Some(cfg) = config() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no diagnostic directory configured (diag::init)",
        ));
    };
    // First, in case the platform ends the process while the crash file is
    // being written.
    LOGGER.flush_file(Duration::from_millis(500));
    let run = RUNS.current();
    let meta = CrashMeta {
        source,
        platform: &cfg.platform,
        thread: None,
        run: run.as_deref(),
    };
    let path = write_crash_in(&cfg.dir, &meta, text)?;
    sweep(&cfg.dir, cfg.keep, cfg.max_age);
    Ok(path)
}

/// Install a panic hook that writes a crash file (message, location, thread,
/// open run, build, backtrace) and queues an `E` line in the log, then hands
/// over to whichever hook was installed before. Idempotent. Independent of
/// the `log` logger: it writes the file itself, into the directory
/// [`super::init`] was given (with none yet, only the previous hook runs).
/// A panic on the main thread, which ends the process, is also reported to
/// the recorder ([`spora_core::record::note_process_panic`]), so the records
/// its teardown closes end as `crashed`.
pub fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            on_panic(info);
            prev(info);
        }));
    });
}

/// Panic locations seen in this process, each with how often it has
/// panicked since its crash file.
static SEEN: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());

/// Count a panic at `location`; `None` when it is the first there (it gets a
/// crash file), else how many earlier ones there were.
fn repeat_of(seen: &Mutex<Vec<(String, u64)>>, location: &str) -> Option<u64> {
    let mut seen = seen.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, n)) = seen.iter_mut().find(|(l, _)| l == location) {
        *n += 1;
        return Some(*n);
    }
    if seen.len() >= MAX_PANIC_SITES {
        return Some(0);
    }
    seen.push((location.to_string(), 0));
    None
}

/// The panics std raises itself when stdout or stderr is gone (`spora share
/// | head`): the process ends, but nothing crashed.
fn is_lost_stdio(msg: &str) -> bool {
    msg.starts_with("failed printing to stdout") || msg.starts_with("failed printing to stderr")
}

/// Whether a panic takes the process down with it, as far as the hook can
/// tell: one on a Rust program's main thread (the CLI's `#[tokio::main]`)
/// does. One anywhere else is caught — by tokio for a task, by UniFFI for a
/// call — and the process lives on; an FFI library has no Rust main thread.
fn ends_process(thread: &str, msg: &str) -> bool {
    thread == "main" && !is_lost_stdio(msg)
}

/// Must not panic: a panic inside a panic hook aborts the process. Hence
/// `try_with`, `try_current` and no unwraps.
fn on_panic(info: &std::panic::PanicHookInfo<'_>) {
    thread_local! {
        static IN_HOOK: Cell<bool> = const { Cell::new(false) };
    }
    // A thread whose locals are already gone, or a panic raised by this very
    // hook: leave it to the previous hook.
    match IN_HOOK.try_with(|f| f.replace(true)) {
        Ok(false) => {}
        _ => return,
    }

    let thread = std::thread::current();
    let name = thread.name().unwrap_or("<unnamed>");
    let msg = info.payload_as_str().unwrap_or("Box<dyn Any>");
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown>".into());
    // Before anything else: the runtime's teardown that follows closes the
    // open records on its worker threads, which are not panicking, and they
    // must say `crashed` rather than pass for a shutdown.
    if ends_process(name, msg) {
        spora_core::record::note_process_panic();
    }
    let run = RUNS.try_current();
    let repeat = repeat_of(&SEEN, &location);

    if let Some(f) = LOGGER.file.get() {
        let site = info.location().map(|l| (l.file(), l.line()));
        let note = match repeat {
            Some(n) if n > 0 => format!(" (repeat {n}; no new crash file)"),
            Some(_) => " (no crash file: too many panic sites)".into(),
            None => String::new(),
        };
        f.submit(
            Level::Error,
            "rust",
            "panic",
            site,
            format_args!("thread '{name}' panicked at {location}: {msg}{note}"),
            run.clone(),
        );
    }
    if repeat.is_none()
        && !is_lost_stdio(msg)
        && let Some(cfg) = config()
    {
        let bt = std::backtrace::Backtrace::force_capture();
        let text =
            format!("thread '{name}' panicked at {location}:\n{msg}\n\nstack backtrace:\n{bt}");
        let meta = CrashMeta {
            source: "rust",
            platform: &cfg.platform,
            thread: Some(name),
            run: run.as_deref(),
        };
        let _ = write_crash_in(&cfg.dir, &meta, &text);
        sweep(&cfg.dir, cfg.keep, cfg.max_age);
    }
    // The queued line is the log's account of the panic; give the writer a
    // moment to get it to disk in case the process is about to end. Not when
    // the writer itself is the one panicking.
    if name != "spora-diag" {
        LOGGER.flush_file(Duration::from_millis(500));
    }
    let _ = IN_HOOK.try_with(|f| f.set(false));
}

/// Keep the characters a file name and the upload API both accept.
fn file_source(source: &str) -> String {
    let s: String = source
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(32)
        .collect();
    if s.is_empty() { "unknown".into() } else { s }
}

pub(crate) fn write_crash_in(dir: &Path, meta: &CrashMeta<'_>, text: &str) -> io::Result<PathBuf> {
    create_private_dir(dir)?;
    let now = time::unix_ms();
    let header = Header {
        ts: time::iso_ms(now),
        src: "crash",
        source: head(meta.source, MAX_TARGET_BYTES),
        pid: std::process::id(),
        platform: head(meta.platform, MAX_TARGET_BYTES),
        thread: meta.thread.map(|t| head(t, MAX_TARGET_BYTES)),
        run: meta.run,
        build: spora_core::record::build_info(),
    };
    let mut out = serde_json::to_string(&header).map_err(io::Error::other)?;
    out.push('\n');

    // The text gets what the header leaves of one chunk, its final newline
    // (or the cut's mark) included. Redacting an uncut text only shortens it.
    let room = MAX_CRASH_FILE.saturating_sub(out.len());
    if text.len() + usize::from(!text.ends_with('\n')) <= room {
        out.push_str(&redact(text, false));
        if !out.ends_with('\n') {
            out.push('\n');
        }
    } else {
        let max = room.saturating_sub(TRUNCATED.len());
        let mut body = redact(head(text, max), true).into_owned();
        cut_at(&mut body, max);
        out.push_str(&body);
        out.push_str(TRUNCATED);
    }

    // A name taken (a second crash in the same millisecond) moves the stamp
    // on, so names still sort in the order the crashes happened.
    let source = file_source(meta.source);
    let mut ms = now;
    let (path, mut file) = loop {
        let path = dir.join(format!("crash-{}-{source}.txt", time::file_stamp(ms)));
        match create_private_file(&path) {
            Ok(f) => break (path, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && ms - now < 1000 => ms += 1,
            Err(e) => return Err(e),
        }
    };
    file.write_all(out.as_bytes())?;
    file.sync_all()?;
    sync_dir(dir);
    Ok(path)
}

pub(crate) fn is_crash_file(name: &str) -> bool {
    name.starts_with("crash-") && name.ends_with(".txt")
}

/// Delete crash files past `max_age`, then the oldest beyond `keep`.
pub(crate) fn sweep(dir: &Path, keep: usize, max_age: Duration) {
    let files = list_matching(dir, is_crash_file);
    let now = SystemTime::now();
    let excess = files.len().saturating_sub(keep);
    for (i, f) in files.iter().enumerate() {
        let too_old = now
            .duration_since(f.modified)
            .is_ok_and(|age| age > max_age);
        if i < excess || too_old {
            let _ = std::fs::remove_file(&f.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeating_panic_gets_one_crash_file() {
        let seen = Mutex::new(Vec::new());
        assert_eq!(repeat_of(&seen, "src/a.rs:1:1"), None);
        assert_eq!(repeat_of(&seen, "src/a.rs:1:1"), Some(1));
        assert_eq!(repeat_of(&seen, "src/b.rs:2:2"), None);
        assert_eq!(repeat_of(&seen, "src/a.rs:1:1"), Some(2));
        for i in 0..MAX_PANIC_SITES {
            repeat_of(&seen, &format!("src/c.rs:{i}:1"));
        }
        // Past the cap: no file, no count.
        assert_eq!(repeat_of(&seen, "src/d.rs:9:9"), Some(0));
        assert_eq!(repeat_of(&seen, "src/b.rs:2:2"), Some(1));
    }

    #[test]
    fn lost_stdout_is_no_crash() {
        assert!(is_lost_stdio(
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
        assert!(!is_lost_stdio("index out of bounds"));
    }

    #[test]
    fn only_a_main_thread_panic_ends_the_process() {
        assert!(ends_process("main", "index out of bounds"));
        assert!(!ends_process("tokio-runtime-worker", "index out of bounds"));
        assert!(!ends_process("<unnamed>", "index out of bounds"));
        assert!(!ends_process(
            "main",
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
    }
}
