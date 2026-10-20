//! The service layer for platform clients (see the `spora-service` crate):
//! the diagnostic log and its bridge for platform log lines, crash capture,
//! the telemetry upload switch, and bug-report bundles.
//!
//! Collection is unconditional and local; the switch only governs whether
//! what is already on the device is uploaded. Nothing here blocks on the
//! network: the uploader runs on its own thread.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Formatter;
use std::path::PathBuf;
use std::sync::Mutex;

use spora_service::Telemetry;
use spora_service::diag::{self, DiagConfig, Secondary};

/// Set up logging: the `log` crate goes to the platform's own log (logcat on
/// Android, unified logging on Apple) and, given `log_dir`, to the
/// diagnostic log file in that directory, where crash files are kept too
/// (a panic hook is installed for them). Idempotent: a later call can add the
/// file to logging that was first set up without one, and is otherwise a
/// no-op.
///
/// The app passes a directory that is not backed up (Android:
/// `noBackupFilesDir/diag`).
#[uniffi::export(default(log_dir = None))]
pub fn init_logging(log_dir: Option<String>) {
    let file = log_dir.map(DiagConfig::in_dir);
    let with_file = file.is_some();
    diag::init(file, platform_secondary());
    if with_file {
        diag::install_panic_hook();
    }
}

/// Logcat only, as before the diagnostic log existed: [`init_logging`]
/// without a directory.
#[cfg(target_os = "android")]
#[uniffi::export]
pub fn init_android_logging() {
    init_logging(None);
}

/// Initialize logging on Apple platforms. Routes the `log` crate into the
/// unified logging system (visible in Console.app and `log stream --predicate
/// 'subsystem == "to.spora"'`). Safe to call more than once. This is the
/// Apple counterpart to `init_android_logging`: [`init_logging`] without a
/// directory. A macOS/iOS client calls it (or `init_logging`) once at startup
/// and again from the tunnel extension process, which is separate.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[uniffi::export]
pub fn init_apple_logging() {
    init_logging(None);
}

#[cfg(target_os = "android")]
fn platform_secondary() -> Option<Secondary> {
    use android_logger::FilterBuilder;
    use log::LevelFilter;
    let filter = FilterBuilder::new()
        .filter_module("quinn", LevelFilter::Warn)
        .filter_module("quinn_proto", LevelFilter::Warn)
        .filter_module("quinn_udp", LevelFilter::Warn)
        .filter_module("tracing", LevelFilter::Warn)
        .filter_module("smoltcp", LevelFilter::Warn)
        .filter_level(LevelFilter::Debug)
        .build();
    let logger = android_logger::AndroidLogger::new(
        android_logger::Config::default()
            .with_tag("spora")
            .with_max_level(LevelFilter::Trace)
            .with_filter(filter),
    );
    Some(Secondary::new(Box::new(logger), LevelFilter::Debug))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn platform_secondary() -> Option<Secondary> {
    use log::LevelFilter;
    let logger = oslog::OsLogger::new("to.spora")
        .level_filter(LevelFilter::Debug)
        .category_level_filter("quinn", LevelFilter::Warn)
        .category_level_filter("quinn_proto", LevelFilter::Warn)
        .category_level_filter("quinn_udp", LevelFilter::Warn)
        .category_level_filter("smoltcp", LevelFilter::Warn);
    Some(Secondary::new(Box::new(logger), LevelFilter::Debug))
}

#[cfg(not(any(target_os = "android", target_os = "macos", target_os = "ios")))]
fn platform_secondary() -> Option<Secondary> {
    None
}

/// Severity of a platform log line, in Android's terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    /// Not kept in the file.
    Verbose,
}

impl From<LogLevel> for log::Level {
    fn from(l: LogLevel) -> Self {
        match l {
            LogLevel::Error => log::Level::Error,
            LogLevel::Warn => log::Level::Warn,
            LogLevel::Info => log::Level::Info,
            LogLevel::Debug => log::Level::Debug,
            LogLevel::Verbose => log::Level::Trace,
        }
    }
}

/// A platform log line (Kotlin, Swift) into the diagnostic log file, with
/// `tag` as its target. Only the file: the platform has already logged it
/// natively. A no-op until [`init_logging`] was given a directory.
#[uniffi::export]
pub fn log_line(level: LogLevel, tag: String, message: String) {
    diag::log_line(level.into(), &tag, &message);
}

/// Write a crash file for a crash the platform caught (Android: the default
/// uncaught-exception handler, `source = "kotlin"`), synchronously and
/// durably, so it is on disk before the process dies. Never fails toward the
/// caller, which is a crash handler: a crash that cannot be written is
/// logged and dropped. Needs the directory from [`init_logging`].
#[uniffi::export]
pub fn write_crash(source: String, text: String) {
    let written = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        diag::write_crash(&source, &text)
    }));
    match written {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => log::warn!("write_crash({source}): {e}"),
        Err(_) => log::warn!("write_crash({source}): panicked"),
    }
}

/// Where the service keeps its state and finds what it uploads.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ServiceConfig {
    /// `service.json` (the switch, the device token, upload cursors). Must
    /// not be backed up: a restored token would clone a device (Android:
    /// `noBackupFilesDir/service`).
    pub state_dir: String,
    /// The connection-record directory the app passes to `connect`/`share`.
    #[uniffi(default = None)]
    pub record_dir: Option<String>,
    /// The directory given to [`init_logging`] (log and crash files); `None`
    /// finds it there, if `init_logging` ran first.
    #[uniffi(default = None)]
    pub log_dir: Option<String>,
    /// `android`, `ios`, `macos`, `windows` or `linux`.
    pub platform: String,
    pub app_version: String,
    /// API base URLs in preference order. Empty means Spora's built-in API:
    /// its registration keeps working at whatever addresses later releases
    /// give it. A list is another API, even one naming the built-in
    /// addresses: the device registers anew there, and that token goes only
    /// to the listed addresses that issued it.
    #[uniffi(default = [])]
    pub api_bases: Vec<String>,
}

#[derive(Debug, uniffi::Error)]
pub enum ServiceError {
    /// A configuration that cannot work (e.g. an API base that is not a URL).
    Config(String),
    /// The directories involved.
    Io(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Config(s) => write!(f, "configuration: {s}"),
            ServiceError::Io(s) => s.fmt(f),
        }
    }
}

impl From<spora_service::Error> for ServiceError {
    fn from(e: spora_service::Error) -> Self {
        match e {
            spora_service::Error::Config(s) => ServiceError::Config(s),
            e => ServiceError::Io(e.to_string()),
        }
    }
}

/// The config [`init_service`] was last given, kept even when the service
/// could not start: a bug report made without the service still finds the
/// app's directories, platform and version in it.
static OFFERED: Mutex<Option<spora_service::ServiceConfig>> = Mutex::new(None);

/// Open the service state and start the uploader thread. Idempotent: the
/// first successful call's config holds for the life of the process. Reads
/// local files only; the uploader does its network work on its own thread,
/// and nothing at all while uploads are off.
#[uniffi::export]
pub fn init_service(config: ServiceConfig) -> Result<(), ServiceError> {
    let mut cfg =
        spora_service::ServiceConfig::new(config.state_dir, config.platform, config.app_version)
            .with_api_bases(config.api_bases);
    if let Some(dir) = config.record_dir {
        cfg = cfg.with_record_dir(dir);
    }
    if let Some(dir) = config.log_dir.map(PathBuf::from).or_else(diag::log_dir) {
        cfg = cfg.with_log_dir(dir);
    }
    *crate::lock(&OFFERED) = Some(cfg.clone());
    Telemetry::init_global(cfg)?;
    Ok(())
}

/// The upload switch as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TelemetryStatus {
    pub upload_enabled: bool,
    /// The account requires telemetry (last known).
    pub required: bool,
    /// The UI owes the user the force notice: show it once, then call
    /// [`acknowledge_telemetry_notice`].
    pub required_notice_pending: bool,
    /// The registered device, for support.
    pub device_id: Option<String>,
    pub last_upload_unix_ms: Option<u64>,
    pub last_error: Option<String>,
}

impl From<spora_service::TelemetryStatus> for TelemetryStatus {
    fn from(s: spora_service::TelemetryStatus) -> Self {
        Self {
            upload_enabled: s.upload_enabled,
            required: s.required,
            required_notice_pending: s.required_notice_pending,
            device_id: s.device_id,
            last_upload_unix_ms: s.last_upload_unix_ms,
            last_error: s.last_error,
        }
    }
}

#[derive(Debug, uniffi::Error)]
pub enum TelemetryError {
    /// The account requires telemetry, so uploads stay on. The UI shows the
    /// force notice.
    Required,
    /// [`init_service`] has not run.
    NotInitialized,
    Io(String),
}

impl std::fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TelemetryError::Required => spora_service::REQUIRED_NOTICE.fmt(f),
            TelemetryError::NotInitialized => "the service is not initialized".fmt(f),
            TelemetryError::Io(s) => s.fmt(f),
        }
    }
}

/// The switch, from this process's copy of the state (no I/O). Before
/// [`init_service`]: everything off and unknown.
#[uniffi::export]
pub fn telemetry_status() -> TelemetryStatus {
    match Telemetry::global() {
        Some(t) => t.status().into(),
        None => TelemetryStatus {
            upload_enabled: false,
            required: false,
            required_notice_pending: false,
            device_id: None,
            last_upload_unix_ms: None,
            last_error: None,
        },
    }
}

/// Flip the upload switch. Turning it off while the account requires
/// telemetry fails with [`TelemetryError::Required`] and changes nothing.
/// Turning it on starts an upload pass on the uploader's thread.
#[uniffi::export]
pub fn set_telemetry_enabled(enabled: bool) -> Result<(), TelemetryError> {
    let t = Telemetry::global().ok_or(TelemetryError::NotInitialized)?;
    t.set_upload_enabled(enabled).map_err(|e| match e {
        spora_service::Error::Required => TelemetryError::Required,
        e => TelemetryError::Io(e.to_string()),
    })
}

/// The UI has shown the force notice.
#[uniffi::export]
pub fn acknowledge_telemetry_notice() {
    if let Some(t) = Telemetry::global()
        && let Err(e) = t.acknowledge_notice()
    {
        log::warn!("acknowledge_telemetry_notice: {e}");
    }
}

/// Ask the uploader for a pass soon (e.g. the app came to the foreground).
/// Cheap, and a no-op while uploads are off.
#[uniffi::export]
pub fn telemetry_nudge() {
    spora_service::nudge();
}

/// What [`export_bug_report`] wrote.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BugReportSummary {
    pub path: String,
    /// Files bundled (the manifest not counted).
    pub included_files: u32,
    /// Files the manifest lists as left out (too old, over the size budget,
    /// unreadable).
    pub omitted_files: u32,
    /// Size of the zip.
    pub bytes: u64,
}

impl From<spora_service::BundleSummary> for BugReportSummary {
    fn from(s: spora_service::BundleSummary) -> Self {
        Self {
            path: s.path.to_string_lossy().into_owned(),
            included_files: s.included_files,
            omitted_files: s.omitted_files,
            bytes: s.bytes,
        }
    }
}

/// Bundle the recent connection records, diagnostic log and crash files into
/// a zip at `out_path` for the user to send by their own means (share sheet,
/// mail). Works without the server and whatever the upload switch says;
/// without a running service (before [`init_service`], or after it failed)
/// it bundles the directories [`init_service`] was given, the log directory
/// and the record directories this process has used. `platform_info`
/// (device model, OS version, …) goes into the manifest, with `platform`
/// and `app_version` added where the caller left them out and they are
/// known. Synchronous file work, possibly a few seconds: call it off the UI
/// thread.
#[uniffi::export]
pub fn export_bug_report(
    out_path: String,
    note: Option<String>,
    platform_info: HashMap<String, String>,
) -> Result<BugReportSummary, ServiceError> {
    let platform: BTreeMap<String, String> = platform_info.into_iter().collect();
    let out = PathBuf::from(out_path);
    let summary = match Telemetry::global() {
        Some(t) => t.export_bug_report(&out, note, platform),
        None => diag::bundle::export(&without_service(out, note, platform)),
    };
    summary
        .map(BugReportSummary::from)
        .map_err(|e| ServiceError::Io(e.to_string()))
}

/// What [`export_bug_report`] bundles when there is no service to ask.
fn without_service(
    out: PathBuf,
    note: Option<String>,
    mut platform: BTreeMap<String, String>,
) -> spora_service::BundleOptions {
    let offered = crate::lock(&OFFERED).clone();
    let (mut record_dirs, log_dir) = match offered {
        Some(cfg) => {
            platform.entry("platform".into()).or_insert(cfg.platform);
            platform
                .entry("app_version".into())
                .or_insert(cfg.app_version);
            (cfg.record_dirs, cfg.log_dir)
        }
        None => {
            platform
                .entry("platform".into())
                .or_insert_with(|| diag::default_platform().to_string());
            (Vec::new(), None)
        }
    };
    for dir in crate::record_dirs() {
        if !record_dirs.contains(&dir) {
            record_dirs.push(dir);
        }
    }
    let mut opts = spora_service::BundleOptions::new(out);
    opts.record_dirs = record_dirs;
    opts.log_dir = log_dir.or_else(diag::log_dir);
    opts.note = note;
    opts.platform = platform;
    opts
}

#[cfg(test)]
mod tests {
    use super::*;
    use spora_core::record::{Recorder, Role};
    use std::path::Path;
    use std::time::Duration;

    fn read_matching(dir: &Path, prefix: &str) -> String {
        let mut text = String::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with(prefix) {
                text.push_str(&std::fs::read_to_string(&path).unwrap());
            }
        }
        text
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    fn path(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    fn status_off() -> TelemetryStatus {
        TelemetryStatus {
            upload_enabled: false,
            required: false,
            required_notice_pending: false,
            device_id: None,
            last_upload_unix_ms: None,
            last_error: None,
        }
    }

    /// The process-wide pieces (logger, service) can be set up only once,
    /// so their whole life is one test, in the order an app goes through.
    #[test]
    fn logging_service_and_bug_report() {
        let _g = crate::lock(&crate::TEST_LOCK);
        let tmp = tempfile::tempdir().unwrap();
        let log_dir = tmp.path().join("diag");
        let record_dir = tmp.path().join("records");
        let state_dir = tmp.path().join("service");

        // before anything is set up: nothing fails, nothing is written
        log_line(LogLevel::Info, "SporaTest".into(), "too early".into());
        write_crash("kotlin".into(), "too early".into());
        assert_eq!(telemetry_status(), status_off());
        assert!(matches!(
            set_telemetry_enabled(true),
            Err(TelemetryError::NotInitialized)
        ));
        acknowledge_telemetry_notice();
        telemetry_nudge();

        init_logging(Some(path(&log_dir)));
        init_logging(None);
        let secret = "A".repeat(48);
        log_line(
            LogLevel::Info,
            "SporaTest".into(),
            format!("sharing https://spora.to/s/{secret}?r=1.2.3.4:443"),
        );
        log_line(LogLevel::Verbose, "SporaTest".into(), "not kept".into());
        write_crash(
            "kotlin".into(),
            "java.lang.IllegalStateException: boom\n\tat to.spora.X".into(),
        );
        // whatever the platform hands over, nothing fails toward the caller
        // and the file name stays inside the directory
        write_crash(String::new(), String::new());
        write_crash("../../etc/passwd".into(), "\0".repeat(10));
        assert!(diag::flush(Duration::from_secs(5)));
        let log = read_matching(&log_dir, "diag-");
        let line = log
            .lines()
            .find(|l| l.contains("\"tgt\":\"SporaTest\""))
            .expect("the app line is in the log");
        assert!(line.contains("\"src\":\"app\""), "{line}");
        assert!(line.contains("\"lvl\":\"I\""), "{line}");
        assert!(line.contains("/s/<redacted>"), "{line}");
        assert!(!line.contains(&secret), "{line}");
        assert!(!log.contains("not kept"));
        assert!(!log.contains("too early"));
        assert!(read_matching(&log_dir, "crash-").contains("IllegalStateException: boom"));
        let crash_names: Vec<String> = std::fs::read_dir(&log_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("crash-"))
            .collect();
        assert!(
            crash_names.iter().any(|n| n.ends_with("-etcpasswd.txt")),
            "{crash_names:?}"
        );
        assert!(
            crash_names.iter().any(|n| n.ends_with("-unknown.txt")),
            "{crash_names:?}"
        );

        // a run with a record, for the bundle
        let cfg = crate::record_config(Some(path(&record_dir))).unwrap();
        Recorder::start(&cfg, Role::Client, None, vec![], false).close_shutdown(None);

        // a bug report needs no service
        let out = tmp.path().join("reports/early.zip");
        let platform = HashMap::from([("model".to_string(), "Pixel 9".to_string())]);
        let summary = export_bug_report(path(&out), Some("note".into()), platform.clone()).unwrap();
        assert_eq!(summary.path, path(&out));
        assert!(summary.included_files >= 3, "{summary:?}");
        let zip = std::fs::read(&out).unwrap();
        assert_eq!(zip.len() as u64, summary.bytes);
        for name in ["manifest.json", "records/", "log/diag-", "crash/crash-"] {
            assert!(contains(&zip, name), "{name} in the bundle");
        }
        let unused = tmp.path().join("reports/unused.zip");
        // (other tests' runs may have added record directories of their own)
        let opts = without_service(unused.clone(), None, BTreeMap::new());
        assert!(opts.record_dirs.contains(&record_dir), "{opts:?}");
        assert_eq!(opts.log_dir.as_deref(), Some(log_dir.as_path()));
        assert_eq!(opts.platform["platform"], diag::default_platform());
        assert!(!opts.platform.contains_key("app_version"));

        let config = |state_dir: &Path, api: &str| ServiceConfig {
            state_dir: path(state_dir),
            record_dir: Some(path(&record_dir)),
            log_dir: Some(path(&log_dir)),
            platform: "android".into(),
            app_version: "0.0.0-test".into(),
            api_bases: vec![api.into()],
        };
        // a configuration that cannot work leaves the service uninitialized
        let offered_records = tmp.path().join("offered-records");
        assert!(matches!(
            init_service(ServiceConfig {
                record_dir: Some(path(&offered_records)),
                ..config(&state_dir, "ftp://example.invalid")
            }),
            Err(ServiceError::Config(_))
        ));
        assert_eq!(telemetry_status(), status_off());
        // ... and a bug report made then bundles what the app offered and
        // says which app made it (the caller's own entries win)
        let opts = without_service(
            unused,
            None,
            BTreeMap::from([("platform".to_string(), "android-tv".to_string())]),
        );
        assert_eq!(opts.record_dirs[0], offered_records);
        assert!(opts.record_dirs.contains(&record_dir), "{opts:?}");
        assert_eq!(opts.log_dir.as_deref(), Some(log_dir.as_path()));
        assert_eq!(opts.platform["platform"], "android-tv");
        assert_eq!(opts.platform["app_version"], "0.0.0-test");

        // a device whose account requires telemetry (as last known); nothing
        // listens at the API base, so the uploader's passes fail fast
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            state_dir.join("service.json"),
            r#"{"v":1,"upload_enabled":true,"required":true,"required_notice_pending":true}"#,
        )
        .unwrap();
        init_service(config(&state_dir, "http://127.0.0.1:9")).unwrap();
        let other = tmp.path().join("other");
        init_service(config(&other, "http://127.0.0.1:9")).unwrap();
        assert!(!other.exists(), "a second init is a no-op");
        let status = telemetry_status();
        assert!(status.upload_enabled && status.required && status.required_notice_pending);
        assert_eq!(status.device_id, None);
        assert!(matches!(
            set_telemetry_enabled(false),
            Err(TelemetryError::Required)
        ));
        assert!(telemetry_status().upload_enabled);
        acknowledge_telemetry_notice();
        assert!(!telemetry_status().required_notice_pending);
        set_telemetry_enabled(true).unwrap();
        telemetry_nudge();

        let out = tmp.path().join("reports/late.zip");
        let summary = export_bug_report(path(&out), None, platform).unwrap();
        assert!(summary.included_files >= 3, "{summary:?}");
    }

    #[test]
    fn log_levels_map_onto_log_levels() {
        assert_eq!(log::Level::from(LogLevel::Error), log::Level::Error);
        assert_eq!(log::Level::from(LogLevel::Warn), log::Level::Warn);
        assert_eq!(log::Level::from(LogLevel::Info), log::Level::Info);
        assert_eq!(log::Level::from(LogLevel::Debug), log::Level::Debug);
        assert_eq!(log::Level::from(LogLevel::Verbose), log::Level::Trace);
    }
}
