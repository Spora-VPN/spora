//! The upload switch and the uploader thread behind it.
//!
//! One per-device switch, default off; off means no telemetry data leaves
//! the device. On, a background thread replicates the connection records,
//! the diagnostic log and crash files to the API ([`crate::upload`]): a pass
//! at start, one shortly after every nudge (a record closing, the network
//! changing, the switch turning on), one every 15 minutes, and exponential
//! backoff (1 min to 1 h; longer, up to a day, if the server's `Retry-After`
//! says so) after a failed pass. A nudge does not cut short a backoff the server
//! asked for (it answered, with an error); after a pass that got no answer
//! at all (offline, blocked) it may bring the next one forward to a minute
//! after the failure — a changed network is the moment to try again. The
//! user's own actions (switching on, a refused switch-off wanting the
//! flag) go through regardless. While the platform asks for radio silence
//! ([`set_dormant`]) the thread runs no pass at all. Plain `std::thread`
//! and a condvar, so it behaves the same under the FFI and the CLI and needs
//! no caller's async runtime.
//!
//! The same thread keeps the device's relay access fresh when the
//! configuration manages it ([`ServiceConfig::relays`], see
//! [`crate::access`]): it fetches the relay advice and a relay token when
//! there is none, and again once the token's `renew_after` has passed,
//! whatever the upload switch says, with the same backoff.
//!
//! Registration is lazy: a device registers once uploads are on, or once
//! it needs relay access.
//! The server can require telemetry for a device's account (a promotion paid
//! for in data): the flag is fetched right after registering, then at most
//! daily, and with every upload answer. While it is set the switch cannot be
//! turned off ([`Error::Required`]; the UI shows [`REQUIRED_NOTICE`]), and
//! when it first appears the UI owes the user that notice
//! ([`TelemetryStatus::required_notice_pending`]).

use std::collections::BTreeMap;
use std::io;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use spora_core::record::{Entry, RecordSubscriber};

use spora_core::identity::{Credentials, DeviceIdentity, ShareId};

use crate::Error;
use crate::api::{Api, ApiError, PLATFORMS};
use crate::diag;
use crate::diag::bundle::{BundleOptions, BundleSummary};
use crate::seal::{Sealer, StateKey};
use crate::state::{ServiceState, StateStore};
use crate::upload::{Pass, PassSummary};

/// The longest `Retry-After` honoured: the longest wait spora-web asks for
/// (a device over its daily quota waits for the oldest hour of its 24-hour
/// window to pass). Longer than [`UploadTimings::backoff_max`] on purpose:
/// retrying hourly against a quota that frees only the next day would send
/// a refused chunk every hour.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// What the UI says when the account requires telemetry (the user's own
/// wording).
pub const REQUIRED_NOTICE: &str = "Your account requires that telemetry is enabled (most likely \
     because you've signed up to a promotion). You can keep it enabled, sign in to a different \
     account, or contact support.";

/// When the uploader runs.
#[derive(Debug, Clone)]
pub struct UploadTimings {
    /// Between passes while everything goes well.
    pub interval: Duration,
    /// First wait after a failed pass; doubles per failure up to `backoff_max`
    /// (a server's `Retry-After` may ask for longer, up to a day).
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// How often the force-telemetry flag is fetched for a registered device
    /// (and, after a failed attempt, how long until the next).
    pub status_interval: Duration,
    /// How long a nudge waits before its pass, gathering further nudges (and
    /// letting a just-closed record reach its file).
    pub nudge_delay: Duration,
}

impl Default for UploadTimings {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15 * 60),
            backoff_min: Duration::from_secs(60),
            backoff_max: Duration::from_secs(60 * 60),
            status_interval: Duration::from_secs(24 * 60 * 60),
            nudge_delay: Duration::from_secs(2),
        }
    }
}

/// Where the service keeps its state and finds what it uploads.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// `service.json` lives here. Must not be backed up or synced.
    pub state_dir: PathBuf,
    /// Connection-record directories (the `record` stream).
    pub record_dirs: Vec<PathBuf>,
    /// The diagnostic directory (the `log` and `crash` streams).
    pub log_dir: Option<PathBuf>,
    /// `android`, `ios`, `macos`, `windows` or `linux` ([`crate::api::PLATFORMS`]).
    pub platform: String,
    /// Sent as `X-App-Version` and at registration.
    pub app_version: String,
    /// API base URLs in preference order. Empty means the built-in API, at
    /// the running release's [`crate::DEFAULT_API_BASES`]: a device
    /// registered with it keeps working when a release adds or swaps
    /// fronts. A list is an override (even one naming the built-in fronts):
    /// its devices' tokens go only to the bases that minted them. A device
    /// of another API is not used with this configuration: its token goes
    /// only to its own API, and what that API said about its account binds
    /// nothing here. It is kept (parked) for when its API is configured
    /// again.
    pub api_bases: Vec<String>,
    pub timings: UploadTimings,
    /// How the secrets in `service.json` are kept ([`crate::seal`]).
    pub state_key: StateKey,
    /// Keep the device's relay access fresh (the relay advice and token,
    /// [`crate::access`]): a process that shares wants it, one that only
    /// connects does not (and then never registers for it).
    pub relays: bool,
}

impl ServiceConfig {
    pub fn new(
        state_dir: impl Into<PathBuf>,
        platform: impl Into<String>,
        app_version: impl Into<String>,
    ) -> Self {
        Self {
            state_dir: state_dir.into(),
            record_dirs: Vec::new(),
            log_dir: None,
            platform: platform.into(),
            app_version: app_version.into(),
            api_bases: Vec::new(),
            timings: UploadTimings::default(),
            state_key: StateKey::Plaintext,
            relays: false,
        }
    }

    pub fn with_state_key(mut self, key: StateKey) -> Self {
        self.state_key = key;
        self
    }

    pub fn with_relay_access(mut self, relays: bool) -> Self {
        self.relays = relays;
        self
    }

    pub fn with_record_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.record_dirs.push(dir.into());
        self
    }

    pub fn with_log_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.log_dir = Some(dir.into());
        self
    }

    pub fn with_api_bases(mut self, bases: Vec<String>) -> Self {
        self.api_bases = bases;
        self
    }
}

/// The switch as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryStatus {
    pub upload_enabled: bool,
    /// The account requires telemetry (last known).
    pub required: bool,
    /// The UI should show [`REQUIRED_NOTICE`] once, then call
    /// [`Telemetry::acknowledge_notice`].
    pub required_notice_pending: bool,
    /// The registered device, for support.
    pub device_id: Option<String>,
    pub last_upload_unix_ms: Option<u64>,
    pub last_error: Option<String>,
}

impl TelemetryStatus {
    /// The switch as a client configured for `api` sees it: the device and
    /// the account's flag are its registration's with that API, active or
    /// parked. A registration with another API concerns this configuration
    /// in nothing: with only such a one, no device and no flag. (A flag
    /// stored with no registration at all is nobody else's, and stands.)
    /// [`Telemetry::status`] is this.
    pub fn for_api(s: &ServiceState, api: &Api) -> Self {
        let r = s.served(|d| api.serves(d));
        let (required, required_notice_pending) = match &r {
            Some(r) => (r.required, r.required_notice_pending),
            None if s.device.is_none() => (s.required, s.required_notice_pending),
            None => (false, false),
        };
        Self {
            upload_enabled: s.upload_enabled,
            required,
            required_notice_pending,
            device_id: r.map(|r| r.device.id),
            last_upload_unix_ms: s.last_upload_unix_ms,
            last_error: s.last_error.clone(),
        }
    }
}

impl From<&ServiceState> for TelemetryStatus {
    /// The state as stored: the active registration's device and flag,
    /// whichever API it belongs to ([`TelemetryStatus::for_api`] is the
    /// view of one configuration).
    fn from(s: &ServiceState) -> Self {
        Self {
            upload_enabled: s.upload_enabled,
            required: s.required,
            required_notice_pending: s.required_notice_pending,
            device_id: s.device.as_ref().map(|d| d.id.clone()),
            last_upload_unix_ms: s.last_upload_unix_ms,
            last_error: s.last_error.clone(),
        }
    }
}

/// The handle. Opening it reads the state file and nothing else; the
/// uploader thread runs once [`Telemetry::start`] is called.
pub struct Telemetry {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) cfg: ServiceConfig,
    pub(crate) api: Api,
    pub(crate) store: StateStore,
    /// The device identity (minted at open if the state had none).
    pub(crate) device: DeviceIdentity,
    /// Its cert hash, hex.
    pub(crate) cert_hash: String,
    /// The state key minted at open ([`StateKey::Mint`]), for the platform.
    pub(crate) minted_key: Option<Vec<u8>>,
    /// The running shares' credentials, by share id: a new relay token goes
    /// to each ([`crate::access`]).
    pub(crate) shares: Mutex<std::collections::HashMap<ShareId, Credentials>>,
    /// Keep the relay access fresh ([`ServiceConfig::relays`], then
    /// [`Telemetry::set_relay_access`]).
    pub(crate) manage_relays: AtomicBool,
    /// One pass at a time: the thread's, an explicit [`Telemetry::upload_now`]
    /// and a relay refresh ([`Telemetry::refresh_relays`]).
    pub(crate) pass_lock: Mutex<()>,
    signal: Mutex<Signal>,
    wake: Condvar,
    worker: Mutex<Option<Worker>>,
    /// The platform asked for radio silence: the thread runs no pass.
    dormant: AtomicBool,
    /// The next pass fetches the force flag whatever its schedule.
    status_wanted: AtomicBool,
}

/// The uploader thread, and the flag that tells it (and its pass) to stop.
struct Worker {
    handle: JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

/// Why a pass is wanted sooner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Nudge {
    /// There may be something to send (a record closed, the network
    /// changed, the app came to the foreground): soon, within the backoff.
    Soft,
    /// The user acted (switched on, or a refused switch-off wants the flag):
    /// soon, whatever the backoff.
    Urgent,
}

#[derive(Default)]
struct Signal {
    /// The strongest nudge not acted on yet.
    nudge: Option<Nudge>,
    /// [`Telemetry::finish`] wants a last pass.
    final_wanted: bool,
    /// How it went: `Some(true)` when it ran without failing.
    final_done: Option<bool>,
}

static GLOBAL: OnceLock<Telemetry> = OnceLock::new();
static GLOBAL_INIT: Mutex<()> = Mutex::new(());
/// [`set_dormant`]'s last word, for the global instance made after it.
static DORMANT: AtomicBool = AtomicBool::new(false);

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Telemetry {
    /// Read (or start) the state in `cfg.state_dir`. No network, no thread.
    /// A state file that exists but cannot be read is an error.
    pub fn open(cfg: ServiceConfig) -> Result<Telemetry, Error> {
        let api = Api::new(&cfg.api_bases, &cfg.app_version).map_err(Error::Config)?;
        Telemetry::open_with(cfg, api)
    }

    /// [`Telemetry::open`] with `api` in place of the one `cfg.api_bases`
    /// names (a test's built-in API over fake servers).
    pub(crate) fn open_with(cfg: ServiceConfig, api: Api) -> Result<Telemetry, Error> {
        let (sealer, minted_key) = Sealer::new(&cfg.state_key).map_err(Error::Config)?;
        let store = StateStore::open_sealed(&cfg.state_dir, sealer)?;
        let device = crate::access::ensure_identity(&store)?;
        let cert_hash = spora_core::identity::hex(&device.cert_hash());
        let cfg_relays = cfg.relays;
        Ok(Telemetry {
            inner: Arc::new(Inner {
                cfg,
                api,
                store,
                device,
                cert_hash,
                minted_key,
                shares: Mutex::new(std::collections::HashMap::new()),
                manage_relays: AtomicBool::new(cfg_relays),
                pass_lock: Mutex::new(()),
                signal: Mutex::new(Signal::default()),
                wake: Condvar::new(),
                worker: Mutex::new(None),
                dormant: AtomicBool::new(false),
                status_wanted: AtomicBool::new(false),
            }),
        })
    }

    /// The process-wide instance: opened and started by the first call,
    /// returned as is by every later one (whose `cfg` is then ignored).
    /// Never touches the network on the caller's thread.
    pub fn init_global(cfg: ServiceConfig) -> Result<&'static Telemetry, Error> {
        let _g = lock(&GLOBAL_INIT);
        if let Some(t) = GLOBAL.get() {
            return Ok(t);
        }
        let t = Telemetry::open(cfg)?;
        t.inner
            .dormant
            .store(DORMANT.load(Ordering::SeqCst), Ordering::SeqCst);
        let t = GLOBAL.get_or_init(|| t);
        t.start();
        Ok(t)
    }

    /// The state key minted at open ([`StateKey::Mint`]): the platform keeps
    /// it in its secure store and passes it back as [`StateKey::Provided`].
    pub fn minted_state_key(&self) -> Option<Vec<u8>> {
        self.inner.minted_key.clone()
    }

    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    /// Start (or stop) keeping the relay access fresh, as
    /// [`ServiceConfig::relays`] would have from the start: for a process
    /// that learns only later that it serves a share on Spora's relays.
    pub fn set_relay_access(&self, manage: bool) {
        let was = self.inner.manage_relays.swap(manage, Ordering::SeqCst);
        if manage && !was {
            self.inner.nudge(Nudge::Soft);
        }
    }

    /// The process-wide instance, once [`Telemetry::init_global`] made it.
    pub fn global() -> Option<&'static Telemetry> {
        GLOBAL.get()
    }

    pub fn config(&self) -> &ServiceConfig {
        &self.inner.cfg
    }

    /// The API this configuration uses (built-in or an override).
    pub fn api(&self) -> &Api {
        &self.inner.api
    }

    /// Start the uploader thread (idempotent). It does nothing while uploads
    /// are off, beyond the daily flag check of an already registered device.
    pub fn start(&self) {
        let mut worker = lock(&self.inner.worker);
        if worker.as_ref().is_some_and(|w| !w.handle.is_finished()) {
            return;
        }
        // Whatever an earlier `finish` asked of an earlier thread is not
        // this one's to do.
        self.inner.signal(|s| {
            s.final_wanted = false;
            s.final_done = None;
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (inner, flag) = (self.inner.clone(), stop.clone());
        match std::thread::Builder::new()
            .name("spora-telemetry".into())
            .spawn(move || run(inner, flag))
        {
            Ok(handle) => *worker = Some(Worker { handle, stop }),
            Err(e) => log::warn!("telemetry: cannot start the uploader thread ({e})"),
        }
    }

    /// Stop the uploader thread and wait for it: a pass under way ends
    /// after its current request.
    pub fn stop(&self) {
        let worker = lock(&self.inner.worker).take();
        if let Some(w) = worker {
            w.stop.store(true, Ordering::SeqCst);
            self.inner.signal(|_| {});
            let _ = w.handle.join();
        }
    }

    /// The end of the process: if the uploader thread runs and uploads are
    /// on, one last pass now — no debounce, no backoff — so a run's final
    /// record and log lines go before it exits; then stop the thread. Waits
    /// at most `timeout` in all (a pass still going then ends after its
    /// current request, unwaited for: cursors make an interrupted pass
    /// harmless). `true` if the pass ran to its end without failing.
    /// Nothing is sent while dormant ([`Telemetry::set_dormant`]).
    pub fn finish(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let Some(worker) = lock(&self.inner.worker).take() else {
            return false;
        };
        let wanted = !self.inner.dormant.load(Ordering::SeqCst)
            && self.inner.store.reload().is_ok_and(|s| s.upload_enabled);
        let mut done = false;
        if wanted {
            let mut sig = lock(&self.inner.signal);
            sig.final_done = None;
            sig.final_wanted = true;
            self.inner.wake.notify_all();
            loop {
                if let Some(ok) = sig.final_done.take() {
                    done = ok;
                    break;
                }
                let now = Instant::now();
                if now >= deadline || worker.handle.is_finished() {
                    break;
                }
                sig = self
                    .inner
                    .wake
                    .wait_timeout(sig, deadline - now)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        }
        worker.stop.store(true, Ordering::SeqCst);
        // A request the thread never took (still in an earlier pass when the
        // time ran out) is withdrawn: left standing, it would make the first
        // thing a later `start`'s thread does a last pass, and its last.
        // The thread reads both flags under this lock, `stop` first, so one
        // that took the request is running that pass and is not affected.
        self.inner.signal(|s| s.final_wanted = false);
        while !worker.handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        if worker.handle.is_finished() {
            let _ = worker.handle.join();
        }
        done
    }

    /// Radio silence (`true`): the uploader thread runs no pass — neither
    /// its timer's nor a nudge's — and a pass under way ends after its
    /// current request. Leaving it nudges. Explicit
    /// [`Telemetry::upload_now`] calls are not affected.
    pub fn set_dormant(&self, dormant: bool) {
        let was = self.inner.dormant.swap(dormant, Ordering::SeqCst);
        if was && !dormant {
            self.inner.nudge(Nudge::Soft);
        } else {
            self.inner.signal(|_| {});
        }
    }

    /// This process's view of the state (see [`Telemetry::reload`]), for
    /// this configuration's API ([`TelemetryStatus::for_api`]).
    pub fn status(&self) -> TelemetryStatus {
        TelemetryStatus::for_api(&self.inner.store.get(), &self.inner.api)
    }

    /// Re-read the state file, for a caller that shares it with another
    /// process, and return the result.
    pub fn reload(&self) -> Result<TelemetryStatus, Error> {
        Ok(TelemetryStatus::for_api(
            &self.inner.store.reload()?,
            &self.inner.api,
        ))
    }

    /// Flip the switch. Turning it off while the account requires telemetry
    /// fails with [`Error::Required`] and changes nothing — and has the
    /// uploader ask the server for the flag again soon, which may since have
    /// cleared it (a caller that can wait asks itself:
    /// [`Telemetry::refresh_status`]). The flag is the one
    /// [`Telemetry::status`] shows: a flag another API set on its own
    /// registration binds nothing here. Turning it on fails with
    /// [`Error::Config`] on a platform the API does not register.
    pub fn set_upload_enabled(&self, enabled: bool) -> Result<(), Error> {
        let platform = self.inner.cfg.platform.as_str();
        if enabled && !PLATFORMS.contains(&platform) {
            return Err(Error::Config(format!(
                "uploads are not available on {platform:?}"
            )));
        }
        let api = &self.inner.api;
        let changed = self.inner.store.modify(|s| {
            if !enabled && TelemetryStatus::for_api(s, api).required {
                // Whether there is anyone to ask again.
                return Err(s.served(|d| api.serves(d)).is_some());
            }
            let changed = s.upload_enabled != enabled;
            s.upload_enabled = enabled;
            Ok(changed)
        })?;
        let changed = match changed {
            Ok(c) => c,
            Err(registered) => {
                if registered {
                    self.inner.status_wanted.store(true, Ordering::SeqCst);
                    self.inner.nudge(Nudge::Urgent);
                }
                return Err(Error::Required);
            }
        };
        if changed {
            log::info!(
                "telemetry: uploads switched {}",
                if enabled { "on" } else { "off" }
            );
        }
        if enabled {
            self.inner.nudge(Nudge::Urgent);
        }
        Ok(())
    }

    /// Ask the server for the account's flag now, on the caller's thread
    /// (as long as a request takes: up to a minute or so). For a caller
    /// that can wait — e.g. after [`Error::Required`]: a flag the server has
    /// cleared since is then known, and switching off works. Without a
    /// device registered with this API there is no one to ask (and no flag
    /// that binds), and the state is returned as it is.
    pub fn refresh_status(&self) -> Result<TelemetryStatus, Error> {
        let st = self.inner.store.reload()?;
        if let Some(r) = st.served(|d| self.inner.api.serves(d)) {
            self.inner.new_pass(&|| false).fetch_status(&r.device)?;
        }
        Ok(self.status())
    }

    /// The UI has shown the force notice: the one [`Telemetry::status`]
    /// reported, or — with no registration with this API — the one the
    /// state as stored shows (`TelemetryStatus::from`).
    pub fn acknowledge_notice(&self) -> Result<(), Error> {
        let api = &self.inner.api;
        self.inner
            .store
            .modify(|s| match s.served(|d| api.serves(d)) {
                Some(r) => {
                    s.with_device(&r.device, |s| s.required_notice_pending = false);
                }
                None => s.required_notice_pending = false,
            })?;
        Ok(())
    }

    /// Ask for a pass soon (within any backoff the server asked for). Cheap
    /// and non-blocking.
    pub fn nudge(&self) {
        self.inner.nudge(Nudge::Soft);
    }

    /// One pass now, on the caller's thread: register if needed, fetch the
    /// flag, upload everything pending (files resting after a refusal
    /// included). Fails with [`Error::Off`] while uploads are off.
    pub fn upload_now(&self) -> Result<PassSummary, Error> {
        self.inner.pass(true, &|| false)
    }

    /// A pass as the uploader thread runs it.
    #[cfg(test)]
    pub(crate) fn background_pass(&self) -> Result<PassSummary, Error> {
        self.inner.pass(false, &|| false)
    }

    /// The record subscriber a platform gives every run: tracks open runs
    /// for the log's `run` stamps ([`diag::run_tracker`]) and nudges this
    /// uploader when a record closes.
    pub fn record_subscriber(&self) -> RecordSubscriber {
        subscriber(Arc::downgrade(&self.inner))
    }

    /// [`diag::bundle::export`] with this service's directories, the
    /// registered device id, and `platform`/`app_version` added to
    /// `platform_info` unless the caller set them.
    pub fn export_bug_report(
        &self,
        out: &Path,
        note: Option<String>,
        mut platform_info: BTreeMap<String, String>,
    ) -> std::io::Result<BundleSummary> {
        let cfg = &self.inner.cfg;
        platform_info
            .entry("platform".into())
            .or_insert_with(|| cfg.platform.clone());
        platform_info
            .entry("app_version".into())
            .or_insert_with(|| cfg.app_version.clone());
        let mut opts = BundleOptions::new(out);
        opts.record_dirs = cfg.record_dirs.clone();
        opts.log_dir = cfg.log_dir.clone().or_else(diag::log_dir);
        opts.note = note;
        opts.platform = platform_info;
        let st = self.inner.store.get();
        opts.device_id = st
            .served(|d| self.inner.api.serves(d))
            .map(|r| r.device)
            .or(st.device)
            .map(|d| d.id);
        diag::bundle::export(&opts)
    }
}

impl Drop for Telemetry {
    /// Ask the thread to stop without waiting for it (a request in flight
    /// can take a minute); [`Telemetry::stop`] is the waiting kind.
    fn drop(&mut self) {
        if let Some(w) = lock(&self.inner.worker).as_ref() {
            w.stop.store(true, Ordering::SeqCst);
        }
        self.inner.signal(|_| {});
    }
}

/// [`Telemetry::record_subscriber`] for the process-wide instance; the
/// nudge finds the instance when the record closes, so this can be built
/// before [`Telemetry::init_global`] (it only tracks runs until then).
pub fn record_subscriber() -> RecordSubscriber {
    let tracker = diag::run_tracker();
    Arc::new(move |entry: &Entry| {
        tracker(entry);
        if matches!(entry, Entry::Close(_))
            && let Some(t) = GLOBAL.get()
        {
            t.nudge();
        }
    })
}

/// Nudge the process-wide instance, if there is one.
pub fn nudge() {
    if let Some(t) = GLOBAL.get() {
        t.nudge();
    }
}

/// [`Telemetry::set_dormant`] for the process-wide instance; said before
/// [`Telemetry::init_global`], it holds for the instance made then.
pub fn set_dormant(dormant: bool) {
    let _g = lock(&GLOBAL_INIT);
    DORMANT.store(dormant, Ordering::SeqCst);
    if let Some(t) = GLOBAL.get() {
        t.set_dormant(dormant);
    }
}

/// [`Telemetry::finish`] for the process-wide instance: `false` (and
/// nothing done) when there is none.
pub fn finish(timeout: Duration) -> bool {
    GLOBAL.get().is_some_and(|t| t.finish(timeout))
}

fn subscriber(inner: Weak<Inner>) -> RecordSubscriber {
    let tracker = diag::run_tracker();
    Arc::new(move |entry: &Entry| {
        tracker(entry);
        if matches!(entry, Entry::Close(_))
            && let Some(i) = inner.upgrade()
        {
            i.nudge(Nudge::Soft);
        }
    })
}

impl Inner {
    fn signal(&self, f: impl FnOnce(&mut Signal)) {
        let mut s = lock(&self.signal);
        f(&mut s);
        self.wake.notify_all();
    }

    fn nudge(&self, kind: Nudge) {
        self.signal(|s| s.nudge = s.nudge.max(Some(kind)));
    }

    pub(crate) fn new_pass<'a>(&'a self, halt: &'a dyn Fn() -> bool) -> Pass<'a> {
        Pass {
            api: &self.api,
            store: &self.store,
            platform: &self.cfg.platform,
            cert_hash: &self.cert_hash,
            record_dirs: &self.cfg.record_dirs,
            log_dir: self.cfg.log_dir.as_deref(),
            status_interval: self.cfg.timings.status_interval,
            refresh_status: false,
            halt,
        }
    }

    fn pass(&self, explicit: bool, halt: &dyn Fn() -> bool) -> Result<PassSummary, Error> {
        let _g = lock(&self.pass_lock);
        // Relay access first: a share starting or renewing waits on it, an
        // upload does not. Its failure does not stop the uploads, but fails
        // the pass (for its backoff) if they went well.
        let renewed = if !halt() && self.renewal_due(crate::time::unix_ms()) {
            Some(self.renew_relay_access_locked(halt))
        } else {
            None
        };
        let mut pass = self.new_pass(halt);
        pass.refresh_status = self.status_wanted.swap(false, Ordering::SeqCst);
        let result = pass.run(explicit);
        let done = |sum: &PassSummary| {
            format!(
                "telemetry: pass {}: {} chunks of {} files, {} bytes sent, {} stored",
                if sum.halted { "halted" } else { "done" },
                sum.chunks,
                sum.files,
                sum.bytes_sent,
                sum.bytes_accepted
            )
        };
        match &result {
            Ok(sum) if sum.registered || sum.chunks > sum.log_chunks => {
                log::debug!("{}", done(sum))
            }
            // The log stream alone: below the log file's level, or each such
            // pass would leave the next one this line to send, and an
            // uploader with nothing else to do would never go quiet.
            Ok(sum) if sum.chunks > 0 => log::trace!("{}", done(sum)),
            Ok(_) | Err(Error::Off | Error::Required) => {}
            Err(e) => {
                let msg = e.to_string();
                if matches!(e, Error::Api(ApiError::Transport(_))) {
                    log::info!("telemetry: upload pass failed: {msg}");
                } else {
                    log::warn!("telemetry: upload pass failed: {msg}");
                }
                let _ = self.store.modify(|s| s.last_error = Some(msg));
            }
        }
        // A failed renewal (logged and noted where it failed) fails a pass
        // whose uploads went well, so the thread backs off before asking
        // again.
        match (result, renewed) {
            (Ok(_), Some(Err(e))) => Err(e),
            (r, _) => r,
        }
    }

    /// [`Inner::pass`] for the thread: a panic in a pass is a failed pass
    /// (backed off from), not the end of uploads for the process.
    fn guarded_pass(&self, halt: &dyn Fn() -> bool) -> Result<PassSummary, Error> {
        match std::panic::catch_unwind(AssertUnwindSafe(|| self.pass(false, halt))) {
            Ok(r) => r,
            Err(p) => {
                let what = p
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_default();
                let msg = format!("the upload pass panicked: {what}");
                log::error!("telemetry: {msg}");
                let _ = self.store.modify(|s| s.last_error = Some(msg.clone()));
                Err(Error::Io(io::Error::other(msg)))
            }
        }
    }
}

/// How a pass went, as far as the schedule cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Done,
    /// No answer from any base (offline, blocked).
    Unreachable,
    /// Failed otherwise (the server answered with an error), with the wait
    /// it asked for, if any.
    Failed(Option<Duration>),
}

impl Outcome {
    fn of(r: &Result<PassSummary, Error>) -> Outcome {
        match r {
            Ok(_) | Err(Error::Off) => Outcome::Done,
            Err(Error::Api(ApiError::Transport(_))) => Outcome::Unreachable,
            Err(Error::Api(ApiError::Status { retry_after, .. })) => Outcome::Failed(*retry_after),
            Err(_) => Outcome::Failed(None),
        }
    }
}

/// When the thread's next pass is due.
#[derive(Debug)]
struct Schedule {
    next: Instant,
    backoff: Option<Duration>,
    /// The earliest a soft nudge may bring the next pass to.
    floor: Instant,
}

impl Schedule {
    fn new(now: Instant) -> Schedule {
        Schedule {
            next: now,
            backoff: None,
            floor: now,
        }
    }

    /// The relay access wants renewing at `at`: as a nudge, it may bring the
    /// next pass forward, but never past a backoff.
    fn renewal(&mut self, at: Instant) {
        self.next = self.next.min(at.max(self.floor));
    }

    fn nudge(&mut self, kind: Nudge, now: Instant, t: &UploadTimings) {
        let soon = now + t.nudge_delay;
        match kind {
            Nudge::Soft => self.next = self.next.min(soon.max(self.floor)),
            Nudge::Urgent => {
                self.backoff = None;
                self.floor = now;
                self.next = self.next.min(soon);
            }
        }
    }

    fn passed(&mut self, outcome: Outcome, now: Instant, t: &UploadTimings) {
        if outcome == Outcome::Done {
            self.backoff = None;
            self.next = now + t.interval;
            self.floor = now;
            return;
        }
        let b = self
            .backoff
            .map_or(t.backoff_min, |b| (b * 2).min(t.backoff_max));
        self.backoff = Some(b);
        let wait = match outcome {
            Outcome::Failed(Some(asked)) => asked.clamp(b, MAX_RETRY_AFTER.max(b)),
            _ => b,
        };
        self.next = now + wait;
        // After no answer at all, a nudge (a changed network, above all)
        // may try again once the shortest backoff has passed; an answered
        // failure's backoff is the server's to set.
        self.floor = match outcome {
            Outcome::Unreachable => now + t.backoff_min.min(wait),
            _ => self.next,
        };
    }
}

fn run(inner: Arc<Inner>, stop: Arc<AtomicBool>) {
    let t = inner.cfg.timings.clone();
    let mut plan = Schedule::new(Instant::now());
    loop {
        let last = {
            let mut sig = lock(&inner.signal);
            loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                if sig.final_wanted {
                    sig.final_wanted = false;
                    break true;
                }
                let dormant = inner.dormant.load(Ordering::SeqCst);
                if !dormant && let Some(kind) = sig.nudge.take() {
                    plan.nudge(kind, Instant::now(), &t);
                }
                if !dormant && let Some(at) = inner.renewal_at() {
                    plan.renewal(at);
                }
                let now = Instant::now();
                if dormant {
                    // No pass until the platform says otherwise (which
                    // nudges); a nudge meanwhile waits too.
                    sig = inner.wake.wait(sig).unwrap_or_else(|e| e.into_inner());
                } else if now >= plan.next {
                    break false;
                } else {
                    sig = inner
                        .wake
                        .wait_timeout(sig, plan.next - now)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }
        };
        let halt =
            || stop.load(Ordering::SeqCst) || (!last && inner.dormant.load(Ordering::SeqCst));
        let result = inner.guarded_pass(&halt);
        if last {
            let ok = result.is_ok();
            inner.signal(|s| s.final_done = Some(ok));
            return;
        }
        plan.passed(Outcome::of(&result), Instant::now(), &t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timings() -> UploadTimings {
        UploadTimings {
            interval: Duration::from_secs(900),
            backoff_min: Duration::from_secs(60),
            backoff_max: Duration::from_secs(3600),
            status_interval: Duration::from_secs(86_400),
            nudge_delay: Duration::from_secs(2),
        }
    }

    #[allow(non_snake_case)]
    fn S(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn nudges_shorten_the_interval() {
        let t = timings();
        let t0 = Instant::now();
        let mut p = Schedule::new(t0);
        p.passed(Outcome::Done, t0, &t);
        assert_eq!(p.next, t0 + S(900));
        p.nudge(Nudge::Soft, t0 + S(10), &t);
        assert_eq!(p.next, t0 + S(12));
        // A later nudge does not push a pass already due sooner.
        p.nudge(Nudge::Soft, t0 + S(11), &t);
        assert_eq!(p.next, t0 + S(12));
    }

    #[test]
    fn an_answered_failure_holds_off_soft_nudges() {
        let t = timings();
        let t0 = Instant::now();
        let mut p = Schedule::new(t0);
        p.passed(Outcome::Failed(None), t0, &t);
        assert_eq!(p.next, t0 + S(60));
        p.passed(Outcome::Failed(None), t0, &t);
        assert_eq!(p.next, t0 + S(120));
        p.nudge(Nudge::Soft, t0 + S(1), &t);
        assert_eq!(p.next, t0 + S(120));
        // Retry-After lengthens the wait, past the backoff's cap (a quota
        // that frees tomorrow), up to a day.
        p.passed(Outcome::Failed(Some(S(1000))), t0, &t);
        assert_eq!(p.next, t0 + S(1000));
        p.passed(Outcome::Failed(Some(S(7200))), t0, &t);
        assert_eq!(p.next, t0 + S(7200));
        p.nudge(Nudge::Soft, t0 + S(10), &t);
        assert_eq!(p.next, t0 + S(7200));
        p.passed(Outcome::Failed(Some(S(99_999))), t0, &t);
        assert_eq!(p.next, t0 + S(86_400));
        // A shorter one does not cut the backoff.
        p.passed(Outcome::Failed(Some(S(1))), t0, &t);
        assert_eq!(p.next, t0 + S(1920));
        // The user switching on goes through, and starts the backoff over.
        p.nudge(Nudge::Urgent, t0 + S(5), &t);
        assert_eq!(p.next, t0 + S(7));
        p.passed(Outcome::Failed(None), t0 + S(7), &t);
        assert_eq!(p.next, t0 + S(67));
    }

    #[test]
    fn no_answer_lets_a_nudge_retry_after_the_shortest_backoff() {
        let t = timings();
        let t0 = Instant::now();
        let mut p = Schedule::new(t0);
        for _ in 0..5 {
            p.passed(Outcome::Unreachable, t0, &t);
        }
        assert_eq!(p.next, t0 + S(960));
        p.nudge(Nudge::Soft, t0 + S(5), &t);
        assert_eq!(p.next, t0 + S(60));
        p.nudge(Nudge::Soft, t0 + S(100), &t);
        assert_eq!(p.next, t0 + S(60));
        // The retry fails too: the backoff keeps growing.
        p.passed(Outcome::Unreachable, t0 + S(60), &t);
        assert_eq!(p.next, t0 + S(60 + 1920));
        p.passed(Outcome::Done, t0 + S(70), &t);
        assert_eq!(p.backoff, None);
    }
}
