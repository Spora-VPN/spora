//! `service.json`: the device identity (its key pair and cert), the device's
//! registration, the upload switch, the cached force-telemetry flag, the
//! per-file upload cursors, and the relay access the API gave it (the relay
//! advice and the relay token). The secrets in it are sealed when the
//! platform gives a key ([`crate::seal`]).
//!
//! A registration belongs to the API that issued it — the built-in API,
//! whatever fronts a release lists for it, or an override's own bases
//! ([`crate::api`]) — and so does what comes with it there: the cursors
//! (that server's lengths), the refusals, the account's flag. The active
//! registration keeps those at the top level of the file; a registration
//! with another API is parked with its own ([`Registration`], at most
//! [`MAX_PARKED`]), for when a process configured for that API runs again.
//! Two processes sharing the state but not the API — `SPORA_API` set in one
//! shell only — then take turns with their registrations instead of each
//! registering anew, and sending everything again, every pass. (Two
//! releases with different built-in fronts share one API, and one
//! registration.)
//!
//! Written atomically (temp file, fsync, rename; 0600 on Unix). Several
//! processes may share the file — a CLI `share`, a CLI `use`, a `spora
//! telemetry off` from another shell — so every change is a read-modify-write
//! under an advisory lock on a sidecar file ([`LOCK_FILE`]), held from the
//! read to the rename and never across a network request: no process writes
//! a stale copy back over another's change (the upload switch above all).
//!
//! Unknown fields survive a rewrite, the device's included, so a
//! downgrade-then-upgrade loses nothing. A file that cannot be parsed is
//! moved aside (`service.json.corrupt`) before anything replaces it, and the
//! device starts fresh. A file that cannot be *read* (permissions, I/O) is
//! an error, never a fresh state: acting on a default would report a switch
//! flipped that was not, or write an empty state over a real registration.
//! The directory must not be backed up or synced (Android: under
//! `noBackupFilesDir`): a restored token would make two installs one device.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::fsutil::{create_private_dir, create_private_file, open_lock_file, sync_dir, try_lock};
use crate::seal::Sealer;

pub const STATE_FILE: &str = "service.json";
pub const STATE_VERSION: u32 = 1;
/// Locked around every read-modify-write of [`STATE_FILE`], in the same
/// directory. Never deleted (that would let two processes lock two files).
pub const LOCK_FILE: &str = ".service.lock";

/// Registrations with other APIs kept besides the active one; parking one
/// more drops the oldest (whose API, used again, then registers anew).
pub const MAX_PARKED: usize = 4;

/// How long a change waits for another process's (a few file operations).
const LOCK_WAIT: Duration = Duration::from_secs(10);
/// The temp file of a save that never finished is removed after this long.
const STALE_TEMP: Duration = Duration::from_secs(60);

/// A registered device. `Debug` leaves the token out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub token: String,
    /// The API base URLs configured when the device registered. An
    /// override's device sends its token to these and no others: a client
    /// configured for another API registers a device of its own there
    /// rather than hand this token over (or let that API's answers change
    /// this registration). For a built-in device ([`Device::builtin`]) they
    /// are only a note of where it registered.
    #[serde(default)]
    pub api_bases: Vec<String>,
    /// Registered with the built-in API (a configuration that named no
    /// bases): its token goes to every front of the running release's
    /// built-in list, whichever fronts it registered at, and never to an
    /// override. `false`, an override's, for a device stored before the
    /// field existed (by development builds only).
    #[serde(default)]
    pub builtin: bool,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .field("api_bases", &self.api_bases)
            .field("builtin", &self.builtin)
            .finish()
    }
}

/// The device identity: one key pair and self-signed cert per device, for
/// every share it makes (spora-core's `DeviceIdentity`). Base64url DER; the
/// key is sealed on disk when there is a state key. `Debug` leaves the key
/// out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredIdentity {
    pub cert: String,
    pub key: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl StoredIdentity {
    /// A freshly minted identity, as stored (for seeding a state file).
    pub fn generate() -> StoredIdentity {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let d = spora_core::identity::DeviceIdentity::generate();
        StoredIdentity {
            cert: b64.encode(d.cert_der_bytes()),
            key: b64.encode(d.key_der_bytes()),
            extra: serde_json::Map::new(),
        }
    }
}

impl fmt::Debug for StoredIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredIdentity")
            .field("cert", &self.cert)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// One relay endpoint the API advised, as it described it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisedRelay {
    /// A spora-core URL tag (`quic`, `nz`, `tcptls`).
    pub protocol: String,
    pub host: String,
    pub port: u16,
}

/// The relay token the API minted for this device: opaque bytes
/// (base64url, sealed on disk when there is a state key) with what the API
/// said about them. `Debug` leaves the value out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedRelayToken {
    pub value: String,
    /// The device it names, as the API said (hex cert hash).
    #[serde(default)]
    pub subject: String,
    pub expires_unix_ms: u64,
    pub renew_after_unix_ms: u64,
    pub fetched_unix_ms: u64,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl fmt::Debug for CachedRelayToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedRelayToken")
            .field("value", &"<redacted>")
            .field("subject", &self.subject)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .field("renew_after_unix_ms", &self.renew_after_unix_ms)
            .field("fetched_unix_ms", &self.fetched_unix_ms)
            .finish()
    }
}

/// What a registration got from `GET /v1/relays`, and how asking went. A
/// failed request keeps the advice and the token it had.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAccess {
    /// The relays to write into new shares, in order. Empty: never fetched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advice: Vec<AdvisedRelay>,
    /// `None`: never fetched, or the API said the device is not entitled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<CachedRelayToken>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub last_success_unix_ms: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub last_failure_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl RelayAccess {
    pub fn is_empty(&self) -> bool {
        *self == RelayAccess::default()
    }
}

/// Bytes of each file the server has acknowledged, per stream
/// (`record`, `log`, `crash`) and file name.
pub type Cursors = BTreeMap<String, BTreeMap<String, u64>>;

/// A file that could not go at its cursor: the server refused the chunk
/// there, or it could not be read or sent from here. It rests until its
/// cursor moves or a day has passed ([`crate::upload::REFUSAL_REST`]), so a
/// refusal costs a request a day rather than one every pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// The cursor it was refused at.
    pub at: u64,
    pub unix_ms: u64,
    pub why: String,
}

/// Per stream and file name, like [`Cursors`].
pub type Refusals = BTreeMap<String, BTreeMap<String, Refusal>>;

/// A registration with everything that belongs to it at its API: the
/// fields [`ServiceState`] keeps at its top level for the active one. The
/// form a parked registration is kept in, and the view of one
/// ([`ServiceState::served`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Registration {
    pub device: Device,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub required_notice_pending: bool,
    #[serde(default)]
    pub status_checked_unix_ms: u64,
    #[serde(default)]
    pub status_failed_unix_ms: u64,
    #[serde(default)]
    pub cursors: Cursors,
    #[serde(default)]
    pub refused: Refusals,
    #[serde(default, skip_serializing_if = "RelayAccess::is_empty")]
    pub relay_access: RelayAccess,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Registration {
    /// `device` with nothing yet from its server.
    fn new(device: Device) -> Registration {
        Registration {
            device,
            required: false,
            required_notice_pending: false,
            status_checked_unix_ms: 0,
            status_failed_unix_ms: 0,
            cursors: Cursors::new(),
            refused: Refusals::new(),
            relay_access: RelayAccess::default(),
            extra: serde_json::Map::new(),
        }
    }

    /// Trade what belongs to a registration (all but the device itself)
    /// with the active one's in `s`. (A field added here is cleared in
    /// [`ServiceState::park`] too.)
    fn trade(&mut self, s: &mut ServiceState) {
        std::mem::swap(&mut self.required, &mut s.required);
        std::mem::swap(
            &mut self.required_notice_pending,
            &mut s.required_notice_pending,
        );
        std::mem::swap(
            &mut self.status_checked_unix_ms,
            &mut s.status_checked_unix_ms,
        );
        std::mem::swap(
            &mut self.status_failed_unix_ms,
            &mut s.status_failed_unix_ms,
        );
        std::mem::swap(&mut self.cursors, &mut s.cursors);
        std::mem::swap(&mut self.refused, &mut s.refused);
        std::mem::swap(&mut self.relay_access, &mut s.relay_access);
    }
}

/// One registration is another: the same token (ids are per server, so two
/// APIs may issue the same one).
fn same(a: &Device, b: &Device) -> bool {
    a.token == b.token
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceState {
    #[serde(default = "version")]
    pub v: u32,
    /// The device's key pair and cert, minted on first use. Every
    /// registration is made with its cert hash: one that was not (a state
    /// from before device identities) is forgotten when one is minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_identity: Option<StoredIdentity>,
    #[serde(default)]
    pub device: Option<Device>,
    #[serde(default)]
    pub upload_enabled: bool,
    /// Last-known force-telemetry flag, kept for offline sessions.
    #[serde(default)]
    pub required: bool,
    /// The UI owes the user the force notice.
    #[serde(default)]
    pub required_notice_pending: bool,
    /// When the flag was last refreshed from the server.
    #[serde(default)]
    pub status_checked_unix_ms: u64,
    /// When asking the server for the flag last failed (0: not since it last
    /// worked). The next attempt waits as long as after a success.
    #[serde(default)]
    pub status_failed_unix_ms: u64,
    #[serde(default)]
    pub last_upload_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub cursors: Cursors,
    #[serde(default)]
    pub refused: Refusals,
    /// The active registration's relay access.
    #[serde(default, skip_serializing_if = "RelayAccess::is_empty")]
    pub relay_access: RelayAccess,
    /// Registrations with other APIs, oldest first, each with its own
    /// cursors, refusals, flag and relay access (the fields above are the
    /// active one's).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parked: Vec<Registration>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn version() -> u32 {
    STATE_VERSION
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            v: STATE_VERSION,
            device_identity: None,
            device: None,
            upload_enabled: false,
            required: false,
            required_notice_pending: false,
            status_checked_unix_ms: 0,
            status_failed_unix_ms: 0,
            last_upload_unix_ms: None,
            last_error: None,
            cursors: Cursors::new(),
            refused: Refusals::new(),
            relay_access: RelayAccess::default(),
            parked: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }
}

/// How a load went, for callers that care whether the file was usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loaded {
    Read,
    Missing,
    /// Unparseable: the state starts fresh, and the file is moved aside
    /// (`service.json.corrupt`) before anything is written in its place.
    Corrupt,
    /// It could not be read at all ([`ServiceState::load_checked`] only;
    /// [`ServiceState::read`] says why).
    Unreadable,
}

impl ServiceState {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(STATE_FILE)
    }

    /// The state in `dir`: a missing file is a fresh state, and so (with a
    /// warning) is one that cannot be parsed; a file that cannot be read is
    /// an error. Changes nothing on disk. Sealed fields are left sealed: this
    /// is the state to show, never to act on a secret of.
    pub fn read(dir: &Path) -> io::Result<(ServiceState, Loaded)> {
        Self::read_with(dir, &Sealer::lenient())
    }

    /// [`ServiceState::read`] with the sealed fields opened by `sealer`. A
    /// file whose sealed fields do not open is state loss: [`Loaded::Corrupt`].
    pub(crate) fn read_with(dir: &Path, sealer: &Sealer) -> io::Result<(ServiceState, Loaded)> {
        let path = Self::path(dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok((ServiceState::default(), Loaded::Missing));
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot read {}: {e}", path.display()),
                ));
            }
        };
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| e.to_string())
            .and_then(|mut v| {
                sealer.open_state(&mut v).map_err(|e| e.0)?;
                serde_json::from_value::<ServiceState>(v).map_err(|e| e.to_string())
            });
        match parsed {
            Ok(s) => Ok((s, Loaded::Read)),
            Err(e) => {
                log::warn!("service: {} is unusable ({e})", path.display());
                Ok((ServiceState::default(), Loaded::Corrupt))
            }
        }
    }

    /// [`ServiceState::read`] for a caller that only shows the state: one
    /// that cannot be read comes back fresh (with a warning) as
    /// [`Loaded::Unreadable`] — to be shown as such, never acted on.
    pub fn load_checked(dir: &Path) -> (ServiceState, Loaded) {
        match Self::read(dir) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("service: {e}");
                (ServiceState::default(), Loaded::Unreadable)
            }
        }
    }

    /// [`ServiceState::load_checked`]'s state alone.
    pub fn load(dir: &Path) -> ServiceState {
        Self::load_checked(dir).0
    }

    /// Write atomically into `dir` (created, 0700 on Unix, if missing), the
    /// secrets in the clear. The bare write: changes other processes may
    /// race go through the store, which holds [`LOCK_FILE`] around the read
    /// and this.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        self.save_with(dir, &Sealer::lenient())
    }

    /// [`ServiceState::save`] with the secrets sealed by `sealer`.
    pub(crate) fn save_with(&self, dir: &Path, sealer: &Sealer) -> io::Result<()> {
        // Unique per save, so two writers in one process never share one.
        static SAVES: AtomicU64 = AtomicU64::new(0);
        create_private_dir(dir)?;
        let path = Self::path(dir);
        let n = SAVES.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".{STATE_FILE}.{}.{n}.tmp", std::process::id()));
        let mut value = serde_json::to_value(self).map_err(io::Error::other)?;
        sealer.seal_state(&mut value);
        let json = serde_json::to_vec_pretty(&value).map_err(io::Error::other)?;
        let written = (|| {
            let _ = std::fs::remove_file(&tmp);
            let mut f = create_private_file(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written?;
        sync_dir(dir);
        Ok(())
    }

    /// The cursor of one file, 0 if none.
    pub fn cursor(&self, stream: &str, file: &str) -> u64 {
        self.cursors
            .get(stream)
            .and_then(|m| m.get(file))
            .copied()
            .unwrap_or(0)
    }

    /// The refusal one file rests under, if any.
    pub fn refusal(&self, stream: &str, file: &str) -> Option<&Refusal> {
        self.refused.get(stream)?.get(file)
    }

    /// The active registration, with what belongs to it.
    pub fn registration(&self) -> Option<Registration> {
        let mut r = Registration::new(self.device.clone()?);
        r.required = self.required;
        r.required_notice_pending = self.required_notice_pending;
        r.status_checked_unix_ms = self.status_checked_unix_ms;
        r.status_failed_unix_ms = self.status_failed_unix_ms;
        r.cursors = self.cursors.clone();
        r.refused = self.refused.clone();
        r.relay_access = self.relay_access.clone();
        Some(r)
    }

    /// The registration an API configuration can use (`serves`: its
    /// [`crate::api::Api::serves`]), active or parked — the active one
    /// first, then the newest parked one. `None`: that API has none here,
    /// and nothing this state holds concerns it (the account flag of a
    /// registration with another API included).
    pub fn served(&self, serves: impl Fn(&Device) -> bool) -> Option<Registration> {
        if let Some(d) = &self.device
            && serves(d)
        {
            return self.registration();
        }
        self.parked
            .iter()
            .rev()
            .find(|p| serves(&p.device))
            .cloned()
    }

    /// Make the registration `serves` accepts the active one, parking the
    /// active one if need be, and return its device; `None` (and nothing
    /// changed) if there is none.
    pub(crate) fn activate(&mut self, serves: impl Fn(&Device) -> bool) -> Option<Device> {
        if let Some(d) = &self.device
            && serves(d)
        {
            return Some(d.clone());
        }
        let i = self.parked.iter().rposition(|p| serves(&p.device))?;
        let mut r = self.parked.remove(i);
        self.park();
        r.trade(self);
        self.device = Some(r.device);
        self.device.clone()
    }

    /// Park the active registration with what belongs to it, leaving the
    /// top level empty for another (without one, whatever is there belongs
    /// to nobody and goes). The oldest parked one goes beyond
    /// [`MAX_PARKED`].
    pub(crate) fn park(&mut self) {
        let Some(device) = self.device.take() else {
            // The fields `Registration::trade` trades.
            self.required = false;
            self.required_notice_pending = false;
            self.status_checked_unix_ms = 0;
            self.status_failed_unix_ms = 0;
            self.cursors.clear();
            self.refused.clear();
            self.relay_access = RelayAccess::default();
            return;
        };
        let mut r = Registration::new(device);
        r.trade(self);
        self.parked.retain(|p| !same(&p.device, &r.device));
        self.parked.push(r);
        let over = self.parked.len().saturating_sub(MAX_PARKED);
        self.parked.drain(..over);
    }

    /// `f` applied to the state as `dev` sees it — `dev` active, its own
    /// cursors, refusals and flag at the top level — whether it is the
    /// active registration or a parked one; what `f` changes there stays
    /// with `dev` (and the switch, which is no registration's, stays
    /// changed). `None`, and `f` not called, if the state no longer holds
    /// `dev`. `f` must not change `device` or `parked`.
    pub(crate) fn with_device<R>(
        &mut self,
        dev: &Device,
        f: impl FnOnce(&mut ServiceState) -> R,
    ) -> Option<R> {
        if self.device.as_ref().is_some_and(|d| same(d, dev)) {
            return Some(f(self));
        }
        let i = self.parked.iter().position(|p| same(&p.device, dev))?;
        let mut parked = std::mem::take(&mut self.parked);
        let r = &mut parked[i];
        r.trade(self);
        let active = self.device.replace(r.device.clone());
        let out = f(self);
        self.device = active;
        r.trade(self);
        self.parked = parked;
        Some(out)
    }

    /// Forget `dev`, active or parked, with everything that belonged to it.
    /// `false` if the state does not hold it.
    pub(crate) fn forget(&mut self, dev: &Device) -> bool {
        if self.device.as_ref().is_some_and(|d| same(d, dev)) {
            self.device = None;
            self.park(); // with no device: clears what was its
            return true;
        }
        let n = self.parked.len();
        self.parked.retain(|p| !same(&p.device, dev));
        self.parked.len() != n
    }
}

/// The state file plus this process's copy of it. Every read and every
/// change of the file holds [`LOCK_FILE`], so a change is always made to
/// the current contents and never undoes another process's:
/// [`StateStore::modify`] is a true read-modify-write across processes. The
/// lock is held for file work only, never across a request.
pub(crate) struct StateStore {
    dir: PathBuf,
    cache: Mutex<ServiceState>,
    sealer: Sealer,
}

impl StateStore {
    /// Open the state in `dir` (created if missing), secrets in the clear. A
    /// file that cannot be read is an error.
    #[cfg(test)]
    pub(crate) fn open(dir: &Path) -> io::Result<StateStore> {
        Self::open_sealed(dir, Sealer::lenient())
    }

    /// Open the state in `dir`, its secrets sealed by `sealer`: a file whose
    /// sealed fields do not open is moved aside and the state starts fresh.
    pub(crate) fn open_sealed(dir: &Path, sealer: Sealer) -> io::Result<StateStore> {
        create_private_dir(dir)?;
        let store = StateStore {
            dir: dir.to_path_buf(),
            cache: Mutex::new(ServiceState::default()),
            sealer,
        };
        {
            let mut cache = store.cache();
            let _lock = store.lock_file()?;
            sweep_temp_files(dir);
            *cache = store.load_locked()?;
        }
        Ok(store)
    }

    fn cache(&self) -> MutexGuard<'_, ServiceState> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lock the file against every other writer, waiting up to
    /// [`LOCK_WAIT`]. Closing the returned file releases the lock.
    fn lock_file(&self) -> io::Result<File> {
        let path = self.dir.join(LOCK_FILE);
        let f = open_lock_file(&path)?;
        let deadline = Instant::now() + LOCK_WAIT;
        let mut pause = Duration::from_millis(1);
        loop {
            match try_lock(&f) {
                Ok(()) => return Ok(f),
                // No file locks on this platform (there is one on every
                // platform Spora ships on): one process is all the state can
                // count on there.
                Err(TryLockError::Error(e)) if e.kind() == io::ErrorKind::Unsupported => {
                    return Ok(f);
                }
                Err(TryLockError::Error(e)) => return Err(e),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(pause);
                    pause = (pause * 2).min(Duration::from_millis(50));
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{} is held by another process", path.display()),
                    ));
                }
            }
        }
    }

    /// The file's state, with the lock held: an unparseable file is moved
    /// aside here, where no other process can be writing a good one.
    fn load_locked(&self) -> io::Result<ServiceState> {
        let (s, how) = ServiceState::read_with(&self.dir, &self.sealer)?;
        if how == Loaded::Corrupt {
            let path = ServiceState::path(&self.dir);
            let aside = path.with_extension("json.corrupt");
            match std::fs::rename(&path, &aside) {
                Ok(()) => log::warn!(
                    "service: moved {} to {}; starting fresh",
                    path.display(),
                    aside.display()
                ),
                Err(e) => log::warn!("service: cannot move {} aside ({e})", path.display()),
            }
        }
        Ok(s)
    }

    /// This process's copy.
    pub(crate) fn get(&self) -> ServiceState {
        self.cache().clone()
    }

    /// Re-read the file (another process may have changed it).
    pub(crate) fn reload(&self) -> io::Result<ServiceState> {
        let mut cache = self.cache();
        let _lock = self.lock_file()?;
        *cache = self.load_locked()?;
        Ok(cache.clone())
    }

    /// Apply `f` to the current file contents and save the result if it
    /// differs, all under the lock. The closure's value is returned either
    /// way.
    pub(crate) fn modify<R>(&self, f: impl FnOnce(&mut ServiceState) -> R) -> io::Result<R> {
        let mut cache = self.cache();
        let _lock = self.lock_file()?;
        let mut s = self.load_locked()?;
        let before = s.clone();
        let r = f(&mut s);
        if s != before {
            s.save_with(&self.dir, &self.sealer)?;
        }
        *cache = s;
        Ok(r)
    }

    /// Save the state as it is: proof, before obtaining something that must
    /// be kept (a registration), that it can be.
    pub(crate) fn rewrite(&self) -> io::Result<()> {
        let mut cache = self.cache();
        let _lock = self.lock_file()?;
        let s = self.load_locked()?;
        s.save_with(&self.dir, &self.sealer)?;
        *cache = s;
        Ok(())
    }
}

/// Remove the temp files of saves that never finished (a process killed
/// mid-save). Called with the lock held, so no save of the store is under
/// way; the age only spares a bare [`ServiceState::save`].
fn sweep_temp_files(dir: &Path) {
    let prefix = format!(".{STATE_FILE}.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.starts_with(&prefix) && name.ends_with(".tmp")) {
            continue;
        }
        let stale = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= STALE_TEMP);
        if stale {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut device = Device {
            id: "6f1c".into(),
            token: "secret-token".into(),
            api_bases: vec!["https://api.example".into()],
            builtin: true,
            extra: serde_json::Map::new(),
        };
        device
            .extra
            .insert("future".into(), serde_json::json!(true));
        let mut s = ServiceState {
            device: Some(device),
            upload_enabled: true,
            required: true,
            required_notice_pending: true,
            status_checked_unix_ms: 42,
            status_failed_unix_ms: 43,
            last_upload_unix_ms: Some(7),
            last_error: Some("http 503".into()),
            ..Default::default()
        };
        s.cursors
            .entry("record".into())
            .or_default()
            .insert("a.jsonl".into(), 123);
        s.refused.entry("log".into()).or_default().insert(
            "b.jsonl".into(),
            Refusal {
                at: 5,
                unix_ms: 6,
                why: "http 400 (misaligned)".into(),
            },
        );
        s.extra
            .insert("future".into(), serde_json::json!({"x": [1, 2]}));
        s.save(dir.path()).unwrap();

        let (back, how) = ServiceState::read(dir.path()).unwrap();
        assert_eq!(how, Loaded::Read);
        assert_eq!(back, s);
        assert_eq!(back.cursor("record", "a.jsonl"), 123);
        assert_eq!(back.cursor("log", "a.jsonl"), 0);
        assert_eq!(back.refusal("log", "b.jsonl").unwrap().at, 5);

        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ServiceState::path(dir.path())).unwrap())
                .unwrap();
        assert_eq!(raw["v"], 1);
        assert_eq!(raw["device"]["token"], "secret-token");
        assert_eq!(raw["device"]["builtin"], true);
        assert_eq!(raw["device"]["future"], true);
        assert_eq!(raw["future"]["x"][1], 2);
        assert_eq!(raw["cursors"]["record"]["a.jsonl"], 123);

        // No temp file left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [STATE_FILE]);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ServiceState::path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn debug_hides_the_token() {
        let d = Device {
            id: "id".into(),
            token: "secret-token".into(),
            api_bases: Vec::new(),
            builtin: false,
            extra: serde_json::Map::new(),
        };
        assert!(!format!("{d:?}").contains("secret-token"));
    }

    #[test]
    fn missing_and_partial_files() {
        let dir = tempfile::tempdir().unwrap();
        let (s, how) = ServiceState::load_checked(dir.path());
        assert_eq!(how, Loaded::Missing);
        assert_eq!(s, ServiceState::default());

        // Fields missing from an older or hand-edited file take defaults.
        std::fs::write(
            ServiceState::path(dir.path()),
            br#"{"upload_enabled":true,"device":{"id":"d","token":"t"}}"#,
        )
        .unwrap();
        let (s, how) = ServiceState::load_checked(dir.path());
        assert_eq!(how, Loaded::Read);
        assert!(s.upload_enabled);
        assert_eq!(s.v, STATE_VERSION);
        let d = s.device.unwrap();
        assert!(d.api_bases.is_empty());
        // A device stored before the field existed is an override's.
        assert!(!d.builtin);
    }

    #[test]
    fn corrupt_file_starts_fresh_and_is_kept_aside() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(ServiceState::path(dir.path()), b"{\"device\": tru").unwrap();
        // Reading alone moves nothing.
        let (s, how) = ServiceState::load_checked(dir.path());
        assert_eq!(how, Loaded::Corrupt);
        assert_eq!(s, ServiceState::default());
        assert!(ServiceState::path(dir.path()).exists());

        // The store sets it aside before anything can replace it.
        let store = StateStore::open(dir.path()).unwrap();
        assert!(!ServiceState::path(dir.path()).exists());
        assert!(dir.path().join("service.json.corrupt").exists());
        store.modify(|s| s.upload_enabled = true).unwrap();
        assert_eq!(ServiceState::load_checked(dir.path()).1, Loaded::Read);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_is_an_error_not_a_fresh_state() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path()).unwrap();
        store
            .modify(|s| {
                s.upload_enabled = true;
                s.device = Some(Device {
                    id: "d".into(),
                    token: "t".into(),
                    api_bases: Vec::new(),
                    builtin: false,
                    extra: serde_json::Map::new(),
                });
            })
            .unwrap();
        let path = ServiceState::path(dir.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&path).is_ok() {
            return; // root reads anything; nothing to test
        }
        assert!(ServiceState::read(dir.path()).is_err());
        assert_eq!(ServiceState::load_checked(dir.path()).1, Loaded::Unreadable);
        assert!(StateStore::open(dir.path()).is_err());
        assert!(store.reload().is_err());
        // Switching off must not "succeed" against a default state, and
        // switching on must not write a default over the registration.
        assert!(store.modify(|s| s.upload_enabled = false).is_err());
        assert!(store.modify(|s| s.upload_enabled = true).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let s = ServiceState::read(dir.path()).unwrap().0;
        assert!(s.upload_enabled && s.device.is_some());
    }

    /// Two stores on one directory race like two processes (the in-process
    /// mutex is per store); the lock file must serialize them anyway.
    #[test]
    fn changes_from_two_stores_are_never_lost() {
        const N: u64 = 40;
        let dir = tempfile::tempdir().unwrap();
        let a = StateStore::open(dir.path()).unwrap();
        let b = StateStore::open(dir.path()).unwrap();
        let bump = |store: &StateStore, key: &str| {
            for _ in 0..N {
                store
                    .modify(|s| {
                        *s.cursors
                            .entry("t".into())
                            .or_default()
                            .entry(key.into())
                            .or_default() += 1;
                    })
                    .unwrap();
            }
        };
        std::thread::scope(|sc| {
            sc.spawn(|| bump(&a, "a"));
            sc.spawn(|| bump(&b, "b"));
        });
        let s = ServiceState::read(dir.path()).unwrap().0;
        assert_eq!(s.cursor("t", "a"), N);
        assert_eq!(s.cursor("t", "b"), N);
    }

    fn dev(id: &str, base: &str) -> Device {
        Device {
            id: id.into(),
            token: format!("tok-{id}"),
            api_bases: vec![base.into()],
            builtin: false,
            extra: serde_json::Map::new(),
        }
    }

    fn at(base: &str) -> impl Fn(&Device) -> bool + '_ {
        move |d: &Device| d.api_bases.iter().any(|b| b == base)
    }

    /// A registration with another API is parked with everything that is
    /// its own, and comes back with it.
    #[test]
    fn registrations_are_parked_and_taken_back_whole() {
        let mut s = ServiceState {
            device: Some(dev("a", "A")),
            upload_enabled: true,
            required: true,
            required_notice_pending: true,
            status_checked_unix_ms: 5,
            last_error: Some("x".into()),
            ..Default::default()
        };
        s.cursors
            .entry("record".into())
            .or_default()
            .insert("f".into(), 7);
        let a = s.registration().unwrap();

        // Nothing this API's: nothing changes.
        assert_eq!(s.activate(at("B")), None);
        assert_eq!(s.device.as_ref().unwrap().id, "a");

        s.park();
        assert_eq!(s.device, None);
        assert!(!s.required && !s.required_notice_pending && s.cursors.is_empty());
        assert_eq!(s.status_checked_unix_ms, 0);
        // The switch and the notes are nobody's registration.
        assert!(s.upload_enabled);
        assert_eq!(s.last_error.as_deref(), Some("x"));
        assert_eq!(s.parked, std::slice::from_ref(&a));
        s.device = Some(dev("b", "B"));
        s.cursors
            .entry("record".into())
            .or_default()
            .insert("f".into(), 3);
        assert_eq!(s.served(at("A")), Some(a.clone()));
        assert_eq!(s.served(at("B")).unwrap().device.id, "b");
        assert_eq!(s.served(at("C")), None);

        assert_eq!(s.activate(at("A")).unwrap().id, "a");
        assert_eq!(s.registration(), Some(a));
        assert_eq!(s.parked.len(), 1);
        assert_eq!(s.parked[0].device.id, "b");
        assert_eq!(s.parked[0].cursors["record"]["f"], 3);

        // Survives the file.
        let dir = tempfile::tempdir().unwrap();
        s.save(dir.path()).unwrap();
        assert_eq!(ServiceState::read(dir.path()).unwrap().0, s);
    }

    /// Changes for a registration go to it, active or parked; a forgotten
    /// one takes none.
    #[test]
    fn changes_reach_their_own_registration() {
        let (a, b) = (dev("a", "A"), dev("b", "B"));
        let mut s = ServiceState {
            device: Some(a.clone()),
            ..Default::default()
        };
        s.park();
        s.device = Some(b.clone());
        let set = |s: &mut ServiceState, n: u64| {
            s.cursors
                .entry("log".into())
                .or_default()
                .insert("f".into(), n);
            s.required = true;
        };
        assert_eq!(s.with_device(&a, |s| set(s, 1)), Some(()));
        assert_eq!(s.cursor("log", "f"), 0);
        assert!(!s.required);
        assert_eq!(s.device.as_ref(), Some(&b));
        assert_eq!(s.parked[0].cursors["log"]["f"], 1);
        assert!(s.parked[0].required);
        s.with_device(&b, |s| set(s, 2));
        assert_eq!(s.cursor("log", "f"), 2);
        assert_eq!(s.parked[0].cursors["log"]["f"], 1);

        // The same id from another API is another registration.
        let mut a2 = dev("a", "A2");
        a2.token = "tok-a2".into();
        assert_eq!(s.with_device(&a2, |s| set(s, 9)), None);
        assert!(!s.forget(&a2));

        assert!(s.forget(&a));
        assert!(s.parked.is_empty());
        assert_eq!(s.with_device(&a, |s| set(s, 3)), None);
        assert!(s.forget(&b));
        assert_eq!(s.device, None);
        assert!(s.cursors.is_empty() && !s.required);
    }

    #[test]
    fn parking_keeps_the_newest_few() {
        let mut s = ServiceState::default();
        for i in 0..=MAX_PARKED + 1 {
            s.park();
            s.device = Some(dev(&i.to_string(), &format!("B{i}")));
        }
        let ids: Vec<&str> = s.parked.iter().map(|p| p.device.id.as_str()).collect();
        assert_eq!(ids.len(), MAX_PARKED);
        assert_eq!(ids.first(), Some(&"1"));
        assert_eq!(ids.last(), Some(&MAX_PARKED.to_string().as_str()));
        // Parked once only, however often.
        s.activate(at("B2")).unwrap();
        s.activate(at("B3")).unwrap();
        s.activate(at("B2")).unwrap();
        assert_eq!(s.parked.len(), MAX_PARKED);
    }

    #[test]
    fn stale_temp_files_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join(".service.json.1.0.tmp");
        let fresh = dir.path().join(".service.json.2.0.tmp");
        std::fs::write(&stale, b"half").unwrap();
        std::fs::write(&fresh, b"half").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        StateStore::open(dir.path()).unwrap();
        assert!(!stale.exists());
        assert!(fresh.exists(), "a save may still be writing it");
    }
}
