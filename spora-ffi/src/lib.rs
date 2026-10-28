uniffi::setup_scaffolding!();

mod service;

use crate::ConnectError::InvalidUrl;
use log::info;
use once_cell::sync::Lazy;
use spora_core::record::{NetworkFeed, NetworkState, RecordConfig};
use spora_core::tun_util;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Callback interface that Kotlin implements to protect sockets from VPN routing.
#[uniffi::export(callback_interface)]
pub trait SocketProtectorCallback: Send + Sync {
    fn protect(&self, fd: i32);
}

/// Callback interface for MTU notifications.
///
/// Called when the effective tunnel MTU is discovered (via PMTUD).
/// May be called multiple times: once after relay connection, and again after
/// direct P2P upgrade. The Android app can use the value to configure the TUN device MTU.
#[uniffi::export(callback_interface)]
pub trait MtuCallback: Send + Sync {
    fn on_mtu(&self, mtu: i32);
}

/// Tunnel lifecycle events surfaced to the host (used by the Apple client to
/// drive status UI: reconnecting, direct-path upgrade, session ended). Mirrors
/// [`spora_core::TunnelEvent`] with string-typed socket addresses so it lowers
/// cleanly over UniFFI.
#[derive(uniffi::Enum)]
pub enum SporaEvent {
    /// A transport path is active. `carrier` and `path` use the stable
    /// diagnostic-record vocabulary (for example `nz` and
    /// `direct_punched`).
    PathActivated {
        carrier: String,
        path: String,
        local: Option<String>,
        peer: String,
    },
    /// A relay-via session is up. `peer` is the remote address (the relay's
    /// address when the path goes through it).
    RelaySessionEstablished { peer: String },
    /// A direct (hole-punched) connection was established and handed to the
    /// transport router; the actual swap applies shortly after.
    DirectUpgradeSucceeded { local: String, peer: String },
    /// One direct-upgrade attempt failed (the upgrade task may retry).
    /// `code` is the stable vocabulary entry (`spora_core::record::Reason`);
    /// `reason` is the same thing in words. Count the first, show the second.
    DirectUpgradeFailed { code: String, reason: String },
    /// Client only: a re-dial is starting after the transport died.
    Reconnecting,
    /// Client only: the re-dial succeeded.
    Reconnected,
    /// The active session ended (peer replaced, cancelled, or transport closed).
    SessionEnded { reason: String },
    /// Share side: the connection log could not be written.
    ConnLogDegraded { detail: String },
}

impl From<spora_core::TunnelEvent> for SporaEvent {
    fn from(e: spora_core::TunnelEvent) -> Self {
        use spora_core::TunnelEvent as T;
        match e {
            T::PathActivated {
                carrier,
                path,
                local,
                peer,
            } => SporaEvent::PathActivated {
                carrier: carrier.as_str().into(),
                path: path.as_str().into(),
                local: local.map(|address| address.to_string()),
                peer: peer.to_string(),
            },
            T::RelaySessionEstablished { peer } => SporaEvent::RelaySessionEstablished {
                peer: peer.to_string(),
            },
            T::DirectUpgradeSucceeded { local, peer } => SporaEvent::DirectUpgradeSucceeded {
                local: local.to_string(),
                peer: peer.to_string(),
            },
            T::DirectUpgradeFailed { code, reason } => SporaEvent::DirectUpgradeFailed {
                code: code.to_string(),
                reason,
            },
            T::Reconnecting => SporaEvent::Reconnecting,
            T::Reconnected => SporaEvent::Reconnected,
            T::SessionEnded { reason } => SporaEvent::SessionEnded { reason },
            T::ConnLogDegraded { detail } => SporaEvent::ConnLogDegraded { detail },
        }
    }
}

/// Callback interface for tunnel lifecycle events. Implementations MUST be
/// non-blocking (enqueue and return) — the callback is invoked inline from the
/// tunnel's async tasks (see [`spora_core::EventHook`]).
#[uniffi::export(callback_interface)]
pub trait EventCallback: Send + Sync {
    fn on_event(&self, event: SporaEvent);
}

/// Wrap a UniFFI event callback into the non-blocking hook spora-core expects.
fn wrap_event_hook(cb: Option<Box<dyn EventCallback>>) -> spora_core::EventHook {
    cb.map(|cb| {
        let cb = Arc::new(cb);
        Arc::new(move |ev: spora_core::TunnelEvent| {
            cb.on_event(ev.into());
        }) as Arc<dyn Fn(spora_core::TunnelEvent) + Send + Sync>
    })
}

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime")
});

static NEXT_HANDLE: AtomicI32 = AtomicI32::new(1);
static SESSIONS: Lazy<Mutex<HashMap<i32, TunnelSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

struct TunnelSession {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
}

struct ShareSessionEntry {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    /// The share it serves: one instance per share, and the service's
    /// registry entry to drop on stop.
    share_id: spora_core::identity::ShareId,
    /// The session's DNS forwarder (see spora-core's `dns`), so the app can
    /// hand it the device's resolvers (`set_share_dns_servers`).
    dns: Arc<spora_core::dns::DnsForwarder>,
}

static SHARE_SESSIONS: Lazy<Mutex<HashMap<i32, ShareSessionEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// A poisoned lock still guards consistent data here (nothing panics while
/// holding one), and a panic must not cross into the app.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(uniffi::Record)]
pub struct ShareResult {
    pub handle: i32,
    pub url: String,
}

/// The kind of network underneath the tunnel, as the platform reports it
/// (spora-core's `record::NetworkKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkKind {
    /// No usable network at all.
    None,
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

impl From<NetworkKind> for spora_core::record::NetworkKind {
    fn from(k: NetworkKind) -> Self {
        use spora_core::record::NetworkKind as K;
        match k {
            NetworkKind::None => K::None,
            NetworkKind::Wifi => K::Wifi,
            NetworkKind::Cellular => K::Cellular,
            NetworkKind::Ethernet => K::Ethernet,
            NetworkKind::Other => K::Other,
        }
    }
}

/// The platform's network reports ([`set_network_state`]), shared by every
/// run's record: a record opens on the latest report and takes each later
/// one as a step until it closes — from the moment it opens, so a change
/// while `connect` is still dialing is recorded, whether the dial then
/// succeeds or fails.
static NETWORK: Lazy<NetworkFeed> = Lazy::new(NetworkFeed::new);

/// Taken around each report, so whether it changed anything is judged
/// against the report before it.
static NETWORK_REPORT: Mutex<()> = Mutex::new(());

/// Record directories this process has written to, for a bug report made
/// without the service ([`export_bug_report`]).
static RECORD_DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

pub(crate) fn record_dirs() -> Vec<PathBuf> {
    lock(&RECORD_DIRS).clone()
}

/// Report the network underneath the tunnel: the underlying non-VPN network
/// that has internet, or `None` when there is none. `validated` = the OS
/// confirmed it reaches the internet (Android's `NET_CAPABILITY_VALIDATED`);
/// `null` when the platform cannot tell. Kept for the records of runs that
/// start later, and recorded as a step in every open run's record — runs
/// still inside `connect`/`share` included. A change also nudges the
/// uploader: a new network is when a failed upload is worth retrying.
/// Repeating an unchanged state records nothing and nudges nothing.
#[uniffi::export]
pub fn set_network_state(kind: NetworkKind, validated: Option<bool>) {
    let state = NetworkState {
        kind: kind.into(),
        validated,
    };
    if report_network(state) {
        spora_service::nudge();
    }
}

/// Hand `state` to every run through the feed; whether it differs from the
/// report before it.
fn report_network(state: NetworkState) -> bool {
    let _serial = lock(&NETWORK_REPORT);
    let changed = NETWORK.current() != Some(state);
    NETWORK.set(state);
    changed
}

/// The record config for a run whose platform passed `record_dir`: the
/// network feed, and a subscriber that stamps diagnostic-log lines with the
/// run's id and nudges the uploader when the record closes.
fn record_config(record_dir: Option<String>) -> Option<RecordConfig> {
    let dir = PathBuf::from(record_dir?);
    {
        let mut dirs = lock(&RECORD_DIRS);
        if !dirs.contains(&dir) {
            dirs.push(dir.clone());
        }
    }
    // The subscriber hears network steps with the feed held, so it must
    // never report into the feed itself (it only tracks runs and nudges).
    Some(
        RecordConfig::in_dir(dir)
            .with_network_feed(NetworkFeed::clone(&NETWORK))
            .with_subscriber(spora_service::record_subscriber()),
    )
}

#[derive(Debug, uniffi::Error)]
pub enum ShareError {
    /// `init_service` has not run (shares need the device identity it keeps).
    NotInitialized,
    /// The share was made under another device identity (the service state
    /// was lost and the device minted a new one): offer to make a new share.
    IdentityMismatch,
    /// A share on Spora's relays was asked for before any relays were
    /// fetched: call `refresh_relays` first.
    NoRelayAdvice,
    /// This share is already running (one instance per share).
    AlreadyRunning,
    /// Not a share blob this build reads.
    InvalidShare(String),
    Generic(String),
}

impl std::fmt::Display for ShareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareError::NotInitialized => "the service is not initialized".fmt(f),
            ShareError::IdentityMismatch => {
                "the share was made under another device identity".fmt(f)
            }
            ShareError::NoRelayAdvice => "no relays from the API yet".fmt(f),
            ShareError::AlreadyRunning => "this share is already running".fmt(f),
            ShareError::InvalidShare(s) => write!(f, "not a share: {s}"),
            ShareError::Generic(s) => s.fmt(f),
        }
    }
}

/// Wrap a UniFFI callback into the closure type that spora-core expects.
fn wrap_protector(cb: Box<dyn SocketProtectorCallback>) -> spora_core::SocketProtector {
    let cb = Arc::new(cb);
    Some(Arc::new(move |fd: i32| {
        cb.protect(fd);
    }))
}

/// What one relay endpoint of a share is sent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RelayCredential {
    /// Nothing: an open relay.
    None,
    /// These bytes (a self-hosted relay's token, as the user pasted it).
    Static { token: Vec<u8> },
    /// The device's relay token: Spora's relays.
    Spora,
}

/// One relay endpoint of a share. `endpoint` is in the share URL's `?r=`
/// form: `host:port` (QUIC), `nz/host:port`, `tcptls/host:port` or
/// `direct/host:port`, an IPv6 literal bracketed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RelayEntry {
    pub endpoint: String,
    pub credential: RelayCredential,
}

impl TryFrom<RelayEntry> for spora_core::identity::RelayEntry {
    type Error = ShareError;
    fn try_from(e: RelayEntry) -> Result<Self, ShareError> {
        use spora_core::identity::Credential;
        Ok(spora_core::identity::RelayEntry {
            endpoint: spora_core::identity::RelayEndpoint::from_url_param(&e.endpoint)
                .map_err(ShareError::Generic)?,
            credential: match e.credential {
                RelayCredential::None => Credential::None,
                RelayCredential::Static { token } => Credential::Static(token),
                RelayCredential::Spora => Credential::Spora,
            },
        })
    }
}

impl From<&spora_core::identity::RelayEntry> for RelayEntry {
    fn from(e: &spora_core::identity::RelayEntry) -> Self {
        use spora_core::identity::Credential;
        RelayEntry {
            endpoint: e.endpoint.to_url_param(),
            credential: match &e.credential {
                Credential::None => RelayCredential::None,
                Credential::Static(token) => RelayCredential::Static {
                    token: token.clone(),
                },
                Credential::Spora => RelayCredential::Spora,
            },
        }
    }
}

fn service() -> Result<&'static spora_service::Telemetry, ShareError> {
    spora_service::Telemetry::global().ok_or(ShareError::NotInitialized)
}

fn parse_share(blob: &[u8]) -> Result<spora_core::identity::Share, ShareError> {
    spora_core::identity::Share::from_blob(blob).map_err(ShareError::InvalidShare)
}

/// Make a new share of this device and return its blob, offline. With
/// `use_spora`, the relays `refresh_relays` last fetched come first (each
/// presenting the device's relay token), then `own`; without fetched
/// relays that is [`ShareError::NoRelayAdvice`]. The platform stores the
/// blob (it holds the share's secret: keep it in an encrypted store) and
/// passes it to `start_share`; its URL never changes ([`share_url`]), so
/// other relays mean a new share.
#[uniffi::export]
pub fn make_share(own: Vec<RelayEntry>, use_spora: bool) -> Result<Vec<u8>, ShareError> {
    let own = own
        .into_iter()
        .map(spora_core::identity::RelayEntry::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let share = service()?.make_share(own, use_spora).map_err(|e| match e {
        spora_service::Error::NoRelayAdvice => ShareError::NoRelayAdvice,
        e => ShareError::Generic(e.to_string()),
    })?;
    Ok(share.to_blob())
}

/// A share's URL: the same for as long as the share exists.
#[uniffi::export]
pub fn share_url(share_blob: Vec<u8>) -> Result<String, ShareError> {
    Ok(parse_share(&share_blob)?.url().to_string())
}

/// A share's id (hex): public, unique per share.
#[uniffi::export]
pub fn share_id(share_blob: Vec<u8>) -> Result<String, ShareError> {
    Ok(spora_core::identity::hex(
        &parse_share(&share_blob)?.share_id,
    ))
}

/// A share's relays, in the order its URL lists them.
#[uniffi::export]
pub fn share_relays(share_blob: Vec<u8>) -> Result<Vec<RelayEntry>, ShareError> {
    Ok(parse_share(&share_blob)?
        .relays
        .iter()
        .map(Into::into)
        .collect())
}

/// Starts sharing this device's connection as the share `share_blob` (made
/// by [`make_share`] under this device's identity; another device's is
/// [`ShareError::IdentityMismatch`]). Never touches the network beyond the
/// share's own registrations: the relay token is the one the service has
/// cached (none: the share starts degraded and gets one when the service
/// renews), and every renewal reaches it until [`stop_share`]. One instance
/// per share ([`ShareError::AlreadyRunning`]).
///
/// Connection logging (the sharer-side per-flow record, see spora-core's
/// `connlog`): pass `conn_log_dir` to enable it. The app should pass a
/// directory under its files dir (e.g. `filesDir/connlog/<share id>`) and
/// exclude it from Android auto-backup. `conn_log_dir = None` disables
/// logging. `conn_log_retention_days = None` uses the core default (90
/// days). `conn_log_sessions_only = true` records who was connected and
/// when, but no per-flow destination records. Fails if `conn_log_dir` is
/// set but not writable — a default-on liability log must not silently
/// degrade at startup.
///
/// `record_dir` turns on the connection record (spora-core's `record`, the
/// diagnostic account of this run) in that directory — one directory for
/// every share and connect, not backed up (Android:
/// `noBackupFilesDir/records`). `None` keeps no record. `stun_servers`
/// empty uses the built-in list.
#[uniffi::export(default(record_dir = None, stun_servers = []))]
pub fn start_share(
    share_blob: Vec<u8>,
    protector: Option<Box<dyn SocketProtectorCallback>>,
    conn_log_dir: Option<String>,
    conn_log_retention_days: Option<u32>,
    conn_log_sessions_only: bool,
    record_dir: Option<String>,
    stun_servers: Vec<String>,
) -> Result<ShareResult, ShareError> {
    let svc = service()?;
    let share = parse_share(&share_blob)?;
    let device = svc.device_identity();
    if share.cert_hash != device.cert_hash() {
        return Err(ShareError::IdentityMismatch);
    }
    if lock(&SHARE_SESSIONS)
        .values()
        .any(|e| e.share_id == share.share_id && !e.task.is_finished())
    {
        return Err(ShareError::AlreadyRunning);
    }
    let uses_spora = share
        .relays
        .iter()
        .any(|r| r.credential == spora_core::identity::Credential::Spora);
    if uses_spora {
        svc.set_relay_access(true);
    }
    let conn_log = conn_log_dir.map(|dir| {
        let mut cfg = spora_core::connlog::ConnLogConfig::in_dir(dir);
        if let Some(days) = conn_log_retention_days {
            cfg.retention = std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60);
        }
        cfg.log_destinations = !conn_log_sessions_only;
        cfg
    });
    // Android has no resolv.conf, so `System` finds nothing and the public
    // fallback answers until the app supplies the network's resolvers via
    // `set_share_dns_servers`.
    let dns = spora_core::dns::DnsForwarder::system();
    let mut config = spora_core::Config {
        protector: protector.and_then(wrap_protector),
        conn_log,
        dns_forwarder: Some(dns.clone()),
        record: record_config(record_dir),
        relay_token: svc.relay_token(),
        ..spora_core::Config::default()
    };
    if !stun_servers.is_empty() {
        config.stun_servers = stun_servers;
    }
    let share_id = share.share_id;
    let session = RUNTIME
        .block_on(spora_core::share(device, share, config))
        .map_err(|e| {
            if e.starts_with(spora_core::identity::IDENTITY_MISMATCH) {
                ShareError::IdentityMismatch
            } else {
                ShareError::Generic(e)
            }
        })?;
    svc.register_share(share_id, session.credentials.clone());

    let url = session.url.to_string();
    let cancel = session.cancel.clone();
    let task = session.task;

    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    lock(&SHARE_SESSIONS).insert(
        id,
        ShareSessionEntry {
            cancel,
            task,
            share_id,
            dns,
        },
    );

    Ok(ShareResult { handle: id, url })
}

/// The tunnel's synthetic resolver address (spora-core's `dns::PROXY_ADDR`,
/// port 53). A *client* app sets it as the VPN's DNS server
/// (`VpnService.Builder.addDnsServer`); the sharer's DNS forwarder answers
/// it from the sharer's own resolvers, so the client never needs to know
/// what those are. Pure convention — nothing is negotiated on the wire.
#[uniffi::export]
pub fn dns_forwarder_address() -> String {
    spora_core::dns::PROXY_ADDR.to_string()
}

/// Tell a share session which resolvers this device is using, so clients'
/// queries are forwarded there. Android has no resolv.conf, so the app
/// supplies them: `ConnectivityManager.getLinkProperties(activeNetwork)
/// .getDnsServers()` right after `share()`, and again from
/// `NetworkCallback.onLinkPropertiesChanged`. Entries are `ip` or `ip:port`
/// (a v6 literal with a port is bracketed); unparseable ones are skipped
/// with a log line. An empty list means "unknown": the public fallback
/// answers.
///
/// Known defect: with Private DNS in strict mode the system resolves over
/// TLS while the forwarder sends plain UDP to the same addresses (see
/// spora-core's `dns`).
#[uniffi::export]
pub fn set_share_dns_servers(handle: i32, servers: Vec<String>) -> Result<(), TunnelError> {
    let sessions = lock(&SHARE_SESSIONS);
    let entry = sessions.get(&handle).ok_or(TunnelError::InvalidHandle)?;
    let mut parsed = Vec::with_capacity(servers.len());
    for s in &servers {
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            parsed.push(std::net::SocketAddr::new(ip, 53));
        } else if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
            parsed.push(addr);
        } else {
            log::warn!("set_share_dns_servers: ignoring unparseable resolver {s:?}");
        }
    }
    info!("FFI set_share_dns_servers(handle={handle}, servers={parsed:?})");
    entry.dns.set_servers(parsed);
    Ok(())
}

/// Stops the share session associated with the given handle.
#[uniffi::export]
pub fn stop_share(handle: i32) -> Result<(), TunnelError> {
    let entry = lock(&SHARE_SESSIONS)
        .remove(&handle)
        .ok_or(TunnelError::InvalidHandle)?;
    entry.cancel.cancel();
    entry.task.abort();
    if let Some(svc) = spora_service::Telemetry::global() {
        svc.unregister_share(&entry.share_id);
    }
    Ok(())
}

#[derive(Debug, uniffi::Error)]
pub enum ConnectError {
    InvalidUrl,
    Generic(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Generic(s) => s.fmt(f),
            InvalidUrl => "Invalid URL".fmt(f),
        }
    }
}

#[derive(Debug, uniffi::Error)]
pub enum TunnelError {
    InvalidHandle,
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::InvalidHandle => "Invalid tunnel handle".fmt(f),
        }
    }
}

/// Establishes a tunnel connection and returns a handle for managing it.
///
/// Blocks until the connection is established (relay negotiation),
/// then spawns the tunnel loop in the background and returns immediately.
/// The `protector` callback is invoked on every new socket fd so that
/// Android can call `VpnService.protect()` to bypass VPN routing.
/// Use `disconnect` to tear down the tunnel.
///
/// `record_dir` turns on the connection record for this run, as for
/// [`share`].
#[uniffi::export(default(record_dir = None))]
pub fn connect(
    url: String,
    tun_fd: RawFd,
    protector: Box<dyn SocketProtectorCallback>,
    mtu_callback: Option<Box<dyn MtuCallback>>,
    record_dir: Option<String>,
) -> Result<i32, ConnectError> {
    info!("FFI connect() called with tun_fd={}", tun_fd);

    let url = Url::parse(&url).map_err(|_| InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(InvalidUrl);
    }

    let mtu_cb: spora_core::MtuCallback = mtu_callback.map(|cb| {
        let cb = Arc::new(cb);
        Arc::new(move |mtu: u16| {
            cb.on_mtu(mtu as i32);
        }) as Arc<dyn Fn(u16) + Send + Sync>
    });

    let config = spora_core::Config {
        protector: wrap_protector(protector),
        mtu_callback: mtu_cb,
        record: record_config(record_dir),
        ..spora_core::Config::default()
    };

    let result = RUNTIME.block_on(async {
        spora_core::connect(url, &config)
            .await
            .map_err(ConnectError::Generic)
    })?;

    let cancel = result.cancel;
    let keepalive_knob = result.keepalive_knob;
    let keepalive_waker = result.keepalive_waker;
    info!("FFI connect(): relay established");

    // Spawn the tunnel loop in the background.
    let task = RUNTIME.spawn(async move {
        info!("FFI tunnel task: starting with tun_fd={}", tun_fd);
        let tun = unsafe { OwnedFd::from_raw_fd(tun_fd) };
        match tun_util::start_fd(result.transport, tun).await {
            Ok(()) => info!("FFI tunnel task: exited normally"),
            Err(e) => log::error!("FFI tunnel task: exited with error: {}", e),
        }
    });

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    info!("FFI connect(): returning handle={}", handle);
    lock(&SESSIONS).insert(
        handle,
        TunnelSession {
            cancel,
            task,
            keepalive_knob,
            keepalive_waker,
        },
    );

    Ok(handle)
}

/// Apple counterpart to [`connect`]. Establishes a tunnel and pumps packets
/// against an Apple `utun` descriptor (4-byte AF framing, unlike Android's raw
/// TUN). A `protector` (bind sockets to the physical interface via
/// `IP_BOUND_IF`) is required on macOS: unlike iOS, the OS does not auto-bypass
/// provider sockets, so without it the relay dial loops back into the tunnel and
/// dead-locks. An optional [`EventCallback`] surfaces lifecycle events for
/// status UI.
///
/// Blocks until the relay session is established, then spawns the tunnel loop
/// and returns a handle. The `tun_fd` ownership is transferred to Rust, which
/// closes it when the tunnel ends (the caller must hand over a `dup()` of the
/// provider's utun fd and not use it afterward).
///
/// `record_dir` turns on the connection record for this run, as for
/// [`share`].
#[uniffi::export(default(record_dir = None))]
pub fn connect_utun(
    url: String,
    tun_fd: RawFd,
    protector: Option<Box<dyn SocketProtectorCallback>>,
    mtu_callback: Option<Box<dyn MtuCallback>>,
    event_callback: Option<Box<dyn EventCallback>>,
    record_dir: Option<String>,
) -> Result<i32, ConnectError> {
    info!("FFI connect_utun() called with tun_fd={}", tun_fd);

    let url = Url::parse(&url).map_err(|_| InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(InvalidUrl);
    }

    let mtu_cb: spora_core::MtuCallback = mtu_callback.map(|cb| {
        let cb = Arc::new(cb);
        Arc::new(move |mtu: u16| {
            cb.on_mtu(mtu as i32);
        }) as Arc<dyn Fn(u16) + Send + Sync>
    });

    // On Darwin the OS does NOT auto-bypass provider-originated sockets, and
    // NEPacketTunnelNetworkSettings.excludedRoutes are unreliable for a packet
    // tunnel — so the Apple client passes a protector that binds each socket to
    // the physical interface (IP_BOUND_IF). Without it the relay dial routes back
    // into the tunnel and dead-locks.
    let config = spora_core::Config {
        protector: protector.and_then(wrap_protector),
        mtu_callback: mtu_cb,
        event_hook: wrap_event_hook(event_callback),
        record: record_config(record_dir),
        ..spora_core::Config::default()
    };

    let result = RUNTIME.block_on(async {
        spora_core::connect(url, &config)
            .await
            .map_err(ConnectError::Generic)
    })?;

    let cancel = result.cancel;
    let keepalive_knob = result.keepalive_knob;
    let keepalive_waker = result.keepalive_waker;
    info!("FFI connect_utun(): relay established");

    let task = RUNTIME.spawn(async move {
        info!("FFI utun tunnel task: starting with tun_fd={}", tun_fd);
        let tun = unsafe { OwnedFd::from_raw_fd(tun_fd) };
        match tun_util::start_fd_utun(result.transport, tun).await {
            Ok(()) => info!("FFI utun tunnel task: exited normally"),
            Err(e) => log::error!("FFI utun tunnel task: exited with error: {}", e),
        }
    });

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    info!("FFI connect_utun(): returning handle={}", handle);
    lock(&SESSIONS).insert(
        handle,
        TunnelSession {
            cancel,
            task,
            keepalive_knob,
            keepalive_waker,
        },
    );

    Ok(handle)
}

/// Tears down the tunnel associated with the given handle.
#[uniffi::export]
pub fn disconnect(handle: i32) -> Result<(), TunnelError> {
    info!("FFI disconnect() called with handle={}", handle);
    let session = lock(&SESSIONS)
        .remove(&handle)
        .ok_or(TunnelError::InvalidHandle)?;
    update_dormancy();
    info!("FFI disconnect(): cancelling token...");
    session.cancel.cancel();
    info!("FFI disconnect(): aborting task...");
    session.task.abort();
    info!("FFI disconnect(): done");
    Ok(())
}

/// Controls the keepalive behavior for a client tunnel.
///
/// - `interval_secs = 0`: on-demand mode (dormant when idle, probes on traffic after gap).
/// - `interval_secs > 0`: always probe at that interval (e.g. 20 when screen is on).
///
/// Transition from 0→N sends an immediate ping to detect dead connections.
///
/// The telemetry uploader follows: while every client tunnel's keepalive is
/// 0 it sends nothing, and a change back to N > 0 lets it catch up.
#[uniffi::export]
pub fn set_keepalive(handle: i32, interval_secs: u32) -> Result<(), TunnelError> {
    info!(
        "FFI set_keepalive(handle={}, interval_secs={})",
        handle, interval_secs
    );
    {
        let sessions = lock(&SESSIONS);
        let session = sessions.get(&handle).ok_or(TunnelError::InvalidHandle)?;
        session
            .keepalive_knob
            .store(interval_secs as u64, Ordering::Relaxed);
        // Wake the transport task so it notices the knob change immediately.
        // Without this, a Dormant transport has no timers and would sleep
        // until the next inbound/outbound packet.
        if let Some(w) = lock(&session.keepalive_waker).take() {
            w.wake();
        }
    }
    update_dormancy();
    Ok(())
}

/// Taken around each dormancy update, so the service hears them in the
/// order the table changed.
static DORMANCY: Mutex<()> = Mutex::new(());

/// Radio silence for the telemetry uploader ([`spora_service::set_dormant`])
/// follows the client tunnels: dormant while there is at least one and every
/// one of them has its keepalive at 0 (screen off, machine asleep), so a
/// dormant phone is not woken by uploads either. Re-evaluated when a knob
/// changes and when a tunnel goes; not when one comes, because a new
/// tunnel's knob reads 0 until the app sets it, right after `connect`.
fn update_dormancy() {
    let _serial = lock(&DORMANCY);
    let dormant = all_dormant(&lock(&SESSIONS));
    spora_service::set_dormant(dormant);
}

fn all_dormant(sessions: &HashMap<i32, TunnelSession>) -> bool {
    !sessions.is_empty()
        && sessions
            .values()
            .all(|s| s.keepalive_knob.load(Ordering::Relaxed) == 0)
}

/// Held by tests that touch this crate's process-wide state.
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use spora_core::record::{NetworkKind as Kind, Outcome, Record, Recorder, Role, StepKind};
    use std::time::{Duration, Instant};

    fn network_steps(record: &Record) -> Vec<NetworkState> {
        record
            .steps
            .iter()
            .filter(|s| s.kind == StepKind::Network)
            .filter_map(|s| s.network)
            .collect()
    }

    fn snapshot(record: &Recorder) -> Record {
        record.snapshot().unwrap()
    }

    fn tunnel(knob: u64) -> TunnelSession {
        TunnelSession {
            cancel: CancellationToken::new(),
            task: RUNTIME.spawn(async {}),
            keepalive_knob: Arc::new(AtomicU64::new(knob)),
            keepalive_waker: Arc::new(Mutex::new(None)),
        }
    }

    struct NoProtector;

    impl SocketProtectorCallback for NoProtector {
        fn protect(&self, _fd: i32) {}
    }

    #[test]
    fn network_kinds_map_onto_the_record_vocabulary() {
        for (kind, code) in [
            (NetworkKind::None, "none"),
            (NetworkKind::Wifi, "wifi"),
            (NetworkKind::Cellular, "cellular"),
            (NetworkKind::Ethernet, "ethernet"),
            (NetworkKind::Other, "other"),
        ] {
            assert_eq!(Kind::from(kind).as_str(), code);
        }
    }

    #[test]
    fn network_reports_reach_every_open_run() {
        let _g = lock(&TEST_LOCK);
        let wifi = NetworkState {
            kind: Kind::Wifi,
            validated: Some(true),
        };
        let cellular = NetworkState {
            kind: Kind::Cellular,
            validated: Some(false),
        };
        let none = NetworkState {
            kind: Kind::None,
            validated: None,
        };
        set_network_state(NetworkKind::Wifi, Some(true));

        let dir = tempfile::tempdir().unwrap();
        let cfg = record_config(Some(dir.path().to_string_lossy().into_owned())).unwrap();
        assert_eq!(cfg.dir.as_deref(), Some(dir.path()));
        assert!(cfg.network_feed.is_some());
        assert!(cfg.subscriber.is_some());
        assert!(record_dirs().contains(&dir.path().to_path_buf()));
        assert!(record_config(None).is_none());

        // a run opens on the network last reported, and hears every change
        // once from then on: no table entry needed, which a run still inside
        // `connect`/`share` does not have yet
        let client = Recorder::start(&cfg, Role::Client, None, vec![], false);
        let exit = Recorder::start(&cfg, Role::Exit, None, vec![], false);
        assert_eq!(snapshot(&client).open.network, Some(wifi));
        // only a change nudges the uploader
        assert!(report_network(cellular));
        assert!(!report_network(cellular));
        set_network_state(NetworkKind::Cellular, Some(false));
        assert_eq!(network_steps(&snapshot(&client)), vec![cellular]);
        assert_eq!(network_steps(&snapshot(&exit)), vec![cellular]);

        // a closed run hears nothing more
        client.close_shutdown(None);
        set_network_state(NetworkKind::None, None);
        assert_eq!(network_steps(&snapshot(&client)), vec![cellular]);
        assert_eq!(network_steps(&snapshot(&exit)), vec![cellular, none]);
        exit.close_shutdown(None);
    }

    /// The case the feed is for: the network changes while `connect` is
    /// still dialing, and the dial fails.
    #[test]
    fn a_change_during_a_failing_dial_is_in_its_record() {
        let _g = lock(&TEST_LOCK);
        set_network_state(NetworkKind::Wifi, Some(false));
        // a relay that takes the connection, sees the network go, and hangs
        // up in the middle of the handshake
        let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = relay.local_addr().unwrap().port();
        let hang_up = std::thread::spawn(move || {
            let (conn, _) = relay.accept().unwrap();
            set_network_state(NetworkKind::None, None);
            drop(conn);
        });
        let dir = tempfile::tempdir().unwrap();
        // The version byte and any 44 bytes make a token.
        let url = format!(
            "https://example.invalid/s/AQ{}?r=tcptls/127.0.0.1:{port}",
            "A".repeat(58)
        );
        let result = connect(
            url,
            -1,
            Box::new(NoProtector),
            None,
            Some(dir.path().to_string_lossy().into_owned()),
        );
        assert!(matches!(result, Err(ConnectError::Generic(_))));
        hang_up.join().unwrap();

        // the record is written on its own thread
        let deadline = Instant::now() + Duration::from_secs(10);
        let record = loop {
            let closed = Record::read_dir(dir.path())
                .unwrap_or_default()
                .into_iter()
                .map(|(_, r)| r)
                .find(|r| r.close.is_some());
            if let Some(r) = closed {
                break r;
            }
            assert!(Instant::now() < deadline, "no closed record");
            std::thread::sleep(Duration::from_millis(20));
        };
        let wifi = NetworkState {
            kind: Kind::Wifi,
            validated: Some(false),
        };
        let none = NetworkState {
            kind: Kind::None,
            validated: None,
        };
        assert_eq!(record.open.network, Some(wifi));
        assert_eq!(network_steps(&record), vec![none]);
        assert_eq!(record.close.unwrap().outcome, Outcome::NeverConnected);
    }

    #[test]
    fn uploads_rest_while_every_client_tunnel_is_dormant() {
        let _g = lock(&TEST_LOCK);
        let mut sessions = HashMap::new();
        assert!(!all_dormant(&sessions), "no tunnel to keep quiet for");
        sessions.insert(1, tunnel(0));
        assert!(all_dormant(&sessions));
        sessions.insert(2, tunnel(20));
        assert!(!all_dormant(&sessions));
        sessions[&2].keepalive_knob.store(0, Ordering::Relaxed);
        assert!(all_dormant(&sessions));

        // the exported calls keep the table (and the service) in step
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        lock(&SESSIONS).insert(handle, tunnel(20));
        set_keepalive(handle, 0).unwrap();
        assert!(all_dormant(&lock(&SESSIONS)));
        set_keepalive(handle, 20).unwrap();
        assert!(!all_dormant(&lock(&SESSIONS)));
        set_keepalive(handle, 0).unwrap();
        disconnect(handle).unwrap();
        assert!(!all_dormant(&lock(&SESSIONS)));
        assert!(matches!(
            set_keepalive(handle, 0),
            Err(TunnelError::InvalidHandle)
        ));
        assert!(matches!(
            disconnect(handle),
            Err(TunnelError::InvalidHandle)
        ));
    }

    #[test]
    fn share_handles_are_checked() {
        let _g = lock(&TEST_LOCK);
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        lock(&SHARE_SESSIONS).insert(
            handle,
            ShareSessionEntry {
                cancel: CancellationToken::new(),
                task: RUNTIME.spawn(async {}),
                share_id: [9; 8],
                dns: spora_core::dns::DnsForwarder::system(),
            },
        );
        set_share_dns_servers(handle, vec!["192.0.2.53".into(), "nonsense".into()]).unwrap();
        stop_share(handle).unwrap();
        assert!(matches!(
            stop_share(handle),
            Err(TunnelError::InvalidHandle)
        ));
        assert!(matches!(
            set_share_dns_servers(handle, vec![]),
            Err(TunnelError::InvalidHandle)
        ));
    }
}
