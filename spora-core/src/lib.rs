mod carrier;
pub mod connlog;
pub mod direct_port;
pub mod dns;
pub mod e2e;
pub mod e2e_noise;
pub mod e2e_tls;
pub mod identity;
mod neg;
mod reassembly;
pub mod record;
pub mod server;
pub mod signal;
pub mod transport;
pub mod tun_util;

use std::collections::HashSet;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use log::{debug, info, warn};
use quinn::Connection;
use stunclient::StunClient;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
pub use tokio_util::sync::CancellationToken;
use url::Url;

use crate::connlog::{AddrKind, ConnLog, ConnLogConfig, SessionLog};
use crate::e2e::{authenticate_incoming, client_connect, client_endpoint, server_endpoint};
use crate::identity::{
    CertHash, Credentials, DeviceIdentity, ROUTING_HASH_LEN, RelayEndpoint, RelayEntry,
    RelayProtocol, RoutingHash, SECRET_LEN, Share, ShareIdentity, Token,
};
use crate::neg::{NegChannel, SignalNegChannel};
use crate::record::{
    Carrier, EndpointRef, Fault, MtuSource, Outcome, PathKind, PathState, Reason, Recorder, Role,
    RttSource, StepKind,
};
use crate::server::TunnelError;
pub use crate::server::is_local_address;
use crate::signal::SignalChannel;
use crate::transport::DialFuture;
pub use crate::transport::IpTransport;
use crate::transport::ReconnectTransport;
use crate::transport::keepalive::{
    KeepAliveConfig, KeepAliveMode, KeepAliveTransport, LinkCounters,
};
use crate::transport::upgradable::{UpgradeSender, upgradable_transport};
pub use relay_client::RegisterTarget;
use relay_client::protocol::RegisterKind;

/// Callback invoked once after the end-to-end QUIC connection's PMTUD has
/// converged. The application can use this to configure its TUN device.
pub type MtuCallback = Option<Arc<dyn Fn(u16) + Send + Sync>>;

/// The OS handle of a freshly bound outer socket, as handed to a
/// [`SocketProtector`]: the raw fd on Unix, the raw `SOCKET` on Windows.
#[cfg(unix)]
pub type SocketHandle = i32;
/// The OS handle of a freshly bound outer socket, as handed to a
/// [`SocketProtector`]: the raw fd on Unix, the raw `SOCKET` on Windows.
#[cfg(windows)]
pub type SocketHandle = u64;

/// Called with every outer (relay/STUN/punch/TCP) socket the core creates,
/// before it is used, so the platform can keep it out of its own tunnel:
/// `VpnService.protect()` on Android, `IP_BOUND_IF` on macOS, `SO_MARK` +
/// policy routing on Linux, `IP_UNICAST_IF` on Windows.
pub type SocketProtector = Option<Arc<dyn Fn(SocketHandle) + Send + Sync>>;

/// Future driving one share-side session; it should resolve when the session
/// ends (transport closed/errored) or its cancellation token fires.
pub type SessionFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Invoked once per accepted client session when `ExitMode::Custom` is set.
/// Receives the fully composed session transport (keepalive + upgradable +
/// QUIC) and a token that is cancelled when a new peer replaces this session
/// or the share stops.
pub type SessionHandler =
    Arc<dyn Fn(IpTransport, CancellationToken) -> SessionFuture + Send + Sync>;

/// How the share side turns tunneled IP packets into real traffic.
#[derive(Clone, Default)]
pub enum ExitMode {
    /// Userland smoltcp netstack (default). Unprivileged: TCP/UDP flows are
    /// terminated in-process and re-originated from ordinary OS sockets.
    #[default]
    Netstack,
    /// Bypass the netstack: hand each session's `IpTransport` to the
    /// application, which is expected to move packets into the OS (e.g. a TUN
    /// device plus kernel forwarding/NAT). Requires privileges on the caller's
    /// side; the core still owns accept, registration, and direct upgrade.
    Custom(SessionHandler),
}

/// Call the protector callback with the socket's OS handle.
pub fn protect_socket(protector: &SocketProtector, socket: &UdpSocket) {
    if let Some(f) = protector {
        f(raw_socket_handle(socket));
    }
}

fn apply_protector_to_std(protector: &SocketProtector, socket: &std::net::UdpSocket) {
    if let Some(f) = protector {
        f(raw_socket_handle(socket));
    }
}

/// The platform's raw handle for a socket, in the form a [`SocketProtector`]
/// receives.
#[cfg(unix)]
pub(crate) fn raw_socket_handle(socket: &impl std::os::unix::io::AsRawFd) -> SocketHandle {
    socket.as_raw_fd()
}

/// The platform's raw handle for a socket, in the form a [`SocketProtector`]
/// receives.
#[cfg(windows)]
pub(crate) fn raw_socket_handle(socket: &impl std::os::windows::io::AsRawSocket) -> SocketHandle {
    socket.as_raw_socket()
}

pub struct ConnectResult {
    pub transport: IpTransport,
    /// Stops the run: cancelling it closes the live session's connection
    /// (the exit records an orderly leave), ends the background tasks and
    /// closes the record.
    pub cancel: CancellationToken,
    /// Stops the run like `cancel` and waits until the stop has reached the
    /// network — for a process about to exit (see [`RunStopper::stop`]).
    pub stopper: RunStopper,
    pub keepalive_knob: Arc<AtomicU64>,
    pub keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    /// This run's diagnostic record (see [`record`]). Disabled — and inert —
    /// unless `Config::record` asked for one. It is closed when `cancel`
    /// fires; a caller that ends the session another way should close it.
    pub record: Recorder,
}

/// The longest [`RunStopper::stop`] waits for a stopped client's QUIC close
/// to be handed to the network. It normally takes well under a millisecond;
/// the bound is for a connection whose socket will not take it.
pub const STOP_FLUSH_GRACE: Duration = Duration::from_millis(500);

/// Stops a client run and waits until the stop has reached the network.
/// Cheap to clone; obtained from [`ConnectResult::stopper`].
#[derive(Clone)]
pub struct RunStopper {
    cancel: CancellationToken,
    /// Cancelled once the run's closing is done.
    closed: CancellationToken,
}

impl RunStopper {
    /// Stop the run — exactly what cancelling [`ConnectResult::cancel`]
    /// does — and wait until it has finished closing: the record closed and
    /// the live session's QUIC close handed to the network (at most
    /// [`STOP_FLUSH_GRACE`] spent on that). A process that is about to exit
    /// awaits this before its runtime goes: dropped too early, the runtime
    /// takes the connection's driver with it before the close is sent, the
    /// exit hears nothing, and its keepalive declares the session dead 30 s
    /// later — a failure in its record, for a client that left on purpose.
    /// Best called while the transport is still held: dropping it first
    /// closes the connection too, but only this close is watched until it
    /// has gone out.
    pub async fn stop(&self) {
        self.cancel.cancel();
        self.closed.cancelled().await;
    }
}

/// Every protocol interval/timeout that used to be a hardcoded constant.
/// `Default` is exactly today's production values; tests and the lab can
/// scale them down to make slow scenarios run in seconds of wall time.
#[derive(Clone, Debug)]
pub struct Timings {
    /// Cadence of the sharer's REGISTER packets to the relay.
    pub register_interval: Duration,
    /// QUIC max idle timeout (both relay-via and direct connections). Also
    /// the nz carrier's recv-idle deadline. This is the passive backstop
    /// reaper for a dead/quiet session (no packets → connection torn down).
    pub quic_idle_timeout: Duration,
    /// Interval of the SHARE side's reactive ICMP keepalive (NOT a quinn
    /// keep-alive anymore — quinn's periodic keepalive was removed so the
    /// transport-agnostic keepalive layer is the single, knob-honoring
    /// control point; see `transport::quic::build_transport_config`). The
    /// client side is knob-driven (Adaptive), not this.
    pub quic_keep_alive: Duration,
    /// `ReconnectTransport` sleep after a failed dial.
    pub reconnect_delay: Duration,
    /// Initiator wait after a failed direct-upgrade attempt — the first wait
    /// of a streak of consecutive failures. Each further failure doubles it,
    /// up to `upgrade_retry_max`. The streak is per session (a reconnect
    /// starts over) and a wake from dormancy (keepalive knob 0 -> >0) starts
    /// it over too.
    pub upgrade_retry_delay: Duration,
    /// Cap on the doubling initiator retry wait (see `upgrade_retry_delay`).
    pub upgrade_retry_max: Duration,
    /// How long the transport router holds the current transport's death
    /// waiting for an in-flight direct-upgrade swap before propagating it
    /// (see `transport::upgradable`). Must cover the responder's conclusion
    /// racing the initiator's close of the old path — which can trail by a
    /// QUIC PTO or two (hundreds of ms) on high-RTT paths, not just a
    /// reordered flight.
    pub upgrade_rescue_grace: Duration,
    /// Timeout for each of the two punch phases (punch exchange + verify).
    pub punch_phase_timeout: Duration,
    /// Interval between punch/verify packets within a phase.
    pub punch_send_interval: Duration,
    /// Initiator timeout waiting for the responder's endpoint over the
    /// signal channel.
    pub endpoint_exchange_timeout: Duration,
    /// Per-service budget for one STUN binding query. A black-holed service
    /// must yield quickly enough for the next configured service to be tried.
    pub stun_query_timeout: Duration,
    /// Per-relay budget for the client's relay-via dial (handshake + accept
    /// ack). When it elapses the client fails over to the next relay, so a
    /// dead/censored relay doesn't stall the whole connect on one endpoint.
    pub relay_dial_timeout: Duration,
    /// Adaptive keepalive: send-silence gap that re-activates probing.
    pub keepalive_idle_threshold: Duration,
    /// Adaptive keepalive: how long to wait for a ping response.
    pub keepalive_response_timeout: Duration,
    /// Adaptive keepalive: inbound within this window keeps the peer alive.
    pub keepalive_inbound_grace: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            register_interval: relay_client::DEFAULT_REGISTER_INTERVAL, // 30s
            quic_idle_timeout: Duration::from_secs(30),
            quic_keep_alive: Duration::from_secs(10),
            reconnect_delay: transport::RECONNECT_DELAY, // 5s
            upgrade_retry_delay: Duration::from_secs(15),
            upgrade_retry_max: Duration::from_secs(5 * 60),
            upgrade_rescue_grace: Duration::from_secs(2),
            punch_phase_timeout: Duration::from_secs(5),
            punch_send_interval: Duration::from_millis(300),
            endpoint_exchange_timeout: Duration::from_secs(10),
            stun_query_timeout: Duration::from_secs(3),
            relay_dial_timeout: Duration::from_secs(8),
            keepalive_idle_threshold: Duration::from_secs(20),
            keepalive_response_timeout: Duration::from_secs(3),
            keepalive_inbound_grace: Duration::from_secs(5),
        }
    }
}

/// Lifecycle notifications emitted by `share()`/`connect()` sessions.
#[derive(Debug, Clone)]
pub enum TunnelEvent {
    /// A transport path is active and can carry tunnel traffic. Emitted for
    /// the initial carrier and again after an acknowledged direct-path swap.
    /// Unlike the older relay/direct lifecycle events, this names the exact
    /// carrier and path and is therefore suitable for automated assertions.
    PathActivated {
        carrier: Carrier,
        path: PathKind,
        local: Option<SocketAddr>,
        peer: SocketAddr,
    },
    /// A relay-via QUIC session is up (sharer: peer accepted; client:
    /// connected to the sharer). `peer` is the remote address of the QUIC
    /// connection — the relay's address when the path goes through it.
    RelaySessionEstablished { peer: SocketAddr },
    /// A direct connection was established and the transport router
    /// acknowledged replacing the relay path with it. Traffic submitted
    /// after this event uses the direct path.
    DirectUpgradeSucceeded { local: SocketAddr, peer: SocketAddr },
    /// One direct-upgrade attempt failed (the upgrade task may retry).
    /// `code` is the vocabulary entry (see [`record::Reason`]) and is what
    /// anything counting failures should use; `reason` is the same thing in
    /// words, for a human reading a log.
    DirectUpgradeFailed { code: Reason, reason: String },
    /// Client only: a re-dial is starting after the transport died.
    Reconnecting,
    /// Client only: the re-dial succeeded.
    Reconnected,
    /// Share side: the active session ended (replaced by a new peer,
    /// cancelled, or its transport closed).
    SessionEnded { reason: String },
    /// Share side: the connection log could not be written (disk full, IO
    /// error). The tunnel is unaffected; the gap is recorded in the log
    /// itself once writing recovers.
    ConnLogDegraded { detail: String },
}

/// Hook invoked inline from the tunnel's async tasks for every
/// [`TunnelEvent`]. **Hooks must be non-blocking** — do the minimum (e.g.
/// push into an unbounded channel) and return; blocking here stalls the
/// session that emitted the event.
pub type EventHook = Option<Arc<dyn Fn(TunnelEvent) + Send + Sync>>;

fn emit(hook: &EventHook, event: TunnelEvent) {
    if let Some(h) = hook {
        h(event);
    }
}

#[derive(Clone)]
pub struct Config {
    /// STUN services used for direct-path discovery, in fallback order. Each
    /// service gets a bounded query attempt; the socket from the first
    /// successful response is retained for punching.
    pub stun_servers: Vec<String>,
    pub protector: SocketProtector,
    pub mtu_callback: MtuCallback,
    /// Share side only: what consumes the tunneled IP packets.
    pub exit_mode: ExitMode,
    /// Protocol intervals/timeouts. Defaults are production values.
    pub timings: Timings,
    /// Lifecycle event hook. Must be non-blocking (see [`EventHook`]).
    pub event_hook: EventHook,
    /// Whether to attempt the direct (hole-punched) upgrade after a relay-via
    /// session is established. Disabling holds the session on the relay; the
    /// signal channel is kept open so the peer's upgrade attempts time out
    /// instead of seeing EOF.
    pub enable_direct_upgrade: bool,
    /// Share side only: per-flow connection logging (see [`connlog`]).
    /// `None` disables it at the core level; platforms are expected to
    /// enable it by default with a platform-appropriate directory. When set
    /// but unwritable, `share()` fails loudly rather than running unlogged.
    pub conn_log: Option<ConnLogConfig>,
    /// Share side only: the DNS forwarder behind the tunnel's synthetic
    /// resolver address (see [`dns`]). The default forwards clients' queries
    /// to this host's own system resolvers, with a public fallback. `None`
    /// disables it: queries to the synthetic address are then dropped like
    /// any other private destination.
    pub dns_forwarder: Option<Arc<dns::DnsForwarder>>,
    /// Whether, and where, to keep a diagnostic record of how each
    /// connection went (see [`record`]). `None` — the default — records
    /// nothing: writing to a user's disk is the platform's decision, not the
    /// core's. Platforms that want the "send logs" story, and the lab, set a
    /// directory here.
    pub record: Option<record::RecordConfig>,
    /// Share side only: the device's current relay token, presented to every
    /// relay endpoint of the share whose credential is
    /// [`Credential::Spora`](crate::identity::Credential::Spora) (the same
    /// bytes for every such relay of every share). Opaque here. `None` starts
    /// the share degraded: those relays get tokenless registrations, which an
    /// authorizing relay refuses, until
    /// [`ShareSession::update_relay_token`] brings one.
    pub relay_token: Option<Vec<u8>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stun_servers: default_stun_servers(),
            protector: None,
            mtu_callback: None,
            exit_mode: ExitMode::Netstack,
            timings: Timings::default(),
            event_hook: None,
            enable_direct_upgrade: true,
            conn_log: None,
            dns_forwarder: Some(dns::DnsForwarder::system()),
            record: None,
            relay_token: None,
        }
    }
}

/// Log target of every line that names one of a client's flows (its source or
/// destination address). Such lines keep their levels on stderr and logcat,
/// but the diagnostic log file never keeps this target: per-flow destinations
/// belong to the connection log, which never leaves the sharer's machine.
pub const FLOW_LOG_TARGET: &str = "spora_core::flow";

/// Log target of periodic per-connection statistics and per-probe lines.
/// The diagnostic log file drops this target: the connection record's
/// samples already carry these numbers, at a cadence that keeps the file's
/// history measured in days rather than hours.
pub const STATS_LOG_TARGET: &str = "spora_core::stats";

/// Built-in STUN fallback order. The first four answered from the Russian
/// field-lab node when selected; Google remains last for networks where it is
/// reachable. Provider diversity precedes Cloudflare's alternate port.
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
    "stun.relay.metered.ca:80",
    "stun.cloudflare.com:53",
    "stun.l.google.com:19302",
];

pub fn default_stun_servers() -> Vec<String> {
    DEFAULT_STUN_SERVERS
        .iter()
        .map(|server| (*server).to_owned())
        .collect()
}

/// The built-in relay: the default for a share with no relay of its own
/// choosing (tests, the lab, a CLI given none and no API).
pub const DEFAULT_RELAY: (&str, u16) = ("167.71.66.250", 443);

pub struct ShareSession {
    pub url: Url,
    pub cancel: CancellationToken,
    pub task: JoinHandle<()>,
    /// This run's diagnostic record (see [`record`]), e.g. for reporting
    /// network changes into it. Disabled — and inert — unless
    /// `Config::record` asked for one. The share loop closes it however the
    /// share ends.
    pub record: Recorder,
    /// The share's credential state: what its registrars and park workers
    /// present. Clone it to renew the relay token from elsewhere.
    pub credentials: Credentials,
}

impl ShareSession {
    /// Present `token` from now on to every relay of this share that wants
    /// the device's relay token: one write, then every registrar of the
    /// current listener generation (QUIC and nz) sends a REGISTER at once,
    /// and an empty TCP park pool refills at once. Sessions, direct
    /// upgrades, sockets and the connection log are untouched; healthy
    /// parked connections stay (a relay checks tokens when it parks, never
    /// while it forwards).
    pub fn update_relay_token(&self, token: Option<Vec<u8>>) {
        self.credentials.set_spora_token(token);
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }

    pub fn abort(self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

/// Start serving `share` under `device` (the identity the share was made
/// under; any other is refused with an
/// [`IDENTITY_MISMATCH`](crate::identity::IDENTITY_MISMATCH) error).
///
/// Persistence is the caller's: the device identity (spora-service keeps it)
/// and the share's blob ([`Share::to_blob`], the platform keeps it). The URL
/// is the share's ([`Share::url`]): the same every time the same share is
/// started. The relays come from the share, each with its credential;
/// `config.relay_token` is the device's relay token for the `Spora` ones.
pub async fn share(
    device: DeviceIdentity,
    share: Share,
    config: Config,
) -> Result<ShareSession, String> {
    let identity = Arc::new(ShareIdentity::new(&device, &share)?);
    let routing_hash = identity.routing_hash;
    let relays: Vec<RelayEntry> = share.relays.clone();
    if relays.is_empty() {
        return Err("share: the share has no relays".into());
    }
    let endpoints = share.endpoints();
    let url = share.url();
    let credentials = Credentials::new(config.relay_token.clone());

    // Resolve only the UDP-QUIC relays — the ones the signed-REGISTER loop
    // announces to. `TcpTls` relays are reached by the sharer connecting OUT
    // (spawn_tcp_registrars), not by UDP registration. A `Direct` endpoint is
    // the sharer's own advertised listener (the CLIENT resolves the name), so a
    // Direct/TcpTls hostname the sharer can't resolve locally must NOT abort it.
    let register_targets: Vec<RegisterTarget> = if relays
        .iter()
        .any(|r| r.endpoint.protocol == RelayProtocol::UdpQuic)
    {
        resolve_register_targets(&relays, RelayProtocol::UdpQuic).map_err(|f| f.detail)?
    } else {
        Vec::new()
    };

    // A `Direct` (relay-less) sharer must bind the advertised port so clients
    // can dial it; a relay-only sharer keeps an ephemeral port (0). One socket
    // means one port, so all Direct endpoints must agree on it.
    let direct_ports: std::collections::BTreeSet<u16> = endpoints
        .iter()
        .filter(|r| !r.protocol.is_relayed())
        .map(|r| r.port)
        .collect();
    let bind_port = match direct_ports.len() {
        0 => 0,
        1 => *direct_ports.iter().next().unwrap(),
        _ => {
            return Err(format!(
                "share: all direct endpoints must use one port (a single socket), got {:?}",
                direct_ports
            ));
        }
    };

    // Bind dual-stack when any endpoint is (or may be) v6: a resolved relay v6,
    // or a Direct endpoint that is a v6 literal or a hostname (which may carry an
    // AAAA record the client will dial). Only a Direct *v4 literal* stays v4-only
    // — resolving the advertised name here (which may be external-only) is
    // avoided, so a dual-stack socket serves whichever family the client picks.
    let want_v6 = register_targets.iter().any(|t| t.addr.is_ipv6())
        || endpoints
            .iter()
            .any(|r| !r.protocol.is_relayed() && r.host.parse::<std::net::Ipv4Addr>().is_err());

    // Sign each relay registration with the device's certificate key, so the
    // relay (which holds no secret) can verify the routing hash is ours and
    // reject an on-path attacker's attempt to rebind it. ONE signer per share,
    // shared by every registrar generation (see QuicListenerCtx), the nz
    // carrier and the TCP park pool: one strictly-increasing timestamp series
    // per routing hash, which must not restart when the listener rolls.
    let signer = Arc::new(std::sync::Mutex::new(
        relay_client::protocol::RegisterSigner::new(
            &identity.cert_der_bytes,
            &identity.key_der_bytes,
            identity.share_id,
        )
        .map_err(|e| format!("build register signer: {}", e))?,
    ));

    let cancel = CancellationToken::new();
    let rec = open_record(
        &config,
        Role::Exit,
        Some(&routing_hash),
        endpoint_refs(&endpoints),
    );
    let listener_ctx = QuicListenerCtx {
        protector: config.protector.clone(),
        want_v6,
        register_targets,
        register_interval: config.timings.register_interval,
        signer: signer.clone(),
        credentials: credentials.clone(),
        identity: identity.clone(),
        timings: config.timings.clone(),
        cancel: cancel.clone(),
        rec: rec.clone(),
    };
    // Direct endpoints get their own PERMANENT endpoint on the advertised
    // port: it never rolls (the port is in the URL) and never registers.
    // The relay-facing listener always starts on an ephemeral port and
    // rolls per accepted session. Splitting the two means a mixed
    // Direct + relay config gets the full per-port behavior on its relay
    // path instead of falling back to the legacy shared endpoint.
    let direct_endpoint = if bind_port != 0 {
        let binding = rec
            .step(StepKind::ListenerBind)
            .path(PathKind::DirectAdvertised);
        let sock = match bind_share_udp(&config.protector, want_v6, bind_port) {
            Ok(s) => s,
            Err(e) => {
                binding.fail(Reason::BindFailed, e.clone());
                rec.close(Outcome::NeverConnected, Some(Reason::BindFailed), None);
                return Err(e);
            }
        };
        match sock.local_addr() {
            Ok(a) => binding.local(a).ok(),
            Err(_) => binding.ok(),
        }
        Some(server_endpoint(sock, &identity, &config.timings).map_err(|f| f.detail)?)
    } else {
        None
    };
    // Generation 0; bind errors surface from share() itself.
    let listener = match listener_ctx.spawn_listener(0) {
        Ok(l) => l,
        Err(e) => {
            rec.close(Outcome::NeverConnected, Some(Reason::BindFailed), None);
            return Err(e);
        }
    };
    info!(
        "share: e2e endpoint up, rh {:x?}, registering with {:?}, direct bind_port {}",
        &routing_hash[..4],
        listener_ctx
            .register_targets
            .iter()
            .map(|t| t.addr)
            .collect::<Vec<_>>(),
        bind_port
    );

    // Connection log: opened before the share goes live, so a default-on log
    // that cannot be written fails here loudly instead of running unlogged.
    let conn_log = match &config.conn_log {
        Some(cfg) => match ConnLog::open(cfg.clone(), &identity, config.event_hook.clone()) {
            Ok(cl) => Some(cl),
            Err(e) => {
                rec.close(
                    Outcome::NeverConnected,
                    Some(Reason::StorageError),
                    Some(e.clone()),
                );
                return Err(e);
            }
        },
        None => None,
    };

    let cancel_child = cancel.clone();
    let config_for_loop = config.clone();
    let identity_for_loop = identity.clone();
    let record = rec.clone();
    let carriers = ShareCarriers {
        relays,
        signer,
        credentials: credentials.clone(),
    };
    let task = tokio::spawn(run_share_loop(
        listener,
        listener_ctx,
        direct_endpoint,
        identity_for_loop,
        carriers,
        cancel_child,
        config_for_loop,
        conn_log,
        rec,
    ));

    Ok(ShareSession {
        url,
        cancel,
        task,
        record,
        credentials,
    })
}

/// What a share's non-QUIC carriers (TCP park pool, nz) need beyond the
/// config: the share's relays with their credentials, its one signer, and
/// its credential state.
struct ShareCarriers {
    relays: Vec<RelayEntry>,
    signer: Arc<std::sync::Mutex<relay_client::protocol::RegisterSigner>>,
    credentials: Credentials,
}

/// Closes the exit's record however `run_share_loop` ends — including the
/// endings nobody planned. `stop` is the share's own token: cancelled, the
/// share was stopped; not cancelled, the loop ended on its own or its task
/// was dropped — which, when the process panicked, is the program failing
/// rather than anyone shutting it down.
struct ShareRecordGuard {
    rec: Recorder,
    stop: CancellationToken,
}

impl Drop for ShareRecordGuard {
    fn drop(&mut self) {
        let reason = if !self.stop.is_cancelled() && record::crashing() {
            Reason::Crashed
        } else {
            Reason::LocalShutdown
        };
        self.rec.close_shutdown(Some(reason));
    }
}

/// Everything needed to mint a fresh QUIC listener generation. The rolling
/// listener is the sharer half of the per-port session design: every accepted
/// session PERMANENTLY claims the socket it arrived on (its own endpoint, its
/// own relay flow, its own port), and the routing key immediately moves to a
/// fresh socket via re-registration — the relay's `rk -> addr` binding always
/// points at a port with no active flow, so a new client can never be
/// dropped for an old client's sake (the "actively-serving lockout"), and
/// same-DCID Initials can never be swallowed by a previous session's
/// connection (one endpoint per session). The relay needs no changes: its
/// flow table is keyed by addresses (existing flows keep forwarding), and a
/// REGISTER from a new source displaces the old binding.
///
/// NAT caveat (pre-existing for a client-less sharer, wider now): a listener
/// socket's NAT mapping is kept alive ONLY by its outbound REGISTERs, which
/// the relay never answers — on NATs whose unreplied-UDP timeout is at or
/// below the register interval (netfilter default: 30s, equal to ours;
/// CGNAT often less) the mapping can lapse between REGISTERs and inbound
/// Initials forwarded by the relay are dropped until the next REGISTER
/// re-opens it. The clean fix is a tiny relay REGISTER-ACK (makes the
/// conntrack state "replied", typical timeout 120s+, and doubles as
/// registration confirmation) — relay follow-up, not done here.
struct QuicListenerCtx {
    protector: SocketProtector,
    want_v6: bool,
    register_targets: Vec<RegisterTarget>,
    register_interval: Duration,
    signer: Arc<std::sync::Mutex<relay_client::protocol::RegisterSigner>>,
    credentials: Credentials,
    identity: Arc<ShareIdentity>,
    timings: Timings,
    cancel: CancellationToken,
    rec: Recorder,
}

/// One listener generation: the quinn endpoint clients currently land on and
/// the registrar task announcing its socket to the relays.
struct QuicListener {
    endpoint: quinn::Endpoint,
    registrar: Option<JoinHandle<()>>,
}

impl QuicListenerCtx {
    /// Bind a socket (`bind_port` 0 except for generation 0 of a Direct
    /// sharer), build the endpoint, and start registering from it.
    fn spawn_listener(&self, bind_port: u16) -> Result<QuicListener, String> {
        let binding = self.rec.step(StepKind::ListenerBind);
        let std_socket = match bind_share_udp(&self.protector, self.want_v6, bind_port) {
            Ok(s) => s,
            Err(e) => {
                binding.fail(Reason::BindFailed, e.clone());
                return Err(e);
            }
        };
        match std_socket.local_addr() {
            Ok(a) => binding.local(a).ok(),
            Err(_) => binding.ok(),
        }
        let std_clone = std_socket
            .try_clone()
            .map_err(|e| format!("socket try_clone: {}", e))?;
        std_clone
            .set_nonblocking(true)
            .map_err(|e| format!("set_nonblocking on cloned socket: {}", e))?;
        let registrar_sock = Arc::new(
            tokio::net::UdpSocket::from_std(std_clone)
                .map_err(|e| format!("tokio::from_std: {}", e))?,
        );
        let endpoint =
            server_endpoint(std_socket, &self.identity, &self.timings).map_err(|f| f.detail)?;

        // The registrar selects on the share's cancel token, so `stop()` and
        // `abort()` (which cancels before aborting) both end it; a roll ends
        // it via `QuicListener::demote`. `register_loop`'s first tick fires
        // immediately, so a fresh generation displaces the old registration
        // within one packet's flight time.
        // There is no acknowledgement to wait for: relays never answer a
        // REGISTER, so this records that we started announcing, and nothing
        // about whether anyone accepted it. A registration rejected for a bad
        // token, a stale timestamp or an unauthorized source looks exactly
        // like this, and then like clients that never arrive.
        self.rec
            .mark(StepKind::Register)
            .detail(format!(
                "announcing to {} relay(s) every {:?}; relays do not acknowledge",
                self.register_targets.len(),
                self.register_interval
            ))
            .ok();
        let registrar = (!self.register_targets.is_empty()).then(|| {
            let targets = self.register_targets.clone();
            let interval = self.register_interval;
            let signer = self.signer.clone();
            let credentials = self.credentials.clone();
            let cancel = self.cancel.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = relay_client::register_loop(
                        registrar_sock,
                        RegisterKind::Quic,
                        targets,
                        interval,
                        signer,
                        credentials,
                    ) => {}
                }
            })
        });
        Ok(QuicListener {
            endpoint,
            registrar,
        })
    }
}

impl QuicListener {
    /// Demote to session-private: stop announcing this socket (the routing
    /// key belongs to the next generation) and refuse new handshakes — a
    /// client racing the re-registration gets a fast refusal (dial fails,
    /// redial lands on the new port) instead of a hang.
    fn demote(&mut self) {
        if let Some(r) = self.registrar.take() {
            r.abort();
        }
        self.endpoint.set_server_config(None);
    }
}

/// Spawn TCP/TLS registrar pools for every `TcpTls` relay of the share. Each
/// pool worker parks a connection at the relay; when a client is spliced in it
/// runs the E2E TLS server and delivers the session, then re-parks to refill.
fn spawn_tcp_registrars(
    config: &Config,
    carriers: &ShareCarriers,
    identity: Arc<ShareIdentity>,
    session_tx: tokio::sync::mpsc::UnboundedSender<(carrier::PeerSession, Option<u64>)>,
    cancel: CancellationToken,
    rec: &Recorder,
) {
    // Connections kept parked per relay so a client always finds one.
    const POOL_SIZE: usize = 4;
    for relay in carriers
        .relays
        .iter()
        .filter(|r| r.endpoint.protocol == RelayProtocol::TcpTls)
    {
        let addrs = match resolve_one_relay(&relay.endpoint) {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    "tcp registrar: skipping unresolvable {}: {}",
                    relay.endpoint.host, e
                );
                continue;
            }
        };
        for addr in addrs {
            for _ in 0..POOL_SIZE {
                tokio::spawn(tcp_park_worker(
                    ParkTarget {
                        addr,
                        credential: relay.credential.clone(),
                        signer: carriers.signer.clone(),
                        credentials: carriers.credentials.clone(),
                    },
                    identity.clone(),
                    session_tx.clone(),
                    cancel.clone(),
                    config.protector.clone(),
                    rec.clone(),
                ));
            }
        }
    }
}

/// One TCP relay a park worker keeps a connection at, and what it presents
/// there (read afresh for every connection it opens).
struct ParkTarget {
    addr: SocketAddr,
    credential: crate::identity::Credential,
    signer: Arc<std::sync::Mutex<relay_client::protocol::RegisterSigner>>,
    credentials: Credentials,
}

/// How long a park worker waits after the relay refused or reaped its
/// connection: 500 ms, doubling while the refusals continue (a lapsed or
/// missing token is refused every time), at most a minute. A new relay
/// token cuts the wait short.
const PARK_RETRY_FIRST: Duration = Duration::from_millis(500);
const PARK_RETRY_MAX: Duration = Duration::from_secs(60);

/// One pool worker: keep a connection parked at the target, delivering a
/// session whenever a client is spliced in, until cancelled.
async fn tcp_park_worker(
    target: ParkTarget,
    identity: Arc<ShareIdentity>,
    session_tx: tokio::sync::mpsc::UnboundedSender<(carrier::PeerSession, Option<u64>)>,
    cancel: CancellationToken,
    protector: SocketProtector,
    rec: Recorder,
) {
    let relay_addr = target.addr;
    let mut token_changed = target.credentials.subscribe();
    let mut retry = PARK_RETRY_FIRST;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let parking = rec
            .step_now(StepKind::RelayPark)
            .via(relay_addr)
            .carrier(Carrier::TcpTls);
        let wait = match park_and_accept(&target, identity.as_ref(), &protector, &cancel).await {
            Ok(Some(session)) => {
                parking.detail("a client was spliced in").ok();
                if session_tx.send((session, None)).is_err() {
                    return; // the share loop is gone
                }
                retry = PARK_RETRY_FIRST;
                continue;
            }
            // Reaped (idle) or refused (a relay that will not take this
            // share: a bad, lapsed or absent token) — re-park after a pause
            // so a refusal doesn't become a tight reconnect loop.
            Ok(None) => {
                // The relay does not say which of the two this was, and this
                // is not the place to guess.
                parking.fail(
                    Reason::PeerClosed,
                    "the relay closed the parked connection (idle reap, or a refused park)",
                );
                let w = retry;
                retry = (retry * 2).min(PARK_RETRY_MAX);
                w
            }
            Err(e) => {
                debug!("tcp registrar {}: {}", relay_addr, e);
                parking.fail_with(&e);
                Duration::from_secs(1)
            }
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
            r = token_changed.changed() => {
                // A new token: whatever the relay refused may now be taken.
                if r.is_ok() {
                    retry = PARK_RETRY_FIRST;
                }
            }
        }
    }
}

/// Park one connection at the relay; when a client is spliced in, run the E2E
/// TLS server and return the session. `Ok(None)` = the relay closed the
/// parked connection (an idle reap, or a refusal; re-park). Cancellable while
/// parked.
async fn park_and_accept(
    target: &ParkTarget,
    identity: &ShareIdentity,
    protector: &SocketProtector,
    cancel: &CancellationToken,
) -> Result<Option<carrier::PeerSession>, Fault> {
    use tokio::io::AsyncWriteExt;
    let relay_addr = target.addr;
    let mut tcp = tokio::net::TcpStream::connect(relay_addr)
        .await
        .map_err(|e| Fault::from_io(&e).context("connect relay"))?;
    let _ = tcp.set_nodelay(true);
    carrier::protect_tcp(protector, &tcp);
    // Signed after the connect, just before the write: the relay wants each
    // park's timestamp above the last it took for this share, so the less
    // time between signing and arriving, the less a sibling worker's park can
    // overtake it (a park that does lose that race is refused and retried).
    let token = target.credentials.token(&target.credential);
    let preamble = target
        .signer
        .lock()
        .expect("register signer")
        .park_preamble(&token);
    tcp.write_all(&preamble)
        .await
        .map_err(|e| Fault::from_io(&e).context("park preamble"))?;

    // Park: wait (no timeout, cancellable) for the first byte — a client was
    // spliced in. EOF (0) means the relay reaped this idle parked connection
    // (its PARK_TTL) or refused it; the caller re-parks.
    let mut peek = [0u8; 1];
    let n = tokio::select! {
        _ = cancel.cancelled() => {
            return Err(Fault::new(Reason::Cancelled, "cancelled while parked"));
        }
        r = tcp.peek(&mut peek) => r.map_err(|e| Fault::from_io(&e).context("park peek"))?,
    };
    if n == 0 {
        return Ok(None);
    }

    // A client is here — run the timed E2E TLS server handshake + secret.
    let transport = e2e_tls::accept(tcp, identity).await?;
    Ok(Some(carrier::PeerSession {
        transport,
        remote_addr: relay_addr,
        quic_conn: None,
        signal: None,
        fixed_mtu: carrier::STREAM_TUNNEL_MTU,
    }))
}

/// Sharer-side Noise UDP carrier. Bind a dedicated socket, register every
/// `NoiseUdp` relay from it (so those relays route clients here), and run a
/// multi-client accept dispatcher that delivers each authenticated client as a
/// session into `session_tx`. A no-op when the share lists no `NoiseUdp` relay.
fn spawn_noise_registrar(
    config: &Config,
    carriers: &ShareCarriers,
    identity: Arc<ShareIdentity>,
    session_tx: tokio::sync::mpsc::UnboundedSender<(carrier::PeerSession, Option<u64>)>,
    cancel: CancellationToken,
) {
    if !carriers
        .relays
        .iter()
        .any(|r| r.endpoint.protocol == RelayProtocol::NoiseUdp)
    {
        return;
    }
    let nz_relays = carriers.relays.clone();
    let protector = config.protector.clone();
    let signer = carriers.signer.clone();
    let credentials = carriers.credentials.clone();
    let register_interval = config.timings.register_interval;
    let hs_timeout = config.timings.relay_dial_timeout;
    let idle = config.timings.quic_idle_timeout;

    tokio::spawn(async move {
        let targets = match resolve_register_targets(&nz_relays, RelayProtocol::NoiseUdp) {
            Ok(t) => t,
            Err(e) => {
                warn!("[share] nz: cannot resolve relays: {e}");
                return;
            }
        };
        let want_v6 = targets.iter().any(|t| t.addr.is_ipv6());

        // Rolling listener, nz edition: each generation binds a fresh socket,
        // registers it, and serves handshakes until its dispatcher delivers a
        // session — that socket then belongs to the session (the dispatcher
        // keeps pumping it, but stops accepting new handshakes) and the next
        // generation takes over the routing hash. The share's one signer
        // spans every generation (see QuicListenerCtx).
        loop {
            // A transient bind failure must not kill the nz carrier for the
            // share's lifetime — retry until it works or the share stops.
            let socket = loop {
                let bound = bind_share_udp(&protector, want_v6, 0).and_then(|s| {
                    s.set_nonblocking(true)
                        .map_err(|e| format!("set_nonblocking: {e}"))?;
                    UdpSocket::from_std(s)
                        .map(Arc::new)
                        .map_err(|e| format!("from_std: {e}"))
                });
                match bound {
                    Ok(s) => break s,
                    Err(e) => {
                        warn!("[share] nz: listener bind failed: {e}; retrying");
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                        }
                    }
                }
            };
            info!(
                "[share] nz carrier up, registering with {:?}",
                targets.iter().map(|t| t.addr).collect::<Vec<_>>()
            );

            let registrar = {
                let sock = socket.clone();
                let targets = targets.clone();
                let signer = signer.clone();
                let credentials = credentials.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = relay_client::register_loop(
                            sock,
                            RegisterKind::Nz,
                            targets,
                            register_interval,
                            signer,
                            credentials,
                        ) => {}
                    }
                })
            };
            let accepting = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let (rolled_tx, rolled_rx) = tokio::sync::oneshot::channel::<()>();
            let dispatcher = tokio::spawn(noise_accept_dispatcher(
                socket,
                identity.clone(),
                session_tx.clone(),
                hs_timeout,
                idle,
                cancel.clone(),
                accepting,
                Arc::new(std::sync::Mutex::new(Some(rolled_tx))),
            ));

            tokio::select! {
                _ = cancel.cancelled() => {
                    registrar.abort();
                    // The dispatcher exits via its own cancel arm.
                    return;
                }
                // A session claimed this generation's socket: stop announcing
                // it (the dispatcher runs on, serving the session) and roll.
                _ = rolled_rx => {
                    registrar.abort();
                    drop(dispatcher); // detach; it lives with its session
                }
            }
        }
    });
}

/// Read the shared nz socket and route each datagram: to an existing session by
/// its `recv_index`, or — a fresh `routing_hash`-prefixed msg1 — to a new
/// `noise_accept` whose dispatcher-assigned index we record for routing. The
/// relay is dumb, so all clients arrive from the relay's one address; demux is
/// purely by the session index, never by source address.
///
/// Rolling-listener wiring: on the FIRST successfully-authenticated session
/// the accept task clears `accepting` and fires `rolled` — the generation
/// manager then registers a fresh socket and this dispatcher becomes
/// session-private: it keeps routing the live session's datagrams but
/// ignores new handshakes, and exits once its routing tables empty out.
#[allow(clippy::too_many_arguments)]
async fn noise_accept_dispatcher(
    socket: Arc<UdpSocket>,
    identity: Arc<ShareIdentity>,
    session_tx: tokio::sync::mpsc::UnboundedSender<(carrier::PeerSession, Option<u64>)>,
    hs_timeout: Duration,
    idle: Duration,
    cancel: CancellationToken,
    accepting: Arc<std::sync::atomic::AtomicBool>,
    rolled: Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
) {
    use crate::transport::noise::{DATA_MIN_LEN, NZ_MSG1_MIN, NZ_TUNNEL_MTU, noise_accept};
    type RawTx = tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>;
    // idx_A -> that session's raw-datagram sender.
    let mut by_index: std::collections::HashMap<u32, RawTx> = std::collections::HashMap::new();
    // idx_B -> idx_A, so a client's retransmitted msg1 (its msg2 was lost) is
    // re-delivered to the same session instead of spawning a duplicate.
    let mut by_client: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    // One deobfuscator for this identity's whole flow. It reverses the wire
    // shaping before we inspect recv_index/routing_hash at fixed offsets; the
    // clean bytes are what we route AND forward to the per-session channels.
    let shaper = crate::transport::shaper::nz_shaper(&identity.routing_hash, &identity.secret);
    // The `routing_hash` prefix is cleartext on the wire (a passive censor learns
    // it), so an attacker can forge msg1-shaped packets. We insert routing entries
    // BEFORE the psk-gated handshake completes (they're needed to route msg1
    // retransmits), so a failed accept must reap its entries or the tables grow
    // unbounded (memory-exhaustion DoS). Failed-accept tasks report back here; a
    // hard cap backstops any burst faster than the reap.
    const MAX_INFLIGHT: usize = 4096;
    let (reap_tx, mut reap_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, u32)>();
    let mut buf = vec![0u8; 2048];
    // A demoted dispatcher's session can die SILENTLY (its peer just stops
    // sending), which recv_from alone can never observe — sweep the routing
    // tables for closed session channels on a timer and exit (releasing the
    // socket) once nothing is left to route. Without this, every nz session
    // would leak a socket + task for the share's lifetime.
    let mut cleanup = tokio::time::interval(Duration::from_secs(5));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let demoted = !accepting.load(std::sync::atomic::Ordering::Relaxed);
        let (n, src) = tokio::select! {
            _ = cancel.cancelled() => return,
            _ = cleanup.tick() => {
                if demoted {
                    by_index.retain(|_, tx| !tx.is_closed());
                    by_client.retain(|_, ia| by_index.contains_key(ia));
                    if by_index.is_empty() {
                        debug!("[share] nz: demoted dispatcher done, releasing socket");
                        return;
                    }
                }
                continue;
            }
            // A spawned accept task failed to authenticate — drop its pre-auth
            // routing entries so a forged-msg1 spray can't leak the tables.
            Some((ia, ib)) = reap_rx.recv() => {
                by_index.remove(&ia);
                by_client.remove(&ib);
                if demoted && by_index.is_empty() {
                    return;
                }
                continue;
            }
            r = socket.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(e) => { warn!("[share] nz recv: {e}"); continue; }
            },
        };

        // Reverse the wire shaping first; a non-shaped/garbage datagram drops.
        let Some(clean) = shaper.deobfuscate(&buf[..n]) else {
            continue;
        };

        // 1) Belongs to an existing session? Route by recv_index.
        if clean.len() >= DATA_MIN_LEN {
            let idx = u32::from_be_bytes(clean[0..4].try_into().unwrap());
            if by_index.contains_key(&idx) {
                let dead = by_index[&idx].send((clean.clone(), src)).is_err();
                if dead {
                    by_index.remove(&idx);
                    by_client.retain(|_, v| *v != idx);
                    // A demoted (rolled-away) dispatcher whose session is
                    // gone has nothing left to route: release the socket.
                    if demoted && by_index.is_empty() {
                        return;
                    }
                }
                continue;
            }
        }

        // 2) A handshake msg1 addressed to us (routing_hash prefix)?
        if clean.len() >= NZ_MSG1_MIN && clean[0..ROUTING_HASH_LEN] == identity.routing_hash {
            let idx_b = u32::from_be_bytes(
                clean[ROUTING_HASH_LEN..ROUTING_HASH_LEN + 4]
                    .try_into()
                    .unwrap(),
            );
            // Retransmit for an IN-FLIGHT handshake: always redeliver, even
            // when demoted — this dispatcher still owns every handshake it
            // started, and the relay keeps forwarding by the client's flow.
            if let Some(&idx_a) = by_client.get(&idx_b) {
                if let Some(tx) = by_index.get(&idx_a) {
                    let _ = tx.send((clean.clone(), src)); // retransmit -> same session
                }
                continue;
            }
            // NEW handshakes only while this socket holds the routing key;
            // once demoted they belong to the next generation.
            if demoted {
                continue;
            }
            // Shed load past the cap so a forged-msg1 burst can't exhaust memory
            // faster than failed accepts reap themselves.
            if by_index.len() >= MAX_INFLIGHT {
                warn!("[share] nz dispatcher at capacity ({MAX_INFLIGHT}); dropping new handshake");
                continue;
            }
            // New client: assign the idx_A the dispatcher will route future
            // packets by, seed the session's channel with this msg1, and drive
            // the responder handshake in its own task.
            let mut idx_a: u32 = rand::random();
            while by_index.contains_key(&idx_a) {
                idx_a = rand::random();
            }
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
            let _ = tx.send((clean.clone(), src));
            by_index.insert(idx_a, tx);
            by_client.insert(idx_b, idx_a);

            let sock = socket.clone();
            let id = identity.clone();
            let stx = session_tx.clone();
            let reap = reap_tx.clone();
            let accepting = accepting.clone();
            let rolled = rolled.clone();
            tokio::spawn(async move {
                match noise_accept(sock, rx, idx_a, None, id.as_ref(), hs_timeout, idle).await {
                    Ok(mut transport) => {
                        let remote_addr = transport.peer_addr();
                        let signal = transport
                            .take_signal()
                            .map(crate::signal::SignalChannel::noise);
                        // Deliver the session FIRST: if the share loop is
                        // gone the send fails and we must not roll (the
                        // manager would otherwise mint generations for a
                        // dead share until cancellation propagates).
                        let delivered = stx
                            .send((
                                carrier::PeerSession {
                                    transport: Box::new(transport),
                                    remote_addr,
                                    quic_conn: None,
                                    signal,
                                    fixed_mtu: NZ_TUNNEL_MTU,
                                },
                                None,
                            ))
                            .is_ok();
                        // The session claims this generation's socket: stop
                        // accepting here and let the manager roll to a
                        // fresh one.
                        if delivered {
                            accepting.store(false, std::sync::atomic::Ordering::Relaxed);
                            if let Some(tx) = rolled.lock().expect("rolled sender").take() {
                                let _ = tx.send(());
                            }
                        }
                    }
                    // Reap the pre-auth routing entries; the live-session case is
                    // covered by the reactive cleanup on a dead by_index sender.
                    Err(e) => {
                        warn!("[share] nz accept failed: {e}");
                        let _ = reap.send((idx_a, idx_b));
                    }
                }
            });
        }
        // else: unknown / garbage — drop.
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_share_loop(
    mut listener: QuicListener,
    roll_ctx: QuicListenerCtx,
    direct_endpoint: Option<quinn::Endpoint>,
    identity: Arc<ShareIdentity>,
    carriers: ShareCarriers,
    cancel: CancellationToken,
    config: Config,
    conn_log: Option<ConnLog>,
    rec: Recorder,
) {
    // EVERY exit from this loop — cancellation, endpoint death, a panic in
    // an event hook — must stop the detached registrar generations and
    // carrier workers, which all select on `cancel`. The guard makes any
    // exit equivalent to an explicit stop; without it, an endpoint-driver
    // death would leave the last registrar re-announcing a dead socket to
    // the relays forever.
    let _cancel_guard = cancel.clone().drop_guard();
    // Any exit from this loop ends the run, so the record gets its ending
    // here — including the exits nobody planned (endpoint death, a panic in
    // a hook), which is when having one matters most.
    // Declared after `_cancel_guard`, so dropped first: the token still says
    // whether anyone stopped the share.
    let _record_guard = ShareRecordGuard {
        rec: rec.clone(),
        stop: cancel.clone(),
    };
    let secret = identity.secret;
    let mut tunnel_cancel: Option<CancellationToken> = None;
    let mut iteration: u32 = 0;
    // Generation of the ACTIVE session's endpoint (None: direct/tcp/nz).
    let mut active_gen: Option<u64> = None;
    // Which listener generation the CURRENT `listener` is; sessions are
    // tagged with the generation they were accepted on so the loop knows
    // whether an arriving session claims the current listener (-> roll) or
    // came from a demoted one / another carrier.
    let mut generation: u64 = 0;
    // Endpoints of demoted generations, kept so their session (at most one
    // is active, plus briefly-draining kicked ones) stays served and the
    // socket is closed once no session can be using it anymore.
    let mut demoted: std::collections::HashMap<u64, quinn::Endpoint> =
        std::collections::HashMap::new();
    // Authenticated sessions arrive here from the per-connection QUIC auth
    // tasks (tagged with their listener generation) and the TCP/TLS + nz
    // registrars (untagged), unified as carrier::PeerSession.
    let (session_tx, mut session_rx) =
        tokio::sync::mpsc::unbounded_channel::<(carrier::PeerSession, Option<u64>)>();

    // Sharer-side TCP/TLS carrier: park connections at each TcpTls relay and
    // deliver each spliced client as a session into the same channel.
    spawn_tcp_registrars(
        &config,
        &carriers,
        identity.clone(),
        session_tx.clone(),
        cancel.clone(),
        &rec,
    );

    // Sharer-side Noise UDP carrier: register each NoiseUdp relay from a
    // dedicated socket and deliver each authenticated client into the same
    // channel. No-op when the config lists no NoiseUdp relay.
    spawn_noise_registrar(
        &config,
        &carriers,
        identity.clone(),
        session_tx.clone(),
        cancel.clone(),
    );

    info!("[share] waiting for peers");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("share cancelled");
                if let Some(tc) = tunnel_cancel.take() { tc.cancel(); }
                listener.demote();
                listener.endpoint.close(0u32.into(), b"share-cancelled");
                if let Some(ep) = &direct_endpoint {
                    ep.close(0u32.into(), b"share-cancelled");
                }
                for (_, ep) in demoted.drain() {
                    ep.close(0u32.into(), b"share-cancelled");
                }
                break;
            }
            // Accept connection attempts and authenticate each one in its own
            // task, so a peer that stalls the secret read (an attacker who knows
            // only the routing key) can't block the accept loop and starve
            // legitimate peers. The sharer still serves one tunnel at a time;
            // we just no longer serialize the handshake+auth of every attempt.
            incoming = listener.endpoint.accept() => {
                match incoming {
                    None => { info!("share endpoint closed"); break; }
                    Some(incoming) => {
                        let tx = session_tx.clone();
                        let cancel = cancel.clone();
                        let listener_gen = generation;
                        let accept_rec = rec.clone();
                        tokio::spawn(async move {
                            // Written as `started` immediately: a handshake
                            // that hangs, or a task cancelled mid-flight,
                            // then leaves a step saying so rather than
                            // leaving nothing at all.
                            let accepting = accept_rec
                                .step_now(StepKind::Accept)
                                .carrier(Carrier::Quic)
                                .path(PathKind::Relay);
                            tokio::select! {
                                _ = cancel.cancelled() => {
                                    accepting.skip(Reason::Cancelled, "share stopping");
                                }
                                res = authenticate_incoming(incoming, &secret, true) => match res {
                                    Ok(session) => {
                                        accepting.peer(session.conn.remote_address()).ok();
                                        let _ = tx.send((carrier::PeerSession::from_quic(session), Some(listener_gen)));
                                    }
                                    Err(e) => {
                                        warn!("[share] accept failed: {}", e);
                                        accepting.fail_with(&e);
                                    }
                                }
                            }
                        });
                    }
                }
            }
            // Direct (relay-less) clients dial the permanent advertised
            // endpoint; their sessions never trigger a roll (untagged).
            incoming = async { direct_endpoint.as_ref().unwrap().accept().await },
                if direct_endpoint.is_some() =>
            {
                match incoming {
                    None => { info!("share direct endpoint closed"); break; }
                    Some(incoming) => {
                        let tx = session_tx.clone();
                        let cancel = cancel.clone();
                        let accept_rec = rec.clone();
                        tokio::spawn(async move {
                            let accepting = accept_rec
                                .step_now(StepKind::Accept)
                                .carrier(Carrier::Quic)
                                .path(PathKind::DirectAdvertised);
                            tokio::select! {
                                _ = cancel.cancelled() => {
                                    accepting.skip(Reason::Cancelled, "share stopping");
                                }
                                res = authenticate_incoming(incoming, &secret, true) => match res {
                                    Ok(session) => {
                                        accepting.peer(session.conn.remote_address()).ok();
                                        let _ = tx.send((carrier::PeerSession::from_quic(session), None));
                                    }
                                    Err(e) => {
                                        warn!("[share] direct accept failed: {}", e);
                                        accepting.fail_with(&e);
                                    }
                                }
                            }
                        });
                    }
                }
            }
            Some((session, from_gen)) = session_rx.recv() => {
                iteration += 1;
                let remote_addr = session.remote_addr;

                // Roll: the session was accepted on the CURRENT listener, so
                // that socket is now its private endpoint — mint the next
                // generation and move the routing key there. On a roll
                // failure (fd exhaustion, ...) keep the current listener:
                // the share degrades to the legacy shared-endpoint behavior
                // instead of dying.
                if from_gen == Some(generation) {
                    let rolling = rec.step(StepKind::ListenerRoll);
                    match roll_ctx.spawn_listener(0) {
                        Ok(next) => {
                            let mut old = std::mem::replace(&mut listener, next);
                            old.demote();
                            demoted.insert(generation, old.endpoint);
                            generation += 1;
                            rolling.detail(format!("generation {generation}")).ok();
                            debug!("[share #{iteration}] rolled listener to generation {generation}");
                        }
                        Err(e) => {
                            // Not fatal — the share degrades to a shared
                            // endpoint — but that degraded mode is the cause
                            // of failures much later, so it is a step.
                            rolling.fail(Reason::BindFailed, e.clone());
                            warn!("[share] listener roll failed: {e}; keeping current listener");
                        }
                    }
                }

                // Close demoted endpoints no session can be using anymore.
                // Kept: the NEW active session's endpoint, and — for one
                // more takeover — the endpoint of the session being
                // replaced, so a stale-generation session that was already
                // queued behind this one cannot have the rug pulled from
                // under a LIVE endpoint (its own arrival will be processed
                // against a still-consistent map and self-heal by kick).
                let prev_gen = active_gen;
                active_gen = from_gen;
                demoted.retain(|g, ep| {
                    if Some(*g) == from_gen || Some(*g) == prev_gen {
                        true
                    } else {
                        ep.close(0u32.into(), b"session-replaced");
                        false
                    }
                });

                if let Some(tc) = tunnel_cancel.take() {
                    info!("[share #{}] new peer, cancelling previous tunnel", iteration);
                    tc.cancel();
                }

                // Sessions accepted here always bootstrap relay-via, so the
                // connection's remote address is the relay's, recorded as such.
                let slog = conn_log.as_ref().map(|cl| cl.session(remote_addr));

                let child_cancel = cancel.child_token();
                tunnel_cancel = Some(child_cancel.clone());
                // A QUIC session that did not arrive on a listener generation
                // came in on the advertised (relay-less) endpoint; every
                // other carrier reaches us through a relay.
                let carrier_kind = session.carrier();
                let path_kind = if carrier_kind == Carrier::Quic && from_gen.is_none() {
                    PathKind::DirectAdvertised
                } else {
                    PathKind::Relay
                };
                // Kept for API compatibility; PathActivated is the precise
                // automation surface for all carriers and path kinds.
                emit(
                    &config.event_hook,
                    TunnelEvent::RelaySessionEstablished { peer: remote_addr },
                );
                emit(
                    &config.event_hook,
                    TunnelEvent::PathActivated {
                        carrier: carrier_kind,
                        path: path_kind,
                        local: None,
                        peer: remote_addr,
                    },
                );
                spawn_responder_tunnel(
                    session,
                    identity.clone(),
                    &config,
                    child_cancel,
                    cancel.clone(),
                    slog,
                    rec.for_session(iteration),
                    path_kind,
                );
            }
        }
    }
}

/// The session's transport as the share's exit (the netstack, or a custom
/// handler) holds it. When the exit lets go of it while the session was not
/// cancelled from this end, the exit ended on its own — a handler that
/// failed or returned, a netstack that stopped, a client it gave up on — and
/// the client is told the session died (`SessionMeters::close_dead`). That
/// has to happen here, as the exit drops it: the router dropping the
/// connection a moment later would close it the orderly way. A client that
/// closed the session itself already closed the connection, which keeps
/// that close.
struct ExitTransport {
    inner: IpTransport,
    meters: SessionMeters,
    /// The session's own token: cancelled when a newer session replaced
    /// this one or the share stopped — the deliberate ends.
    session_cancel: CancellationToken,
}

impl Drop for ExitTransport {
    fn drop(&mut self) {
        if !self.session_cancel.is_cancelled() {
            self.meters.close_dead();
        }
    }
}

impl futures_util::Stream for ExitTransport {
    type Item = std::io::Result<Vec<u8>>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl futures_util::Sink<Vec<u8>> for ExitTransport {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_responder_tunnel(
    session: carrier::PeerSession,
    identity: Arc<ShareIdentity>,
    config: &Config,
    tunnel_cancel: CancellationToken,
    // The share's own token (`tunnel_cancel`'s parent): cancelled, the
    // session ended because the share stopped rather than being replaced.
    share_stop: CancellationToken,
    slog: Option<Arc<SessionLog>>,
    rec: Recorder,
    path_kind: PathKind,
) {
    let carrier_kind = session.carrier();
    let carrier::PeerSession {
        transport,
        remote_addr,
        quic_conn,
        signal,
        fixed_mtu,
    } = session;

    // On a relayed carrier `remote_addr` is the *relay's* address: the exit
    // never observes the client's own address unless a punch lands later.
    // `path` is what says which of the two this is.
    rec.mark(StepKind::SessionUp)
        .peer(remote_addr)
        .carrier(carrier_kind)
        .path(path_kind)
        .ok();
    let meters = SessionMeters::new(&rec, carrier_kind, path_kind, quic_conn.clone(), fixed_mtu);

    let (upgradable, upgrade_sender, router_handle) =
        upgradable_transport(transport, config.timings.upgrade_rescue_grace);
    spawn_sampler(
        meters.clone(),
        tunnel_cancel.clone(),
        upgrade_sender.ended(),
    );
    // Share-side keepalive: reactive, not always-on. It pings only while the
    // client is active (recently heard from) and goes quiet once the client
    // goes silent — so a dormant client is never forced to ACK share-side
    // pings and gets true radio silence. An active client always pings (its
    // Adaptive knob is on), so the return path stays warm whenever it should.
    let ka_interval = config.timings.quic_keep_alive;
    // Quiet after ~3 ping intervals of client silence: long enough to span an
    // active client's own keepalive cadence (so we don't flap off between its
    // pings), short enough to reach radio silence soon after it goes dormant.
    let active_window = ka_interval * 3;
    let keepalive_cfg = KeepAliveConfig {
        mode: KeepAliveMode::Periodic {
            interval: ka_interval,
            // Declare a silent peer dead after the idle timeout, so the
            // session is reaped even on the TCP carrier — which, unlike QUIC
            // (max_idle_timeout) and nz (reader idle deadline), has NO
            // transport-level idle timeout, so without this a silently-dead
            // TCP client would linger forever (held fd, open connlog record,
            // no SessionEnded). `.max(active_window)` keeps the reaper from
            // firing before the share side has even stopped pinging.
            recv_timeout: Some(config.timings.quic_idle_timeout.max(active_window)),
        },
        active_window: Some(active_window),
        counters: Some(meters.counters.clone()),
        recorder: Some(rec.clone()),
        on_dead: Some(meters.on_dead()),
        ..Default::default()
    };
    // The meter (Custom exit mode) must ignore the synthetic keepalive pings
    // riding the tunnel; tell it which inner address pair they use.
    let keepalive_pair = (keepalive_cfg.src_ip, keepalive_cfg.dst_ip);
    let transport: IpTransport = Box::new(ExitTransport {
        inner: Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg)),
        meters: meters.clone(),
        session_cancel: tunnel_cancel.clone(),
    });

    let protector_for_tunnel = config.protector.clone();
    let upgrade_cancel = tunnel_cancel.clone();

    // Responder upgrade: only for a QUIC session with the upgrade enabled. A
    // TcpTls (stream) session has no signal channel or UDP path; and a session
    // whose client is Direct dropped its signal, so try_direct_upgrade
    // terminates via SignalClosed before it STUNs.
    let upgrade_task = match (config.enable_direct_upgrade, signal) {
        (true, Some(signal)) => {
            let stun_servers = config.stun_servers.clone();
            let protector = config.protector.clone();
            let mtu_cb = config.mtu_callback.clone();
            let timings = config.timings.clone();
            let event_hook = config.event_hook.clone();
            let role = DirectRole::Responder { identity };
            let path_ipv6 = remote_addr.is_ipv6();
            let upgrade_slog = slog.clone();
            let upgrade_meters = meters.clone();
            tokio::spawn(async move {
                try_direct_upgrade(
                    signal,
                    upgrade_sender,
                    &stun_servers,
                    role,
                    path_ipv6,
                    &protector,
                    upgrade_cancel,
                    None,
                    mtu_cb,
                    timings,
                    event_hook,
                    upgrade_slog,
                    upgrade_meters,
                )
                .await;
            })
        }
        // No upgrade (stream carrier, or upgrade disabled): drop the
        // UpgradeSender (the router drains, by design) and hold the signal (if
        // any) until the session ends so a QUIC peer's stream doesn't see EOF.
        (_, held_signal) => {
            // Not attempted, and for two quite different reasons — recorded
            // as `skipped`, because "we chose not to" is a different fact
            // from "we tried and it failed".
            let reason = if config.enable_direct_upgrade {
                Reason::UpgradeUnsupported
            } else {
                Reason::UpgradeDisabled
            };
            rec.mark(StepKind::PathSwap)
                .carrier(carrier_kind)
                .skip(reason, "no direct upgrade attempted");
            drop(upgrade_sender);
            tokio::spawn(async move {
                upgrade_cancel.cancelled().await;
                drop(held_signal);
            })
        }
    };

    // MTU: dynamic (PMTUD) for QUIC, fixed for a stream carrier.
    let mtu_rec = rec.clone();
    match quic_conn {
        Some(conn) => {
            let cb = config.mtu_callback.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                match conn.max_datagram_size() {
                    Some(mds) => {
                        info!("e2e max datagram size (post-PMTUD): {}", mds);
                        mtu_rec
                            .mark(StepKind::Mtu)
                            .detail(format!("discovered {mds}"))
                            .ok();
                        if let Some(cb) = cb {
                            cb(mds as u16);
                        }
                    }
                    None => mtu_rec
                        .mark(StepKind::Mtu)
                        .fail(Reason::Unknown, "no datagram size after PMTUD"),
                }
            });
        }
        None => {
            rec.mark(StepKind::Mtu)
                .detail(format!("declared {fixed_mtu}"))
                .ok();
            if let Some(cb) = config.mtu_callback.clone() {
                cb(fixed_mtu);
            }
        }
    }

    let exit_slog = slog.clone();
    let dns_forwarder = config.dns_forwarder.clone();
    let end_cancel = tunnel_cancel.clone();
    rec.mark(StepKind::ExitStart)
        .detail(match &config.exit_mode {
            ExitMode::Netstack => "netstack",
            ExitMode::Custom(_) => "custom handler",
        })
        .ok();
    let session_fut: SessionFuture = match &config.exit_mode {
        ExitMode::Netstack => Box::pin(async move {
            let _ = server::start_tunnel(
                transport,
                protector_for_tunnel,
                tunnel_cancel,
                true,
                dns_forwarder,
                exit_slog,
            )
            .await;
        }),
        ExitMode::Custom(handler) => {
            // The handler only moves packets; flow accounting happens in a
            // passive meter wrapped around the transport it receives, so any
            // custom exit (e.g. the CLI's --os-routing) is logged without
            // its own instrumentation.
            let transport = match &exit_slog {
                Some(sl) => Box::new(transport::meter::MeteredTransport::new(
                    transport,
                    sl.clone(),
                    keepalive_pair,
                    dns_forwarder.is_some(),
                )) as IpTransport,
                None => transport,
            };
            handler(transport, tunnel_cancel)
        }
    };
    let event_hook = config.event_hook.clone();
    tokio::spawn(async move {
        session_fut.await;
        upgrade_task.abort();
        // Await the aborted task so its SessionLog writes (address records)
        // cannot land after the SessionEnd record below.
        let _ = upgrade_task.await;
        drop(router_handle);
        let reason = if end_cancel.is_cancelled() {
            "cancelled"
        } else {
            "transport_closed"
        };
        if end_cancel.is_cancelled() {
            // Cancelled from this end: a newer peer took its place, or the
            // share stopped (the run's own token) — either way the ordinary
            // end of a session. (A stop's step usually lands after the run's
            // close, and so is not recorded at all.)
            if share_stop.is_cancelled() {
                meters.record_local_end(Reason::LocalShutdown, "the share stopped");
            } else {
                meters.record_local_end(Reason::Replaced, "a newer session took its place");
            }
        } else {
            // It ended by itself: the client closed it, or it died.
            meters.record_end();
        }
        if let Some(sl) = &slog {
            sl.end(reason);
        }
        emit(
            &event_hook,
            TunnelEvent::SessionEnded {
                reason: reason.to_string(),
            },
        );
    });
}

/// Connect to a sharer via the URL. Returns the IP-level transport plus the
/// keepalive controls so the caller (CLI/FFI) can toggle dormant mode.
pub async fn connect(url: Url, config: &Config) -> Result<ConnectResult, String> {
    let token = match Token::from_url(&url) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            // Worth a record of its own: "the link is malformed" is a
            // diagnosis, and it is the first thing anyone asks about.
            let rec = open_record(config, Role::Client, None, Vec::new());
            rec.mark(StepKind::TokenParse)
                .fail(Reason::BadToken, e.clone());
            rec.close(Outcome::NeverConnected, Some(Reason::BadToken), None);
            return Err(e);
        }
    };
    let rec = open_record(
        config,
        Role::Client,
        Some(&token.routing_hash()),
        endpoint_refs(&token.relays),
    );
    rec.mark(StepKind::TokenParse).ok();
    // Resolve every relay in the URL (a hostname may expand to v4+v6) and try
    // them IPv6 first: a v6 relay path drives a v6 hole punch, which succeeds
    // far more often (no NAT, just a stateful firewall) than a v4 one. The
    // order is re-derived on each (re)dial, so DNS changes and censorship
    // failover both take effect on reconnect.
    let resolving = rec.step(StepKind::RelayResolve);
    let relay_addrs = match resolve_relays_preferring_v6(&token.relays) {
        Ok(addrs) => {
            resolving
                .detail(format!("{} endpoint(s) to try", addrs.len()))
                .ok();
            addrs
        }
        Err(e) => {
            resolving.fail_with(&e);
            rec.close(Outcome::NeverConnected, Some(e.reason), None);
            return Err(e.detail);
        }
    };
    info!(
        "connect: relays {:?} for rh {:x?}",
        relay_addrs,
        &token.routing_hash()[..4]
    );

    let cancel = CancellationToken::new();
    let keepalive_knob = Arc::new(AtomicU64::new(0));
    let keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>> =
        Arc::new(std::sync::Mutex::new(None));
    // The session up right now, if any: whoever sees it end — its transport
    // dying under the reconnect layer, or the caller stopping — takes it out
    // and records its `session_end`, once.
    let live_session: SessionSlot = Arc::new(std::sync::Mutex::new(None));

    let initial = match dial_relays(
        &relay_addrs,
        &token,
        config,
        cancel.clone(),
        keepalive_knob.clone(),
        keepalive_waker.clone(),
        &rec.for_cycle(0),
        &live_session,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            rec.close(
                Outcome::NeverConnected,
                Some(e.reason),
                Some(e.detail.clone()),
            );
            return Err(format!("initial dial: {}", e));
        }
    };

    let dialer_token = token.clone();
    let dialer_config = config.clone();
    let dialer_cancel = cancel.clone();
    let dialer_knob = keepalive_knob.clone();
    let dialer_waker = keepalive_waker.clone();
    // The last answer DNS gave us. Every redial asks again — that is the
    // point of re-resolving — but a resolver that has just been broken or
    // poisoned must not cost us the addresses we already have, so this is
    // what a failed lookup falls back to.
    let known_relays = Arc::new(std::sync::Mutex::new(relay_addrs.clone()));
    let dialer_rec = rec.clone();
    let dialer_session = live_session.clone();
    // Which re-dial cycle a step belongs to. Without it, forty reconnects in
    // an hour are forty indistinguishable piles of steps.
    let cycles = Arc::new(AtomicU64::new(0));
    let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
        let token = dialer_token.clone();
        let config = dialer_config.clone();
        let cancel = dialer_cancel.clone();
        let knob = dialer_knob.clone();
        let waker = dialer_waker.clone();
        let known = known_relays.clone();
        let cycle = cycles.fetch_add(1, Ordering::Relaxed) + 1;
        let rec = dialer_rec.for_cycle(cycle as u32);
        let session = dialer_session.clone();
        Box::pin(async move {
            emit(&config.event_hook, TunnelEvent::Reconnecting);
            rec.mark(StepKind::Reconnect).ok();
            // Ask DNS again for this cycle: a relay that moved, a hostname
            // whose records changed, and a censor that started poisoning one
            // name are all only visible if we look. Resolution stays on this
            // task rather than a blocking pool thread — the network namespace
            // (and any per-thread resolver state) belongs to this thread.
            let relays = resolve_for_dial(&token.relays, &known, &rec);
            let result = dial_relays(
                &relays, &token, &config, cancel, knob, waker, &rec, &session,
            )
            .await;
            if result.is_ok() {
                emit(&config.event_hook, TunnelEvent::Reconnected);
            }
            result.map_err(std::io::Error::from)
        })
    });

    // A session that ends by itself — the sharer closed it (stopped, or
    // took another client), or it died — says how at the moment the
    // reconnect layer sees it go, ahead of the redial it starts. One that
    // ends because the caller stopped is the closer's below.
    let dying_session = live_session.clone();
    let dying_cancel = cancel.clone();
    let on_death: transport::DeathHook = Box::new(move || {
        if dying_cancel.is_cancelled() {
            return;
        }
        let ended = dying_session.lock().ok().and_then(|mut s| s.take());
        if let Some(meters) = ended {
            meters.record_end();
            // Before the reconnect layer drops the transport, whose drop
            // would close the connection as an orderly end.
            meters.close_dead();
        }
    });
    let transport = Box::new(
        ReconnectTransport::new(
            initial,
            dialer,
            config.timings.reconnect_delay,
            Some((keepalive_knob.clone(), keepalive_waker.clone())),
        )
        .with_death_hook(on_death),
    );
    // The record outlives the call: it is closed when the caller cancels, so
    // a session that runs for an hour still gets an ending. The live
    // session's connection is closed right then too, not whenever the caller
    // gets round to dropping the transport: a process that exits after
    // stopping may never get that far with its runtime still running, and
    // the exit would hear nothing until its keepalive gave up on us.
    let closing = rec.clone();
    let closing_cancel = cancel.clone();
    let closed = CancellationToken::new();
    let closed_guard = closed.clone().drop_guard();
    tokio::spawn(async move {
        // However this task ends — done, or dropped with the runtime — a
        // `RunStopper::stop` waiting on it is released.
        let _closed = closed_guard;
        closing_cancel.cancelled().await;
        let ended = live_session.lock().ok().and_then(|mut s| s.take());
        let conn = ended.as_ref().and_then(SessionMeters::current_quic);
        if let Some(meters) = ended {
            meters.record_local_end(Reason::LocalShutdown, "the tunnel was stopped");
        }
        closing.close_shutdown(Some(Reason::LocalShutdown));
        if let Some(conn) = conn {
            transport::quic::close_and_flush(&conn, b"client stopped", STOP_FLUSH_GRACE).await;
        }
    });

    Ok(ConnectResult {
        transport,
        stopper: RunStopper {
            cancel: cancel.clone(),
            closed,
        },
        cancel,
        keepalive_knob,
        keepalive_waker,
        record: rec,
    })
}

/// Re-resolve the URL's relays for a redial, remembering the last usable
/// answer.
///
/// DNS is one of the things a censor breaks, and it is broken at exactly the
/// moment we most need to reconnect — so a failed lookup here falls back to
/// the addresses that worked before rather than ending the cycle. Both the
/// lookup and the fallback are recorded: "we are dialling yesterday's
/// addresses because the resolver stopped answering" is a finding.
fn resolve_for_dial(
    endpoints: &[RelayEndpoint],
    known: &std::sync::Mutex<Vec<(SocketAddr, RelayProtocol)>>,
    rec: &Recorder,
) -> Vec<(SocketAddr, RelayProtocol)> {
    let step = rec.step(StepKind::RelayResolve);
    match resolve_relays_preferring_v6(endpoints) {
        Ok(addrs) => {
            step.detail(format!("{} endpoint(s) to try", addrs.len()))
                .ok();
            *known.lock().unwrap_or_else(|e| e.into_inner()) = addrs.clone();
            addrs
        }
        Err(e) => {
            let fallback = known.lock().unwrap_or_else(|e| e.into_inner()).clone();
            warn!(
                "relay resolution failed ({}); dialling {} previously resolved address(es)",
                e,
                fallback.len()
            );
            step.fail_with(&Fault::new(
                e.reason,
                format!(
                    "{}; falling back to {} previously resolved address(es)",
                    e.detail,
                    fallback.len()
                ),
            ));
            fallback
        }
    }
}

/// Try each relay (already ordered IPv6-first) until one bootstraps a
/// relay-via session, time-boxing each attempt by `relay_dial_timeout` so a
/// dead/censored relay — or one the sharer never registered with (a family
/// mismatch looks identical: the Initial is silently dropped) — fails over to
/// the next instead of stalling. Returns the last error if all fail.
#[allow(clippy::too_many_arguments)]
async fn dial_relays(
    relay_addrs: &[(SocketAddr, RelayProtocol)],
    token: &Token,
    config: &Config,
    cancel: CancellationToken,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    rec: &Recorder,
    session: &SessionSlot,
) -> Result<IpTransport, Fault> {
    let mut last_err: Option<Fault> = None;
    for &(relay_addr, protocol) in relay_addrs {
        // One step per endpoint tried, so a record shows every relay that was
        // attempted and how each one refused — not just the last one, which
        // is all the returned error can carry.
        let step = rec
            .step_now(StepKind::RelayDial)
            .via(relay_addr)
            .carrier(Carrier::of_protocol(protocol))
            .path(PathKind::of_protocol(protocol));
        let attempt = dial_initiator(
            relay_addr,
            protocol,
            token,
            config,
            cancel.clone(),
            keepalive_knob.clone(),
            keepalive_waker.clone(),
            rec,
            session,
        );
        match tokio::time::timeout(config.timings.relay_dial_timeout, attempt).await {
            Ok(Ok(transport)) => {
                step.ok();
                return Ok(transport);
            }
            Ok(Err(e)) => {
                warn!("relay {} dial failed: {}", relay_addr, e);
                step.fail_with(&e);
                last_err = Some(e);
            }
            Err(_) => {
                warn!(
                    "relay {} dial timed out after {:?}",
                    relay_addr, config.timings.relay_dial_timeout
                );
                let f = Fault::new(
                    Reason::ConnectTimeout,
                    format!(
                        "relay {relay_addr} dial timed out after {:?}",
                        config.timings.relay_dial_timeout
                    ),
                );
                step.fail_with(&f);
                last_err = Some(f);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Fault::new(Reason::NoRelays, "no relays to dial")))
}

#[allow(clippy::too_many_arguments)]
async fn dial_initiator(
    relay_addr: SocketAddr,
    protocol: RelayProtocol,
    token: &Token,
    config: &Config,
    cancel: CancellationToken,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    rec: &Recorder,
    live_session: &SessionSlot,
) -> Result<IpTransport, Fault> {
    // Select the client-side dialer for this endpoint's protocol. The returned
    // session is end-to-end authenticated (cert-hash pinned + secret) whatever
    // the protocol; the relay is never trusted. Relay path: require the sharer's
    // accept ack so a bad/expired token fails here instead of reconnect-looping.
    let client = carrier::relay_client_for(protocol);
    debug!("dialing {} via {:?} carrier", relay_addr, client.protocol());
    let session = client
        .dial(carrier::DialCtx {
            target: relay_addr,
            cert_hash: token.cert_hash,
            routing_hash: token.routing_hash(),
            secret: token.secret,
            protector: &config.protector,
            timings: &config.timings,
            expect_ack: true,
            rec,
        })
        .await?;
    let carrier::PeerSession {
        transport,
        remote_addr,
        quic_conn,
        signal,
        fixed_mtu,
    } = session;

    let carrier_kind = Carrier::of_protocol(protocol);
    let path_kind = PathKind::of_protocol(protocol);
    // Kept for API compatibility; PathActivated is the precise automation
    // surface for all carriers and path kinds.
    emit(
        &config.event_hook,
        TunnelEvent::RelaySessionEstablished { peer: remote_addr },
    );
    emit(
        &config.event_hook,
        TunnelEvent::PathActivated {
            carrier: carrier_kind,
            path: path_kind,
            local: None,
            peer: remote_addr,
        },
    );
    // `remote_addr` is the relay's address on a relayed carrier — the peer's
    // own address is not observable from here, and the record must not imply
    // otherwise. `path` says which it is.
    rec.mark(StepKind::SessionUp)
        .peer(remote_addr)
        .carrier(carrier_kind)
        .path(path_kind)
        .ok();
    let meters = SessionMeters::new(rec, carrier_kind, path_kind, quic_conn.clone(), fixed_mtu);
    if let Ok(mut live) = live_session.lock() {
        *live = Some(meters.clone());
    }

    let (upgradable, upgrade_sender, router_handle) =
        upgradable_transport(transport, config.timings.upgrade_rescue_grace);
    // Per session, not per run: `cancel` is the run's token, and this runs
    // again on every redial.
    spawn_sampler(meters.clone(), cancel.clone(), upgrade_sender.ended());
    let upgrade_knob = keepalive_knob.clone();
    let keepalive_cfg = KeepAliveConfig {
        mode: KeepAliveMode::Adaptive {
            knob: keepalive_knob,
            waker: keepalive_waker,
        },
        idle_threshold: config.timings.keepalive_idle_threshold,
        response_timeout: config.timings.keepalive_response_timeout,
        inbound_grace: config.timings.keepalive_inbound_grace,
        counters: Some(meters.counters.clone()),
        recorder: Some(rec.clone()),
        on_dead: Some(meters.on_dead()),
        ..Default::default()
    };
    let transport: IpTransport =
        Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg));

    // MTU: a QUIC carrier reads the PMTUD-converged max_datagram_size after
    // ~1.5s; a stream carrier has no per-datagram limit, so report a fixed MTU.
    let mtu_cb_relay = config.mtu_callback.clone();
    let mtu_rec = rec.clone();
    match quic_conn {
        Some(conn) => {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                match conn.max_datagram_size() {
                    Some(mds) => {
                        info!("e2e max datagram size (post-PMTUD): {}", mds);
                        mtu_rec
                            .mark(StepKind::Mtu)
                            .detail(format!("discovered {mds}"))
                            .ok();
                        if let Some(cb) = mtu_cb_relay {
                            cb(mds as u16);
                        }
                    }
                    // Nothing came of the probing. Silence here used to be
                    // indistinguishable from a converged path.
                    None => mtu_rec
                        .mark(StepKind::Mtu)
                        .fail(Reason::Unknown, "no datagram size after PMTUD"),
                }
            });
        }
        None => {
            rec.mark(StepKind::Mtu)
                .detail(format!("declared {fixed_mtu}"))
                .ok();
            if let Some(cb) = mtu_cb_relay {
                cb(fixed_mtu);
            }
        }
    }

    let upgrade_cancel = cancel.clone();
    // Only a *relayed QUIC* session benefits from a direct upgrade. A Direct
    // session already terminates directly on the sharer; a TcpTls session has
    // no QUIC signal channel and no UDP path to punch. Skipping for Direct also
    // drops the signal now, so the sharer's responder upgrade hits EOF on its
    // first recv_endpoint and stops *before* it ever STUNs.
    let attempt_upgrade = config.enable_direct_upgrade && protocol.is_relayed() && signal.is_some();
    if attempt_upgrade {
        let signal = signal.expect("attempt_upgrade requires a signal channel");
        let role = DirectRole::Initiator {
            cert_hash: token.cert_hash,
            routing_hash: token.routing_hash(),
            secret: token.secret,
        };
        let stun_servers = config.stun_servers.clone();
        let protector = config.protector.clone();
        let mtu_cb = config.mtu_callback.clone();
        let timings = config.timings.clone();
        let event_hook = config.event_hook.clone();
        let path_ipv6 = relay_addr.is_ipv6();
        let upgrade_meters = meters.clone();
        tokio::spawn(async move {
            try_direct_upgrade(
                signal,
                upgrade_sender,
                &stun_servers,
                role,
                path_ipv6,
                &protector,
                upgrade_cancel,
                Some(upgrade_knob),
                mtu_cb,
                timings,
                event_hook,
                None, // client side: no connection log
                upgrade_meters,
            )
            .await;
            drop(router_handle);
        });
    } else {
        // Not attempting an initiator upgrade. For a Direct session drop the
        // signal now (stops the peer's responder before STUN). For a relayed
        // session with the upgrade globally disabled, hold the SignalChannel
        // open so the peer's attempts time out instead of seeing EOF. Either
        // way the holder must die with the *session*, not just the connect-level
        // cancel token: each re-dial runs through here again, so a cancel-only
        // holder would accumulate one parked task per redial. The router drops
        // its upgrade receiver when the session ends, so `upgrade_sender.closed()`
        // is exactly the session-death signal.
        // Recorded as skipped, with which of the three reasons it was: not
        // attempting is a different fact from attempting and failing.
        let skip_reason = if !config.enable_direct_upgrade {
            Reason::UpgradeDisabled
        } else {
            Reason::UpgradeUnsupported
        };
        rec.mark(StepKind::PathSwap)
            .carrier(carrier_kind)
            .skip(skip_reason, "no direct upgrade attempted");
        let drop_signal_now = !protocol.is_relayed();
        tokio::spawn(async move {
            // Direct: drop the signal now (peer's responder stops before STUN).
            // Relayed QUIC + disabled: hold it until session death (peer's
            // attempts time out instead of erroring). Stream carrier: None.
            let held_signal = if drop_signal_now {
                drop(signal);
                None
            } else {
                signal
            };
            tokio::select! {
                _ = upgrade_cancel.cancelled() => {}
                _ = upgrade_sender.closed() => {}
            }
            drop(held_signal);
            drop(router_handle);
        });
    }

    Ok(transport)
}

/// Open a record for one run, or a handle that does nothing when the platform
/// has not asked for one (the core does not write to a user's disk uninvited).
fn open_record(
    config: &Config,
    role: Role,
    routing_hash: Option<&[u8]>,
    endpoints: Vec<EndpointRef>,
) -> Recorder {
    match config.record.as_ref() {
        Some(cfg) => Recorder::start(
            cfg,
            role,
            routing_hash,
            endpoints,
            config.enable_direct_upgrade,
        ),
        None => Recorder::disabled(),
    }
}

/// The configured endpoints, as the record describes them.
fn endpoint_refs(relays: &[RelayEndpoint]) -> Vec<EndpointRef> {
    relays
        .iter()
        .map(|r| EndpointRef {
            host: r.host.clone(),
            port: r.port,
            carrier: Carrier::of_protocol(r.protocol),
            path: PathKind::of_protocol(r.protocol),
            addr: None,
        })
        .collect()
}

/// Everything one live session needs in order to describe itself: where its
/// traffic is going, how much of it there has been, and whatever the carrier
/// is willing to say about the path.
///
/// It is shared with the direct upgrade, which replaces the path (and the
/// connection the numbers come from) underneath a running sampler — so a
/// single series continues across the swap instead of restarting.
#[derive(Clone)]
pub(crate) struct SessionMeters {
    rec: Recorder,
    carrier: Carrier,
    path: Arc<PathState>,
    counters: Arc<LinkCounters>,
    quic: Arc<std::sync::Mutex<Option<Connection>>>,
    /// Set for carriers that declare a fixed frame size instead of probing
    /// for one.
    fixed_mtu: Option<u16>,
}

/// The client's session that is up right now (see `connect`).
type SessionSlot = Arc<std::sync::Mutex<Option<SessionMeters>>>;

impl SessionMeters {
    fn new(
        rec: &Recorder,
        carrier: Carrier,
        path: PathKind,
        quic: Option<Connection>,
        fixed_mtu: u16,
    ) -> Self {
        Self {
            rec: rec.clone(),
            carrier,
            path: Arc::new(PathState::new(path)),
            counters: Arc::new(LinkCounters::default()),
            quic: Arc::new(std::sync::Mutex::new(quic.clone())),
            fixed_mtu: quic.is_none().then_some(fixed_mtu),
        }
    }

    /// The direct upgrade landed: from here the numbers come from the new
    /// path and the new connection.
    fn on_direct(&self, path: PathKind, quic: Option<Connection>) {
        self.path.set(path);
        if let Ok(mut slot) = self.quic.lock() {
            *slot = quic;
        }
    }

    /// The session's QUIC connection right now (after an upgrade, the direct
    /// one); `None` on a carrier without one.
    fn current_quic(&self) -> Option<Connection> {
        self.quic.lock().ok().and_then(|g| g.clone())
    }

    /// This end found the session dead: tell the peer so over its current
    /// connection (`transport::quic::SESSION_DEAD_CODE`), ahead of the
    /// orderly close the transport's drop would send — which the peer would
    /// record as an ordinary end. Called on every failure path that ends a
    /// session: the keepalive giving up (both roles), the client's reconnect
    /// layer seeing its transport die, an exit that stopped on its own. A
    /// connection already closed — the peer's own close, an idle timeout —
    /// keeps the close it had.
    fn close_dead(&self) {
        if let Some(conn) = self.current_quic() {
            transport::quic::close_dead(&conn);
        }
    }

    /// The keepalive layer's `on_dead` for this session.
    fn on_dead(&self) -> Arc<dyn Fn() + Send + Sync> {
        let meters = self.clone();
        Arc::new(move || meters.close_dead())
    }

    /// Record this session's `session_end`, for a session that ended by
    /// itself (not cancelled from this end), with what ended it as the
    /// keepalive layer saw it (see `LinkCounters::ended_by`): the QUIC close
    /// reason, its own `keepalive_timeout`, a stream error's code. A peer's
    /// deliberate close is the ordinary end of a session, so it concludes
    /// `ok` (`peer_closed`); the rest are failures — among them a peer that
    /// closed the session because it died on its side (`close_dead`), and
    /// `transport_closed` when nothing better is known (an nz or TCP stream
    /// that just ended, an exit handler that returned on its own).
    fn record_end(&self) {
        let fault = self
            .counters
            .ended_by()
            .unwrap_or_else(|| Fault::new(Reason::TransportClosed, "the transport closed"));
        let step = self.end_step();
        if fault.reason == Reason::PeerClosed {
            step.ok_because(fault.reason, fault.detail);
        } else {
            step.fail_with(&fault);
        }
    }

    /// Record this session's `session_end` for a session this end ended —
    /// replaced, or stopped — which is an ordinary end: `ok`, with `why`.
    fn record_local_end(&self, why: Reason, detail: &str) {
        self.end_step().ok_because(why, detail);
    }

    fn end_step(&self) -> record::StepHandle {
        self.rec
            .mark(StepKind::SessionEnd)
            .carrier(self.carrier)
            .path(self.path.get())
    }

    fn take_sample(&self) {
        let c = &self.counters;
        let mut s = record::SampleInput {
            path: self.path.get(),
            carrier: self.carrier,
            tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
            tx_pkts: c.tx_pkts.load(Ordering::Relaxed),
            rx_pkts: c.rx_pkts.load(Ordering::Relaxed),
            probes_sent: Some(c.probes_sent.load(Ordering::Relaxed)),
            probes_lost: Some(
                c.probes_sent
                    .load(Ordering::Relaxed)
                    .saturating_sub(c.probes_answered.load(Ordering::Relaxed)),
            ),
            ..Default::default()
        };
        // The probe's round trip goes through the tunnel, so it is the only
        // one comparable across carriers; the carrier's own estimate is
        // better but measures a different thing, so it is labelled.
        if let Some(rtt) = c.last_rtt() {
            s.rtt_ms = Some(rtt.as_secs_f64() * 1000.0);
            s.rtt_src = Some(RttSource::Keepalive);
        }
        let conn = self.quic.lock().ok().and_then(|g| g.clone());
        match conn {
            Some(conn) => {
                let st = conn.stats();
                s.rtt_ms = Some(st.path.rtt.as_secs_f64() * 1000.0);
                s.rtt_src = Some(RttSource::Quic);
                s.cwnd = Some(st.path.cwnd);
                // Send-side only: QUIC tells us what we lost, never what the
                // peer did.
                s.lost_pkts = Some(st.path.lost_packets);
                s.mtu = conn.max_datagram_size().map(|m| m as u16);
                s.mtu_src = Some(MtuSource::Discovered);
            }
            None => {
                s.mtu = self.fixed_mtu;
                s.mtu_src = self.fixed_mtu.map(|_| MtuSource::Declared);
            }
        }
        self.rec.sample(s);
    }
}

/// Sample this session until it ends — its router stops (`ended`, see
/// [`UpgradeSender::ended`]) or `cancel` fires — and meanwhile count its
/// traffic toward the run's closing total. Cheap: a few atomics and one
/// `stats()` call per interval.
///
/// Ending with the session, not the run, matters on the client: every
/// redial builds a new session, and a sampler that lived as long as the run
/// would go on sampling (and holding the connection of) each dead one.
fn spawn_sampler(meters: SessionMeters, cancel: CancellationToken, ended: CancellationToken) {
    if !meters.rec.is_enabled() {
        return;
    }
    let interval = meters.rec.sample_interval();
    let traffic = meters.rec.count_traffic(meters.counters.clone());
    tokio::spawn(async move {
        // Dropped when the session ends, folding its final figures in.
        let _traffic = traffic;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ended.cancelled() => break,
                _ = tokio::time::sleep(interval), if !interval.is_zero() => meters.take_sample(),
            }
        }
    });
}

// ---------- Direct upgrade ----------

pub(crate) enum DirectRole {
    Initiator {
        cert_hash: CertHash,
        routing_hash: RoutingHash,
        secret: [u8; SECRET_LEN],
    },
    Responder {
        identity: Arc<ShareIdentity>,
    },
}

/// Why a single direct-upgrade attempt failed.
#[derive(Debug)]
pub(crate) enum DirectError {
    /// The signal channel is closed — no further negotiation is possible for
    /// this session. Terminal: `try_direct_upgrade` must return (retrying
    /// would fail instantly and hot-spin on the responder side).
    SignalClosed(Fault),
    /// Transient failure (STUN, punch, QUIC handshake, ...); a later attempt
    /// may succeed.
    Transient(Fault),
}

impl DirectError {
    /// A transient failure. Takes anything that converts into a [`Fault`], so
    /// a call site that has not been given a vocabulary code yet still
    /// compiles — and records an honest `unknown` rather than a guess.
    fn transient(e: impl Into<Fault>) -> Self {
        DirectError::Transient(e.into())
    }

    fn signal_closed(e: impl Into<Fault>) -> Self {
        DirectError::SignalClosed(e.into())
    }

    fn fault(&self) -> &Fault {
        match self {
            DirectError::SignalClosed(f) | DirectError::Transient(f) => f,
        }
    }

    fn reason(&self) -> &str {
        &self.fault().detail
    }
}

/// Map a negotiation-channel error to `DirectError`. `NegChannelClosed` is
/// terminal — note this covers both a genuinely closed stream AND a length
/// prefix over the 64 KiB signal limit (framing desync), since `recv_signal`
/// cannot distinguish them; retrying on a desynced stream would be useless
/// anyway. A garbled endpoint *payload* (`ProtocolError`) is transient.
fn neg_err(e: TunnelError) -> DirectError {
    match e {
        TunnelError::NegChannelClosed => {
            DirectError::signal_closed(Fault::new(Reason::SignalClosed, "signal channel closed"))
        }
        // A refused candidate is a policy decision about an address the peer
        // chose, not a broken peer — and on a hostile network the difference
        // is the whole finding.
        TunnelError::PunchTargetRefused(msg) => {
            DirectError::transient(Fault::new(Reason::TargetRejected, msg))
        }
        other => {
            DirectError::transient(Fault::new(Reason::ProtocolViolation, format!("{other:?}")))
        }
    }
}

/// The initiator's wait between failed direct-upgrade attempts: `base`
/// (`Timings::upgrade_retry_delay`) after the first failure of a streak,
/// doubled for each further consecutive failure, never more than `max`
/// (`Timings::upgrade_retry_max`; a cap below `base` wins). One per session,
/// so a reconnect starts over; a wake from dormancy [`reset`]s it, wherever
/// the wake is seen (see [`UpgradePacing`]).
///
/// A path that has refused to punch a few times in a row is unlikely to
/// start punching on the next try, and each try is STUN queries, a punch
/// burst and a record entry — so the attempts thin out instead of firing
/// every 15 s for the life of the session.
///
/// [`reset`]: UpgradeBackoff::reset
#[derive(Debug)]
struct UpgradeBackoff {
    base: Duration,
    max: Duration,
    /// Consecutive failed attempts since the streak (re)started.
    failures: u32,
}

impl UpgradeBackoff {
    fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            failures: 0,
        }
    }

    /// Count a failed attempt and return the wait before the next one.
    fn failed(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        // 2^31 is far past any cap; stopping there keeps the shift defined.
        let doublings = (self.failures - 1).min(31);
        self.base.saturating_mul(1u32 << doublings).min(self.max)
    }

    /// The wait the first failure of a streak gets.
    fn first_wait(&self) -> Duration {
        self.base.min(self.max)
    }

    /// Start the streak over.
    fn reset(&mut self) {
        self.failures = 0;
    }
}

/// Failed direct-upgrade attempts the initiator makes while the application
/// is dormant before it parks until a wake.
const MAX_DORMANT_UPGRADE_ATTEMPTS: u32 = 3;

/// The initiator's pacing between direct-upgrade attempts: the backoff
/// streak, and the dormancy bookkeeping around it. A wake — the keepalive
/// knob going from 0 to above it — starts the streak over and counts dormant
/// attempts afresh wherever it is seen: before an attempt, at the end of one
/// that began dormant, in the dormant park, or during the retry wait
/// ([`wait_before_retry`]).
#[derive(Debug)]
struct UpgradePacing {
    backoff: UpgradeBackoff,
    /// Attempts that failed while dormant since the last wake.
    dormant_attempts: u32,
    /// The knob read above 0 when the current attempt began.
    was_active: bool,
}

impl UpgradePacing {
    fn new(base: Duration, max: Duration) -> Self {
        Self {
            backoff: UpgradeBackoff::new(base, max),
            dormant_attempts: 0,
            was_active: false,
        }
    }

    /// Before an attempt, with the knob as it reads now: whether to park
    /// until a wake instead (dormant, and out of dormant attempts).
    fn before_attempt(&mut self, knob: u64) -> bool {
        let active = knob > 0;
        if active && !self.was_active {
            // Awake (or just started).
            self.woke();
        }
        self.was_active = active;
        !active && self.dormant_attempts >= MAX_DORMANT_UPGRADE_ATTEMPTS
    }

    /// An attempt failed, with the knob as it reads now (`None`: there is
    /// none, so never dormant): the wait before the next attempt.
    fn after_failure(&mut self, knob: Option<u64>) -> Duration {
        match knob {
            Some(0) => self.dormant_attempts += 1,
            // The attempt began dormant and the application woke while it
            // ran: a wake like any other, so the next wait is the streak's
            // first — not the doubled one the dormant streak had reached.
            Some(_) if !self.was_active => {
                info!("Direct upgrade: woke during the attempt; backoff reset");
                self.woke();
            }
            _ => {}
        }
        self.backoff.failed()
    }

    /// Awake: the streak starts over and dormant attempts count afresh.
    fn woke(&mut self) {
        self.dormant_attempts = 0;
        self.was_active = true;
        self.backoff.reset();
    }
}

/// How often the initiator's retry wait looks at the keepalive knob for a
/// wake from dormancy (the same cadence the dormant park polls at).
const UPGRADE_KNOB_POLL: Duration = Duration::from_secs(5);

/// How an initiator's retry wait ended.
#[derive(Debug, PartialEq, Eq)]
enum RetryWaitEnd {
    /// Time for the next attempt. `woke`: the application woke from
    /// dormancy during the wait, and `backoff` has started over.
    Elapsed { woke: bool },
    /// The run was cancelled or the session ended: stop trying.
    Stop,
}

/// Wait `wait` before the next direct-upgrade attempt. `dormant`: the
/// keepalive knob read 0 when the failed attempt concluded. (A wake during
/// the attempt itself was already counted when it concluded, by
/// [`UpgradePacing::after_failure`].)
///
/// The wait can be minutes, so it watches for the two things that change the
/// plan: the session ending (no point lingering on a dead one) and a wake from
/// dormancy (`knob` seen at 0, then above it), which starts the streak over —
/// `backoff` is reset and the wait in progress shrinks to the streak's first
/// wait, counted from when it began, much as the dormant park acts on a wake
/// at once.
async fn wait_before_retry(
    wait: Duration,
    dormant: bool,
    backoff: &mut UpgradeBackoff,
    knob: Option<&AtomicU64>,
    cancel: &CancellationToken,
    upgrade_sender: &UpgradeSender,
) -> RetryWaitEnd {
    let started = tokio::time::Instant::now();
    let mut deadline = started + wait;
    let mut seen_dormant = dormant;
    let mut woke = false;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return RetryWaitEnd::Elapsed { woke };
        }
        let tick = (deadline - now).min(UPGRADE_KNOB_POLL);
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Direct upgrade cancelled during retry wait");
                return RetryWaitEnd::Stop;
            }
            _ = upgrade_sender.closed() => {
                info!("Upgrade channel closed during retry wait, stopping direct upgrade");
                return RetryWaitEnd::Stop;
            }
            _ = tokio::time::sleep(tick) => {}
        }
        let Some(knob) = knob else {
            continue;
        };
        if knob.load(Ordering::Relaxed) == 0 {
            seen_dormant = true;
        } else if seen_dormant {
            seen_dormant = false;
            woke = true;
            backoff.reset();
            deadline = deadline.min(started + backoff.first_wait());
            info!("Direct upgrade: woke during the retry wait; backoff reset");
        }
    }
}

/// Background task: repeatedly try to establish a direct UDP connection.
/// On success, send the new transport via `upgrade_sender`.
///
/// `path_ipv6` is the relay-via session's address family; the initiator
/// STUNs (and therefore punches) in that family first, since it is the one
/// family both peers are known to have. The responder follows the family of
/// the endpoint the initiator signals.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_direct_upgrade(
    mut signal: SignalChannel,
    upgrade_sender: UpgradeSender,
    stun_servers: &[String],
    role: DirectRole,
    path_ipv6: bool,
    protector: &SocketProtector,
    cancel: CancellationToken,
    keepalive_knob: Option<Arc<AtomicU64>>,
    mtu_callback: MtuCallback,
    timings: Timings,
    event_hook: EventHook,
    // Share side only: records what each upgrade round learns about the
    // peer's outer address (self-reported endpoint, punch-validated source,
    // verified direct address) and the sharer's own STUN result.
    conn_log: Option<Arc<SessionLog>>,
    // This session's meters: the upgrade writes its steps here, and on
    // success it repoints them at the new path so one quality series
    // continues across the swap.
    meters: SessionMeters,
) {
    let initiator = matches!(role, DirectRole::Initiator { .. });
    let mut pacing = UpgradePacing::new(timings.upgrade_retry_delay, timings.upgrade_retry_max);

    loop {
        if cancel.is_cancelled() {
            info!("Direct upgrade cancelled");
            return;
        }
        if upgrade_sender.is_closed() {
            info!("Upgrade channel closed (transport replaced), stopping direct upgrade");
            return;
        }

        if initiator
            && let Some(ref knob) = keepalive_knob
            && pacing.before_attempt(knob.load(std::sync::atomic::Ordering::Relaxed))
        {
            info!("Direct upgrade: dormant attempts exhausted, waiting for screen-on");
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => { info!("Direct upgrade cancelled while parked"); return; }
                    _ = tokio::time::sleep(UPGRADE_KNOB_POLL) => {}
                }
                if upgrade_sender.is_closed() {
                    info!("Upgrade channel closed while parked");
                    return;
                }
                if knob.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                    pacing.woke();
                    break;
                }
            }
        }

        let result = match &role {
            DirectRole::Initiator {
                cert_hash,
                routing_hash,
                secret,
            } => {
                try_direct_as_initiator(
                    &mut signal,
                    stun_servers,
                    path_ipv6,
                    protector,
                    *cert_hash,
                    *routing_hash,
                    *secret,
                    &timings,
                    &meters.rec,
                )
                .await
            }
            DirectRole::Responder { identity } => {
                try_direct_as_responder(
                    &mut signal,
                    stun_servers,
                    protector,
                    identity,
                    &timings,
                    conn_log.as_deref(),
                    &meters.rec,
                )
                .await
            }
        };
        match result {
            Ok((transport, path)) => {
                info!("Direct connection established, upgrading transport");
                let swap = meters
                    .rec
                    .mark(StepKind::PathSwap)
                    .local(path.local)
                    .peer(path.peer)
                    .path(PathKind::DirectPunched)
                    .carrier(meters.carrier);
                let applied = match upgrade_sender.send(transport) {
                    Ok(applied) => applied,
                    Err(_) => {
                        warn!("Failed to send upgrade — tunnel already closed");
                        swap.fail(Reason::SwapFailed, "tunnel already closed");
                        return;
                    }
                };
                if applied.await.is_err() {
                    warn!("Failed to apply upgrade — transport router stopped");
                    swap.fail(Reason::SwapFailed, "transport router stopped");
                    return;
                }
                swap.ok();
                // From here the numbers describe the direct path.
                meters.on_direct(PathKind::DirectPunched, path.quic_conn.clone());
                if let Some(sl) = &conn_log {
                    sl.addr(AddrKind::Verified, path.peer);
                }
                emit(
                    &event_hook,
                    TunnelEvent::DirectUpgradeSucceeded {
                        local: path.local,
                        peer: path.peer,
                    },
                );
                emit(
                    &event_hook,
                    TunnelEvent::PathActivated {
                        carrier: meters.carrier,
                        path: PathKind::DirectPunched,
                        local: Some(path.local),
                        peer: path.peer,
                    },
                );
                // MTU: a QUIC path reports its PMTUD-converged datagram size after
                // a grace; nz reports its fixed budget immediately.
                let mtu_rec = meters.rec.clone();
                match path.quic_conn {
                    Some(conn) => {
                        let cb = mtu_callback.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(1500)).await;
                            match conn.max_datagram_size() {
                                Some(mds) => {
                                    info!("P2P max datagram size (post-PMTUD): {}", mds);
                                    mtu_rec
                                        .mark(StepKind::Mtu)
                                        .path(PathKind::DirectPunched)
                                        .detail(format!("discovered {mds}"))
                                        .ok();
                                    if let Some(cb) = cb {
                                        cb(mds as u16);
                                    }
                                }
                                None => mtu_rec
                                    .mark(StepKind::Mtu)
                                    .path(PathKind::DirectPunched)
                                    .fail(Reason::Unknown, "no datagram size after PMTUD"),
                            }
                        });
                    }
                    None => {
                        mtu_rec
                            .mark(StepKind::Mtu)
                            .path(PathKind::DirectPunched)
                            .detail(format!("declared {}", path.fixed_mtu))
                            .ok();
                        if let Some(cb) = mtu_callback.clone() {
                            cb(path.fixed_mtu);
                        }
                    }
                }
                return;
            }
            Err(e) => {
                warn!("Direct connection attempt failed: {}", e.reason());
                emit(
                    &event_hook,
                    TunnelEvent::DirectUpgradeFailed {
                        code: e.fault().reason,
                        reason: e.reason().to_string(),
                    },
                );
                if matches!(e, DirectError::SignalClosed(_)) {
                    info!("Signal channel closed — stopping direct upgrade for this session");
                    return;
                }
                if initiator {
                    let knob = keepalive_knob
                        .as_ref()
                        .map(|k| k.load(std::sync::atomic::Ordering::Relaxed));
                    let wait = pacing.after_failure(knob);
                    warn!("Retrying in {wait:?}...");
                    match wait_before_retry(
                        wait,
                        knob == Some(0),
                        &mut pacing.backoff,
                        keepalive_knob.as_deref(),
                        &cancel,
                        &upgrade_sender,
                    )
                    .await
                    {
                        RetryWaitEnd::Elapsed { woke: false } => {}
                        RetryWaitEnd::Elapsed { woke: true } => pacing.woke(),
                        RetryWaitEnd::Stop => return,
                    }
                }
            }
        }
    }
}

/// Initiator (B): STUN, exchange endpoint, punch, build direct QUIC client
/// (cert-pinned to `routing_hash`, sends `secret` on auth stream). On success
/// also returns the punched socket's local address (for event reporting).
/// The direct path a successful upgrade round produced, carrier-neutral. The
/// old `(transport, quinn::Connection, local)` triple was QUIC-specific; nz has
/// no `Connection`, so the MTU source is split out.
struct DirectPath {
    /// Verified direct peer address.
    peer: SocketAddr,
    /// Local address of the punched socket.
    local: SocketAddr,
    /// The QUIC connection, read for the post-PMTUD dynamic MTU. `None` for nz,
    /// which reports `fixed_mtu` immediately.
    quic_conn: Option<Connection>,
    fixed_mtu: u16,
}

#[allow(clippy::too_many_arguments)]
async fn try_direct_as_initiator(
    signal: &mut SignalChannel,
    stun_servers: &[String],
    path_ipv6: bool,
    protector: &SocketProtector,
    cert_hash: CertHash,
    routing_hash: RoutingHash,
    secret: [u8; SECRET_LEN],
    timings: &Timings,
    rec: &Recorder,
) -> Result<(IpTransport, DirectPath), DirectError> {
    let (socket, external_addr) = pierce_keep_socket_recorded(
        stun_servers,
        protector,
        path_ipv6,
        timings.stun_query_timeout,
        rec,
    )
    .await
    .map_err(DirectError::transient)?;
    let exchange = rec
        .step_now(StepKind::EndpointExchange)
        .local(external_addr);
    let peer_addr = {
        let mut neg = SignalNegChannel::new(signal);
        neg.send_endpoint(external_addr).await.map_err(neg_err)?;
        tokio::time::timeout(timings.endpoint_exchange_timeout, neg.recv_endpoint())
            .await
            .map_err(|_| {
                // Not a punch failure: the peer never told us where to aim,
                // which is a different fact about a different stage.
                DirectError::transient(Fault::new(
                    Reason::ExchangeTimeout,
                    format!(
                        "no endpoint from the peer within {:?}",
                        timings.endpoint_exchange_timeout
                    ),
                ))
            })?
            .map_err(neg_err)?
    };
    // The punch socket's family is fixed by our STUN result; a peer endpoint
    // in the other family is unreachable from it. Fail fast (the exchange is
    // one candidate per side, no multi-family negotiation) instead of
    // burning 2x punch_phase_timeout sending packets the OS refuses.
    exchange.peer(peer_addr).ok();
    if peer_addr.is_ipv6() != external_addr.is_ipv6() {
        let f = Fault::new(
            Reason::FamilyMismatch,
            format!("address family mismatch: ours {external_addr}, peer {peer_addr}"),
        );
        rec.mark(StepKind::Punch).peer(peer_addr).fail_with(&f);
        return Err(DirectError::transient(f));
    }

    let punching = rec
        .step_now(StepKind::Punch)
        .local(external_addr)
        .peer(peer_addr);
    let (punch_pkt, verify_pkt) = punch_markers(&secret);
    let (socket, learned_peer) = match punch_and_verify(
        socket,
        peer_addr,
        &punch_pkt,
        &verify_pkt,
        timings.punch_phase_timeout,
        timings.punch_send_interval,
    )
    .await
    {
        Ok(x) => {
            // The address that answered, which is not always the one the peer
            // signalled — that difference is what a symmetric NAT looks like.
            punching.peer(x.1).ok();
            x
        }
        Err(e) => {
            punching.fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    let local_addr = socket
        .local_addr()
        .map_err(|e| DirectError::transient(Fault::from_io(&e).context("local_addr")))?;
    let building = rec
        .step_now(StepKind::DirectHandshake)
        .peer(learned_peer)
        .local(local_addr)
        .path(PathKind::DirectPunched);
    // Rebuild the direct path with the SAME carrier as the relay path — the
    // signal variant tells us which. nz: a fresh NNpsk0 session over the punched
    // socket (independent keys/counters — a rebuild, not a cipher-state handoff).
    if signal.is_noise() {
        let socket = std::sync::Arc::new(socket);
        let mut transport = match crate::transport::noise::noise_connect(
            socket,
            learned_peer,
            &cert_hash,
            &routing_hash,
            &secret,
            timings.relay_dial_timeout,
            timings.quic_idle_timeout,
        )
        .await
        {
            Ok(t) => {
                building.carrier(Carrier::NoiseUdp).ok();
                t
            }
            Err(e) => {
                building.carrier(Carrier::NoiseUdp).fail_with(&e);
                return Err(DirectError::transient(e));
            }
        };
        let _ = transport.take_signal(); // already direct — no further upgrade
        return Ok((
            Box::new(transport),
            DirectPath {
                peer: learned_peer,
                local: local_addr,
                quic_conn: None,
                fixed_mtu: crate::transport::noise::NZ_TUNNEL_MTU,
            },
        ));
    }
    let std_sock = socket
        .into_std()
        .map_err(|e| DirectError::transient(Fault::from_io(&e).context("into_std")))?;
    let endpoint = client_endpoint(std_sock, cert_hash, routing_hash, timings)
        .map_err(DirectError::transient)?;
    // Dial the address the peer's packets actually came from — our NAT has a
    // mapping open toward it, which may not be true of the signaled address.
    // No accept ack on the direct path: the secret is already proven good, and
    // waiting on a reverse-direction byte over a fresh punch only adds failures.
    let session = match client_connect(&endpoint, learned_peer, &secret, false).await {
        Ok(s) => {
            building.carrier(Carrier::Quic).ok();
            s
        }
        Err(e) => {
            building.carrier(Carrier::Quic).fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    // Reuse the session's transport: its reader task is already attached to
    // the connection, and building a second QuicPeerTransport here would
    // leave that reader to steal the first inbound datagram before exiting.
    let conn = session.conn;
    Ok((
        Box::new(session.transport),
        DirectPath {
            peer: conn.remote_address(),
            local: local_addr,
            quic_conn: Some(conn),
            fixed_mtu: 0,
        },
    ))
}

/// Responder (A): wait for peer endpoint, STUN, send own endpoint, punch,
/// build direct QUIC server using identity, verify peer's secret. On success
/// also returns the punched socket's local address (for event reporting).
#[allow(clippy::too_many_arguments)]
async fn try_direct_as_responder(
    signal: &mut SignalChannel,
    stun_servers: &[String],
    protector: &SocketProtector,
    identity: &ShareIdentity,
    timings: &Timings,
    conn_log: Option<&SessionLog>,
    rec: &Recorder,
) -> Result<(IpTransport, DirectPath), DirectError> {
    let exchange = rec.step_now(StepKind::EndpointExchange);
    let (peer_addr, socket) = {
        let mut neg = SignalNegChannel::new(signal);
        let peer_addr = neg.recv_endpoint().await.map_err(neg_err)?;
        // Client-asserted, not observed: logged as `reported` and never to
        // be read as anything stronger (a malicious client can put any
        // address here).
        if let Some(sl) = conn_log {
            sl.addr(AddrKind::Reported, peer_addr);
        }
        // Follow the initiator's family: it signaled first, so STUN (and
        // punch) in the family its endpoint lives in.
        let (socket, external_addr) = pierce_keep_socket_recorded(
            stun_servers,
            protector,
            peer_addr.is_ipv6(),
            timings.stun_query_timeout,
            rec,
        )
        .await
        .map_err(DirectError::transient)?;
        if let Some(sl) = conn_log {
            sl.addr(AddrKind::SharerPublic, external_addr);
        }
        // Send our endpoint even when the families ended up mismatched (no
        // matching-family STUN address resolved): the initiator then detects
        // the mismatch immediately instead of timing out on the exchange.
        neg.send_endpoint(external_addr).await.map_err(neg_err)?;
        exchange.local(external_addr).peer(peer_addr).ok();
        if peer_addr.is_ipv6() != external_addr.is_ipv6() {
            let f = Fault::new(
                Reason::FamilyMismatch,
                format!("address family mismatch: ours {external_addr}, peer {peer_addr}"),
            );
            rec.mark(StepKind::Punch).peer(peer_addr).fail_with(&f);
            return Err(DirectError::transient(f));
        }
        (peer_addr, socket)
    };

    // Responder accepts from whatever source the QUIC Initial arrives on, so
    // the learned peer address is informational for the punch — but it is
    // address-validated (learned from packets the peer actually sourced), so
    // the connection log records it even when the QUIC build below fails.
    let (punch_pkt, verify_pkt) = punch_markers(&identity.secret);
    let punching = rec.step_now(StepKind::Punch).peer(peer_addr);
    let (socket, learned_peer) = match punch_and_verify(
        socket,
        peer_addr,
        &punch_pkt,
        &verify_pkt,
        timings.punch_phase_timeout,
        timings.punch_send_interval,
    )
    .await
    {
        Ok(x) => {
            punching.peer(x.1).ok();
            x
        }
        Err(e) => {
            punching.fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    if let Some(sl) = conn_log {
        sl.addr(AddrKind::PunchVerified, learned_peer);
    }
    let local_addr = socket
        .local_addr()
        .map_err(|e| DirectError::transient(Fault::from_io(&e).context("local_addr")))?;
    let building = rec
        .step_now(StepKind::DirectHandshake)
        .peer(learned_peer)
        .local(local_addr)
        .path(PathKind::DirectPunched);
    // nz responder: accept a fresh NNpsk0 session on the punched socket (a pump
    // feeds noise_accept, which waits for the initiator's msg1). Same carrier as
    // the relay path; independent keys.
    if signal.is_noise() {
        let socket = std::sync::Arc::new(socket);
        let shaper = crate::transport::shaper::nz_shaper(&identity.routing_hash, &identity.secret);
        let (rx, pump) = crate::transport::noise::spawn_socket_pump(socket.clone(), shaper);
        let mut transport = match crate::transport::noise::noise_accept(
            socket,
            rx,
            rand::random(),
            Some(pump),
            identity,
            timings.relay_dial_timeout,
            timings.quic_idle_timeout,
        )
        .await
        {
            Ok(t) => {
                building.carrier(Carrier::NoiseUdp).ok();
                t
            }
            Err(e) => {
                building.carrier(Carrier::NoiseUdp).fail_with(&e);
                return Err(DirectError::transient(e));
            }
        };
        let peer = transport.peer_addr();
        let _ = transport.take_signal(); // already direct — no further upgrade
        return Ok((
            Box::new(transport),
            DirectPath {
                peer,
                local: local_addr,
                quic_conn: None,
                fixed_mtu: crate::transport::noise::NZ_TUNNEL_MTU,
            },
        ));
    }
    let std_sock = socket
        .into_std()
        .map_err(|e| DirectError::transient(Fault::from_io(&e).context("into_std")))?;
    let endpoint = server_endpoint(std_sock, identity, timings).map_err(DirectError::transient)?;
    // Time-box only the wait for the initiator's connection attempt — not the
    // handshake, which keeps its own deadline inside authenticate_incoming.
    // endpoint.accept() blocks until an Incoming arrives; if the initiator's
    // VERIFY replies were lost it never dials, and an unbounded wait would pin
    // this task for the whole session (holding the signal channel, so no retry
    // round can progress). On timeout we return Transient and the upgrade loop
    // retries or observes cancellation. (After a successful mutual punch the
    // initiator dials immediately, so this only fires when it isn't coming.)
    let accept_deadline = timings.punch_phase_timeout * 2;
    let incoming = match tokio::time::timeout(accept_deadline, endpoint.accept()).await {
        Ok(Some(incoming)) => incoming,
        Ok(None) => {
            return Err(DirectError::transient(Fault::new(
                Reason::TransportClosed,
                "direct endpoint closed before accept",
            )));
        }
        Err(_) => {
            return Err(DirectError::transient(Fault::new(
                Reason::VerifyTimeout,
                format!(
                    "direct accept timed out after {accept_deadline:?} (initiator never dialed)"
                ),
            )));
        }
    };
    // No accept ack on the direct path (see the initiator-side note).
    let session = match authenticate_incoming(incoming, &identity.secret, false).await {
        Ok(s) => {
            building.carrier(Carrier::Quic).ok();
            s
        }
        Err(e) => {
            building.carrier(Carrier::Quic).fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    // Reuse the session's transport (see the initiator-side note): a second
    // QuicPeerTransport would orphan the session's reader, which eats the
    // first inbound datagram on the fresh direct path.
    let conn = session.conn;
    Ok((
        Box::new(session.transport),
        DirectPath {
            peer: conn.remote_address(),
            local: local_addr,
            quic_conn: Some(conn),
            fixed_mtu: 0,
        },
    ))
}

// ---------- Helpers ----------

/// Resolve the relay to a single address. IP literals (v4, and v6 with or
/// without brackets — `Token::from_url` strips them, but a caller-supplied
/// `Config.relay_host` may not) short-circuit DNS. For hostnames, IPv4 is
/// preferred when both families resolve (the deployed relay is v4-first);
/// an AAAA-only host resolves to its IPv6 address(es).
///
/// A bare/bracketed IP literal short-circuits DNS (one address). A hostname
/// expands to EVERY resolved address — both families — so a dual-record
/// `relay.example` behaves exactly as if its A and AAAA had been listed as
/// separate relays.
fn resolve_one_relay(relay: &RelayEndpoint) -> Result<Vec<SocketAddr>, Fault> {
    let host = &relay.host;
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, relay.port)]);
    }
    let addrs: Vec<SocketAddr> = format!("{}:{}", host, relay.port)
        .to_socket_addrs()
        .map_err(|e| {
            Fault::new(
                Reason::DnsFailure,
                format!("resolve relay {}:{} failed: {e}", host, relay.port),
            )
        })?
        .collect();
    if addrs.is_empty() {
        return Err(Fault::new(
            Reason::DnsNoRecords,
            format!("no address for relay {}:{}", host, relay.port),
        ));
    }
    Ok(addrs)
}

/// Resolve every configured relay into a flat, de-duplicated address list
/// (URL/config order preserved). A per-relay resolution failure is logged and
/// skipped — censorship that blocks one relay's DNS must not take down the
/// rest — so this errors only when NOTHING resolves.
fn resolve_relays(relays: &[RelayEndpoint]) -> Result<Vec<(SocketAddr, RelayProtocol)>, Fault> {
    let mut out: Vec<(SocketAddr, RelayProtocol)> = Vec::new();
    let mut seen: HashSet<(SocketAddr, RelayProtocol)> = HashSet::new();
    for relay in relays {
        match resolve_one_relay(relay) {
            Ok(addrs) => {
                for a in addrs {
                    // Each resolved address inherits its endpoint's protocol; a
                    // hostname with A+AAAA records fans out into several.
                    let entry = (a, relay.protocol);
                    if seen.insert(entry) {
                        out.push(entry);
                    }
                }
            }
            Err(e) => warn!("skipping unresolvable relay: {}", e),
        }
    }
    if out.is_empty() {
        return Err(Fault::new(
            Reason::DnsNoRecords,
            "no relay address resolved from the configured relays",
        ));
    }
    Ok(out)
}

/// Like [`resolve_relays`], but stable-sorted IPv6-first. The client uses
/// this so a v6 relay path (and therefore a v6 hole punch) is tried before
/// v4; within a family the configured order (and protocol) is preserved.
fn resolve_relays_preferring_v6(
    relays: &[RelayEndpoint],
) -> Result<Vec<(SocketAddr, RelayProtocol)>, Fault> {
    let mut addrs = resolve_relays(relays)?;
    addrs.sort_by_key(|(a, _)| !a.is_ipv6()); // false(0)=v6 first, true(1)=v4
    Ok(addrs)
}

/// Resolve the share's `protocol` relays into registration targets, each
/// address keeping its endpoint's credential (an address listed twice keeps
/// the first). Unresolvable endpoints are skipped; none at all is an error.
fn resolve_register_targets(
    relays: &[RelayEntry],
    protocol: RelayProtocol,
) -> Result<Vec<RegisterTarget>, Fault> {
    let mut out: Vec<RegisterTarget> = Vec::new();
    for relay in relays.iter().filter(|r| r.endpoint.protocol == protocol) {
        match resolve_one_relay(&relay.endpoint) {
            Ok(addrs) => {
                for addr in addrs {
                    if !out.iter().any(|t| t.addr == addr) {
                        out.push(RegisterTarget {
                            addr,
                            credential: relay.credential.clone(),
                        });
                    }
                }
            }
            Err(e) => warn!("skipping unresolvable relay: {}", e),
        }
    }
    if out.is_empty() {
        return Err(Fault::new(
            Reason::DnsNoRecords,
            "no relay address resolved from the configured relays",
        ));
    }
    Ok(out)
}

/// Bind the sharer's UDP socket. When the relay set spans IPv6 (or is mixed),
/// bind `::` dual-stack (IPV6_V6ONLY off) so one socket reaches relays of both
/// families and receives Initials forwarded by any of them; a pure-v4 relay
/// set keeps a plain `0.0.0.0` socket. Applies the FD protector.
/// UDP socket buffer size for nz sockets. The nz carrier has no tunnel pacer, so
/// an unpaced inner-TCP burst (a full congestion window at once) can overrun the
/// OS default receive buffer (~200 KB) and drop — which collapses the inner
/// TCP. quinn sizes QUIC's sockets internally; nz must size its own. Best-effort:
/// the kernel caps at net.core.{r,w}mem_max.
const NZ_SOCK_BUF: usize = 4 * 1024 * 1024;

/// Enlarge a UDP socket's send/recv buffers (see [`NZ_SOCK_BUF`]). Cross-platform
/// via `socket2::SockRef` (AsFd on unix, AsSocket on Windows). Failures are
/// ignored — a smaller-than-requested buffer still works, just with less burst
/// headroom.
fn tune_udp_buffers<'a, S>(socket: &'a S)
where
    socket2::SockRef<'a>: From<&'a S>,
{
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(NZ_SOCK_BUF);
    let _ = sock.set_send_buffer_size(NZ_SOCK_BUF);
}

fn bind_share_udp(
    protector: &SocketProtector,
    want_v6: bool,
    port: u16,
) -> Result<std::net::UdpSocket, String> {
    // `port` is 0 (ephemeral) for a relay-only sharer, or the advertised port a
    // `Direct` (relay-less) sharer must bind so clients can dial it.
    let std = if want_v6 {
        let sock = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
            .map_err(|e| format!("create v6 socket: {}", e))?;
        sock.set_only_v6(false)
            .map_err(|e| format!("set_only_v6(false): {}", e))?;
        sock.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())
            .map_err(|e| format!("bind [::]:{}: {}", port, e))?;
        std::net::UdpSocket::from(sock)
    } else {
        std::net::UdpSocket::bind(("0.0.0.0", port))
            .map_err(|e| format!("bind 0.0.0.0:{}: {}", port, e))?
    };
    std.set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;
    tune_udp_buffers(&std);
    apply_protector_to_std(protector, &std);
    Ok(std)
}

/// Bind an ephemeral UDP wildcard socket in `peer`'s address family (so
/// send_to toward it cannot fail with a family mismatch), apply the FD
/// protector, and return it as a `std::net::UdpSocket` ready for handoff to
/// quinn. The client uses this per relay-dial attempt, so the punch family
/// matches the relay family unambiguously (no v4-mapped guessing).
pub(crate) fn bind_local_udp(
    protector: &SocketProtector,
    peer: SocketAddr,
) -> Result<std::net::UdpSocket, Fault> {
    let wildcard: SocketAddr = if peer.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let std = std::net::UdpSocket::bind(wildcard)
        .map_err(|e| Fault::from_io(&e).context(&format!("bind UDP {wildcard}")))?;
    std.set_nonblocking(true)
        .map_err(|e| Fault::from_io(&e).context("set_nonblocking"))?;
    tune_udp_buffers(&std);
    apply_protector_to_std(protector, &std);
    Ok(std)
}

/// Fail at once when the kernel has no route to `peer` for a socket set up
/// like [`bind_local_udp`]'s (same family, same protector).
///
/// quinn-udp logs a send error and drops the datagram as if it were lost,
/// so a QUIC dial to an unroutable address (a v6 relay on a network without
/// IPv6: the kernel answers every Initial with ENETUNREACH) would wait out
/// the whole handshake timeout before the next relay is tried. A UDP
/// `connect()` is the kernel's route lookup with no packet sent. It runs on
/// a throwaway socket so the dial's own stays unconnected: quinn sends with
/// an explicit destination, which the BSDs refuse on a connected socket.
/// Only a "no route" answer fails the dial; anything else lets it go ahead.
pub(crate) fn check_udp_route(protector: &SocketProtector, peer: SocketAddr) -> Result<(), Fault> {
    use std::io::ErrorKind::{AddrNotAvailable, HostUnreachable, NetworkDown, NetworkUnreachable};
    let wildcard: SocketAddr = if peer.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let probe = match std::net::UdpSocket::bind(wildcard) {
        Ok(s) => s,
        Err(e) => {
            debug!("route check to {peer} skipped: bind {wildcard}: {e}");
            return Ok(());
        }
    };
    apply_protector_to_std(protector, &probe);
    match probe.connect(peer) {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                NetworkUnreachable | HostUnreachable | NetworkDown | AddrNotAvailable
            ) =>
        {
            Err(Fault::new(
                Reason::NoRoute,
                format!("no route to {peer}: {e}"),
            ))
        }
        Err(e) => {
            debug!("route check to {peer} inconclusive: {e}");
            Ok(())
        }
    }
}

/// Length of the per-session hole-punch markers.
const PUNCH_MARKER_LEN: usize = 16;

/// Per-session hole-punch markers `(probe, verify)`, derived from the shared
/// secret so they are unpredictable to an on-path observer — the secret travels
/// out of band in the share URL, never on the wire — instead of the old fixed
/// `sporaHP1P`/`sporaHP1V` literals a DPI box could byte-match. Both peers
/// derive identical values from the same 16-byte secret; the two markers differ
/// (distinct derivation labels) so a received VERIFY still proves the path is
/// bidirectional. Security still comes from the QUIC handshake that follows —
/// these only steer where we point it.
fn punch_markers(secret: &[u8; SECRET_LEN]) -> ([u8; PUNCH_MARKER_LEN], [u8; PUNCH_MARKER_LEN]) {
    let derive = |label: &[u8]| {
        let mut input = Vec::with_capacity(label.len() + SECRET_LEN);
        input.extend_from_slice(label);
        input.extend_from_slice(secret);
        let digest = ring::digest::digest(&ring::digest::SHA256, &input);
        let mut marker = [0u8; PUNCH_MARKER_LEN];
        marker.copy_from_slice(&digest.as_ref()[..PUNCH_MARKER_LEN]);
        marker
    };
    (
        derive(b"spora-punch-v1-probe"),
        derive(b"spora-punch-v1-verify"),
    )
}

/// Cap on peer-reflexive sources learned during a single punch exchange. A
/// spoofed-source punch flood would otherwise grow the learned/targets lists
/// without bound — and we send to every entry each tick, so the per-tick send
/// fan-out (and an O(n) membership scan per packet) would blow up. The signaled
/// address is always punched regardless, so a flood that fills this cap only
/// costs the peer-reflexive optimization, not the punch itself.
const MAX_PUNCH_SOURCES: usize = 64;

/// Record a peer-reflexive `src` heard during punching. Returns `true` if it was
/// newly added (so the caller starts punching it). Deduped via the set (O(1))
/// and bounded by `MAX_PUNCH_SOURCES`.
fn record_punch_source(
    learned: &mut HashSet<SocketAddr>,
    targets: &mut HashSet<SocketAddr>,
    src: SocketAddr,
) -> bool {
    if learned.contains(&src) || learned.len() >= MAX_PUNCH_SOURCES {
        return false;
    }
    learned.insert(src);
    targets.insert(src);
    true
}

/// Punch through NAT and verify *bidirectional* connectivity, learning the
/// peer's **observed** source address (ICE peer-reflexive style) rather than
/// trusting only the signaled one.
///
/// Why observed-source: a Linux conntrack NAT can remap an outgoing punch to
/// a different external port when an unsolicited inbound punch has already
/// created an `UNREPLIED` entry for the port we wanted ("port-steal"), so the
/// peer's packets routinely arrive from a port we were never told about.
/// Matching only the signaled address makes the punch fail in exactly that
/// case (and every retry re-poisons it). Instead we accept a punch/verify
/// from any source, learn it, and also send to it — which opens our own NAT
/// toward the address that actually works. Pointing the subsequent QUIC dial
/// at a wrong address merely fails the cert-pinned, secret-authenticated
/// handshake and retries, so trusting the observed source is safe.
///
/// Receiving a VERIFY proves both directions at once (it reached us, and the
/// peer sent it only because they received our packet), so success is the
/// first VERIFY received. We reply VERIFY to every source we hear from, plus
/// a few extra on exit, so the peer converges too. Returns the punched socket
/// and the learned peer address to dial.
///
/// `phase_timeout`/`send_interval` come from `Timings` (the total budget is
/// `2 * phase_timeout`, preserving the old two-phase wall-clock).
async fn punch_and_verify(
    socket: UdpSocket,
    signaled: SocketAddr,
    punch_pkt: &[u8],
    verify_pkt: &[u8],
    phase_timeout: Duration,
    send_interval: Duration,
) -> Result<(UdpSocket, SocketAddr), Fault> {
    debug!("Direct connection: punching {} (observed-source)", signaled);

    // Whether anything from the peer ever arrived. It separates the two
    // failures that look alike from the outside — "our packets never reached
    // them, or theirs never reached us" from "we met, but never confirmed it
    // both ways" — and only the first is evidence about the network.
    let heard_peer = std::sync::atomic::AtomicBool::new(false);
    let result = tokio::time::timeout(phase_timeout.saturating_mul(2), async {
        let mut buf = [0u8; 1500];
        let mut interval = tokio::time::interval(send_interval);
        // Always punch the signaled address; add learned sources as we hear
        // from them (and verify those — sending to a source opens our NAT
        // toward it).
        let mut targets: HashSet<SocketAddr> = HashSet::from([signaled]);
        let mut learned: HashSet<SocketAddr> = HashSet::new();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    for t in &targets {
                        let _ = socket.send_to(punch_pkt, *t).await;
                    }
                    for l in &learned {
                        let _ = socket.send_to(verify_pkt, *l).await;
                    }
                }
                result = socket.recv_from(&mut buf) => {
                    let (n, src) = match result {
                        Ok(x) => x,
                        Err(e) => return Err(Fault::from_io(&e).context("punch recv")),
                    };
                    let msg = &buf[..n];
                    if msg != punch_pkt && msg != verify_pkt {
                        continue;
                    }
                    heard_peer.store(true, std::sync::atomic::Ordering::Relaxed);
                    if record_punch_source(&mut learned, &mut targets, src) {
                        debug!("Direct connection: learned peer source {}", src);
                    }
                    // Open our NAT toward this source and tell it we heard it.
                    let _ = socket.send_to(verify_pkt, src).await;
                    if msg == verify_pkt {
                        // Bidirectional confirmed. A few extra VERIFYs so the
                        // peer reaches the same conclusion before we settle.
                        for _ in 0..3 {
                            let _ = socket.send_to(verify_pkt, src).await;
                        }
                        return Ok::<_, Fault>(src);
                    }
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(peer)) => {
            debug!("Bidirectional direct connection confirmed with {}", peer);
            Ok((socket, peer))
        }
        Ok(Err(e)) => Err(e),
        Err(_) if heard_peer.load(std::sync::atomic::Ordering::Relaxed) => Err(Fault::new(
            Reason::VerifyTimeout,
            format!(
                "heard the peer but never confirmed both directions within {:?}",
                phase_timeout.saturating_mul(2)
            ),
        )),
        Err(_) => Err(Fault::new(
            Reason::PunchTimeout,
            format!(
                "nothing from the peer within {:?}",
                phase_timeout.saturating_mul(2)
            ),
        )),
    }
}

/// Try STUN services in order and retain the successful query socket for the
/// direct connection (same socket/port = same NAT mapping). One resolved
/// address per service gets a bounded attempt, so a black-holed provider
/// cannot prevent later providers from being tried.
pub async fn pierce_keep_socket_with_fallback(
    stun_servers: &[String],
    protector: &SocketProtector,
    prefer_ipv6: bool,
    query_timeout: Duration,
) -> Result<(UdpSocket, SocketAddr), Fault> {
    pierce_keep_socket_recorded(
        stun_servers,
        protector,
        prefer_ipv6,
        query_timeout,
        &Recorder::disabled(),
    )
    .await
}

async fn pierce_keep_socket_recorded(
    stun_servers: &[String],
    protector: &SocketProtector,
    prefer_ipv6: bool,
    query_timeout: Duration,
    rec: &Recorder,
) -> Result<(UdpSocket, SocketAddr), Fault> {
    if stun_servers.is_empty() {
        return Err(Fault::new(
            Reason::DnsNoRecords,
            "no STUN services configured",
        ));
    }
    if query_timeout.is_zero() {
        return Err(Fault::new(Reason::StunFailed, "STUN query timeout is zero"));
    }

    let mut last: Option<Fault> = None;
    for stun_server in stun_servers {
        let attempt = rec.step_now(StepKind::Stun).via(stun_server);
        let resolved = match tokio::time::timeout(
            query_timeout,
            tokio::net::lookup_host(stun_server.as_str()),
        )
        .await
        {
            Ok(Ok(addresses)) => addresses.collect::<Vec<_>>(),
            Ok(Err(error)) => {
                let fault = Fault::new(
                    Reason::DnsFailure,
                    format!("resolve stun {stun_server}: {error}"),
                );
                attempt.fail_with(&fault);
                last = Some(fault);
                continue;
            }
            Err(_) => {
                let fault = Fault::new(
                    Reason::DnsFailure,
                    format!("resolve stun {stun_server}: timed out after {query_timeout:?}"),
                );
                attempt.fail_with(&fault);
                last = Some(fault);
                continue;
            }
        };
        let stun_addr = resolved
            .iter()
            .copied()
            .find(|address| address.is_ipv6() == prefer_ipv6)
            .or_else(|| resolved.first().copied());
        let Some(stun_addr) = stun_addr else {
            let fault = Fault::new(
                Reason::DnsNoRecords,
                format!("stun {stun_server} resolved to no address"),
            );
            attempt.fail_with(&fault);
            last = Some(fault);
            continue;
        };

        let wildcard: std::net::IpAddr = if stun_addr.is_ipv6() {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        };
        let mut bound = None;
        let mut bind_fault = None;
        for local_port in server::BASE_PORT..server::BASE_PORT + 10 {
            let local_addr = SocketAddr::new(wildcard, local_port);
            match UdpSocket::bind(local_addr).await {
                Ok(udp) => {
                    bound = Some((udp, local_port));
                    break;
                }
                Err(error) => {
                    bind_fault =
                        Some(Fault::from_io(&error).context(&format!("bind {local_addr}")));
                }
            }
        }
        let Some((udp, local_port)) = bound else {
            let fault = bind_fault.unwrap_or_else(|| {
                Fault::new(Reason::BindFailed, "no STUN socket port could be tried")
            });
            attempt.fail_with(&fault);
            last = Some(fault);
            continue;
        };
        tune_udp_buffers(&udp);
        protect_socket(protector, &udp);
        debug!("STUN {stun_server} via {stun_addr}, local :{local_port}");

        let mut client = StunClient::new(stun_addr);
        client.set_timeout(query_timeout);
        // Drop the default SOFTWARE attribute ("SimpleRustStunClient"): it
        // is a near-unique cleartext fingerprint in every binding request.
        client.set_software(None);
        match client.query_external_address_async(&udp).await {
            Ok(external_addr) => {
                attempt
                    .local(external_addr)
                    .detail(format!("selected {stun_server} ({stun_addr})"))
                    .ok();
                return Ok((udp, external_addr));
            }
            Err(error) => {
                // The STUN client folds "no reply" and "unusable reply"
                // into one error, so this cannot honestly claim the stronger
                // of the two.
                let fault = Fault::new(
                    Reason::StunTimeout,
                    format!(
                        "stun query to {stun_server} ({stun_addr}) from :{local_port}: {error}"
                    ),
                );
                attempt.fail_with(&fault);
                last = Some(fault);
            }
        }
    }
    Err(last.unwrap_or_else(|| Fault::new(Reason::StunFailed, "no STUN candidate could be tried")))
}

/// Back-compatible single-service entry point.
pub async fn pierce_keep_socket(
    stun_server: &str,
    protector: &SocketProtector,
    prefer_ipv6: bool,
) -> Result<(UdpSocket, SocketAddr), Fault> {
    pierce_keep_socket_with_fallback(
        &[stun_server.to_owned()],
        protector,
        prefer_ipv6,
        Timings::default().stun_query_timeout,
    )
    .await
}

pub async fn pierce(stun_server: &str) -> Result<(SocketAddr, SocketAddr), String> {
    let (socket, external_addr) = pierce_keep_socket(stun_server, &None, false).await?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("failed to get local addr: {}", e))?;
    Ok((local_addr, external_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e::{E2eSession, accept_one};

    async fn answer_one_stun(socket: UdpSocket) {
        let mut request = [0u8; 256];
        let (length, peer) = socket.recv_from(&mut request).await.unwrap();
        assert!(length >= 20);
        let std::net::IpAddr::V4(peer_ip) = peer.ip() else {
            panic!("test responder expected IPv4");
        };
        let mut response = Vec::with_capacity(32);
        response.extend_from_slice(&[0x01, 0x01, 0x00, 0x0c]);
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request[8..20]);
        response.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        response.extend_from_slice(&(peer.port() ^ 0x2112).to_be_bytes());
        response.extend_from_slice(
            &(u32::from(peer_ip) ^ u32::from_be_bytes([0x21, 0x12, 0xa4, 0x42])).to_be_bytes(),
        );
        socket.send_to(&response, peer).await.unwrap();
    }

    #[test]
    fn built_in_stun_order_is_provider_diverse_before_the_alternate_port() {
        assert_eq!(
            default_stun_servers(),
            [
                "stun.cloudflare.com:3478",
                "global.stun.twilio.com:3478",
                "stun.relay.metered.ca:80",
                "stun.cloudflare.com:53",
                "stun.l.google.com:19302",
            ]
        );
    }

    #[tokio::test]
    async fn stun_query_falls_back_after_a_bounded_black_hole() {
        let black_hole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let black_hole_addr = black_hole.local_addr().unwrap();
        let responder_addr = responder.local_addr().unwrap();
        let responder_task = tokio::spawn(answer_one_stun(responder));
        let servers = vec![black_hole_addr.to_string(), responder_addr.to_string()];

        let started = std::time::Instant::now();
        let (socket, external) =
            pierce_keep_socket_with_fallback(&servers, &None, false, Duration::from_millis(75))
                .await
                .unwrap();

        assert!(started.elapsed() >= Duration::from_millis(70));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(external.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(external.port(), socket.local_addr().unwrap().port());
        responder_task.await.unwrap();
    }

    #[test]
    fn punch_source_recording_is_deduped_and_bounded() {
        let mut learned = HashSet::new();
        let mut targets = HashSet::new();
        let a: SocketAddr = "1.2.3.4:5".parse().unwrap();

        // New source recorded into both sets.
        assert!(record_punch_source(&mut learned, &mut targets, a));
        assert!(learned.contains(&a) && targets.contains(&a));
        // Duplicate is not re-recorded.
        assert!(!record_punch_source(&mut learned, &mut targets, a));

        // Fill to the cap with distinct sources, then a flood source is refused.
        for i in 0..MAX_PUNCH_SOURCES as u32 {
            let s = SocketAddr::from(([10, 0, (i >> 8) as u8, i as u8], 9));
            record_punch_source(&mut learned, &mut targets, s);
        }
        assert_eq!(
            learned.len(),
            MAX_PUNCH_SOURCES,
            "learned is bounded by the cap"
        );
        let flood: SocketAddr = "9.9.9.9:9".parse().unwrap();
        assert!(!record_punch_source(&mut learned, &mut targets, flood));
        assert_eq!(learned.len(), MAX_PUNCH_SOURCES);
    }
    use crate::transport::upgradable::upgradable_transport;

    /// Regression test: a CLOSED signal channel must be terminal for
    /// `try_direct_upgrade`. The responder used to loop straight back into
    /// `try_direct_as_responder` on any error; with the peer's signal stream
    /// gone, `recv_endpoint` fails instantly and the task hot-spins forever.
    #[tokio::test]
    async fn responder_upgrade_terminates_when_signal_closes() {
        let _ = env_logger::builder().is_test(true).try_init();
        let timings = Timings::default();
        let identity = Arc::new(ShareIdentity::generate());
        let secret = identity.secret;

        // Direct A<->B QUIC session on loopback (no relay needed: we only
        // want a real SignalChannel riding a real bidi stream).
        let a_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        a_std.set_nonblocking(true).unwrap();
        let a_addr = a_std.local_addr().unwrap();
        let a_endpoint = server_endpoint(a_std, &identity, &timings).unwrap();

        let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        b_std.set_nonblocking(true).unwrap();
        let b_endpoint =
            client_endpoint(b_std, identity.cert_hash, identity.routing_hash, &timings).unwrap();

        let accept_task = tokio::spawn(async move {
            accept_one(&a_endpoint, &secret, false)
                .await
                .unwrap()
                .unwrap()
        });
        let b_session = client_connect(&b_endpoint, a_addr, &secret, false)
            .await
            .unwrap();
        let a_session = accept_task.await.unwrap();

        // Keep B's connection alive but drop ONLY its signal half, so A's
        // upgrade-sender stays open (the relay-via transport is still up)
        // while A's `recv_endpoint` hits a closed stream.
        let E2eSession {
            conn: _b_conn,
            transport: _b_transport,
            signal: b_signal,
        } = b_session;
        drop(b_signal);

        // A live UpgradeSender (router task running over A's transport).
        let (_upgradable, upgrade_sender, _router_handle) = upgradable_transport(
            Box::new(a_session.transport),
            Timings::default().upgrade_rescue_grace,
        );
        assert!(!upgrade_sender.is_closed());

        let cancel = CancellationToken::new();
        let upgrade_task = tokio::spawn(async move {
            let stun_servers = vec!["127.0.0.1:1".to_owned()];
            try_direct_upgrade(
                a_session.signal,
                upgrade_sender,
                &stun_servers, // never reached: recv_endpoint fails first
                DirectRole::Responder { identity },
                false,
                &None,
                cancel,
                None,
                None,
                Timings::default(),
                None,
                None,
                SessionMeters::new(
                    &Recorder::disabled(),
                    Carrier::Quic,
                    PathKind::Relay,
                    None,
                    1200,
                ),
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(5), upgrade_task)
            .await
            .expect("responder upgrade task must terminate once the signal channel is closed")
            .unwrap();
    }

    /// The share run's recorder is handed back, so a platform can report
    /// network changes into a live share; stopping the share still closes it.
    #[tokio::test]
    async fn share_hands_back_its_record() {
        use crate::record::{NetworkKind, NetworkState, RecordConfig};

        // A relay that never answers: REGISTER is fire-and-forget.
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let wifi = NetworkState {
            kind: NetworkKind::Wifi,
            validated: Some(true),
        };
        let config = Config {
            dns_forwarder: None,
            record: Some(RecordConfig::in_memory().with_network(wifi)),
            ..Config::default()
        };
        let device = DeviceIdentity::generate();
        let sh = Share::open(&device, vec![RelayEndpoint::new("127.0.0.1", relay_port)]).unwrap();
        let session = share(device, sh, config).await.expect("share()");
        let record = session.record.clone();
        let cellular = NetworkState {
            kind: NetworkKind::Cellular,
            validated: Some(false),
        };
        record.network(cellular);
        session.stop().await;

        let snap = record.snapshot().expect("recording was asked for");
        assert_eq!(snap.open.role, Role::Exit);
        assert_eq!(snap.open.network, Some(wifi));
        let changes: Vec<_> = snap
            .steps_of(StepKind::Network)
            .map(|s| s.network)
            .collect();
        assert_eq!(changes, vec![Some(cellular)]);
        let close = snap.close.expect("stopping the share closes its record");
        assert_eq!(
            close.reason,
            Some(Reason::LocalShutdown),
            "a stop, not a crash"
        );
    }

    /// A session's sampler ends with the session — its router stopping — not
    /// with the run: a client redials into a new session every time the
    /// tunnel drops, and each dead one must stop being sampled (and held).
    /// Its traffic still counts toward the run's closing total.
    #[tokio::test]
    async fn a_sessions_sampler_ends_with_the_session() {
        use crate::record::RecordConfig;
        use crate::transport::mock::mock_transport;

        let cfg = RecordConfig {
            sample_interval: Duration::from_millis(10),
            ..RecordConfig::in_memory()
        };
        let rec = Recorder::start(&cfg, Role::Client, None, Vec::new(), true);
        let (mock, _handle) = mock_transport();
        let (upgradable, upgrade_sender, _router) =
            upgradable_transport(Box::new(mock), Duration::ZERO);
        let meters = SessionMeters::new(
            &rec.for_cycle(0),
            Carrier::Quic,
            PathKind::Relay,
            None,
            1200,
        );
        meters.counters.tx_bytes.fetch_add(500, Ordering::Relaxed);
        meters.counters.rx_bytes.fetch_add(700, Ordering::Relaxed);
        let run = CancellationToken::new();
        spawn_sampler(meters, run.clone(), upgrade_sender.ended());
        let samples = || rec.snapshot().unwrap().samples.len();

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(samples() > 0, "a live session is sampled");
        // The session ends: its transport is dropped and the router stops.
        drop(upgradable);
        tokio::time::timeout(Duration::from_secs(2), upgrade_sender.ended().cancelled())
            .await
            .expect("the router ends with its transport");
        tokio::time::sleep(Duration::from_millis(30)).await;
        let after_end = samples();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(samples(), after_end, "sampled after its session ended");
        assert!(!run.is_cancelled());

        rec.close(Outcome::ClosedLocally, None, None);
        let close = rec.snapshot().unwrap().close.unwrap();
        assert_eq!((close.tx_bytes, close.rx_bytes), (500, 700));
    }

    #[test]
    fn upgrade_retry_waits_double_up_to_the_cap() {
        let secs = Duration::from_secs;
        let mut backoff = UpgradeBackoff::new(secs(15), secs(300));
        let waits: Vec<u64> = (0..7).map(|_| backoff.failed().as_secs()).collect();
        assert_eq!(waits, [15, 30, 60, 120, 240, 300, 300]);
        // However long the streak, the arithmetic stays at the cap.
        for _ in 0..100 {
            backoff.failed();
        }
        assert_eq!(backoff.failed(), secs(300));
        backoff.reset();
        assert_eq!(backoff.failed(), secs(15), "a reset starts the streak over");

        // A cap below the base wins.
        let mut capped = UpgradeBackoff::new(secs(15), secs(10));
        assert_eq!(capped.first_wait(), secs(10));
        assert_eq!(capped.failed(), secs(10));
        assert_eq!(capped.failed(), secs(10));
    }

    /// A live session's upgrade channel, for driving `wait_before_retry`: the
    /// session lives while both the transport and the mock's far end do.
    fn live_upgrade_channel() -> (
        crate::transport::upgradable::UpgradableTransport,
        crate::transport::mock::MockTransportHandle,
        UpgradeSender,
    ) {
        let (mock, handle) = crate::transport::mock::mock_transport();
        let (upgradable, sender, _router) = upgradable_transport(Box::new(mock), Duration::ZERO);
        (upgradable, handle, sender)
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_wait_without_a_wake_runs_its_course() {
        let (_upgradable, _far_end, sender) = live_upgrade_channel();
        let knob = AtomicU64::new(10);
        let mut backoff = UpgradeBackoff::new(Duration::from_secs(15), Duration::from_secs(300));
        backoff.failed();
        let wait = backoff.failed(); // 30s
        let t0 = tokio::time::Instant::now();
        let end = wait_before_retry(
            wait,
            false,
            &mut backoff,
            Some(&knob),
            &CancellationToken::new(),
            &sender,
        )
        .await;
        assert_eq!(end, RetryWaitEnd::Elapsed { woke: false });
        assert_eq!(t0.elapsed(), Duration::from_secs(30));
        assert_eq!(
            backoff.failed(),
            Duration::from_secs(60),
            "the streak goes on"
        );
    }

    /// Screen off and on again during a long wait: the wait shrinks to the
    /// streak's first one (counted from its start) and the streak restarts.
    #[tokio::test(start_paused = true)]
    async fn a_wake_during_the_retry_wait_restarts_the_backoff() {
        let (_upgradable, _far_end, sender) = live_upgrade_channel();
        let knob = Arc::new(AtomicU64::new(10));
        let mut backoff = UpgradeBackoff::new(Duration::from_secs(15), Duration::from_secs(300));
        for _ in 0..4 {
            backoff.failed();
        }
        let wait = backoff.failed(); // 240s
        let flipper = knob.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(7)).await;
            flipper.store(0, Ordering::Relaxed); // dormant
            tokio::time::sleep(Duration::from_secs(5)).await;
            flipper.store(10, Ordering::Relaxed); // awake, at 12s
        });
        let t0 = tokio::time::Instant::now();
        let end = wait_before_retry(
            wait,
            false,
            &mut backoff,
            Some(&knob),
            &CancellationToken::new(),
            &sender,
        )
        .await;
        assert_eq!(end, RetryWaitEnd::Elapsed { woke: true });
        // The knob is read every 5s: dormant seen at 10s, the wake at 15s,
        // which is already the reset streak's first wait.
        assert_eq!(t0.elapsed(), Duration::from_secs(15));
        assert_eq!(backoff.failed(), Duration::from_secs(15));
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_wait_ends_with_its_session() {
        let (upgradable, _far_end, sender) = live_upgrade_channel();
        let mut backoff = UpgradeBackoff::new(Duration::from_secs(15), Duration::from_secs(300));
        let wait = backoff.failed();
        drop(upgradable); // the session's transport is gone: its router stops
        let t0 = tokio::time::Instant::now();
        let end = wait_before_retry(
            wait,
            false,
            &mut backoff,
            None,
            &CancellationToken::new(),
            &sender,
        )
        .await;
        assert_eq!(end, RetryWaitEnd::Stop);
        assert!(t0.elapsed() < wait, "lingered {:?}", t0.elapsed());
    }

    /// Decision 11's wake, seen where it is easiest to miss: the screen goes
    /// off, the next attempt begins dormant, and the application wakes while
    /// that attempt runs. The wait after it is the streak's first, not the
    /// doubled one the streak had reached.
    #[test]
    fn a_wake_during_a_dormant_attempt_restarts_the_streak() {
        let secs = Duration::from_secs;
        let mut pacing = UpgradePacing::new(secs(15), secs(300));
        for want in [15, 30, 60] {
            assert!(!pacing.before_attempt(10));
            assert_eq!(pacing.after_failure(Some(10)), secs(want));
        }
        assert!(!pacing.before_attempt(0), "the attempt begins dormant");
        assert_eq!(
            pacing.after_failure(Some(10)),
            secs(15),
            "woken during the attempt: the streak starts over"
        );
        assert!(!pacing.before_attempt(10));
        assert_eq!(pacing.after_failure(Some(10)), secs(30), "and goes on");
    }

    /// Attempts made while dormant carry the streak on, and after three of
    /// them the initiator parks; the wake that ends the park starts it over.
    #[test]
    fn dormant_attempts_carry_the_streak_and_run_out() {
        let secs = Duration::from_secs;
        let mut pacing = UpgradePacing::new(secs(15), secs(300));
        assert!(!pacing.before_attempt(10));
        assert_eq!(pacing.after_failure(Some(10)), secs(15));
        for want in [30, 60, 120] {
            assert!(!pacing.before_attempt(0));
            assert_eq!(pacing.after_failure(Some(0)), secs(want));
        }
        assert!(pacing.before_attempt(0), "out of dormant attempts: park");
        pacing.woke(); // the park sees the knob above 0
        assert!(!pacing.before_attempt(10));
        assert_eq!(pacing.after_failure(Some(10)), secs(15));
    }

    /// No knob, no dormancy: nothing ever restarts the streak.
    #[test]
    fn without_a_knob_the_streak_only_grows() {
        let mut pacing = UpgradePacing::new(Duration::from_secs(15), Duration::from_secs(300));
        let waits: Vec<u64> = (0..4)
            .map(|_| pacing.after_failure(None).as_secs())
            .collect();
        assert_eq!(waits, [15, 30, 60, 120]);
    }
}
