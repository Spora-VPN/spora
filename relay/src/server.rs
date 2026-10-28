//! Running a relay: what the `relay` binary does once it has parsed its
//! flags, shared with any binary that links this crate and supplies its own
//! [`Authorizer`](crate::authz::Authorizer).

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use log::info;
use tokio::net::UdpSocket;

use crate::authz::Authorizer;
use crate::sessionlog::{SessionLog, SessionLogConfig};
use crate::{State, serve};

/// Called once both listeners are bound, with the UDP and (if any) TCP
/// address: the moment the relay serves.
pub type OnReady = Box<dyn FnOnce(SocketAddr, Option<SocketAddr>) + Send>;

/// Where and how to serve.
pub struct ServeOptions {
    /// The UDP socket's address (QUIC and nz). A `::` wildcard is made
    /// dual-stack.
    pub bind: SocketAddr,
    /// Also serve the TCP/TLS carrier on this port, on `bind`'s address.
    pub tcp_port: Option<u16>,
    /// The session log, or `None` to run without one.
    pub session_log: Option<SessionLogConfig>,
    /// Print a `relay_ready` JSON line on stdout once both listeners are up.
    pub json: bool,
    /// Told when both listeners are up (e.g. to write a health mark).
    pub on_ready: Option<OnReady>,
}

/// Open the session log, bind the listeners and serve forever. Fails (before
/// anything is bound) when the session log cannot be written: a log asked for
/// must never become a silent gap.
pub async fn run(opts: ServeOptions, authorizer: Arc<dyn Authorizer>) -> Result<(), String> {
    info!("authorization: {}", authorizer.describe());
    let mut state = State::default().with_authorizer(authorizer.clone());
    match opts.session_log {
        Some(cfg) => {
            let path = cfg.path.clone();
            let days = cfg.retention.as_secs() / 86_400;
            let log = SessionLog::open(cfg).map_err(|e| {
                format!(
                    "{e}\nthe session log path is not writable. Under systemd, set \
                     `StateDirectory=spora-relay` in the unit (the relay then writes to \
                     $STATE_DIRECTORY automatically), or pass --session-log <writable path>, \
                     or --no-session-log to run without it."
                )
            })?;
            info!("session log at {} (retention {days} days)", path.display());
            state = state.with_session_log(log);
        }
        None => info!("session log DISABLED (--no-session-log)"),
    }

    let tcp_bound = match opts.tcp_port {
        Some(tcp_port) => {
            let tcp_bind = SocketAddr::new(opts.bind.ip(), tcp_port);
            let listener = tokio::net::TcpListener::bind(tcp_bind)
                .await
                .map_err(|e| format!("bind TCP {tcp_bind} failed: {e}"))?;
            let bound = listener
                .local_addr()
                .map_err(|e| format!("read bound TCP address failed: {e}"))?;
            info!("tcp-relay listening on TCP {bound}");
            tokio::spawn(crate::tcp::serve_tcp(
                listener,
                crate::tcp::TcpRelayState::with_authorizer(authorizer),
            ));
            Some(bound)
        }
        None => None,
    };

    let socket = bind_udp(opts.bind).map_err(|e| format!("bind {} failed: {e}", opts.bind))?;
    let bound = socket
        .local_addr()
        .map_err(|e| format!("read bound UDP address failed: {e}"))?;
    info!("dumb-relay listening on UDP {}", bound);
    if opts.json {
        println!(
            "{}",
            serde_json::json!({"event":"relay_ready","udp":bound,"tcp":tcp_bound})
        );
        let _ = std::io::stdout().flush();
    }
    if let Some(ready) = opts.on_ready {
        ready(bound, tcp_bound);
    }
    serve(socket, state).await;
    Ok(())
}

/// Where the session log lives when no path is given. Prefers systemd's
/// `$STATE_DIRECTORY` (an absolute, service-owned, writable path that systemd
/// creates from `StateDirectory=`), so the on-by-default log works under a
/// hardened unit without a writable working directory. Falls back to a
/// cwd-relative file for non-systemd / development runs.
pub fn default_session_log_path() -> PathBuf {
    if let Some(state) = std::env::var_os("STATE_DIRECTORY") {
        // systemd may list several dirs colon-separated; use the first.
        let lossy = state.to_string_lossy();
        if let Some(first) = lossy.split(':').find(|s| !s.is_empty()) {
            return PathBuf::from(first).join("relay-sessions.sqlite");
        }
    }
    PathBuf::from("relay-sessions.sqlite")
}

/// Bind the relay socket. A `::` wildcard is made explicitly dual-stack
/// (IPV6_V6ONLY off) rather than trusting the OS default, so v4 peers reach
/// the same socket as v4-mapped addresses and one flow table serves both
/// families — mixed-family flows (v4 sharer, v6 client) included.
pub fn bind_udp(bind: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind),
        socket2::Type::DGRAM,
        None,
    )?;
    if bind.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    UdpSocket::from_std(socket.into())
}
