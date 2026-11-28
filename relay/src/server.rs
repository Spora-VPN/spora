//! Running a relay: what the `relay` binary does once it has parsed its
//! flags, shared with any binary that links this crate and supplies its own
//! [`Authorizer`](crate::authz::Authorizer).

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use log::{info, warn};
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

/// What [`run`] asks the kernel for as each of the UDP socket's two buffers:
/// 8 MiB. See [`Tuning::udp_buffer`].
pub const DEFAULT_UDP_BUFFER: usize = 8 << 20;

/// Settings whose defaults suit most hosts. [`run`] serves with the
/// defaults; a binary with flags for them passes its own to [`run_tuned`].
/// More may be added, so start from `Tuning::default()` and set what
/// differs.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Tuning {
    /// Bytes to ask the kernel for as the UDP socket's receive buffer and
    /// as its send buffer (`SO_RCVBUF`, `SO_SNDBUF`), unless the socket
    /// already has as much. 0 asks for nothing.
    ///
    /// Every datagram of every session comes in through that one receive
    /// buffer, and whatever arrives while it is full is dropped by the
    /// kernel. The relay empties it ahead of its sending (see
    /// [`serve`](crate::serve)), which holds a burst while the relay runs;
    /// the buffer has to hold what comes while it does not. A system's
    /// default (208 KiB on Linux) is about a hundred full-size datagrams.
    /// The kernel grants no more than the host's limit (Linux:
    /// `net.core.rmem_max`, `net.core.wmem_max`), so the host has to allow
    /// what is asked here; `run` logs what the socket got and warns when
    /// that is less.
    pub udp_buffer: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            udp_buffer: DEFAULT_UDP_BUFFER,
        }
    }
}

/// [`run_tuned`] with the default [`Tuning`].
pub async fn run(opts: ServeOptions, authorizer: Arc<dyn Authorizer>) -> Result<(), String> {
    run_tuned(opts, Tuning::default(), authorizer).await
}

/// Open the session log, bind the listeners and serve forever. Fails (before
/// anything is bound) when the session log cannot be written: a log asked for
/// must never become a silent gap.
pub async fn run_tuned(
    opts: ServeOptions,
    tuning: Tuning,
    authorizer: Arc<dyn Authorizer>,
) -> Result<(), String> {
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
    report_udp_buffers(&socket, tuning.udp_buffer);
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
    // As a task of its own, not on the thread that called `run`: on a
    // multi-threaded runtime that thread never watches the sockets itself,
    // so every wait there would end with a worker waking it, a second
    // thread switch for each datagram that finds the relay idle.
    let mut forwarding = AbortOnDrop(tokio::spawn(serve(socket, state)));
    (&mut forwarding.0)
        .await
        .map_err(|e| format!("the relay's forwarding task ended: {e}"))
}

/// Stops the task when dropped, so that a caller that drops `run`'s future
/// stops the forwarding with it, as when the loop ran inside that future.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
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

/// A UDP socket's buffer sizes in bytes, as its system reports them. Linux
/// reports twice the size it was asked for and granted: it counts its own
/// bookkeeping for each datagram against the buffer and doubles the figure
/// to allow for it (see [`reported_for`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpBuffers {
    pub recv: usize,
    pub send: usize,
}

/// Ask the kernel for `want` bytes as each of the socket's buffers, and
/// return what the socket has afterwards. A buffer already as large as that
/// request would make it is left alone (a host set up with larger defaults
/// keeps them), and `want` 0 changes nothing. Never an error for asking too
/// much: Linux grants up to its limit silently, and where a system refuses
/// a size over its limit instead, the request is halved until one is taken.
pub fn grow_udp_buffers(socket: &UdpSocket, want: usize) -> std::io::Result<UdpBuffers> {
    let socket = socket2::SockRef::from(socket);
    Ok(UdpBuffers {
        recv: grow(
            want,
            || socket.recv_buffer_size(),
            |n| socket.set_recv_buffer_size(n),
        )?,
        send: grow(
            want,
            || socket.send_buffer_size(),
            |n| socket.set_send_buffer_size(n),
        )?,
    })
}

fn grow(
    want: usize,
    get: impl Fn() -> std::io::Result<usize>,
    set: impl Fn(usize) -> std::io::Result<()>,
) -> std::io::Result<usize> {
    let had = get()?;
    let mut ask = want;
    while reported_for(ask) > had && set(ask).is_err() {
        ask /= 2;
    }
    get()
}

/// What a system reports for a buffer it was asked to make `want` bytes and
/// granted in full: on Linux twice that, elsewhere the size itself.
fn reported_for(want: usize) -> usize {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        want.saturating_mul(2)
    } else {
        want
    }
}

/// Whether a buffer the system reports as `reported` bytes is smaller than
/// asking for `want` bytes would have made it, had the host allowed it.
fn short_of(want: usize, reported: usize) -> bool {
    reported < reported_for(want)
}

/// Grow the relay socket's buffers to `want` and log what the kernel gave:
/// an operator has to be able to see that the host's limit cut the request.
fn report_udp_buffers(socket: &UdpSocket, want: usize) {
    let got = match grow_udp_buffers(socket, want) {
        Ok(got) => got,
        Err(e) => {
            warn!("could not read or set the UDP socket's buffer sizes: {e}");
            return;
        }
    };
    info!(
        "UDP socket buffers: receive {} bytes, send {} bytes, as the system reports them \
         (asked for {want} each)",
        got.recv, got.send
    );
    if short_of(want, got.recv) || short_of(want, got.send) {
        warn!(
            "the system granted less than the {want} bytes asked for as the UDP socket's \
             buffers (it reports receive {}, send {}). The relay serves; what arrives \
             while it is kept from running has that much room and no more. To allow the \
             full size, raise the host's limit (Linux: sysctl net.core.rmem_max={want} \
             net.core.wmem_max={want}, or more) and restart the relay",
            got.recv, got.send
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bound socket; needs a runtime around it.
    fn socket() -> UdpSocket {
        bind_udp("127.0.0.1:0".parse().unwrap()).unwrap()
    }

    fn sizes(socket: &UdpSocket) -> UdpBuffers {
        let socket = socket2::SockRef::from(socket);
        UdpBuffers {
            recv: socket.recv_buffer_size().unwrap(),
            send: socket.send_buffer_size().unwrap(),
        }
    }

    #[tokio::test]
    async fn asking_for_nothing_or_for_less_than_the_socket_has_changes_nothing() {
        let socket = socket();
        let had = sizes(&socket);
        assert_eq!(grow_udp_buffers(&socket, 0).unwrap(), had);
        assert_eq!(grow_udp_buffers(&socket, 1024).unwrap(), had);
        assert_eq!(sizes(&socket), had);
        // And neither is short of what was asked.
        assert!(!short_of(0, had.recv) && !short_of(1024, had.recv));
    }

    #[tokio::test]
    async fn asking_for_more_never_leaves_the_socket_with_less() {
        let socket = socket();
        let had = sizes(&socket);
        // More than any host's limit is likely to allow: the request must
        // come back as whatever the host gives, not as an error.
        let got = grow_udp_buffers(&socket, 1 << 30).unwrap();
        assert!(
            got.recv >= had.recv && got.send >= had.send,
            "{had:?} -> {got:?}"
        );
        assert_eq!(sizes(&socket), got);
    }

    /// Linux's rule, held to the host's own limits: a request is cut to
    /// `rmem_max` / `wmem_max` and reported doubled.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_grants_up_to_the_hosts_limit() {
        let limit = |name: &str| -> Option<usize> {
            std::fs::read_to_string(format!("/proc/sys/net/core/{name}"))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        let (Some(rmem_max), Some(wmem_max)) = (limit("rmem_max"), limit("wmem_max")) else {
            return; // not readable here (an older kernel inside a namespace)
        };
        let socket = socket();
        let had = sizes(&socket);
        let want = 4 << 20;
        let got = grow_udp_buffers(&socket, want).unwrap();
        // A host whose defaults are already that large is left as it was.
        if had.recv < 2 * want {
            assert_eq!(got.recv, 2 * want.min(rmem_max));
            assert_eq!(short_of(want, got.recv), rmem_max < want);
        }
        if had.send < 2 * want {
            assert_eq!(got.send, 2 * want.min(wmem_max));
            assert_eq!(short_of(want, got.send), wmem_max < want);
        }
    }

    /// `run` hands the forwarding to a task of its own; that task must not
    /// outlive a caller that gives `run` up.
    #[tokio::test]
    async fn dropping_run_stops_the_forwarding_and_frees_the_port() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let opts = ServeOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            tcp_port: None,
            session_log: None,
            json: false,
            on_ready: Some(Box::new(move |udp, _| {
                let _ = tx.send(udp);
            })),
        };
        let relay = tokio::spawn(run(opts, Arc::new(crate::authz::Open)));
        let addr = rx.await.expect("the relay never became ready");
        tokio::task::yield_now().await;
        assert!(
            std::net::UdpSocket::bind(addr).is_err(),
            "the relay holds its port while it serves"
        );

        relay.abort();
        let freed = async {
            while std::net::UdpSocket::bind(addr).is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), freed)
            .await
            .expect("the forwarding task kept the socket after `run` was dropped");
    }

    #[test]
    fn a_refused_size_is_halved_until_one_is_taken() {
        use std::cell::Cell;
        let size = Cell::new(100usize);
        let asked = Cell::new(0u32);
        // A system that refuses anything over 1000, as the BSDs refuse a
        // size over their limit.
        let got = grow(
            4096,
            || Ok(size.get()),
            |n| {
                asked.set(asked.get() + 1);
                if n > 1000 {
                    return Err(std::io::ErrorKind::InvalidInput.into());
                }
                size.set(n);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((got, asked.get()), (512, 4)); // 4096, 2048, 1024 refused
        // And one that refuses everything keeps what it had.
        let got = grow(4096, || Ok(100), |_| Err(std::io::ErrorKind::Other.into())).unwrap();
        assert_eq!(got, 100);
    }
}
