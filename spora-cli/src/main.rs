use clap::{Parser, Subcommand};
#[cfg(target_os = "linux")]
use spora_core::ExitMode;
use spora_core::identity::{DeviceIdentity, RelayEntry, RoutingHash, Share, hex};
use spora_core::record::Record;
use spora_core::{Config, connect};
use std::path::PathBuf;
use url::Url;

/// The generated command reference (docs-site) and its freshness test.
#[cfg(test)]
mod docs;
/// Share-side netstack bypass (`spora share --os-routing`): Linux only (it
/// drives iptables and kernel forwarding).
#[cfg(target_os = "linux")]
mod os_route;
/// Client-side tunnel integration for `spora use` (interface, routes, MTU,
/// resolver) on Linux, macOS and Windows.
use spora_vpn as vpn;

/// Active keepalive/liveness probe interval (seconds) for the always-on CLI
/// client. Non-zero opts out of spora-core's dormant ("screen off") mode.
const KEEPALIVE_PROBE_SECS: u64 = 10;

/// `println!` for what `share` and `use` print for a human: a terminal or
/// pipe that has gone away (`spora share | head -2`) is no reason for a
/// share or a VPN client to die, so a failed write is ignored rather than
/// panicking as `println!` does.
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), $($arg)*);
    }};
}

/// Use jemalloc on non-Windows glibc targets. The default glibc allocator
/// holds onto pages under heavy alloc/free churn (every IP packet on the
/// share side allocates a `Vec<u8>`); jemalloc returns memory to the OS far
/// more aggressively. Excluded on musl (the static release builds):
/// jemalloc-sys does not build for aarch64-musl, and musl's own allocator
/// does not have glibc's page-retention behavior.
#[cfg(all(not(windows), not(target_env = "musl")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(name = "spora")]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug, Clone)]
enum Mode {
    /// Share over a tunnel. Serves the share kept at
    /// $XDG_CONFIG_HOME/spora/share.bin (made on the first run), so the share
    /// URL stays the same across invocations. The relays are part of the
    /// share (and of its URL): relay flags that differ from the stored
    /// share's make a new share, with a new URL. Without relay flags a new
    /// share uses Spora's relays, which this machine gets from Spora's API
    /// (registering it there) along with the token they want.
    Share {
        /// Override the share file path.
        #[arg(long, alias = "identity-file")]
        share_file: Option<PathBuf>,
        /// Make a new share (a new URL) and overwrite the stored one.
        #[arg(long)]
        fresh: bool,
        /// Bypass the userland netstack: write client packets to a TUN device
        /// and let the kernel route/NAT them. Requires root (or
        /// CAP_NET_ADMIN). Linux only.
        #[arg(long)]
        os_routing: bool,
        /// TUN interface address in CIDR form (with --os-routing).
        #[arg(long, default_value = "10.213.0.1/24", requires = "os_routing")]
        tun_addr: String,
        /// TUN interface IPv6 address in CIDR form (with --os-routing). Must
        /// be a ULA (fc00::/7): clients may only source inner v6 traffic from
        /// ULA space, so a global address here would shadow a real prefix
        /// without ever being reachable.
        #[arg(long, default_value = "fd00:5350::1/64", requires = "os_routing")]
        tun_addr6: String,
        /// TUN MTU (with --os-routing).
        #[arg(long, default_value_t = 1280, requires = "os_routing")]
        tun_mtu: u16,
        /// With --os-routing: don't touch ip_forward or iptables. You are
        /// responsible for forwarding + NAT; per-client return routes on the
        /// TUN are still installed.
        #[arg(long, requires = "os_routing")]
        no_nat: bool,
        /// Override the relay address(es) (host:port) used for registration
        /// and baked into the share URL. Repeat the flag for multiple relays
        /// (the sharer registers with all; the client tries them IPv6-first
        /// then in order). A hostname with both A and AAAA records counts as
        /// two relays.
        #[arg(long)]
        relay: Vec<String>,
        /// Advertise a relay-less DIRECT endpoint (host:port) clients can dial
        /// straight to this sharer: no relay, no relay bandwidth. The sharer
        /// binds this port, so it must be publicly reachable. Repeat for
        /// several advertised addresses (they must share one port). Combine
        /// with --relay for a mix, or use alone for pure relay-less sharing.
        #[arg(long)]
        direct: Vec<String>,
        /// Advertise a TCP/TLS relay endpoint (host:port): a TCP relay carrying
        /// end-to-end TLS, for networks that block UDP/QUIC. The sharer connects
        /// out and parks connections at it. Repeat for several; combine with
        /// --relay to offer both (the client tries them in preference order).
        #[arg(long)]
        tcp_relay: Vec<String>,
        /// Advertise a Noise UDP (`nz`) relay endpoint (host:port): the dumb UDP
        /// relay carrying an end-to-end Noise datagram session, a high-entropy,
        /// non-QUIC-shaped transport for networks that fingerprint or throttle
        /// QUIC. Point it at a relay on a non-443 UDP port. Repeat for several;
        /// combine with --relay to offer both (the client tries them in order).
        #[arg(long)]
        nz_relay: Vec<String>,
        /// Override the ordered STUN servers (host:port) used for
        /// direct-upgrade endpoint discovery. Repeat for fallbacks.
        #[arg(long)]
        stun: Vec<String>,
        /// Keep the session on its initial relay/carrier path instead of
        /// attempting a direct upgrade.
        #[arg(long)]
        no_direct_upgrade: bool,
        /// Token for the relays given with --relay, --tcp-relay and
        /// --nz-relay, when they want one (a self-hosted relay run with
        /// --token or --token-file). The token itself or a path to a file
        /// containing it; surrounding whitespace is trimmed. Kept in the
        /// share, never in its URL.
        #[arg(long)]
        relay_token: Option<String>,
        /// Disable the connection log. By default the sharer keeps a local
        /// per-flow record (who connected to which destination, when) at
        /// $XDG_STATE_HOME/spora/connlog/<routing-key>/ (in root's home for a
        /// run with sudo), the sharer's own egress accountability record for
        /// answering abuse reports.
        #[arg(long)]
        no_conn_log: bool,
        /// Answer clients' DNS queries from these servers (ip or ip:port,
        /// repeatable, in preference order) instead of this host's own
        /// resolvers. Used exclusively: no public fallback.
        #[arg(long, conflicts_with = "no_dns_forwarder")]
        dns_upstream: Vec<String>,
        /// Don't answer clients' DNS queries at all: queries to the tunnel's
        /// resolver address (100.64.0.53) are dropped like any other private
        /// destination, so clients must bring public resolvers of their own.
        #[arg(long)]
        no_dns_forwarder: bool,
        /// Override the connection-log directory.
        #[arg(long, conflicts_with = "no_conn_log")]
        conn_log_dir: Option<PathBuf>,
        /// Connection-log retention in days; older records are deleted
        /// (unless pinned by `spora log hold`).
        #[arg(long, default_value_t = 90, conflicts_with = "no_conn_log")]
        conn_log_retention_days: u32,
        /// Log sessions only (who was connected and when), without per-flow
        /// destination records.
        #[arg(long, conflicts_with = "no_conn_log")]
        conn_log_sessions_only: bool,
        /// Don't keep a diagnostic record of how each connection went.
        #[arg(long)]
        no_record: bool,
        /// Override the diagnostic-record directory (default:
        /// $XDG_STATE_HOME/spora/records/, in root's home for a run with
        /// sudo). Uploads only take the default directory; `spora report
        /// --record-dir` bundles another.
        #[arg(long, conflicts_with = "no_record")]
        record_dir: Option<PathBuf>,
        /// Label this machine in every record it writes.
        #[arg(long, conflicts_with = "no_record")]
        record_label: Option<String>,
        /// Tie the records from this run to something outside it: a ticket,
        /// a test run.
        #[arg(long, conflicts_with = "no_record")]
        record_id: Option<String>,
        /// Don't write the diagnostic log to disk. By default it is also kept
        /// at $XDG_STATE_HOME/spora/log/ (in root's home for a run with sudo;
        /// at most 16 MiB and 14 days, with any crash reports), so `spora
        /// report` can bundle it.
        #[arg(long)]
        no_diag_log: bool,
        /// Emit newline-delimited JSON lifecycle events on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Connect through a share URL. By default this is a full VPN client:
    /// it brings up the tunnel interface, routes traffic through it, sets
    /// the resolver, follows the path's MTU, and restores everything on
    /// exit. Needs root (Administrator on Windows), except with --tun-name.
    Use {
        /// The share URL (https://spora.to/s/...) received from the sharer.
        url: String,
        /// Override the ordered STUN servers (host:port) used for
        /// direct-upgrade endpoint discovery. Repeat for fallbacks.
        #[arg(long)]
        stun: Vec<String>,
        /// Keep the session on its initial relay/carrier path instead of
        /// attempting a direct upgrade.
        #[arg(long)]
        no_direct_upgrade: bool,
        /// Attach to this pre-created TUN instead of bringing up the tunnel
        /// interface yourself. The caller owns its address, MTU, routes and
        /// cleanup; nothing else on the host is touched (Linux only).
        #[arg(long)]
        tun_name: Option<String>,
        /// Address of the tunnel interface, in CIDR form. Must be private
        /// (RFC1918/CGNAT): sharers refuse other client sources.
        #[arg(long, default_value = vpn::DEFAULT_TUN_ADDR, conflicts_with = "tun_name")]
        tun_addr: String,
        /// IPv6 address of the tunnel interface, in CIDR form (must be a
        /// ULA, fc00::/7).
        #[arg(long, default_value = vpn::DEFAULT_TUN_ADDR6, conflicts_with = "tun_name")]
        tun_addr6: String,
        /// Carry no IPv6 in the tunnel: no v6 address, no v6 routes. On a
        /// v6-capable host, v6 traffic then bypasses the tunnel.
        #[arg(long, conflicts_with = "tun_name")]
        no_ipv6: bool,
        /// Route only this prefix into the tunnel (repeatable) instead of
        /// everything. The host's more specific routes (its LANs) still win.
        #[arg(long, conflicts_with = "tun_name")]
        route: Vec<String>,
        /// Bring the interface up with its address and MTU but install no
        /// routes and leave the resolver alone: you route into it yourself.
        #[arg(long, conflicts_with_all = ["tun_name", "route"])]
        no_routes: bool,
        /// Resolver to use while connected (repeatable). The default,
        /// 100.64.0.53, is the sharer's DNS forwarder, which answers from the
        /// sharer's own resolvers. Anything else is reached through the
        /// tunnel, so it must be public.
        #[arg(long, conflicts_with_all = ["tun_name", "no_routes"])]
        dns: Vec<String>,
        /// Leave the host's resolver configuration alone.
        #[arg(long, conflicts_with_all = ["tun_name", "dns"])]
        no_dns: bool,
        /// Pin the interface MTU (576..=1500) instead of following the
        /// path's discovered budget.
        #[arg(long, conflicts_with = "tun_name")]
        mtu: Option<u16>,
        /// Don't keep a diagnostic record of how the connection went.
        #[arg(long)]
        no_record: bool,
        /// Override the diagnostic-record directory (default:
        /// $XDG_STATE_HOME/spora/records/, in root's home for a run with
        /// sudo). Uploads only take the default directory; `spora report
        /// --record-dir` bundles another.
        #[arg(long, conflicts_with = "no_record")]
        record_dir: Option<PathBuf>,
        /// Label this machine in every record it writes.
        #[arg(long, conflicts_with = "no_record")]
        record_label: Option<String>,
        /// Tie this run's record to something outside it: a ticket, a test
        /// run.
        #[arg(long, conflicts_with = "no_record")]
        record_id: Option<String>,
        /// Don't write the diagnostic log to disk. By default it is also kept
        /// at $XDG_STATE_HOME/spora/log/ (in root's home for a run with sudo;
        /// at most 16 MiB and 14 days, with any crash reports), so `spora
        /// report` can bundle it.
        #[arg(long)]
        no_diag_log: bool,
        /// Emit newline-delimited JSON lifecycle events on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Print the source/build identity embedded in this executable.
    BuildInfo {
        /// Emit the complete build identity as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect the share's connection log: which client reached which
    /// destination, and when. It stays on this machine.
    Log {
        #[command(subcommand)]
        cmd: LogCmd,
    },
    /// Read the diagnostic records of past connections: what was attempted,
    /// what failed, and why.
    Record {
        #[command(subcommand)]
        cmd: RecordCmd,
    },
    /// Bundle the recent diagnostic records, diagnostic log and crash
    /// reports of this machine into one zip file to send with a bug report.
    /// Works offline and whether or not telemetry is on; manifest.json
    /// inside lists everything included and everything left out. The files
    /// of runs made with sudo (such as `sudo spora use`) belong to root:
    /// bundle those with `sudo spora report`.
    Report {
        /// Where to write the zip (default: spora-report-<time>.zip in the
        /// current directory).
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// A few words for whoever reads the report: what you were doing,
        /// what went wrong.
        #[arg(long)]
        note: Option<String>,
        /// How far back to look, in hours.
        #[arg(long, default_value_t = 72, value_parser = clap::value_parser!(u64).range(1..=8760))]
        hours: u64,
        /// Also bundle the records in this directory: one a run's
        /// --record-dir pointed at. The default directory is always
        /// included.
        #[arg(long)]
        record_dir: Vec<PathBuf>,
    },
    /// Telemetry: whether this machine sends its diagnostic records,
    /// diagnostic log and crash reports to Spora. They show where and how
    /// networks block Spora, and help fix problems. They include network
    /// addresses: the public address your network shows, the addresses of
    /// the peers, relays and other servers this machine connects with, and
    /// the address each upload comes from. Off unless you turn it on. Either
    /// way everything is still kept on this machine, for `spora report`. For
    /// runs made with sudo (such as `sudo spora use`), use `sudo spora
    /// telemetry`.
    Telemetry {
        #[command(subcommand)]
        cmd: TelemetryCmd,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum TelemetryCmd {
    /// Whether uploads are on, whether your account requires them, this
    /// machine's device id, and how the last upload went.
    Status {
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Turn uploads on. `spora share` and `spora use` send what is pending
    /// in the background (running ones within 15 minutes) and once more as
    /// they stop.
    On,
    /// Turn uploads off: nothing more is uploaded. A machine registered
    /// earlier still asks the API once a day whether its account requires
    /// telemetry. Refused while your account requires telemetry.
    Off,
    /// With uploads on, send everything not sent yet, now, and say what
    /// went. Registers this machine with the API first if it has not been.
    /// Without --api or $SPORA_API that is Spora's built-in API, and its
    /// registration keeps working at whatever addresses later versions
    /// give that API. --api and $SPORA_API name another API, even at the
    /// built-in address: this machine registers anew there, the token it
    /// gets goes only to the addresses that issued it, and the other
    /// registration is kept for when its API is used again.
    Upload {
        /// API base URL (repeat for fallbacks, tried in order). Overrides
        /// $SPORA_API (a comma-separated list) and the built-in API.
        #[arg(long)]
        api: Vec<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum RecordCmd {
    /// One line per record: when, which end, how it ended, and the first
    /// thing that failed.
    List {
        /// Record directory (default: $XDG_STATE_HOME/spora/records/, in
        /// root's home for a run with sudo).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// How many records to list, newest first.
        #[arg(long, short = 'n', default_value_t = 20)]
        count: usize,
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// The full story of one record: every step, in order, with its verdict.
    Show {
        /// Record id (or its first characters). Defaults to the newest.
        id: Option<String>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Machine-readable JSON output: the whole record, folded.
        #[arg(long)]
        json: bool,
        /// Include the quality samples taken while the tunnel was up.
        #[arg(long)]
        samples: bool,
    },
    /// Write records out as JSON, for handing to someone else.
    Export {
        #[arg(long)]
        dir: Option<PathBuf>,
        /// How many records to export, newest first.
        #[arg(long, short = 'n', default_value_t = 20)]
        count: usize,
        /// Write to this file instead of standard output.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum LogCmd {
    /// Query flows: "who connected to destination IP X during [from, to]".
    /// Prints matching flows, the sessions they belong to (with everything
    /// known about the client's outer address), and any log gaps or clock
    /// jumps overlapping the window.
    Query {
        /// Destination IP to match.
        #[arg(long)]
        ip: Option<std::net::IpAddr>,
        /// Destination port to match.
        #[arg(long)]
        port: Option<u16>,
        /// Window start: RFC3339 (2026-06-12T10:00:00Z), a date
        /// (2026-06-12), or unix seconds/milliseconds.
        #[arg(long)]
        from: Option<String>,
        /// Window end (same formats as --from).
        #[arg(long)]
        to: Option<String>,
        /// Machine-readable JSON output (for export/handover).
        #[arg(long)]
        json: bool,
        /// Log directory (default: derived from the share file;
        /// overrides --share-file when both are given).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Share file used to locate the default log directory.
        #[arg(long, alias = "identity-file")]
        share_file: Option<PathBuf>,
    },
    /// List sessions with their address records.
    Sessions {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long, alias = "identity-file")]
        share_file: Option<PathBuf>,
    },
    /// Manage legal holds: time ranges pinned against retention expiry
    /// (e.g. after receiving a preservation request).
    Hold {
        #[command(subcommand)]
        cmd: HoldCmd,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum HoldCmd {
    /// Pin [from, to] against the retention sweep.
    Add {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        /// Why this hold exists (e.g. the case/reference number).
        #[arg(long)]
        note: Option<String>,
        /// Log directory; overrides --share-file when both are given.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Share file used to locate the default log directory.
        #[arg(long, alias = "identity-file")]
        share_file: Option<PathBuf>,
    },
    /// List active holds.
    List {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long, alias = "identity-file")]
        share_file: Option<PathBuf>,
    },
    /// Remove a hold by id (records it pinned become subject to retention
    /// again on the next sweep).
    Remove {
        id: i64,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long, alias = "identity-file")]
        share_file: Option<PathBuf>,
    },
}

/// The share's DNS forwarder from `--dns-upstream` / `--no-dns-forwarder`
/// (see spora-core's `dns`): this host's system resolvers with a public
/// fallback by default; an explicit list is used exclusively; `None` when
/// disabled.
fn dns_forwarder_config(
    upstreams: &[String],
    disabled: bool,
) -> Result<Option<std::sync::Arc<spora_core::dns::DnsForwarder>>, String> {
    use spora_core::dns::{DnsForwarder, DnsUpstream};
    if disabled {
        return Ok(None);
    }
    if upstreams.is_empty() {
        return Ok(Some(DnsForwarder::system()));
    }
    let mut servers = Vec::with_capacity(upstreams.len());
    for u in upstreams {
        servers.push(parse_resolver(u).map_err(|e| format!("--dns-upstream: {e}"))?);
    }
    Ok(Some(DnsForwarder::with_fallback(
        DnsUpstream::Servers(servers),
        Vec::new(),
    )))
}

/// `ip` (port 53) or `ip:port` — literals only; a resolver is not something
/// to look up with a resolver.
fn parse_resolver(s: &str) -> Result<std::net::SocketAddr, String> {
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, 53));
    }
    s.parse::<std::net::SocketAddr>()
        .map_err(|_| format!("'{s}' is not an IP address or ip:port (a v6 literal with a port is bracketed: [::1]:53)"))
}

/// Load a relay token from `--relay-token`: either a path to a file
/// containing it, or the token itself. Surrounding whitespace is trimmed, as
/// the relay trims its own copy.
fn load_relay_token(arg: &str) -> Result<Vec<u8>, String> {
    let text = match std::fs::read_to_string(arg) {
        Ok(contents) => contents,
        Err(_) => arg.to_string(), // not a readable file: treat as a literal token
    };
    let token = text.trim();
    if token.is_empty() {
        return Err("--relay-token: the token is empty".into());
    }
    Ok(token.as_bytes().to_vec())
}

/// Split `host:port` on the LAST ':' (so bracketed IPv6 like `[::1]:443`
/// works) and validate the port.
fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    let Some(idx) = s.rfind(':') else {
        return Err(format!("'{}' is not a host:port pair (no ':' found)", s));
    };
    let (host, port_str) = (&s[..idx], &s[idx + 1..]);
    if host.is_empty() {
        return Err(format!("'{}' has an empty host part", s));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("'{}' is not a valid port in '{}'", port_str, s))?;
    Ok((host.to_string(), port))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    init_logging(&args.mode);
    let human = match &args.mode {
        Mode::Share { json, .. } | Mode::Use { json, .. } => !json,
        _ => true,
    };
    // share/use watch for stop signals from the start; one-shot commands
    // keep the default action (a Ctrl+C ends them at once).
    let shutdown = match &args.mode {
        Mode::Share { .. } | Mode::Use { .. } => Some(Shutdown::watch()?),
        _ => None,
    };
    // A one-shot command whose reader goes away (`spora telemetry status |
    // head`) ends quietly, as Unix tools do, instead of panicking on the
    // next print; share/use rather outlive a closed stdout (`say!`). std's
    // sockets never raise SIGPIPE (MSG_NOSIGNAL / SO_NOSIGPIPE), so only
    // the pipe is affected.
    #[cfg(unix)]
    if shutdown.is_none() {
        // SAFETY: setting a signal's disposition to its default is
        // async-signal-safe and touches no Rust state.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    }
    let result = run(args.mode, shutdown.as_ref()).await;
    if let Err(e) = &result {
        // For the log file: stderr gets it from the caller of `main`.
        log::error!(target: EXIT_LOG_TARGET, "exiting: {e}");
    }
    spora_service::diag::flush(std::time::Duration::from_secs(2));
    if let Some(shutdown) = &shutdown {
        final_upload(human, shutdown).await;
    }
    result
}

/// The target of `main`'s closing error line, which only the log file gets:
/// stderr has it already, from `main`'s return value.
const EXIT_LOG_TARGET: &str = "spora_cli::exit";

/// The process logger: stderr through env_logger, as `RUST_LOG` says, behind
/// spora-service's composite logger, which withholds what no sink may get
/// (raw HTTP traces carry the upload token) whatever `RUST_LOG` asks for.
/// `share` and `use` run for hours and are what a bug report is about, so
/// they also keep the diagnostic log file (its own fixed levels, crash
/// reports beside it); one-shot commands write no file per invocation.
fn init_logging(mode: &Mode) {
    use spora_service::diag::{self, DiagConfig, Secondary};
    let keep_file = match mode {
        Mode::Share { no_diag_log, .. } | Mode::Use { no_diag_log, .. } => !no_diag_log,
        _ => false,
    };
    // These print their own summary, which the service's info lines would
    // only repeat.
    let default_level = match mode {
        Mode::Report { .. } | Mode::Telemetry { .. } => "warn",
        _ => "info",
    };
    let mut stderr =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_level));
    quieten_stderr(&mut stderr);
    let stderr = stderr.build();
    let stderr_level = stderr.filter();
    let file = keep_file.then(|| DiagConfig::in_dir(default_diag_dir()).with_platform(platform()));
    diag::init(file, Some(Secondary::new(Box::new(stderr), stderr_level)));
    // share/use keep a record, whose ending must admit a panic, log file or
    // not (without one the hook writes no crash file).
    if matches!(mode, Mode::Share { .. } | Mode::Use { .. }) {
        diag::install_panic_hook();
    }
}

/// stderr's filters on top of `RUST_LOG`: chatty libraries held to warnings,
/// `main`'s closing line (printed by `main`'s caller already) and the
/// targets withheld from every sink switched off. The composite logger in
/// front withholds those whatever the filters say; this keeps them off in
/// the plain logger as well, as far as `RUST_LOG` lets it (a more specific
/// directive, such as `ureq_proto::util=trace`, outranks these).
fn quieten_stderr(b: &mut env_logger::Builder) {
    b.filter_module("quinn", log::LevelFilter::Warn)
        .filter_module("quinn_proto", log::LevelFilter::Warn)
        .filter_module("quinn_udp", log::LevelFilter::Warn)
        .filter_module("tracing", log::LevelFilter::Warn)
        .filter_module("smoltcp", log::LevelFilter::Warn)
        .filter_module(EXIT_LOG_TARGET, log::LevelFilter::Off);
    for target in spora_service::diag::WITHHELD_TARGETS {
        b.filter_module(target, log::LevelFilter::Off);
    }
}

/// How long the end of `share`/`use` waits for its last upload.
const FINAL_UPLOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The last upload pass of a `share`/`use` run, once its record has closed,
/// its log is on disk and (for `use`) the host's routes and resolver are
/// back: nothing else would send them before the next run, and a run that
/// failed to connect is exactly what telemetry is for. Only with uploads on
/// (otherwise the process just exits); at most [`FINAL_UPLOAD_WAIT`], and a
/// second Ctrl+C cuts it short — the first, after a run that ended by
/// itself. A second one pressed during teardown, before this started, counts
/// as well. An interrupted pass costs nothing: the next one resumes where
/// the server's copy ends.
async fn final_upload(human: bool, shutdown: &Shutdown) {
    let Some(t) = spora_service::Telemetry::global() else {
        return;
    };
    // The file as it is now (another shell may have switched uploads since
    // the run started), read without waiting for its lock.
    let state = spora_service::state::ServiceState::read(&t.config().state_dir);
    if !state.is_ok_and(|(s, _)| s.upload_enabled) {
        return;
    }
    if human {
        say!(
            "Sending this run's diagnostics (at most {} s; Ctrl+C skips)...",
            FINAL_UPLOAD_WAIT.as_secs()
        );
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    // A thread of its own rather than the runtime's blocking pool: dropping
    // the runtime would wait for a blocking task, Ctrl+C or not.
    let spawned = std::thread::Builder::new()
        .name("spora-final-upload".into())
        .spawn(move || {
            let _ = tx.send(spora_service::finish(FINAL_UPLOAD_WAIT));
        });
    if spawned.is_err() {
        return;
    }
    let skip_at = if shutdown.count() == 0 { 1 } else { 2 };
    tokio::select! {
        _ = rx => {}
        () = shutdown.signal(skip_at) => {}
        // finish() keeps to its deadline; this is in case a state file lock
        // it waits on does not.
        _ = tokio::time::sleep(FINAL_UPLOAD_WAIT + std::time::Duration::from_secs(2)) => {}
    }
}

/// `shutdown` is the stop-signal watcher of `share` and `use` (`None` for the
/// other commands).
async fn run(mode: Mode, shutdown: Option<&Shutdown>) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        Mode::Share {
            share_file,
            fresh,
            os_routing,
            tun_addr,
            tun_addr6,
            tun_mtu,
            no_nat,
            relay,
            direct,
            tcp_relay,
            nz_relay,
            stun,
            no_direct_upgrade,
            relay_token,
            no_conn_log,
            dns_upstream,
            no_dns_forwarder,
            conn_log_dir,
            conn_log_retention_days,
            conn_log_sessions_only,
            no_record,
            record_dir,
            record_label,
            record_id,
            no_diag_log: _,
            json,
        } => {
            let shutdown = shutdown.expect("share watches for stop signals");
            let path = share_file.unwrap_or_else(default_share_path);
            let mut config = Config::default();
            // --relay (UDP-QUIC), --direct (relay-less), --tcp-relay and
            // --nz-relay endpoints compose into one preference-ordered list,
            // which is the share's own; without any, the share keeps the
            // relays it was made with (a new one gets the default relay).
            let static_token = relay_token.as_deref().map(load_relay_token).transpose()?;
            let credential = match &static_token {
                Some(t) => spora_core::identity::Credential::Static(t.clone()),
                None => spora_core::identity::Credential::None,
            };
            let mut relays = Vec::new();
            let relayed = |host: String, port: u16, protocol| spora_core::identity::RelayEntry {
                endpoint: spora_core::identity::RelayEndpoint::with_protocol(host, port, protocol),
                credential: credential.clone(),
            };
            for r in &relay {
                let (host, port) = parse_host_port(r).map_err(|e| format!("--relay: {}", e))?;
                relays.push(relayed(
                    host,
                    port,
                    spora_core::identity::RelayProtocol::UdpQuic,
                ));
            }
            for d in &direct {
                let (host, port) = parse_host_port(d).map_err(|e| format!("--direct: {}", e))?;
                relays.push(spora_core::identity::RelayEntry::open(
                    spora_core::identity::RelayEndpoint::with_protocol(
                        host,
                        port,
                        spora_core::identity::RelayProtocol::Direct,
                    ),
                ));
            }
            for t in &tcp_relay {
                let (host, port) = parse_host_port(t).map_err(|e| format!("--tcp-relay: {}", e))?;
                relays.push(relayed(
                    host,
                    port,
                    spora_core::identity::RelayProtocol::TcpTls,
                ));
            }
            for z in &nz_relay {
                let (host, port) = parse_host_port(z).map_err(|e| format!("--nz-relay: {}", e))?;
                relays.push(relayed(
                    host,
                    port,
                    spora_core::identity::RelayProtocol::NoiseUdp,
                ));
            }
            if static_token.is_some()
                && relay.is_empty()
                && tcp_relay.is_empty()
                && nz_relay.is_empty()
            {
                return Err(
                    "--relay-token is for the relays given with --relay, --tcp-relay or --nz-relay"
                        .into(),
                );
            }
            // The device identity lives in the service's state, which also
            // keeps the relay access a share on Spora's relays needs.
            let service = spora_service::Telemetry::init_global(service_config(&[]))
                .map_err(|e| format!("service state in {}: {e}", service_dir().display()))?;
            let device = service.device_identity();
            let share = load_or_make_share(
                &path,
                fresh,
                &device,
                (!relays.is_empty()).then_some(relays),
                &mut || spora_relays_share(service),
            )?;
            if share
                .relays
                .iter()
                .any(|r| r.credential == spora_core::identity::Credential::Spora)
            {
                service.set_relay_access(true);
                config.relay_token = service.relay_token();
                if config.relay_token.is_none() {
                    say!(
                        "No valid relay token yet: Spora's relays will refuse this share until one comes from the API."
                    );
                }
            }
            if !stun.is_empty() {
                for server in &stun {
                    parse_host_port(server).map_err(|e| format!("--stun: {}", e))?;
                }
                config.stun_servers = stun;
            }
            config.enable_direct_upgrade = !no_direct_upgrade;
            // Reassigned only under --os-routing (Linux).
            #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
            let mut dns_forwarder = dns_forwarder_config(&dns_upstream, no_dns_forwarder)?;
            config.dns_forwarder = dns_forwarder.clone();
            install_json_event_hook(&mut config, json);
            let connlog_dir = if no_conn_log {
                None
            } else {
                let dir =
                    conn_log_dir.unwrap_or_else(|| default_connlog_dir(&share.routing_hash()));
                let mut cl = spora_core::connlog::ConnLogConfig::in_dir(&dir);
                cl.retention =
                    std::time::Duration::from_secs(u64::from(conn_log_retention_days) * 86_400);
                cl.log_destinations = !conn_log_sessions_only;
                #[cfg(target_os = "linux")]
                if os_routing {
                    cl.egress_lookup = Some(os_route::conntrack_egress_lookup());
                }
                config.conn_log = Some(cl);
                Some(dir)
            };
            let record_dir =
                record_config(&mut config, no_record, record_dir, record_label, record_id);
            #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
            let mut routing: Option<ShareRouting> = None;
            if os_routing {
                #[cfg(target_os = "linux")]
                {
                    let opts = os_route::Options::parse(&tun_addr, &tun_addr6, tun_mtu, !no_nat)?;
                    let mut guard = os_route::OsRoute::setup(&opts)?;
                    if let Some(fwd) = &dns_forwarder
                        && !guard.start_dns_forwarder(fwd.clone()).await?
                    {
                        // --no-nat: no DNAT, so the synthetic address stays
                        // unanswered. Say so rather than claim a forwarder.
                        dns_forwarder = None;
                        config.dns_forwarder = None;
                    }
                    config.exit_mode = ExitMode::Custom(guard.session_handler());
                    routing = Some(guard);
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (&tun_addr, &tun_addr6, tun_mtu, no_nat);
                    return Err("--os-routing is only available on Linux (it drives iptables and kernel forwarding); the default netstack exit works everywhere".into());
                }
            }
            let routing_hash_hex = hex(&share.routing_hash());
            let cert_hash_hex = hex(&share.cert_hash);
            let upgrade_enabled = config.enable_direct_upgrade;
            let telemetry = start_telemetry();
            // A stop signal that comes while this sets up is kept and acted
            // on once the share is up: setting up resolves and binds, and
            // never waits for a peer.
            let share_id = share.share_id;
            let session = spora_core::share(device, share, config).await?;
            // Renewed relay tokens reach the running share from now on.
            service.register_share(share_id, session.credentials.clone());
            if json {
                let ready = emit_json_event(serde_json::json!({
                    "v": 1,
                    "event": "share_ready",
                    "url": session.url.as_str(),
                    "routing_hash": routing_hash_hex,
                    "cert_hash": cert_hash_hex,
                    "share_file": path,
                    "tun_name": routing.as_ref().map(|g| g.tun_name()),
                    "record_dir": record_dir,
                    "upgrade_enabled": upgrade_enabled,
                    "dns_upstreams": dns_forwarder.as_ref().map(|f| {
                        f.upstreams().iter().map(ToString::to_string).collect::<Vec<_>>()
                    }),
                    "dns_fallback": dns_forwarder.as_ref().map(|f| {
                        f.fallback().iter().map(ToString::to_string).collect::<Vec<_>>()
                    }),
                }));
                if let Err(e) = ready {
                    let failure = LocalFailure::event_stream(e);
                    close_on_local_failure(&session.record, &failure);
                    session.stop().await;
                    return Err(failure.error.into());
                }
            } else {
                say!("Share this URL with the peer that wants to connect:");
                say!("{}", session.url);
                say!("(Share kept at {})", path.display());
                if let Some(g) = &routing {
                    say!(
                        "OS routing enabled: client traffic is forwarded by the kernel via {}.",
                        g.tun_name()
                    );
                }
                match &connlog_dir {
                    Some(dir) => say!(
                        "Connection log: {} (retention {} days; query with `{}`, disable with --no-conn-log)",
                        dir.display(),
                        conn_log_retention_days,
                        spora_cmd("log")
                    ),
                    None => say!(
                        "Connection log DISABLED: you will have no record of what clients did with your IP."
                    ),
                }
                if let Some(dir) = &record_dir {
                    let read = if *dir == default_record_dir() {
                        spora_cmd("record")
                    } else {
                        spora_cmd(&format!(
                            "record list --dir {}",
                            shell_word(&dir.to_string_lossy())
                        ))
                    };
                    say!(
                        "Diagnostic record: {} (read it with `{read}`, disable with --no-record)",
                        dir.display()
                    );
                }
                print_diagnostics_banner(telemetry, record_dir.as_deref());
                match &dns_forwarder {
                    Some(f) => {
                        let ups = f.upstreams();
                        let join = |v: &[std::net::SocketAddr]| {
                            v.iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        if ups.is_empty() {
                            say!(
                                "DNS forwarder: no system resolvers found; clients resolve through {} (public fallback)",
                                join(&f.fallback())
                            );
                        } else {
                            say!(
                                "DNS forwarder: clients resolve through this host's resolvers ({})",
                                join(&ups)
                            );
                        }
                    }
                    None => say!(
                        "DNS forwarder DISABLED: clients must point their resolver at a public address."
                    ),
                }
                say!("Press Ctrl+C to stop sharing.");
            }
            shutdown.requested().await;
            if json {
                // Stopping goes ahead whether or not anyone still reads the
                // stream (a SIGHUP may have taken the reader with it).
                let _ = emit_json_event(serde_json::json!({"v": 1, "event": "stopping"}));
            } else {
                say!("Stopping share session...");
            }
            session.stop().await;
            service.unregister_share(&share_id);
            // `routing` (if any) drops here, after the session has stopped,
            // running OsRoute's cleanup. Dropping at scope end — rather than an
            // explicit call — means cleanup also runs if `share()` errored above
            // or the task panicked.
            drop(routing);
        }
        Mode::Use {
            url,
            stun,
            no_direct_upgrade,
            tun_name,
            tun_addr,
            tun_addr6,
            no_ipv6,
            route,
            no_routes,
            dns,
            no_dns,
            mtu,
            no_record,
            record_dir,
            record_label,
            record_id,
            no_diag_log: _,
            json,
        } => {
            let mode = match tun_name {
                Some(name) if cfg!(target_os = "linux") => UseMode::Attach(name),
                // Refused before the dial, which would take the sharer's
                // session from whoever has it for nothing.
                Some(_) => {
                    return Err(
                        "--tun-name (attach to a pre-created TUN) is only available on Linux"
                            .into(),
                    );
                }
                None => UseMode::Vpn(vpn::Options::parse(
                    &tun_addr, &tun_addr6, no_ipv6, &route, no_routes, &dns, no_dns, mtu,
                )?),
            };
            run_use(
                UseArgs {
                    url,
                    stun,
                    no_direct_upgrade,
                    mode,
                    no_record,
                    record_dir,
                    record_label,
                    record_id,
                    json,
                },
                shutdown.expect("use watches for stop signals"),
            )
            .await?;
        }
        // Unquoted: their errors may end in a command line to copy.
        Mode::Log { cmd } => run_log_cmd(cmd).map_err(|e| Plain(e.to_string()))?,
        Mode::Record { cmd } => run_record_cmd(cmd).map_err(Plain)?,
        Mode::Report {
            out,
            note,
            hours,
            record_dir,
        } => run_report(out, note, hours, record_dir)?,
        Mode::Telemetry { cmd } => run_telemetry_cmd(cmd)?,
        Mode::BuildInfo { json } => {
            let build = spora_core::record::build_info();
            if json {
                println!("{}", serde_json::to_string(&build)?);
            } else {
                println!(
                    "{} {}{} ({} {})",
                    build.version,
                    build.commit.as_deref().unwrap_or("unknown commit"),
                    if build.dirty { " +uncommitted" } else { "" },
                    build.target,
                    build.profile
                );
            }
        }
    }
    Ok(())
}

/// Share-side OS routing guard; only Linux has one.
#[cfg(target_os = "linux")]
type ShareRouting = os_route::OsRoute;
#[cfg(not(target_os = "linux"))]
struct ShareRouting;
#[cfg(not(target_os = "linux"))]
impl ShareRouting {
    fn tun_name(&self) -> &str {
        ""
    }
}

/// How `spora use` gets its tunnel interface.
enum UseMode {
    /// Bring the interface up and manage routes/MTU/resolver (the VPN client).
    Vpn(vpn::Options),
    /// Attach to a pre-created TUN and only pump packets: the caller owns the
    /// interface's address, MTU, routes and cleanup. A Linux-only product
    /// feature exercised by the in-tree `cli_vpn` lab test; the field lab
    /// drives the ordinary VPN mode (`--route`/`--no-dns`) instead. It must
    /// keep touching nothing else on the host.
    Attach(String),
}

struct UseArgs {
    url: String,
    stun: Vec<String>,
    no_direct_upgrade: bool,
    mode: UseMode,
    no_record: bool,
    record_dir: Option<PathBuf>,
    record_label: Option<String>,
    record_id: Option<String>,
    json: bool,
}

async fn run_use(args: UseArgs, shutdown: &Shutdown) -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse(&args.url)?;
    if url.scheme() != "https" {
        return Err(format!(
            "unsupported scheme {}: expected an https:// share URL",
            url.scheme()
        )
        .into());
    }
    let mut config = Config::default();
    if !args.stun.is_empty() {
        for server in &args.stun {
            parse_host_port(server).map_err(|e| format!("--stun: {}", e))?;
        }
        config.stun_servers = args.stun.clone();
    }
    config.enable_direct_upgrade = !args.no_direct_upgrade;
    let json = args.json;

    // Phase 1 (VPN mode): the interface exists with its address and MTU but
    // no routes, so the relay dial and STUN below use the normal network —
    // the same two-phase bring-up as the Android client.
    let session = match &args.mode {
        UseMode::Vpn(opts) => {
            for ip in opts.unreachable_resolvers() {
                log::warn!(
                    "resolver {ip} is a private address: sharers drop traffic to private destinations, so it will not answer through the tunnel"
                );
            }
            Some(std::sync::Arc::new(vpn::Session::setup(opts.clone())?))
        }
        UseMode::Attach(_) => None,
    };
    if let Some(s) = &session {
        config.protector = s.protector();
    }
    install_event_hook(&mut config, json, session.as_ref());
    install_mtu_hook(&mut config, json, session.as_ref());

    let configured_record_dir = record_config(
        &mut config,
        args.no_record,
        args.record_dir,
        args.record_label,
        args.record_id,
    );
    let telemetry = start_telemetry();
    if !json {
        if let Some(dir) = &configured_record_dir {
            say!("Diagnostic record: {}", dir.display());
        }
        print_diagnostics_banner(telemetry, configured_record_dir.as_deref());
    }
    // A dial can take a while (each relay has `relay_dial_timeout`), and a
    // stop signal ends it where it is.
    let result = tokio::select! {
        r = connect(url, &config) => match r {
            Ok(result) => result,
            Err(e) => return Err(format!("could not connect: {e}").into()),
        },
        () = shutdown.requested() => {
            // The dial goes with its future, and its record with it: the
            // steps it left unfinished become `abandoned`, and the run
            // closes `never_connected`. The process then ends as after any
            // other stop: log flushed, last upload sent.
            if json {
                let _ = emit_json_event(serde_json::json!({"v": 1, "event": "stopping"}));
            } else {
                say!("Stopped before the tunnel came up.");
            }
            if let Some(s) = &session {
                s.shutdown();
            }
            return Ok(());
        }
    };
    // The CLI is always-on and has no screen state, so opt out of the
    // Android dormant/battery semantics. A keepalive knob of 0 means
    // "screen off" to spora-core, which disables the liveness probe
    // (a dead tunnel is never detected) and parks the direct upgrade
    // after a few transient failures. Set an active probe interval so
    // neither happens; only the Android FFI drives the knob to 0.
    result
        .keepalive_knob
        .store(KEEPALIVE_PROBE_SECS, std::sync::atomic::Ordering::Relaxed);
    if let Some(w) = result.keepalive_waker.lock().unwrap().take() {
        w.wake();
    }
    let record = result.record.clone();
    let stopper = result.stopper.clone();
    let record_dir_json = config.record.as_ref().and_then(|r| r.dir.clone());
    let pump = start_pump(
        args.mode,
        session.as_deref(),
        result.transport,
        json,
        record_dir_json,
        config.enable_direct_upgrade,
    );
    let mut pump = match pump {
        Ok(pump) => pump,
        Err(failure) => {
            // The tunnel is up and this host would not take it. The record
            // says so, the session ends and whatever was changed is put
            // back, all before the error goes up to `main` (and the last
            // upload).
            close_on_local_failure(&record, &failure);
            stopper.stop().await;
            if let Some(s) = &session {
                s.shutdown();
            }
            return Err(failure.error.into());
        }
    };
    let outcome = wait_for_tunnel_end(&mut pump, json, &record, &stopper, shutdown).await;
    // Undo the host changes while the interface still exists: the pump, and
    // with it the device, goes after.
    if let Some(s) = &session {
        s.shutdown();
    }
    drop(pump);
    outcome
}

/// The packet pump of a `use` run.
type Pump = std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>>>>;

/// Point the host at a tunnel that just came up — attach the pre-created
/// TUN, or (VPN mode, phase 2: the session is up and its sockets are
/// protected) install the routes and the resolver — announce it, and hand
/// back its packet pump. What fails here is this host's doing, not the
/// network's (see [`LocalFailure`]).
fn start_pump(
    mode: UseMode,
    session: Option<&vpn::Session>,
    transport: spora_core::IpTransport,
    json: bool,
    record_dir_json: Option<PathBuf>,
    upgrade_enabled: bool,
) -> Result<Pump, LocalFailure> {
    match mode {
        UseMode::Attach(name) => {
            #[cfg(not(target_os = "linux"))]
            {
                // Refused before the dial (see `run`).
                let _ = (name, transport, json, record_dir_json, upgrade_enabled);
                Err(LocalFailure::host(
                    "--tun-name (attach to a pre-created TUN) is only available on Linux".into(),
                ))
            }
            #[cfg(target_os = "linux")]
            {
                let tun = tokio_tun::Tun::builder()
                    .name(&name)
                    .try_build()
                    .map_err(|e| {
                        let kind = match &e {
                            tokio_tun::Error::NixError(errno) => {
                                std::io::Error::from(*errno).kind()
                            }
                            tokio_tun::Error::IoError(e) => e.kind(),
                        };
                        LocalFailure::of_kind(format!("could not attach TUN {name}: {e}"), kind)
                    })?;
                let actual_tun_name = tun.name().to_string();
                if json {
                    emit_json_event(serde_json::json!({
                        "v": 1,
                        "event": "tunnel_ready",
                        "mode": "attached",
                        "tun_name": actual_tun_name,
                        "record_dir": record_dir_json,
                        "upgrade_enabled": upgrade_enabled,
                    }))
                    .map_err(LocalFailure::event_stream)?;
                } else {
                    say!(
                        "Attached to {actual_tun_name}; its address, MTU and routes are yours to manage."
                    );
                    say!("Press Ctrl+C to disconnect.");
                }
                Ok(Box::pin(spora_core::tun_util::start(transport, tun)))
            }
        }
        UseMode::Vpn(_) => {
            let session = session.expect("VPN mode has a session");
            let activation = session.activate().map_err(LocalFailure::host)?;
            let pump_handle = session.pump_handle().map_err(LocalFailure::host)?;
            let opts = session.options();
            let tun_addr = format!("{}/{}", opts.tun_addr, opts.tun_prefix);
            let tun_addr6 = opts.tun_addr6.map(|(a, p)| format!("{a}/{p}"));
            if json {
                emit_json_event(serde_json::json!({
                    "v": 1,
                    "event": "tunnel_ready",
                    "mode": "vpn",
                    "tun_name": session.tun_name(),
                    "tun_addr": tun_addr,
                    "tun_addr6": tun_addr6,
                    "mtu": session.current_mtu(),
                    "mtu_policy": match opts.mtu {
                        vpn::MtuPolicy::Auto => "auto",
                        vpn::MtuPolicy::Fixed(_) => "fixed",
                    },
                    "routes": activation.routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "dns": activation.dns.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "dns_method": activation.dns_method,
                    "record_dir": record_dir_json,
                    "upgrade_enabled": upgrade_enabled,
                }))
                .map_err(LocalFailure::event_stream)?;
            } else {
                let addrs = match &tun_addr6 {
                    Some(a6) => format!("{tun_addr}, {a6}"),
                    None => tun_addr.clone(),
                };
                say!(
                    "Tunnel up on {} ({addrs}), MTU {}{}.",
                    session.tun_name(),
                    session.current_mtu(),
                    match opts.mtu {
                        vpn::MtuPolicy::Auto => " (follows the path)",
                        vpn::MtuPolicy::Fixed(_) => " (pinned)",
                    }
                );
                match &opts.routes {
                    vpn::RouteSet::Default => say!("Routing all traffic through the tunnel."),
                    vpn::RouteSet::Prefixes(_) => say!(
                        "Routing {} through the tunnel.",
                        activation
                            .routes
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    vpn::RouteSet::None => {
                        say!(
                            "No routes installed (--no-routes): route into the interface yourself."
                        )
                    }
                }
                match activation.dns_method {
                    Some(how) => say!(
                        "Resolver: {} (set via {how}; restored on exit).",
                        activation
                            .dns
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    None => say!("Resolver left unchanged."),
                }
                say!("Press Ctrl+C to disconnect.");
            }
            Ok(Box::pin(vpn::run_pump(transport, pump_handle)))
        }
    }
}

/// What kept a run from putting a tunnel (or a share) that came up into
/// service: this host, not the network — no permission for the TUN, a route
/// or resolver change refused, an event stream nobody reads any more.
struct LocalFailure {
    reason: spora_core::record::Reason,
    error: String,
}

impl LocalFailure {
    /// The operating system refused: `permission_denied` for want of
    /// privilege, else `misconfigured`.
    fn of_kind(error: String, kind: std::io::ErrorKind) -> LocalFailure {
        use spora_core::record::Reason;
        let reason = if kind == std::io::ErrorKind::PermissionDenied {
            Reason::PermissionDenied
        } else {
            Reason::Misconfigured
        };
        LocalFailure { reason, error }
    }

    /// A change to the host that spora-vpn could not make. It reports text,
    /// and the run is root's: the host refused the configuration.
    fn host(error: String) -> LocalFailure {
        LocalFailure {
            reason: spora_core::record::Reason::Misconfigured,
            error,
        }
    }

    /// `--json`'s event stream could not be written.
    fn event_stream(e: std::io::Error) -> LocalFailure {
        Self::of_kind(format!("event stream: {e}"), e.kind())
    }
}

/// Close `record` for a run that a [`LocalFailure`] ends, ahead of anything
/// else that would: the core's closer, stopped next, would make it an
/// ordinary local shutdown, and a recorder merely dropped while its session
/// is up calls the tunnel `lost`.
fn close_on_local_failure(record: &spora_core::record::Recorder, failure: &LocalFailure) {
    use spora_core::record::Outcome;
    let outcome = if record.has_connected() {
        Outcome::ClosedLocally
    } else {
        Outcome::NeverConnected
    };
    record.close(outcome, Some(failure.reason), Some(failure.error.clone()));
}

/// Run the pump until the tunnel ends or a stop signal comes, then close the
/// record explicitly and end the session: a process killed mid-run leaves a
/// truncated record, which is honest but much less useful than one with an
/// ending. The session's end is awaited until it has reached the network
/// ([`spora_core::RunStopper::stop`]): the process exits soon after, and a
/// close still queued then never goes, so the exit would record a client
/// that left on purpose as a session that died.
async fn wait_for_tunnel_end(
    pump: &mut Pump,
    json: bool,
    record: &spora_core::record::Recorder,
    stopper: &spora_core::RunStopper,
    shutdown: &Shutdown,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::select! {
        () = shutdown.requested() => {
            if json {
                // Stopping goes ahead whether or not anyone still reads the
                // stream (a SIGHUP may have taken the reader with it).
                let _ = emit_json_event(serde_json::json!({"v": 1, "event": "stopping"}));
            } else {
                say!("Disconnecting...");
            }
            // The core's closer records the session's end and closes the
            // record; this close only backs it up.
            stopper.stop().await;
            record.close_shutdown(Some(spora_core::record::Reason::LocalShutdown));
            Ok(())
        }
        res = pump => {
            // Closed first: the core's closer, stopped next, would make
            // this a local shutdown.
            record.close_shutdown(None);
            stopper.stop().await;
            res.map_err(|e| format!("tunnel: {e}"))?;
            Ok(())
        }
    }
}

/// Route spora-core's MTU reports (the carrier's datagram budget, reported
/// after PMTUD converges and again after a direct upgrade) to the tunnel
/// interface through spora-vpn's MTU policy, announcing both the report and
/// what was set.
fn install_mtu_hook(
    config: &mut Config,
    json: bool,
    session: Option<&std::sync::Arc<vpn::Session>>,
) {
    config.mtu_callback = vpn::mtu_callback(session, move |event| match event {
        vpn::MtuEvent::Reported(reported) => {
            if json {
                let _ = emit_json_event(
                    serde_json::json!({"v": 1, "event": "path_mtu", "mtu": reported}),
                );
            } else {
                log::info!("path MTU budget reported: {reported}");
            }
        }
        vpn::MtuEvent::Applied(mtu) => {
            if json {
                let _ =
                    emit_json_event(serde_json::json!({"v": 1, "event": "tun_mtu", "mtu": mtu}));
            } else {
                log::info!("tunnel interface MTU set to {mtu}");
            }
        }
        vpn::MtuEvent::Failed { reported, error } => {
            log::warn!("could not apply MTU {reported}: {error}");
        }
    });
}

fn emit_json_event(value: serde_json::Value) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn install_json_event_hook(config: &mut spora_core::Config, enabled: bool) {
    install_event_hook(config, enabled, None);
}

/// Consume spora-core's lifecycle events: print them as JSON when asked, and
/// let the VPN session re-detect its uplink when the tunnel reconnects (the
/// network may have changed underneath; macOS/Windows bind the outer sockets
/// to it — spora-vpn's hook does that before the event reaches us).
fn install_event_hook(
    config: &mut spora_core::Config,
    json: bool,
    session: Option<&std::sync::Arc<vpn::Session>>,
) {
    if !json && session.is_none() {
        return;
    }
    config.event_hook = vpn::event_hook(session, move |event| {
        if json {
            let _ = emit_json_event(tunnel_event_json(event));
        }
    });
}

fn tunnel_event_json(event: spora_core::TunnelEvent) -> serde_json::Value {
    use spora_core::TunnelEvent;
    match event {
        TunnelEvent::PathActivated {
            carrier,
            path,
            local,
            peer,
        } => serde_json::json!({
            "v":1,
            "event":"path_activated",
            "carrier":carrier.as_str(),
            "path":path.as_str(),
            "local":local,
            "peer":peer
        }),
        TunnelEvent::RelaySessionEstablished { peer } => {
            serde_json::json!({"v":1,"event":"relay_session_established","peer":peer})
        }
        TunnelEvent::DirectUpgradeSucceeded { local, peer } => serde_json::json!({
            "v":1,"event":"direct_upgrade_succeeded","local":local,"peer":peer
        }),
        TunnelEvent::DirectUpgradeFailed { code, reason } => serde_json::json!({
            "v":1,"event":"direct_upgrade_failed","code":code.as_str(),"reason":reason
        }),
        TunnelEvent::Reconnecting => serde_json::json!({"v":1,"event":"reconnecting"}),
        TunnelEvent::Reconnected => serde_json::json!({"v":1,"event":"reconnected"}),
        TunnelEvent::SessionEnded { reason } => {
            serde_json::json!({"v":1,"event":"session_ended","reason":reason})
        }
        TunnelEvent::ConnLogDegraded { detail } => {
            serde_json::json!({"v":1,"event":"conn_log_degraded","detail":detail})
        }
    }
}

// ---------- `spora log` ----------

fn run_log_cmd(cmd: LogCmd) -> Result<(), Box<dyn std::error::Error>> {
    use spora_core::connlog;
    match cmd {
        LogCmd::Query {
            ip,
            port,
            from,
            to,
            json,
            dir,
            share_file,
        } => {
            let dir = resolve_connlog_dir(dir, share_file, "log query")?;
            let db = connlog::open_readonly(&dir)?;
            let q = connlog::FlowQuery {
                ip,
                port,
                session: None,
                from_ms: from.as_deref().map(parse_time).transpose()?,
                to_ms: to.as_deref().map(parse_time).transpose()?,
            };
            let flows = connlog::query_flows(&db, &q)?;
            let mut session_ids: Vec<i64> = flows.iter().map(|f| f.session_id).collect();
            session_ids.sort_unstable();
            session_ids.dedup();
            let sessions = if session_ids.is_empty() {
                Vec::new()
            } else {
                connlog::query_sessions(&db, Some(&session_ids))?
            };
            let marks = connlog::query_marks(&db, q.from_ms, q.to_ms)?;
            if json {
                print_query_json(&flows, &sessions, &marks);
            } else {
                print_query_human(&flows, &sessions, &marks);
            }
        }
        LogCmd::Sessions { dir, share_file } => {
            let dir = resolve_connlog_dir(dir, share_file, "log sessions")?;
            let db = connlog::open_readonly(&dir)?;
            for s in connlog::query_sessions(&db, None)? {
                print_session(&s);
            }
        }
        LogCmd::Hold { cmd } => match cmd {
            HoldCmd::Add {
                from,
                to,
                note,
                dir,
                share_file,
            } => {
                let dir = resolve_connlog_dir(dir, share_file, "log hold add")?;
                let db = connlog::open_readwrite(&dir)?;
                let id =
                    connlog::add_hold(&db, parse_time(&from)?, parse_time(&to)?, note.as_deref())?;
                println!(
                    "hold {} added: records in [{}, {}] are pinned against retention",
                    id, from, to
                );
            }
            HoldCmd::List { dir, share_file } => {
                let dir = resolve_connlog_dir(dir, share_file, "log hold list")?;
                let db = connlog::open_readonly(&dir)?;
                let holds = connlog::list_holds(&db)?;
                if holds.is_empty() {
                    println!("no holds");
                }
                for (id, from, to, note) in holds {
                    println!(
                        "hold {}: {} .. {}  {}",
                        id,
                        fmt_ms(from),
                        fmt_ms(to),
                        note.unwrap_or_default()
                    );
                }
            }
            HoldCmd::Remove {
                id,
                dir,
                share_file,
            } => {
                let dir = resolve_connlog_dir(dir, share_file, "log hold remove")?;
                let db = connlog::open_readwrite(&dir)?;
                if connlog::remove_hold(&db, id)? {
                    println!("hold {} removed", id);
                } else {
                    println!("no hold with id {}", id);
                }
            }
        },
    }
    Ok(())
}

fn print_query_human(
    flows: &[spora_core::connlog::FlowRow],
    sessions: &[spora_core::connlog::SessionRow],
    marks: &[spora_core::connlog::MarkRow],
) {
    if flows.is_empty() {
        println!("no matching flows");
    }
    for f in flows {
        let last = f.last_ms.map(fmt_ms).unwrap_or_else(|| "open".into());
        let mut extra = String::new();
        if let Some(e) = &f.egress_addr {
            extra.push_str(&format!("  egress {}", e));
        }
        if !f.confirmed {
            // Meter-path records: traffic offered to the tunnel; the handler
            // may still have dropped it.
            extra.push_str("  (offered, not confirmed egress)");
        }
        println!(
            "{} .. {}  {} {}:{} -> {}:{}  up {}B down {}B  {}{}  session {:016x}",
            fmt_ms(f.first_ms),
            last,
            proto_name(f.proto),
            f.src,
            f.src_port,
            f.dst,
            f.dst_port,
            f.bytes_up,
            f.bytes_down,
            match (f.end_reason.as_deref(), f.established) {
                (Some(r), true) => format!("established, {}", r),
                (Some(r), false) => format!("unanswered, {}", r),
                (None, true) => "established, still open".into(),
                (None, false) => "unanswered, still open".into(),
            },
            extra,
            f.session_id as u64,
        );
    }
    for s in sessions {
        print_session(s);
    }
    let mut warned = false;
    for m in marks {
        if matches!(m.kind.as_str(), "log_gap" | "clock_jump" | "flow_throttle") {
            if !warned {
                println!("\nWARNING: the log has irregularities overlapping this window:");
                warned = true;
            }
            println!(
                "  {} {} {}",
                fmt_ms(m.ts_ms),
                m.kind,
                m.detail.as_deref().unwrap_or("")
            );
        }
    }
}

fn print_session(s: &spora_core::connlog::SessionRow) {
    println!(
        "\nsession {:016x}: {} .. {}  via relay {}  ({})",
        s.id as u64,
        fmt_ms(s.start_ms),
        s.end_ms.map(fmt_ms).unwrap_or_else(|| "open".into()),
        s.relay_addr,
        s.end_reason.as_deref().unwrap_or("still active")
    );
    for (ts, kind, addr) in &s.addrs {
        let caveat = match kind.as_str() {
            "reported" => "  (client-asserted, UNVERIFIED)",
            "punch_verified" => "  (address-validated by hole punch)",
            "verified" => "  (verified direct connection)",
            "sharer_public" => "  (this sharer's own public address)",
            _ => "",
        };
        println!("  {}  {} {}{}", fmt_ms(*ts), kind, addr, caveat);
    }
    if !s
        .addrs
        .iter()
        .any(|(_, k, _)| k == "verified" || k == "punch_verified")
    {
        println!("  note: relay-via only — the client's outer address was never directly observed");
    }
}

fn print_query_json(
    flows: &[spora_core::connlog::FlowRow],
    sessions: &[spora_core::connlog::SessionRow],
    marks: &[spora_core::connlog::MarkRow],
) {
    let mut out = String::from("{\"flows\":[");
    for (i, f) in flows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"session\":\"{:016x}\",\"proto\":\"{}\",\"src\":\"{}\",\"src_port\":{},\"dst\":\"{}\",\"dst_port\":{},\"first\":\"{}\",\"last\":{},\"bytes_up\":{},\"bytes_down\":{},\"egress\":{},\"established\":{},\"confirmed_egress\":{},\"end_reason\":{}}}",
            f.session_id as u64,
            proto_name(f.proto),
            json_str(&f.src),
            f.src_port,
            json_str(&f.dst),
            f.dst_port,
            fmt_ms(f.first_ms),
            f.last_ms.map(|t| format!("\"{}\"", fmt_ms(t))).unwrap_or_else(|| "null".into()),
            f.bytes_up,
            f.bytes_down,
            f.egress_addr.as_deref().map(|e| format!("\"{}\"", json_str(e))).unwrap_or_else(|| "null".into()),
            f.established,
            f.confirmed,
            f.end_reason.as_deref().map(|r| format!("\"{}\"", json_str(r))).unwrap_or_else(|| "null".into()),
        ));
    }
    out.push_str("],\"sessions\":[");
    for (i, s) in sessions.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"id\":\"{:016x}\",\"start\":\"{}\",\"end\":{},\"end_reason\":{},\"relay\":\"{}\",\"addrs\":[",
            s.id as u64,
            fmt_ms(s.start_ms),
            s.end_ms.map(|t| format!("\"{}\"", fmt_ms(t))).unwrap_or_else(|| "null".into()),
            s.end_reason.as_deref().map(|r| format!("\"{}\"", json_str(r))).unwrap_or_else(|| "null".into()),
            json_str(&s.relay_addr),
        ));
        for (j, (ts, kind, addr)) in s.addrs.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"ts\":\"{}\",\"kind\":\"{}\",\"addr\":\"{}\"}}",
                fmt_ms(*ts),
                json_str(kind),
                json_str(addr)
            ));
        }
        out.push_str("]}");
    }
    out.push_str("],\"marks\":[");
    for (i, m) in marks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // Mark details written by the logger are JSON objects already; emit
        // them as nested objects rather than escaped strings.
        let detail = match m.detail.as_deref() {
            Some(d) if d.starts_with('{') => d.to_string(),
            Some(d) => format!("\"{}\"", json_str(d)),
            None => "null".into(),
        };
        out.push_str(&format!(
            "{{\"ts\":\"{}\",\"kind\":\"{}\",\"detail\":{}}}",
            fmt_ms(m.ts_ms),
            json_str(&m.kind),
            detail,
        ));
    }
    out.push_str("]}");
    println!("{}", out);
}

fn json_str(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect()
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "other",
    }
}

fn fmt_ms(ms: i64) -> String {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms.max(0) as u64);
    humantime::format_rfc3339_seconds(t).to_string()
}

/// Accepts RFC3339, a bare date (midnight UTC), or unix seconds/milliseconds.
fn parse_time(s: &str) -> Result<i64, String> {
    if let Ok(n) = s.parse::<i64>() {
        // Heuristic: values before ~5138 AD in ms are seconds.
        return Ok(if n < 100_000_000_000 { n * 1000 } else { n });
    }
    let attempt = if s.len() == 10 && s.as_bytes()[4] == b'-' {
        format!("{}T00:00:00Z", s)
    } else {
        s.to_string()
    };
    humantime::parse_rfc3339(&attempt)
        .map_err(|e| {
            format!(
                "'{}' is not a recognized time ({}); use RFC3339, YYYY-MM-DD, or unix seconds",
                s, e
            )
        })
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
        })
}

/// The connection-log directory for `spora <cmd>`: `dir`, or the one of the
/// share's in the state directory.
fn resolve_connlog_dir(
    dir: Option<PathBuf>,
    share_file: Option<PathBuf>,
    cmd: &str,
) -> Result<PathBuf, String> {
    if let Some(d) = dir {
        return Ok(d);
    }
    let elsewhere = sudo_elsewhere("connection log", cmd);
    let path = share_file.unwrap_or_else(default_share_path);
    let bytes = std::fs::read(&path).map_err(|e| {
        format!(
            "cannot read share {} to locate the log ({}); pass --dir explicitly{elsewhere}",
            path.display(),
            e
        )
    })?;
    let share = Share::from_blob(&bytes)?;
    let dir = default_connlog_dir(&share.routing_hash());
    match std::fs::metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "no connection log at {} (pass --dir{elsewhere})",
            dir.display()
        )),
        Err(e) => Err(format!(
            "reading {}: {e}{}",
            dir.display(),
            sudo_cause(&e, &dir)
        )),
        Ok(_) => Ok(dir),
    }
}

/// One connection log per share, named by its routing hash.
fn default_connlog_dir(routing_hash: &RoutingHash) -> PathBuf {
    connlog_base_dir().join(hex(routing_hash))
}

fn connlog_base_dir() -> PathBuf {
    state_dir().join("connlog")
}

/// Where the CLI keeps what it learns about its runs: `spora` in the state
/// home (see [`state_home`]; `%LOCALAPPDATA%` on Windows). Everything the
/// CLI keeps besides the identity is under it: records, the diagnostic log
/// and crash reports, the telemetry state, the connection log. Decided once
/// per process, so every command and banner names the same place.
fn state_dir() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| process_state_home().join("spora"))
        .clone()
}

#[cfg(unix)]
fn process_state_home() -> PathBuf {
    state_home(
        StateEnv {
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
            home: std::env::var_os("HOME"),
            sudo_user: std::env::var_os("SUDO_USER"),
            root: running_as_root(),
        },
        root_home,
    )
}

#[cfg(not(unix))]
fn process_state_home() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// What the state home depends on, as the process finds it.
#[cfg(unix)]
struct StateEnv {
    xdg_state_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
    sudo_user: Option<std::ffi::OsString>,
    /// The effective uid is 0.
    root: bool,
}

/// The directory the state directory goes in: `$XDG_STATE_HOME` when it is
/// set (to an absolute path: the XDG spec ignores anything else), else
/// `~/.local/state`, where under sudo `~` is root's home from the password
/// database (`root_home`, asked only then) rather than `$HOME`. sudo keeps
/// the user's `HOME` on macOS by default, and elsewhere with `sudo -E` or a
/// distribution's `env_keep`; root writing there would leave files in the
/// user's home that the user's own runs can then neither read nor replace.
#[cfg(unix)]
fn state_home(env: StateEnv, root_home: impl FnOnce() -> PathBuf) -> PathBuf {
    if let Some(dir) = env
        .xdg_state_home
        .map(PathBuf::from)
        .filter(|d| d.is_absolute())
    {
        return dir;
    }
    let home = if env.root && is_sudo_user(env.sudo_user.as_deref()) {
        root_home()
    } else {
        match env.home.filter(|h| !h.is_empty()) {
            Some(h) => PathBuf::from(h),
            None => return PathBuf::from("."),
        }
    };
    home.join(".local").join("state")
}

/// Root's home directory as the password database has it, whatever `HOME`
/// says; the usual one if the database does not answer.
#[cfg(unix)]
fn root_home() -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;
    let mut buf: Vec<libc::c_char> = vec![0; 1024];
    loop {
        // SAFETY: an all-zero `passwd` (null pointers, zero ids) is a valid
        // value for getpwuid_r to fill in.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local of the size passed; the
        // strings `pw` points to live in `buf`, read below while it does.
        let rc = unsafe { libc::getpwuid_r(0, &mut pw, buf.as_mut_ptr(), buf.len(), &mut found) };
        if rc == libc::ERANGE && buf.len() < 1 << 16 {
            let len = buf.len() * 4;
            buf.resize(len, 0);
            continue;
        }
        if rc == 0 && !found.is_null() && !pw.pw_dir.is_null() {
            // SAFETY: a NUL-terminated string in `buf`, filled in above.
            let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
            let dir = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
            if dir.is_absolute() {
                return dir;
            }
        }
        break;
    }
    PathBuf::from(if cfg!(target_os = "macos") {
        "/var/root"
    } else {
        "/root"
    })
}

// ---------------------------------------------------------------------------
// diagnostic records

/// Point `config` at a record directory unless the user opted out. Recording
/// is on by default here: this is the machine you run when you want to know
/// what happened, and a diagnostic you have to enable before reproducing a
/// problem is one you do not have when it matters.
fn record_config(
    config: &mut Config,
    no_record: bool,
    dir: Option<PathBuf>,
    label: Option<String>,
    correlation_id: Option<String>,
) -> Option<PathBuf> {
    if no_record {
        return None;
    }
    let dir = dir.unwrap_or_else(default_record_dir);
    let mut rc = spora_core::record::RecordConfig::in_dir(&dir);
    rc.label = label;
    rc.correlation_id = correlation_id;
    // Stamps the diagnostic log's lines with the open run, and wakes the
    // uploader when a record closes.
    rc.subscriber = Some(spora_service::record_subscriber());
    config.record = Some(rc);
    Some(dir)
}

fn default_record_dir() -> PathBuf {
    state_dir().join("records")
}

/// The diagnostic log and crash reports of `share` and `use`.
fn default_diag_dir() -> PathBuf {
    state_dir().join("log")
}

/// The telemetry state: the upload switch, the device registration, the
/// upload cursors.
fn service_dir() -> PathBuf {
    state_dir().join("service")
}

/// The newest `limit` records in `dir` (default: the default directory),
/// for `spora <cmd>`.
fn load_records(dir: Option<PathBuf>, limit: usize, cmd: &str) -> Result<Vec<Record>, String> {
    let elsewhere = if dir.is_none() {
        sudo_elsewhere("records", cmd)
    } else {
        String::new()
    };
    let dir = dir.unwrap_or_else(default_record_dir);
    match std::fs::metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "no records at {} (run with recording on, or pass --dir{elsewhere})",
                dir.display()
            ));
        }
        Err(e) => {
            return Err(format!(
                "reading {}: {e}{}",
                dir.display(),
                sudo_cause(&e, &dir)
            ));
        }
        Ok(_) => {}
    }
    let mut records = Record::read_dir(&dir)
        .map_err(|e| format!("reading {}: {e}{}", dir.display(), sudo_cause(&e, &dir)))?
        .into_iter()
        .map(|(_, r)| r)
        .collect::<Vec<_>>();
    records.truncate(limit);
    Ok(records)
}

fn run_record_cmd(cmd: RecordCmd) -> Result<(), String> {
    match cmd {
        RecordCmd::List { dir, count, json } => {
            let records = load_records(dir, count, "record list")?;
            if json {
                println!("{}", spora_core::record::records_to_json(&records));
                return Ok(());
            }
            if records.is_empty() {
                println!("no records");
                return Ok(());
            }
            println!(
                "{:<21} {:<10} {:<6} {:<16} {:>8}  first failure",
                "when", "id", "role", "outcome", "took"
            );
            for r in &records {
                let took = r
                    .close
                    .as_ref()
                    .map(|c| format!("{:.1}s", c.at_ms as f64 / 1000.0))
                    .unwrap_or_else(|| "-".into());
                let first = match r.first_failure() {
                    Some(step) => format!(
                        "{} {}",
                        step.kind,
                        step.reason
                            .map(|x| x.to_string())
                            .unwrap_or_else(|| "-".into())
                    ),
                    None => "-".into(),
                };
                println!(
                    "{:<21} {:<10} {:<6} {:<16} {:>8}  {}",
                    spora_core::record::utc_timestamp(r.open.at_unix_ms),
                    short_id(&r.open.id),
                    r.open.role,
                    if r.truncated {
                        "unknown (cut)".to_string()
                    } else {
                        r.outcome().to_string()
                    },
                    took,
                    first
                );
            }
        }
        RecordCmd::Show {
            id,
            dir,
            json,
            samples,
        } => {
            let records = load_records(dir, 200, "record show")?;
            let record = match &id {
                Some(want) => records
                    .into_iter()
                    .find(|r| r.open.id.starts_with(want))
                    .ok_or_else(|| format!("no record whose id starts with {want}"))?,
                None => records
                    .into_iter()
                    .next()
                    .ok_or_else(|| "no records".to_string())?,
            };
            if json {
                println!("{}", record.to_json_pretty());
                return Ok(());
            }
            print_record(&record, samples);
        }
        RecordCmd::Export { dir, count, out } => {
            let records = load_records(dir, count, "record export")?;
            let json = spora_core::record::records_to_json(&records);
            match out {
                Some(path) => {
                    std::fs::write(&path, json.as_bytes())
                        .map_err(|e| format!("writing {}: {e}", path.display()))?;
                    eprintln!("{} record(s) written to {}", records.len(), path.display());
                }
                None => println!("{json}"),
            }
        }
    }
    Ok(())
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// `wifi validated`, `cellular unvalidated`, or the bare kind when the
/// platform cannot tell.
fn network_text(n: &spora_core::record::NetworkState) -> String {
    match n.validated {
        Some(true) => format!("{} validated", n.kind),
        Some(false) => format!("{} unvalidated", n.kind),
        None => n.kind.to_string(),
    }
}

fn print_record(r: &Record, samples: bool) {
    let b = &r.open.build;
    println!(
        "{} {} record {}",
        spora_core::record::utc_timestamp(r.open.at_unix_ms),
        r.open.role,
        r.open.id
    );
    println!(
        "  build   {} {}{}  ({} {})",
        b.version,
        b.commit.as_deref().unwrap_or("unknown commit"),
        if b.dirty { " +uncommitted" } else { "" },
        b.target,
        b.profile
    );
    if let Some(rk) = &r.open.routing_key {
        println!("  identity {rk}");
    }
    if !r.open.endpoints.is_empty() {
        let eps: Vec<String> = r
            .open
            .endpoints
            .iter()
            .map(|e| format!("{}:{} ({})", e.host, e.port, e.carrier))
            .collect();
        println!("  endpoints {}", eps.join(", "));
    }
    if let Some(label) = &r.open.label {
        println!("  label   {label}");
    }
    if let Some(n) = &r.open.network {
        println!("  network {}", network_text(n));
    }
    println!();
    for step in &r.steps {
        let mut where_ = Vec::new();
        if let Some(n) = &step.network {
            where_.push(network_text(n));
        }
        if let Some(v) = &step.via {
            where_.push(format!("via {v}"));
        }
        if let Some(p) = &step.peer {
            where_.push(format!("peer {p}"));
        }
        if let Some(c) = step.carrier {
            where_.push(c.to_string());
        }
        if let Some(p) = step.path {
            where_.push(p.to_string());
        }
        println!(
            "{:>8}ms  {:<17} {:<9} {:<18} {:<32} {}",
            step.at_ms,
            step.kind,
            step.outcome,
            step.reason
                .map(|x| x.to_string())
                .unwrap_or_else(|| "-".into()),
            where_.join(" "),
            step.dur_ms.map(|d| format!("{d}ms")).unwrap_or_default(),
        );
        if let Some(detail) = &step.detail {
            println!("           {detail}");
        }
    }
    for gap in &r.gaps {
        println!("{:>8}ms GAP: {} entries dropped", gap.at_ms, gap.dropped);
    }
    if samples {
        println!();
        for s in &r.samples {
            println!(
                "{:>8}ms sample {} {} rtt={} tx={}B rx={}B probes={}/{} mtu={}",
                s.at_ms,
                s.path,
                s.carrier,
                s.rtt_ms
                    .map(|v| format!("{v:.0}ms"))
                    .unwrap_or_else(|| "-".into()),
                s.tx_bytes,
                s.rx_bytes,
                s.probes_sent.unwrap_or(0) - s.probes_lost.unwrap_or(0),
                s.probes_sent.unwrap_or(0),
                s.mtu.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
            );
        }
    }
    println!();
    match &r.close {
        Some(c) => {
            println!(
                "ended {} after {:.1}s: {} session(s), {} reconnect(s), {:.1}s connected, {}B up / {}B down",
                c.outcome,
                c.at_ms as f64 / 1000.0,
                c.sessions,
                c.reconnects,
                c.connected_ms as f64 / 1000.0,
                c.tx_bytes,
                c.rx_bytes
            );
            if let Some(t) = c.first_connect_ms {
                println!("first connected after {:.1}s", t as f64 / 1000.0);
            }
            if let Some(t) = c.direct_ms {
                println!("direct path after {:.1}s", t as f64 / 1000.0);
            }
        }
        // Not the same as "it failed": the process went away before it could
        // say how this ended.
        None => println!("no ending recorded — the process went away mid-run"),
    }
}

// ---------------------------------------------------------------------------
// diagnostic log, bug reports, telemetry

/// The API's name for this OS: `linux`, `macos` or `windows`.
fn platform() -> &'static str {
    spora_service::diag::default_platform()
}

/// Sent with every API request and written into bug reports: the crate
/// version alone would be the same for every build, so the commit rides
/// along as semver build metadata (`0.1.0+0e0d46b04b21.dirty`, well within
/// the registry's 32 characters).
fn app_version() -> String {
    let build = spora_core::record::build_info();
    match build.commit {
        Some(commit) => format!(
            "{}+{}{}",
            build.version,
            commit.chars().take(12).collect::<String>(),
            if build.dirty { ".dirty" } else { "" }
        ),
        None => build.version,
    }
}

/// Whether this process runs as root. Never on Windows, where an elevated
/// console keeps the user's own profile directories.
fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// A root run that a user started with sudo. It keeps its records, log and
/// telemetry state in root's home (see [`state_home`]), so the commands that
/// read them must run with sudo too.
fn sudo_run() -> bool {
    running_as_root() && is_sudo_user(std::env::var_os("SUDO_USER").as_deref())
}

/// `SUDO_USER` names someone other than root: sudo was how they got here.
fn is_sudo_user(sudo_user: Option<&std::ffi::OsStr>) -> bool {
    sudo_user.is_some_and(|u| !u.is_empty() && u != "root")
}

/// `spora <args>` as this run's state is reached: with `sudo` in front when
/// this is a sudo run.
fn spora_cmd(args: &str) -> String {
    if sudo_run() {
        format!("sudo spora {args}")
    } else {
        format!("spora {args}")
    }
}

/// The line a non-root `report` and `telemetry` end with: runs made with
/// sudo keep their state in root's home (see [`state_home`]), which this
/// user can neither read nor change, and which this process cannot even
/// tell exists.
fn sudo_hint(args: &str) {
    if cfg!(unix) && !running_as_root() {
        say!("For runs made with sudo (such as `sudo spora use`), use `sudo spora {args}`.");
    }
}

/// What a non-root run adds when it finds no `what` in its own state: runs
/// made with sudo keep theirs in root's home (see [`state_home`]), where
/// only `sudo spora <args>` looks.
fn sudo_elsewhere(what: &str, args: &str) -> String {
    if cfg!(unix) && !running_as_root() {
        format!("; runs made with sudo keep their {what} in root's home, for `sudo spora {args}`")
    } else {
        String::new()
    }
}

/// What to add to an error about `path` that this non-root run may not
/// touch: in its own state, how to have it back (see [`give_back`]);
/// anywhere else, that it may be root's to read.
fn sudo_cause(e: &std::io::Error, path: &std::path::Path) -> String {
    if let Some(cmd) = give_back(e, path) {
        format!(" (left there by a run with sudo? `{cmd}` gives it back to you)")
    } else if cfg!(unix) && !running_as_root() && e.kind() == std::io::ErrorKind::PermissionDenied {
        " (root's? the same command with sudo reads it)".to_string()
    } else {
        String::new()
    }
}

/// The command that hands this user's state directory back to them, when
/// `e` says this run may not touch `path` in it (see
/// [`give_back_target`]).
fn give_back(e: &std::io::Error, path: &std::path::Path) -> Option<String> {
    let state = give_back_target(e.kind(), path, &state_dir(), running_as_root())?;
    Some(format!(
        "sudo chown -R \"$USER\" {}",
        shell_word(&state.to_string_lossy())
    ))
}

/// The directory to hand back to this user when a non-root run (`root`
/// false) may not touch `path`: all of `state`, this user's own state
/// directory, when `path` is in it. What this user may not touch there was
/// most likely left by a run with sudo, one that kept the user's `HOME` (as
/// spora did before it moved those runs to root's home) or was handed
/// `XDG_STATE_HOME`; handing it back is the fix (`sudo spora` reads root's
/// own state, not this). Anywhere else — root's home, a service's directory
/// named with `--dir` — nothing: those are someone else's, and a recursive
/// change of their owner would hand the user what is not theirs.
fn give_back_target(
    kind: std::io::ErrorKind,
    path: &std::path::Path,
    state: &std::path::Path,
    root: bool,
) -> Option<PathBuf> {
    let theirs = cfg!(unix) && !root && kind == std::io::ErrorKind::PermissionDenied;
    (theirs && path.starts_with(state)).then(|| state.to_path_buf())
}

/// `s` as one shell word, for a command line the user is told to run.
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:@%,=".contains(c));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// An error whose text is the whole message: `main` prints the `Debug` form
/// of what it returns, which for a boxed `String` is quoted and escaped.
struct Plain(String);

impl std::fmt::Debug for Plain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for Plain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Plain {}

/// `--api` if given, else `$SPORA_API` (comma-separated), else nothing: the
/// service's built-in default, which is the production API. A `SPORA_API`
/// that is set but names no address (`SPORA_API=`, a stray comma) is passed
/// on as it is, for the service to refuse as not a URL: it is a development
/// setup gone wrong, and quietly meaning production would send that
/// machine's test runs there. One that is not UTF-8 is just as set: it goes
/// on with U+FFFD for each bad byte, which no base takes.
fn api_bases(flags: &[String], env: Option<&std::ffi::OsStr>) -> Vec<String> {
    if !flags.is_empty() {
        return flags.to_vec();
    }
    let Some(v) = env else {
        return Vec::new();
    };
    let v = v.to_string_lossy();
    let bases: Vec<String> = v
        .split(',')
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(str::to_string)
        .collect();
    if bases.is_empty() {
        vec![v.into_owned()]
    } else {
        bases
    }
}

/// What the uploader sends is always the default directories, whatever a
/// run's `--record-dir` says: every process sharing the state directory must
/// list the same files, or each would prune the others' upload cursors and
/// make them resend.
fn service_config(api: &[String]) -> spora_service::ServiceConfig {
    spora_service::ServiceConfig::new(service_dir(), platform(), app_version())
        .with_record_dir(default_record_dir())
        .with_log_dir(default_diag_dir())
        .with_api_bases(api_bases(api, std::env::var_os("SPORA_API").as_deref()))
}

/// The API this configuration uses (`SPORA_API`, else the built-in one),
/// for reading which registration is its. Building it touches no network;
/// an error when `SPORA_API` does not parse.
fn configured_api() -> Result<spora_service::api::Api, String> {
    let cfg = service_config(&[]);
    spora_service::api::Api::new(&cfg.api_bases, &cfg.app_version)
}

/// The API a registration belongs to, as `telemetry status --json` shows
/// every API: `{"builtin": bool, "bases": [...]}`, the bases being where
/// its token goes. For the built-in API those are this version's built-in
/// addresses, whichever ones the registration was made at; for an
/// override, the addresses that issued the token.
fn registration_api(d: &spora_service::state::Device) -> serde_json::Value {
    if d.builtin {
        serde_json::json!({ "builtin": true, "bases": spora_service::DEFAULT_API_BASES })
    } else {
        serde_json::json!({ "builtin": false, "bases": d.api_bases })
    }
}

/// How `telemetry status` names the API of a registration.
fn registration_api_name(d: &spora_service::state::Device) -> String {
    if d.builtin {
        "the built-in API".to_string()
    } else {
        d.api_bases.join(", ")
    }
}

/// The uploader of a `share`/`use` run. Started whether or not uploads are
/// on: it does nothing while they are off (beyond the daily check of the
/// account's flag for a device registered earlier), and a `spora telemetry
/// on` from another shell then takes effect at its next pass rather than at
/// the next restart. A state directory it cannot use costs the uploads, not
/// the run.
fn start_telemetry() -> Option<&'static spora_service::Telemetry> {
    match spora_service::Telemetry::init_global(service_config(&[])) {
        Ok(t) => Some(t),
        Err(e) => {
            log::warn!(
                "telemetry state in {}: {e}; this run uploads nothing",
                service_dir().display()
            );
            None
        }
    }
}

/// The `share`/`use` banner lines about what is kept and what is sent.
/// `record_dir` is where this run's record goes (`None`: it keeps none).
fn print_diagnostics_banner(
    telemetry: Option<&spora_service::Telemetry>,
    record_dir: Option<&std::path::Path>,
) {
    if let Some(dir) = spora_service::diag::log_dir() {
        say!(
            "Diagnostic log: {} (bundle it for a bug report with `{}`, disable with --no-diag-log)",
            dir.display(),
            spora_cmd("report")
        );
    }
    let Some(t) = telemetry else { return };
    let status = t.status();
    if status.upload_enabled {
        let bases = &t.config().api_bases;
        say!(
            "Telemetry uploads are on{}: diagnostic records, the diagnostic log and crash reports are sent to {} (see `{}`).",
            if status.required {
                ", as your account requires"
            } else {
                ""
            },
            if bases.is_empty() {
                "Spora".to_string()
            } else {
                format!("{} (SPORA_API)", bases.join(", "))
            },
            spora_cmd("telemetry status")
        );
        // Uploads take the default directory only (see service_config).
        if let Some(dir) = record_dir.filter(|d| *d != default_record_dir()) {
            say!(
                "This run's record goes to {}, which is not uploaded; `{}` bundles it.",
                dir.display(),
                spora_cmd(&format!(
                    "report --record-dir {}",
                    shell_word(&dir.to_string_lossy())
                ))
            );
        }
    }
    show_required_notice(t, &status);
}

/// The notice the user is owed once after the account started requiring
/// telemetry (the server's flag switched uploads on without them).
fn show_required_notice(t: &spora_service::Telemetry, status: &spora_service::TelemetryStatus) {
    if status.required_notice_pending {
        say!("{}", spora_service::REQUIRED_NOTICE);
        if let Err(e) = t.acknowledge_notice() {
            log::warn!("telemetry: could not record that the notice was shown: {e}");
        }
    }
}

/// The telemetry state for a `spora telemetry` command.
fn open_telemetry(api: &[String]) -> Result<spora_service::Telemetry, Plain> {
    spora_service::Telemetry::open(service_config(api)).map_err(|e| match e {
        spora_service::Error::Config(e) => Plain(format!("API address (--api or SPORA_API): {e}")),
        spora_service::Error::Io(e) => Plain(format!(
            "telemetry state in {}: {e}{}",
            service_dir().display(),
            sudo_cause(&e, &service_dir())
        )),
        e => Plain(format!(
            "telemetry state in {}: {e}",
            service_dir().display()
        )),
    })
}

fn run_telemetry_cmd(cmd: TelemetryCmd) -> Result<(), Plain> {
    use spora_service::state::{Loaded, ServiceState};
    match cmd {
        TelemetryCmd::Status { json } => {
            // Reading the state creates nothing; a machine that never turned
            // uploads on has no state file and is reported as such. One that
            // cannot be read is an error, never "off".
            let dir = service_dir();
            let (state, loaded) = ServiceState::read(&dir)
                .map_err(|e| Plain(format!("telemetry state: {e}{}", sudo_cause(&e, &dir))))?;
            // As a run here sees it: the registration with the API this
            // configuration uses (the built-in one, or SPORA_API's), and
            // that account's flag. Registrations with other APIs are kept
            // for when theirs is used again and bind nothing here. An API
            // address that does not parse shows the state as stored.
            let configured = configured_api();
            let (status, served) = match &configured {
                Ok(api) => (
                    spora_service::TelemetryStatus::for_api(&state, api),
                    state.served(|d| api.serves(d)),
                ),
                Err(_) => (
                    spora_service::TelemetryStatus::from(&state),
                    state.registration(),
                ),
            };
            let file = ServiceState::path(&dir);
            let others: Vec<spora_service::state::Device> = state
                .registration()
                .into_iter()
                .chain(state.parked.iter().cloned())
                .filter(|r| {
                    served
                        .as_ref()
                        .is_none_or(|s| s.device.token != r.device.token)
                })
                .map(|r| r.device)
                .collect();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "upload_enabled": status.upload_enabled,
                        "required": status.required,
                        "required_notice_pending": status.required_notice_pending,
                        "api": configured.as_ref().ok().map(|api| serde_json::json!({
                            "builtin": api.is_builtin(),
                            "bases": api.bases(),
                        })),
                        "device_id": status.device_id,
                        "device_api": served.as_ref().map(|r| registration_api(&r.device)),
                        "other_device_apis": others.iter().map(registration_api).collect::<Vec<_>>(),
                        "last_upload_unix_ms": status.last_upload_unix_ms,
                        "last_error": status.last_error,
                        "state_file": file,
                    })
                );
                return Ok(());
            }
            println!(
                "uploads      {}",
                if status.upload_enabled { "on" } else { "off" }
            );
            println!(
                "required     {}",
                if status.required {
                    "yes, by your account"
                } else {
                    "no"
                }
            );
            match &configured {
                Ok(api) if api.is_builtin() => {
                    println!("api          built-in ({})", api.bases().join(", "))
                }
                Ok(api) => println!("api          {} (SPORA_API)", api.bases().join(", ")),
                Err(e) => println!("api          SPORA_API is not usable: {e}"),
            }
            match (&status.device_id, &served) {
                (Some(id), Some(r)) if r.device.builtin || !r.device.api_bases.is_empty() => {
                    println!(
                        "device       {id} (registered with {})",
                        registration_api_name(&r.device)
                    )
                }
                (Some(id), _) => println!("device       {id}"),
                (None, _) if others.is_empty() || configured.is_err() => {
                    println!("device       not registered")
                }
                (None, _) => println!("device       not registered with this API"),
            }
            // (A registration from before devices said where they belong
            // goes nowhere, and is not worth a line.)
            for d in others
                .iter()
                .filter(|d| d.builtin || !d.api_bases.is_empty())
            {
                println!(
                    "             also registered with {} (kept for when that API is used again)",
                    registration_api_name(d)
                );
            }
            println!(
                "last upload  {}",
                status
                    .last_upload_unix_ms
                    .map(spora_core::record::utc_timestamp)
                    .unwrap_or_else(|| "never".into())
            );
            println!(
                "last error   {}",
                status.last_error.as_deref().unwrap_or("-")
            );
            println!(
                "state        {}{}",
                file.display(),
                if matches!(loaded, Loaded::Missing) {
                    " (not created yet)"
                } else {
                    ""
                }
            );
            if status.required {
                println!();
                println!("{}", spora_service::REQUIRED_NOTICE);
                if status.required_notice_pending
                    && let Ok(t) = open_telemetry(&[])
                {
                    let _ = t.acknowledge_notice();
                }
            }
            sudo_hint("telemetry status");
        }
        TelemetryCmd::On => {
            let t = open_telemetry(&[])?;
            let was_on = t.status().upload_enabled;
            t.set_upload_enabled(true)
                .map_err(|e| Plain(format!("could not switch uploads on: {e}")))?;
            println!(
                "{}",
                if was_on {
                    "Uploads were already on."
                } else {
                    "Uploads on."
                }
            );
            println!("{UPLOADS_WHAT}");
            println!(
                "`spora share` and `spora use` send in the background (running ones within 15 minutes) and once more as they stop; `spora telemetry upload` sends now; `spora telemetry off` stops it."
            );
            show_required_notice(&t, &t.status());
            sudo_hint("telemetry on");
        }
        TelemetryCmd::Off => {
            let t = open_telemetry(&[])?;
            let mut result = t.set_upload_enabled(false);
            if matches!(result, Err(spora_service::Error::Required)) {
                // The flag on file may be stale: the account may no longer
                // require telemetry. Ask (a request, so it can take a while),
                // then try again on the state as the answer left it, whatever
                // the answer was: a server that no longer knows this device
                // (401) makes it forget the device, and the flag with it.
                println!("Your account required telemetry when last asked; asking again...");
                let _ = t.refresh_status();
                if !t.status().required {
                    result = t.set_upload_enabled(false);
                }
            }
            match result {
                Ok(()) => {}
                Err(spora_service::Error::Required) => {
                    let _ = t.acknowledge_notice();
                    return Err(Plain(spora_service::REQUIRED_NOTICE.to_string()));
                }
                Err(e) => return Err(Plain(format!("could not switch uploads off: {e}"))),
            }
            println!(
                "Uploads off: nothing more is uploaded. Records and logs are still kept on this machine; `spora report` bundles them for a bug report."
            );
            if t.status().device_id.is_some() {
                println!(
                    "Once a day this machine still asks Spora whether its account requires telemetry; deleting {} stops that too (and forgets the registration).",
                    spora_service::state::ServiceState::path(&service_dir()).display()
                );
            }
            sudo_hint("telemetry off");
        }
        TelemetryCmd::Upload { api } => {
            let t = open_telemetry(&api)?;
            let bases = t.api().describe();
            let sum = match t.upload_now() {
                Ok(sum) => sum,
                Err(spora_service::Error::Off) => {
                    return Err(Plain(
                        "uploads are off: turn them on first with `spora telemetry on` (or send a bug report by hand: `spora report`)".into(),
                    ));
                }
                Err(e) => return Err(Plain(format!("upload to {bases} failed: {e}"))),
            };
            let status = t.status();
            if sum.registered {
                println!(
                    "Registered this machine as device {} with {bases}.",
                    status.device_id.as_deref().unwrap_or("-")
                );
            }
            println!("{}", sent_summary(&sum));
            if sum.skipped_files > 0 {
                println!(
                    "{} file(s) could not be sent this time: {}",
                    sum.skipped_files,
                    status.last_error.as_deref().unwrap_or("see the log")
                );
            }
            show_required_notice(&t, &status);
            sudo_hint("telemetry upload");
        }
    }
    Ok(())
}

/// What `spora telemetry upload` says it sent. A pass that halted (uploads
/// switched off by another process meanwhile, say) says so: its numbers are
/// what went before that, not everything there was.
fn sent_summary(sum: &spora_service::PassSummary) -> String {
    const HALTED: &str = "uploads were switched off meanwhile (or the uploader stopped)";
    if sum.chunks == 0 {
        return if sum.halted {
            format!("Nothing was sent: {HALTED}.")
        } else {
            "Nothing new to send.".to_string()
        };
    }
    let sent = format!(
        "Sent {} from {} file(s) in {} request(s); {} of it was new to the server.",
        fmt_bytes(sum.bytes_sent),
        sum.files,
        sum.chunks,
        fmt_bytes(sum.bytes_accepted)
    );
    if sum.halted {
        format!("{sent} The upload stopped there: {HALTED}.")
    } else {
        sent
    }
}

/// What uploads carry, as `spora telemetry on` says it.
const UPLOADS_WHAT: &str = "This machine's diagnostic records, diagnostic log and crash reports are sent to Spora. They show where and how networks block Spora, and help fix problems. They include network addresses: the public address your network shows, the addresses of the peers, relays and other servers this machine connects with, and the address each upload comes from.";

fn run_report(
    out: Option<PathBuf>,
    note: Option<String>,
    hours: u64,
    record_dirs: Vec<PathBuf>,
) -> Result<(), Plain> {
    let out = out.unwrap_or_else(|| {
        PathBuf::from(format!(
            "spora-report-{}.zip",
            file_stamp(std::time::SystemTime::now())
        ))
    });
    let mut opts = spora_service::BundleOptions::new(&out);
    opts.record_dirs = report_record_dirs(record_dirs)?;
    opts.log_dir = Some(default_diag_dir());
    opts.window = std::time::Duration::from_secs(hours * 3600);
    opts.note = note;
    opts.platform = std::collections::BTreeMap::from([
        ("platform".to_string(), platform().to_string()),
        ("app_version".to_string(), app_version()),
    ]);
    // Lets support find what this machine uploaded, if it ever did: its
    // registration with the API this configuration uses, else the active one
    // (as `Telemetry::export_bug_report` picks it).
    let state = spora_service::state::ServiceState::load(&service_dir());
    opts.device_id = configured_api()
        .ok()
        .and_then(|api| state.served(|d| api.serves(d)))
        .map(|r| r.device)
        .or(state.device)
        .map(|d| d.id);
    let sum = spora_service::diag::bundle::export(&opts)
        .map_err(|e| Plain(format!("could not write {}: {e}", out.display())))?;
    let path = std::path::absolute(&sum.path).unwrap_or(sum.path);
    println!("Bug report written to {}", path.display());
    if sum.included_files == 0 {
        let mut looked = vec![state_dir().display().to_string()];
        looked.extend(
            opts.record_dirs[1..]
                .iter()
                .map(|d| d.display().to_string()),
        );
        println!(
            "It holds no records, logs or crash reports: none from the last {hours} hours were found under {}.",
            looked.join(", ")
        );
    } else {
        println!(
            "It holds {} file(s) from the last {hours} hours ({} zipped).",
            sum.included_files,
            fmt_bytes(sum.bytes)
        );
    }
    // The manifest's count of what it left out includes the directories it
    // could not read; they get a line of their own, with why.
    let (unreadable, dir_entries) = unreadable_report_dirs(&opts);
    let dirs: Vec<String> = unreadable
        .iter()
        .map(|(dir, e)| format!("{}: {e}", dir.display()))
        .collect();
    let files = sum.omitted_files.saturating_sub(dir_entries);
    if let Some(text) = left_out_text(files, sum.included_files > 0, &dirs) {
        println!("{text}");
    }
    let mut give_backs: Vec<String> = Vec::new();
    for cmd in unreadable.iter().filter_map(|(dir, e)| give_back(e, dir)) {
        if !give_backs.contains(&cmd) {
            println!("Left there by a run with sudo? `{cmd}` gives it back to you.");
            give_backs.push(cmd);
        }
    }
    // The zip is readable by its owner only, and the owner of a sudo run's
    // is root. Handing it over is left to the user: a root process changing
    // ownership in a directory the user controls could be steered onto
    // another file.
    if sudo_run()
        && let Some(user) = std::env::var_os("SUDO_USER")
    {
        println!(
            "It belongs to root: `sudo chown {} {}` lets you attach it from your own account.",
            shell_word(&user.to_string_lossy()),
            shell_word(&path.to_string_lossy())
        );
    }
    println!("Email it to support@spora.to");
    sudo_hint("report");
    Ok(())
}

/// The directories of a bug report that could not be read in full, each
/// with why, and how many entries of its manifest they make: the bundle
/// lists one per kind of file whose directory it could not read (`records/`
/// for any number of record directories; `crash/` and `log/` for the log
/// directory), and counts them with the files it left out.
fn unreadable_report_dirs(
    opts: &spora_service::BundleOptions,
) -> (Vec<(PathBuf, std::io::Error)>, u32) {
    let mut dirs = Vec::new();
    let mut entries = 0;
    for dir in &opts.record_dirs {
        if let Err(e) = list_in_full(dir) {
            dirs.push((dir.clone(), e));
            entries = 1;
        }
    }
    if let Some(dir) = &opts.log_dir
        && let Err(e) = list_in_full(dir)
    {
        dirs.push((dir.clone(), e));
        entries += 2;
    }
    (dirs, entries)
}

/// Whether `dir` lists in full, as a bug report lists it: every entry and
/// its metadata. A directory that is not there is no error, just empty.
fn list_in_full(dir: &std::path::Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        match entry?.metadata() {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// What `spora report` says its manifest lists as left out: `files` files
/// (`more` of them, next to some included) and the directories it could not
/// read, each already put as `<dir>: <why>`. Nothing when nothing was.
fn left_out_text(files: u32, more: bool, dirs: &[String]) -> Option<String> {
    let files = (files > 0).then(|| format!("{files} {}file(s)", if more { "more " } else { "" }));
    let unread = match dirs.len() {
        0 => None,
        1 => Some("a directory it could not read".to_string()),
        n => Some(format!("{n} directories it could not read")),
    };
    let what = match (files, unread) {
        (None, None) => return None,
        (Some(f), None) => f,
        (None, Some(d)) => d,
        (Some(f), Some(d)) => format!("{f} and {d}"),
    };
    let mut text = format!("Its manifest.json lists {what} as left out, with the reason");
    if dirs.is_empty() {
        text.push('.');
    } else {
        text.push(':');
        for d in dirs {
            text.push_str("\n  ");
            text.push_str(d);
        }
    }
    Some(text)
}

/// The record directories a bug report bundles: the default one always, and
/// those a run's `--record-dir` pointed at when asked for (a bundle keeps no
/// upload cursors, so any directory will do). A named directory that does
/// not exist is an error: likely a typo, which would otherwise make a report
/// silently without its records. One that cannot be looked at is kept: the
/// report then lists it as a directory it could not read, with why.
fn report_record_dirs(extra: Vec<PathBuf>) -> Result<Vec<PathBuf>, Plain> {
    let mut dirs = vec![default_record_dir()];
    for dir in extra {
        if dirs.contains(&dir) {
            continue;
        }
        match std::fs::metadata(&dir) {
            Ok(m) if !m.is_dir() => {
                return Err(Plain(format!(
                    "--record-dir {}: not a directory",
                    dir.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Plain(format!(
                    "--record-dir {}: no such directory",
                    dir.display()
                )));
            }
            _ => dirs.push(dir),
        }
    }
    Ok(dirs)
}

/// `20261019T120000Z`: sorts by time, and is a valid file name everywhere.
fn file_stamp(t: std::time::SystemTime) -> String {
    humantime::format_rfc3339_seconds(t)
        .to_string()
        .replace(['-', ':'], "")
}

fn fmt_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    let f = n as f64;
    if f < KIB {
        format!("{n} B")
    } else if f < KIB * KIB {
        format!("{:.1} KiB", f / KIB)
    } else {
        format!("{:.1} MiB", f / (KIB * KIB))
    }
}

/// The stop signals of a `share`/`use` run, watched from its start to its
/// exit: SIGINT (Ctrl+C), SIGTERM (`systemctl stop`, `kill`) and SIGHUP (the
/// terminal closed, the SSH session dropped) on Unix; Ctrl+C, Ctrl+Break and
/// the console's close, logoff and shutdown events on Windows, which give a
/// few seconds' grace. Watched from the start, no signal ever takes its
/// default action — killing the process on the spot — while the run sets
/// up, dials, stops or sends its last upload: the first one stops the run
/// wherever it is, and the run still closes its record, puts the host's
/// routes and resolver back (`--os-routing`'s rules too) and flushes its
/// log. Each signal is counted, so one that comes during teardown is not
/// lost: the second skips the last upload (see [`final_upload`]), and the
/// third ends the process at once, cleanup or not, for a run stuck where
/// no stop request reaches it (a name lookup that hangs, a teardown that
/// does).
#[derive(Clone)]
struct Shutdown {
    signals: tokio::sync::watch::Receiver<u32>,
}

/// The signal count at which [`Shutdown`] stops waiting for the run.
const SIGNALS_TO_EXIT_AT_ONCE: u32 = 3;

impl Shutdown {
    /// Start watching; the handlers are in place when this returns.
    fn watch() -> std::io::Result<Shutdown> {
        let (tx, signals) = tokio::sync::watch::channel(0u32);
        let seen = move |name: &str| {
            let mut n = 0;
            tx.send_modify(|count| {
                *count += 1;
                n = *count;
            });
            match n {
                1 => log::debug!("{name}: stopping"),
                SIGNALS_TO_EXIT_AT_ONCE => {
                    log::warn!("{name}, the third stop signal: exiting now, without cleaning up");
                    spora_service::diag::flush(std::time::Duration::from_millis(500));
                    std::process::exit(130);
                }
                _ => log::debug!("{name} again ({n} so far)"),
            }
        };
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut int = signal(SignalKind::interrupt())?;
            let mut term = signal(SignalKind::terminate())?;
            let mut hup = signal(SignalKind::hangup())?;
            tokio::spawn(async move {
                loop {
                    let name = tokio::select! {
                        Some(()) = int.recv() => "SIGINT",
                        Some(()) = term.recv() => "SIGTERM",
                        Some(()) = hup.recv() => "SIGHUP",
                        else => return,
                    };
                    seen(name);
                }
            });
        }
        #[cfg(windows)]
        {
            use tokio::signal::windows::{
                ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown,
            };
            let mut int = ctrl_c()?;
            let mut brk = ctrl_break()?;
            let mut close = ctrl_close()?;
            let mut logoff = ctrl_logoff()?;
            let mut shutdown = ctrl_shutdown()?;
            tokio::spawn(async move {
                loop {
                    let name = tokio::select! {
                        Some(()) = int.recv() => "Ctrl+C",
                        Some(()) = brk.recv() => "Ctrl+Break",
                        Some(()) = close.recv() => "console close",
                        Some(()) = logoff.recv() => "logoff",
                        Some(()) = shutdown.recv() => "system shutdown",
                        else => return,
                    };
                    seen(name);
                }
            });
        }
        #[cfg(not(any(unix, windows)))]
        tokio::spawn(async move {
            while tokio::signal::ctrl_c().await.is_ok() {
                seen("Ctrl+C");
            }
        });
        Ok(Shutdown { signals })
    }

    /// The signals seen so far.
    fn count(&self) -> u32 {
        *self.signals.borrow()
    }

    /// Until the `n`th signal; at once if it came already.
    async fn signal(&self, n: u32) {
        let mut signals = self.signals.clone();
        let gone = signals.wait_for(|count| *count >= n).await.is_err();
        if gone {
            // The watcher has stopped (the runtime is going away): no
            // signal is coming.
            std::future::pending::<()>().await;
        }
    }

    /// Until the first signal: the run is to stop.
    async fn requested(&self) {
        self.signal(1).await
    }
}

#[cfg(not(windows))]
fn config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("spora")
}

#[cfg(windows)]
fn config_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("spora")
}

fn default_share_path() -> PathBuf {
    config_dir().join("share.bin")
}

/// A new share on Spora's relays (fetching them, with a relay token, when
/// none are cached yet).
fn spora_relays_share(
    service: &spora_service::Telemetry,
) -> Result<Share, Box<dyn std::error::Error>> {
    if service.relay_access_status().advised.is_empty() {
        tokio::task::block_in_place(|| service.refresh_relays()).map_err(|e| {
            format!(
                "cannot get Spora's relays from its API ({e}); pass --relay to share through a relay of your own"
            )
        })?;
    }
    Ok(service.make_share(Vec::new(), true)?)
}

/// The share at `path`, or a new one (written there) when there is none,
/// `fresh` asks for one, it was made under another device, or `relays` (the
/// relay flags, if any were given) are not the ones it was made with: the
/// relays are in the URL, so other relays are another share. A new share
/// without relay flags is `default_share`'s.
fn load_or_make_share(
    path: &std::path::Path,
    fresh: bool,
    device: &DeviceIdentity,
    relays: Option<Vec<RelayEntry>>,
    default_share: &mut dyn FnMut() -> Result<Share, Box<dyn std::error::Error>>,
) -> Result<Share, Box<dyn std::error::Error>> {
    if !fresh && let Ok(bytes) = std::fs::read(path) {
        let why_new = match Share::from_blob(&bytes) {
            Err(e) => Some(format!("it cannot be read ({e})")),
            Ok(share) if share.cert_hash != device.cert_hash() => {
                Some("it was made under another device identity".to_string())
            }
            Ok(share) => match &relays {
                Some(wanted) if *wanted != share.relays => {
                    Some("the relays given are not the ones it was made with".to_string())
                }
                _ => return Ok(share),
            },
        };
        if let Some(why) = why_new {
            say!(
                "Making a new share (a new URL) in place of the one at {}: {why}.",
                path.display()
            );
        }
    }
    let share = match relays {
        Some(relays) => Share::new(device, relays)?,
        None => default_share()?,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private_atomically(path, &share.to_blob())?;
    Ok(share)
}

/// Persist a private file (the device key, a share's secret) durably and
/// privately.
///
/// `std::fs::write` truncates-then-writes in place: a crash or power loss
/// mid-write leaves a torn file, which then fails to parse on every later
/// launch — costing the user their stable URL. It also
/// creates the file with the umask (typically world-/group-readable) and only
/// chmods afterward, leaving a window where the private key is exposed.
///
/// Instead, write to a sibling temp file created `0600` from the start, fsync
/// it, then atomically rename over the target: a reader (and a crash) sees
/// either the old file or the complete new one, never a truncated mix, and the
/// key bytes are never group/world-readable.
#[cfg(unix)]
fn write_private_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("share.bin");
    // Per-process temp name so a concurrent writer can't clobber our partial
    // file before the rename.
    let tmp = dir.join(format!(".{}.{}.tmp", stem, std::process::id()));

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    let res = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Windows: the same temp-file-then-rename, without a POSIX mode (the file
/// inherits the profile directory's ACL, which is per-user).
#[cfg(windows)]
fn write_private_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("share.bin");
    let tmp = dir.join(format!(".{}.{}.tmp", stem, std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    let res = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| {
            drop(f);
            // `rename` does not replace an existing file on Windows.
            let _ = std::fs::remove_file(path);
            std::fs::rename(&tmp, path)
        });
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(all(test, unix))]
mod identity_persistence_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A unique scratch dir under the temp dir (no tempfile dependency).
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spora-cli-test-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn relay(port: u16) -> Vec<RelayEntry> {
        vec![RelayEntry::open(spora_core::identity::RelayEndpoint::new(
            "127.0.0.1",
            port,
        ))]
    }

    /// A share over `relay(9)` of `device`, standing in for one on
    /// Spora's relays.
    fn spora_default(
        device: &DeviceIdentity,
    ) -> impl FnMut() -> Result<Share, Box<dyn std::error::Error>> + '_ {
        move || Ok(Share::new(device, relay(9))?)
    }

    #[test]
    fn a_created_share_is_private_and_round_trips() {
        let dir = scratch("create");
        let path = dir.join("share.bin");
        let device = DeviceIdentity::generate();

        let share =
            load_or_make_share(&path, false, &device, None, &mut spora_default(&device)).unwrap();
        assert_eq!(share.relays, relay(9), "no relay flags: the default share");

        // The secret must never be group/world readable, even briefly.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the share file must be 0600");

        // Loading again returns the SAME share, not a new one, and never
        // asks for a default.
        let mut never = || -> Result<Share, Box<dyn std::error::Error>> {
            panic!("a stored share needs no default")
        };
        let again = load_or_make_share(&path, false, &device, None, &mut never).unwrap();
        assert_eq!(again, share, "the share must be stable across launches");
        assert_eq!(again.url(), share.url());

        // The same relay flags keep it too.
        let given = load_or_make_share(
            &path,
            false,
            &device,
            Some(share.relays.clone()),
            &mut never,
        )
        .unwrap();
        assert_eq!(given, share);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn other_relays_fresh_or_another_device_make_a_new_share() {
        let dir = scratch("renew");
        let path = dir.join("share.bin");
        let device = DeviceIdentity::generate();
        let mut default = spora_default(&device);
        let first =
            load_or_make_share(&path, false, &device, Some(relay(1)), &mut default).unwrap();

        let moved =
            load_or_make_share(&path, false, &device, Some(relay(2)), &mut default).unwrap();
        assert_ne!(
            moved.share_id, first.share_id,
            "other relays: another share"
        );
        assert_eq!(moved.relays, relay(2));
        // ...and it is now the stored one.
        assert_eq!(
            load_or_make_share(&path, false, &device, None, &mut default).unwrap(),
            moved
        );

        let fresh = load_or_make_share(&path, true, &device, None, &mut default).unwrap();
        assert_ne!(fresh.share_id, moved.share_id, "--fresh: another share");
        assert_eq!(
            fresh.relays,
            relay(9),
            "without relay flags: the default share"
        );

        let other = DeviceIdentity::generate();
        let rebuilt =
            load_or_make_share(&path, false, &other, None, &mut spora_default(&other)).unwrap();
        assert_eq!(
            rebuilt.cert_hash,
            other.cert_hash(),
            "made under the device in use"
        );

        std::fs::write(&path, b"garbage").unwrap();
        let recovered = load_or_make_share(&path, false, &device, None, &mut default).unwrap();
        assert_eq!(recovered.cert_hash, device.cert_hash());

        // A default that cannot be made (no API) is the error, and the
        // stored share is left as it was.
        let mut failing = || -> Result<Share, Box<dyn std::error::Error>> { Err("no API".into()) };
        let before = std::fs::read(&path).unwrap();
        assert!(load_or_make_share(&path, true, &device, None, &mut failing).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_write_replaces_without_leaving_a_temp() {
        let dir = scratch("atomic");
        let path = dir.join("share.bin");

        write_private_atomically(&path, b"first-version").unwrap();
        write_private_atomically(&path, b"second-version-which-is-longer").unwrap();

        // The final file holds the complete new content (never a torn mix)...
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"second-version-which-is-longer"
        );
        // ...and the rename consumed the temp — no `.share.bin.<pid>.tmp` litter.
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "temp file leaked: {:?}", leftover);

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(all(test, unix))]
mod state_dir_tests {
    use super::*;

    fn env(xdg: Option<&str>, home: Option<&str>, sudo_user: Option<&str>, root: bool) -> StateEnv {
        StateEnv {
            xdg_state_home: xdg.map(Into::into),
            home: home.map(Into::into),
            sudo_user: sudo_user.map(Into::into),
            root,
        }
    }

    fn home_of(e: StateEnv) -> PathBuf {
        state_home(e, || PathBuf::from("/var/root"))
    }

    #[test]
    fn a_users_own_run_keeps_its_state_in_its_home() {
        assert_eq!(
            home_of(env(None, Some("/home/u"), None, false)),
            PathBuf::from("/home/u/.local/state")
        );
        // SUDO_USER alone, as a shell started from sudo passes it on to
        // its children, is not a run with sudo.
        assert_eq!(
            home_of(env(None, Some("/home/u"), Some("u"), false)),
            PathBuf::from("/home/u/.local/state")
        );
        assert_eq!(home_of(env(None, None, None, false)), PathBuf::from("."));
        assert_eq!(
            home_of(env(None, Some(""), None, false)),
            PathBuf::from(".")
        );
    }

    #[test]
    fn a_run_with_sudo_keeps_its_state_in_roots_home() {
        // HOME as sudo keeps it on macOS (and with `sudo -E`): the user's.
        for home in [Some("/Users/u"), Some("/var/root"), None] {
            assert_eq!(
                home_of(env(None, home, Some("u"), true)),
                PathBuf::from("/var/root/.local/state"),
                "HOME={home:?}"
            );
        }
        // Root's own runs (a root login, `su`, a service) go by HOME.
        for sudo_user in [None, Some(""), Some("root")] {
            assert_eq!(
                home_of(env(None, Some("/root"), sudo_user, true)),
                PathBuf::from("/root/.local/state"),
                "SUDO_USER={sudo_user:?}"
            );
        }
    }

    #[test]
    fn root_home_is_only_asked_for_under_sudo() {
        for e in [
            env(None, Some("/home/u"), None, false),
            env(None, Some("/root"), None, true),
            env(Some("/srv/state"), Some("/Users/u"), Some("u"), true),
        ] {
            state_home(e, || panic!("asked for root's home"));
        }
    }

    #[test]
    fn xdg_state_home_wins_when_it_is_a_path() {
        for (sudo_user, root) in [(None, false), (Some("u"), true)] {
            assert_eq!(
                home_of(env(Some("/srv/state"), Some("/home/u"), sudo_user, root)),
                PathBuf::from("/srv/state")
            );
        }
        // Empty or relative: unset, as the XDG spec has it.
        for xdg in ["", "state"] {
            assert_eq!(
                home_of(env(Some(xdg), Some("/home/u"), None, false)),
                PathBuf::from("/home/u/.local/state")
            );
            assert_eq!(
                home_of(env(Some(xdg), Some("/Users/u"), Some("u"), true)),
                PathBuf::from("/var/root/.local/state")
            );
        }
    }

    #[test]
    fn root_home_comes_from_the_password_database() {
        let home = root_home();
        assert!(home.is_absolute(), "{}", home.display());
        if cfg!(target_os = "linux") && std::path::Path::new("/etc/passwd").exists() {
            let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
            if let Some(dir) = passwd
                .lines()
                .map(|l| l.split(':').collect::<Vec<_>>())
                .find(|f| f.len() > 5 && f[2] == "0")
                .map(|f| f[5].to_string())
            {
                assert_eq!(home, PathBuf::from(dir));
            }
        }
    }

    #[test]
    fn every_state_path_is_under_the_state_dir() {
        let state = state_dir();
        assert_eq!(state.file_name().unwrap(), "spora");
        for dir in [
            default_record_dir(),
            default_diag_dir(),
            service_dir(),
            connlog_base_dir(),
        ] {
            assert_eq!(dir.parent(), Some(state.as_path()), "{}", dir.display());
        }
        let config = service_config(&[]);
        assert_eq!(config.state_dir, service_dir());
        assert_eq!(config.record_dirs, [default_record_dir()]);
        assert_eq!(config.log_dir, Some(default_diag_dir()));
    }

    /// A user's own run that finds nothing in its own state says where runs
    /// made with sudo keep theirs; a directory it was pointed at is only
    /// that directory.
    #[test]
    fn finding_nothing_points_at_runs_made_with_sudo() {
        if running_as_root() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("spora-cli-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let e = load_records(Some(dir.clone()), 1, "record list").unwrap_err();
        assert_eq!(
            e,
            format!(
                "no records at {} (run with recording on, or pass --dir)",
                dir.display()
            )
        );
        assert_eq!(
            sudo_elsewhere("records", "record list"),
            "; runs made with sudo keep their records in root's home, for `sudo spora record list`"
        );

        let note = sudo_elsewhere("connection log", "log query");
        let e = resolve_connlog_dir(None, Some(dir.join("share.bin")), "log query").unwrap_err();
        assert!(e.ends_with(&format!("pass --dir explicitly{note}")), "{e}");
        // A share whose log was never written (in this process's state
        // directory, which this only reads).
        std::fs::create_dir_all(&dir).unwrap();
        let device = DeviceIdentity::generate();
        let share = Share::open(
            &device,
            vec![spora_core::identity::RelayEndpoint::new("127.0.0.1", 1)],
        )
        .unwrap();
        std::fs::write(dir.join("share.bin"), share.to_blob()).unwrap();
        let e = resolve_connlog_dir(None, Some(dir.join("share.bin")), "log query").unwrap_err();
        assert_eq!(
            e,
            format!(
                "no connection log at {} (pass --dir{note})",
                default_connlog_dir(&share.routing_hash()).display()
            )
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The chown advice hands back this user's own state directory, and
    /// only for a path in it: never root's home, a service's directory or
    /// anything else a command was pointed at.
    #[test]
    fn only_the_users_own_state_is_handed_back() {
        use std::io::ErrorKind::{NotFound, PermissionDenied};
        let state = std::path::Path::new("/home/u/.local/state/spora");
        let give = |kind, path: &str, root| {
            give_back_target(kind, std::path::Path::new(path), state, root)
        };
        for path in [
            "/home/u/.local/state/spora",
            "/home/u/.local/state/spora/records",
            "/home/u/.local/state/spora/connlog/00ff",
        ] {
            assert_eq!(
                give(PermissionDenied, path, false),
                Some(state.to_path_buf()),
                "{path}"
            );
        }
        for path in [
            "/root",
            "/root/.local/state/spora/records",
            "/var/lib/spora-use/records",
            "/home/u",
            "/home/u/.local/state/spora-old/records",
        ] {
            assert_eq!(give(PermissionDenied, path, false), None, "{path}");
        }
        let records = "/home/u/.local/state/spora/records";
        assert_eq!(give(NotFound, records, false), None);
        assert_eq!(give(PermissionDenied, records, true), None, "root reads it");

        if running_as_root() {
            return;
        }
        let denied = || std::io::Error::from(PermissionDenied);
        assert_eq!(
            sudo_cause(&denied(), std::path::Path::new("/root")),
            " (root's? the same command with sudo reads it)"
        );
        assert_eq!(
            sudo_cause(&denied(), &default_record_dir()),
            format!(
                " (left there by a run with sudo? `sudo chown -R \"$USER\" {}` gives it back to you)",
                shell_word(&state_dir().to_string_lossy())
            )
        );
        assert_eq!(
            sudo_cause(&std::io::Error::from(NotFound), &default_record_dir()),
            ""
        );
    }
}

#[cfg(test)]
mod dns_upstream_tests {
    use super::*;

    #[test]
    fn parse_resolver_accepts_literals_only() {
        assert_eq!(
            parse_resolver("192.168.1.1").unwrap(),
            "192.168.1.1:53".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_resolver("10.0.0.1:5353").unwrap(),
            "10.0.0.1:5353".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_resolver("2606:4700:4700::1111").unwrap(),
            "[2606:4700:4700::1111]:53"
                .parse::<std::net::SocketAddr>()
                .unwrap()
        );
        assert_eq!(
            parse_resolver("[::1]:5300").unwrap(),
            "[::1]:5300".parse::<std::net::SocketAddr>().unwrap()
        );
        assert!(parse_resolver("dns.google").is_err(), "no hostnames");
        assert!(parse_resolver("").is_err());
    }

    #[test]
    fn dns_forwarder_config_modes() {
        use spora_core::dns::DnsUpstream;
        assert!(dns_forwarder_config(&[], true).unwrap().is_none());
        let system = dns_forwarder_config(&[], false).unwrap().unwrap();
        assert_eq!(system.mode(), DnsUpstream::System);
        assert!(
            !system.fallback().is_empty(),
            "system mode falls back to public resolvers"
        );
        let explicit = dns_forwarder_config(&["9.9.9.9".into()], false)
            .unwrap()
            .unwrap();
        assert_eq!(
            explicit.mode(),
            DnsUpstream::Servers(vec!["9.9.9.9:53".parse().unwrap()])
        );
        assert!(
            explicit.fallback().is_empty(),
            "an explicit list is used exclusively"
        );
        assert!(dns_forwarder_config(&["nope".into()], false).is_err());
    }
}

#[cfg(test)]
mod automation_surface_tests {
    use super::*;

    #[test]
    fn use_accepts_named_tun_json_and_direct_upgrade_control() {
        let args = Args::try_parse_from([
            "spora",
            "use",
            "https://spora.to/s/token?r=127.0.0.1:443",
            "--tun-name",
            "splab-deadbeef",
            "--no-direct-upgrade",
            "--json",
            "--record-id",
            "attempt-1",
            "--stun",
            "first.example:3478",
            "--stun",
            "second.example:53",
        ])
        .unwrap();
        match args.mode {
            Mode::Use {
                tun_name,
                no_direct_upgrade,
                json,
                record_id,
                stun,
                ..
            } => {
                assert_eq!(tun_name.as_deref(), Some("splab-deadbeef"));
                assert!(no_direct_upgrade);
                assert!(json);
                assert_eq!(record_id.as_deref(), Some("attempt-1"));
                assert_eq!(stun, ["first.example:3478", "second.example:53"]);
            }
            _ => panic!("parsed the wrong command"),
        }
    }

    #[test]
    fn build_info_has_machine_readable_mode() {
        let args = Args::try_parse_from(["spora", "build-info", "--json"]).unwrap();
        assert!(matches!(args.mode, Mode::BuildInfo { json: true }));
    }

    #[test]
    fn tunnel_events_have_machine_readable_path_notifications() {
        let activated = tunnel_event_json(spora_core::TunnelEvent::PathActivated {
            carrier: spora_core::record::Carrier::NoiseUdp,
            path: spora_core::record::PathKind::DirectPunched,
            local: Some("192.0.2.1:1234".parse().unwrap()),
            peer: "198.51.100.2:4321".parse().unwrap(),
        });
        assert_eq!(activated["event"], "path_activated");
        assert_eq!(activated["carrier"], "nz");
        assert_eq!(activated["path"], "direct_punched");

        let direct = tunnel_event_json(spora_core::TunnelEvent::DirectUpgradeSucceeded {
            local: "192.0.2.1:1234".parse().unwrap(),
            peer: "198.51.100.2:4321".parse().unwrap(),
        });
        assert_eq!(direct["event"], "direct_upgrade_succeeded");
        assert_eq!(direct["peer"], "198.51.100.2:4321");

        let failed = tunnel_event_json(spora_core::TunnelEvent::DirectUpgradeFailed {
            code: spora_core::record::Reason::StunTimeout,
            reason: "STUN did not answer".into(),
        });
        assert_eq!(failed["event"], "direct_upgrade_failed");
        assert_eq!(failed["code"], "stun_timeout");
    }
}

#[cfg(test)]
mod diagnostics_tests {
    use super::*;

    #[test]
    fn long_running_modes_can_skip_the_diag_log() {
        for mode in ["share", "use"] {
            let mut argv = vec!["spora", mode];
            if mode == "use" {
                argv.push("https://spora.to/s/token?r=127.0.0.1:443");
            }
            let default = Args::try_parse_from(&argv).unwrap();
            argv.push("--no-diag-log");
            let skipped = Args::try_parse_from(&argv).unwrap();
            for (args, want) in [(default, false), (skipped, true)] {
                match args.mode {
                    Mode::Share { no_diag_log, .. } | Mode::Use { no_diag_log, .. } => {
                        assert_eq!(no_diag_log, want, "{mode}")
                    }
                    _ => panic!("parsed the wrong command"),
                }
            }
        }
        assert!(
            Args::try_parse_from(["spora", "record", "list", "--no-diag-log"]).is_err(),
            "one-shot commands keep no log file to skip"
        );
    }

    #[test]
    fn report_defaults_and_limits() {
        let args = Args::try_parse_from(["spora", "report"]).unwrap();
        match args.mode {
            Mode::Report {
                out: None,
                note: None,
                hours: 72,
                record_dir,
            } => assert!(record_dir.is_empty()),
            _ => panic!("parsed the wrong command"),
        }
        let args = Args::try_parse_from([
            "spora",
            "report",
            "-o",
            "r.zip",
            "--note",
            "it broke",
            "--hours",
            "6",
            "--record-dir",
            "/var/lib/spora-share/records",
            "--record-dir",
            "runs",
        ])
        .unwrap();
        match args.mode {
            Mode::Report {
                out,
                note,
                hours,
                record_dir,
            } => {
                assert_eq!(out, Some(PathBuf::from("r.zip")));
                assert_eq!(note.as_deref(), Some("it broke"));
                assert_eq!(hours, 6);
                assert_eq!(
                    record_dir,
                    [
                        PathBuf::from("/var/lib/spora-share/records"),
                        PathBuf::from("runs")
                    ]
                );
            }
            _ => panic!("parsed the wrong command"),
        }
        assert!(Args::try_parse_from(["spora", "report", "--hours", "0"]).is_err());
    }

    /// A run's `--record-dir` is not uploaded, but a bug report can carry
    /// it, next to the default directory's records.
    #[test]
    fn report_bundles_extra_record_dirs() {
        let dir = std::env::temp_dir().join(format!("spora-cli-report-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let extra = dir.join("runs");
        std::fs::create_dir_all(&extra).unwrap();
        assert_eq!(
            report_record_dirs(vec![extra.clone(), default_record_dir(), extra.clone()]).unwrap(),
            [default_record_dir(), extra],
            "the default first, each directory once"
        );
        let missing = dir.join("missing");
        assert_eq!(
            report_record_dirs(vec![missing.clone()]).unwrap_err().0,
            format!("--record-dir {}: no such directory", missing.display()),
            "a directory that is not there is an error, not an empty report"
        );
        let file = dir.join("file");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            report_record_dirs(vec![file.clone()]).unwrap_err().0,
            format!("--record-dir {}: not a directory", file.display())
        );
        // One that cannot even be looked at is the report's to list as
        // unreadable, with why; it is no typo.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let closed = dir.join("closed");
            let inside = closed.join("records");
            std::fs::create_dir_all(&inside).unwrap();
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
            let looked = std::fs::metadata(&inside).is_ok();
            let dirs = report_record_dirs(vec![inside.clone()]);
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
            if !looked {
                assert_eq!(dirs.unwrap(), [default_record_dir(), inside]);
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// stderr's own filter keeps off what no sink may get (ureq-proto's
    /// dump of the raw request, bearer token included) under a blanket or
    /// same-target `RUST_LOG`, and `main`'s closing line, which `main`'s
    /// caller prints already. (A more specific directive outranks it; the
    /// composite logger's withholding covers that, see tests/process.rs.)
    #[test]
    fn stderr_withholds_what_no_sink_may_get() {
        use log::{Level, Log as _, Metadata};
        for filters in ["trace", "trace,ureq_proto=trace"] {
            let mut b = env_logger::Builder::new();
            b.parse_filters(filters);
            quieten_stderr(&mut b);
            let logger = b.build();
            let at = |target: &str| {
                logger.enabled(
                    &Metadata::builder()
                        .target(target)
                        .level(Level::Trace)
                        .build(),
                )
            };
            for t in spora_service::diag::WITHHELD_TARGETS {
                assert!(!at(t), "{t} under RUST_LOG={filters}");
                assert!(!at(&format!("{t}::util")), "{t} under RUST_LOG={filters}");
            }
            assert!(!at(EXIT_LOG_TARGET), "under RUST_LOG={filters}");
            assert!(at("spora_core"), "everything else stays as RUST_LOG says");
        }
    }

    #[test]
    fn app_version_names_the_build_and_fits_the_registry() {
        let v = app_version();
        assert!(v.starts_with(env!("CARGO_PKG_VERSION")), "{v}");
        assert!(v.len() <= 32, "{v} is longer than the registry's column");
        if let Some(commit) = spora_core::record::build_info().commit {
            assert!(v.contains(&commit[..commit.len().min(12)]), "{v}");
        }
    }

    #[test]
    fn suggested_command_lines_quote_what_needs_it() {
        assert_eq!(
            shell_word("/var/lib/spora/records"),
            "/var/lib/spora/records"
        );
        assert_eq!(shell_word("my runs"), "'my runs'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word(""), "''");
    }

    #[test]
    fn telemetry_commands_parse() {
        for (sub, want) in [
            ("status", "status"),
            ("on", "on"),
            ("off", "off"),
            ("upload", "upload"),
        ] {
            let args = Args::try_parse_from(["spora", "telemetry", sub]).unwrap();
            let got = match args.mode {
                Mode::Telemetry { cmd } => match cmd {
                    TelemetryCmd::Status { json: false } => "status",
                    TelemetryCmd::On => "on",
                    TelemetryCmd::Off => "off",
                    TelemetryCmd::Upload { api } if api.is_empty() => "upload",
                    other => panic!("unexpected {other:?}"),
                },
                _ => panic!("parsed the wrong command"),
            };
            assert_eq!(got, want);
        }
        let args = Args::try_parse_from([
            "spora",
            "telemetry",
            "upload",
            "--api",
            "https://a.example",
            "--api",
            "https://b.example",
        ])
        .unwrap();
        match args.mode {
            Mode::Telemetry {
                cmd: TelemetryCmd::Upload { api },
            } => assert_eq!(api, ["https://a.example", "https://b.example"]),
            _ => panic!("parsed the wrong command"),
        }
        assert!(
            Args::try_parse_from(["spora", "telemetry", "status", "--json"]).is_ok(),
            "status has a machine-readable mode"
        );
    }

    #[test]
    fn api_flag_beats_env_beats_default() {
        let env = Some(std::ffi::OsStr::new(
            " https://env-a.example , https://env-b.example,",
        ));
        assert_eq!(
            api_bases(&["https://flag.example".into()], env),
            ["https://flag.example"]
        );
        assert_eq!(
            api_bases(&[], env),
            ["https://env-a.example", "https://env-b.example"]
        );
        assert!(
            api_bases(&[], None).is_empty(),
            "unset means the service default"
        );
        // Set but empty is a broken setup, not production.
        for env in ["", " , "] {
            let bases = api_bases(&[], Some(env.as_ref()));
            assert_eq!(bases, [env]);
            assert!(
                spora_service::api::Api::new(&bases, "test").is_err(),
                "{env:?} must be refused"
            );
        }
    }

    /// A `SPORA_API` that is not UTF-8 is set, not unset: it never means
    /// the built-in (production) API, wherever the bad byte sits.
    #[cfg(unix)]
    #[test]
    fn a_spora_api_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStrExt as _;
        for env in [
            &b"\xff"[..],
            b"http://127.0.0.1:9\xff",
            b"http://127.0.0.1:9/\xff",
            b"http://127.0.0.1:9,http://127.0.0.1:8\xff",
        ] {
            let env = std::ffi::OsStr::from_bytes(env);
            let bases = api_bases(&[], Some(env));
            assert!(!bases.is_empty(), "{env:?} read as unset");
            assert!(
                spora_service::api::Api::new(&bases, "test").is_err(),
                "{env:?} must be refused"
            );
        }
    }

    /// Files and directories the manifest leaves out are counted apart, and
    /// each directory is named with why.
    #[test]
    fn report_words_files_and_directories_apart() {
        assert_eq!(left_out_text(0, true, &[]), None);
        assert_eq!(
            left_out_text(2, true, &[]).unwrap(),
            "Its manifest.json lists 2 more file(s) as left out, with the reason."
        );
        assert_eq!(
            left_out_text(1, false, &[]).unwrap(),
            "Its manifest.json lists 1 file(s) as left out, with the reason."
        );
        assert_eq!(
            left_out_text(0, false, &["/s/log: denied".into()]).unwrap(),
            "Its manifest.json lists a directory it could not read as left out, with the reason:\n  /s/log: denied"
        );
        assert_eq!(
            left_out_text(
                3,
                true,
                &["/s/records: denied".into(), "/s/log: denied".into()]
            )
            .unwrap(),
            "Its manifest.json lists 3 more file(s) and 2 directories it could not read as left out, with the reason:\n  /s/records: denied\n  /s/log: denied"
        );
    }

    /// The manifest's entries for directories it could not read: one for
    /// the records, however many directories; two (`crash/`, `log/`) for the
    /// log directory. A missing directory is just empty.
    #[cfg(unix)]
    #[test]
    fn report_finds_the_directories_it_could_not_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("spora-cli-unread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (a, b, log) = (dir.join("a"), dir.join("b"), dir.join("log"));
        for d in [&a, &b, &log] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("x.jsonl"), b"{}\n").unwrap();
        }
        let mut opts = spora_service::BundleOptions::new(dir.join("r.zip"));
        opts.record_dirs = vec![a.clone(), b.clone(), dir.join("missing")];
        opts.log_dir = Some(log.clone());
        let (found, entries) = unreadable_report_dirs(&opts);
        assert!(found.is_empty());
        assert_eq!(entries, 0);

        let lock = |d: &PathBuf, mode| {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        for d in [&a, &b, &log] {
            lock(d, 0o000);
        }
        let result = unreadable_report_dirs(&opts);
        let export = spora_service::diag::bundle::export(&opts);
        let read_anyway = std::fs::read_dir(&a).is_ok();
        for d in [&a, &b, &log] {
            lock(d, 0o700);
        }
        if read_anyway {
            // Root reads it anyway.
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let (found, entries) = result;
        let found: Vec<&PathBuf> = found.iter().map(|(d, _)| d).collect();
        assert_eq!(found, [&a, &b, &log]);
        assert_eq!(entries, 3);
        assert_eq!(
            export.unwrap().omitted_files,
            entries,
            "the bundle's own count of them"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn upload_summary_says_when_the_pass_stopped_early() {
        let mut sum = spora_service::PassSummary::default();
        assert_eq!(sent_summary(&sum), "Nothing new to send.");
        sum.halted = true;
        assert_eq!(
            sent_summary(&sum),
            "Nothing was sent: uploads were switched off meanwhile (or the uploader stopped)."
        );
        sum.files = 2;
        sum.chunks = 3;
        sum.bytes_sent = 2048;
        sum.bytes_accepted = 1024;
        assert_eq!(
            sent_summary(&sum),
            "Sent 2.0 KiB from 2 file(s) in 3 request(s); 1.0 KiB of it was new to the server. The upload stopped there: uploads were switched off meanwhile (or the uploader stopped)."
        );
        sum.halted = false;
        assert_eq!(
            sent_summary(&sum),
            "Sent 2.0 KiB from 2 file(s) in 3 request(s); 1.0 KiB of it was new to the server."
        );
    }

    #[test]
    fn report_names_sort_by_time_and_are_portable() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_792_411_838_512);
        assert_eq!(file_stamp(t), "20261019T121038Z");
    }

    #[test]
    fn plain_errors_print_unquoted() {
        let e: Box<dyn std::error::Error> = Box::new(Plain("upload failed: \"x\"".into()));
        assert_eq!(format!("{e:?}"), "upload failed: \"x\"");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn the_cli_reports_a_platform_the_api_knows() {
        assert!(["linux", "macos", "windows"].contains(&platform()));
    }

    /// A signal is counted when it comes, not when someone waits for it: a
    /// second Ctrl+C pressed during the teardown, before the last upload
    /// waits for one, still skips that upload.
    #[tokio::test]
    async fn a_signal_is_kept_for_whoever_waits_later() {
        use std::time::Duration;
        let soon = Duration::from_millis(200);
        let (tx, signals) = tokio::sync::watch::channel(0u32);
        let shutdown = Shutdown { signals };
        assert_eq!(shutdown.count(), 0);
        assert!(
            tokio::time::timeout(soon, shutdown.requested())
                .await
                .is_err()
        );
        tx.send_modify(|n| *n += 1);
        tx.send_modify(|n| *n += 1);
        assert_eq!(shutdown.count(), 2);
        tokio::time::timeout(soon, shutdown.requested())
            .await
            .expect("the stop request");
        tokio::time::timeout(soon, shutdown.clone().signal(2))
            .await
            .expect("the second signal, which came before anyone waited");
        assert!(
            tokio::time::timeout(soon, shutdown.signal(3))
                .await
                .is_err()
        );
        drop(tx);
        assert!(
            tokio::time::timeout(soon, shutdown.signal(3))
                .await
                .is_err(),
            "a watcher that is gone sends no signal"
        );
    }
}
