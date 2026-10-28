//! Dumb UDP relay binary. See `lib.rs` for the protocol and state machine.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use serde::Serialize;

use relay::authz::{Authorizer, Open, StaticToken};
use relay::server::{ServeOptions, default_session_log_path};
use relay::sessionlog::SessionLogConfig;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Print embedded build provenance and exit instead of serving.
    #[arg(value_enum)]
    command: Option<Command>,
    /// Emit machine-readable lifecycle output on stdout.
    #[arg(long)]
    json: bool,
    /// UDP port to bind (dual-stack wildcard unless --bind is given)
    #[arg(short, long, default_value_t = 443)]
    port: u16,
    /// Explicit bind address (e.g. 0.0.0.0 for v4-only hosts). Default binds
    /// `::` dual-stack so one socket serves v4 (as v4-mapped) and v6 peers.
    #[arg(short, long)]
    bind: Option<std::net::IpAddr>,
    /// Disable the persistent session log. By default the relay records each
    /// matched flow (client addr ↔ sharer routing hash and device, with
    /// timing and byte counts) — the operator's accountability record (see
    /// sessionlog).
    #[arg(long)]
    no_session_log: bool,
    /// Session-log database path. Default: `$STATE_DIRECTORY/relay-sessions.sqlite`
    /// when run under systemd with `StateDirectory=` set (the recommended
    /// deployment), otherwise `relay-sessions.sqlite` in the working directory.
    #[arg(long, conflicts_with = "no_session_log")]
    session_log: Option<PathBuf>,
    /// Session-log retention in days; older sessions are swept.
    #[arg(long, default_value_t = 90, conflicts_with = "no_session_log")]
    session_log_retention_days: u32,
    /// Admit only sharers that present this token: a file whose contents
    /// (surrounding whitespace trimmed) are the token. Sharers pass the same
    /// text with `spora share --relay-token`. Without it (or --token) the
    /// relay is OPEN: any validly signed registration is accepted.
    #[arg(long, value_name = "PATH", conflicts_with = "token")]
    token_file: Option<PathBuf>,
    /// Like --token-file, with the token itself as the value (other local
    /// users can read it in the process list; prefer --token-file).
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
    /// Also serve the TCP/TLS relay carrier on this port (alongside the UDP
    /// relay), for clients on networks that block UDP/QUIC. The relay only
    /// blind-splices; the end-to-end TLS stays between the peers.
    #[arg(long)]
    tcp_port: Option<u16>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Command {
    BuildInfo,
}

#[derive(Serialize)]
struct BuildInfo {
    version: &'static str,
    commit: Option<&'static str>,
    dirty: bool,
    target: &'static str,
    profile: &'static str,
}

fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        commit: option_env!("SPORA_BUILD_COMMIT").filter(|value| !value.is_empty()),
        dirty: matches!(option_env!("SPORA_BUILD_DIRTY"), Some("1")),
        target: env!("SPORA_BUILD_TARGET"),
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    }
}

/// The authorizer the flags ask for: a static token, or open.
fn authorizer(args: &Args) -> Result<Arc<dyn Authorizer>, String> {
    let token = match (&args.token_file, &args.token) {
        (Some(path), _) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("--token-file {}: {e}", path.display()))?,
        ),
        (None, Some(t)) => Some(t.clone()),
        (None, None) => None,
    };
    match token {
        Some(t) => Ok(Arc::new(
            StaticToken::new(t.trim().as_bytes().to_vec()).map_err(|e| format!("--token: {e}"))?,
        )),
        None => Ok(Arc::new(Open)),
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if matches!(args.command, Some(Command::BuildInfo)) {
        let info = build_info();
        if args.json {
            println!(
                "{}",
                serde_json::to_string(&info).expect("build info is serializable")
            );
        } else {
            println!("relay {} ({})", info.version, info.target);
            println!("commit: {}", info.commit.unwrap_or("unknown"));
            println!("dirty: {}", info.dirty);
            println!("profile: {}", info.profile);
        }
        return;
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let authorizer = authorizer(&args).unwrap_or_else(|e| {
        eprintln!("relay: {e}");
        process::exit(1);
    });
    let session_log = (!args.no_session_log).then(|| {
        let mut cfg = SessionLogConfig::at(
            args.session_log
                .clone()
                .unwrap_or_else(default_session_log_path),
        );
        cfg.retention = Duration::from_secs(u64::from(args.session_log_retention_days) * 86_400);
        cfg
    });
    let opts = ServeOptions {
        bind: SocketAddr::new(
            args.bind
                .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
            args.port,
        ),
        tcp_port: args.tcp_port,
        session_log,
        json: args.json,
        on_ready: None,
    };
    if let Err(e) = relay::server::run(opts, authorizer).await {
        eprintln!("relay: {e}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_interfaces_are_additive_to_the_server_cli() {
        let build = Args::try_parse_from(["relay", "build-info", "--json"]).unwrap();
        assert!(matches!(build.command, Some(Command::BuildInfo)));
        assert!(build.json);

        let serve =
            Args::try_parse_from(["relay", "--bind", "127.0.0.1", "--port", "8443", "--json"])
                .unwrap();
        assert!(serve.command.is_none());
        assert_eq!(serve.port, 8443);
        assert!(serve.json);
    }

    #[test]
    fn a_token_makes_the_relay_static_and_none_leaves_it_open() {
        let open = Args::try_parse_from(["relay"]).unwrap();
        assert!(authorizer(&open).unwrap().describe().starts_with("open"));
        let fixed = Args::try_parse_from(["relay", "--token", " s3cret\n"]).unwrap();
        assert!(authorizer(&fixed).unwrap().describe().starts_with("static"));
        let empty = Args::try_parse_from(["relay", "--token", "  "]).unwrap();
        assert!(authorizer(&empty).is_err(), "an empty token is refused");
        assert!(
            Args::try_parse_from(["relay", "--token", "a", "--token-file", "b"]).is_err(),
            "one source of the token"
        );
    }
}
