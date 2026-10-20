//! Every line the core logs about one of a client's flows — its source or
//! destination address — goes to `spora_core::FLOW_LOG_TARGET`. Platforms keep
//! that target off the diagnostic log file (which uploads and rides in bug
//! reports): the connection log is the only per-flow record, and it never
//! leaves the sharer's machine. stderr and logcat still show the lines.
//!
//! The vendored netstack (`netstack_smoltcp`) is held to the same rule. It
//! logs through `tracing`, whose log bridge must carry the event's `target:`
//! over to the `log` record — which this test also confirms, on lines the
//! netstack only logs with the flow target (a created connection, a malformed
//! transport header).
//!
//! Its own test binary because it installs a global logger to capture them.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use futures_util::SinkExt;
use tokio::net::UdpSocket as TokioUdp;

use spora_core::e2e::{E2eSession, client_connect, client_endpoint};
use spora_core::identity::{Identity, RelayEndpoint, Token};
use spora_core::{Config, FLOW_LOG_TARGET, Timings, share};

/// Every line logged, as (target, message).
static LINES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        LINES
            .lock()
            .unwrap()
            .push((record.target().to_owned(), record.args().to_string()));
    }

    fn flush(&self) {}
}

static LOGGER: Capture = Capture;

/// The client's inner address, a blocked (LAN) destination and a dialed one
/// (TEST-NET-1: never routed, so the dial goes nowhere).
const CLIENT: [u8; 4] = [10, 0, 85, 1];
const BLOCKED: [u8; 4] = [192, 168, 77, 1];
const DIALED: [u8; 4] = [192, 0, 2, 1];

fn tcp_syn(src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    etherparse::PacketBuilder::ipv4(CLIENT, dst, 64)
        .tcp(src_port, dst_port, 1, 64240)
        .syn()
        .write(&mut pkt, &[])
        .unwrap();
    pkt
}

fn udp(src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    etherparse::PacketBuilder::ipv4(CLIENT, dst, 64)
        .udp(src_port, dst_port)
        .write(&mut pkt, b"probe")
        .unwrap();
    pkt
}

/// An IPv4 packet from the client to `dst` that claims transport protocol
/// `proto` but is cut short of that protocol's header: the netstack drops it
/// as malformed, and says so.
fn truncated(proto: u8, dst: [u8; 4]) -> Vec<u8> {
    let mut pkt = vec![
        0x45, 0x00, 0x00, 0x18, // IPv4, IHL=5, total length = 24
        0x00, 0x00, 0x00, 0x00, // id, flags/frag
        0x40, proto, 0x00, 0x00, // TTL=64, protocol, checksum (unchecked)
    ];
    pkt.extend_from_slice(&CLIENT);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // shorter than any header
    pkt
}

fn ip(octets: [u8; 4]) -> String {
    std::net::Ipv4Addr::from(octets).to_string()
}

fn logged(needle: &str) -> bool {
    LINES
        .lock()
        .unwrap()
        .iter()
        .any(|(_, m)| m.contains(needle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_lines_use_the_flow_target() {
    log::set_logger(&LOGGER).expect("the only logger in this binary");
    log::set_max_level(log::LevelFilter::Trace);

    let relay_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_sock.local_addr().unwrap();
    tokio::spawn(relay::serve(relay_sock, relay::State::default()));

    let config = Config {
        relays: vec![RelayEndpoint::new("127.0.0.1", relay_addr.port())],
        dns_forwarder: None,
        enable_direct_upgrade: false,
        ..Config::default()
    };
    let session = share(Identity::generate(), config).await.expect("share()");
    let token = Token::from_url(&session.url).expect("parse url");
    tokio::time::sleep(Duration::from_millis(300)).await; // let registration land

    let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    b_std.set_nonblocking(true).unwrap();
    let b_endpoint =
        client_endpoint(b_std, token.routing_key, &Timings::default()).expect("client_endpoint");
    let endpoint = Box::leak(Box::new(b_endpoint));
    let E2eSession {
        conn: _conn,
        mut transport,
        signal: _signal,
    } = client_connect(endpoint, relay_addr, &token.secret, true)
        .await
        .expect("client_connect");

    // Blocked TCP (repeated: the first is a warning, the rest trace), blocked
    // UDP, and a TCP flow the exit dials.
    for port in [40001, 40002, 40003] {
        transport.send(tcp_syn(port, BLOCKED, 445)).await.unwrap();
    }
    transport.send(udp(40004, BLOCKED, 137)).await.unwrap();
    transport.send(tcp_syn(40005, DIALED, 9)).await.unwrap();
    // Malformed: the netstack's own address-bearing error lines.
    transport.send(truncated(17, DIALED)).await.unwrap();
    transport.send(truncated(6, DIALED)).await.unwrap();

    let wants = [
        "blocked TCP",
        "blocked UDP",
        "new tcp connection",
        // netstack_smoltcp, through tracing's log bridge:
        "created TCP connection",
        "invalid err",
        "invalid TCP err",
    ];
    let deadline = Instant::now() + Duration::from_secs(5);
    while !wants.iter().all(|w| logged(w)) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    session.stop().await;

    let lines = LINES.lock().unwrap();
    let naming_a_flow: Vec<&(String, String)> = lines
        .iter()
        .filter(|(target, _)| {
            target.starts_with("spora_core") || target.starts_with("netstack_smoltcp")
        })
        .filter(|(_, m)| {
            [CLIENT, BLOCKED, DIALED]
                .iter()
                .any(|a| m.contains(&ip(*a)))
        })
        .collect();
    for want in wants {
        assert!(
            naming_a_flow.iter().any(|(_, m)| m.contains(want)),
            "no {want:?} line was logged: {naming_a_flow:#?}"
        );
    }
    let stray: Vec<_> = naming_a_flow
        .iter()
        .filter(|(target, _)| target != FLOW_LOG_TARGET)
        .collect();
    assert!(
        stray.is_empty(),
        "flow lines outside {FLOW_LOG_TARGET}: {stray:#?}"
    );
}
