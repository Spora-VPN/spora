//! A share whose connection log goes to a consumer the host process
//! supplies (`ConnLogConfig::sink`), end to end over loopback: a real share,
//! a real client, and flows through the netstack exit.
//!
//! The exit drops flows to local addresses, loopback included, so the flow
//! that reaches a destination here is a DNS query: the forwarder takes it at
//! its synthetic address and sends it to an upstream of the share's choosing,
//! which may be on loopback, and logs it as a flow to that upstream. A
//! datagram to a private address gives the blocked flow. TCP with byte
//! counts through a real network is spora-lab's `connlog` suite.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket;

use spora_core::connlog::{
    self, ConnLogConfig, ConnLogEvent, ConnLogSink, EventKind, FlowQuery, Mark, ShareRef,
};
use spora_core::dns::{self, DnsForwarder, DnsUpstream};
use spora_core::identity::{DeviceIdentity, RelayEndpoint, Share};
use spora_core::{Config, ConnectResult, ShareSession, connect, share};

/// The tests share the process, and one of them counts its threads.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A sink that keeps what it is handed, in order.
#[derive(Default)]
struct MemorySink(Mutex<Vec<ConnLogEvent>>);

impl ConnLogSink for MemorySink {
    fn event(&self, event: ConnLogEvent) {
        self.0.lock().unwrap().push(event);
    }
}

impl MemorySink {
    fn events(&self) -> Vec<ConnLogEvent> {
        self.0.lock().unwrap().clone()
    }

    /// What `share` has logged so far.
    fn of(&self, share: ShareRef) -> Vec<EventKind> {
        let events = self.events();
        let of_share = events.iter().filter(|e| e.share == share);
        of_share.map(|e| e.kind).collect()
    }
}

async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn start_relay() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(relay::serve(sock, relay::State::default()));
    addr
}

/// A resolver on loopback that answers every query with the query itself
/// (the forwarder never looks inside one).
async fn start_resolver() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// The client's address inside the tunnel.
const INNER: [u8; 4] = [10, 0, 85, 2];
/// A private address: the exit refuses it.
const PRIVATE: [u8; 4] = [192, 168, 1, 1];
const QUERY: &[u8] = b"a query the forwarder passes on unread";

fn udp_packet(src_port: u16, dst: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    etherparse::PacketBuilder::ipv4(INNER, dst, 64)
        .udp(src_port, dst_port)
        .write(&mut pkt, payload)
        .unwrap();
    pkt
}

/// One share on the loopback relay, logging as `conn_log` says, and what
/// its events are named by.
async fn start_share(
    relay: SocketAddr,
    resolver: SocketAddr,
    conn_log: ConnLogConfig,
) -> Result<(ShareSession, ShareRef), String> {
    let device = DeviceIdentity::generate();
    let sh = Share::open(&device, vec![RelayEndpoint::new("127.0.0.1", relay.port())]).unwrap();
    let named = ShareRef {
        routing_hash: sh.routing_hash(),
        share_id: sh.share_id,
    };
    let config = Config {
        enable_direct_upgrade: false,
        // This resolver and no other: nothing leaves loopback.
        dns_forwarder: Some(DnsForwarder::with_fallback(
            DnsUpstream::Servers(vec![resolver]),
            Vec::new(),
        )),
        conn_log: Some(conn_log),
        ..Config::default()
    };
    Ok((share(device, sh, config).await?, named))
}

/// A client of `session` that resolves one name through the exit's
/// forwarder, from inner port `src_port`, and sends one datagram to a
/// private address.
async fn run_client(session: &ShareSession, src_port: u16) -> ConnectResult {
    let config = Config {
        enable_direct_upgrade: false,
        ..Config::default()
    };
    let mut client = connect(session.url.clone(), &config)
        .await
        .expect("connect()");
    let proxy = dns::PROXY_ADDR.octets();
    let query = udp_packet(src_port, proxy, dns::PROXY_PORT, QUERY);
    client.transport.send(query).await.expect("send the query");
    let answered = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(pkt)) = client.transport.next().await {
            if pkt.ends_with(QUERY) {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out waiting for the forwarder's answer");
    assert!(answered, "the tunnel closed before the answer came");
    let refused = udp_packet(src_port, PRIVATE, 9, b"refused");
    client.transport.send(refused).await.expect("send");
    client
}

/// What one client's visit must leave in a share's log, in the order the
/// share produced it: a session that came through `relay`, the query as a
/// flow from `src_port` to `resolver`, the refused datagram, the session's
/// end. Returns the session's and the two flows' ids.
fn assert_one_visit(
    kinds: &[EventKind],
    relay: SocketAddr,
    resolver: SocketAddr,
    src_port: u16,
) -> (i64, i64, i64) {
    let inner = SocketAddr::from((INNER, src_port));
    let [
        EventKind::Mark {
            mark: Mark::ShareStart,
            ..
        },
        EventKind::SessionStart {
            session,
            relay: came_through,
            ts_ms: started,
        },
        EventKind::FlowOpen {
            flow,
            session: open_session,
            proto: 17,
            src,
            dst,
            confirmed: true,
            ts_ms: opened,
        },
        EventKind::FlowEstablished {
            flow: established_flow,
            session: established_session,
            egress: Some(egress),
        },
        EventKind::FlowClose {
            flow: closed_flow,
            session: closed_session,
            last_ms,
            up,
            down,
            established: true,
            reason: "closed",
        },
        EventKind::FlowBlocked {
            flow: blocked_flow,
            session: blocked_session,
            proto: 17,
            src: blocked_src,
            dst: blocked_dst,
            ..
        },
        EventKind::SessionEnd {
            session: ended_session,
            ts_ms: ended,
            reason: "transport_closed",
        },
        EventKind::Mark {
            mark: Mark::ShareStop,
            ..
        },
    ] = *kinds
    else {
        panic!("unexpected events: {kinds:#?}");
    };
    assert_eq!(came_through, relay);
    assert_eq!((src, dst), (inner, resolver));
    // The source the resolver saw the query from: this host, another port.
    assert_eq!(egress.ip(), resolver.ip());
    assert_ne!(egress.port(), 0);
    assert_eq!((up, down), (QUERY.len() as u64, QUERY.len() as u64));
    assert_eq!(blocked_src, inner);
    assert_eq!(blocked_dst, SocketAddr::from((PRIVATE, 9)));
    assert!(started <= opened && opened <= last_ms && last_ms <= ended);
    assert_eq!((established_flow, closed_flow), (flow, flow));
    assert_ne!(flow, blocked_flow);
    for of_session in [
        open_session,
        established_session,
        closed_session,
        blocked_session,
        ended_session,
    ] {
        assert_eq!(of_session, session);
    }
    (session, flow, blocked_flow)
}

/// Threads of this process that write a connection-log database.
#[cfg(target_os = "linux")]
fn writer_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .filter(|name| name.starts_with("spora-connlog"))
        .count()
}

/// A host that runs many shares gives them all one sink and no directory:
/// every share's sessions and flows reach the sink, each named by its
/// share, and no share starts a writer thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shares_of_one_process_feed_one_sink() {
    let _one = ONE_AT_A_TIME.lock().await;
    let _ = env_logger::builder().is_test(true).try_init();
    // A writer left by a share another test stopped is on its way out.
    #[cfg(target_os = "linux")]
    wait_for("earlier writers to exit", || writer_threads() == 0).await;
    let relay = start_relay().await;
    let resolver = start_resolver().await;
    let sink = Arc::new(MemorySink::default());

    let mut shares = Vec::new();
    for _ in 0..2 {
        let log = ConnLogConfig::to_sink(sink.clone());
        shares.push(start_share(relay, resolver, log).await.expect("share()"));
    }
    #[cfg(target_os = "linux")]
    assert_eq!(
        writer_threads(),
        0,
        "a share with a sink alone has a writer"
    );
    for (_, named) in &shares {
        assert!(
            matches!(
                sink.of(*named)[..],
                [EventKind::Mark {
                    mark: Mark::ShareStart,
                    ..
                }]
            ),
            "a share's log begins with its start"
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await; // let registration land

    // A client each, at the same time.
    let (first, second) = tokio::join!(
        run_client(&shares[0].0, 40001),
        run_client(&shares[1].0, 40002)
    );
    for (client, (_, named)) in [first, second].into_iter().zip(&shares) {
        // The refused datagram was the last thing sent: once it is logged,
        // the client leaves.
        wait_for("the blocked flow", || {
            let blocked = |k: &EventKind| matches!(k, EventKind::FlowBlocked { .. });
            sink.of(*named).iter().any(blocked)
        })
        .await;
        client.stopper.stop().await;
        drop(client);
        wait_for("the session's end", || {
            let ended = |k: &EventKind| matches!(k, EventKind::SessionEnd { .. });
            sink.of(*named).iter().any(ended)
        })
        .await;
    }
    #[cfg(target_os = "linux")]
    assert_eq!(writer_threads(), 0);

    let mut ids = Vec::new();
    let mut total = 0;
    for ((session, named), src_port) in shares.into_iter().zip([40001, 40002]) {
        session.stop().await;
        wait_for("the share's stop", || {
            matches!(
                sink.of(named).last(),
                Some(EventKind::Mark {
                    mark: Mark::ShareStop,
                    ..
                })
            )
        })
        .await;
        let kinds = sink.of(named);
        total += kinds.len();
        let (session, flow, blocked) = assert_one_visit(&kinds, relay, resolver, src_port);
        ids.extend([session, flow, blocked]);
    }
    // Nothing at the sink that is neither share's, and no id used twice.
    assert_eq!(sink.events().len(), total);
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 6);
}

/// A directory and a sink at once: the share keeps its database as it does
/// without a sink, and the sink is handed the same records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_and_a_sink_hold_the_same_log() {
    let _one = ONE_AT_A_TIME.lock().await;
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = start_relay().await;
    let resolver = start_resolver().await;
    let sink = Arc::new(MemorySink::default());
    let dir = tempfile::tempdir().unwrap();
    #[cfg(target_os = "linux")]
    wait_for("earlier writers to exit", || writer_threads() == 0).await;
    let log = ConnLogConfig::in_dir(dir.path()).with_sink(sink.clone());
    let (session, named) = start_share(relay, resolver, log).await.expect("share()");
    assert!(dir.path().join("connlog.sqlite").is_file());
    // The database's writer, which the other test counts none of.
    #[cfg(target_os = "linux")]
    assert_eq!(writer_threads(), 1);
    tokio::time::sleep(Duration::from_millis(300)).await; // let registration land

    let client = run_client(&session, 40003).await;
    wait_for("the blocked flow", || {
        let blocked = |k: &EventKind| matches!(k, EventKind::FlowBlocked { .. });
        sink.of(named).iter().any(blocked)
    })
    .await;
    client.stopper.stop().await;
    drop(client);
    wait_for("the session's end", || {
        let ended = |k: &EventKind| matches!(k, EventKind::SessionEnd { .. });
        sink.of(named).iter().any(ended)
    })
    .await;
    session.stop().await;
    // The writer's last word, after everything else is in the database.
    let marks = || {
        let db = connlog::open_readonly(dir.path()).unwrap();
        let marks = connlog::query_marks(&db, None, None).unwrap();
        marks.into_iter().map(|m| m.kind).collect::<Vec<_>>()
    };
    wait_for("the database's share_stop", || marks().len() == 2).await;
    assert_eq!(marks(), ["share_start", "share_stop"]);

    let kinds = sink.of(named);
    assert_eq!(sink.events().len(), kinds.len());
    let (session_id, flow_id, blocked_id) = assert_one_visit(&kinds, relay, resolver, 40003);

    let db = connlog::open_readonly(dir.path()).unwrap();
    let sessions = connlog::query_sessions(&db, None).unwrap();
    let [stored] = &sessions[..] else {
        panic!("one session in the database: {sessions:#?}");
    };
    assert_eq!(stored.id, session_id);
    assert_eq!(stored.relay_addr, relay.to_string());
    assert_eq!(stored.end_reason.as_deref(), Some("transport_closed"));
    let flows = connlog::query_flows(&db, &FlowQuery::default()).unwrap();
    assert_eq!(flows.len(), 2, "{flows:#?}");
    let flow = flows.iter().find(|f| f.id == flow_id).expect("the query");
    assert_eq!(flow.session_id, session_id);
    assert_eq!(
        (flow.dst.as_str(), flow.dst_port),
        (resolver.ip().to_string().as_str(), resolver.port())
    );
    assert_eq!(
        (flow.bytes_up, flow.bytes_down),
        (QUERY.len() as u64, QUERY.len() as u64)
    );
    assert!(flow.established && flow.confirmed);
    assert_eq!(flow.end_reason.as_deref(), Some("closed"));
    let sink_egress = kinds.iter().find_map(|k| match k {
        EventKind::FlowEstablished { egress, .. } => egress.map(|a| a.to_string()),
        _ => None,
    });
    assert_eq!(flow.egress_addr, sink_egress);
    let blocked = flows.iter().find(|f| f.id == blocked_id).expect("blocked");
    assert_eq!(blocked.dst, Ipv4Addr::from(PRIVATE).to_string());
    assert_eq!(blocked.end_reason.as_deref(), Some("blocked"));
}

/// A directory that cannot be written still fails the share, with a sink
/// beside it or without: a host that asked for a database gets one or an
/// error, never a share that runs without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_that_cannot_be_written_fails_the_share() {
    let _one = ONE_AT_A_TIME.lock().await;
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = start_relay().await;
    let resolver = start_resolver().await;
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("a-file");
    std::fs::write(&file, "not a directory").unwrap();
    let below_a_file = file.join("connlog");

    let sink = Arc::new(MemorySink::default());
    for log in [
        ConnLogConfig::in_dir(&below_a_file),
        ConnLogConfig::in_dir(&below_a_file).with_sink(sink.clone()),
    ] {
        let Err(e) = start_share(relay, resolver, log).await else {
            panic!("a share started without the database it was asked to keep");
        };
        assert!(e.contains("connlog: create dir"), "{e}");
    }
    // The share never began to log, so the sink was told nothing.
    assert!(sink.events().is_empty(), "{:#?}", sink.events());

    // And a log with nowhere to go is a mistake, not a log switched off.
    let mut nowhere = ConnLogConfig::in_dir(&below_a_file);
    nowhere.dir = None;
    let Err(e) = start_share(relay, resolver, nowhere).await else {
        panic!("a share started with a connection log that goes nowhere");
    };
    assert!(e.contains("neither a directory nor a sink"), "{e}");
}
