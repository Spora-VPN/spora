//! A session the other end closes on purpose — a client disconnecting, an
//! exit stopping — is the ordinary end of a session, not a failure: its
//! `session_end` concludes `ok` with `peer_closed`, and a run whose last
//! session ended that way closes `closed_by_peer`, not `lost`. That holds
//! with traffic in flight (a send can see the close before the reader does)
//! and for a client process that exits right after stopping. A session that
//! died on one end is a failure on the other end too, even when that end
//! hears the close. Both ends, over a real relay on loopback.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket as TokioUdp;
use tokio::sync::mpsc;

use spora_core::identity::{DeviceIdentity, RelayEndpoint, Share, Token};
use spora_core::record::{Outcome, Reason, RecordConfig, Recorder, StepKind, StepOutcome};
use spora_core::{Config, ExitMode, SessionHandler, Timings, TunnelEvent, connect, share};

/// How often the traffic tests stop a busy session: a send that sees the
/// close first is a race, lost a few times in ten before the fix.
const BUSY_ROUNDS: usize = 20;

/// An exit handler that just drains the tunnel until it ends or is cancelled.
fn draining_exit() -> SessionHandler {
    Arc::new(|mut transport, cancel| {
        Box::pin(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = transport.next() => if !matches!(res, Some(Ok(_))) { break },
                }
            }
        })
    })
}

/// An exit handler that sends to the client every `every` — a download in
/// progress — while draining the tunnel until it ends or is cancelled.
fn downloading_exit(every: Duration) -> SessionHandler {
    Arc::new(move |transport, cancel| {
        Box::pin(async move {
            let (mut sink, mut stream) = transport.split();
            let sender = tokio::spawn(async move {
                while sink.send(packet()).await.is_ok() {
                    tokio::time::sleep(every).await;
                }
            });
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = stream.next() => if !matches!(res, Some(Ok(_))) { break },
                }
            }
            sender.abort();
        })
    })
}

/// An exit handler that gives up on its session after `after`: an exit
/// failing on its own while the client is fine.
fn failing_exit(after: Duration) -> SessionHandler {
    Arc::new(move |transport, _cancel| {
        Box::pin(async move {
            tokio::time::sleep(after).await;
            drop(transport);
        })
    })
}

/// A 1000-byte IPv4 packet; the exits here never look inside.
fn packet() -> Vec<u8> {
    let mut p = vec![0u8; 1000];
    p[0] = 0x45;
    p[9] = 17;
    p
}

async fn start_relay() -> std::net::SocketAddr {
    let sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(relay::serve(sock, relay::State::default()));
    addr
}

fn hooked(events: mpsc::UnboundedSender<TunnelEvent>) -> spora_core::EventHook {
    Some(Arc::new(move |ev| {
        let _ = events.send(ev);
    }))
}

async fn wait_for(
    rx: &mut mpsc::UnboundedReceiver<TunnelEvent>,
    what: &str,
    pred: impl Fn(&TunnelEvent) -> bool,
) {
    wait_for_within(rx, what, Duration::from_secs(10), pred).await
}

async fn wait_for_within(
    rx: &mut mpsc::UnboundedReceiver<TunnelEvent>,
    what: &str,
    within: Duration,
    pred: impl Fn(&TunnelEvent) -> bool,
) {
    tokio::time::timeout(within, async {
        loop {
            match rx.recv().await {
                Some(ev) if pred(&ev) => return,
                Some(_) => continue,
                None => panic!("event channel closed waiting for {what}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

/// Every `session_end` a record holds, as (outcome, reason).
fn session_end(rec: &Recorder) -> Vec<(StepOutcome, Option<Reason>)> {
    rec.snapshot()
        .unwrap()
        .steps_of(StepKind::SessionEnd)
        .map(|s| (s.outcome, s.reason))
        .collect()
}

/// The first `session_end` with its detail, for an assertion's message.
fn first_session_end(rec: &Recorder) -> Option<(StepOutcome, Option<Reason>, Option<String>)> {
    rec.snapshot()
        .unwrap()
        .steps_of(StepKind::SessionEnd)
        .map(|s| (s.outcome, s.reason, s.detail.clone()))
        .next()
}

fn configs() -> (
    Config,
    Config,
    mpsc::UnboundedReceiver<TunnelEvent>,
    mpsc::UnboundedReceiver<TunnelEvent>,
) {
    configs_with(draining_exit(), Timings::default())
}

fn configs_with(
    exit: SessionHandler,
    timings: Timings,
) -> (
    Config,
    Config,
    mpsc::UnboundedReceiver<TunnelEvent>,
    mpsc::UnboundedReceiver<TunnelEvent>,
) {
    let (share_tx, share_rx) = mpsc::unbounded_channel();
    let (client_tx, client_rx) = mpsc::unbounded_channel();
    let timings = Timings {
        reconnect_delay: Duration::from_millis(200),
        relay_dial_timeout: Duration::from_secs(1),
        ..timings
    };
    let share_config = Config {
        exit_mode: ExitMode::Custom(exit),
        event_hook: hooked(share_tx),
        enable_direct_upgrade: false,
        dns_forwarder: None,
        record: Some(RecordConfig::in_memory()),
        timings: timings.clone(),
        ..Config::default()
    };
    let client_config = Config {
        event_hook: hooked(client_tx),
        enable_direct_upgrade: false,
        record: Some(RecordConfig::in_memory()),
        timings,
        ..Config::default()
    };
    (share_config, client_config, share_rx, client_rx)
}

/// Share a fresh device's fresh share over the loopback relay.
async fn share_at(
    relay: std::net::SocketAddr,
    config: Config,
) -> Result<spora_core::ShareSession, String> {
    let device = DeviceIdentity::generate();
    let sh = Share::open(&device, vec![RelayEndpoint::new("127.0.0.1", relay.port())]).unwrap();
    share(device, sh, config).await
}

fn is_session_up(ev: &TunnelEvent) -> bool {
    matches!(ev, TunnelEvent::RelaySessionEstablished { .. })
}

fn is_session_ended(ev: &TunnelEvent) -> bool {
    matches!(ev, TunnelEvent::SessionEnded { .. })
}

fn is_redial(ev: &TunnelEvent) -> bool {
    matches!(ev, TunnelEvent::Reconnecting)
}

/// Set the client's keepalive knob, waking the layer that reads it.
fn set_knob(client: &spora_core::ConnectResult, secs: u64) {
    client.keepalive_knob.store(secs, Ordering::Relaxed);
    if let Some(w) = client.keepalive_waker.lock().unwrap().take() {
        w.wake();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_leaves_is_no_failure_of_the_exit() {
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = start_relay().await;
    let (share_config, client_config, mut share_rx, mut client_rx) = configs();
    let session = share_at(relay, share_config).await.expect("share()");
    tokio::time::sleep(Duration::from_millis(300)).await; // let registration land

    let client = connect(session.url.clone(), &client_config)
        .await
        .expect("connect()");
    wait_for(&mut client_rx, "the client's session", is_session_up).await;
    wait_for(&mut share_rx, "the exit's session", is_session_up).await;

    // The client stops: its connection closes the orderly way.
    client.cancel.cancel();
    drop(client.transport);
    wait_for(&mut share_rx, "the exit's session end", is_session_ended).await;

    let exit_record = session.record.clone();
    assert_eq!(
        session_end(&exit_record),
        [(StepOutcome::Ok, Some(Reason::PeerClosed))],
        "the exit records the client's close as an ordinary end"
    );
    session.stop().await;
    let exit = exit_record.snapshot().unwrap();
    assert_eq!(exit.outcome(), Outcome::ClosedByPeer);
    assert_eq!(exit.first_failure().map(|s| s.kind), None);

    // The client stopped while its session was up.
    tokio::time::sleep(Duration::from_millis(100)).await; // the closer task
    assert_eq!(
        session_end(&client.record),
        [(StepOutcome::Ok, Some(Reason::LocalShutdown))]
    );
    assert_eq!(
        client.record.snapshot().unwrap().outcome(),
        Outcome::ClosedLocally
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exit_that_stops_is_no_failure_of_the_client() {
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = start_relay().await;
    let (share_config, client_config, mut share_rx, mut client_rx) = configs();
    let session = share_at(relay, share_config).await.expect("share()");
    tokio::time::sleep(Duration::from_millis(300)).await; // let registration land

    let client = connect(session.url.clone(), &client_config)
        .await
        .expect("connect()");
    wait_for(&mut client_rx, "the client's session", is_session_up).await;
    wait_for(&mut share_rx, "the exit's session", is_session_up).await;
    // Awake (a dormant client parks instead of redialling), and something
    // has to read the tunnel for the client to notice it end.
    client
        .keepalive_knob
        .store(10, std::sync::atomic::Ordering::Relaxed);
    let mut transport = client.transport;
    let reader = tokio::spawn(async move { while transport.next().await.is_some() {} });

    // The exit stops: the client's session ends by the exit's close, and
    // the client starts redialling (into nothing).
    let exit_record = session.record.clone();
    session.stop().await;
    assert_eq!(
        exit_record.snapshot().unwrap().outcome(),
        Outcome::ClosedLocally
    );
    wait_for(&mut client_rx, "the client's redial", is_redial).await;

    let snap = client.record.snapshot().unwrap();
    let kinds: Vec<StepKind> = snap
        .steps
        .iter()
        .map(|s| s.kind)
        .filter(|k| matches!(k, StepKind::SessionEnd | StepKind::Reconnect))
        .collect();
    assert_eq!(
        kinds[..2],
        [StepKind::SessionEnd, StepKind::Reconnect],
        "the session's end is recorded before the redial it starts"
    );
    assert_eq!(
        session_end(&client.record),
        [(StepOutcome::Ok, Some(Reason::PeerClosed))],
        "the client records the exit's close as an ordinary end"
    );

    // The user gives up while the redials fail: the exit closed it.
    client.cancel.cancel();
    tokio::time::sleep(Duration::from_millis(100)).await; // the closer task
    let snap = client.record.snapshot().unwrap();
    assert_eq!(snap.outcome(), Outcome::ClosedByPeer);
    assert_eq!(
        session_end(&client.record).len(),
        1,
        "no second session_end for a session that already ended"
    );
    reader.abort();
}

/// The client leaves while the exit is sending to it: the exit's send can
/// meet the closed connection before its reader reports the close, and the
/// end must be the client's close either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_leaves_mid_download_is_no_failure_of_the_exit() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut ends = Vec::new();
    for _ in 0..BUSY_ROUNDS {
        let relay = start_relay().await;
        let (share_config, client_config, mut share_rx, mut client_rx) = configs_with(
            downloading_exit(Duration::from_micros(200)),
            Timings::default(),
        );
        let session = share_at(relay, share_config).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let client = connect(session.url.clone(), &client_config).await.unwrap();
        wait_for(&mut client_rx, "the client's session", is_session_up).await;
        wait_for(&mut share_rx, "the exit's session", is_session_up).await;
        let mut transport = client.transport;
        let reader = tokio::spawn(async move { while transport.next().await.is_some() {} });
        tokio::time::sleep(Duration::from_millis(300)).await;

        client.cancel.cancel();
        reader.abort();
        wait_for(&mut share_rx, "the exit's session end", is_session_ended).await;
        ends.push(first_session_end(&session.record));
        session.stop().await;
    }
    let wrong: Vec<_> = ends
        .iter()
        .filter(|e| !matches!(e, Some((StepOutcome::Ok, Some(Reason::PeerClosed), _))))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} of {BUSY_ROUNDS} orderly leaves recorded as something else: {wrong:?}",
        wrong.len()
    );
}

/// The exit stops while the client is sending to it: the client's send can
/// meet the closed connection first — in the router, or in the reconnect
/// layer, which records the session's end the moment a send fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exit_that_stops_mid_upload_is_no_failure_of_the_client() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut ends = Vec::new();
    for _ in 0..BUSY_ROUNDS {
        let relay = start_relay().await;
        let (share_config, client_config, mut share_rx, mut client_rx) =
            configs_with(draining_exit(), Timings::default());
        let session = share_at(relay, share_config).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let client = connect(session.url.clone(), &client_config).await.unwrap();
        wait_for(&mut client_rx, "the client's session", is_session_up).await;
        wait_for(&mut share_rx, "the exit's session", is_session_up).await;
        set_knob(&client, 10);
        let (mut sink, mut stream) = client.transport.split();
        let reader = tokio::spawn(async move { while stream.next().await.is_some() {} });
        let sender = tokio::spawn(async move {
            loop {
                let _ = sink.send(packet()).await;
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        session.stop().await;
        wait_for(&mut client_rx, "the client's redial", is_redial).await;
        ends.push(first_session_end(&client.record));
        client.cancel.cancel();
        reader.abort();
        sender.abort();
    }
    let wrong: Vec<_> = ends
        .iter()
        .filter(|e| !matches!(e, Some((StepOutcome::Ok, Some(Reason::PeerClosed), _))))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} of {BUSY_ROUNDS} orderly stops recorded as something else: {wrong:?}",
        wrong.len()
    );
}

/// A UDP proxy between the client and the relay whose relay-to-client
/// direction can be blackholed. Returns its port.
async fn one_way_proxy(relay: std::net::SocketAddr, drop_downlink: Arc<AtomicBool>) -> u16 {
    let front = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
    let port = front.local_addr().unwrap().port();
    let back = Arc::new(TokioUdp::bind("127.0.0.1:0").await.unwrap());
    back.connect(relay).await.unwrap();
    let client: Arc<std::sync::Mutex<Option<std::net::SocketAddr>>> = Default::default();
    let (f, b, c) = (front.clone(), back.clone(), client.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = f.recv_from(&mut buf).await {
            *c.lock().unwrap() = Some(from);
            let _ = b.send(&buf[..n]).await;
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok(n) = back.recv(&mut buf).await {
            if drop_downlink.load(Ordering::Relaxed) {
                continue;
            }
            let to = *client.lock().unwrap();
            if let Some(to) = to {
                let _ = front.send_to(&buf[..n], to).await;
            }
        }
    });
    port
}

/// The client's downlink dies while its uplink works: its keepalive gives
/// up on the session — and the close it sends, which does reach the exit,
/// says the session died. The exit records a failure, not an ordinary leave.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_whose_tunnel_died_is_a_failure_of_the_exit_too() {
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = start_relay().await;
    let drop_downlink = Arc::new(AtomicBool::new(false));
    let proxy_port = one_way_proxy(relay, drop_downlink.clone()).await;
    let timings = Timings {
        keepalive_response_timeout: Duration::from_millis(500),
        keepalive_inbound_grace: Duration::from_secs(1),
        ..Timings::default()
    };
    let (share_config, client_config, mut share_rx, mut client_rx) =
        configs_with(downloading_exit(Duration::from_millis(100)), timings);
    let session = share_at(relay, share_config).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut token = Token::from_url(&session.url).unwrap();
    token.relays = vec![RelayEndpoint::new("127.0.0.1", proxy_port)];
    let client = connect(token.to_url(), &client_config).await.unwrap();
    wait_for(&mut client_rx, "the client's session", is_session_up).await;
    wait_for(&mut share_rx, "the exit's session", is_session_up).await;
    set_knob(&client, 1);
    let mut transport = client.transport;
    let reader = tokio::spawn(async move { while transport.next().await.is_some() {} });
    tokio::time::sleep(Duration::from_millis(500)).await;

    drop_downlink.store(true, Ordering::Relaxed);
    wait_for(&mut client_rx, "the client's redial", is_redial).await;
    wait_for(&mut share_rx, "the exit's session end", is_session_ended).await;
    assert_eq!(
        session_end(&client.record),
        [(StepOutcome::Failed, Some(Reason::KeepaliveTimeout))]
    );
    let exit_end = first_session_end(&session.record);
    assert!(
        matches!(
            exit_end,
            Some((StepOutcome::Failed, Some(Reason::TransportClosed), _))
        ),
        "the exit heard the client's session die: {exit_end:?}"
    );
    let exit_record = session.record.clone();
    session.stop().await;
    assert_eq!(exit_record.snapshot().unwrap().outcome(), Outcome::Lost);
    client.cancel.cancel();
    reader.abort();
}

/// The exit's handler gives up on a healthy session: the client hears the
/// session died, not that the exit ended it on purpose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exit_that_fails_is_a_failure_of_the_client() {
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = start_relay().await;
    let (share_config, client_config, mut share_rx, mut client_rx) =
        configs_with(failing_exit(Duration::from_millis(500)), Timings::default());
    let session = share_at(relay, share_config).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = connect(session.url.clone(), &client_config).await.unwrap();
    wait_for(&mut client_rx, "the client's session", is_session_up).await;
    set_knob(&client, 10);
    let mut transport = client.transport;
    let reader = tokio::spawn(async move { while transport.next().await.is_some() {} });

    wait_for(&mut share_rx, "the exit's session end", is_session_ended).await;
    wait_for(&mut client_rx, "the client's redial", is_redial).await;
    let client_end = first_session_end(&client.record);
    assert!(
        matches!(
            client_end,
            Some((StepOutcome::Failed, Some(Reason::TransportClosed), _))
        ),
        "the client heard the exit's session die: {client_end:?}"
    );
    client.cancel.cancel();
    reader.abort();
    session.stop().await;
}

/// A client process stops and exits at once — its runtime, and with it the
/// connection's driver, gone right after — as `spora use` does on Ctrl+C.
/// `RunStopper::stop` returns only once the close is on its way, so the exit
/// still records an orderly leave, promptly, instead of its keepalive
/// declaring the session dead later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_process_that_exits_right_after_stopping_still_says_goodbye() {
    let _ = env_logger::builder().is_test(true).try_init();
    const ROUNDS: usize = 10;
    let mut ends = Vec::new();
    for _ in 0..ROUNDS {
        let relay = start_relay().await;
        // A dead client must show within the wait below.
        let timings = Timings {
            quic_idle_timeout: Duration::from_secs(8),
            ..Timings::default()
        };
        let (share_config, client_config, mut share_rx, _client_rx) =
            configs_with(draining_exit(), timings);
        let session = share_at(relay, share_config).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        // The client, in a runtime of its own that goes away with it.
        let url = session.url.clone();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let client = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let client = connect(url, &client_config).await.unwrap();
                let _ = stop_rx.await;
                client.stopper.stop().await;
                drop(client.transport);
            });
            rt.shutdown_background();
        });
        wait_for(&mut share_rx, "the exit's session", is_session_up).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop_tx.send(()).unwrap();
        client.join().unwrap();

        wait_for_within(
            &mut share_rx,
            "the exit's session end",
            Duration::from_secs(15),
            is_session_ended,
        )
        .await;
        ends.push(first_session_end(&session.record));
        session.stop().await;
    }
    let wrong: Vec<_> = ends
        .iter()
        .filter(|e| !matches!(e, Some((StepOutcome::Ok, Some(Reason::PeerClosed), _))))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} of {ROUNDS} clients that stopped and exited were not heard leaving: {wrong:?}",
        wrong.len()
    );
}
