//! A running share's relay token can be renewed without touching the share:
//! `ShareSession::update_relay_token` makes every registrar send a REGISTER
//! at once (not at its next tick) and an empty TCP park pool refill at once
//! (not after its retry backoff). Against relays that check a token, over
//! loopback.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket as TokioUdp;

use spora_core::identity::{
    Credential, DeviceIdentity, RelayEndpoint, RelayEntry, RelayProtocol, Share,
};
use spora_core::{Config, ExitMode, SessionHandler, Timings, connect, share};

const TOKEN: &[u8] = b"relay-token-1";

fn token_relay() -> Arc<dyn relay::authz::Authorizer> {
    Arc::new(relay::authz::StaticToken::new(TOKEN.to_vec()).unwrap())
}

/// Holds the session open until it is cancelled (a dropped transport closes
/// its connection).
fn idle_exit() -> SessionHandler {
    Arc::new(|transport, cancel| {
        Box::pin(async move {
            let _held = transport;
            cancel.cancelled().await
        })
    })
}

/// A share config whose registrars would wait an hour between REGISTERs:
/// anything sooner was the token update's doing.
fn share_config() -> Config {
    Config {
        exit_mode: ExitMode::Custom(idle_exit()),
        enable_direct_upgrade: false,
        dns_forwarder: None,
        relay_token: None,
        timings: Timings {
            register_interval: Duration::from_secs(3600),
            ..Timings::default()
        },
        ..Config::default()
    }
}

fn client_config() -> Config {
    Config {
        enable_direct_upgrade: false,
        timings: Timings {
            relay_dial_timeout: Duration::from_secs(1),
            reconnect_delay: Duration::from_millis(200),
            ..Timings::default()
        },
        ..Config::default()
    }
}

fn spora_entry(endpoint: RelayEndpoint) -> RelayEntry {
    RelayEntry {
        endpoint,
        credential: Credential::Spora,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_token_registers_at_once() {
    let _ = env_logger::builder().is_test(true).try_init();
    let sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = sock.local_addr().unwrap();
    tokio::spawn(relay::serve(
        sock,
        relay::State::default().with_authorizer(token_relay()),
    ));

    let device = DeviceIdentity::generate();
    let sh = Share::new(
        &device,
        vec![spora_entry(RelayEndpoint::new(
            "127.0.0.1",
            relay_addr.port(),
        ))],
    )
    .unwrap();
    let session = share(device, sh, share_config()).await.expect("share()");
    // Started degraded: the relay refused the tokenless REGISTER, so the
    // share cannot be reached.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        connect(session.url.clone(), &client_config())
            .await
            .is_err(),
        "a share whose registration was refused must be unreachable"
    );

    session.update_relay_token(Some(TOKEN.to_vec()));
    let started = Instant::now();
    let client = tokio::time::timeout(
        Duration::from_secs(10),
        connect(session.url.clone(), &client_config()),
    )
    .await
    .expect("connect timed out")
    .expect("the new token registered the share at once, not an hour later");
    assert!(started.elapsed() < Duration::from_secs(10));
    client.stopper.stop().await;
    session.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_token_refills_a_refused_park_pool_at_once() {
    let _ = env_logger::builder().is_test(true).try_init();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let state = relay::tcp::TcpRelayState::with_authorizer(token_relay());
    tokio::spawn(relay::tcp::serve_tcp(listener, state.clone()));

    let device = DeviceIdentity::generate();
    let sh = Share::new(
        &device,
        vec![spora_entry(RelayEndpoint::with_protocol(
            "127.0.0.1",
            relay_addr.port(),
            RelayProtocol::TcpTls,
        ))],
    )
    .unwrap();
    let session = share(device, sh, share_config()).await.expect("share()");
    // Refused parks back off: 0.5 s, 1 s, 2 s, 4 s — after 8 s the workers
    // are well into a long wait.
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(
        state.parked_key_count(),
        0,
        "every tokenless park is refused"
    );

    session.update_relay_token(Some(TOKEN.to_vec()));
    let deadline = Instant::now() + Duration::from_secs(2);
    while state.parked_key_count() == 0 {
        assert!(
            Instant::now() < deadline,
            "the pool did not refill at once on a new token"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    session.stop().await;
}
