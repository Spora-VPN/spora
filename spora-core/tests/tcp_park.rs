//! A share's pool of connections parked at a TCP/TLS relay, against relays
//! that close what they hold, refuse it, or are not there. Over loopback.
//!
//! What loopback cannot show is a parked connection that dies with no FIN
//! and no RST (the relay host lost power, a NAT forgot it): that is the
//! kernel's keepalive, and it takes a network that drops packets. See
//! `tcp_parked_pool_survives_relay_power_loss` in spora-lab's `recovery`
//! suite.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};

use spora_core::identity::{
    Credential, DeviceIdentity, RelayEndpoint, RelayEntry, RelayProtocol, Share,
};
use spora_core::{Config, ExitMode, SessionHandler, Timings, connect, share};

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

/// A share that gives a dial to its relay `relay_dial_timeout`, and takes a
/// parked connection the relay closes after twice that for one the relay had
/// taken (8 s and 16 s outside tests).
fn share_config(relay_dial_timeout: Duration) -> Config {
    Config {
        exit_mode: ExitMode::Custom(idle_exit()),
        enable_direct_upgrade: false,
        dns_forwarder: None,
        timings: Timings {
            relay_dial_timeout,
            ..Timings::default()
        },
        ..Config::default()
    }
}

fn client_config() -> Config {
    Config {
        enable_direct_upgrade: false,
        timings: Timings {
            relay_dial_timeout: Duration::from_secs(2),
            ..Timings::default()
        },
        ..Config::default()
    }
}

fn tcp_relay(addr: SocketAddr) -> RelayEntry {
    RelayEntry {
        endpoint: RelayEndpoint::with_protocol("127.0.0.1", addr.port(), RelayProtocol::TcpTls),
        credential: Credential::None,
    }
}

async fn wait_for(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Connections a share keeps parked per relay address unless it is set
/// otherwise (`Config::tcp_park_pool`).
const POOL: usize = spora_core::DEFAULT_TCP_PARK_POOL;

/// Reads what a share parks, like a relay, and splices nobody in. With
/// `hold` it keeps the connections until `close_all`; without, it closes
/// each one as soon as its preamble is read, as a relay refusing the park
/// does. A FIN either way: the preamble was read.
struct FakeRelay {
    addr: SocketAddr,
    parked: Arc<Mutex<Vec<Park>>>,
}

/// A park a [`FakeRelay`] read: when, and its connection while held.
struct Park {
    at: Instant,
    conn: Option<TcpStream>,
}

impl FakeRelay {
    async fn start(hold: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let parked = Arc::new(Mutex::new(Vec::new()));
        let seen = parked.clone();
        tokio::spawn(async move {
            loop {
                let (mut conn, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let read =
                        relay_client::tcp::read_preamble(&mut conn, Duration::from_secs(5)).await;
                    if matches!(read, Ok(relay_client::tcp::Preamble::Park { .. })) {
                        seen.lock().unwrap().push(Park {
                            at: Instant::now(),
                            conn: hold.then_some(conn),
                        });
                    }
                });
            }
        });
        Self { addr, parked }
    }

    /// Parks read so far.
    fn parks(&self) -> usize {
        self.parked.lock().unwrap().len()
    }

    /// Parks read after `t`.
    fn parks_after(&self, t: Instant) -> usize {
        let parked = self.parked.lock().unwrap();
        parked.iter().filter(|park| park.at > t).count()
    }

    fn close_all(&self) {
        for park in self.parked.lock().unwrap().iter_mut() {
            park.conn.take();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_the_relay_dropped_is_parked_again_while_a_client_would_wait() {
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = FakeRelay::start(true).await;
    let device = DeviceIdentity::generate();
    let sh = Share::new(&device, vec![tcp_relay(relay.addr)]).unwrap();
    let dial_timeout = Duration::from_millis(250);
    let session = share(device, sh, share_config(dial_timeout))
        .await
        .expect("share()");

    // A relay drops parked connections it had taken when it restarts, and
    // when a client comes for ones it holds longer than its `PARK_TTL`. That
    // client then waits 3 s (`CONNECT_WAIT`) for a new one. However often
    // the pool has been dropped before, the next must come within that.
    for round in 1..=5 {
        wait_for("a parked pool", Duration::from_secs(5), || {
            relay.parks() >= POOL * round
        })
        .await;
        // Long enough parked to have been taken (twice the dial timeout).
        tokio::time::sleep(dial_timeout * 3).await;
        let dropped = Instant::now();
        relay.close_all();
        wait_for(
            &format!("the pool to come back (round {round})"),
            relay::tcp::CONNECT_WAIT - Duration::from_millis(500),
            || relay.parks_after(dropped) > 0,
        )
        .await;
    }
    session.stop().await;
}

/// `Config::tcp_park_pool`: a share keeps that many connections parked per
/// relay address, no more, and refills to that many.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_share_parks_as_many_connections_as_it_is_set_to() {
    let _ = env_logger::builder().is_test(true).try_init();
    assert_eq!(POOL, 4);
    assert_eq!(Config::default().tcp_park_pool, POOL);
    let dial_timeout = Duration::from_millis(250);
    let mut sessions = Vec::new();
    // The default beside a smaller and a larger pool, so that neither
    // number is 4 by accident; then no pool at all.
    for pool in [POOL, 2, 7, 0] {
        let relay = FakeRelay::start(true).await;
        let device = DeviceIdentity::generate();
        let sh = Share::new(&device, vec![tcp_relay(relay.addr)]).unwrap();
        let config = Config {
            tcp_park_pool: pool,
            ..share_config(dial_timeout)
        };
        let session = share(device, sh, config).await.expect("share()");
        wait_for("the pool", Duration::from_secs(5), || relay.parks() >= pool).await;
        // Nothing beyond it, however long the share is left alone.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(relay.parks(), pool, "parked with a pool of {pool}");

        // Each connection the relay drops (having taken it) is replaced,
        // one for one.
        if pool > 0 {
            let dropped = Instant::now();
            relay.close_all();
            wait_for("the pool again", Duration::from_secs(5), || {
                relay.parks_after(dropped) >= pool
            })
            .await;
            tokio::time::sleep(Duration::from_millis(700)).await;
            assert_eq!(relay.parks_after(dropped), pool, "re-parked of {pool}");
        }
        sessions.push(session);
    }
    for session in sessions {
        session.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_parks_still_back_off() {
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = FakeRelay::start(false).await;
    let device = DeviceIdentity::generate();
    let sh = Share::new(&device, vec![tcp_relay(relay.addr)]).unwrap();
    let session = share(device, sh, share_config(Duration::from_secs(8)))
        .await
        .expect("share()");

    // Each worker parks, is refused at once, and waits 0.5 s, 1 s, 2 s...:
    // 3 parks each in the first 3 s. A refusal taken for a dropped
    // connection would be answered at once instead, thousands of times.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let parks = relay.parks();
    assert!(
        (POOL * 2..=POOL * 4).contains(&parks),
        "{parks} parks in 3 s of refusals"
    );
    session.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_share_is_reached_at_the_first_dial() {
    let _ = env_logger::builder().is_test(true).try_init();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(relay::tcp::serve_tcp(
        listener,
        relay::tcp::TcpRelayState::new(),
    ));

    let device = DeviceIdentity::generate();
    let sh = Share::new(&device, vec![tcp_relay(relay_addr)]).unwrap();
    let config = || share_config(Duration::from_secs(8));
    let first = share(device.clone(), sh.clone(), config())
        .await
        .expect("share()");
    tokio::time::sleep(Duration::from_millis(500)).await;
    first.stop().await;

    // The relay still holds what the first run parked, ahead of what this
    // one parks, and counts it for 90 s. The first run closed all of it, so
    // the relay must pass it over, not splice the client into it.
    let second = share(device, sh, config()).await.expect("share()");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        connect(second.url.clone(), &client_config()),
    )
    .await
    .expect("connect timed out")
    .expect("the client met a connection the stopped share had parked");
    client.stopper.stop().await;
    second.stop().await;
}

/// A host that is down, as far as TCP can tell on loopback: a listener
/// whose accept queue is full and that nobody accepts from, so the kernel
/// drops every further SYN and says nothing.
#[cfg(target_os = "linux")]
struct SilentHost {
    addr: SocketAddr,
    _listener: socket2::Socket,
    _queued: Vec<std::net::TcpStream>,
}

#[cfg(target_os = "linux")]
impl SilentHost {
    fn start() -> Self {
        use socket2::{Domain, Socket, Type};
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        listener.set_reuse_address(true).unwrap();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        listener.bind(&any.into()).unwrap();
        listener.listen(0).unwrap();
        let addr = listener.local_addr().unwrap().as_socket().unwrap();
        let mut queued = Vec::new();
        for _ in 0..16 {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
                Ok(conn) => queued.push(conn),
                Err(_) => {
                    return Self {
                        addr,
                        _listener: listener,
                        _queued: queued,
                    };
                }
            }
        }
        panic!("the listener kept taking connections");
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dial_to_a_relay_that_is_down_is_given_up_and_made_again() {
    let _ = env_logger::builder().is_test(true).try_init();
    let down = tokio::task::spawn_blocking(SilentHost::start)
        .await
        .unwrap();
    let relay_addr = down.addr;

    let device = DeviceIdentity::generate();
    let sh = Share::new(&device, vec![tcp_relay(relay_addr)]).unwrap();
    let session = share(device, sh, share_config(Duration::from_millis(300)))
        .await
        .expect("share()");

    // Left to the kernel, a connect repeats its SYN ever more rarely: Linux
    // sends one 11 s after the first and the next at 19 s (before 6.5: at
    // 7 s and 15 s). The host comes back in that gap, where a worker still
    // inside its first connect would park 3.7 s later at best. One that
    // gives a dial up and dials again every 1.3 s parks well within that.
    tokio::time::sleep(Duration::from_millis(11_300)).await;
    drop(down);
    let after = relay::tcp::TcpRelayState::new();
    let listener = TcpListener::bind(relay_addr)
        .await
        .expect("the relay's port again");
    tokio::spawn(relay::tcp::serve_tcp(listener, after.clone()));
    wait_for(
        "the share to park at the relay that came back",
        Duration::from_millis(2500),
        || after.parked_key_count() == 1,
    )
    .await;
    session.stop().await;
}
