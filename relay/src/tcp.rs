//! TCP/TLS relay carrier server.
//!
//! A dumb byte-splicer, the TCP analogue of the UDP relay: sharers PARK
//! connections at their routing key; a client CONNECTs and the relay splices it
//! 1:1 to a parked sharer connection. The end-to-end TLS runs A<->B *through*
//! the splice, so the relay holds no keys and reads no plaintext (parity with
//! the UDP relay — see `lib.rs`).
//!
//! The sharer keeps a small pool of parked connections; the relay pops one per
//! client and blind-splices. No multiplexing (each client is its own splice),
//! no reverse-tunnel control channel — the sharer simply parks another
//! connection to refill the pool after one is consumed.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use log::{debug, info, warn};
use tokio::net::{TcpListener, TcpStream};

use relay_client::protocol::{self, PARK_SIG_DOMAIN, hex};
use relay_client::tcp::{self, Preamble};

use crate::RoutingHash;
use crate::authz::{self, Authorizer, Carrier, RegistrationCtx};

/// How long a parked connection stays eligible. The sharer refreshes its pool
/// well within this; older ones are discarded on pop so a vanished sharer never
/// leaves the relay splicing a client into a dead socket.
pub const PARK_TTL: Duration = Duration::from_secs(90);
/// How long a CONNECT waits for a parked sharer connection to appear (covers the
/// brief window while the sharer refills its pool).
pub const CONNECT_WAIT: Duration = Duration::from_secs(3);
/// Cap on parked connections held per routing hash.
pub const MAX_PARKED: usize = 32;
/// Time-box the preamble read so a silent connection can't pin a task.
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a routing hash's last park timestamp is remembered: the UDP
/// registration expiry, so the replay window is the same on both carriers
/// and the map cannot grow without bound.
pub const PARK_TS_TTL: Duration = crate::REGISTRATION_TIMEOUT;
/// The map is pruned at most this often (on a park), not on every park.
const PARK_TS_PRUNE_EVERY: Duration = Duration::from_secs(5);

struct Parked {
    conn: TcpStream,
    at: Instant,
}

/// The replay guard of parks: per routing hash, the last signed timestamp
/// accepted and when.
struct ParkStamps {
    last: HashMap<RoutingHash, (u64, Instant)>,
    pruned: Instant,
}

/// Shared state: parked sharer connections keyed by routing hash, the parks'
/// replay guard, and who may park.
pub struct TcpRelayState {
    parked: Mutex<HashMap<RoutingHash, VecDeque<Parked>>>,
    stamps: Mutex<ParkStamps>,
    authorizer: Arc<dyn Authorizer>,
}

impl TcpRelayState {
    /// Parks every signed preamble (the [`authz::Open`] authorizer).
    pub fn new() -> Arc<Self> {
        Self::with_authorizer(Arc::new(authz::Open))
    }

    /// Parks what `authorizer` allows.
    pub fn with_authorizer(authorizer: Arc<dyn Authorizer>) -> Arc<Self> {
        Arc::new(Self {
            parked: Mutex::new(HashMap::new()),
            stamps: Mutex::new(ParkStamps {
                last: HashMap::new(),
                pruned: Instant::now(),
            }),
            authorizer,
        })
    }

    fn park(&self, rk: RoutingHash, conn: TcpStream) {
        let mut map = self.parked.lock().unwrap();
        let q = map.entry(rk).or_default();
        while q.len() >= MAX_PARKED {
            q.pop_front(); // drop the oldest rather than grow without bound
        }
        q.push_back(Parked {
            conn,
            at: Instant::now(),
        });
    }

    /// Pop a *fresh* parked connection for `rk`, discarding any that expired.
    fn take_fresh(&self, rk: &RoutingHash) -> Option<TcpStream> {
        let mut map = self.parked.lock().unwrap();
        let q = map.get_mut(rk)?;
        while let Some(p) = q.pop_front() {
            if p.at.elapsed() < PARK_TTL {
                return Some(p.conn);
            }
            // else: stale — discard and keep looking
        }
        None
    }

    /// Take `ts` as the last park timestamp of `rk` if it is fresh
    /// (strictly above the last one taken): checked and taken under one
    /// lock, since parks are read concurrently and a replayed preamble may
    /// race its original. `Err(())` when stale; `Ok(previous)` otherwise,
    /// for [`TcpRelayState::give_back_stamp`] should the park be refused.
    fn take_stamp(
        &self,
        rk: RoutingHash,
        ts: u64,
        now: Instant,
    ) -> Result<Option<(u64, Instant)>, ()> {
        let mut st = self.stamps.lock().unwrap();
        if now.duration_since(st.pruned) >= PARK_TS_PRUNE_EVERY {
            st.last
                .retain(|_, (_, at)| now.duration_since(*at) < PARK_TS_TTL);
            st.pruned = now;
        }
        let previous = st.last.get(&rk).copied();
        if let Some((last, at)) = previous
            && ts <= last
            && now.duration_since(at) < PARK_TS_TTL
        {
            return Err(());
        }
        st.last.insert(rk, (ts, now));
        Ok(previous)
    }

    /// A refused park gives its timestamp back (unless a later park has
    /// taken another since): a refusal must not make the share's own next
    /// park look stale.
    fn give_back_stamp(&self, rk: RoutingHash, ts: u64, previous: Option<(u64, Instant)>) {
        let mut st = self.stamps.lock().unwrap();
        if st.last.get(&rk).is_some_and(|(t, _)| *t == ts) {
            match previous {
                Some(p) => {
                    st.last.insert(rk, p);
                }
                None => {
                    st.last.remove(&rk);
                }
            }
        }
    }

    /// Number of routing hashes with at least one parked connection (for tests).
    pub fn parked_key_count(&self) -> usize {
        self.parked
            .lock()
            .unwrap()
            .values()
            .filter(|q| !q.is_empty())
            .count()
    }

    /// Number of routing hashes whose last park timestamp is remembered (for
    /// tests).
    pub fn stamp_count(&self) -> usize {
        self.stamps.lock().unwrap().last.len()
    }
}

/// Accept loop. Runs forever.
pub async fn serve_tcp(listener: TcpListener, state: Arc<TcpRelayState>) {
    match listener.local_addr() {
        Ok(a) => info!("tcp-relay listening on {a}"),
        Err(_) => info!("tcp-relay listening"),
    }
    loop {
        match listener.accept().await {
            Ok((conn, addr)) => {
                let _ = conn.set_nodelay(true);
                tokio::spawn(handle_conn(conn, addr, state.clone()));
            }
            Err(e) => warn!("tcp accept error: {e}"),
        }
    }
}

async fn handle_conn(mut conn: TcpStream, source: SocketAddr, state: Arc<TcpRelayState>) {
    let preamble = match tcp::read_preamble(&mut conn, PREAMBLE_TIMEOUT).await {
        Ok(p) => p,
        Err(e) => {
            debug!("tcp: bad preamble from {source}: {e:?}");
            return;
        }
    };
    match preamble {
        Preamble::Park { signed, token } => {
            let verified = protocol::parse_signed(&signed)
                .filter(|(_, rest)| rest.is_empty())
                .ok_or(protocol::RegisterVerifyError::Malformed)
                .and_then(|(reg, _)| reg.verify(PARK_SIG_DOMAIN));
            let reg = match verified {
                Ok(r) => r,
                Err(e) => {
                    debug!("tcp: rejecting park from {source}: {e:?}");
                    return;
                }
            };
            let rk = reg.routing_hash;
            let now = Instant::now();
            // Replay guard: without it, anyone who saw one park preamble (it
            // is cleartext) could park connections for that share at will.
            let Ok(previous) = state.take_stamp(rk, reg.timestamp_millis, now) else {
                debug!(
                    "tcp: rejecting stale/replayed park for rh {} from {source}",
                    hex(&rk[..4])
                );
                return;
            };
            let ctx = RegistrationCtx {
                cert_hash: reg.cert_hash,
                share_id: reg.share_id,
                routing_hash: rk,
                source,
                carrier: Carrier::Tcp,
            };
            if !state.authorizer.authorize(&ctx, &token, SystemTime::now()) {
                state.give_back_stamp(rk, reg.timestamp_millis, previous);
                debug!(
                    "tcp: refusing unauthorized park for rh {} (device {}) from {source}",
                    hex(&rk[..4]),
                    hex(&reg.cert_hash[..4])
                );
                return;
            }
            debug!("tcp park rh {} from {source}", hex(&rk[..4]));
            // Park the connection; it lives in the queue until a client pops it.
            state.park(rk, conn);
        }
        Preamble::Connect(rk) => {
            debug!("tcp CONNECT rh {}", hex(&rk[..4]));
            let deadline = Instant::now() + CONNECT_WAIT;
            let sharer = loop {
                if let Some(s) = state.take_fresh(&rk) {
                    break Some(s);
                }
                if Instant::now() >= deadline {
                    break None;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let Some(mut sharer) = sharer else {
                debug!(
                    "tcp: no parked sharer for rh {}; dropping client",
                    hex(&rk[..4])
                );
                return;
            };
            // Blind 1:1 splice — the E2E TLS runs A<->B through here; the relay
            // sees only ciphertext.
            match tokio::io::copy_bidirectional(&mut conn, &mut sharer).await {
                Ok((c2s, s2c)) => {
                    debug!("tcp splice done rh {}: c2s={c2s} s2c={s2c}", hex(&rk[..4]))
                }
                Err(e) => debug!("tcp splice ended rh {}: {e}", hex(&rk[..4])),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_client::protocol::RegisterSigner;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn start_with(state: Arc<TcpRelayState>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(listener, state));
        addr
    }

    async fn start() -> (std::net::SocketAddr, Arc<TcpRelayState>) {
        let state = TcpRelayState::new();
        let addr = start_with(state.clone()).await;
        (addr, state)
    }

    fn signer() -> RegisterSigner {
        let ck = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        RegisterSigner::new(ck.cert.der(), &ck.key_pair.serialize_der(), rand::random()).unwrap()
    }

    /// Poll `parked_key_count` up to ~400 ms.
    async fn wait_parked(state: &Arc<TcpRelayState>, want: usize) -> usize {
        for _ in 0..40 {
            if state.parked_key_count() == want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        state.parked_key_count()
    }

    async fn park(addr: std::net::SocketAddr, preamble: &[u8]) -> TcpStream {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(preamble).await.unwrap();
        s
    }

    #[tokio::test]
    async fn splices_client_to_a_parked_sharer_both_directions() {
        let (addr, state) = start().await;
        let mut sig = signer();
        let rk = sig.routing_hash();

        // Sharer parks a connection.
        let mut sharer = park(addr, &sig.park_preamble(&[])).await;
        assert_eq!(wait_parked(&state, 1).await, 1);

        // Client connects and is spliced.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&tcp::build_connect(&rk)).await.unwrap();

        // client -> sharer
        client.write_all(b"hello-sharer").await.unwrap();
        let mut buf = [0u8; 12];
        sharer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-sharer");

        // sharer -> client
        sharer.write_all(b"hello-client").await.unwrap();
        let mut buf2 = [0u8; 12];
        client.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hello-client");
    }

    #[tokio::test]
    async fn client_with_no_parked_sharer_is_dropped() {
        let (addr, _state) = start().await;
        let rk = [0x77u8; 20];
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&tcp::build_connect(&rk)).await.unwrap();
        // No sharer parked: the relay waits CONNECT_WAIT then closes → EOF.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(CONNECT_WAIT + Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("relay must close the client, not hang")
            .unwrap();
        assert_eq!(n, 0, "client read must hit EOF (relay closed it)");
    }

    #[tokio::test]
    async fn bad_preamble_is_dropped() {
        let (addr, _state) = start().await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        // Wrong magic — parses-and-rejects fast.
        c.write_all(b"XXXXX").await.unwrap();
        let mut buf = [0u8; 1];
        let res = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .expect("relay must close on a bad preamble, not hang");
        match res {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("expected the connection closed, but read {n} bytes"),
        }
    }

    #[tokio::test]
    async fn a_replayed_park_preamble_is_refused() {
        // A preamble is cleartext: a copy sent again (from anywhere) must not
        // park a second connection for the share.
        let (addr, state) = start().await;
        let mut sig = signer();
        let pre = sig.park_preamble(&[]);
        let _first = park(addr, &pre).await;
        assert_eq!(wait_parked(&state, 1).await, 1);
        let mut replay = park(addr, &pre).await;
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), replay.read(&mut buf))
            .await
            .expect("the relay closes a replayed park")
            .unwrap_or(0);
        assert_eq!(n, 0);
        let q = state
            .parked
            .lock()
            .unwrap()
            .get(&sig.routing_hash())
            .map(|q| q.len());
        assert_eq!(q, Some(1), "only the original is parked");
        // The sharer's own next preamble (a higher timestamp) parks fine.
        let _second = park(addr, &sig.park_preamble(&[])).await;
        for _ in 0..40 {
            if state.parked.lock().unwrap()[&sig.routing_hash()].len() == 2 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the fresh park was not parked");
    }

    #[tokio::test]
    async fn a_forged_or_cross_use_signature_is_refused() {
        let (addr, state) = start().await;
        // A UDP REGISTER's signed part, re-framed as a park: wrong domain.
        let mut sig = signer();
        let reg = sig.register_packet(protocol::RegisterKind::Quic, &[]);
        let signed = &reg[protocol::CTRL_MAGIC.len() + 1..];
        let mut p = tcp::TCP_MAGIC.to_vec();
        p.push(tcp::role::PARK_V2);
        p.extend_from_slice(signed);
        p.extend_from_slice(&0u16.to_be_bytes());
        let _c = park(addr, &p).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(state.parked_key_count(), 0);
    }

    #[tokio::test]
    async fn the_authorizer_decides_parks() {
        let state = TcpRelayState::with_authorizer(Arc::new(
            authz::StaticToken::new(b"bearer".to_vec()).unwrap(),
        ));
        let addr = start_with(state.clone()).await;
        let mut sig = signer();

        let _refused = park(addr, &sig.park_preamble(&[])).await;
        let _wrong = park(addr, &sig.park_preamble(b"guess")).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(state.parked_key_count(), 0, "no or wrong token: refused");
        assert_eq!(state.stamp_count(), 0, "a refusal burns no timestamp");

        let _ok = park(addr, &sig.park_preamble(b"bearer")).await;
        assert_eq!(wait_parked(&state, 1).await, 1, "the right token parks");
    }

    #[test]
    fn park_stamps_are_taken_once_and_pruned_after_the_registration_timeout() {
        let state = TcpRelayState::new();
        let t0 = Instant::now();
        assert_eq!(state.take_stamp([1; 20], 100, t0), Ok(None));
        assert_eq!(state.take_stamp([1; 20], 100, t0), Err(()), "a replay");
        assert_eq!(state.take_stamp([1; 20], 99, t0), Err(()), "older");
        let prev = state.take_stamp([1; 20], 101, t0).unwrap();
        assert_eq!(prev.map(|p| p.0), Some(100));
        // A refused 101 gives the stamp back to 100...
        state.give_back_stamp([1; 20], 101, prev);
        assert_eq!(state.take_stamp([1; 20], 100, t0), Err(()));
        assert!(state.take_stamp([1; 20], 101, t0).is_ok());
        // ...but never over a later one taken meanwhile.
        state.give_back_stamp([1; 20], 50, None);
        assert_eq!(state.take_stamp([1; 20], 101, t0), Err(()));
        // Past the TTL the old stamp no longer counts, and a later park
        // (of any routing hash) prunes it.
        let late = t0 + PARK_TS_TTL + Duration::from_secs(1);
        assert!(state.take_stamp([2; 20], 1, late).is_ok());
        assert_eq!(state.stamp_count(), 1, "only the new one");
    }

    #[test]
    fn concurrent_replays_of_one_preamble_park_once() {
        let state = TcpRelayState::new();
        let t0 = Instant::now();
        let taken: usize = std::thread::scope(|s| {
            (0..8)
                .map(|_| s.spawn(|| state.take_stamp([3; 20], 500, t0).is_ok()))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum()
        });
        assert_eq!(taken, 1);
    }
}
