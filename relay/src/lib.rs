//! Dumb UDP relay library. The binary in `main.rs` is a thin wrapper around
//! [`serve`].
//!
//! Wire protocol (see also `relay_client::protocol`):
//!   - A (sharer) sends a signed `REGISTER_V2` (share id + timestamp + cert +
//!     signature, then its relay token) to the relay every ~30s per share.
//!     The relay derives the routing hash `SHA-256(SHA-256(cert)[..20] ||
//!     share_id)[..20]`, verifies the signature, enforces a strictly-
//!     increasing timestamp per routing hash (replay guard), asks its
//!     [`authz::Authorizer`] about the token, and stores
//!     `routing_hash -> A's UDP addr`, one per address family (see
//!     [`Registration`]). It holds no secret — it only verifies.
//!   - B (client) sends a QUIC Initial with DCID = the routing hash. The
//!     relay reads the DCID out of the long header, looks up A's addr,
//!     installs a bidirectional flow `(B_addr <-> A_addr)`, and forwards.
//!   - Subsequent packets (long or short header) from either flow endpoint
//!     are forwarded by source-address lookup. The authorizer is consulted at
//!     registration only, never on the forwarding path: a registration
//!     refused later (a lapsed token) stops new clients from finding the
//!     share, and its live flows run on until they fall idle.
//!   - Idle entries time out (registrations ~120s, flows ~60s).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use log::{debug, info, warn};
use tokio::net::UdpSocket;

use relay_client::protocol::{self, CertHash, Classified, ROUTING_HASH_LEN, RegisterKind, hex};

pub mod authz;
pub mod server;
pub mod sessionlog;
pub mod tcp;
use authz::{Authorizer, Carrier, RegistrationCtx};
use sessionlog::{SessionLog, SessionState};

pub use relay_client::protocol::RoutingHash;

pub const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(120);
pub const FLOW_TIMEOUT: Duration = Duration::from_secs(60);
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
pub const RECV_BUF: usize = 4096;

/// Smallest `nz` (Noise UDP) carrier first packet the relay will route by its
/// leading routing-hash prefix: `routing_hash(20) | session index(4) | a
/// Noise NNpsk0 msg1 (32-byte ephemeral + 16-byte tag = 48)`. The relay reads
/// only the public 20-byte prefix — the same thing it reads from a QUIC
/// Initial's DCID.
pub const NZ_MSG1_MIN: usize = ROUTING_HASH_LEN + 4 + 48;

/// How long after the sharer last sent toward its client the flow still counts
/// as "actively serving" (and so blocks a new client). Must exceed the sharer's
/// QUIC keep-alive cadence (10s) so a live but idle session stays protected
/// between keep-alive PINGs; short enough that a rejected/abandoned connection
/// frees the slot quickly. See the one-at-a-time logic in `handle_packet`.
pub const REVERSE_ACTIVITY_GRACE: Duration = Duration::from_secs(20);

/// One share's registration: where its sharer is in each address family,
/// the last signed timestamp accepted (the replay guard), and which device it
/// is (for the session log).
///
/// A dual-stack sharer registers with a relay listed by both its addresses
/// through both, and each family keeps its own binding: a client is sent to
/// the sharer in the client's own family, so a client that fails over from
/// one family to the other reaches the sharer by its other path too (a
/// sharer whose v4 mapping lapsed is still reachable over v6, and the other
/// way round). A family the sharer has only one binding in serves clients of
/// both. The replay guard stays ONE per registration, across families: the
/// signature does not cover the family, so a guard per family would let a
/// REGISTER captured on one path be replayed from an address of the other
/// and take that family's binding. The sharer spaces its families apart in
/// each round so that they arrive in the order it signed them.
#[derive(Clone, Copy)]
struct Registration {
    v4: Option<Binding>,
    v6: Option<Binding>,
    last_ts: u64,
    cert_hash: CertHash,
}

/// Where a share's sharer is in one address family.
#[derive(Clone, Copy)]
struct Binding {
    addr: SocketAddr,
    seen: Instant,
    /// REGISTERs accepted from the other family since this binding's last
    /// one. A sharer refreshes both families every round, so this stays at
    /// most 1 while both are alive; past that, this family missed a round (a
    /// lost packet, or the sharer lost this family) and its clients go to
    /// the other binding, which it is still refreshing.
    others_since: u32,
}

/// Whether `addr` is an IPv4 peer. A dual-stack socket reports v4 peers
/// v4-mapped; they are v4 here.
fn is_v4(addr: &SocketAddr) -> bool {
    addr.ip().to_canonical().is_ipv4()
}

impl Registration {
    fn new(cert_hash: CertHash) -> Registration {
        Registration {
            v4: None,
            v6: None,
            last_ts: 0,
            cert_hash,
        }
    }

    /// An accepted REGISTER from `src`.
    fn refresh(&mut self, src: SocketAddr, ts: u64, now: Instant) {
        let v4 = is_v4(&src);
        let (own, other) = if v4 {
            (&mut self.v4, &mut self.v6)
        } else {
            (&mut self.v6, &mut self.v4)
        };
        let moved = own.is_some_and(|b| b.addr != src);
        *own = Some(Binding {
            addr: src,
            seen: now,
            others_since: 0,
        });
        if let Some(b) = other {
            b.others_since = b.others_since.saturating_add(1);
            // A v6 binding that moved means the sharer moved: a listener
            // rolled to a new port after accepting a session, or a new
            // network (v6 is rarely translated, so its address is the
            // sharer's own). The v4 binding then still names the old one
            // until its REGISTER follows, FAMILY_GAP later — a listener
            // that takes no new clients — so it is behind until then. A v4
            // binding that moved says nothing of the sharer: a NAT may hand
            // it a new port at any time.
            if moved && !v4 {
                b.others_since = b.others_since.max(2);
            }
        }
        self.last_ts = ts;
    }

    /// Forget bindings not refreshed within `timeout`. False when none is
    /// left.
    fn expire(&mut self, now: Instant, timeout: Duration) -> bool {
        for b in [&mut self.v4, &mut self.v6] {
            if b.is_some_and(|b| now.duration_since(b.seen) >= timeout) {
                *b = None;
            }
        }
        self.v4.is_some() || self.v6.is_some()
    }

    /// Where to send a client arriving from `client`: the sharer in the
    /// client's family while that binding is current, else the other one.
    fn route(&self, client: &SocketAddr) -> Option<SocketAddr> {
        let (own, other) = if is_v4(client) {
            (self.v4, self.v6)
        } else {
            (self.v6, self.v4)
        };
        match (own, other) {
            (Some(own), Some(other)) if own.others_since > 1 => Some(other.addr),
            (Some(own), _) => Some(own.addr),
            (None, other) => other.map(|b| b.addr),
        }
    }

    /// Whether `addr` is one of the sharer's own addresses.
    fn is_sharer(&self, addr: &SocketAddr) -> bool {
        [self.v4, self.v6].iter().flatten().any(|b| b.addr == *addr)
    }
}

/// A forwarding-table entry. Stored under both endpoints of a flow.
#[derive(Clone)]
struct Flow {
    /// Where to forward packets arriving from this entry's key address.
    dst: SocketAddr,
    /// Last time any packet refreshed this entry (for idle expiry).
    ts: Instant,
    /// `true` for the entry keyed by the sharer's address (so its `dst` is the
    /// client). Lets the forwarder record return traffic only for the real
    /// sharer→client direction.
    from_sharer: bool,
    /// On the sharer-keyed entry only: when the sharer last sent toward the
    /// client. `None` until the sharer responds. Drives the "actively serving"
    /// check that protects an established client from being displaced.
    reverse: Option<Instant>,
    /// Shared session accounting for the connection log, present on BOTH of a
    /// flow's entries (so either direction's bytes land in the same totals).
    /// `None` when session logging is disabled — keeps the no-log path free.
    session: Option<Arc<SessionState>>,
}

pub struct State {
    /// `(routing_hash, kind) -> registration`: a share's QUIC listener and
    /// its nz socket are different sockets, registered separately, and a QUIC
    /// Initial is routed to the one, an nz first packet to the other. The
    /// registration's `last_ts` is the replay guard: a REGISTER is only
    /// accepted if its signed timestamp strictly exceeds the stored one, so a
    /// captured registration replayed (e.g. from another source) is rejected
    /// while the genuine sharer keeps refreshing.
    registrations: HashMap<(RoutingHash, RegisterKind), Registration>,
    flows: HashMap<SocketAddr, Flow>,
    registration_timeout: Duration,
    flow_timeout: Duration,
    sweep_interval: Duration,
    /// Who may register (see [`authz`]). [`authz::Open`] by default.
    authorizer: Arc<dyn Authorizer>,
    /// Optional persistent session log (off by default; the deployed binary
    /// attaches one). Records each matched flow for operator accountability —
    /// see [`sessionlog`].
    session_log: Option<SessionLog>,
}

impl Default for State {
    fn default() -> Self {
        Self::with_timeouts(REGISTRATION_TIMEOUT, FLOW_TIMEOUT, SWEEP_INTERVAL)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Forward(SocketAddr),
    Drop,
}

/// Addresses the relay refuses to register or forward to. Unspecified,
/// multicast, and broadcast are never legitimate peer addresses; forwarding to
/// them turns the relay into a reflector/amplifier (one inbound packet → a
/// multicast group, etc.). Loopback is intentionally allowed so the unit/lab
/// tests and local development can run every peer on 127.0.0.1.
///
/// The IP is canonicalized for the *policy check only*: on a dual-stack
/// socket v4 peers appear as v4-mapped (`::ffff:a.b.c.d`), and without
/// canonicalization `::ffff:224.0.0.1` / `::ffff:255.255.255.255` /
/// `::ffff:0.0.0.0` would walk past the v6 arm. The stored/forwarded
/// `SocketAddr` keeps its kernel-reported (mapped) form — send_to with a
/// plain V4 address on an AF_INET6 socket fails.
fn is_relayable(addr: &SocketAddr) -> bool {
    let ip = addr.ip().to_canonical();
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_broadcast(),
        std::net::IpAddr::V6(_) => true,
    }
}

impl State {
    /// Build a `State` with custom expiry timeouts and sweep cadence
    /// (defaults: 120s / 60s / 5s). Used by tests and the e2e lab to make
    /// expiry scenarios run in seconds of wall time.
    pub fn with_timeouts(
        registration_timeout: Duration,
        flow_timeout: Duration,
        sweep_interval: Duration,
    ) -> State {
        State {
            registrations: HashMap::new(),
            flows: HashMap::new(),
            registration_timeout,
            flow_timeout,
            sweep_interval,
            authorizer: Arc::new(authz::Open),
            session_log: None,
        }
    }

    /// Attach a persistent session log (the deployed binary does this; tests
    /// and the lab leave it off). Builder-style so `State::default()` stays
    /// the logging-free path.
    pub fn with_session_log(mut self, log: SessionLog) -> State {
        self.session_log = Some(log);
        self
    }

    /// Decide who may register with `authorizer` instead of accepting every
    /// signed registration. Builder-style. See [`authz`].
    pub fn with_authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> State {
        self.authorizer = authorizer;
        self
    }

    /// Decide what to do with a packet from `src`. Updates internal state
    /// (registrations, flow timestamps) and returns the address to forward
    /// the bytes to, or `Drop`.
    pub fn handle_packet(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Action {
        let classified = protocol::classify(pkt);

        if let Classified::Control { ty, body } = classified {
            self.handle_control(src, ty, body, now);
            return Action::Drop;
        }

        // Existing flow? Forward by source-address lookup. This covers both
        // long- and short-header packets after the first match.
        if let Some(flow) = self.flows.get_mut(&src) {
            flow.ts = now;
            let from_sharer = flow.from_sharer;
            // Record sharer→client return traffic so we can tell an actively
            // served client (protected) from an idle/abandoned flow.
            if from_sharer {
                flow.reverse = Some(now);
            }
            // Session accounting (hot path: one atomic add per direction).
            if let Some(s) = &flow.session {
                if from_sharer {
                    s.add_s2c(pkt.len() as u64);
                } else {
                    s.add_c2s(pkt.len() as u64);
                }
            }
            return Action::Forward(flow.dst);
        }

        // Unmatched source — install a new flow if the packet carries a
        // registered routing hash. Two carriers present it two ways, and the
        // relay treats them identically once the 20 bytes are in hand:
        //   - UdpQuic: a QUIC Initial's DCID (at the QUIC offset).
        //   - NoiseUdp: an nz first packet's leading routing-hash prefix.
        // The nz check runs even when classify() bucketed the (random) first byte
        // as a QUIC long header, as long as the QUIC-DCID lookup missed — so an nz
        // msg1 that merely looks QUIC-shaped is still routed.
        let mut matched: Option<(RoutingHash, RegisterKind)> = None;
        if let Classified::QuicLongHeader { dcid } = classified
            && dcid.len() == ROUTING_HASH_LEN
        {
            let mut rk: RoutingHash = [0u8; ROUTING_HASH_LEN];
            rk.copy_from_slice(dcid);
            if self.registrations.contains_key(&(rk, RegisterKind::Quic)) {
                matched = Some((rk, RegisterKind::Quic));
            }
        }
        if matched.is_none() && pkt.len() >= NZ_MSG1_MIN {
            let mut rk: RoutingHash = [0u8; ROUTING_HASH_LEN];
            rk.copy_from_slice(&pkt[..ROUTING_HASH_LEN]);
            if self.registrations.contains_key(&(rk, RegisterKind::Nz)) {
                matched = Some((rk, RegisterKind::Nz));
            }
        }
        if let Some(key @ (rk, _)) = matched
            && let Some(reg) = self.registrations.get_mut(&key)
        {
            // Sweep only runs when packets arrive, so a quiet relay can
            // still hold a binding well past its timeout. Treat an expired
            // one as absent (and drop it now) — otherwise we'd forward to a
            // dead sharer and, worse, install a flow keyed to its address
            // that blocks its one-flow slot until the flow itself times out.
            if !reg.expire(now, self.registration_timeout) {
                self.registrations.remove(&key);
                debug!(
                    "ignoring expired registration rh {} for client {}",
                    hex(&rk[..4]),
                    src
                );
                return Action::Drop;
            }
            let reg = *reg;
            let cert_hash = reg.cert_hash;
            let Some(sharer_addr) = reg.route(&src) else {
                return Action::Drop;
            };
            // Refuse a self-referential or non-relayable flow *before* the
            // one-at-a-time check, so a spoofed packet can neither bootstrap
            // a self-sustaining loop nor occupy the sharer's flow slot.
            // flows.insert(src, ...) and flows.insert(sharer_addr, ...)
            // collapse to flows[X] = (X) when src == sharer_addr, which
            // would make the relay forward every packet from X back to X
            // forever from a single (spoofed) packet; a source that is the
            // sharer's binding in the other family would loop the relay
            // between the sharer's own two addresses.
            if reg.is_sharer(&src) || !is_relayable(&src) {
                debug!(
                    "refusing self-referential/non-relayable flow for {} (rh {})",
                    src,
                    hex(&rk[..4])
                );
                return Action::Drop;
            }
            // One-at-a-time, but only against an *actively serving* sharer.
            // A flow counts as serving only while the sharer is returning
            // traffic to its current client (within REVERSE_ACTIVITY_GRACE).
            // A party that merely knows the (public) routing key can install
            // a flow and keep sending client→sharer packets, but the sharer
            // never returns sustained traffic to an unauthenticated peer (it
            // closes the QUIC connection on auth failure/timeout), so that
            // flow falls idle and a genuine client can displace it. Without
            // this, a single Initial-shaped packet refreshed every <60s would
            // hold the slot and lock out every real client.
            let mut preserved_reverse = None;
            let mut reused_session: Option<Arc<SessionState>> = None;
            if let Some(existing) = self.flows.get(&sharer_addr).cloned() {
                if existing.dst == src {
                    // Same client re-sending (e.g. an Initial retransmit):
                    // keep its established serving state AND its session, so
                    // a retransmit refreshes rather than opening a duplicate.
                    preserved_reverse = existing.reverse;
                    reused_session = existing.session.clone();
                } else {
                    let serving = existing
                        .reverse
                        .is_some_and(|t| now.duration_since(t) < REVERSE_ACTIVITY_GRACE);
                    if serving {
                        debug!(
                            "dropping client {} for actively-serving sharer {} (rh {})",
                            src,
                            sharer_addr,
                            hex(&rk[..4])
                        );
                        return Action::Drop;
                    }
                    // Idle/abandoned incumbent — close its session and
                    // displace it for this client.
                    if let (Some(log), Some(s)) = (&self.session_log, &existing.session) {
                        log.close_session(s, "displaced");
                    }
                    self.flows.remove(&existing.dst);
                }
            }
            // Open (or reuse, on retransmit) the session for this flow. Only
            // allocated when logging is on, so the no-log path stays free.
            let session = match (reused_session, &self.session_log) {
                (Some(s), _) => Some(s),
                (None, Some(log)) => Some(log.open_session(&rk, &cert_hash, src, sharer_addr)),
                (None, None) => None,
            };
            if let Some(s) = &session {
                // Count the client Initial that installed the flow.
                s.add_c2s(pkt.len() as u64);
            }
            self.flows.insert(
                src,
                Flow {
                    dst: sharer_addr,
                    ts: now,
                    from_sharer: false,
                    reverse: None,
                    session: session.clone(),
                },
            );
            self.flows.insert(
                sharer_addr,
                Flow {
                    dst: src,
                    ts: now,
                    from_sharer: true,
                    reverse: preserved_reverse,
                    session,
                },
            );
            info!(
                "matched client {} <-> sharer {} on rh {}",
                src,
                sharer_addr,
                hex(&rk[..4])
            );
            return Action::Forward(sharer_addr);
        }

        Action::Drop
    }

    fn handle_control(&mut self, src: SocketAddr, ty: u8, body: &[u8], now: Instant) {
        match RegisterKind::from_ctrl(ty) {
            Some(kind) => {
                // Cheap source check before spending a signature verification.
                if !is_relayable(&src) {
                    warn!("ignoring REGISTER from non-relayable source {}", src);
                    return;
                }
                // Verify the signature and derive the routing hash from the
                // cert and share id. We hold no secret — this only proves the
                // registration was made by the key behind the cert hash.
                let (reg, token) = match protocol::verify_register(kind, body) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("rejecting REGISTER from {}: {:?}", src, e);
                        return;
                    }
                };
                let rk = reg.routing_hash;
                let key = (rk, kind);
                // Replay guard: the signed timestamp must strictly exceed the
                // last one accepted for this routing hash. A captured
                // registration replayed (e.g. from an attacker's address)
                // carries an already-seen timestamp and is dropped; the
                // genuine sharer's next refresh always carries a fresh higher
                // one.
                if let Some(existing) = self.registrations.get(&key)
                    && reg.timestamp_millis <= existing.last_ts
                {
                    debug!(
                        "rejecting stale/replayed REGISTER for rh {} from {} (ts {} <= {})",
                        hex(&rk[..4]),
                        src,
                        reg.timestamp_millis,
                        existing.last_ts
                    );
                    return;
                }
                // Authorization last, so the authorizer only ever sees
                // authenticated, fresh registrations.
                let ctx = RegistrationCtx {
                    cert_hash: reg.cert_hash,
                    share_id: reg.share_id,
                    routing_hash: rk,
                    source: src,
                    carrier: match kind {
                        RegisterKind::Quic => Carrier::Quic,
                        RegisterKind::Nz => Carrier::Nz,
                    },
                };
                if !self.authorizer.authorize(&ctx, token, SystemTime::now()) {
                    debug!(
                        "refusing unauthorized REGISTER for rh {} (device {}) from {}",
                        hex(&rk[..4]),
                        hex(&reg.cert_hash[..4]),
                        src
                    );
                    return;
                }
                let entry = self
                    .registrations
                    .entry(key)
                    .or_insert_with(|| Registration::new(reg.cert_hash));
                let fam = if is_v4(&src) { entry.v4 } else { entry.v6 };
                let is_new = fam.is_none();
                entry.refresh(src, reg.timestamp_millis, now);
                if is_new {
                    info!("REGISTER {kind:?} rh {} from {}", hex(&rk[..4]), src);
                } else {
                    debug!(
                        "REGISTER {kind:?} refresh rh {} from {}",
                        hex(&rk[..4]),
                        src
                    );
                }
            }
            None => warn!("unknown control type 0x{:02x} from {}", ty, src),
        }
    }

    /// Drop expired registrations and flows.
    pub fn sweep(&mut self, now: Instant) {
        let before_reg = self.registrations.len();
        let before_flows = self.flows.len();
        let registration_timeout = self.registration_timeout;
        let flow_timeout = self.flow_timeout;
        self.registrations
            .retain(|_, r| r.expire(now, registration_timeout));
        // Close the session log entry for each expired flow before dropping it.
        // The shared `SessionState` makes the close idempotent, so the flow's
        // two entries (which may expire in different sweeps) emit exactly one
        // close. Borrow the log separately from `flows` (disjoint fields).
        let log = self.session_log.as_ref();
        self.flows.retain(|_, flow| {
            let alive = now.duration_since(flow.ts) < flow_timeout;
            if !alive && let (Some(log), Some(s)) = (log, &flow.session) {
                log.close_session(s, "idle");
            }
            alive
        });
        let reg_removed = before_reg - self.registrations.len();
        let flow_removed = before_flows - self.flows.len();
        if reg_removed + flow_removed > 0 {
            debug!(
                "sweep: removed {} registrations, {} flow entries",
                reg_removed, flow_removed
            );
        }
    }

    pub fn registration_count(&self) -> usize {
        self.registrations.len()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// Main recv/forward loop. Runs forever.
pub async fn serve(socket: UdpSocket, mut state: State) {
    let mut buf = vec![0u8; RECV_BUF];
    let mut last_sweep = Instant::now();
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("recv error: {}", e);
                continue;
            }
        };
        let now = Instant::now();
        if let Action::Forward(dst) = state.handle_packet(src, &buf[..n], now)
            && let Err(e) = socket.send_to(&buf[..n], dst).await
        {
            warn!("send_to {} ({} bytes) failed: {}", dst, n, e);
        }
        if now.duration_since(last_sweep) >= state.sweep_interval {
            state.sweep(now);
            last_sweep = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_client::protocol::RegisterSigner;
    use std::sync::Mutex;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A sharer-side registrar for one share of a fresh device (random
    /// ECDSA-P256 cert): `routing_key()` is the routing hash the relay
    /// derives, and `next_register_packet()` a valid REGISTER_V2 each call.
    struct Reg {
        signer: RegisterSigner,
        token: Vec<u8>,
    }

    impl Reg {
        fn routing_key(&self) -> RoutingHash {
            self.signer.routing_hash()
        }

        fn next_register_packet(&mut self) -> Vec<u8> {
            self.signer.register_packet(RegisterKind::Quic, &self.token)
        }

        fn with_token(mut self, token: &[u8]) -> Reg {
            self.token = token.to_vec();
            self
        }
    }

    fn registrar() -> Reg {
        let ck = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        Reg {
            signer: RegisterSigner::new(
                ck.cert.der(),
                &ck.key_pair.serialize_der(),
                rand::random(),
            )
            .unwrap(),
            token: Vec::new(),
        }
    }

    /// An authorizer that records what it was asked and answers `allow`.
    struct Recording {
        allow: bool,
        seen: Mutex<Vec<(RegistrationCtx, Vec<u8>)>>,
    }

    impl Authorizer for Recording {
        fn authorize(&self, ctx: &RegistrationCtx, token: &[u8], _: SystemTime) -> bool {
            self.seen.lock().unwrap().push((*ctx, token.to_vec()));
            self.allow
        }

        fn describe(&self) -> String {
            "recording".into()
        }
    }

    fn recording(allow: bool) -> Arc<Recording> {
        Arc::new(Recording {
            allow,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn initial_with_dcid(dcid: &[u8]) -> Vec<u8> {
        // Minimal QUIC long-header shape: 0xC0, version(4), dcid_len, dcid
        let mut pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, dcid.len() as u8];
        pkt.extend_from_slice(dcid);
        pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        pkt
    }

    fn short_header() -> Vec<u8> {
        vec![0x40, 0x11, 0x22, 0x33, 0x44]
    }

    fn rk(seed: u8) -> RoutingHash {
        [seed; ROUTING_HASH_LEN]
    }

    #[test]
    fn register_then_match_installs_bidirectional_flow() {
        let mut s = State::default();
        let now = Instant::now();
        let a_addr = addr("10.0.0.1:1111");
        let b_addr = addr("10.0.0.2:2222");

        let mut a = registrar();
        let key = a.routing_key();
        assert_eq!(
            s.handle_packet(a_addr, &a.next_register_packet(), now),
            Action::Drop
        );
        assert_eq!(s.registration_count(), 1);

        let initial = initial_with_dcid(&key);
        assert_eq!(
            s.handle_packet(b_addr, &initial, now),
            Action::Forward(a_addr)
        );
        assert_eq!(s.flow_count(), 2);

        let pkt = short_header();
        assert_eq!(s.handle_packet(a_addr, &pkt, now), Action::Forward(b_addr));
        assert_eq!(s.handle_packet(b_addr, &pkt, now), Action::Forward(a_addr));
    }

    // A dual-stack socket's view of a sharer and clients: v4 peers v4-mapped.
    const SHARER6: &str = "[2001:db8::a]:1111";
    const SHARER4: &str = "[::ffff:203.0.113.14]:1111";
    const CLIENT6: &str = "[2001:db8::b]:2222";
    const CLIENT4: &str = "[::ffff:198.51.100.7]:3333";

    #[test]
    fn each_client_reaches_the_sharer_in_its_own_family() {
        let mut s = State::default();
        let now = Instant::now();
        let mut a = registrar();
        s.handle_packet(addr(SHARER6), &a.next_register_packet(), now);
        s.handle_packet(addr(SHARER4), &a.next_register_packet(), now);
        assert_eq!(s.registration_count(), 1, "one registration, two bindings");
        let initial = initial_with_dcid(&a.routing_key());
        assert_eq!(
            s.handle_packet(addr(CLIENT6), &initial, now),
            Action::Forward(addr(SHARER6))
        );
        assert_eq!(
            s.handle_packet(addr(CLIENT4), &initial, now),
            Action::Forward(addr(SHARER4))
        );
    }

    #[test]
    fn a_sharer_in_one_family_serves_clients_of_both() {
        let mut s = State::default();
        let now = Instant::now();
        let mut a = registrar();
        s.handle_packet(addr(SHARER4), &a.next_register_packet(), now);
        let initial = initial_with_dcid(&a.routing_key());
        assert_eq!(
            s.handle_packet(addr(CLIENT6), &initial, now),
            Action::Forward(addr(SHARER4))
        );
    }

    #[test]
    fn a_family_that_misses_a_round_hands_its_clients_to_the_other() {
        let mut s = State::default();
        let now = Instant::now();
        let mut a = registrar();
        let initial = initial_with_dcid(&a.routing_key());
        // A round through both, then one through v4 alone.
        s.handle_packet(addr(SHARER6), &a.next_register_packet(), now);
        s.handle_packet(addr(SHARER4), &a.next_register_packet(), now);
        s.handle_packet(addr(SHARER4), &a.next_register_packet(), now);
        assert_eq!(
            s.handle_packet(addr(CLIENT6), &initial, now),
            Action::Forward(addr(SHARER4))
        );
        // v6 back: its clients go to it again.
        let mut s2 = State::default();
        let mut b = registrar();
        let initial = initial_with_dcid(&b.routing_key());
        s2.handle_packet(addr(SHARER6), &b.next_register_packet(), now);
        s2.handle_packet(addr(SHARER4), &b.next_register_packet(), now);
        s2.handle_packet(addr(SHARER4), &b.next_register_packet(), now);
        s2.handle_packet(addr(SHARER6), &b.next_register_packet(), now);
        assert_eq!(
            s2.handle_packet(addr(CLIENT6), &initial, now),
            Action::Forward(addr(SHARER6))
        );
    }

    #[test]
    fn a_sharer_that_moved_is_looked_for_where_it_went() {
        let mut s = State::default();
        let now = Instant::now();
        let mut a = registrar();
        let initial = initial_with_dcid(&a.routing_key());
        s.handle_packet(addr(SHARER6), &a.next_register_packet(), now);
        s.handle_packet(addr(SHARER4), &a.next_register_packet(), now);
        // The listener rolled: v6 from the new port, v4 not yet.
        let new6 = addr("[2001:db8::a]:1112");
        s.handle_packet(new6, &a.next_register_packet(), now);
        assert_eq!(
            s.handle_packet(addr(CLIENT4), &initial, now),
            Action::Forward(new6),
            "a v4 client must not be sent to the old listener"
        );
        // A NAT moving the v4 binding leaves v6 where it is.
        let mut s = State::default();
        let mut b = registrar();
        let initial = initial_with_dcid(&b.routing_key());
        s.handle_packet(addr(SHARER6), &b.next_register_packet(), now);
        s.handle_packet(addr(SHARER4), &b.next_register_packet(), now);
        s.handle_packet(addr(SHARER6), &b.next_register_packet(), now);
        s.handle_packet(
            addr("[::ffff:203.0.113.14]:4444"),
            &b.next_register_packet(),
            now,
        );
        assert_eq!(
            s.handle_packet(addr(CLIENT6), &initial, now),
            Action::Forward(addr(SHARER6))
        );
    }

    #[test]
    fn a_register_replayed_from_the_other_family_is_refused() {
        let mut s = State::default();
        let now = Instant::now();
        let mut a = registrar();
        let pkt = a.next_register_packet();
        s.handle_packet(addr(SHARER4), &pkt, now);
        // Captured on the v4 path, replayed from a v6 address of the
        // attacker's: one guard across families refuses it.
        s.handle_packet(addr("[2001:db8::66]:6666"), &pkt, now);
        let initial = initial_with_dcid(&a.routing_key());
        assert_eq!(
            s.handle_packet(addr(CLIENT6), &initial, now),
            Action::Forward(addr(SHARER4))
        );
    }

    #[test]
    fn an_expired_binding_hands_its_clients_to_the_other() {
        let mut s = State::with_timeouts(Duration::from_secs(10), FLOW_TIMEOUT, SWEEP_INTERVAL);
        let t0 = Instant::now();
        let mut a = registrar();
        s.handle_packet(addr(SHARER4), &a.next_register_packet(), t0);
        s.handle_packet(
            addr(SHARER6),
            &a.next_register_packet(),
            t0 + Duration::from_secs(5),
        );
        let initial = initial_with_dcid(&a.routing_key());
        assert_eq!(
            s.handle_packet(addr(CLIENT4), &initial, t0 + Duration::from_secs(12)),
            Action::Forward(addr(SHARER6))
        );
        s.sweep(t0 + Duration::from_secs(16));
        assert_eq!(s.registration_count(), 0, "both bindings expired");
    }

    #[test]
    fn a_client_at_the_sharers_other_address_is_refused() {
        let mut s = State::default();
        let now = Instant::now();
        let mut a = registrar();
        // v4 fell behind, so a v4 client would go to the v6 binding: from
        // the sharer's own v4 address that would loop the relay between the
        // sharer's two addresses.
        s.handle_packet(addr(SHARER4), &a.next_register_packet(), now);
        s.handle_packet(addr(SHARER6), &a.next_register_packet(), now);
        s.handle_packet(addr(SHARER6), &a.next_register_packet(), now);
        let initial = initial_with_dcid(&a.routing_key());
        assert_eq!(s.handle_packet(addr(SHARER4), &initial, now), Action::Drop);
        assert_eq!(s.flow_count(), 0);
    }

    #[test]
    fn unregistered_dcid_is_dropped() {
        let mut s = State::default();
        let initial = initial_with_dcid(&rk(0xCC));
        assert_eq!(
            s.handle_packet(addr("1.2.3.4:5"), &initial, Instant::now()),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 0);
    }

    #[test]
    fn short_header_from_unknown_src_is_dropped() {
        let mut s = State::default();
        let pkt = short_header();
        assert_eq!(
            s.handle_packet(addr("1.2.3.4:5"), &pkt, Instant::now()),
            Action::Drop
        );
    }

    #[test]
    fn second_client_dropped_while_first_flow_active() {
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b1 = addr("10.0.0.2:2222");
        let b2 = addr("10.0.0.3:3333");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);
        s.handle_packet(b1, &initial_with_dcid(&key), now);
        assert_eq!(s.flow_count(), 2);
        // The sharer returns traffic to b1, so the flow is actively serving.
        assert_eq!(
            s.handle_packet(a, &short_header(), now),
            Action::Forward(b1)
        );

        // A second client is now dropped while b1 is actively served.
        assert_eq!(
            s.handle_packet(b2, &initial_with_dcid(&key), now),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 2);

        assert_eq!(
            s.handle_packet(b1, &short_header(), now),
            Action::Forward(a)
        );
    }

    #[test]
    fn idle_flow_is_displaced_by_a_new_client() {
        // The #3 fix: a flow with no return traffic from the sharer (an
        // attacker who knows the routing key but can't get served) does not
        // lock out a genuine client.
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let attacker = addr("10.9.9.9:9999");
        let client = addr("10.0.0.2:2222");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);

        // Attacker installs a flow but the sharer never returns traffic to it.
        assert_eq!(
            s.handle_packet(attacker, &initial_with_dcid(&key), now),
            Action::Forward(a)
        );
        // A genuine client displaces the idle flow.
        assert_eq!(
            s.handle_packet(client, &initial_with_dcid(&key), now),
            Action::Forward(a)
        );
        // The sharer now routes to the genuine client, and the attacker's stale
        // entry is gone (its packets no longer match a flow).
        assert_eq!(
            s.handle_packet(a, &short_header(), now),
            Action::Forward(client)
        );
        assert_eq!(
            s.handle_packet(attacker, &short_header(), now),
            Action::Drop
        );
    }

    #[test]
    fn actively_served_flow_becomes_displaceable_after_grace() {
        // An actively-served client is protected, but once the sharer stops
        // returning traffic (e.g. the connection ended) the slot frees up after
        // REVERSE_ACTIVITY_GRACE so a new client is not blocked forever.
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b1 = addr("10.0.0.2:2222");
        let b2 = addr("10.0.0.3:3333");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), t0);
        s.handle_packet(b1, &initial_with_dcid(&key), t0);
        s.handle_packet(a, &short_header(), t0); // sharer serves b1

        // Within the grace window, b2 is refused.
        let mid = t0 + REVERSE_ACTIVITY_GRACE / 2;
        assert_eq!(
            s.handle_packet(b2, &initial_with_dcid(&key), mid),
            Action::Drop
        );

        // After the grace window with no further return traffic, b2 displaces b1.
        let late = t0 + REVERSE_ACTIVITY_GRACE + Duration::from_secs(1);
        assert_eq!(
            s.handle_packet(b2, &initial_with_dcid(&key), late),
            Action::Forward(a)
        );
        assert_eq!(
            s.handle_packet(a, &short_header(), late),
            Action::Forward(b2)
        );
    }

    #[test]
    fn self_referential_flow_is_refused() {
        // A client whose source address equals the registered sharer address
        // (achievable by spoofing the source) must not install a flow: it would
        // collapse to flows[X] = (X) and self-forward forever. Reproduces the
        // single-packet relay loop from the review.
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);
        assert_eq!(
            s.handle_packet(a, &initial_with_dcid(&key), now),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 0, "no self-referential flow installed");
        // And the sharer's slot is still free for a genuine client afterwards.
        let b = addr("10.0.0.2:2222");
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), now),
            Action::Forward(a)
        );
    }

    #[test]
    fn v6_and_mixed_family_flows_forward() {
        // The state machine is family-agnostic: a v6 sharer serves a
        // v4-mapped client (the dual-stack-socket shape) without any
        // normalization of the stored addresses.
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("[2001:db8::1]:1111");
        let b = addr("[::ffff:203.0.113.6]:2222");

        let mut reg = registrar();
        let key = reg.routing_key();
        assert_eq!(
            s.handle_packet(a, &reg.next_register_packet(), now),
            Action::Drop
        );
        assert_eq!(s.registration_count(), 1);

        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), now),
            Action::Forward(a)
        );
        assert_eq!(s.handle_packet(a, &short_header(), now), Action::Forward(b));
        assert_eq!(s.handle_packet(b, &short_header(), now), Action::Forward(a));
    }

    #[test]
    fn v4_mapped_non_relayable_sources_are_refused() {
        // On a dual-stack socket, v4 junk arrives in ::ffff: form — the
        // policy must see through the mapping (multicast/broadcast/
        // unspecified have no v6-arm equivalents).
        let mut s = State::default();
        let now = Instant::now();
        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(addr("[2001:db8::1]:1111"), &reg.next_register_packet(), now);

        for src in [
            "[::ffff:224.0.0.1]:9",
            "[::ffff:255.255.255.255]:9",
            "[::ffff:0.0.0.0]:9",
            "[ff02::1]:9",
        ] {
            assert_eq!(
                s.handle_packet(addr(src), &initial_with_dcid(&key), now),
                Action::Drop,
                "must refuse flow from {src}"
            );
            // A REGISTER (with a valid signature and fresh timestamp) from a
            // non-relayable source must not rebind the key. Control packets
            // always return Drop, so assert on the binding instead.
            s.handle_packet(addr(src), &reg.next_register_packet(), now);
        }
        assert_eq!(s.flow_count(), 0);
        // The genuine sharer still owns the binding: a real client is
        // forwarded to it, not to any of the junk sources.
        let b = addr("[2001:db8::b]:2222");
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), now),
            Action::Forward(addr("[2001:db8::1]:1111"))
        );
    }

    #[test]
    fn register_from_non_relayable_source_is_ignored() {
        let mut s = State::default();
        let now = Instant::now();
        let mut reg = registrar();
        // 0.0.0.0 (unspecified) and a multicast address must not be bound, even
        // with an otherwise-valid signature.
        assert_eq!(
            s.handle_packet(addr("0.0.0.0:9"), &reg.next_register_packet(), now),
            Action::Drop
        );
        assert_eq!(
            s.handle_packet(addr("224.0.0.1:9"), &reg.next_register_packet(), now),
            Action::Drop
        );
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn non_relayable_client_source_installs_no_flow() {
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);
        // A client Initial whose (spoofed) source is multicast must be dropped,
        // so the relay never reflects/amplifies to a multicast group.
        assert_eq!(
            s.handle_packet(addr("224.0.0.5:7"), &initial_with_dcid(&key), now),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 0);
    }

    #[test]
    fn flow_timestamp_refreshes_on_traffic() {
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b = addr("10.0.0.2:2222");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), t0);
        s.handle_packet(b, &initial_with_dcid(&key), t0);

        let t1 = t0 + Duration::from_secs(50);
        s.handle_packet(b, &short_header(), t1);
        s.sweep(t1 + Duration::from_secs(5));
        assert_eq!(s.flow_count(), 2, "flow should still be alive");

        s.sweep(t1 + Duration::from_secs(70));
        assert_eq!(s.flow_count(), 0);
    }

    #[test]
    fn registration_expires_after_timeout() {
        let mut s = State::default();
        let t0 = Instant::now();
        let mut reg = registrar();
        s.handle_packet(addr("10.0.0.1:1"), &reg.next_register_packet(), t0);
        assert_eq!(s.registration_count(), 1);
        s.sweep(t0 + REGISTRATION_TIMEOUT - Duration::from_secs(1));
        assert_eq!(s.registration_count(), 1);
        s.sweep(t0 + REGISTRATION_TIMEOUT + Duration::from_secs(1));
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn expired_registration_does_not_match_even_without_a_sweep() {
        // A quiet relay never sweeps; a client arriving after the timeout
        // must NOT be forwarded to the stale sharer (and no flow installed).
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b = addr("10.0.0.2:2222");
        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), t0);

        let late = t0 + REGISTRATION_TIMEOUT + Duration::from_secs(1);
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), late),
            Action::Drop
        );
        assert_eq!(
            s.flow_count(),
            0,
            "no flow installed off a stale registration"
        );
        assert_eq!(
            s.registration_count(),
            0,
            "stale registration dropped on access"
        );
    }

    #[test]
    fn registration_refresh_extends_timestamp() {
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1");
        let mut reg = registrar();
        s.handle_packet(a, &reg.next_register_packet(), t0);
        let t1 = t0 + REGISTRATION_TIMEOUT - Duration::from_secs(5);
        // A refresh carries a strictly-greater signed timestamp, so the relay
        // accepts it and extends the registration.
        s.handle_packet(a, &reg.next_register_packet(), t1);
        s.sweep(t0 + REGISTRATION_TIMEOUT + Duration::from_secs(1));
        assert_eq!(s.registration_count(), 1);
    }

    #[test]
    fn replayed_register_from_other_source_does_not_rebind() {
        // The #2 fix: an on-path attacker who captures a valid REGISTER cannot
        // rebind the key by replaying it from its own address — the replayed
        // copy carries an already-seen timestamp and is refused.
        let mut s = State::default();
        let now = Instant::now();
        let sharer = addr("10.0.0.1:1111");
        let attacker = addr("10.9.9.9:9999");
        let mut reg = registrar();
        let key = reg.routing_key();

        let pkt = reg.next_register_packet();
        assert_eq!(s.handle_packet(sharer, &pkt, now), Action::Drop);
        // Attacker replays the identical bytes from its own source.
        assert_eq!(s.handle_packet(attacker, &pkt, now), Action::Drop);

        // A client is still routed to the genuine sharer, not the attacker.
        let b = addr("10.0.0.2:2222");
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), now),
            Action::Forward(sharer)
        );
    }

    // --- Authorization ---

    #[test]
    fn open_mode_accepts_tokenless_registration() {
        // The default authorizer is Open: a plain (tokenless) signed
        // registration is accepted.
        let mut s = State::default();
        let mut reg = registrar();
        s.handle_packet(
            addr("10.0.0.1:1"),
            &reg.next_register_packet(),
            Instant::now(),
        );
        assert_eq!(s.registration_count(), 1);
    }

    #[test]
    fn the_authorizer_sees_the_derived_identity_and_the_token() {
        let auth = recording(true);
        let mut s = State::default().with_authorizer(auth.clone());
        let mut reg = registrar().with_token(b"tok");
        let a = addr("10.0.0.1:1111");
        s.handle_packet(a, &reg.next_register_packet(), Instant::now());
        assert_eq!(s.registration_count(), 1);
        let seen = auth.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let (ctx, token) = &seen[0];
        assert_eq!(ctx.routing_hash, reg.routing_key());
        assert_eq!(ctx.cert_hash, reg.signer.cert_hash());
        assert_eq!(ctx.source, a);
        assert_eq!(ctx.carrier, Carrier::Quic);
        assert_eq!(token, b"tok");
    }

    #[test]
    fn a_refused_registration_binds_nothing_and_burns_no_timestamp() {
        let auth = recording(false);
        let mut s = State::default().with_authorizer(auth.clone());
        let mut reg = registrar();
        let refused = reg.next_register_packet();
        s.handle_packet(addr("10.0.0.1:1"), &refused, Instant::now());
        assert_eq!(s.registration_count(), 0);
        // The same packet, once the authorizer relents, is still fresh: a
        // refusal must not advance the replay guard.
        s.authorizer = Arc::new(authz::Open);
        s.handle_packet(addr("10.0.0.1:1"), &refused, Instant::now());
        assert_eq!(s.registration_count(), 1);
    }

    #[test]
    fn stale_and_replayed_registrations_never_reach_the_authorizer() {
        let auth = recording(true);
        let mut s = State::default().with_authorizer(auth.clone());
        let mut reg = registrar();
        let pkt = reg.next_register_packet();
        s.handle_packet(addr("10.0.0.1:1"), &pkt, Instant::now());
        s.handle_packet(addr("10.9.9.9:9"), &pkt, Instant::now());
        assert_eq!(auth.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn static_token_mode_routes_the_holder_and_refuses_the_rest() {
        let mut s = State::default().with_authorizer(Arc::new(
            authz::StaticToken::new(b"bearer".to_vec()).unwrap(),
        ));
        let now = Instant::now();
        let mut without = registrar();
        s.handle_packet(addr("10.0.0.5:5"), &without.next_register_packet(), now);
        let mut wrong = registrar().with_token(b"guess");
        s.handle_packet(addr("10.0.0.6:6"), &wrong.next_register_packet(), now);
        assert_eq!(s.registration_count(), 0);

        let mut reg = registrar().with_token(b"bearer");
        let a = addr("10.0.0.1:1111");
        s.handle_packet(a, &reg.next_register_packet(), now);
        assert_eq!(s.registration_count(), 1);
        assert_eq!(
            s.handle_packet(
                addr("10.0.0.2:2222"),
                &initial_with_dcid(&reg.routing_key()),
                now
            ),
            Action::Forward(a)
        );
    }

    #[test]
    fn two_shares_of_one_device_register_side_by_side() {
        let ck = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        let key = ck.key_pair.serialize_der();
        let mut one = RegisterSigner::new(ck.cert.der(), &key, [1; 8]).unwrap();
        let mut two = RegisterSigner::new(ck.cert.der(), &key, [2; 8]).unwrap();
        assert_ne!(one.routing_hash(), two.routing_hash());
        let mut s = State::default();
        let now = Instant::now();
        let a1 = addr("10.0.0.1:1");
        let a2 = addr("10.0.0.1:2");
        s.handle_packet(a1, &one.register_packet(RegisterKind::Quic, &[]), now);
        s.handle_packet(a2, &two.register_packet(RegisterKind::Quic, &[]), now);
        assert_eq!(s.registration_count(), 2);
        assert_eq!(
            s.handle_packet(
                addr("10.0.0.9:9"),
                &initial_with_dcid(&two.routing_hash()),
                now
            ),
            Action::Forward(a2)
        );
    }

    fn nz_msg1(rh: &RoutingHash) -> Vec<u8> {
        let mut pkt = rh.to_vec();
        pkt.extend_from_slice(&[0x11; NZ_MSG1_MIN - ROUTING_HASH_LEN]);
        pkt
    }

    #[test]
    fn a_shares_quic_and_nz_sockets_register_side_by_side() {
        // One relay port serving both carriers: the share's QUIC listener
        // and nz socket each keep their own registration, and each carrier's
        // first packet goes to its own socket.
        let mut s = State::default();
        let now = Instant::now();
        let mut reg = registrar();
        let quic_sock = addr("10.0.0.1:1000");
        let nz_sock = addr("10.0.0.1:2000");
        s.handle_packet(
            quic_sock,
            &reg.signer.register_packet(RegisterKind::Quic, &[]),
            now,
        );
        s.handle_packet(
            nz_sock,
            &reg.signer.register_packet(RegisterKind::Nz, &[]),
            now,
        );
        // A later QUIC refresh does not take the nz route over.
        s.handle_packet(
            quic_sock,
            &reg.signer.register_packet(RegisterKind::Quic, &[]),
            now,
        );
        assert_eq!(s.registration_count(), 2);
        let rh = reg.routing_key();
        assert_eq!(
            s.handle_packet(addr("10.0.0.7:7"), &initial_with_dcid(&rh), now),
            Action::Forward(quic_sock)
        );
        assert_eq!(
            s.handle_packet(addr("10.0.0.8:8"), &nz_msg1(&rh), now),
            Action::Forward(nz_sock)
        );
    }

    #[test]
    fn an_nz_registration_does_not_route_quic_and_the_reverse() {
        let mut s = State::default();
        let now = Instant::now();
        let mut reg = registrar();
        s.handle_packet(
            addr("10.0.0.1:2000"),
            &reg.signer.register_packet(RegisterKind::Nz, &[]),
            now,
        );
        assert_eq!(
            s.handle_packet(
                addr("10.0.0.7:7"),
                &initial_with_dcid(&reg.routing_key()),
                now
            ),
            Action::Drop
        );
        let mut other = registrar();
        s.handle_packet(
            addr("10.0.0.2:1000"),
            &other.signer.register_packet(RegisterKind::Quic, &[]),
            now,
        );
        assert_eq!(
            s.handle_packet(addr("10.0.0.8:8"), &nz_msg1(&other.routing_key()), now),
            Action::Drop
        );
    }

    #[test]
    fn the_retired_register_type_is_ignored() {
        let mut s = State::default();
        let mut reg = registrar();
        let mut pkt = reg.next_register_packet();
        pkt[protocol::CTRL_MAGIC.len()] = 0x01;
        s.handle_packet(addr("10.0.0.1:1"), &pkt, Instant::now());
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn forged_register_for_a_known_share_is_rejected() {
        // Knowing a share's (public) cert and share id is not enough: a
        // registration naming the victim's cert but signed with another key
        // does not verify, and the attacker's own cert derives a different
        // routing hash.
        let mut s = State::default();
        let now = Instant::now();
        let victim = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        let attacker = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        let share_id = [0x5A; 8];
        let victim_rh = routing_hash_of(victim.cert.der(), &share_id);

        let mut forged = RegisterSigner::new(
            victim.cert.der(),
            &attacker.key_pair.serialize_der(),
            share_id,
        )
        .unwrap();
        s.handle_packet(
            addr("10.9.9.9:9"),
            &forged.register_packet(RegisterKind::Quic, &[]),
            now,
        );
        assert_eq!(s.registration_count(), 0, "forged register must not bind");
        assert_eq!(
            s.handle_packet(addr("10.0.0.2:2"), &initial_with_dcid(&victim_rh), now),
            Action::Drop
        );
    }

    fn routing_hash_of(cert: &[u8], share_id: &[u8; 8]) -> RoutingHash {
        protocol::routing_hash(&protocol::cert_hash(cert), share_id)
    }

    #[test]
    fn malformed_register_is_ignored() {
        let mut s = State::default();
        let mut bad = protocol::CTRL_MAGIC.to_vec();
        bad.push(protocol::ctrl::REGISTER_V2);
        bad.extend_from_slice(&[0xFFu8; 5]);
        assert_eq!(
            s.handle_packet(addr("1.2.3.4:5"), &bad, Instant::now()),
            Action::Drop
        );
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn empty_packet_is_dropped() {
        let mut s = State::default();
        assert_eq!(
            s.handle_packet(addr("1.2.3.4:5"), &[], Instant::now()),
            Action::Drop
        );
    }

    #[tokio::test]
    async fn end_to_end_forwarding_via_real_sockets() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let _serve = tokio::spawn(serve(relay_sock, State::default()));

        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut reg = registrar();
        let key = reg.routing_key();

        a_sock
            .send_to(&reg.next_register_packet(), relay_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let initial = initial_with_dcid(&key);
        b_sock.send_to(&initial, relay_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let recv = tokio::time::timeout(Duration::from_secs(1), a_sock.recv_from(&mut buf))
            .await
            .expect("A should receive B's initial")
            .unwrap();
        assert_eq!(&buf[..recv.0], &initial[..]);
        assert_eq!(recv.1, relay_addr);

        let reply = vec![0x40, 0x00, 0xCA, 0xFE];
        a_sock.send_to(&reply, relay_addr).await.unwrap();
        let recv = tokio::time::timeout(Duration::from_secs(1), b_sock.recv_from(&mut buf))
            .await
            .expect("B should receive A's reply")
            .unwrap();
        assert_eq!(&buf[..recv.0], &reply[..]);
        assert_eq!(recv.1, relay_addr);
    }

    // --- Session logging ---

    use crate::sessionlog::{SessionLog, SessionLogConfig};

    fn fast_log(path: &std::path::Path) -> SessionLog {
        let mut cfg = SessionLogConfig::at(path);
        cfg.flush_interval = Duration::from_millis(20);
        SessionLog::open(cfg).unwrap()
    }

    /// Poll the (async-written) session DB until `pred` passes or 5s elapse.
    fn wait_session<F>(path: &std::path::Path, pred: F)
    where
        F: Fn(&rusqlite::Connection) -> bool,
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(db) = rusqlite::Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ) && pred(&db)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "session log condition not met within 5s"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[test]
    fn session_log_records_matched_flow_with_counts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.sqlite");
        let mut s = State::default().with_session_log(fast_log(&path));

        let now = Instant::now();
        let a = addr("10.0.0.1:1111"); // sharer
        let b = addr("10.0.0.2:2222"); // client
        let mut reg = registrar();
        let key = reg.routing_key();

        s.handle_packet(a, &reg.next_register_packet(), now);
        // Client Initial installs the flow (counted as the first c2s packet).
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), now),
            Action::Forward(a)
        );
        // One sharer→client packet (s2c) and one more client→sharer (c2s).
        s.handle_packet(a, &short_header(), now);
        s.handle_packet(b, &short_header(), now);
        // Idle past the flow timeout → session closed as 'idle' on sweep.
        s.sweep(now + FLOW_TIMEOUT + Duration::from_secs(1));
        // Dropping State drops the SessionLog → writer flushes and exits.
        drop(s);

        let key_hex = hex(&key);
        let device_hex = hex(&reg.signer.cert_hash());
        wait_session(&path, |db| {
            db.query_row(
                "SELECT client_addr, sharer_addr, pkts_c2s, pkts_s2c, end_reason, cert_hash
                 FROM sessions WHERE routing_hash=?1",
                [&key_hex],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                },
            )
            .map(|(client, sharer, c2s, s2c, reason, device)| {
                client == "10.0.0.2:2222"
                    && sharer == "10.0.0.1:1111"
                    && device == device_hex
                    && c2s == 2 // Initial + one short-header
                    && s2c == 1
                    && reason.as_deref() == Some("idle")
            })
            .unwrap_or(false)
        });
    }

    #[test]
    fn session_log_records_displacement() {
        // An idle incumbent (a peer that installed a flow but the sharer never
        // returned traffic to) is closed as 'displaced' when a real client
        // takes the slot.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.sqlite");
        let mut s = State::default().with_session_log(fast_log(&path));

        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let attacker = addr("10.9.9.9:9999");
        let client = addr("10.0.0.2:2222");
        let mut reg = registrar();
        let key = reg.routing_key();

        s.handle_packet(a, &reg.next_register_packet(), now);
        // Attacker installs a flow; the sharer never serves it (stays idle).
        assert_eq!(
            s.handle_packet(attacker, &initial_with_dcid(&key), now),
            Action::Forward(a)
        );
        // A genuine client displaces the idle incumbent.
        assert_eq!(
            s.handle_packet(client, &initial_with_dcid(&key), now),
            Action::Forward(a)
        );
        drop(s);

        wait_session(&path, |db| {
            let displaced: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE client_addr='10.9.9.9:9999' AND end_reason='displaced'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let client_open: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE client_addr='10.0.0.2:2222' AND end_ms IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            displaced == 1 && client_open == 1
        });
    }
}
