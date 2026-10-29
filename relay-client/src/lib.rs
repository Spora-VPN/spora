//! Client side of the dumb UDP relay protocol: shared wire-protocol constants
//! plus a small registration helper that sharers use to announce themselves.
//!
//! The relay token is opaque here, end to end: this crate carries whatever
//! bytes a share's [`Credential`] says to present and knows nothing of their
//! format.

use std::net::SocketAddr;
use std::sync::Arc;

use log::{debug, info, warn};

pub mod credential;
pub mod protocol;
pub mod tcp;

pub use credential::{Credential, Credentials};
pub use protocol::{CERT_HASH_LEN, ROUTING_HASH_LEN, SHARE_ID_LEN};

/// Default interval between REGISTER packets sent by the sharer to the relay.
/// Short enough that the relay's registration entry never expires under
/// normal conditions (relay's default registration timeout is 120s).
pub const DEFAULT_REGISTER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// One relay address a registrar announces to, and what it presents there.
#[derive(Clone, Debug)]
pub struct RegisterTarget {
    pub addr: SocketAddr,
    pub credential: Credential,
}

/// Run a sharer-side registration loop on `socket` (the share's QUIC listener
/// or its nz socket, as `kind` says), sending a freshly *signed* REGISTER to
/// EVERY target every `interval` (a new timestamp +
/// signature per packet, so the relay's replay guard accepts our refreshes
/// but rejects a captured copy replayed from elsewhere), and at once whenever
/// the share's relay token changes (`credentials`). Cancel by dropping the
/// task or the socket.
///
/// A per-relay send error is logged and skipped, never fatal — on a
/// dual-stack socket a host without a route to one family (e.g. a v4-only
/// host and a v6 relay) keeps registering with the relays it CAN reach, so a
/// matching-family client still finds it. Such an error repeats every
/// interval for as long as the share runs, and again from every listener
/// the share rolls to, so it is a warning when an address starts failing (or
/// fails differently) and once more when it works again, per process (what
/// this host can send to is no one share's business); the repeats in
/// between are debug lines.
///
/// `socket` should be shared (e.g. via `Arc<UdpSocket>`) with quinn's server
/// endpoint so a single NAT mapping is used for both registration and
/// incoming peer connections.
pub async fn register_loop(
    socket: Arc<tokio::net::UdpSocket>,
    kind: protocol::RegisterKind,
    targets: Vec<RegisterTarget>,
    interval: std::time::Duration,
    signer: Arc<std::sync::Mutex<protocol::RegisterSigner>>,
    credentials: Credentials,
) {
    let mut changed = credentials.subscribe();
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            r = changed.changed() => {
                if r.is_err() {
                    // Every sender is gone, so no token will change again;
                    // keep the plain cadence.
                    tick.tick().await;
                } else {
                    // A new token: present it now, then the next refresh one
                    // full interval later.
                    tick.reset();
                }
            }
        }
        for target in &targets {
            // A fresh packet per relay: each carries a strictly-increasing
            // timestamp, so the relays never see a "replayed" (equal-ts) copy.
            // The signer is SHARED across a share's successive registrar
            // instances (the rolling listener re-registers from a fresh
            // socket per accepted session) and carriers: one strictly-
            // increasing timestamp series per routing hash means a new
            // instance's first REGISTER can never be rejected as a replay of
            // the old instance's last.
            let token = credentials.token(&target.credential);
            let pkt = signer
                .lock()
                .expect("register signer")
                .register_packet(kind, &token);
            let sent = socket.send_to(&pkt, target.addr).await;
            note_send(target.addr, sent.err());
        }
    }
}

/// What a send failed with: enough to tell one failure from another.
type SendError = (std::io::ErrorKind, Option<i32>);

/// The error each address's last REGISTER send failed with, process-wide.
static SEND_FAILURES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<SocketAddr, SendError>>,
> = std::sync::LazyLock::new(Default::default);

/// Log a REGISTER send's outcome: a warning when sending to `addr` starts
/// failing or fails differently, a note when it works again, debug lines for
/// the repeats.
fn note_send(addr: SocketAddr, error: Option<std::io::Error>) {
    let mut failures = SEND_FAILURES.lock().unwrap_or_else(|e| e.into_inner());
    match error {
        None => {
            if failures.remove(&addr).is_some() {
                info!("register_loop: sending to {addr} works again");
            }
        }
        Some(e) => {
            let what = (e.kind(), e.raw_os_error());
            if failures.insert(addr, what) == Some(what) {
                debug!("register_loop: send_to {addr} failed: {e}");
            } else {
                warn!("register_loop: send_to {addr} failed: {e} (logged again when it changes)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Classified, RegisterKind, classify, ctrl, verify_register};
    use std::time::Duration;

    fn signer() -> Arc<std::sync::Mutex<protocol::RegisterSigner>> {
        let ck = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        Arc::new(std::sync::Mutex::new(
            protocol::RegisterSigner::new(ck.cert.der(), &ck.key_pair.serialize_der(), [1; 8])
                .unwrap(),
        ))
    }

    async fn recv_token(sock: &tokio::net::UdpSocket) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("a REGISTER")
            .unwrap();
        let Classified::Control { ty, body } = classify(&buf[..n]) else {
            panic!("not a control packet")
        };
        assert_eq!(ty, ctrl::REGISTER_V2);
        verify_register(RegisterKind::Quic, body)
            .unwrap()
            .1
            .to_vec()
    }

    #[tokio::test]
    async fn each_target_gets_its_credential_and_a_new_token_goes_out_at_once() {
        let spora = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let open = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fixed = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let creds = Credentials::new(Some(b"tok-1".to_vec()));
        let targets = vec![
            RegisterTarget {
                addr: spora.local_addr().unwrap(),
                credential: Credential::Spora,
            },
            RegisterTarget {
                addr: open.local_addr().unwrap(),
                credential: Credential::None,
            },
            RegisterTarget {
                addr: fixed.local_addr().unwrap(),
                credential: Credential::Static(b"bearer".to_vec()),
            },
        ];
        let task = tokio::spawn(register_loop(
            sock,
            RegisterKind::Quic,
            targets,
            Duration::from_secs(3600),
            signer(),
            creds.clone(),
        ));
        assert_eq!(recv_token(&spora).await, b"tok-1");
        assert_eq!(recv_token(&open).await, b"");
        assert_eq!(recv_token(&fixed).await, b"bearer");

        // An hour-long interval: only the token change can send again now.
        creds.set_spora_token(Some(b"tok-2".to_vec()));
        assert_eq!(recv_token(&spora).await, b"tok-2");
        assert_eq!(recv_token(&open).await, b"");
        assert_eq!(recv_token(&fixed).await, b"bearer");
        task.abort();
    }
}
