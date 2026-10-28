//! Wire protocol for the TCP/TLS relay carrier.
//!
//! A TCP peer opens a connection to the relay and sends a preamble naming its
//! role. The relay then either PARKS the connection (a sharer offering
//! itself) or SPLICES it to a parked sharer connection (a client). Everything
//! after the preamble is the end-to-end TLS the relay blindly forwards — the
//! relay holds no keys and reads no plaintext, exactly like the UDP relay.
//!
//! - **CONNECT** (client): `magic(4) | CONNECT | routing_hash(20)`. Clients do
//!   not authenticate to relays; the routing hash rides in cleartext because
//!   the relay must read it to route, as the UDP relay reads the DCID.
//! - **PARK_V2** (sharer): `magic(4) | PARK_V2 | signed registration |
//!   token_len(2, BE) | token`, the signed registration being the UDP
//!   REGISTER's ([`crate::protocol::SignedRegistration`]) under its own
//!   signature domain. The relay derives the routing hash from the cert and
//!   share id, verifies the signature, requires a strictly increasing
//!   timestamp per routing hash (so a sniffed preamble cannot be replayed to
//!   park someone else's share), and asks its authorizer about the token.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::protocol::{MAX_CERT_LEN, MAX_SIG_LEN, ROUTING_HASH_LEN, RoutingHash, SIGNED_HEAD_LEN};

/// Preamble magic: "spT2" (spora TCP, share-id registrations). Lets the relay
/// reject port scans / garbage before doing anything.
pub const TCP_MAGIC: [u8; 4] = *b"spT2";

/// Connection roles, in the preamble's role byte.
pub mod role {
    /// A client asks to be spliced to a sharer parked at the routing hash.
    pub const CONNECT: u8 = 0x02;
    /// A sharer parks a connection for one share; the relay holds it until a
    /// client arrives to be spliced.
    pub const PARK_V2: u8 = 0x03;
}

/// Largest relay token the relay will read after a park's signature (a hard
/// cap so a malicious `token_len` can't make the relay buffer unboundedly).
pub const MAX_TOKEN_LEN: usize = 4096;

/// A client's CONNECT preamble.
pub fn build_connect(routing_hash: &RoutingHash) -> Vec<u8> {
    let mut p = Vec::with_capacity(TCP_MAGIC.len() + 1 + ROUTING_HASH_LEN);
    p.extend_from_slice(&TCP_MAGIC);
    p.push(role::CONNECT);
    p.extend_from_slice(routing_hash);
    p
}

/// A sharer's park preamble around an already-signed registration (see
/// [`crate::protocol::RegisterSigner::park_preamble`]).
pub(crate) fn build_park_preamble(signed: &[u8], token: &[u8]) -> Vec<u8> {
    debug_assert!(token.len() <= u16::MAX as usize);
    let mut p = Vec::with_capacity(TCP_MAGIC.len() + 1 + signed.len() + 2 + token.len());
    p.extend_from_slice(&TCP_MAGIC);
    p.push(role::PARK_V2);
    p.extend_from_slice(signed);
    p.extend_from_slice(&(token.len() as u16).to_be_bytes());
    p.extend_from_slice(token);
    p
}

/// Split a preamble buffer into its role and the rest, checking the magic.
pub fn parse_role(buf: &[u8]) -> Option<(u8, &[u8])> {
    if buf.len() < TCP_MAGIC.len() + 1 || buf[..TCP_MAGIC.len()] != TCP_MAGIC {
        return None;
    }
    Some((buf[TCP_MAGIC.len()], &buf[TCP_MAGIC.len() + 1..]))
}

/// A preamble read off a relay connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Preamble {
    Connect(RoutingHash),
    /// `signed` is the whole signed registration (parse it with
    /// [`crate::protocol::parse_signed`] and verify it under
    /// [`crate::protocol::PARK_SIG_DOMAIN`]); `token` is the relay token.
    Park {
        signed: Vec<u8>,
        token: Vec<u8>,
    },
}

/// Why a preamble could not be read. Carries nothing the peer sent.
#[derive(Debug, PartialEq, Eq)]
pub enum PreambleError {
    /// The peer was silent or closed before the preamble was complete.
    Incomplete,
    /// Wrong magic, unknown role, or a length over its cap.
    Malformed,
}

/// Read one preamble from `r`, each read bounded by `timeout` so a silent
/// connection cannot pin the task. Every length is capped before anything
/// is buffered.
pub async fn read_preamble<R: AsyncRead + Unpin>(
    r: &mut R,
    timeout: Duration,
) -> Result<Preamble, PreambleError> {
    let mut head = [0u8; TCP_MAGIC.len() + 1];
    read_exact(r, &mut head, timeout).await?;
    let (role, _) = parse_role(&head).ok_or(PreambleError::Malformed)?;
    match role {
        role::CONNECT => {
            let mut rh = [0u8; ROUTING_HASH_LEN];
            read_exact(r, &mut rh, timeout).await?;
            Ok(Preamble::Connect(rh))
        }
        role::PARK_V2 => {
            let mut signed = vec![0u8; SIGNED_HEAD_LEN];
            read_exact(r, &mut signed, timeout).await?;
            let cert_len =
                u16::from_be_bytes([signed[SIGNED_HEAD_LEN - 2], signed[SIGNED_HEAD_LEN - 1]])
                    as usize;
            if cert_len == 0 || cert_len > MAX_CERT_LEN {
                return Err(PreambleError::Malformed);
            }
            // cert, then the signature's length.
            let at = signed.len();
            signed.resize(at + cert_len + 2, 0);
            read_exact(r, &mut signed[at..], timeout).await?;
            let sig_len =
                u16::from_be_bytes([signed[signed.len() - 2], signed[signed.len() - 1]]) as usize;
            if sig_len == 0 || sig_len > MAX_SIG_LEN {
                return Err(PreambleError::Malformed);
            }
            // signature, then the token's length.
            let at = signed.len();
            signed.resize(at + sig_len + 2, 0);
            read_exact(r, &mut signed[at..], timeout).await?;
            let token_len =
                u16::from_be_bytes([signed[signed.len() - 2], signed[signed.len() - 1]]) as usize;
            signed.truncate(signed.len() - 2);
            if token_len > MAX_TOKEN_LEN {
                return Err(PreambleError::Malformed);
            }
            let mut token = vec![0u8; token_len];
            read_exact(r, &mut token, timeout).await?;
            Ok(Preamble::Park { signed, token })
        }
        _ => Err(PreambleError::Malformed),
    }
}

async fn read_exact<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<(), PreambleError> {
    if buf.is_empty() {
        return Ok(());
    }
    match tokio::time::timeout(timeout, r.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        _ => Err(PreambleError::Incomplete),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{PARK_SIG_DOMAIN, RegisterSigner, SHARE_ID_LEN, parse_signed};

    const T: Duration = Duration::from_millis(200);

    fn signer() -> RegisterSigner {
        let ck = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        RegisterSigner::new(
            ck.cert.der(),
            &ck.key_pair.serialize_der(),
            [3u8; SHARE_ID_LEN],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn park_preamble_round_trips_with_and_without_token() {
        let mut s = signer();
        for token in [vec![], vec![0xABu8; 40]] {
            let p = s.park_preamble(&token);
            let got = read_preamble(&mut &p[..], T).await.unwrap();
            let Preamble::Park { signed, token: t } = got else {
                panic!("expected a park")
            };
            assert_eq!(t, token);
            let (reg, rest) = parse_signed(&signed).unwrap();
            assert!(
                rest.is_empty(),
                "the signed part is exactly the registration"
            );
            let v = reg.verify(PARK_SIG_DOMAIN).unwrap();
            assert_eq!(v.routing_hash, s.routing_hash());
        }
    }

    #[tokio::test]
    async fn connect_round_trips() {
        let rh = [0x9Au8; ROUTING_HASH_LEN];
        let p = build_connect(&rh);
        assert_eq!(p.len(), 25);
        assert_eq!(
            read_preamble(&mut &p[..], T).await,
            Ok(Preamble::Connect(rh))
        );
    }

    #[tokio::test]
    async fn rejects_bad_magic_unknown_role_and_short_input() {
        let rh = [0x01u8; ROUTING_HASH_LEN];
        let mut p = build_connect(&rh);
        p[0] ^= 0xFF;
        assert_eq!(
            read_preamble(&mut &p[..], T).await,
            Err(PreambleError::Malformed)
        );

        let mut p = build_connect(&rh);
        p[4] = 0x01; // the pre-share-id REGISTER role
        assert_eq!(
            read_preamble(&mut &p[..], T).await,
            Err(PreambleError::Malformed)
        );

        let p = build_connect(&rh);
        assert_eq!(
            read_preamble(&mut &p[..10], T).await,
            Err(PreambleError::Incomplete)
        );
        let park = signer().park_preamble(b"tok");
        assert_eq!(
            read_preamble(&mut &park[..park.len() - 1], T).await,
            Err(PreambleError::Incomplete)
        );
    }

    #[tokio::test]
    async fn an_oversized_token_length_is_refused_before_reading_it() {
        let mut p = signer().park_preamble(&[]);
        let n = p.len();
        let big = (MAX_TOKEN_LEN as u16 + 1).to_be_bytes();
        p[n - 2] = big[0];
        p[n - 1] = big[1];
        assert_eq!(
            read_preamble(&mut &p[..], T).await,
            Err(PreambleError::Malformed)
        );
    }
}
