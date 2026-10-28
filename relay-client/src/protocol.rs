//! Wire-protocol constants and parsing shared between the relay binary and
//! its clients. The relay ("dumb forwarder") does not speak QUIC; it routes
//! UDP packets by inspecting the QUIC long-header DCID, and accepts a small
//! out-of-band control protocol from sharers who want to register a share.
//!
//! Names, as everywhere in Spora:
//!
//! - **cert hash** = `SHA-256(cert DER)[..20]`: identifies a device (one key
//!   pair and self-signed cert per device).
//! - **share id** = 8 random public bytes, one per share.
//! - **routing hash** = `SHA-256(cert hash || share id)[..20]`: the 20-byte
//!   on-wire form of the routing key (cert hash, share id). It is the QUIC
//!   DCID, the nz header prefix, the TCP CONNECT preamble's key and the
//!   relay's registration-map key. Clients compute it from the URL; the relay
//!   computes it from a registration's cert and share id, so a registration
//!   can only ever claim the routing hash of a key it holds.

use std::time::{SystemTime, UNIX_EPOCH};

/// Magic prefix that distinguishes our control packets from QUIC. The first
/// byte (0x80) has the "fixed bit" (0x40) clear, so a QUIC parser treats it
/// as malformed and discards it; the next three bytes are an ASCII tag
/// (`spR`) for collision resistance against random data.
pub const CTRL_MAGIC: [u8; 4] = [0x80, b's', b'p', b'R'];

/// Control message types (the byte immediately after `CTRL_MAGIC`).
pub mod ctrl {
    /// A sharer registers one share's QUIC listener. Body: a signed
    /// registration ([`super::SignedRegistration`]) followed by the relay
    /// token, which runs to the end of the packet. The relay derives the
    /// routing hash from the cert and share id, verifies the signature,
    /// requires a fresh timestamp, and asks its authorizer about the token.
    /// (`0x01`, the pre-share-id REGISTER, is gone: a relay ignores it as
    /// unknown.)
    pub const REGISTER_V2: u8 = 0x02;
    /// The same for the share's nz (Noise UDP) socket, which is a different
    /// socket from its QUIC listener: a relay serving both carriers on one
    /// port keeps the two registrations apart (QUIC Initials go to the QUIC
    /// one, nz first packets to the nz one) instead of letting each overwrite
    /// the other.
    pub const REGISTER_NZ_V2: u8 = 0x03;
}

/// Which of a share's UDP sockets a REGISTER announces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegisterKind {
    Quic,
    Nz,
}

impl RegisterKind {
    pub fn ctrl(self) -> u8 {
        match self {
            RegisterKind::Quic => ctrl::REGISTER_V2,
            RegisterKind::Nz => ctrl::REGISTER_NZ_V2,
        }
    }

    pub fn from_ctrl(ty: u8) -> Option<Self> {
        match ty {
            ctrl::REGISTER_V2 => Some(RegisterKind::Quic),
            ctrl::REGISTER_NZ_V2 => Some(RegisterKind::Nz),
            _ => None,
        }
    }

    /// The signature domain: a QUIC registration's signature must not be
    /// replayable as an nz one (it would re-point the share's nz route), nor
    /// either as a TCP park.
    pub fn domain(self) -> &'static [u8] {
        match self {
            RegisterKind::Quic => REGISTER_SIG_DOMAIN,
            RegisterKind::Nz => REGISTER_NZ_SIG_DOMAIN,
        }
    }
}

/// Routing hashes are 20 bytes so they fit in a QUIC v1 DCID (max 20 per RFC
/// 9000 §17.2).
pub const ROUTING_HASH_LEN: usize = 20;
/// `SHA-256(cert DER)` truncated, like the routing hash.
pub const CERT_HASH_LEN: usize = 20;
/// Random, public, one per share.
pub const SHARE_ID_LEN: usize = 8;

pub type RoutingHash = [u8; ROUTING_HASH_LEN];
pub type CertHash = [u8; CERT_HASH_LEN];
pub type ShareId = [u8; SHARE_ID_LEN];

/// Width of the registration timestamp (milliseconds since the Unix epoch).
const TIMESTAMP_LEN: usize = 8;

/// The largest cert a relay reads from a registration. A device cert is a
/// few hundred bytes; the cap bounds what a hostile peer can make the relay
/// parse (and, on TCP, buffer).
pub const MAX_CERT_LEN: usize = 4096;
/// The largest signature a relay reads (an ASN.1 ECDSA-P256 signature is at
/// most 72 bytes).
pub const MAX_SIG_LEN: usize = 256;

/// Domain-separation prefixes for the registration signature, one per use so
/// a signature made for one can never be replayed as another: a captured
/// QUIC REGISTER must not re-point the share's nz route or park a TCP
/// connection, nor the reverse.
pub const REGISTER_SIG_DOMAIN: &[u8] = b"spora-relay-register-v2";
pub const REGISTER_NZ_SIG_DOMAIN: &[u8] = b"spora-relay-register-nz-v2";
pub const PARK_SIG_DOMAIN: &[u8] = b"spora-relay-park-v2";

/// `SHA-256(cert_der)[..20]`.
pub fn cert_hash(cert_der: &[u8]) -> CertHash {
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    let mut h = [0u8; CERT_HASH_LEN];
    h.copy_from_slice(&digest.as_ref()[..CERT_HASH_LEN]);
    h
}

/// `SHA-256(cert_hash || share_id)[..20]`. Not the share id itself: a bare
/// random value could be registered by anyone with any key pair, and DCIDs
/// are cleartext in QUIC long headers, so any on-path observer could
/// dead-end any share. The derivation binds the hash to key possession.
pub fn routing_hash(cert_hash: &CertHash, share_id: &ShareId) -> RoutingHash {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(cert_hash);
    ctx.update(share_id);
    let digest = ctx.finish();
    let mut h = [0u8; ROUTING_HASH_LEN];
    h.copy_from_slice(&digest.as_ref()[..ROUTING_HASH_LEN]);
    h
}

/// The signed part of a registration, shared by the UDP REGISTER and the TCP
/// park preamble. Encoded as
/// `share_id(8) | ts(8, BE) | cert_len(2, BE) | cert | sig_len(2, BE) | sig`;
/// the signature (ECDSA-P256-SHA256, ASN.1 DER, by the cert's key) covers
/// `domain || share_id || ts || cert_len || cert` — everything before it.
/// The relay token is NOT signed: it follows the signature, so a token can
/// change without touching the signing path.
#[derive(Debug)]
pub struct SignedRegistration<'a> {
    pub share_id: ShareId,
    pub timestamp_millis: u64,
    pub cert_der: &'a [u8],
    pub signature: &'a [u8],
}

/// Length of the fixed head of a [`SignedRegistration`]: share id, timestamp
/// and the cert length.
pub const SIGNED_HEAD_LEN: usize = SHARE_ID_LEN + TIMESTAMP_LEN + 2;

fn signed_part(share_id: &ShareId, ts: u64, cert_der: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIGNED_HEAD_LEN + cert_der.len());
    v.extend_from_slice(share_id);
    v.extend_from_slice(&ts.to_be_bytes());
    v.extend_from_slice(&(cert_der.len() as u16).to_be_bytes());
    v.extend_from_slice(cert_der);
    v
}

fn signing_input(domain: &[u8], signed: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + signed.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(signed);
    v
}

/// Parse a signed registration from the front of `body`; returns it and the
/// bytes after it (the token, for a UDP REGISTER).
pub fn parse_signed(body: &[u8]) -> Option<(SignedRegistration<'_>, &[u8])> {
    if body.len() < SIGNED_HEAD_LEN {
        return None;
    }
    let mut share_id = [0u8; SHARE_ID_LEN];
    share_id.copy_from_slice(&body[..SHARE_ID_LEN]);
    let ts = u64::from_be_bytes(
        body[SHARE_ID_LEN..SHARE_ID_LEN + TIMESTAMP_LEN]
            .try_into()
            .unwrap(),
    );
    let cert_len =
        u16::from_be_bytes([body[SIGNED_HEAD_LEN - 2], body[SIGNED_HEAD_LEN - 1]]) as usize;
    if cert_len == 0 || cert_len > MAX_CERT_LEN {
        return None;
    }
    let cert_end = SIGNED_HEAD_LEN.checked_add(cert_len)?;
    let sig_len_end = cert_end.checked_add(2)?;
    if body.len() < sig_len_end {
        return None;
    }
    let sig_len = u16::from_be_bytes([body[cert_end], body[cert_end + 1]]) as usize;
    if sig_len == 0 || sig_len > MAX_SIG_LEN {
        return None;
    }
    let sig_end = sig_len_end.checked_add(sig_len)?;
    if body.len() < sig_end {
        return None;
    }
    Some((
        SignedRegistration {
            share_id,
            timestamp_millis: ts,
            cert_der: &body[SIGNED_HEAD_LEN..cert_end],
            signature: &body[sig_len_end..sig_end],
        },
        &body[sig_end..],
    ))
}

/// Why a signed registration was rejected. The relay logs this; it carries no
/// secret-dependent information.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterVerifyError {
    /// Body did not parse as a signed registration.
    Malformed,
    /// The certificate could not be parsed as an end-entity cert.
    BadCert,
    /// The signature did not verify against the cert's public key.
    BadSignature,
}

/// What a verified registration proves: the holder of the key behind
/// `cert_hash` asked, at `timestamp_millis`, for `routing_hash` (derived
/// here, never taken from the wire) to point at the packet's source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRegistration {
    pub cert_hash: CertHash,
    pub share_id: ShareId,
    pub routing_hash: RoutingHash,
    pub timestamp_millis: u64,
}

impl SignedRegistration<'_> {
    /// Verify the signature under `domain` ([`RegisterKind::domain`] or
    /// [`PARK_SIG_DOMAIN`]) and derive the routing hash. Freshness (the
    /// timestamp must exceed the last one accepted for the routing hash),
    /// authorization and source policy are the caller's.
    pub fn verify(&self, domain: &[u8]) -> Result<VerifiedRegistration, RegisterVerifyError> {
        let cert = rustls_pki_types::CertificateDer::from(self.cert_der);
        let eec =
            webpki::EndEntityCert::try_from(&cert).map_err(|_| RegisterVerifyError::BadCert)?;
        let input = signing_input(
            domain,
            &signed_part(&self.share_id, self.timestamp_millis, self.cert_der),
        );
        eec.verify_signature(webpki::ring::ECDSA_P256_SHA256, &input, self.signature)
            .map_err(|_| RegisterVerifyError::BadSignature)?;
        let cert_hash = cert_hash(self.cert_der);
        Ok(VerifiedRegistration {
            cert_hash,
            share_id: self.share_id,
            routing_hash: routing_hash(&cert_hash, &self.share_id),
            timestamp_millis: self.timestamp_millis,
        })
    }
}

/// Verify a REGISTER body of `kind` (the bytes after the control type) and
/// return what it proves plus the trailing relay token (possibly empty),
/// borrowed from `body`.
pub fn verify_register(
    kind: RegisterKind,
    body: &[u8],
) -> Result<(VerifiedRegistration, &[u8]), RegisterVerifyError> {
    let (signed, token) = parse_signed(body).ok_or(RegisterVerifyError::Malformed)?;
    Ok((signed.verify(kind.domain())?, token))
}

/// Signs a share's registrations with the device's certificate key. Holds the
/// parsed key pair so each packet is a cheap sign, and guarantees a
/// strictly-increasing timestamp across the signer's lifetime (so a relay's
/// replay guard never rejects our own refreshes even if the wall clock
/// stalls or steps backward). One signer per share serves every listener
/// generation, carrier and relay of that share: one timestamp series per
/// routing hash.
pub struct RegisterSigner {
    key_pair: ring::signature::EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    cert_der: Vec<u8>,
    cert_hash: CertHash,
    share_id: ShareId,
    routing_hash: RoutingHash,
    last_ts: u64,
}

impl RegisterSigner {
    /// Build a signer for one share from the device's self-signed cert DER
    /// and its PKCS#8 private key.
    pub fn new(cert_der: &[u8], key_pkcs8_der: &[u8], share_id: ShareId) -> Result<Self, String> {
        if cert_der.len() > MAX_CERT_LEN {
            return Err(format!(
                "register signer: cert is {} bytes, relays read at most {MAX_CERT_LEN}",
                cert_der.len()
            ));
        }
        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            key_pkcs8_der,
            &rng,
        )
        .map_err(|e| format!("register signer: rejected key: {}", e))?;
        let cert_hash = cert_hash(cert_der);
        Ok(Self {
            key_pair,
            rng,
            cert_der: cert_der.to_vec(),
            cert_hash,
            share_id,
            routing_hash: routing_hash(&cert_hash, &share_id),
            last_ts: 0,
        })
    }

    /// The routing hash this signer registers.
    pub fn routing_hash(&self) -> RoutingHash {
        self.routing_hash
    }

    /// The device's cert hash.
    pub fn cert_hash(&self) -> CertHash {
        self.cert_hash
    }

    /// The signed part under `domain`, with a fresh timestamp.
    fn next_signed(&mut self, domain: &[u8]) -> Vec<u8> {
        let ts = now_millis().max(self.last_ts + 1);
        self.last_ts = ts;
        let mut out = signed_part(&self.share_id, ts, &self.cert_der);
        let sig = self
            .key_pair
            .sign(&self.rng, &signing_input(domain, &out))
            .expect("ECDSA signing of a bounded input does not fail");
        out.extend_from_slice(&(sig.as_ref().len() as u16).to_be_bytes());
        out.extend_from_slice(sig.as_ref());
        out
    }

    /// The next UDP REGISTER of `kind`, carrying `token` (empty for a relay
    /// that wants none).
    pub fn register_packet(&mut self, kind: RegisterKind, token: &[u8]) -> Vec<u8> {
        let signed = self.next_signed(kind.domain());
        let mut pkt = Vec::with_capacity(CTRL_MAGIC.len() + 1 + signed.len() + token.len());
        pkt.extend_from_slice(&CTRL_MAGIC);
        pkt.push(kind.ctrl());
        pkt.extend_from_slice(&signed);
        pkt.extend_from_slice(token);
        pkt
    }

    /// The next TCP park preamble (see [`crate::tcp`]), carrying `token`.
    pub fn park_preamble(&mut self, token: &[u8]) -> Vec<u8> {
        let signed = self.next_signed(PARK_SIG_DOMAIN);
        crate::tcp::build_park_preamble(&signed, token)
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Classify an inbound UDP packet for the relay's dispatcher.
#[derive(Debug, PartialEq, Eq)]
pub enum Classified<'a> {
    /// Our control protocol: type byte + body.
    Control { ty: u8, body: &'a [u8] },
    /// A QUIC long-header packet, e.g. Initial. DCID is parseable in cleartext.
    QuicLongHeader { dcid: &'a [u8] },
    /// A QUIC short-header (1-RTT) packet. DCID length isn't on the wire — we
    /// can't extract it without per-connection state, so the relay routes
    /// these by 5-tuple instead.
    QuicShortHeader,
    /// Unrecognized: not our control magic, not a valid QUIC packet shape.
    Unknown,
}

/// Classify a packet by its first byte (and following fields, for long
/// headers). Cheap; no allocations.
pub fn classify(pkt: &[u8]) -> Classified<'_> {
    if pkt.len() > CTRL_MAGIC.len() && pkt[..CTRL_MAGIC.len()] == CTRL_MAGIC {
        return Classified::Control {
            ty: pkt[CTRL_MAGIC.len()],
            body: &pkt[CTRL_MAGIC.len() + 1..],
        };
    }
    if pkt.is_empty() {
        return Classified::Unknown;
    }
    let b0 = pkt[0];
    // QUIC long header: header-form bit (0x80) + fixed bit (0x40) both set.
    if (b0 & 0xC0) == 0xC0 {
        // Layout: type(1) + version(4) + dcid_len(1) + dcid_bytes
        if pkt.len() < 6 {
            return Classified::Unknown;
        }
        let dcid_len = pkt[5] as usize;
        if pkt.len() < 6 + dcid_len {
            return Classified::Unknown;
        }
        return Classified::QuicLongHeader {
            dcid: &pkt[6..6 + dcid_len],
        };
    }
    // QUIC short header: header-form clear, fixed bit set (0x40..=0x7F).
    if (b0 & 0xC0) == 0x40 {
        return Classified::QuicShortHeader;
    }
    Classified::Unknown
}

/// Lowercase hex, the form cert hashes and routing hashes take in logs, the
/// relay's session log and the API.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed ECDSA-P256 cert + PKCS#8 key, like a device carries.
    fn test_cert() -> (Vec<u8>, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        (ck.cert.der().to_vec(), ck.key_pair.serialize_der())
    }

    fn signer() -> RegisterSigner {
        let (cert, key) = test_cert();
        RegisterSigner::new(&cert, &key, [7u8; SHARE_ID_LEN]).unwrap()
    }

    fn body(pkt: &[u8]) -> &[u8] {
        &pkt[CTRL_MAGIC.len() + 1..]
    }

    #[test]
    fn routing_hash_binds_cert_hash_and_share_id() {
        let a = routing_hash(&[1u8; 20], &[2u8; 8]);
        assert_ne!(a, routing_hash(&[1u8; 20], &[3u8; 8]));
        assert_ne!(a, routing_hash(&[9u8; 20], &[2u8; 8]));
        // The documented derivation, spelled out.
        let mut input = vec![1u8; 20];
        input.extend_from_slice(&[2u8; 8]);
        let d = ring::digest::digest(&ring::digest::SHA256, &input);
        assert_eq!(&a[..], &d.as_ref()[..20]);
    }

    #[test]
    fn register_classifies_as_control_and_verifies() {
        let mut s = signer();
        let pkt = s.register_packet(RegisterKind::Quic, &[]);
        match classify(&pkt) {
            Classified::Control { ty, body } => {
                assert_eq!(ty, ctrl::REGISTER_V2);
                let (v, token) = verify_register(RegisterKind::Quic, body).expect("verifies");
                assert_eq!(v.routing_hash, s.routing_hash());
                assert_eq!(v.cert_hash, s.cert_hash());
                assert_eq!(v.share_id, [7u8; SHARE_ID_LEN]);
                assert!(token.is_empty());
            }
            other => panic!("expected Control, got {:?}", other),
        }
    }

    #[test]
    fn timestamps_strictly_increase_across_both_uses() {
        let mut s = signer();
        let (r1, _) = verify_register(
            RegisterKind::Quic,
            body(&s.register_packet(RegisterKind::Quic, &[])),
        )
        .unwrap();
        let park = s.park_preamble(&[]);
        let (r2, _) = verify_register(
            RegisterKind::Quic,
            body(&s.register_packet(RegisterKind::Quic, &[])),
        )
        .unwrap();
        assert!(
            r2.timestamp_millis > r1.timestamp_millis + 1,
            "the park took one in between"
        );
        let (role, rest) = crate::tcp::parse_role(&park).unwrap();
        assert_eq!(role, crate::tcp::role::PARK_V2);
        let (signed, _) = parse_signed(rest).unwrap();
        assert!(signed.timestamp_millis > r1.timestamp_millis);
        assert!(signed.timestamp_millis < r2.timestamp_millis);
    }

    #[test]
    fn the_token_rides_after_the_signature_unsigned() {
        let mut s = signer();
        let token = vec![0xAB; 40];
        let pkt = s.register_packet(RegisterKind::Quic, &token);
        let (_, got) = verify_register(RegisterKind::Quic, body(&pkt)).expect("verifies");
        assert_eq!(got, &token[..]);
        // Swapping the token keeps the signature valid: it is not covered.
        let mut swapped = pkt[..pkt.len() - token.len()].to_vec();
        swapped.extend_from_slice(b"other");
        let (_, got) = verify_register(RegisterKind::Quic, body(&swapped)).expect("still verifies");
        assert_eq!(got, b"other");
    }

    #[test]
    fn a_tampered_registration_is_rejected() {
        let mut s = signer();
        let pkt = s.register_packet(RegisterKind::Quic, &[]);
        // Flip a share-id byte: the signature no longer covers the body, and
        // the derived routing hash would differ anyway.
        let mut b = body(&pkt).to_vec();
        b[0] ^= 0x01;
        assert_eq!(
            verify_register(RegisterKind::Quic, &b),
            Err(RegisterVerifyError::BadSignature)
        );
        // Flip a timestamp byte.
        let mut b = body(&pkt).to_vec();
        b[SHARE_ID_LEN] ^= 0x01;
        assert_eq!(
            verify_register(RegisterKind::Quic, &b),
            Err(RegisterVerifyError::BadSignature)
        );
    }

    #[test]
    fn another_keys_signature_does_not_verify_for_this_cert() {
        // A valid signature by key B over a registration naming cert A.
        let (cert_a, _) = test_cert();
        let (_, key_b) = test_cert();
        let mut s = RegisterSigner::new(&cert_a, &key_b, [1; SHARE_ID_LEN]).unwrap();
        assert_eq!(
            verify_register(
                RegisterKind::Quic,
                body(&s.register_packet(RegisterKind::Quic, &[]))
            ),
            Err(RegisterVerifyError::BadSignature)
        );
    }

    #[test]
    fn a_signature_verifies_only_for_its_own_use() {
        let mut s = signer();
        let pkt = s.register_packet(RegisterKind::Quic, &[]);
        assert_eq!(pkt[CTRL_MAGIC.len()], ctrl::REGISTER_V2);
        let (signed, _) = parse_signed(body(&pkt)).unwrap();
        assert!(signed.verify(REGISTER_SIG_DOMAIN).is_ok());
        for other in [REGISTER_NZ_SIG_DOMAIN, PARK_SIG_DOMAIN] {
            assert_eq!(signed.verify(other), Err(RegisterVerifyError::BadSignature));
        }
        let nz = s.register_packet(RegisterKind::Nz, &[]);
        assert_eq!(nz[CTRL_MAGIC.len()], ctrl::REGISTER_NZ_V2);
        assert!(verify_register(RegisterKind::Nz, body(&nz)).is_ok());
        assert_eq!(
            verify_register(RegisterKind::Quic, body(&nz)),
            Err(RegisterVerifyError::BadSignature)
        );
    }

    #[test]
    fn truncated_and_oversized_fields_are_malformed() {
        let mut s = signer();
        let pkt = s.register_packet(RegisterKind::Quic, &[]);
        let b = body(&pkt);
        for cut in [0, 5, SIGNED_HEAD_LEN, SIGNED_HEAD_LEN + 10, b.len() - 1] {
            assert_eq!(
                verify_register(RegisterKind::Quic, &b[..cut]),
                Err(RegisterVerifyError::Malformed),
                "cut at {cut}"
            );
        }
        let mut huge = b.to_vec();
        let cl = (MAX_CERT_LEN as u16 + 1).to_be_bytes();
        huge[SIGNED_HEAD_LEN - 2] = cl[0];
        huge[SIGNED_HEAD_LEN - 1] = cl[1];
        assert_eq!(
            verify_register(RegisterKind::Quic, &huge),
            Err(RegisterVerifyError::Malformed)
        );
    }

    #[test]
    fn classifies_long_header() {
        // Initial packet shape: 0xC0, version(4 bytes), dcid_len, dcid_bytes...
        let dcid = [0xAAu8; 20];
        let mut pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 20];
        pkt.extend_from_slice(&dcid);
        pkt.extend_from_slice(&[0xDE, 0xAD]); // trailing payload
        match classify(&pkt) {
            Classified::QuicLongHeader { dcid: got } => assert_eq!(got, &dcid[..]),
            other => panic!("expected QuicLongHeader, got {:?}", other),
        }
    }

    #[test]
    fn classifies_short_header() {
        let pkt = vec![0x40, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(classify(&pkt), Classified::QuicShortHeader);
    }

    #[test]
    fn rejects_truncated_long_header() {
        let pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 20, 0xAA, 0xBB]; // dcid_len=20 but only 2 bytes follow
        assert_eq!(classify(&pkt), Classified::Unknown);
    }

    #[test]
    fn ctrl_magic_first_byte_is_not_valid_quic() {
        // Sanity: 0x80 has the fixed bit clear, so QUIC parsers reject it.
        assert_eq!(CTRL_MAGIC[0] & 0x40, 0);
    }

    #[test]
    fn empty_packet_is_unknown() {
        assert_eq!(classify(&[]), Classified::Unknown);
    }

    #[test]
    fn random_byte_zero_is_unknown() {
        // Bytes 0x00..=0x3F have neither header form nor fixed bit set.
        assert_eq!(classify(&[0x00, 0x01, 0x02]), Classified::Unknown);
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0xAB, 0x01]), "ab01");
    }
}
