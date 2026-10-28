//! Device identity, shares, and the share token / URL.
//!
//! Four things, with four lifetimes:
//!
//! - [`DeviceIdentity`]: the device's one key pair and self-signed cert, made
//!   once and kept for as long as the device is "the same device" (by
//!   spora-service, in its state file). Its **cert hash**
//!   (`SHA-256(cert DER)[..20]`) identifies the device to relays, to the API
//!   and to clients, who pin the cert by it.
//! - [`Share`]: one shared connection, made once and never changed — its
//!   share id (8 random public bytes), its secret (16 random bytes, the
//!   password URL holders present) and its relays, each with the
//!   [`Credential`] the sharer presents there. The platform stores it as an
//!   opaque blob ([`Share::to_blob`]); the URL is a pure function of it, so
//!   new relays mean a new share and a new URL.
//! - [`Token`]: the public projection of a share, what a share URL carries:
//!   `https://spora.to/s/<base64url(version || cert hash || share id ||
//!   secret)>?r=<host>:<port>[&r=…]`.
//! - [`ShareIdentity`]: what a running share serves with — the device's key
//!   and cert plus the share's id, secret and **routing hash**
//!   (`SHA-256(cert hash || share id)[..20]`, the on-wire form of the routing
//!   key (cert hash, share id): QUIC DCID, nz header, TCP CONNECT key, the
//!   relay's registration key).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use url::Url;

use crate::transport::quic::generate_self_signed_cert;

pub use relay_client::credential::{Credential, Credentials};
pub use relay_client::protocol::{
    CERT_HASH_LEN, CertHash, ROUTING_HASH_LEN, RoutingHash, SHARE_ID_LEN, ShareId, cert_hash, hex,
    routing_hash,
};

const URL_HOST: &str = "spora.to";
const URL_PATH_PREFIX: &str = "/s/";

pub const SECRET_LEN: usize = 16;
/// The first byte of a share URL's blob.
const URL_VERSION: u8 = 1;
/// `version | cert hash | share id | secret`: 45 bytes, 60 base64url chars.
const TOKEN_BLOB_LEN: usize = 1 + CERT_HASH_LEN + SHARE_ID_LEN + SECRET_LEN;

// ---------------------------------------------------------------------------
// Device identity

/// A device's key pair and self-signed cert (ECDSA P-256). One per device;
/// every share the device makes is served under it. The cert is valid until
/// the year 4096: it lives as long as the device.
#[derive(Clone)]
pub struct DeviceIdentity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    cert_hash: CertHash,
}

/// Written by hand so the private key never reaches a log.
impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("cert_hash", &relay_client::protocol::hex(&self.cert_hash))
            .finish_non_exhaustive()
    }
}

const DEVICE_MAGIC: [u8; 4] = *b"sDEV";
const DEVICE_VERSION: u8 = 1;

impl DeviceIdentity {
    /// A fresh key pair and cert.
    pub fn generate() -> Self {
        let (cert_der, key_der, _fp) = generate_self_signed_cert();
        let key_der = match key_der {
            PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
            _ => unreachable!("rcgen serializes keys as PKCS#8"),
        };
        let cert_der = cert_der.as_ref().to_vec();
        let cert_hash = cert_hash(&cert_der);
        Self {
            cert_der,
            key_der,
            cert_hash,
        }
    }

    /// Rebuild from a stored cert (DER) and PKCS#8 key, checking that the
    /// key is an ECDSA P-256 key and the one the cert names.
    pub fn from_parts(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self, String> {
        let rng = ring::rand::SystemRandom::new();
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &key_der,
            &rng,
        )
        .map_err(|e| format!("device identity: the key is not a P-256 PKCS#8 key: {e}"))?;
        let probe = b"spora-device-identity-check";
        let sig = key
            .sign(&rng, probe)
            .map_err(|_| "device identity: signing failed".to_string())?;
        let cert = CertificateDer::from(cert_der.as_slice());
        let eec = webpki::EndEntityCert::try_from(&cert)
            .map_err(|e| format!("device identity: the cert does not parse: {e}"))?;
        eec.verify_signature(webpki::ring::ECDSA_P256_SHA256, probe, sig.as_ref())
            .map_err(|_| "device identity: the key does not belong to the cert".to_string())?;
        let cert_hash = cert_hash(&cert_der);
        Ok(Self {
            cert_der,
            key_der,
            cert_hash,
        })
    }

    pub fn cert_der_bytes(&self) -> &[u8] {
        &self.cert_der
    }

    /// The PKCS#8 private key. Whoever stores it keeps it sealed.
    pub fn key_der_bytes(&self) -> &[u8] {
        &self.key_der
    }

    pub fn cert_hash(&self) -> CertHash {
        self.cert_hash
    }

    /// Serialize: `[MAGIC(4) | VERSION(1) | cert_len(u32 BE) | cert |
    /// key_len(u32 BE) | key]`. For stores that keep the identity as one
    /// blob; spora-service keeps the two parts separately instead.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + 8 + self.cert_der.len() + self.key_der.len());
        out.extend_from_slice(&DEVICE_MAGIC);
        out.push(DEVICE_VERSION);
        out.extend_from_slice(&(self.cert_der.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.cert_der);
        out.extend_from_slice(&(self.key_der.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.key_der);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes, "device identity");
        if r.take(4)? != DEVICE_MAGIC {
            return Err("device identity: bad magic".into());
        }
        let version = r.u8()?;
        if version != DEVICE_VERSION {
            return Err(format!(
                "device identity: unsupported version {version} (expected {DEVICE_VERSION})"
            ));
        }
        let cert = r.lp32("cert")?.to_vec();
        let key = r.lp32("key")?.to_vec();
        r.finish()?;
        Self::from_parts(cert, key)
    }
}

// ---------------------------------------------------------------------------
// Shares

/// One relay endpoint of a share and what the sharer presents there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayEntry {
    pub endpoint: RelayEndpoint,
    pub credential: Credential,
}

impl RelayEntry {
    /// An endpoint that wants no credential.
    pub fn open(endpoint: RelayEndpoint) -> Self {
        Self {
            endpoint,
            credential: Credential::None,
        }
    }
}

/// One shared connection: immutable once made (see the module docs). Its URL
/// is [`Share::url`]; it can only be served under the device identity it was
/// made under ([`ShareIdentity::new`]).
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    pub cert_hash: CertHash,
    pub share_id: ShareId,
    pub secret: [u8; SECRET_LEN],
    /// In preference order, as written into the URL.
    pub relays: Vec<RelayEntry>,
}

/// Written by hand so the secret never reaches a log.
impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("cert_hash", &relay_client::protocol::hex(&self.cert_hash))
            .field("share_id", &relay_client::protocol::hex(&self.share_id))
            .field("secret", &"<redacted>")
            .field("relays", &self.relays)
            .finish()
    }
}

const SHARE_MAGIC: [u8; 4] = *b"sSHR";
const SHARE_VERSION: u8 = 1;

impl Share {
    /// A new share of `device` over `relays`, with a fresh share id and
    /// secret. Needs at least one relay (a `Direct` endpoint counts).
    pub fn new(device: &DeviceIdentity, relays: Vec<RelayEntry>) -> Result<Self, String> {
        if relays.is_empty() {
            return Err("a share needs at least one relay endpoint".into());
        }
        let mut share_id = [0u8; SHARE_ID_LEN];
        let mut secret = [0u8; SECRET_LEN];
        rand::thread_rng().fill_bytes(&mut share_id);
        rand::thread_rng().fill_bytes(&mut secret);
        Ok(Self {
            cert_hash: device.cert_hash(),
            share_id,
            secret,
            relays,
        })
    }

    /// [`Share::new`] with every endpoint open (no credential).
    pub fn open(device: &DeviceIdentity, endpoints: Vec<RelayEndpoint>) -> Result<Self, String> {
        Self::new(
            device,
            endpoints.into_iter().map(RelayEntry::open).collect(),
        )
    }

    pub fn routing_hash(&self) -> RoutingHash {
        routing_hash(&self.cert_hash, &self.share_id)
    }

    pub fn endpoints(&self) -> Vec<RelayEndpoint> {
        self.relays.iter().map(|r| r.endpoint.clone()).collect()
    }

    /// The public projection: what the URL carries.
    pub fn token(&self) -> Token {
        Token {
            cert_hash: self.cert_hash,
            share_id: self.share_id,
            secret: self.secret,
            relays: self.endpoints(),
        }
    }

    pub fn url(&self) -> Url {
        self.token().to_url()
    }

    /// The share as an opaque, versioned blob for the platform to store.
    /// Layout (big-endian): `MAGIC(4) | VERSION(1) | cert_hash(20) |
    /// share_id(8) | secret(16) | count(u16) | entries`, an entry being
    /// `endpoint_len(u16) | endpoint (the URL's ?r= form) | kind(1: 0 none,
    /// 1 static, 2 spora) | [len(u16) | bytes]` (the bytes for static only).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SHARE_MAGIC);
        out.push(SHARE_VERSION);
        out.extend_from_slice(&self.cert_hash);
        out.extend_from_slice(&self.share_id);
        out.extend_from_slice(&self.secret);
        out.extend_from_slice(&(self.relays.len() as u16).to_be_bytes());
        for r in &self.relays {
            let ep = r.endpoint.to_url_param();
            out.extend_from_slice(&(ep.len() as u16).to_be_bytes());
            out.extend_from_slice(ep.as_bytes());
            match &r.credential {
                Credential::None => out.push(0),
                Credential::Static(b) => {
                    out.push(1);
                    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    out.extend_from_slice(b);
                }
                Credential::Spora => out.push(2),
            }
        }
        out
    }

    /// Parse a blob made by [`Share::to_blob`]. A blob of a version this
    /// build does not know is an error, never a guess. No error repeats the
    /// secret.
    pub fn from_blob(blob: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(blob, "share blob");
        if r.take(4)? != SHARE_MAGIC {
            return Err("share blob: bad magic".into());
        }
        let version = r.u8()?;
        if version != SHARE_VERSION {
            return Err(format!(
                "share blob: unsupported version {version} (this build reads {SHARE_VERSION})"
            ));
        }
        let mut cert_hash = [0u8; CERT_HASH_LEN];
        cert_hash.copy_from_slice(r.take(CERT_HASH_LEN)?);
        let mut share_id = [0u8; SHARE_ID_LEN];
        share_id.copy_from_slice(r.take(SHARE_ID_LEN)?);
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(r.take(SECRET_LEN)?);
        let count = r.u16()? as usize;
        let mut relays = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let ep = std::str::from_utf8(r.lp16("endpoint")?)
                .map_err(|_| "share blob: an endpoint is not UTF-8".to_string())?;
            let endpoint =
                RelayEndpoint::from_url_param(ep).map_err(|e| format!("share blob: {e}"))?;
            let credential = match r.u8()? {
                0 => Credential::None,
                1 => Credential::Static(r.lp16("static token")?.to_vec()),
                2 => Credential::Spora,
                k => return Err(format!("share blob: unknown credential kind {k}")),
            };
            relays.push(RelayEntry {
                endpoint,
                credential,
            });
        }
        r.finish()?;
        if relays.is_empty() {
            return Err("share blob: no relay endpoints".into());
        }
        Ok(Self {
            cert_hash,
            share_id,
            secret,
            relays,
        })
    }
}

/// What a running share serves with: the device's key and cert, and the
/// share's id, secret and routing hash.
#[derive(Clone)]
pub struct ShareIdentity {
    pub cert_der_bytes: Vec<u8>,
    pub key_der_bytes: Vec<u8>,
    pub cert_hash: CertHash,
    pub share_id: ShareId,
    pub routing_hash: RoutingHash,
    pub secret: [u8; SECRET_LEN],
}

/// The error [`ShareIdentity::new`] gives a share made under another device
/// identity (the device's identity was lost and minted anew, or the blob came
/// from elsewhere). A platform recognizes it to offer re-making the share.
pub const IDENTITY_MISMATCH: &str = "identity_mismatch";

impl ShareIdentity {
    /// `share` served by `device`; refused (with an error starting with
    /// [`IDENTITY_MISMATCH`]) unless the share was made under this device.
    pub fn new(device: &DeviceIdentity, share: &Share) -> Result<Self, String> {
        if share.cert_hash != device.cert_hash() {
            return Err(format!(
                "{IDENTITY_MISMATCH}: the share was made under device {}, this is device {}",
                relay_client::protocol::hex(&share.cert_hash),
                relay_client::protocol::hex(&device.cert_hash()),
            ));
        }
        Ok(Self {
            cert_der_bytes: device.cert_der_bytes().to_vec(),
            key_der_bytes: device.key_der_bytes().to_vec(),
            cert_hash: share.cert_hash,
            share_id: share.share_id,
            routing_hash: share.routing_hash(),
            secret: share.secret,
        })
    }

    /// A fresh device and share id/secret (tests and the lab).
    pub fn generate() -> Self {
        let device = DeviceIdentity::generate();
        let share =
            Share::open(&device, vec![RelayEndpoint::new("127.0.0.1", 1)]).expect("one endpoint");
        Self::new(&device, &share).expect("same device")
    }

    /// Fresh owned `CertificateDer` view of the bytes (clones once).
    pub fn cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der_bytes.clone())
    }

    /// Fresh owned `PrivateKeyDer` view of the bytes (clones once).
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::try_from(self.key_der_bytes.clone())
            .expect("ShareIdentity::key_der_bytes were checked when the identity was made")
    }

    /// The token for this share reached via `relays`.
    pub fn token(&self, relays: Vec<RelayEndpoint>) -> Token {
        Token {
            cert_hash: self.cert_hash,
            share_id: self.share_id,
            secret: self.secret,
            relays,
        }
    }
}

/// Bounds-checked reader for the binary blobs above.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], what: &'static str) -> Self {
        Self { bytes, at: 0, what }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        // Checked: `n` may come from an attacker-influenced length field, and
        // on 32-bit targets usize is 32 bits.
        let end = self
            .at
            .checked_add(n)
            .filter(|e| *e <= self.bytes.len())
            .ok_or_else(|| format!("{}: truncated", self.what))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn lp16(&mut self, field: &str) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
            .map_err(|_| format!("{}: {field} truncated", self.what))
    }

    fn lp32(&mut self, field: &str) -> Result<&'a [u8], String> {
        let b = self.take(4)?;
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        self.take(n)
            .map_err(|_| format!("{}: {field} truncated", self.what))
    }

    fn finish(&self) -> Result<(), String> {
        if self.at != self.bytes.len() {
            return Err(format!(
                "{}: {} trailing bytes",
                self.what,
                self.bytes.len() - self.at
            ));
        }
        Ok(())
    }
}

/// Which relay protocol reaches a given endpoint. The client selects the
/// matching dialer; the sharer treats registerable protocols and direct
/// (relay-less) ones differently. Additional protocols (a TCP/TLS relay, an
/// obfuscated UDP relay) slot in here and get a URL tag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RelayProtocol {
    /// The dumb UDP relay carrying end-to-end QUIC — today's default.
    #[default]
    UdpQuic,
    /// No relay: dial the sharer's own listener directly (the sharer is
    /// publicly reachable). Zero relay bandwidth; see the `carrier` module.
    Direct,
    /// A TCP relay carrying end-to-end TLS (transport diversity: survives
    /// UDP/QUIC-class blocking). Relayed, stream-native — see the `carrier`
    /// module and `e2e_tls`.
    TcpTls,
    /// The dumb UDP relay carrying an end-to-end Noise datagram session — a
    /// high-entropy, non-QUIC-shaped transport for networks that fingerprint or
    /// throttle QUIC. Relayed; see the `carrier` module, `e2e_noise`, and
    /// `transport::noise`.
    NoiseUdp,
}

impl RelayProtocol {
    /// Whether reaching a sharer over this protocol goes through a relay the
    /// sharer must register with. `Direct` is peer-to-peer (no registration);
    /// the sharer instead binds and advertises the endpoint itself.
    pub fn is_relayed(self) -> bool {
        match self {
            RelayProtocol::UdpQuic | RelayProtocol::TcpTls | RelayProtocol::NoiseUdp => true,
            RelayProtocol::Direct => false,
        }
    }

    /// Whether this protocol's E2E path is QUIC datagrams (vs a byte stream or a
    /// Noise datagram session). QUIC and Noise relay carriers support the UDP
    /// hole-punch direct upgrade; this predicate only describes wire shape.
    pub fn is_quic(self) -> bool {
        match self {
            RelayProtocol::UdpQuic | RelayProtocol::Direct => true,
            RelayProtocol::TcpTls | RelayProtocol::NoiseUdp => false,
        }
    }

    /// The URL tag for this protocol, or `None` for the default (`UdpQuic`),
    /// which is encoded as a bare `host:port` for back-compatibility. Non-default
    /// protocols encode as `tag/host:port`.
    fn url_tag(self) -> Option<&'static str> {
        match self {
            RelayProtocol::UdpQuic => None,
            RelayProtocol::Direct => Some("direct"),
            RelayProtocol::TcpTls => Some("tcptls"),
            RelayProtocol::NoiseUdp => Some("nz"),
        }
    }

    /// Parse a URL protocol tag. `quic` is accepted as an explicit spelling of
    /// the default.
    fn from_url_tag(tag: &str) -> Option<Self> {
        match tag {
            "quic" | "udpquic" => Some(RelayProtocol::UdpQuic),
            "direct" => Some(RelayProtocol::Direct),
            "tcptls" => Some(RelayProtocol::TcpTls),
            "nz" => Some(RelayProtocol::NoiseUdp),
            _ => None,
        }
    }
}

/// One relay's address as a host (hostname or IP literal), port, and protocol.
/// The host is stored bare — an IPv6 literal carries NO brackets here;
/// bracketing is a URL-encoding concern handled by [`RelayEndpoint::to_url_param`]
/// / `from_url_param`. A hostname is resolved (and may expand to several
/// addresses, both families) at connect/register time, not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub host: String,
    pub port: u16,
    pub protocol: RelayProtocol,
}

impl RelayEndpoint {
    /// A `UdpQuic` (default-protocol) relay endpoint.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            protocol: RelayProtocol::UdpQuic,
        }
    }

    /// An endpoint reached via a specific protocol.
    pub fn with_protocol(host: impl Into<String>, port: u16, protocol: RelayProtocol) -> Self {
        Self {
            host: host.into(),
            port,
            protocol,
        }
    }

    /// Render for a URL `?r=` value: `host:port` (bracketing an IPv6 literal),
    /// prefixed with `tag/` for non-default protocols.
    pub fn to_url_param(&self) -> String {
        let host_port = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        match self.protocol.url_tag() {
            Some(tag) => format!("{tag}/{host_port}"),
            None => host_port,
        }
    }

    /// Parse one `?r=` value: an optional `tag/` protocol prefix followed by
    /// `[v6literal]:port` or `host:port`. The brackets are stripped so `host` is
    /// always a bare hostname / IP literal. A bare value (no `tag/`) is the
    /// back-compatible `UdpQuic` case.
    pub fn from_url_param(value: &str) -> Result<Self, String> {
        // A host:port never contains '/', so a '/' means an explicit protocol
        // tag (which must be one we understand).
        let (protocol, value) = match value.split_once('/') {
            Some((tag, rest)) => {
                let p = RelayProtocol::from_url_tag(tag).ok_or_else(|| {
                    format!("unknown relay protocol '{tag}' in ?r= value: {value}")
                })?;
                (p, rest)
            }
            None => (RelayProtocol::UdpQuic, value),
        };
        let (host, port_str) = if let Some(rest) = value.strip_prefix('[') {
            let (host, port) = rest
                .split_once("]:")
                .ok_or_else(|| format!("?r= value must be [v6]:port, got {}", value))?;
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(format!("invalid IPv6 literal in ?r= value: {}", host));
            }
            (host, port)
        } else {
            let (host, port) = value
                .rsplit_once(':')
                .ok_or_else(|| format!("?r= value must be host:port, got {}", value))?;
            // An unbracketed v6 literal would mis-split at its last group;
            // refuse it instead of resolving a mangled host later.
            if host.contains(':') {
                return Err(format!(
                    "IPv6 relay literal must be bracketed ([addr]:port), got {}",
                    value
                ));
            }
            (host, port)
        };
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port in ?r= value: {}", port_str))?;
        Ok(RelayEndpoint {
            host: host.to_string(),
            port,
            protocol,
        })
    }
}

/// What the client gets out of a share URL. Carries one or more relay
/// endpoints — the client tries them (IPv6 first) until one bootstraps the
/// session, and the sharer registers with all of them. A hostname that
/// resolves to both A and AAAA records behaves as two separate endpoints
/// (the expansion happens at resolve time, on each side independently).
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    /// The sharer's device: the client pins the cert to it.
    pub cert_hash: CertHash,
    pub share_id: ShareId,
    pub secret: [u8; SECRET_LEN],
    pub relays: Vec<RelayEndpoint>,
}

/// Written by hand so the secret never reaches a log: formatted with `{:?}`
/// it would be a byte list no URL redactor recognizes.
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("cert_hash", &relay_client::protocol::hex(&self.cert_hash))
            .field("share_id", &relay_client::protocol::hex(&self.share_id))
            .field("secret", &"<redacted>")
            .field("relays", &self.relays)
            .finish()
    }
}

impl Token {
    /// `SHA-256(cert_hash || share_id)[..20]`: the DCID / nz prefix / CONNECT
    /// key to reach this share at a relay.
    pub fn routing_hash(&self) -> RoutingHash {
        routing_hash(&self.cert_hash, &self.share_id)
    }

    /// Render as `https://spora.to/s/<base64url>?r=<host>:<port>` with one
    /// `?r=` per relay (IPv6 literals bracketed), order preserved. Built by
    /// string formatting so the `:` stays literal (a human-shareable URL),
    /// rather than `query_pairs_mut`, which would percent-encode it.
    pub fn to_url(&self) -> Url {
        let mut blob = [0u8; TOKEN_BLOB_LEN];
        blob[0] = URL_VERSION;
        blob[1..1 + CERT_HASH_LEN].copy_from_slice(&self.cert_hash);
        blob[1 + CERT_HASH_LEN..1 + CERT_HASH_LEN + SHARE_ID_LEN].copy_from_slice(&self.share_id);
        blob[1 + CERT_HASH_LEN + SHARE_ID_LEN..].copy_from_slice(&self.secret);
        let encoded = URL_SAFE_NO_PAD.encode(blob);
        let query = self
            .relays
            .iter()
            .map(|r| format!("r={}", r.to_url_param()))
            .collect::<Vec<_>>()
            .join("&");
        let url_str = format!(
            "https://{}{}{}?{}",
            URL_HOST, URL_PATH_PREFIX, encoded, query
        );
        Url::parse(&url_str).expect("constructed Token URL must parse")
    }

    /// Parse a share URL back into a token. Collects every `?r=` value; at
    /// least one is required.
    ///
    /// No error echoes the path: a mangled link (`/S/…`, `/s%2F…`, a doubled
    /// slash) still carries the secret there, and the error ends up in the
    /// connection record and the diagnostic log.
    pub fn from_url(url: &Url) -> Result<Self, String> {
        let blob_b64 = url
            .path()
            .strip_prefix(URL_PATH_PREFIX)
            .ok_or_else(|| format!("URL path must start with {URL_PATH_PREFIX}"))?;
        if blob_b64.is_empty() {
            return Err("URL path is missing the token after /s/".into());
        }
        let blob = URL_SAFE_NO_PAD
            .decode(blob_b64)
            .map_err(|e| format!("invalid base64 in URL token: {}", e))?;
        if blob.len() != TOKEN_BLOB_LEN {
            return Err(format!(
                "token blob is {} bytes, expected {} (a link made by an older Spora?)",
                blob.len(),
                TOKEN_BLOB_LEN
            ));
        }
        if blob[0] != URL_VERSION {
            return Err(format!(
                "share link version {} is not one this build reads ({URL_VERSION})",
                blob[0]
            ));
        }
        let mut cert_hash = [0u8; CERT_HASH_LEN];
        cert_hash.copy_from_slice(&blob[1..1 + CERT_HASH_LEN]);
        let mut share_id = [0u8; SHARE_ID_LEN];
        share_id.copy_from_slice(&blob[1 + CERT_HASH_LEN..1 + CERT_HASH_LEN + SHARE_ID_LEN]);
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&blob[1 + CERT_HASH_LEN + SHARE_ID_LEN..]);

        let relays = url
            .query_pairs()
            .filter(|(k, _)| k == "r")
            .map(|(_, v)| RelayEndpoint::from_url_param(&v))
            .collect::<Result<Vec<_>, _>>()?;
        if relays.is_empty() {
            return Err("URL is missing required ?r= query parameter".into());
        }

        Ok(Token {
            cert_hash,
            share_id,
            secret,
            relays,
        })
    }
}

/// Server cert verifier that pins the cert's hash (`SHA-256(cert)[..20]`) to
/// the cert hash carried in a share URL. B installs this on its rustls
/// `ClientConfig` when dialing A, through a relay or directly.
#[derive(Debug)]
pub struct CertHashVerifier {
    expected: CertHash,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl CertHashVerifier {
    pub fn new(expected: CertHash, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { expected, provider }
    }
}

impl rustls::client::danger::ServerCertVerifier for CertHashVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual = cert_hash(end_entity.as_ref());
        if actual == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert hash mismatch: expected {:x?}, got {:x?}",
                &self.expected[..4],
                &actual[..4],
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests;
