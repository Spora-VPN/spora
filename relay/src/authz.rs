//! Who may register with this relay.
//!
//! *Authentication* is the relay's own job and is done before anything here
//! runs: a registration (UDP REGISTER or TCP park) carries the device's cert
//! and a signature over the share id and a timestamp; the relay verifies the
//! signature, derives the routing hash from the cert hash and the share id,
//! and requires the timestamp to exceed the last one it accepted for that
//! routing hash. A registration that reaches an [`Authorizer`] is therefore
//! known to come from the holder of the key behind `cert_hash`.
//!
//! *Authorization* is the [`Authorizer`]'s: given that, and the token the
//! registration carried, allow or deny. The token is opaque bytes to this
//! crate. Its built-in modes are [`Open`] (no token wanted; anything is
//! accepted) and [`StaticToken`] (a constant-time compare against one
//! configured value, a self-hosted relay's bearer token). Anything else — a
//! token format, issuer keys, expiry, entitlement — is an `Authorizer` a
//! binary linking this crate supplies.

use std::net::SocketAddr;
use std::time::SystemTime;

use relay_client::protocol::{CertHash, RoutingHash, ShareId};

/// Which listener a registration arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// A UDP REGISTER for the share's QUIC listener.
    Quic,
    /// A UDP REGISTER for the share's nz (Noise UDP) socket.
    Nz,
    /// A TCP park.
    Tcp,
}

/// What the relay knows about a registration it has authenticated.
#[derive(Clone, Copy, Debug)]
pub struct RegistrationCtx {
    /// The registering device: `SHA-256(cert)[..20]`, the cert being the one
    /// whose key signed the registration.
    pub cert_hash: CertHash,
    pub share_id: ShareId,
    /// `SHA-256(cert_hash || share_id)[..20]`, derived by the relay.
    pub routing_hash: RoutingHash,
    /// Where the registration came from.
    pub source: SocketAddr,
    pub carrier: Carrier,
}

/// Allow or deny an authenticated registration. Called on every accepted
/// REGISTER refresh (every ~30 s per share and relay) and every park, from
/// the forwarding task: an implementation must be cheap and must not block
/// (no I/O on this path; anything it records goes through a channel).
pub trait Authorizer: Send + Sync {
    fn authorize(&self, ctx: &RegistrationCtx, token: &[u8], now: SystemTime) -> bool;

    /// One line for the startup log, e.g. "open" or "static token".
    fn describe(&self) -> String;
}

/// Accept every authenticated registration, whatever token it carries.
pub struct Open;

impl Authorizer for Open {
    fn authorize(&self, _: &RegistrationCtx, _: &[u8], _: SystemTime) -> bool {
        true
    }

    fn describe(&self) -> String {
        "open (any signed registration is accepted)".into()
    }
}

/// Accept a registration whose token equals the configured bytes.
pub struct StaticToken {
    token: Vec<u8>,
}

impl StaticToken {
    /// `token` must not be empty: an empty token is what an open-relay
    /// registration carries.
    pub fn new(token: Vec<u8>) -> Result<Self, String> {
        if token.is_empty() {
            return Err("the static token is empty".into());
        }
        Ok(Self { token })
    }
}

impl Authorizer for StaticToken {
    fn authorize(&self, _: &RegistrationCtx, token: &[u8], _: SystemTime) -> bool {
        constant_time_eq(&self.token, token)
    }

    fn describe(&self) -> String {
        "static token (registrations must present the configured token)".into()
    }
}

/// Compare without an early exit, so the time taken says nothing about how
/// much of a guess was right. (The length is not secret: it is compared
/// first.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RegistrationCtx {
        RegistrationCtx {
            cert_hash: [1; 20],
            share_id: [2; 8],
            routing_hash: [3; 20],
            source: "10.0.0.1:1".parse().unwrap(),
            carrier: Carrier::Quic,
        }
    }

    #[test]
    fn open_accepts_anything() {
        let now = SystemTime::now();
        assert!(Open.authorize(&ctx(), b"", now));
        assert!(Open.authorize(&ctx(), b"whatever", now));
    }

    #[test]
    fn static_token_accepts_only_its_bytes() {
        let a = StaticToken::new(b"bearer-1".to_vec()).unwrap();
        let now = SystemTime::now();
        assert!(a.authorize(&ctx(), b"bearer-1", now));
        assert!(!a.authorize(&ctx(), b"bearer-2", now));
        assert!(!a.authorize(&ctx(), b"bearer-", now));
        assert!(!a.authorize(&ctx(), b"", now));
        assert!(StaticToken::new(Vec::new()).is_err());
    }
}
