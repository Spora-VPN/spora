//! What a sharer presents to each relay, and the one part of it that changes
//! while a share runs.
//!
//! Every relay endpoint of a share carries a [`Credential`]: `None` (an open
//! relay), `Static` (bearer bytes a self-hosted relay compares against its
//! configured value) or `Spora` (the device's current relay token, the same
//! bytes for every Spora relay of every share). The kinds and static bytes
//! are fixed by the share; the relay token is renewed while shares run, so it
//! lives in [`Credentials`], shared by every registrar and park worker of a
//! share. They read it each time they build a packet or open a parked
//! connection, and [`Credentials::subscribe`] tells them when it changed, so a
//! new token is presented at once instead of at the next 30-second tick.

use std::sync::{Arc, RwLock};

use tokio::sync::watch;

/// What one relay endpoint of a share is sent.
#[derive(Clone, PartialEq, Eq, Default)]
pub enum Credential {
    /// Nothing: the relay is open.
    #[default]
    None,
    /// These bytes, verbatim (a self-hosted relay's bearer token).
    Static(Vec<u8>),
    /// The device's current relay token (see [`Credentials`]).
    Spora,
}

/// Written by hand so a static token never reaches a log.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::None => f.write_str("None"),
            Credential::Static(b) => write!(f, "Static(<{} bytes>)", b.len()),
            Credential::Spora => f.write_str("Spora"),
        }
    }
}

struct CredentialMap {
    /// The relay token sent to `Spora` endpoints; `None` until one is in hand
    /// (a share started degraded: it registers with those relays tokenless,
    /// which an authorizing relay refuses, until a token arrives).
    spora: Option<Vec<u8>>,
}

/// The mutable credential state of one running share. Cheap to clone; every
/// clone shares the same state.
#[derive(Clone)]
pub struct Credentials {
    map: Arc<RwLock<CredentialMap>>,
    epoch: Arc<watch::Sender<u64>>,
}

impl Credentials {
    pub fn new(spora_token: Option<Vec<u8>>) -> Self {
        Self {
            map: Arc::new(RwLock::new(CredentialMap {
                spora: spora_token.filter(|t| !t.is_empty()),
            })),
            epoch: Arc::new(watch::channel(0).0),
        }
    }

    /// The bytes to present for `credential` right now.
    pub fn token(&self, credential: &Credential) -> Vec<u8> {
        match credential {
            Credential::None => Vec::new(),
            Credential::Static(b) => b.clone(),
            Credential::Spora => self
                .map
                .read()
                .expect("credential map")
                .spora
                .clone()
                .unwrap_or_default(),
        }
    }

    /// Whether a relay token is in hand.
    pub fn has_spora_token(&self) -> bool {
        self.map.read().expect("credential map").spora.is_some()
    }

    /// Replace the relay token (one write) and tell every subscriber.
    pub fn set_spora_token(&self, token: Option<Vec<u8>>) {
        self.map.write().expect("credential map").spora = token.filter(|t| !t.is_empty());
        self.epoch.send_modify(|e| *e += 1);
    }

    /// A receiver whose `changed()` resolves after the next
    /// [`set_spora_token`](Self::set_spora_token).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        let mut rx = self.epoch.subscribe();
        rx.mark_unchanged();
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_by_kind() {
        let c = Credentials::new(None);
        assert!(c.token(&Credential::None).is_empty());
        assert_eq!(c.token(&Credential::Static(b"s".to_vec())), b"s");
        assert!(
            c.token(&Credential::Spora).is_empty(),
            "no token yet: degraded"
        );
        c.set_spora_token(Some(b"t1".to_vec()));
        assert_eq!(c.token(&Credential::Spora), b"t1");
        assert!(c.has_spora_token());
        c.set_spora_token(Some(Vec::new()));
        assert!(!c.has_spora_token(), "an empty token is no token");
    }

    #[tokio::test]
    async fn subscribers_hear_a_change() {
        let c = Credentials::new(None);
        let mut rx = c.subscribe();
        let clone = c.clone();
        let waiter = tokio::spawn(async move { rx.changed().await.is_ok() });
        tokio::task::yield_now().await;
        clone.set_spora_token(Some(b"t".to_vec()));
        assert!(waiter.await.unwrap());
        assert_eq!(c.token(&Credential::Spora), b"t");
    }

    #[test]
    fn debug_hides_static_bytes() {
        let s = format!("{:?}", Credential::Static(b"hunter2".to_vec()));
        assert!(!s.contains("hunter2"), "{s}");
    }
}
