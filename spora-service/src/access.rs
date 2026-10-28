//! Relay access: the device identity, the relays and relay token the API
//! hands the device, their renewal, the shares that are running, and making
//! new shares.
//!
//! The device has one key pair and cert ([`spora_core::identity::DeviceIdentity`]),
//! minted the first time the service opens its state and kept there (the key
//! sealed when the platform gives a state key). Every registration with the
//! API names its cert hash. `GET /v1/relays` answers with the relays to write
//! into new shares (the *advice*) and a relay token: opaque bytes the Spora
//! relays check, naming this device, valid for a few days, to be renewed
//! after `renew_after`. Both are cached in the state, so starting a share
//! never needs the network: it presents the cached token, and the service's
//! thread renews it while the process lives and pushes each new token to
//! every running share ([`Telemetry::register_share`]). A failed request
//! keeps what was cached.

use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use spora_core::identity::{
    Credential, Credentials, DeviceIdentity, RelayEndpoint, RelayEntry, Share, ShareId,
};

use crate::api::ApiError;
use crate::state::{
    AdvisedRelay, CachedRelayToken, RelayAccess, ServiceState, StateStore, StoredIdentity,
};
use crate::telemetry::{Inner, Telemetry, lock};
use crate::upload::PassSummary;
use crate::{Error, time};

/// How long after the API last said the device is not entitled to a relay
/// token it is asked again.
const NOT_ENTITLED_RECHECK: Duration = Duration::from_secs(6 * 60 * 60);

/// The device's relay access as the UI shows it. Device-level: whether a
/// particular relay refuses the token is not known here (relays do not
/// answer registrations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAccessStatus {
    /// The device's cert hash, hex.
    pub cert_hash: String,
    /// When the cached relay token expires; `None` without one.
    pub token_expires_unix_ms: Option<u64>,
    /// When it is due for renewal.
    pub renew_after_unix_ms: Option<u64>,
    /// The last time the API answered.
    pub last_success_unix_ms: Option<u64>,
    /// The last failure, if it came after the last success.
    pub last_error: Option<String>,
    /// The cached relay advice.
    pub advised: Vec<AdvisedRelay>,
}

/// The device identity in `store`, minted (and kept) if there is none or
/// it does not parse. Registrations made without it — under another cert
/// hash, or none — are forgotten when one is minted: the next pass that
/// needs one registers anew, naming this device's cert hash.
pub(crate) fn ensure_identity(store: &StateStore) -> Result<DeviceIdentity, Error> {
    let r = store.modify(|s| {
        if let Some(d) = s.device_identity.as_ref().and_then(decode_identity) {
            return d;
        }
        let d = DeviceIdentity::generate();
        if s.device.is_some() || !s.parked.is_empty() {
            log::info!(
                "service: minted the device identity; forgetting registrations made without it"
            );
            s.device = None;
            s.park(); // with no device: clears what was the active one's
            s.parked.clear();
        }
        s.device_identity = Some(StoredIdentity {
            cert: URL_SAFE_NO_PAD.encode(d.cert_der_bytes()),
            key: URL_SAFE_NO_PAD.encode(d.key_der_bytes()),
            extra: serde_json::Map::new(),
        });
        d
    })?;
    Ok(r)
}

fn decode_identity(si: &StoredIdentity) -> Option<DeviceIdentity> {
    let cert = URL_SAFE_NO_PAD.decode(&si.cert).ok()?;
    let key = URL_SAFE_NO_PAD.decode(&si.key).ok()?;
    match DeviceIdentity::from_parts(cert, key) {
        Ok(d) => Some(d),
        Err(e) => {
            log::warn!("service: the stored device identity is unusable ({e}); minting another");
            None
        }
    }
}

impl Inner {
    /// The relay access of this configuration's registration, or — with no
    /// registration at all — what was noted without one.
    fn access(&self, st: &ServiceState) -> RelayAccess {
        match st.served(|d| self.api.serves(d)) {
            Some(r) => r.relay_access,
            None if st.device.is_none() => st.relay_access.clone(),
            None => RelayAccess::default(),
        }
    }

    /// When the relay access is due for renewal (unix ms): now if it was
    /// never fetched, else the token's `renew_after`, or a while after the
    /// API said the device is not entitled.
    fn renew_at_ms(&self, st: &ServiceState) -> u64 {
        let a = self.access(st);
        if a.last_success_unix_ms == 0 {
            return 0;
        }
        match &a.token {
            Some(t) => t.renew_after_unix_ms,
            None => a.last_success_unix_ms + NOT_ENTITLED_RECHECK.as_millis() as u64,
        }
    }

    pub(crate) fn renewal_due(&self, now_ms: u64) -> bool {
        self.manage_relays.load(std::sync::atomic::Ordering::SeqCst)
            && self.renew_at_ms(&self.store.get()) <= now_ms
    }

    /// When the thread should renew, if this configuration manages relay
    /// access.
    pub(crate) fn renewal_at(&self) -> Option<Instant> {
        if !self.manage_relays.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        let at = self.renew_at_ms(&self.store.get());
        let now = time::unix_ms();
        Some(Instant::now() + Duration::from_millis(at.saturating_sub(now)))
    }

    /// Register if need be, fetch the relays and a token, keep both, and
    /// give the token to every running share. The caller holds the pass
    /// lock.
    pub(crate) fn renew_relay_access_locked(&self, halt: &dyn Fn() -> bool) -> Result<(), Error> {
        let pass = self.new_pass(halt);
        let mut sum = PassSummary::default();
        let now = time::unix_ms();
        let dev = match pass.ensure_device(&mut sum) {
            Ok(d) => d,
            Err(e) => {
                let msg = e.to_string();
                let _ = self.store.modify(|s| {
                    if s.device.is_none() {
                        s.relay_access.last_failure_unix_ms = now;
                        s.relay_access.last_error = Some(msg);
                    }
                });
                return Err(e);
            }
        };
        let answer = self.api.relays(&dev).and_then(|a| {
            let bytes = match &a.token {
                Some(t) => Some(URL_SAFE_NO_PAD.decode(&t.value).map_err(|_| {
                    ApiError::BadResponse("the relay token is not base64url".into())
                })?),
                None => None,
            };
            Ok((a, bytes))
        });
        match answer {
            Ok((a, bytes)) => {
                let advised = a.relays.len();
                let entitled = a.token.is_some();
                self.store.modify(|s| {
                    s.with_device(&dev, |s| {
                        s.relay_access.advice = a.relays;
                        s.relay_access.token = a.token.map(|t| CachedRelayToken {
                            value: t.value,
                            subject: t.subject,
                            expires_unix_ms: t.expires_unix_ms,
                            renew_after_unix_ms: t.renew_after_unix_ms,
                            fetched_unix_ms: now,
                            extra: serde_json::Map::new(),
                        });
                        s.relay_access.last_success_unix_ms = now;
                        s.relay_access.last_error = None;
                    })
                })?;
                if entitled {
                    log::info!("relays: {advised} advised, relay token renewed");
                } else {
                    log::warn!("relays: {advised} advised; this device gets no relay token");
                }
                self.push_token(bytes);
                Ok(())
            }
            Err(e) => {
                let e = pass.api_error("relays", Some(&dev), e);
                let msg = e.to_string();
                if matches!(e, Error::Api(ApiError::Transport(_))) {
                    log::info!("relays: {msg}; keeping what is cached");
                } else {
                    log::warn!("relays: {msg}; keeping what is cached");
                }
                let _ = self.store.modify(|s| {
                    s.with_device(&dev, |s| {
                        s.relay_access.last_failure_unix_ms = now;
                        s.relay_access.last_error = Some(msg);
                    })
                });
                Err(e)
            }
        }
    }

    fn push_token(&self, token: Option<Vec<u8>>) {
        let shares = lock(&self.shares);
        for c in shares.values() {
            c.set_spora_token(token.clone());
        }
    }

    /// The cached relay token's bytes, unless it has expired.
    fn current_token(&self) -> Option<Vec<u8>> {
        let t = self.access(&self.store.get()).token?;
        if t.expires_unix_ms <= time::unix_ms() {
            return None;
        }
        URL_SAFE_NO_PAD.decode(&t.value).ok()
    }
}

impl Telemetry {
    /// The device identity every share of this device is served under.
    pub fn device_identity(&self) -> DeviceIdentity {
        self.inner().device.clone()
    }

    /// Fetch the relays and a relay token now, on the caller's thread (as
    /// long as a request takes): register if need be, keep both, give the
    /// token to every running share. A failure keeps what was cached.
    pub fn refresh_relays(&self) -> Result<RelayAccessStatus, Error> {
        let inner = self.inner();
        {
            let _g = lock(&inner.pass_lock);
            inner.renew_relay_access_locked(&|| false)?;
        }
        Ok(self.relay_access_status())
    }

    pub fn relay_access_status(&self) -> RelayAccessStatus {
        let inner = self.inner();
        let a = inner.access(&inner.store.get());
        let failed_last = a.last_failure_unix_ms > a.last_success_unix_ms;
        RelayAccessStatus {
            cert_hash: inner.cert_hash.clone(),
            token_expires_unix_ms: a.token.as_ref().map(|t| t.expires_unix_ms),
            renew_after_unix_ms: a.token.as_ref().map(|t| t.renew_after_unix_ms),
            last_success_unix_ms: (a.last_success_unix_ms > 0).then_some(a.last_success_unix_ms),
            last_error: if failed_last { a.last_error } else { None },
            advised: a.advice,
        }
    }

    /// The relay token to start a share with: the cached one, unless it has
    /// expired (the share then starts degraded and gets one when the
    /// service renews).
    pub fn relay_token(&self) -> Option<Vec<u8>> {
        self.inner().current_token()
    }

    /// A new share of this device, offline: with `use_spora`, the cached
    /// relay advice first (each presenting the device's relay token), then
    /// `own`. Without cached advice that is [`Error::NoRelayAdvice`]: fetch
    /// it first ([`Telemetry::refresh_relays`]).
    pub fn make_share(&self, own: Vec<RelayEntry>, use_spora: bool) -> Result<Share, Error> {
        let mut entries = Vec::new();
        if use_spora {
            let advice = self.relay_access_status().advised;
            for a in &advice {
                if let Some(endpoint) = advised_endpoint(a) {
                    entries.push(RelayEntry {
                        endpoint,
                        credential: Credential::Spora,
                    });
                }
            }
            if entries.is_empty() {
                return Err(Error::NoRelayAdvice);
            }
        }
        entries.extend(own);
        Share::new(&self.inner().device, entries).map_err(Error::Config)
    }

    /// A share started: its credentials get every new relay token from now
    /// on (and the current one, if it started with another).
    pub fn register_share(&self, share_id: ShareId, credentials: Credentials) {
        let inner = self.inner();
        let current = inner.current_token();
        if credentials.token(&Credential::Spora) != current.clone().unwrap_or_default() {
            credentials.set_spora_token(current);
        }
        lock(&inner.shares).insert(share_id, credentials);
    }

    /// A share stopped.
    pub fn unregister_share(&self, share_id: &ShareId) {
        lock(&self.inner().shares).remove(share_id);
    }
}

/// An advised relay as a share endpoint (`None` for a protocol this build
/// does not know).
pub fn advised_endpoint(a: &AdvisedRelay) -> Option<RelayEndpoint> {
    let host = if a.host.contains(':') {
        format!("[{}]", a.host)
    } else {
        a.host.clone()
    };
    RelayEndpoint::from_url_param(&format!("{}/{host}:{}", a.protocol, a.port)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use spora_core::identity::RelayProtocol;

    #[test]
    fn advised_relays_become_endpoints() {
        let a = |p: &str, h: &str| AdvisedRelay {
            protocol: p.into(),
            host: h.into(),
            port: 443,
        };
        assert_eq!(
            advised_endpoint(&a("quic", "1.2.3.4")),
            Some(RelayEndpoint::new("1.2.3.4", 443))
        );
        assert_eq!(
            advised_endpoint(&a("nz", "2001:db8::1")),
            Some(RelayEndpoint::with_protocol(
                "2001:db8::1",
                443,
                RelayProtocol::NoiseUdp
            ))
        );
        assert_eq!(
            advised_endpoint(&a("tcptls", "1.2.3.4")).map(|e| e.protocol),
            Some(RelayProtocol::TcpTls)
        );
        assert_eq!(advised_endpoint(&a("warp", "1.2.3.4")), None);
    }
}
