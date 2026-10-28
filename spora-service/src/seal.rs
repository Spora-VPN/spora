//! Wrap-at-rest for the secrets in `service.json`: the device's private key,
//! the device token(s) and the relay token(s) are AES-256-GCM ciphertext in
//! the file, field by field; everything else (cursors, the cert, the relay
//! advice) stays readable. The key is the platform's: kept in its secure
//! store (Android EncryptedSharedPreferences, the macOS Keychain, Windows
//! DPAPI) and handed in at start ([`StateKey::Provided`]); on a first run, or
//! after the platform's store lost it, the service mints one
//! ([`StateKey::Mint`]) for the platform to keep. Neither side ever writes
//! the raw key to disk. [`StateKey::Plaintext`] (the CLI, tests) writes the
//! fields in the clear and relies on the file's permissions.
//!
//! A sealed field is the string `sealed:v1:<base64url(nonce(12) ||
//! ciphertext || tag)>`, the field's kind bound in as associated data, so a
//! ciphertext moved to another field does not open. A file whose sealed
//! fields do not open with the key at hand (another key, no key) is state
//! loss — a fresh device — never a rotation: the platform's store and this
//! file are lost together or not at all.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;

/// How the service keeps its secrets at rest.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum StateKey {
    /// In the clear (file permissions only): the CLI, tests, platforms
    /// without a secure store.
    #[default]
    Plaintext,
    /// Sealed with this 32-byte key, from the platform's secure store.
    Provided(Vec<u8>),
    /// Mint a key (first run, or the platform's store lost it), seal with
    /// it, and hand it to the platform (the service's `minted_state_key`).
    Mint,
}

/// Written by hand so a key never reaches a log.
impl std::fmt::Debug for StateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateKey::Plaintext => f.write_str("Plaintext"),
            StateKey::Provided(_) => f.write_str("Provided(<key>)"),
            StateKey::Mint => f.write_str("Mint"),
        }
    }
}

pub const STATE_KEY_LEN: usize = 32;
const PREFIX: &str = "sealed:v1:";

/// The sealed fields: where they are in the state (relative to the state
/// itself and to each parked registration) and the associated data each is
/// sealed under.
const TOP_FIELDS: &[(&[&str], &str)] = &[
    (&["device_identity", "key"], "device_identity.key"),
    (&["device", "token"], "device.token"),
    (&["relay_access", "token", "value"], "relay_token.value"),
];
const PARKED_FIELDS: &[(&[&str], &str)] = &[
    (&["device", "token"], "device.token"),
    (&["relay_access", "token", "value"], "relay_token.value"),
];

/// A file's sealed fields could not be opened.
#[derive(Debug)]
pub(crate) struct StateLost(pub(crate) String);

pub(crate) struct Sealer {
    key: Option<LessSafeKey>,
    /// Leave sealed fields as they are instead of failing: a reader that
    /// only shows the state (it never acts on a secret).
    lenient: bool,
}

impl Sealer {
    /// The sealer for `key`, and the key minted for [`StateKey::Mint`].
    pub(crate) fn new(key: &StateKey) -> Result<(Sealer, Option<Vec<u8>>), String> {
        let (bytes, minted) = match key {
            StateKey::Plaintext => {
                return Ok((
                    Sealer {
                        key: None,
                        lenient: false,
                    },
                    None,
                ));
            }
            StateKey::Provided(b) => (b.clone(), None),
            StateKey::Mint => {
                let mut b = vec![0u8; STATE_KEY_LEN];
                SystemRandom::new()
                    .fill(&mut b)
                    .map_err(|_| "cannot mint a state key".to_string())?;
                (b.clone(), Some(b))
            }
        };
        if bytes.len() != STATE_KEY_LEN {
            return Err(format!(
                "the state key is {} bytes, not {STATE_KEY_LEN}",
                bytes.len()
            ));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, &bytes).map_err(|_| "bad state key")?;
        Ok((
            Sealer {
                key: Some(LessSafeKey::new(unbound)),
                lenient: false,
            },
            minted,
        ))
    }

    /// A sealer that seals nothing and leaves sealed fields sealed.
    pub(crate) fn lenient() -> Sealer {
        Sealer {
            key: None,
            lenient: true,
        }
    }

    fn seal(&self, aad: &str, plain: &str) -> String {
        let Some(key) = &self.key else {
            return plain.to_string();
        };
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("the system RNG works");
        let mut buf = plain.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad.as_bytes()),
            &mut buf,
        )
        .expect("AES-GCM sealing of a short string does not fail");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(out))
    }

    fn open(&self, aad: &str, text: &str) -> Result<Option<String>, StateLost> {
        let Some(b64) = text.strip_prefix(PREFIX) else {
            // In the clear: a file written before sealing was on. It is
            // sealed on the next save.
            return Ok(None);
        };
        let Some(key) = &self.key else {
            if self.lenient {
                return Ok(None);
            }
            return Err(StateLost(format!("{aad} is sealed and no key was given")));
        };
        let raw = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| StateLost(format!("{aad}: not a sealed value")))?;
        if raw.len() < NONCE_LEN {
            return Err(StateLost(format!("{aad}: not a sealed value")));
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let mut buf = ct.to_vec();
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| StateLost(format!("{aad}: not a sealed value")))?;
        let plain = key
            .open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf)
            .map_err(|_| StateLost(format!("{aad} does not open with this key")))?;
        String::from_utf8(plain.to_vec())
            .map(Some)
            .map_err(|_| StateLost(format!("{aad}: not text")))
    }

    /// Seal the secret fields of a serialized state, in place.
    pub(crate) fn seal_state(&self, state: &mut Value) {
        if self.key.is_none() {
            return;
        }
        self.each(state, |at, aad, s| {
            *s = self.seal(aad, s);
            let _ = at;
        });
    }

    /// Open the sealed fields of a state read from disk, in place.
    pub(crate) fn open_state(&self, state: &mut Value) -> Result<(), StateLost> {
        let mut failed = None;
        self.each(state, |_, aad, s| {
            if failed.is_some() {
                return;
            }
            match self.open(aad, s) {
                Ok(Some(plain)) => *s = plain,
                Ok(None) => {}
                Err(e) => failed = Some(e),
            }
        });
        failed.map_or(Ok(()), Err)
    }

    fn each(&self, state: &mut Value, mut f: impl FnMut(&[&str], &str, &mut String)) {
        for (path, aad) in TOP_FIELDS {
            if let Some(Value::String(s)) = get_mut(state, path) {
                f(path, aad, s);
            }
        }
        if let Some(Value::Array(parked)) = state.get_mut("parked") {
            for p in parked {
                for (path, aad) in PARKED_FIELDS {
                    if let Some(Value::String(s)) = get_mut(p, path) {
                        f(path, aad, s);
                    }
                }
            }
        }
    }
}

fn get_mut<'a>(v: &'a mut Value, path: &[&str]) -> Option<&'a mut Value> {
    let mut cur = v;
    for k in path {
        cur = cur.get_mut(*k)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn state() -> Value {
        json!({
            "v": 1,
            "device_identity": {"cert": "CERT", "key": "PRIVATE"},
            "device": {"id": "d1", "token": "TOKEN-1"},
            "relay_access": {"token": {"value": "RELAY-1", "subject": "ab"}},
            "parked": [
                {"device": {"id": "d0", "token": "TOKEN-0"},
                 "relay_access": {"token": {"value": "RELAY-0"}}}
            ],
        })
    }

    fn sealer(key: &[u8]) -> Sealer {
        Sealer::new(&StateKey::Provided(key.to_vec())).unwrap().0
    }

    #[test]
    fn secrets_are_sealed_and_the_rest_stays_readable() {
        let s = sealer(&[7; 32]);
        let mut v = state();
        s.seal_state(&mut v);
        let text = v.to_string();
        for secret in ["PRIVATE", "TOKEN-1", "TOKEN-0", "RELAY-1", "RELAY-0"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        for clear in ["CERT", "d1", "d0", "\"ab\""] {
            assert!(text.contains(clear), "{clear} not in {text}");
        }
        s.open_state(&mut v).unwrap();
        assert_eq!(v, state());
    }

    #[test]
    fn another_key_or_none_is_state_loss() {
        let mut v = state();
        sealer(&[7; 32]).seal_state(&mut v);
        assert!(sealer(&[8; 32]).open_state(&mut v.clone()).is_err());
        let (plain, _) = Sealer::new(&StateKey::Plaintext).unwrap();
        assert!(plain.open_state(&mut v.clone()).is_err());
        // A reader that only shows the state leaves the fields sealed.
        let mut shown = v.clone();
        Sealer::lenient().open_state(&mut shown).unwrap();
        assert_eq!(shown, v);
    }

    #[test]
    fn a_field_moved_elsewhere_does_not_open() {
        let s = sealer(&[7; 32]);
        let mut v = state();
        s.seal_state(&mut v);
        let token = v["device"]["token"].clone();
        v["relay_access"]["token"]["value"] = token;
        assert!(s.open_state(&mut v).is_err());
    }

    #[test]
    fn clear_fields_are_taken_and_sealed_next_time() {
        let s = sealer(&[7; 32]);
        let mut v = state();
        s.open_state(&mut v).unwrap();
        assert_eq!(v, state(), "a file from before sealing reads as is");
    }

    #[test]
    fn mint_hands_back_a_key_that_opens_what_it_sealed() {
        let (minting, key) = Sealer::new(&StateKey::Mint).unwrap();
        let key = key.expect("minted");
        assert_eq!(key.len(), STATE_KEY_LEN);
        let mut v = state();
        minting.seal_state(&mut v);
        sealer(&key).open_state(&mut v).unwrap();
        assert_eq!(v, state());
        assert!(Sealer::new(&StateKey::Provided(vec![1; 16])).is_err());
        assert!(!format!("{:?}", StateKey::Provided(key)).contains('['));
    }
}
