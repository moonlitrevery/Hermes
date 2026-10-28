//! At-rest protection for local state.
//!
//! All local state (identity key, MLS group secrets, session, messages) is one
//! file encrypted with XChaCha20-Poly1305 under a random 32-byte master key.
//! The master key lives only in the OS keystore (Secret Service on Linux,
//! Credential Manager on Windows, Keychain on macOS) via the `keyring` crate.
//! Nothing sensitive is ever written to disk in clear; if no keystore is
//! available, opening fails instead of falling back to plaintext.

use std::path::Path;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::{Error, Result, random_bytes};

const SERVICE: &str = "dev.moonlitrevery.hermes";
const MAGIC: &[u8; 8] = b"HERMES2\0";

/// Where the master key is kept.
pub trait KeyVault: Send + Sync {
    fn load(&self) -> Result<Option<[u8; 32]>>;
    fn store(&self, key: &[u8; 32]) -> Result<()>;
}

/// The operating system's credential store.
pub struct SystemKeyring {
    account: String,
}

impl SystemKeyring {
    /// One keystore entry per data directory, so separate profiles (and test
    /// instances) never share a key.
    pub fn for_data_dir(dir: &Path) -> Self {
        let digest = blake3::hash(dir.to_string_lossy().as_bytes());
        Self { account: format!("state-key-{}", &digest.to_hex()[..16]) }
    }

    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, &self.account).map_err(keystore_err)
    }
}

fn keystore_err(e: keyring::Error) -> Error {
    Error::Keystore(e.to_string())
}

impl KeyVault for SystemKeyring {
    fn load(&self) -> Result<Option<[u8; 32]>> {
        match self.entry()?.get_secret() {
            Ok(bytes) => bytes
                .try_into()
                .map(Some)
                .map_err(|_| Error::Keystore("stored key has the wrong length".into())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keystore_err(e)),
        }
    }

    fn store(&self, key: &[u8; 32]) -> Result<()> {
        self.entry()?.set_secret(key).map_err(keystore_err)
    }
}

/// In-process vault for tests.
#[derive(Default)]
pub struct MemoryVault(Mutex<Option<[u8; 32]>>);

impl KeyVault for MemoryVault {
    fn load(&self) -> Result<Option<[u8; 32]>> {
        Ok(*self.0.lock().unwrap())
    }

    fn store(&self, key: &[u8; 32]) -> Result<()> {
        *self.0.lock().unwrap() = Some(*key);
        Ok(())
    }
}

/// Returns the master key for an existing state file, or creates one for a new
/// profile. A state file whose key is gone is an error, never silently replaced.
pub fn master_key(vault: &dyn KeyVault, state_exists: bool) -> Result<[u8; 32]> {
    match vault.load()? {
        Some(key) => Ok(key),
        None if state_exists => Err(Error::Keystore(
            "the encrypted state exists but its key is missing from the system keystore".into(),
        )),
        None => {
            let key = random_bytes::<32>();
            vault.store(&key)?;
            // Read back so a keystore that silently drops writes fails now, not
            // after we have encrypted data with a key we can't recover.
            match vault.load()? {
                Some(k) if k == key => Ok(key),
                _ => Err(Error::Keystore("the system keystore did not keep the key".into())),
            }
        }
    }
}

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 24] = random_bytes();
    let ct = XChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: MAGIC })
        .expect("in-memory encryption");
    [&MAGIC[..], &nonce, &ct].concat()
}

pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < MAGIC.len() + 24 || &sealed[..MAGIC.len()] != MAGIC {
        return Err(Error::Keystore("state file is not a Hermes vault".into()));
    }
    let nonce: [u8; 24] = sealed[MAGIC.len()..MAGIC.len() + 24].try_into().unwrap();
    XChaCha20Poly1305::new_from_slice(key)
        .expect("32-byte key")
        .decrypt(&XNonce::from(nonce), Payload { msg: &sealed[MAGIC.len() + 24..], aad: MAGIC })
        .map_err(|_| Error::Keystore("state file could not be decrypted with the stored key".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip_and_tamper() {
        let key = random_bytes::<32>();
        let sealed = seal(&key, b"segredo");
        assert_eq!(open(&key, &sealed).unwrap(), b"segredo");
        assert!(!sealed.windows(7).any(|w| w == b"segredo"), "plaintext must not appear in the file");

        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, &bad).is_err());
        assert!(open(&random_bytes::<32>(), &sealed).is_err());
    }

    #[test]
    fn missing_key_for_existing_state_is_an_error() {
        let vault = MemoryVault::default();
        assert!(master_key(&vault, true).is_err());
        let k = master_key(&vault, false).unwrap();
        assert_eq!(master_key(&vault, true).unwrap(), k);
    }
}
