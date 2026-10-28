//! Cryptography for Hermes.
//!
//! Every group has a 32-byte secret that is shared only through its invite
//! code. All other keys are derived from it with BLAKE3:
//!
//! - `group_id`: public identifier the server indexes rows by. It cannot be
//!   reversed into the secret, so knowing it does not let Supabase (or anyone
//!   else) read the group.
//! - message key: XChaCha20-Poly1305 key for message bodies and group names.
//!
//! Each device also holds an Ed25519 identity key. Every message is signed,
//! so members cannot impersonate each other even though they share the
//! group key, and the server cannot forge or alter messages.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const INVITE_VERSION: u8 = 1;
const CTX_GROUP_ID: &str = "hermes v1 group id";
const CTX_MESSAGE_KEY: &str = "hermes v1 message key";
const CTX_INVITE_CHECK: &str = "hermes v1 invite checksum";
const AAD_MESSAGE: &[u8] = b"hermes/msg/v1";
const AAD_GROUP_NAME: &[u8] = b"hermes/name/v1";
const SIG_MESSAGE: &[u8] = b"hermes/sig/v1";

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

/// The shared secret of one group. Whoever holds it can read and write the group.
#[derive(Clone)]
pub struct GroupSecret([u8; 32]);

impl GroupSecret {
    pub fn generate() -> Self {
        Self(random_bytes())
    }

    /// Invite code: base58(version || secret || checksum[4]).
    pub fn invite_code(&self) -> String {
        let mut raw = Vec::with_capacity(37);
        raw.push(INVITE_VERSION);
        raw.extend_from_slice(&self.0);
        raw.extend_from_slice(&invite_checksum(&self.0));
        bs58::encode(raw).into_string()
    }

    pub fn from_invite_code(code: &str) -> Result<Self> {
        let cleaned: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let raw = bs58::decode(cleaned).into_vec().map_err(|_| Error::InvalidInvite)?;
        if raw.len() != 37 || raw[0] != INVITE_VERSION {
            return Err(Error::InvalidInvite);
        }
        let secret: [u8; 32] = raw[1..33].try_into().unwrap();
        if raw[33..] != invite_checksum(&secret) {
            return Err(Error::InvalidInvite);
        }
        Ok(Self(secret))
    }

    pub fn group_id(&self) -> String {
        hex::encode(blake3::derive_key(CTX_GROUP_ID, &self.0))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key = blake3::derive_key(CTX_MESSAGE_KEY, &self.0);
        XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key")
    }

    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> ([u8; 24], Vec<u8>) {
        let nonce: [u8; 24] = random_bytes();
        let ct = self
            .cipher()
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
            .expect("encryption cannot fail for in-memory buffers");
        (nonce, ct)
    }

    fn open(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| Error::Decrypt)?;
        self.cipher()
            .decrypt(&XNonce::from(nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| Error::Decrypt)
    }

    /// Encrypts the group's display name for storage on the server.
    pub fn seal_name(&self, name: &str) -> String {
        let aad = [AAD_GROUP_NAME, self.group_id().as_bytes()].concat();
        let (nonce, ct) = self.seal(&aad, name.as_bytes());
        B64.encode([&nonce[..], &ct].concat())
    }

    pub fn open_name(&self, sealed: &str) -> Result<String> {
        let raw = B64.decode(sealed).map_err(|_| Error::Decrypt)?;
        if raw.len() < 24 {
            return Err(Error::Decrypt);
        }
        let aad = [AAD_GROUP_NAME, self.group_id().as_bytes()].concat();
        let pt = self.open(&aad, &raw[..24], &raw[24..])?;
        String::from_utf8(pt).map_err(|_| Error::Decrypt)
    }
}

fn invite_checksum(secret: &[u8; 32]) -> [u8; 4] {
    blake3::derive_key(CTX_INVITE_CHECK, secret)[..4].try_into().unwrap()
}

/// A device's long-term signing identity.
pub struct Identity(SigningKey);

impl Identity {
    pub fn generate() -> Self {
        Self(SigningKey::from_bytes(&random_bytes()))
    }

    pub fn from_hex(secret_hex: &str) -> Result<Self> {
        let bytes: [u8; 32] = hex::decode(secret_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::Malformed("identity key".into()))?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_bytes())
    }
}

/// Short human-comparable fingerprint of a public key, e.g. `3f9a-c1d0-77be-0442`.
pub fn fingerprint(public_hex: &str) -> String {
    let digest = blake3::hash(public_hex.as_bytes());
    let hex = hex::encode(&digest.as_bytes()[..8]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Plaintext content of a message; only group members ever see this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageBody {
    /// Random per-message id, lets clients drop server-side replays.
    pub id: String,
    pub name: String,
    pub text: String,
    /// Sender's clock, unix milliseconds.
    pub sent_at: i64,
}

/// The encrypted, signed form of a message as stored on the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SealedMessage {
    pub sender_pub: String,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}

fn message_aad(group_id: &str, sender_pub: &str) -> Vec<u8> {
    [AAD_MESSAGE, group_id.as_bytes(), sender_pub.as_bytes()].concat()
}

fn signed_bytes(group_id: &str, sender_pub: &str, nonce: &[u8], ct: &[u8]) -> Vec<u8> {
    [SIG_MESSAGE, group_id.as_bytes(), sender_pub.as_bytes(), nonce, ct].concat()
}

pub fn seal_message(group: &GroupSecret, me: &Identity, body: &MessageBody) -> SealedMessage {
    let group_id = group.group_id();
    let sender_pub = me.public_hex();
    let plaintext = serde_json::to_vec(body).expect("serializable");
    let (nonce, ct) = group.seal(&message_aad(&group_id, &sender_pub), &plaintext);
    let sig = me.0.sign(&signed_bytes(&group_id, &sender_pub, &nonce, &ct));
    SealedMessage {
        sender_pub,
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ct),
        signature: B64.encode(sig.to_bytes()),
    }
}

/// Verifies the sender's signature, then decrypts.
pub fn open_message(group: &GroupSecret, sealed: &SealedMessage) -> Result<MessageBody> {
    let group_id = group.group_id();
    let nonce = B64.decode(&sealed.nonce).map_err(|_| Error::Decrypt)?;
    let ct = B64.decode(&sealed.ciphertext).map_err(|_| Error::Decrypt)?;
    let sig = B64.decode(&sealed.signature).map_err(|_| Error::BadSignature)?;

    let pub_bytes: [u8; 32] = hex::decode(&sealed.sender_pub)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::BadSignature)?;
    let key = VerifyingKey::from_bytes(&pub_bytes).map_err(|_| Error::BadSignature)?;
    let sig = Signature::try_from(sig.as_slice()).map_err(|_| Error::BadSignature)?;
    key.verify(&signed_bytes(&group_id, &sealed.sender_pub, &nonce, &ct), &sig)
        .map_err(|_| Error::BadSignature)?;

    let pt = group.open(&message_aad(&group_id, &sealed.sender_pub), &nonce, &ct)?;
    serde_json::from_slice(&pt).map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> MessageBody {
        MessageBody { id: "a1".into(), name: "Arthur".into(), text: "olá".into(), sent_at: 1 }
    }

    #[test]
    fn invite_round_trip() {
        let g = GroupSecret::generate();
        let code = g.invite_code();
        let back = GroupSecret::from_invite_code(&format!("  {code}\n")).unwrap();
        assert_eq!(back.group_id(), g.group_id());
    }

    #[test]
    fn invite_rejects_typos() {
        let code = GroupSecret::generate().invite_code();
        let mut chars: Vec<char> = code.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(GroupSecret::from_invite_code(&typo).is_err());
        assert!(GroupSecret::from_invite_code("").is_err());
    }

    #[test]
    fn message_round_trip() {
        let g = GroupSecret::generate();
        let me = Identity::generate();
        let sealed = seal_message(&g, &me, &body());
        assert_eq!(open_message(&g, &sealed).unwrap(), body());
    }

    #[test]
    fn wrong_group_cannot_read() {
        let me = Identity::generate();
        let sealed = seal_message(&GroupSecret::generate(), &me, &body());
        assert!(open_message(&GroupSecret::generate(), &sealed).is_err());
    }

    #[test]
    fn impersonation_is_rejected() {
        let g = GroupSecret::generate();
        let mut sealed = seal_message(&g, &Identity::generate(), &body());
        sealed.sender_pub = Identity::generate().public_hex();
        assert!(matches!(open_message(&g, &sealed), Err(Error::BadSignature)));
    }

    #[test]
    fn tampering_is_rejected() {
        let g = GroupSecret::generate();
        let mut sealed = seal_message(&g, &Identity::generate(), &body());
        let mut ct = B64.decode(&sealed.ciphertext).unwrap();
        ct[0] ^= 1;
        sealed.ciphertext = B64.encode(ct);
        assert!(open_message(&g, &sealed).is_err());
    }

    #[test]
    fn group_name_round_trip() {
        let g = GroupSecret::generate();
        assert_eq!(g.open_name(&g.seal_name("Ordem")).unwrap(), "Ordem");
        assert!(GroupSecret::generate().open_name(&g.seal_name("Ordem")).is_err());
    }

    #[test]
    fn identity_round_trip() {
        let id = Identity::generate();
        assert_eq!(Identity::from_hex(&id.secret_hex()).unwrap().public_hex(), id.public_hex());
    }
}
