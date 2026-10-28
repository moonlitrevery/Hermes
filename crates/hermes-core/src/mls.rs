//! MLS (RFC 9420) group cryptography on top of openmls.
//!
//! Every device has one Ed25519 signature key; its public half is both the
//! MLS BasicCredential identity and the `credential` the server records for
//! the member. Groups use a single fixed ciphersuite and encrypt handshake
//! messages too, so the server sees neither message content nor who was
//! added or removed by a commit.
//!
//! The group's display name lives in a private GroupContext extension, so it
//! is only ever sent encrypted (inside Welcome messages and commits).

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

use crate::{Error, Result};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
/// Private-use GroupContext extension carrying the UTF-8 group name.
const GROUP_NAME_EXTENSION: u16 = 0xff00;
/// Application messages sent just before a commit are still readable after it.
/// Pre-join epochs are never available: a joiner gets no secrets for them.
const MAX_PAST_EPOCHS: usize = 3;

fn mls_err(context: &str, e: impl std::fmt::Debug) -> Error {
    Error::Mls(format!("{context}: {e:?}"))
}

/// Crypto backend plus an in-memory key/value store that we persist (encrypted)
/// ourselves; see [`crate::vault`].
#[derive(Default)]
pub struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl Provider {
    pub fn export(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let values = self.storage.values.read().unwrap();
        values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn import(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        let provider = Self::default();
        provider.storage.values.write().unwrap().extend(entries);
        provider
    }
}

/// What processing one incoming MLS message produced.
#[derive(Debug)]
pub enum Incoming {
    Application { sender: String, data: Vec<u8> },
    /// A commit was merged; `removed_me` means this device is no longer a member.
    Commit { removed_me: bool },
    /// Proposals and other handshake messages Hermes does not use.
    Ignored,
}

pub struct Device {
    pub provider: Provider,
    signer: SignatureKeyPair,
}

fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        Some(&[ExtensionType::Unknown(GROUP_NAME_EXTENSION)]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

impl Device {
    pub fn generate() -> Result<Self> {
        let provider = Provider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(|e| mls_err("keygen", e))?;
        signer.store(provider.storage()).map_err(|e| mls_err("store key", e))?;
        Ok(Self { provider, signer })
    }

    pub fn load(provider: Provider, public_key: &[u8]) -> Result<Self> {
        let signer = SignatureKeyPair::read(provider.storage(), public_key, CIPHERSUITE.signature_algorithm())
            .ok_or_else(|| Error::Mls("identity key missing from MLS storage".into()))?;
        Ok(Self { provider, signer })
    }

    pub fn public_key(&self) -> &[u8] {
        self.signer.public()
    }

    /// Hex public signature key: the identity the server and other members see.
    pub fn credential_hex(&self) -> String {
        hex::encode(self.signer.public())
    }

    fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.signer.to_public_vec()).into(),
            signature_key: self.signer.public().into(),
        }
    }

    pub fn create_group(&self, group_id: &[u8], name: &str) -> Result<MlsGroup> {
        let name_ext = Extension::Unknown(GROUP_NAME_EXTENSION, UnknownExtension(name.as_bytes().to_vec()));
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .capabilities(capabilities())
            .with_group_context_extensions(Extensions::single(name_ext).map_err(|e| mls_err("extension", e))?)
            .build();
        MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential_with_key(),
        )
        .map_err(|e| mls_err("create group", e))
    }

    pub fn load_group(&self, group_id: &[u8]) -> Result<Option<MlsGroup>> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id)).map_err(|e| mls_err("load group", e))
    }

    /// A fresh single-use KeyPackage, serialized for the join request.
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential_with_key())
            .map_err(|e| mls_err("key package", e))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| mls_err("serialize key package", e))
    }

    /// Stages an Add commit. The caller must `merge_pending_commit` once the
    /// server accepted it, or `clear_pending_commit` if it was refused.
    /// `expected_credential` is the identity the server recorded for the
    /// request; a KeyPackage for any other identity is rejected.
    pub fn add_member(&self, group: &mut MlsGroup, key_package: &[u8], expected_credential: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let kp = KeyPackageIn::tls_deserialize(&mut &key_package[..])
            .map_err(|e| mls_err("parse key package", e))?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| mls_err("invalid key package", e))?;
        if kp.ciphersuite() != CIPHERSUITE {
            return Err(Error::Mls("key package uses another ciphersuite".into()));
        }
        if hex::encode(kp.leaf_node().signature_key().as_slice()) != expected_credential {
            return Err(Error::Mls("key package identity does not match the join request".into()));
        }
        let (commit, welcome, _) = group
            .add_members(&self.provider, &self.signer, &[kp])
            .map_err(|e| mls_err("add member", e))?;
        Ok((serialize(&commit)?, serialize(&welcome)?))
    }

    /// Stages a Remove commit for the member whose signature key is `credential`.
    pub fn remove_member(&self, group: &mut MlsGroup, credential: &str) -> Result<Vec<u8>> {
        let index = group
            .members()
            .find(|m| hex::encode(&m.signature_key) == credential)
            .map(|m| m.index)
            .ok_or_else(|| Error::Mls("member is not in the MLS group".into()))?;
        let (commit, _, _) = group
            .remove_members(&self.provider, &self.signer, &[index])
            .map_err(|e| mls_err("remove member", e))?;
        serialize(&commit)
    }

    pub fn merge_pending_commit(&self, group: &mut MlsGroup) -> Result<()> {
        group.merge_pending_commit(&self.provider).map_err(|e| mls_err("merge commit", e))
    }

    pub fn clear_pending_commit(&self, group: &mut MlsGroup) -> Result<()> {
        group.clear_pending_commit(self.provider.storage()).map_err(|e| mls_err("clear commit", e))
    }

    pub fn encrypt(&self, group: &mut MlsGroup, plaintext: &[u8]) -> Result<Vec<u8>> {
        let msg = group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| mls_err("encrypt", e))?;
        serialize(&msg)
    }

    pub fn process(&self, group: &mut MlsGroup, bytes: &[u8]) -> Result<Incoming> {
        let protocol = MlsMessageIn::tls_deserialize(&mut &bytes[..])
            .map_err(|e| mls_err("parse message", e))?
            .try_into_protocol_message()
            .map_err(|e| mls_err("not a protocol message", e))?;
        let processed = group.process_message(&self.provider, protocol).map_err(|e| mls_err("process", e))?;
        let sender = match processed.credential().credential_type() {
            CredentialType::Basic => hex::encode(processed.credential().serialized_content()),
            _ => String::new(),
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Incoming::Application { sender, data: app.into_bytes() }),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let removed_me = staged.self_removed();
                group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(|e| mls_err("merge commit", e))?;
                Ok(Incoming::Commit { removed_me })
            }
            _ => Ok(Incoming::Ignored),
        }
    }

    pub fn join(&self, welcome: &[u8]) -> Result<MlsGroup> {
        let welcome = match MlsMessageIn::tls_deserialize(&mut &welcome[..])
            .map_err(|e| mls_err("parse welcome", e))?
            .extract()
        {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(Error::Mls("expected a Welcome message".into())),
        };
        // The ratchet tree travels inside the Welcome (ratchet tree extension).
        StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(|e| mls_err("join", e))?
            .into_group(&self.provider)
            .map_err(|e| mls_err("join", e))
    }

    pub fn has_pending_commit(group: &MlsGroup) -> bool {
        group.pending_commit().is_some()
    }

    pub fn delete_group(&self, group: &mut MlsGroup) -> Result<()> {
        group.delete(self.provider.storage()).map_err(|e| mls_err("delete group", e))
    }
}

pub fn group_name(group: &MlsGroup) -> String {
    group
        .extensions()
        .unknown(GROUP_NAME_EXTENSION)
        .and_then(|ext| String::from_utf8(ext.0.clone()).ok())
        .unwrap_or_default()
}

pub fn epoch(group: &MlsGroup) -> i64 {
    group.epoch().as_u64() as i64
}

fn serialize(msg: &MlsMessageOut) -> Result<Vec<u8>> {
    msg.tls_serialize_detached().map_err(|e| mls_err("serialize", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GID: &[u8] = b"0123456789abcdef";

    /// Owner creates a group and adds `others` one by one; returns all groups.
    fn setup(owner: &Device, others: &[&Device]) -> (MlsGroup, Vec<MlsGroup>) {
        let mut g = owner.create_group(GID, "Ordem").unwrap();
        let mut joined: Vec<MlsGroup> = Vec::new();
        for d in others {
            let (commit, welcome) = owner.add_member(&mut g, &d.key_package().unwrap(), &d.credential_hex()).unwrap();
            owner.merge_pending_commit(&mut g).unwrap();
            for (prev, dev) in joined.iter_mut().zip(others.iter()) {
                dev.process(prev, &commit).unwrap();
            }
            joined.push(d.join(&welcome).unwrap());
        }
        (g, joined)
    }

    fn text(incoming: Incoming) -> Vec<u8> {
        match incoming {
            Incoming::Application { data, .. } => data,
            other => panic!("expected application message, got {other:?}"),
        }
    }

    #[test]
    fn members_exchange_messages_and_see_the_name() {
        let (a, b) = (Device::generate().unwrap(), Device::generate().unwrap());
        let (mut ga, mut gb) = setup(&a, &[&b]);
        let mut gb = gb.remove(0);
        assert_eq!(group_name(&gb), "Ordem");
        assert_eq!(epoch(&ga), epoch(&gb));

        let ct = a.encrypt(&mut ga, b"oi").unwrap();
        match b.process(&mut gb, &ct).unwrap() {
            Incoming::Application { sender, data } => {
                assert_eq!(data, b"oi");
                assert_eq!(sender, a.credential_hex());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn removed_member_cannot_decrypt_new_messages() {
        let (a, b, c) = (Device::generate().unwrap(), Device::generate().unwrap(), Device::generate().unwrap());
        let (mut ga, mut joined) = setup(&a, &[&b, &c]);
        let mut gc = joined.pop().unwrap();
        let mut gb = joined.pop().unwrap();

        let commit = a.remove_member(&mut ga, &b.credential_hex()).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();
        assert!(matches!(c.process(&mut gc, &commit).unwrap(), Incoming::Commit { removed_me: false }));
        assert!(matches!(b.process(&mut gb, &commit).unwrap(), Incoming::Commit { removed_me: true }));
        assert!(!gb.is_active());

        let secret = a.encrypt(&mut ga, b"depois da saida").unwrap();
        assert_eq!(text(c.process(&mut gc, &secret).unwrap()), b"depois da saida");
        assert!(b.process(&mut gb, &secret).is_err(), "removed member must not decrypt");
    }

    #[test]
    fn removed_member_that_never_saw_the_commit_still_cannot_decrypt() {
        let (a, b) = (Device::generate().unwrap(), Device::generate().unwrap());
        let (mut ga, mut joined) = setup(&a, &[&b]);
        let mut gb = joined.pop().unwrap();
        a.remove_member(&mut ga, &b.credential_hex()).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();
        let secret = a.encrypt(&mut ga, b"nova epoca").unwrap();
        assert!(b.process(&mut gb, &secret).is_err());
    }

    #[test]
    fn late_joiner_cannot_read_older_messages() {
        let (a, b) = (Device::generate().unwrap(), Device::generate().unwrap());
        let mut ga = a.create_group(GID, "Ordem").unwrap();
        let before = a.encrypt(&mut ga, b"antes da entrada").unwrap();

        let (_, welcome) = a.add_member(&mut ga, &b.key_package().unwrap(), &b.credential_hex()).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();
        let mut gb = b.join(&welcome).unwrap();

        assert!(b.process(&mut gb, &before).is_err(), "message from before joining must stay unreadable");
        let after = a.encrypt(&mut ga, b"depois").unwrap();
        assert_eq!(text(b.process(&mut gb, &after).unwrap()), b"depois");
    }

    #[test]
    fn out_of_order_commit_is_rejected() {
        let (a, b, c, d) = (
            Device::generate().unwrap(),
            Device::generate().unwrap(),
            Device::generate().unwrap(),
            Device::generate().unwrap(),
        );
        let (mut ga, mut joined) = setup(&a, &[&b]);
        let mut gb = joined.pop().unwrap();

        let (commit1, _) = a.add_member(&mut ga, &c.key_package().unwrap(), &c.credential_hex()).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();
        let (commit2, _) = a.add_member(&mut ga, &d.key_package().unwrap(), &d.credential_hex()).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();

        let before = epoch(&gb);
        assert!(b.process(&mut gb, &commit2).is_err(), "commit for a future epoch must be refused");
        assert_eq!(epoch(&gb), before);
        b.process(&mut gb, &commit1).unwrap();
        b.process(&mut gb, &commit2).unwrap();
        assert_eq!(epoch(&gb), epoch(&ga));
    }

    #[test]
    fn replayed_ciphertext_is_rejected() {
        let (a, b) = (Device::generate().unwrap(), Device::generate().unwrap());
        let (mut ga, mut joined) = setup(&a, &[&b]);
        let mut gb = joined.pop().unwrap();
        let ct = a.encrypt(&mut ga, b"uma vez").unwrap();
        b.process(&mut gb, &ct).unwrap();
        assert!(b.process(&mut gb, &ct).is_err());
    }

    #[test]
    fn key_package_for_another_identity_is_refused() {
        let (a, b, mallory) = (Device::generate().unwrap(), Device::generate().unwrap(), Device::generate().unwrap());
        let mut ga = a.create_group(GID, "Ordem").unwrap();
        let kp = mallory.key_package().unwrap();
        assert!(a.add_member(&mut ga, &kp, &b.credential_hex()).is_err());
    }

    #[test]
    fn state_survives_export_and_import() {
        let (a, b) = (Device::generate().unwrap(), Device::generate().unwrap());
        let (mut ga, mut joined) = setup(&a, &[&b]);
        let gb = joined.pop().unwrap();
        let gid = gb.group_id().as_slice().to_vec();
        let pk = b.public_key().to_vec();

        let b2 = Device::load(Provider::import(b.provider.export()), &pk).unwrap();
        let mut gb2 = b2.load_group(&gid).unwrap().unwrap();
        let ct = a.encrypt(&mut ga, b"persistido").unwrap();
        assert_eq!(text(b2.process(&mut gb2, &ct).unwrap()), b"persistido");
    }
}
