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
//!
//! Roles live in the group state too: a second GroupContext extension names
//! the owner and the admins. The GroupContext feeds the key schedule, so every
//! member provably has the same roles, and only a commit can change them.
//! Every client checks each incoming commit against the roles *before* it and
//! refuses to merge one its committer had no right to make (see
//! [`validate_commit`]). The server enforces the same rules; the clients don't
//! rely on it.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use std::collections::BTreeSet;

use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};

use crate::{Error, Result, Role};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
/// Private-use GroupContext extension carrying the UTF-8 group name.
const GROUP_NAME_EXTENSION: u16 = 0xff00;
/// Private-use GroupContext extension carrying [`Roles`] as JSON.
const ROLES_EXTENSION: u16 = 0xff01;
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

/// Who may do what, by credential (hex signature key). Everyone else in the
/// group is a plain member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roles {
    pub owner: String,
    pub admins: BTreeSet<String>,
}

impl Roles {
    pub fn role_of(&self, credential: &str) -> Role {
        if credential == self.owner {
            Role::Owner
        } else if self.admins.contains(credential) {
            Role::Admin
        } else {
            Role::Member
        }
    }
}

fn unknown_ext(ext: &Extensions<GroupContext>, id: u16) -> Option<Vec<u8>> {
    ext.unknown(id).map(|e| e.0.clone())
}

fn roles_in(ext: &Extensions<GroupContext>) -> Option<Roles> {
    serde_json::from_slice(&unknown_ext(ext, ROLES_EXTENSION)?).ok()
}

pub fn roles(group: &MlsGroup) -> Option<Roles> {
    roles_in(group.extensions())
}

fn context_extensions(name: Vec<u8>, roles: &Roles) -> Result<Extensions<GroupContext>> {
    // openmls only accepts private context extensions that every member is
    // required to support.
    let required = RequiredCapabilitiesExtension::new(
        &[ExtensionType::Unknown(GROUP_NAME_EXTENSION), ExtensionType::Unknown(ROLES_EXTENSION)],
        &[],
        &[CredentialType::Basic],
    );
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(required),
        Extension::Unknown(GROUP_NAME_EXTENSION, UnknownExtension(name)),
        Extension::Unknown(ROLES_EXTENSION, UnknownExtension(serde_json::to_vec(roles)?)),
    ])
    .map_err(|e| mls_err("extensions", e))
}

fn credential_at(group: &MlsGroup, index: LeafNodeIndex) -> Option<String> {
    group.members().find(|m| m.index == index).map(|m| hex::encode(&m.signature_key))
}

/// Checks a staged commit against the roles in force *before* it.
///
/// - Add: owner or admin.
/// - Remove: never the owner; an admin only by the owner; a member by any admin.
/// - Role changes: only the owner; an admin may also step down themselves.
///   Ownership and the group name never change.
/// - After the commit, everyone holding a role must still be in the group.
/// - Any other proposal type is refused (Hermes never sends them).
pub fn validate_commit(group: &MlsGroup, committer: &str, staged: &StagedCommit) -> std::result::Result<(), String> {
    let before = roles(group).ok_or("the group has no roles")?;
    let after = roles_in(staged.group_context().extensions()).ok_or("the commit drops the group's roles")?;
    let actor = before.role_of(committer);

    let mut members: BTreeSet<String> = group.members().map(|m| hex::encode(&m.signature_key)).collect();
    if !members.contains(committer) {
        return Err("the committer is not a member".into());
    }
    for queued in staged.queued_proposals() {
        match queued.proposal() {
            Proposal::Add(add) => {
                if !actor.is_admin() {
                    return Err(format!("a {} cannot add members", role_name(actor)));
                }
                members.insert(hex::encode(add.key_package().leaf_node().signature_key().as_slice()));
            }
            Proposal::Remove(remove) => {
                let target = credential_at(group, remove.removed()).ok_or("the commit removes an unknown leaf")?;
                match before.role_of(&target) {
                    Role::Owner => return Err("the owner cannot be removed".into()),
                    Role::Admin if actor != Role::Owner => return Err("only the owner can remove an admin".into()),
                    Role::Member if !actor.is_admin() => {
                        return Err(format!("a {} cannot remove members", role_name(actor)));
                    }
                    _ => {}
                }
                members.remove(&target);
            }
            // Judged by the resulting context below.
            Proposal::GroupContextExtensions(_) => {}
            _ => return Err("the commit contains a proposal type Hermes does not allow".into()),
        }
    }

    if unknown_ext(staged.group_context().extensions(), GROUP_NAME_EXTENSION)
        != unknown_ext(group.extensions(), GROUP_NAME_EXTENSION)
    {
        return Err("the group name cannot change".into());
    }
    if after.owner != before.owner {
        return Err("ownership cannot change".into());
    }
    if after.admins != before.admins {
        let mut stepped_down = before.admins.clone();
        stepped_down.remove(committer);
        let self_demotion = actor == Role::Admin && after.admins == stepped_down;
        if actor != Role::Owner && !self_demotion {
            return Err(format!("a {} cannot change roles", role_name(actor)));
        }
    }
    if !members.contains(&after.owner) || !after.admins.is_subset(&members) {
        return Err("the roles name someone who is not in the group".into());
    }
    Ok(())
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "plain member",
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
        Some(&[ExtensionType::Unknown(GROUP_NAME_EXTENSION), ExtensionType::Unknown(ROLES_EXTENSION)]),
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
        let roles = Roles { owner: self.credential_hex(), admins: BTreeSet::new() };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .capabilities(capabilities())
            .with_group_context_extensions(context_extensions(name.as_bytes().to_vec(), &roles)?)
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

    /// Stages a Remove commit for the member whose signature key is
    /// `credential`. Removing an admin also drops them from the roles, in the
    /// same commit.
    pub fn remove_member(&self, group: &mut MlsGroup, credential: &str) -> Result<Vec<u8>> {
        let index = group
            .members()
            .find(|m| hex::encode(&m.signature_key) == credential)
            .map(|m| m.index)
            .ok_or_else(|| Error::Mls("member is not in the MLS group".into()))?;
        let mut roles = roles(group).ok_or_else(|| Error::Mls("group has no roles".into()))?;
        let cleanup = if roles.admins.remove(credential) {
            let name = unknown_ext(group.extensions(), GROUP_NAME_EXTENSION).unwrap_or_default();
            Some(context_extensions(name, &roles)?)
        } else {
            None
        };
        let mut builder = group.commit_builder().propose_removals([index]);
        if let Some(ext) = cleanup {
            builder = builder.propose_group_context_extensions(ext).map_err(|e| mls_err("remove member", e))?;
        }
        self.stage(builder, "remove member")
    }

    /// Stages a commit that makes `credential` an admin or a plain member.
    pub fn set_role(&self, group: &mut MlsGroup, credential: &str, role: Role) -> Result<Vec<u8>> {
        let mut roles = roles(group).ok_or_else(|| Error::Mls("group has no roles".into()))?;
        match role {
            Role::Admin => roles.admins.insert(credential.to_owned()),
            Role::Member => roles.admins.remove(credential),
            Role::Owner => return Err(Error::Invalid("Ownership cannot be transferred.".into())),
        };
        let ext = context_extensions(unknown_ext(group.extensions(), GROUP_NAME_EXTENSION).unwrap_or_default(), &roles)?;
        let builder = group
            .commit_builder()
            .propose_group_context_extensions(ext)
            .map_err(|e| mls_err("set role", e))?;
        self.stage(builder, "set role")
    }

    fn stage(&self, builder: CommitBuilder<'_, openmls::group::Initial>, what: &str) -> Result<Vec<u8>> {
        let bundle = builder
            .load_psks(self.provider.storage())
            .map_err(|e| mls_err(what, e))?
            .build(self.provider.rand(), self.provider.crypto(), &self.signer, |_| true)
            .map_err(|e| mls_err(what, e))?
            .stage_commit(&self.provider)
            .map_err(|e| mls_err(what, e))?;
        serialize(&bundle.into_contents().0)
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
                // Not merged: the group stays at its current epoch.
                validate_commit(group, &sender, &staged).map_err(Error::InvalidChange)?;
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
        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(|e| mls_err("join", e))?;
        let adder = hex::encode(staged.welcome_sender().map_err(|e| mls_err("join", e))?.signature_key().as_slice());
        let mut group = staged.into_group(&self.provider).map_err(|e| mls_err("join", e))?;
        // Only an owner or admin may add people; refuse a Welcome from anyone else.
        let allowed = roles(&group).is_some_and(|r| r.role_of(&adder).is_admin());
        if !allowed {
            self.delete_group(&mut group)?;
            return Err(Error::InvalidChange("the invitation was not issued by an owner or admin".into()));
        }
        Ok(group)
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

    fn devices(n: usize) -> Vec<Device> {
        (0..n).map(|_| Device::generate().unwrap()).collect()
    }

    /// Commits made by an honest client and accepted by everyone listed.
    fn deliver(commit: &[u8], to: &mut [(&Device, &mut MlsGroup)]) {
        for (d, g) in to.iter_mut() {
            d.process(g, commit).unwrap();
        }
    }

    fn assert_refused(d: &Device, g: &mut MlsGroup, commit: &[u8], why: &str) {
        let before = epoch(g);
        let roles_before = roles(g);
        match d.process(g, commit) {
            Err(Error::InvalidChange(reason)) => assert!(reason.contains(why), "reason {reason:?} should mention {why:?}"),
            other => panic!("commit should be refused ({why}), got {other:?}"),
        }
        assert_eq!(epoch(g), before, "a refused commit must not advance the epoch");
        assert_eq!(roles(g), roles_before);
    }

    #[test]
    fn add_from_plain_member_is_refused_by_the_others() {
        let [a, b, c, d]: [Device; 4] = devices(4).try_into().ok().unwrap();
        let (mut ga, mut joined) = setup(&a, &[&b, &c]);
        let mut gc = joined.pop().unwrap();
        let mut gb = joined.pop().unwrap();

        // B runs a modified client that ignores its role.
        let (commit, _) = b.add_member(&mut gb, &d.key_package().unwrap(), &d.credential_hex()).unwrap();
        assert_refused(&a, &mut ga, &commit, "cannot add members");
        assert_refused(&c, &mut gc, &commit, "cannot add members");

        // The honest members are unaffected and keep talking in their epoch.
        let ct = a.encrypt(&mut ga, b"tudo certo").unwrap();
        assert_eq!(text(c.process(&mut gc, &ct).unwrap()), b"tudo certo");
    }

    #[test]
    fn joiner_refuses_a_welcome_from_a_plain_member() {
        let [a, b, d]: [Device; 3] = devices(3).try_into().ok().unwrap();
        let (_ga, mut joined) = setup(&a, &[&b]);
        let mut gb = joined.pop().unwrap();
        let (_, welcome) = b.add_member(&mut gb, &d.key_package().unwrap(), &d.credential_hex()).unwrap();
        assert!(matches!(d.join(&welcome), Err(Error::InvalidChange(_))));
    }

    #[test]
    fn promotion_by_an_admin_who_is_not_the_owner_is_refused() {
        let [a, b, c]: [Device; 3] = devices(3).try_into().ok().unwrap();
        let (mut ga, mut joined) = setup(&a, &[&b, &c]);
        let mut gc = joined.pop().unwrap();
        let mut gb = joined.pop().unwrap();

        // The owner promotes B: everyone accepts.
        let commit = a.set_role(&mut ga, &b.credential_hex(), Role::Admin).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();
        deliver(&commit, &mut [(&b, &mut gb), (&c, &mut gc)]);
        assert_eq!(roles(&gc).unwrap().role_of(&b.credential_hex()), Role::Admin);

        // B, an admin but not the owner, tries to promote C.
        let commit = b.set_role(&mut gb, &c.credential_hex(), Role::Admin).unwrap();
        assert_refused(&a, &mut ga, &commit, "cannot change roles");
        assert_refused(&c, &mut gc, &commit, "cannot change roles");
        assert_eq!(roles(&ga).unwrap().role_of(&c.credential_hex()), Role::Member);
    }

    #[test]
    fn plain_member_cannot_promote_themselves() {
        let [a, b]: [Device; 2] = devices(2).try_into().ok().unwrap();
        let (mut ga, mut joined) = setup(&a, &[&b]);
        let mut gb = joined.pop().unwrap();
        let commit = b.set_role(&mut gb, &b.credential_hex(), Role::Admin).unwrap();
        assert_refused(&a, &mut ga, &commit, "cannot change roles");
    }

    #[test]
    fn admins_add_and_remove_members() {
        let [a, b, c, d]: [Device; 4] = devices(4).try_into().ok().unwrap();
        let (mut ga, mut joined) = setup(&a, &[&b, &c]);
        let mut gc = joined.pop().unwrap();
        let mut gb = joined.pop().unwrap();
        let commit = a.set_role(&mut ga, &b.credential_hex(), Role::Admin).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();
        deliver(&commit, &mut [(&b, &mut gb), (&c, &mut gc)]);

        let (commit, welcome) = b.add_member(&mut gb, &d.key_package().unwrap(), &d.credential_hex()).unwrap();
        b.merge_pending_commit(&mut gb).unwrap();
        deliver(&commit, &mut [(&a, &mut ga), (&c, &mut gc)]);
        let mut gd = d.join(&welcome).unwrap();

        let commit = b.remove_member(&mut gb, &c.credential_hex()).unwrap();
        b.merge_pending_commit(&mut gb).unwrap();
        deliver(&commit, &mut [(&a, &mut ga), (&d, &mut gd)]);
        assert_eq!(ga.members().count(), 3);
    }

    #[test]
    fn nobody_removes_the_owner_and_only_the_owner_removes_admins() {
        let [a, b, c]: [Device; 3] = devices(3).try_into().ok().unwrap();
        let (mut ga, mut joined) = setup(&a, &[&b, &c]);
        let mut gc = joined.pop().unwrap();
        let mut gb = joined.pop().unwrap();
        for target in [&b, &c] {
            let commit = a.set_role(&mut ga, &target.credential_hex(), Role::Admin).unwrap();
            a.merge_pending_commit(&mut ga).unwrap();
            deliver(&commit, &mut [(&b, &mut gb), (&c, &mut gc)]);
        }

        let commit = b.remove_member(&mut gb, &a.credential_hex()).unwrap();
        b.clear_pending_commit(&mut gb).unwrap();
        assert_refused(&c, &mut gc, &commit, "owner cannot be removed");

        let commit = b.remove_member(&mut gb, &c.credential_hex()).unwrap();
        b.clear_pending_commit(&mut gb).unwrap();
        assert_refused(&a, &mut ga, &commit, "only the owner can remove an admin");

        // The owner can, and the removed admin leaves the roles in the same commit.
        let commit = a.remove_member(&mut ga, &b.credential_hex()).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();
        deliver(&commit, &mut [(&c, &mut gc)]);
        assert!(!roles(&gc).unwrap().admins.contains(&b.credential_hex()));
    }

    #[test]
    fn an_admin_may_step_down() {
        let [a, b]: [Device; 2] = devices(2).try_into().ok().unwrap();
        let (mut ga, mut joined) = setup(&a, &[&b]);
        let mut gb = joined.pop().unwrap();
        let commit = a.set_role(&mut ga, &b.credential_hex(), Role::Admin).unwrap();
        a.merge_pending_commit(&mut ga).unwrap();
        deliver(&commit, &mut [(&b, &mut gb)]);

        let commit = b.set_role(&mut gb, &b.credential_hex(), Role::Member).unwrap();
        b.merge_pending_commit(&mut gb).unwrap();
        deliver(&commit, &mut [(&a, &mut ga)]);
        assert_eq!(roles(&ga).unwrap().role_of(&b.credential_hex()), Role::Member);
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
