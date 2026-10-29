//! Hermes core: MLS (RFC 9420) group chat that uses Supabase only as an
//! untrusted, ordering relay for ciphertext.
//!
//! Flow in short:
//! - The owner creates an MLS group locally and registers its id.
//! - An admin generates a 5-minute, single-use invite code (random, no key
//!   material). The server keeps only its hash.
//! - A joiner trades the code for a join request carrying a KeyPackage. Any
//!   online admin's app then commits an Add and posts the Welcome; the joiner
//!   enters at that epoch and can't read anything older.
//! - Removing a member commits an MLS Remove, so they can't read anything new.
//! - The server accepts a commit only for the group's current epoch, which
//!   totally orders commits; clients process server rows in id order.

pub mod mls;
pub mod realtime;
mod store;
pub mod supabase;
pub mod vault;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use openmls::group::MlsGroup;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use uuid::Uuid;

use crate::mls::{Device, Incoming, Provider, epoch};
use crate::realtime::RealtimeEvent;
use crate::store::{GroupState, PendingJoin, State};
use crate::supabase::{JoinRequestRow, MessageRow, Session, Supabase, SupabaseConfig};
pub use crate::vault::{KeyVault, MemoryVault, SystemKeyring};

pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_MESSAGE_CHARS: usize = 8_000;
/// Invites live 5 minutes on the server; the joiner waits a little longer for clock skew.
const JOIN_WAIT_MS: i64 = 5 * 60 * 1000 + 30_000;
/// Fallback sync for anything Realtime missed (and for noticing removals).
const SYNC_INTERVAL: Duration = Duration::from_secs(15);
const PAGE: u32 = 200;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("That invite code is invalid, already used, or expired.")]
    InvalidInvite,
    #[error("malformed data: {0}")]
    Malformed(String),
    #[error("Supabase is not configured: set HERMES_SUPABASE_URL and HERMES_SUPABASE_ANON_KEY")]
    NotConfigured,
    #[error("{0}")]
    Invalid(String),
    #[error("unknown group")]
    UnknownGroup,
    #[error("MLS: {0}")]
    Mls(String),
    #[error("This group received an invalid change and was frozen: {0}")]
    InvalidChange(String),
    #[error("secure storage: {0}")]
    Keystore(String),
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{message}")]
    Api { status: u16, message: String },
    #[error("realtime: {0}")]
    Realtime(String),
    #[error("storage error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    fn is_epoch_conflict(&self) -> bool {
        matches!(self, Error::Api { status: 409, message } if message.contains("epoch"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

/// Short human-comparable fingerprint of a credential, e.g. `3f9a-c1d0-77be-0442`.
pub fn fingerprint(credential_hex: &str) -> String {
    let hex = hex::encode(&blake3::hash(credential_hex.as_bytes()).as_bytes()[..8]);
    hex.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

// ---- invite codes -------------------------------------------------------------

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 16 Crockford base32 characters = 80 random bits. Carries no key material.
pub fn generate_invite_code() -> String {
    let bytes = random_bytes::<10>();
    let mut bits = 0u32;
    let mut acc = 0u32;
    let mut out = String::with_capacity(16);
    for b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 31) as usize] as char);
        }
    }
    out
}

/// Accepts what people type: any case, dashes or spaces, and the usual
/// Crockford look-alikes (O for 0, I/L for 1).
pub fn normalize_invite_code(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    (code.len() == 16 && code.bytes().all(|b| CROCKFORD.contains(&b))).then_some(code)
}

pub fn format_invite_code(code: &str) -> String {
    code.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

// ---- public types ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    pub fn is_admin(self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    pub display_name: String,
    pub fingerprint: String,
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupInfo {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    pub removed: bool,
    /// Why the group was frozen after receiving an invalid change, if it was.
    pub halted: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Invite {
    pub code: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemberInfo {
    pub user_id: Uuid,
    pub role: Role,
    pub name: Option<String>,
    pub fingerprint: String,
    pub me: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Random id chosen by the sender, inside the ciphertext; used to dedupe.
    pub id: String,
    pub group_id: Uuid,
    pub sender_name: String,
    pub sender_credential: String,
    pub sender_fingerprint: String,
    pub mine: bool,
    pub text: String,
    pub sent_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HermesEvent {
    Message { message: ChatMessage },
    /// Groups were joined, removed, or changed role; reload the list.
    GroupsChanged,
    JoinFailed { reason: String },
    /// A commit broke the group's rules (e.g. a plain member adding someone).
    /// It was not applied; the group is frozen at its last valid epoch.
    InvalidChange { group_id: Uuid, reason: String },
    Online,
    Offline { reason: String },
}

/// Plaintext of an application message.
#[derive(Serialize, Deserialize)]
struct Body {
    v: u8,
    id: String,
    name: String,
    text: String,
    sent_at: i64,
}

struct Inner {
    state: State,
    device: Device,
}

impl Inner {
    fn group_mut(&mut self, id: Uuid) -> Result<&mut GroupState> {
        self.state.groups.iter_mut().find(|g| g.id == id).ok_or(Error::UnknownGroup)
    }

    fn load_group(&self, id: Uuid) -> Result<MlsGroup> {
        self.device.load_group(id.as_bytes())?.ok_or(Error::UnknownGroup)
    }

    fn my_user_id(&self) -> Option<Uuid> {
        self.state.session.as_ref().map(|s| s.user_id)
    }
}

pub struct Hermes {
    path: PathBuf,
    key: [u8; 32],
    sb: Option<Supabase>,
    /// One lock for state, MLS and the session: MLS operations on a group
    /// must never interleave.
    inner: AsyncMutex<Inner>,
}

impl Hermes {
    /// Opens (or creates) the encrypted profile in `data_dir`. The state key is
    /// fetched from (or created in) `vault`.
    pub fn open(data_dir: PathBuf, cfg: Option<SupabaseConfig>, vault: &dyn KeyVault) -> Result<Arc<Self>> {
        // v0.1 kept its keys in a plaintext file; they are useless under MLS.
        let legacy = data_dir.join("hermes.json");
        if legacy.exists() {
            std::fs::remove_file(legacy)?;
        }

        let path = data_dir.join("state.hermes");
        let key = vault::master_key(vault, path.exists())?;
        let (state, device) = match store::load(&path, &key)? {
            Some(state) => {
                let provider = Provider::import(store::decode_mls(&state.mls));
                let public = hex::decode(&state.identity).map_err(|_| Error::Malformed("identity".into()))?;
                let device = Device::load(provider, &public)?;
                (state, device)
            }
            None => {
                let device = Device::generate()?;
                let state = State {
                    version: 2,
                    identity: device.credential_hex(),
                    device_secret: hex::encode(random_bytes::<32>()),
                    display_name: String::new(),
                    session: None,
                    groups: Vec::new(),
                    pending_joins: Vec::new(),
                    mls: Vec::new(),
                };
                (state, device)
            }
        };
        let hermes = Self { path, key, sb: cfg.map(Supabase::new), inner: AsyncMutex::new(Inner { state, device }) };
        hermes.save(&mut hermes.inner.try_lock().expect("fresh lock"))?;
        Ok(Arc::new(hermes))
    }

    fn sb(&self) -> Result<&Supabase> {
        self.sb.as_ref().ok_or(Error::NotConfigured)
    }

    fn save(&self, inner: &mut Inner) -> Result<()> {
        inner.state.mls = store::encode_mls(inner.device.provider.export());
        store::save(&self.path, &self.key, &inner.state)
    }

    // ---- session ----------------------------------------------------------------

    pub async fn access_token(&self) -> Result<String> {
        let mut inner = self.inner.lock().await;
        self.token(&mut inner).await
    }

    async fn token(&self, inner: &mut Inner) -> Result<String> {
        let sb = self.sb()?;
        let session = match inner.state.session.clone() {
            Some(s) if !s.needs_refresh() => return Ok(s.access_token),
            Some(s) => match sb.refresh(&s).await {
                Ok(fresh) => fresh,
                // Refresh token rejected (expired or revoked): the anonymous
                // user is gone, so start a new one and reclaim the device.
                Err(Error::Api { status: 400..=499, .. }) => self.new_user(sb, inner).await?,
                Err(e) => return Err(e),
            },
            None => self.new_user(sb, inner).await?,
        };
        let token = session.access_token.clone();
        inner.state.session = Some(session);
        self.save(inner)?;
        Ok(token)
    }

    /// Signs in as a fresh anonymous user and claims this device: the server
    /// moves the old user's memberships and pending requests here and deletes
    /// the abandoned user, so the group never shows a ghost member.
    async fn new_user(&self, sb: &Supabase, inner: &Inner) -> Result<Session> {
        let session = sb.sign_in_anonymously().await?;
        sb.claim_device(&session.access_token, &inner.state.device_secret).await?;
        Ok(session)
    }

    // ---- profile and groups -----------------------------------------------------

    pub async fn profile(&self) -> Profile {
        let inner = self.inner.lock().await;
        Profile {
            display_name: inner.state.display_name.clone(),
            fingerprint: fingerprint(&inner.state.identity),
            configured: self.sb.is_some(),
        }
    }

    pub async fn set_display_name(&self, name: &str) -> Result<Profile> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
            return Err(Error::Invalid(format!("Name must be 1–{MAX_NAME_CHARS} characters.")));
        }
        {
            let mut inner = self.inner.lock().await;
            inner.state.display_name = name.to_owned();
            self.save(&mut inner)?;
        }
        Ok(self.profile().await)
    }

    pub async fn groups(&self) -> Vec<GroupInfo> {
        let inner = self.inner.lock().await;
        inner.state.groups.iter().map(group_info).collect()
    }

    pub async fn messages(&self, group_id: Uuid) -> Result<Vec<ChatMessage>> {
        let mut inner = self.inner.lock().await;
        Ok(inner.group_mut(group_id)?.messages.clone())
    }

    pub async fn create_group(&self, name: &str) -> Result<GroupInfo> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
            return Err(Error::Invalid(format!("Group name must be 1–{MAX_NAME_CHARS} characters.")));
        }
        let mut inner = self.inner.lock().await;
        let token = self.token(&mut inner).await?;
        let id = Uuid::new_v4();
        let mut group = inner.device.create_group(id.as_bytes(), name)?;
        if let Err(e) = self.sb()?.create_group(&token, id, &inner.device.credential_hex()).await {
            inner.device.delete_group(&mut group)?;
            return Err(e);
        }
        let gs = GroupState {
            id,
            name: name.to_owned(),
            role: Role::Owner,
            last_id: 0,
            removed: false,
            halted: None,
            messages: Vec::new(),
            names: Default::default(),
        };
        let info = group_info(&gs);
        inner.state.groups.push(gs);
        self.save(&mut inner)?;
        Ok(info)
    }

    /// Admins only. The code is valid for 5 minutes and a single use.
    pub async fn create_invite(&self, group_id: Uuid) -> Result<Invite> {
        let mut inner = self.inner.lock().await;
        if !inner.group_mut(group_id)?.role.is_admin() {
            return Err(Error::Invalid("Only group admins can create invite codes.".into()));
        }
        let token = self.token(&mut inner).await?;
        let code = generate_invite_code();
        let expires_at = self.sb()?.create_invite(&token, group_id, &code).await?;
        Ok(Invite { code: format_invite_code(&code), expires_at })
    }

    /// Files a join request. Returns the group id; the group appears (with a
    /// `GroupsChanged` event) once an online admin accepts it.
    pub async fn join(&self, code: &str) -> Result<Uuid> {
        let code = normalize_invite_code(code).ok_or(Error::InvalidInvite)?;
        let mut inner = self.inner.lock().await;
        let token = self.token(&mut inner).await?;
        let key_package = B64.encode(inner.device.key_package()?);
        let reply = self
            .sb()?
            .request_join(&token, &code, &inner.device.credential_hex(), &key_package)
            .await?;
        // The KeyPackage's private keys were just stored; keep them.
        self.save(&mut inner)?;
        match (reply.status.as_str(), reply.request_id, reply.group_id) {
            ("ok", Some(request_id), Some(group_id)) => {
                inner.state.pending_joins.push(PendingJoin { request_id, group_id, deadline: now_ms() + JOIN_WAIT_MS });
                self.save(&mut inner)?;
                Ok(group_id)
            }
            ("already_member", ..) => Err(Error::Invalid("You are already in this group.".into())),
            _ => Err(Error::InvalidInvite),
        }
    }

    pub async fn pending_joins(&self) -> Vec<Uuid> {
        self.inner.lock().await.state.pending_joins.iter().map(|p| p.group_id).collect()
    }

    pub async fn members(&self, group_id: Uuid) -> Result<Vec<MemberInfo>> {
        let mut inner = self.inner.lock().await;
        let token = self.token(&mut inner).await?;
        let rows = self.sb()?.members(&token, group_id).await?;
        let mine = inner.device.credential_hex();
        let my_name = inner.state.display_name.clone();
        // Roles come from the MLS group state, which every member agreed on.
        let roles = mls::roles(&inner.load_group(group_id)?);
        let gs = inner.group_mut(group_id)?;
        Ok(rows
            .into_iter()
            .map(|r| MemberInfo {
                user_id: r.user_id,
                role: roles.as_ref().map_or(Role::Member, |x| x.role_of(&r.credential)),
                me: r.credential == mine,
                name: if r.credential == mine { Some(my_name.clone()) } else { gs.names.get(&r.credential).cloned() },
                fingerprint: fingerprint(&r.credential),
            })
            .collect())
    }

    /// Only the owner promotes or demotes; an admin may also step down. The
    /// change is an MLS commit, so every client checks who made it.
    pub async fn set_role(&self, group_id: Uuid, user_id: Uuid, role: Role) -> Result<()> {
        let mut inner = self.inner.lock().await;
        self.set_role_locked(&mut inner, group_id, user_id, role).await
    }

    async fn set_role_locked(&self, inner: &mut Inner, group_id: Uuid, user_id: Uuid, role: Role) -> Result<()> {
        let token = self.token(inner).await?;
        let sb = self.sb()?;
        let target = sb
            .members(&token, group_id)
            .await?
            .into_iter()
            .find(|m| m.user_id == user_id)
            .ok_or_else(|| Error::Invalid("That person is not in the group.".into()))?;
        let mut events = Vec::new();
        for attempt in 0..2 {
            self.sync_group(inner, &token, group_id, &mut events).await?;
            let mut group = inner.load_group(group_id)?;
            let commit = inner.device.set_role(&mut group, &target.credential, role)?;
            match sb.set_role(&token, group_id, user_id, role, epoch(&group), &B64.encode(commit)).await {
                Ok(_) => {
                    inner.device.merge_pending_commit(&mut group)?;
                    self.refresh_role(inner, group_id, &group)?;
                    break;
                }
                Err(e) if e.is_epoch_conflict() && attempt == 0 => inner.device.clear_pending_commit(&mut group)?,
                Err(e @ Error::Api { .. }) => {
                    inner.device.clear_pending_commit(&mut group)?;
                    self.save(inner)?;
                    return Err(e);
                }
                Err(e) => {
                    self.save(inner)?;
                    return Err(e);
                }
            }
        }
        self.save(inner)
    }

    /// Commits an MLS Remove: the removed member can't decrypt anything sent
    /// afterwards, and the server stops serving them the group.
    pub async fn remove_member(&self, group_id: Uuid, user_id: Uuid) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let token = self.token(&mut inner).await?;
        let sb = self.sb()?;
        let target = sb
            .members(&token, group_id)
            .await?
            .into_iter()
            .find(|m| m.user_id == user_id)
            .ok_or_else(|| Error::Invalid("That person is not in the group.".into()))?;

        let mut events = Vec::new();
        for attempt in 0..2 {
            self.sync_group(&mut inner, &token, group_id, &mut events).await?;
            let mut group = inner.load_group(group_id)?;
            let commit = inner.device.remove_member(&mut group, &target.credential)?;
            match sb.remove_member(&token, group_id, user_id, epoch(&group), &B64.encode(commit)).await {
                Ok(_) => {
                    inner.device.merge_pending_commit(&mut group)?;
                    break;
                }
                Err(e) if e.is_epoch_conflict() && attempt == 0 => inner.device.clear_pending_commit(&mut group)?,
                Err(e @ Error::Api { .. }) => {
                    inner.device.clear_pending_commit(&mut group)?;
                    self.save(&mut inner)?;
                    return Err(e);
                }
                Err(e) => {
                    // Unknown outcome: keep the pending commit; the next sync
                    // merges or drops it depending on what the server stored.
                    self.save(&mut inner)?;
                    return Err(e);
                }
            }
        }
        self.save(&mut inner)
    }

    /// Leaves right away (the server stops serving the group); an admin's app
    /// then commits the MLS removal. The owner can only leave an empty group.
    pub async fn leave_group(&self, group_id: Uuid) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let (removed, role, halted) = {
            let g = inner.group_mut(group_id)?;
            (g.removed, g.role, g.halted.is_some())
        };
        if !removed {
            // Only the owner may remove an admin, so an admin first steps down
            // (a commit every client accepts); any admin can then remove them.
            if role == Role::Admin && !halted {
                let me = inner.my_user_id().ok_or_else(|| Error::Invalid("Not signed in.".into()))?;
                self.set_role_locked(&mut inner, group_id, me, Role::Member).await?;
            }
            let token = self.token(&mut inner).await?;
            match self.sb()?.leave_group(&token, group_id).await {
                Ok(()) | Err(Error::Api { status: 404, .. }) => {}
                Err(e) => return Err(e),
            }
        }
        self.forget(&mut inner, group_id)?;
        self.save(&mut inner)
    }

    fn forget(&self, inner: &mut Inner, group_id: Uuid) -> Result<()> {
        if let Some(mut group) = inner.device.load_group(group_id.as_bytes())? {
            inner.device.delete_group(&mut group)?;
        }
        inner.state.groups.retain(|g| g.id != group_id);
        Ok(())
    }

    // ---- messages ---------------------------------------------------------------

    pub async fn send(&self, group_id: Uuid, text: &str) -> Result<ChatMessage> {
        self.send_with_id(group_id, &hex::encode(random_bytes::<16>()), text).await
    }

    /// Like [`Hermes::send`] with a caller-chosen id. Retrying a send whose
    /// outcome is unknown with the same id never shows the message twice:
    /// every client drops bodies whose id it already has.
    pub async fn send_with_id(&self, group_id: Uuid, id: &str, text: &str) -> Result<ChatMessage> {
        let text = text.trim();
        if text.is_empty() {
            return Err(Error::Invalid("Message is empty.".into()));
        }
        if text.chars().count() > MAX_MESSAGE_CHARS {
            return Err(Error::Invalid(format!("Messages are limited to {MAX_MESSAGE_CHARS} characters.")));
        }
        if id.is_empty() || id.len() > 64 {
            return Err(Error::Invalid("Bad message id.".into()));
        }
        let mut inner = self.inner.lock().await;
        let g = inner.group_mut(group_id)?;
        if g.removed {
            return Err(Error::Invalid("You are no longer in this group.".into()));
        }
        if let Some(reason) = &g.halted {
            return Err(Error::InvalidChange(reason.clone()));
        }
        let token = self.token(&mut inner).await?;
        let body = Body {
            v: 1,
            id: id.to_owned(),
            name: inner.state.display_name.clone(),
            text: text.to_owned(),
            sent_at: now_ms(),
        };
        let plaintext = serde_json::to_vec(&body)?;
        let mut events = Vec::new();

        for attempt in 0..2 {
            if attempt == 1 {
                self.sync_group(&mut inner, &token, group_id, &mut events).await?;
            }
            let mut group = inner.load_group(group_id)?;
            let payload = inner.device.encrypt(&mut group, &plaintext)?;
            match self.sb()?.post_message(&token, group_id, epoch(&group), &B64.encode(payload)).await {
                Ok(_) => {
                    let msg = ChatMessage {
                        id: body.id.clone(),
                        group_id,
                        sender_name: body.name.clone(),
                        sender_credential: inner.device.credential_hex(),
                        sender_fingerprint: fingerprint(&inner.device.credential_hex()),
                        mine: true,
                        text: body.text.clone(),
                        sent_at: body.sent_at,
                    };
                    inner.group_mut(group_id)?.push_message(msg.clone());
                    self.save(&mut inner)?;
                    return Ok(msg);
                }
                Err(e) if e.is_epoch_conflict() && attempt == 0 => continue,
                Err(e) => {
                    // The sending ratchet advanced either way; persist it.
                    self.save(&mut inner)?;
                    return Err(e);
                }
            }
        }
        unreachable!("the loop returns on its second attempt")
    }

    // ---- sync -------------------------------------------------------------------

    /// Brings everything up to date: finishes joins, notices removals and role
    /// changes, applies new commits and messages in server order, and, for
    /// groups this user administers, accepts pending join requests and commits
    /// removals for members who left.
    pub async fn sync(&self) -> Result<Vec<HermesEvent>> {
        let mut inner = self.inner.lock().await;
        let token = self.token(&mut inner).await?;
        let mut events = Vec::new();

        self.finish_joins(&mut inner, &token, &mut events).await?;
        self.refresh_memberships(&mut inner, &token, &mut events).await?;
        let active: Vec<Uuid> = inner.state.groups.iter().filter(|g| !g.removed && g.halted.is_none()).map(|g| g.id).collect();
        for gid in &active {
            if let Err(e) = self.sync_group(&mut inner, &token, *gid, &mut events).await {
                tracing::warn!("sync of group {gid} failed: {e}");
            }
        }
        self.admin_duties(&mut inner, &token, &mut events).await?;
        self.save(&mut inner)?;
        Ok(events)
    }

    async fn finish_joins(&self, inner: &mut Inner, token: &str, events: &mut Vec<HermesEvent>) -> Result<()> {
        let sb = self.sb()?;
        for pj in inner.state.pending_joins.clone() {
            let row = sb.join_request(token, pj.request_id).await?;
            let outcome = match row {
                Some(JoinRequestRow { status, welcome: Some(welcome), .. }) if status == "accepted" => {
                    let welcome = B64.decode(welcome).map_err(|_| Error::Malformed("welcome".into()))?;
                    match inner.device.join(&welcome) {
                        Ok(group) => {
                            inner.state.groups.retain(|g| g.id != pj.group_id);
                            inner.state.groups.push(GroupState {
                                id: pj.group_id,
                                name: mls::group_name(&group),
                                role: Role::Member,
                                last_id: 0,
                                removed: false,
                                halted: None,
                                messages: Vec::new(),
                                names: Default::default(),
                            });
                            events.push(HermesEvent::GroupsChanged);
                            None
                        }
                        Err(Error::InvalidChange(reason)) => Some(format!("The invitation was refused: {reason}.")),
                        Err(e) => Some(format!("The invitation could not be opened: {e}")),
                    }
                }
                Some(_) if now_ms() < pj.deadline => continue,
                Some(_) => Some("No admin accepted the request before the invite code expired.".to_owned()),
                None => Some("The join request no longer exists.".to_owned()),
            };
            inner.state.pending_joins.retain(|p| p.request_id != pj.request_id);
            if let Some(reason) = outcome {
                events.push(HermesEvent::JoinFailed { reason });
            }
        }
        Ok(())
    }

    /// Detects removal (the server stops showing the membership the moment an
    /// admin's Remove commit is accepted). Roles are not taken from the server:
    /// they come from the MLS group state, see [`Hermes::refresh_role`].
    async fn refresh_memberships(&self, inner: &mut Inner, token: &str, events: &mut Vec<HermesEvent>) -> Result<()> {
        let Some(user_id) = inner.my_user_id() else { return Ok(()) };
        let rows = self.sb()?.my_memberships(token, user_id).await?;
        let mut removed = Vec::new();
        let mut changed = false;
        for g in inner.state.groups.iter_mut().filter(|g| !g.removed) {
            if !rows.iter().any(|r| r.group_id == g.id) {
                removed.push(g.id);
            }
        }
        for gid in removed {
            self.mark_removed(inner, gid)?;
            changed = true;
        }
        if changed {
            events.push(HermesEvent::GroupsChanged);
        }
        Ok(())
    }

    /// Keeps the conversation but drops the MLS secrets: nothing new could be
    /// decrypted with them anyway.
    fn mark_removed(&self, inner: &mut Inner, group_id: Uuid) -> Result<()> {
        if let Some(mut group) = inner.device.load_group(group_id.as_bytes())? {
            inner.device.delete_group(&mut group)?;
        }
        inner.group_mut(group_id)?.removed = true;
        Ok(())
    }

    /// Takes this device's role from the MLS group state.
    fn refresh_role(&self, inner: &mut Inner, group_id: Uuid, group: &MlsGroup) -> Result<bool> {
        let role = mls::roles(group).map_or(Role::Member, |r| r.role_of(&inner.device.credential_hex()));
        let g = inner.group_mut(group_id)?;
        let changed = g.role != role;
        g.role = role;
        Ok(changed)
    }

    /// Settles a commit whose server outcome was unknown (network error).
    async fn reconcile_pending(&self, inner: &mut Inner, token: &str, group_id: Uuid, group: &mut MlsGroup) -> Result<()> {
        if !Device::has_pending_commit(group) {
            return Ok(());
        }
        let stored = self.sb()?.commit_at(token, group_id, epoch(group)).await?;
        if stored.is_some_and(|row| row.sender_credential == inner.device.credential_hex()) {
            inner.device.merge_pending_commit(group)
        } else {
            inner.device.clear_pending_commit(group)
        }
    }

    async fn sync_group(&self, inner: &mut Inner, token: &str, group_id: Uuid, events: &mut Vec<HermesEvent>) -> Result<()> {
        let sb = self.sb()?;
        if let Some(reason) = inner.group_mut(group_id)?.halted.clone() {
            return Err(Error::InvalidChange(reason));
        }
        let mut group = inner.load_group(group_id)?;
        self.reconcile_pending(inner, token, group_id, &mut group).await?;
        let result = async {
            loop {
                let after = inner.group_mut(group_id)?.last_id;
                let rows = sb.messages_after(token, group_id, after, PAGE).await?;
                if rows.is_empty() {
                    return Ok(());
                }
                for row in &rows {
                    if !self.apply_row(inner, group_id, &mut group, row, events)? {
                        return Ok(());
                    }
                    inner.group_mut(group_id)?.last_id = row.id;
                }
            }
        }
        .await;
        let still_member = !inner.group_mut(group_id)?.removed;
        if still_member && self.refresh_role(inner, group_id, &group)? {
            events.push(HermesEvent::GroupsChanged);
        }
        result
    }

    /// Returns false when processing must stop (removed, or a gap in epochs).
    fn apply_row(
        &self,
        inner: &mut Inner,
        group_id: Uuid,
        group: &mut MlsGroup,
        row: &MessageRow,
        events: &mut Vec<HermesEvent>,
    ) -> Result<bool> {
        let mine = inner.device.credential_hex();
        // Our own commits were merged when the server accepted them, and MLS
        // never lets a sender decrypt its own application messages.
        if row.sender_credential == mine {
            return Ok(true);
        }
        let Ok(bytes) = B64.decode(&row.payload) else {
            tracing::warn!("skipping undecodable row {}", row.id);
            return Ok(true);
        };
        if row.kind == "commit" {
            if row.epoch < epoch(group) {
                return Ok(true);
            }
            if row.epoch > epoch(group) {
                tracing::error!("group {group_id}: commit for epoch {} while at {}", row.epoch, epoch(group));
                return Ok(false);
            }
        }
        match inner.device.process(group, &bytes) {
            Ok(Incoming::Commit { removed_me: true }) => {
                self.mark_removed(inner, group_id)?;
                events.push(HermesEvent::GroupsChanged);
                Ok(false)
            }
            Ok(Incoming::Commit { .. } | Incoming::Ignored) => Ok(true),
            Err(Error::InvalidChange(reason)) => {
                // Not merged: the epoch stays where it was. Everything after
                // this commit builds on it, so the group can't safely go on.
                tracing::error!("group {group_id}: refused commit in row {}: {reason}", row.id);
                inner.group_mut(group_id)?.halted = Some(reason.clone());
                events.push(HermesEvent::InvalidChange { group_id, reason });
                events.push(HermesEvent::GroupsChanged);
                Ok(false)
            }
            Ok(Incoming::Application { sender, data }) => {
                if sender != row.sender_credential {
                    tracing::warn!("row {}: MLS sender differs from the server's record; dropped", row.id);
                    return Ok(true);
                }
                let Ok(body) = serde_json::from_slice::<Body>(&data) else {
                    tracing::warn!("row {}: unreadable message body", row.id);
                    return Ok(true);
                };
                let msg = ChatMessage {
                    id: body.id,
                    group_id,
                    sender_name: body.name,
                    sender_fingerprint: fingerprint(&sender),
                    sender_credential: sender,
                    mine: false,
                    text: body.text,
                    sent_at: body.sent_at,
                };
                if inner.group_mut(group_id)?.push_message(msg.clone()) {
                    events.push(HermesEvent::Message { message: msg });
                }
                Ok(true)
            }
            Err(e) => {
                tracing::warn!("row {} in {group_id} could not be processed: {e}", row.id);
                Ok(true)
            }
        }
    }

    async fn admin_duties(&self, inner: &mut Inner, token: &str, events: &mut Vec<HermesEvent>) -> Result<()> {
        let admin_groups: Vec<Uuid> = inner
            .state
            .groups
            .iter()
            .filter(|g| !g.removed && g.halted.is_none() && g.role.is_admin())
            .map(|g| g.id)
            .collect();
        if admin_groups.is_empty() {
            return Ok(());
        }
        let sb = self.sb()?;
        let me = inner.my_user_id();
        for req in sb.pending_requests(token).await? {
            if admin_groups.contains(&req.group_id)
                && Some(req.requester_id) != me
                && let Err(e) = self.accept(inner, token, &req, events).await
            {
                tracing::warn!("could not accept join request {}: {e}", req.id);
            }
        }
        for dep in sb.departures(token).await? {
            if !admin_groups.contains(&dep.group_id) {
                continue;
            }
            let result: Result<()> = async {
                for attempt in 0..2 {
                    self.sync_group(inner, token, dep.group_id, events).await?;
                    let mut group = inner.load_group(dep.group_id)?;
                    let roles = mls::roles(&group).ok_or_else(|| Error::Mls("group has no roles".into()))?;
                    if roles.role_of(&dep.credential) == Role::Admin && roles.role_of(&inner.device.credential_hex()) != Role::Owner {
                        return Ok(()); // only the owner may remove an admin
                    }
                    let commit = inner.device.remove_member(&mut group, &dep.credential)?;
                    match sb.complete_departure(token, dep.id, epoch(&group), &B64.encode(commit)).await {
                        Ok(_) => return inner.device.merge_pending_commit(&mut group),
                        Err(e) if e.is_epoch_conflict() && attempt == 0 => inner.device.clear_pending_commit(&mut group)?,
                        Err(e @ Error::Api { .. }) => {
                            inner.device.clear_pending_commit(&mut group)?;
                            return Err(e);
                        }
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            }
            .await;
            if let Err(e) = result {
                tracing::warn!("could not commit departure {}: {e}", dep.id);
            }
        }
        Ok(())
    }

    /// Adds the requester with an MLS commit and hands them the Welcome.
    async fn accept(&self, inner: &mut Inner, token: &str, req: &JoinRequestRow, events: &mut Vec<HermesEvent>) -> Result<()> {
        let sb = self.sb()?;
        let key_package = B64.decode(&req.key_package).map_err(|_| Error::Malformed("key package".into()))?;
        for attempt in 0..2 {
            self.sync_group(inner, token, req.group_id, events).await?;
            let mut group = inner.load_group(req.group_id)?;
            let (commit, welcome) = inner.device.add_member(&mut group, &key_package, &req.credential)?;
            match sb
                .add_member(token, req.id, epoch(&group), &B64.encode(commit), &B64.encode(welcome))
                .await
            {
                Ok(_) => return inner.device.merge_pending_commit(&mut group),
                Err(e) if e.is_epoch_conflict() && attempt == 0 => inner.device.clear_pending_commit(&mut group)?,
                Err(e @ Error::Api { .. }) => {
                    // Already handled by another admin, or expired.
                    inner.device.clear_pending_commit(&mut group)?;
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Streams events until `on_event` returns `false`. Realtime notifications
    /// trigger a sync; a periodic sync covers anything Realtime missed.
    pub async fn run(self: Arc<Self>, mut on_event: impl FnMut(HermesEvent) -> bool) -> Result<()> {
        let ws_url = self.sb()?.config().realtime_url();
        let (tx, mut rx) = mpsc::channel(64);
        let me = self.clone();
        let task = tokio::spawn(realtime::run(
            ws_url,
            move || {
                let me = me.clone();
                async move { me.access_token().await }
            },
            tx,
        ));
        let mut tick = tokio::time::interval(SYNC_INTERVAL);

        loop {
            let mut out = Vec::new();
            let first = tokio::select! {
                ev = rx.recv() => match ev {
                    Some(ev) => Some(ev),
                    None => break,
                },
                _ = tick.tick() => None,
            };
            let mut needs_sync = first.is_none();
            // Coalesce a burst of notifications into one sync.
            for ev in first.into_iter().chain(std::iter::from_fn(|| rx.try_recv().ok())) {
                match ev {
                    RealtimeEvent::Connected => {
                        out.push(HermesEvent::Online);
                        needs_sync = true;
                    }
                    RealtimeEvent::Changed => needs_sync = true,
                    RealtimeEvent::Disconnected(reason) => out.push(HermesEvent::Offline { reason }),
                }
            }
            if needs_sync {
                match self.sync().await {
                    Ok(events) => out.extend(events),
                    Err(e) => tracing::warn!("sync failed: {e}"),
                }
            }
            for e in out {
                if !on_event(e) {
                    task.abort();
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Test support: tries to decrypt a raw server payload with this device's
    /// current MLS state for `group_id`. Not used by the app.
    #[doc(hidden)]
    pub async fn try_decrypt_payload(&self, group_id: Uuid, payload_b64: &str) -> Result<Vec<u8>> {
        let inner = self.inner.lock().await;
        let mut group = inner.load_group(group_id)?;
        let bytes = B64.decode(payload_b64).map_err(|_| Error::Malformed("payload".into()))?;
        match inner.device.process(&mut group, &bytes)? {
            Incoming::Application { data, .. } => Ok(data),
            other => Err(Error::Mls(format!("not an application message: {other:?}"))),
        }
    }

    /// Test support: acts as a *modified* client that accepts a join request
    /// whatever its role in the group. Honest clients never do this.
    #[doc(hidden)]
    pub async fn force_accept_join(&self, req: &JoinRequestRow) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let token = self.token(&mut inner).await?;
        let mut events = Vec::new();
        self.accept(&mut inner, &token, req, &mut events).await?;
        self.save(&mut inner)
    }

    /// Test support: this device's MLS epoch for the group.
    #[doc(hidden)]
    pub async fn epoch(&self, group_id: Uuid) -> Result<i64> {
        Ok(epoch(&self.inner.lock().await.load_group(group_id)?))
    }

    /// Test support: the server user id of the current session.
    #[doc(hidden)]
    pub async fn user_id(&self) -> Option<Uuid> {
        self.inner.lock().await.my_user_id()
    }

    /// Test support: drops the session, as if the anonymous user's refresh
    /// token had been lost. The next request signs in again and reclaims the device.
    #[doc(hidden)]
    pub async fn forget_session(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.state.session = None;
        self.save(&mut inner)
    }
}

fn group_info(g: &GroupState) -> GroupInfo {
    GroupInfo { id: g.id, name: g.name.clone(), role: g.role, removed: g.removed, halted: g.halted.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_codes_are_80_bit_crockford() {
        let a = generate_invite_code();
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|b| CROCKFORD.contains(&b)));
        assert_ne!(a, generate_invite_code());
    }

    #[test]
    fn invite_codes_tolerate_typing() {
        let code = "0123456789ABCDEF".replace('B', "C").replace('F', "G");
        let typed = format_invite_code(&code).to_lowercase().replace('0', "o").replace('1', "l");
        assert_eq!(normalize_invite_code(&format!(" {typed} ")).as_deref(), Some(code.as_str()));
        assert_eq!(normalize_invite_code("too-short"), None);
        assert_eq!(normalize_invite_code("UUUUUUUUUUUUUUUU"), None, "U is not in the alphabet");
    }
}
