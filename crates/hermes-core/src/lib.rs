//! Hermes core: end-to-end encrypted group chat that uses Supabase only as an
//! untrusted relay for ciphertext.

pub mod crypto;
pub mod realtime;
mod store;
pub mod supabase;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::crypto::{GroupSecret, Identity, MessageBody, fingerprint, open_message, random_bytes, seal_message};
use crate::realtime::RealtimeEvent;
use crate::store::{State, StoredGroup};
use crate::supabase::{MessageRow, Session, Supabase, SupabaseConfig};

pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_MESSAGE_CHARS: usize = 8_000;
const PAGE_SIZE: u32 = 50;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("That invite code is not valid. Check it for typos.")]
    InvalidInvite,
    #[error("message could not be decrypted")]
    Decrypt,
    #[error("message signature is invalid")]
    BadSignature,
    #[error("malformed data: {0}")]
    Malformed(String),
    #[error("Supabase is not configured: set HERMES_SUPABASE_URL and HERMES_SUPABASE_ANON_KEY")]
    NotConfigured,
    #[error("You are already in this group.")]
    AlreadyJoined,
    #[error("unknown group")]
    UnknownGroup,
    #[error("{0}")]
    Invalid(String),
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("realtime: {0}")]
    Realtime(String),
    #[error("storage error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    pub display_name: String,
    pub fingerprint: String,
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub invite: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    pub id: i64,
    pub group_id: String,
    pub sender_name: String,
    pub sender_fingerprint: String,
    pub mine: bool,
    pub text: String,
    pub sent_at: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HermesEvent {
    Message { message: ChatMessage },
    Online,
    Offline { reason: String },
}

pub struct Hermes {
    path: PathBuf,
    state: Mutex<State>,
    identity: Identity,
    sb: Option<Supabase>,
    /// Serialises sign-in/refresh so concurrent calls don't create two users.
    auth: AsyncMutex<()>,
    /// Highest message id seen per group, for gap-filling after reconnects.
    last_seen: Mutex<HashMap<String, i64>>,
}

impl Hermes {
    /// Loads (or creates) local state in `data_dir`.
    pub fn open(data_dir: PathBuf, cfg: Option<SupabaseConfig>) -> Result<Arc<Self>> {
        let path = data_dir.join("hermes.json");
        let state = match store::load(&path)? {
            Some(s) => s,
            None => {
                let s = State::new(Identity::generate().secret_hex());
                store::save(&path, &s)?;
                s
            }
        };
        let identity = Identity::from_hex(&state.identity)?;
        Ok(Arc::new(Self {
            path,
            state: Mutex::new(state),
            identity,
            sb: cfg.map(Supabase::new),
            auth: AsyncMutex::new(()),
            last_seen: Mutex::new(HashMap::new()),
        }))
    }

    fn sb(&self) -> Result<&Supabase> {
        self.sb.as_ref().ok_or(Error::NotConfigured)
    }

    fn update_state<T>(&self, f: impl FnOnce(&mut State) -> T) -> Result<T> {
        let mut state = self.state.lock().unwrap();
        let out = f(&mut state);
        store::save(&self.path, &state)?;
        Ok(out)
    }

    pub fn profile(&self) -> Profile {
        Profile {
            display_name: self.state.lock().unwrap().display_name.clone(),
            fingerprint: fingerprint(&self.identity.public_hex()),
            configured: self.sb.is_some(),
        }
    }

    pub fn set_display_name(&self, name: &str) -> Result<Profile> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
            return Err(Error::Invalid(format!("Name must be 1–{MAX_NAME_CHARS} characters.")));
        }
        self.update_state(|s| s.display_name = name.to_owned())?;
        Ok(self.profile())
    }

    pub fn groups(&self) -> Vec<GroupInfo> {
        self.state.lock().unwrap().groups.iter().map(StoredGroup::info).collect()
    }

    fn group_secret(&self, group_id: &str) -> Result<GroupSecret> {
        let state = self.state.lock().unwrap();
        let g = state.groups.iter().find(|g| g.id == group_id).ok_or(Error::UnknownGroup)?;
        GroupSecret::from_invite_code(&g.invite)
    }

    /// Returns a valid access token, signing in anonymously when there is no
    /// usable session. A brand-new anonymous user has no memberships, so every
    /// locally known group is re-joined with its stored secret.
    pub async fn access_token(&self) -> Result<String> {
        let sb = self.sb()?;
        let _guard = self.auth.lock().await;
        let current = self.state.lock().unwrap().session.clone();
        let session = match current {
            Some(s) if !s.needs_refresh() => return Ok(s.access_token),
            Some(s) => match sb.refresh(&s).await {
                Ok(fresh) => fresh,
                // Refresh token rejected (expired or revoked): start over as a new user.
                Err(Error::Api { status: 400..=499, .. }) => self.new_user(sb).await?,
                Err(e) => return Err(e),
            },
            None => self.new_user(sb).await?,
        };
        let token = session.access_token.clone();
        self.update_state(|s| s.session = Some(session))?;
        Ok(token)
    }

    async fn new_user(&self, sb: &Supabase) -> Result<Session> {
        let session = sb.sign_in_anonymously().await?;
        let groups = self.groups();
        for g in groups {
            match sb.join_group(&session.access_token, &g.id, &self.identity.public_hex()).await {
                Ok(_) => {}
                Err(Error::Api { status, message }) => {
                    tracing::warn!("could not rejoin group {}: {status} {message}", g.id)
                }
                Err(e) => return Err(e),
            }
        }
        Ok(session)
    }

    pub async fn create_group(&self, name: &str) -> Result<GroupInfo> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
            return Err(Error::Invalid(format!("Group name must be 1–{MAX_NAME_CHARS} characters.")));
        }
        let secret = GroupSecret::generate();
        let token = self.access_token().await?;
        self.sb()?
            .create_group(&token, &secret.group_id(), &secret.seal_name(name), &self.identity.public_hex())
            .await?;
        self.remember_group(&secret, name)
    }

    pub async fn join_group(&self, invite: &str) -> Result<GroupInfo> {
        let secret = GroupSecret::from_invite_code(invite)?;
        if self.group_secret(&secret.group_id()).is_ok() {
            return Err(Error::AlreadyJoined);
        }
        let token = self.access_token().await?;
        let sealed_name = match self.sb()?.join_group(&token, &secret.group_id(), &self.identity.public_hex()).await {
            Err(Error::Api { status: 404 | 400, message }) if message.contains("group not found") => {
                return Err(Error::Invalid("No group exists for that invite code.".into()));
            }
            r => r?,
        };
        let name = secret.open_name(&sealed_name)?;
        self.remember_group(&secret, &name)
    }

    fn remember_group(&self, secret: &GroupSecret, name: &str) -> Result<GroupInfo> {
        let stored = StoredGroup { id: secret.group_id(), name: name.to_owned(), invite: secret.invite_code() };
        let info = stored.info();
        self.update_state(|s| s.groups.push(stored))?;
        Ok(info)
    }

    pub async fn leave_group(&self, group_id: &str) -> Result<()> {
        let token = self.access_token().await?;
        let user_id = self.state.lock().unwrap().session.as_ref().map(|s| s.user_id.clone()).unwrap_or_default();
        self.sb()?.leave_group(&token, group_id, &user_id).await?;
        self.update_state(|s| s.groups.retain(|g| g.id != group_id))?;
        self.last_seen.lock().unwrap().remove(group_id);
        Ok(())
    }

    /// Oldest-first page of history ending just before `before_id` (or the latest messages).
    pub async fn history(&self, group_id: &str, before_id: Option<i64>) -> Result<Vec<ChatMessage>> {
        let secret = self.group_secret(group_id)?;
        let token = self.access_token().await?;
        let mut rows = self.sb()?.messages_before(&token, group_id, before_id, PAGE_SIZE).await?;
        rows.reverse();
        Ok(rows.iter().filter_map(|r| self.decrypt_row(&secret, r)).collect())
    }

    pub async fn send(&self, group_id: &str, text: &str) -> Result<ChatMessage> {
        let text = text.trim();
        if text.is_empty() {
            return Err(Error::Invalid("Message is empty.".into()));
        }
        if text.chars().count() > MAX_MESSAGE_CHARS {
            return Err(Error::Invalid(format!("Messages are limited to {MAX_MESSAGE_CHARS} characters.")));
        }
        let secret = self.group_secret(group_id)?;
        let body = MessageBody {
            id: hex::encode(random_bytes::<16>()),
            name: self.state.lock().unwrap().display_name.clone(),
            text: text.to_owned(),
            sent_at: now_ms(),
        };
        let sealed = seal_message(&secret, &self.identity, &body);
        let token = self.access_token().await?;
        let row = self.sb()?.post_message(&token, group_id, &sealed).await?;
        self.decrypt_row(&secret, &row)
            .ok_or_else(|| Error::Malformed("server returned an unreadable copy of the message".into()))
    }

    fn decrypt_row(&self, secret: &GroupSecret, row: &MessageRow) -> Option<ChatMessage> {
        {
            let mut seen = self.last_seen.lock().unwrap();
            let last = seen.entry(row.group_id.clone()).or_default();
            *last = (*last).max(row.id);
        }
        let body = match open_message(secret, &row.sealed) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("dropping message {} in {}: {e}", row.id, row.group_id);
                return None;
            }
        };
        Some(ChatMessage {
            id: row.id,
            group_id: row.group_id.clone(),
            sender_name: body.name,
            sender_fingerprint: fingerprint(&row.sealed.sender_pub),
            mine: row.sealed.sender_pub == self.identity.public_hex(),
            text: body.text,
            sent_at: body.sent_at,
            created_at: row.created_at.clone(),
        })
    }

    /// Streams live messages and connection status until `on_event` returns
    /// `false` or the task is dropped. Missed messages are fetched after every
    /// reconnect.
    pub async fn run_realtime(self: Arc<Self>, mut on_event: impl FnMut(HermesEvent) -> bool) -> Result<()> {
        let ws_url = self.sb()?.config().realtime_url();
        let (tx, mut rx) = mpsc::channel(64);
        let me = self.clone();
        let task = tokio::spawn(realtime::run(ws_url, move || {
            let me = me.clone();
            async move { me.access_token().await }
        }, tx));

        while let Some(ev) = rx.recv().await {
            let events = match ev {
                RealtimeEvent::Connected => {
                    let mut out = vec![HermesEvent::Online];
                    out.extend(self.catch_up().await.into_iter().map(|message| HermesEvent::Message { message }));
                    out
                }
                RealtimeEvent::Insert(row) => match self.group_secret(&row.group_id) {
                    Ok(secret) => self.decrypt_row(&secret, &row).map(|message| HermesEvent::Message { message }).into_iter().collect(),
                    Err(_) => vec![],
                },
                RealtimeEvent::Disconnected(reason) => vec![HermesEvent::Offline { reason }],
            };
            for e in events {
                if !on_event(e) {
                    task.abort();
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Fetches messages newer than the last one seen in each group.
    async fn catch_up(&self) -> Vec<ChatMessage> {
        let Ok(token) = self.access_token().await else { return vec![] };
        let Ok(sb) = self.sb() else { return vec![] };
        let mut out = Vec::new();
        for g in self.groups() {
            let Some(after) = self.last_seen.lock().unwrap().get(&g.id).copied() else { continue };
            let Ok(secret) = self.group_secret(&g.id) else { continue };
            match sb.messages_after(&token, &g.id, after, 200).await {
                Ok(rows) => out.extend(rows.iter().filter_map(|r| self.decrypt_row(&secret, r))),
                Err(e) => tracing::warn!("catch-up failed for {}: {e}", g.id),
            }
        }
        out
    }
}
