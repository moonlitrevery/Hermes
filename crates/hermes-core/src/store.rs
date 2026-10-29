//! Local state, persisted as a single encrypted file (see [`crate::vault`]).

use std::collections::HashMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::supabase::Session;
use crate::{ChatMessage, Result, Role, vault};

/// Messages kept per group. History lives only on devices: MLS deletes the
/// keys after use, so old ciphertext on the server can't be decrypted again.
pub const MAX_STORED_MESSAGES: usize = 2_000;

#[derive(Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    /// Hex Ed25519 public key; the private half is in `mls`.
    pub identity: String,
    /// Proves to the server that a new anonymous session is this same device.
    pub device_secret: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub session: Option<Session>,
    #[serde(default)]
    pub groups: Vec<GroupState>,
    #[serde(default)]
    pub pending_joins: Vec<PendingJoin>,
    /// openmls key/value storage, base64-encoded.
    #[serde(default)]
    pub mls: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupState {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    /// Highest server message id already processed.
    pub last_id: i64,
    /// Removed by an admin; the MLS state has been deleted.
    #[serde(default)]
    pub removed: bool,
    /// Set when a commit broke the group's rules; the group is then frozen.
    #[serde(default)]
    pub halted: Option<String>,
    #[serde(default)]
    pub messages: Vec<ChatMessage>,
    /// Display names learned from messages, by credential.
    #[serde(default)]
    pub names: HashMap<String, String>,
}

impl GroupState {
    /// Adds a message unless one with the same body id is already stored
    /// (a resend after a lost response, or a replay). Returns whether it was new.
    pub fn push_message(&mut self, msg: ChatMessage) -> bool {
        if self.messages.iter().any(|m| m.id == msg.id) {
            return false;
        }
        if !msg.mine {
            self.names.insert(msg.sender_credential.clone(), msg.sender_name.clone());
        }
        self.messages.push(msg);
        if self.messages.len() > MAX_STORED_MESSAGES {
            let excess = self.messages.len() - MAX_STORED_MESSAGES;
            self.messages.drain(..excess);
        }
        true
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PendingJoin {
    pub request_id: Uuid,
    pub group_id: Uuid,
    /// Unix ms after which the request can no longer be accepted.
    pub deadline: i64,
}

pub fn encode_mls(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(String, String)> {
    entries.into_iter().map(|(k, v)| (B64.encode(k), B64.encode(v))).collect()
}

pub fn decode_mls(entries: &[(String, String)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    entries
        .iter()
        .filter_map(|(k, v)| Some((B64.decode(k).ok()?, B64.decode(v).ok()?)))
        .collect()
}

pub fn load(path: &Path, key: &[u8; 32]) -> Result<Option<State>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&vault::open(key, &bytes)?)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Atomic write: temp file + rename, so a crash never leaves a torn file.
pub fn save(path: &Path, key: &[u8; 32], state: &State) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let sealed = vault::seal(key, &serde_json::to_vec(state)?);
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&sealed)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: &str) -> ChatMessage {
        ChatMessage {
            id: id.into(),
            group_id: Uuid::nil(),
            sender_name: "Liz".into(),
            sender_credential: "ab".into(),
            sender_fingerprint: "ab".into(),
            mine: false,
            text: "oi".into(),
            sent_at: 0,
        }
    }

    #[test]
    fn duplicate_message_is_stored_once() {
        let mut g = GroupState {
            id: Uuid::nil(),
            name: "g".into(),
            role: Role::Member,
            last_id: 0,
            removed: false,
            halted: None,
            messages: vec![],
            names: HashMap::new(),
        };
        assert!(g.push_message(msg("x")));
        assert!(!g.push_message(msg("x")));
        assert!(g.push_message(msg("y")));
        assert_eq!(g.messages.len(), 2);
    }

    #[test]
    fn state_file_is_encrypted() {
        let dir = std::env::temp_dir().join(format!("hermes-store-{}", Uuid::new_v4()));
        let path = dir.join("state.hermes");
        let key = crate::random_bytes::<32>();
        let mut s = State {
            version: 2,
            identity: "ab".repeat(32),
            device_secret: "cd".repeat(32),
            display_name: "Dante Secreto".into(),
            session: None,
            groups: vec![],
            pending_joins: vec![],
            mls: vec![],
        };
        save(&path, &key, &s).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(13).any(|w| w == b"Dante Secreto"));
        assert!(!raw.windows(64).any(|w| w == "cd".repeat(32).as_bytes()));
        s = load(&path, &key).unwrap().unwrap();
        assert_eq!(s.display_name, "Dante Secreto");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
