//! Local persistent state, stored as JSON in the app's private data directory.
//!
//! This file holds the identity key and every group's invite secret. It is
//! written with owner-only permissions on Unix but is not encrypted at rest.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::supabase::Session;
use crate::{GroupInfo, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    /// Hex Ed25519 secret key.
    pub identity: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub session: Option<Session>,
    #[serde(default)]
    pub groups: Vec<StoredGroup>,
}

impl State {
    pub fn new(identity: String) -> Self {
        Self { version: 1, identity, display_name: String::new(), session: None, groups: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGroup {
    pub id: String,
    pub name: String,
    pub invite: String,
}

impl StoredGroup {
    pub fn info(&self) -> GroupInfo {
        GroupInfo { id: self.id.clone(), name: self.name.clone(), invite: self.invite.clone() }
    }
}

pub fn load(path: &Path) -> Result<Option<State>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Atomic write: temp file + rename, so a crash never leaves a torn file.
pub fn save(path: &Path, state: &State) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(state)?;
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
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join(format!("hermes-test-{}", std::process::id()));
        let path = dir.join("hermes.json");
        let mut s = State::new("ab".repeat(32));
        s.display_name = "Dante".into();
        save(&path, &s).unwrap();
        let back = load(&path).unwrap().unwrap();
        assert_eq!(back.display_name, "Dante");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
