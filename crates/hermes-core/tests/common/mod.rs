//! Helpers shared by the integration test binaries.
#![allow(dead_code)]

use std::sync::Arc;

use hermes_core::supabase::SupabaseConfig;
use hermes_core::{Hermes, MemoryVault};
use uuid::Uuid;

pub const WAIT: std::time::Duration = std::time::Duration::from_secs(30);

pub fn config() -> SupabaseConfig {
    SupabaseConfig {
        url: std::env::var("HERMES_TEST_SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:55321".into()),
        anon_key: std::env::var("HERMES_TEST_SUPABASE_ANON_KEY").expect("HERMES_TEST_SUPABASE_ANON_KEY (see pnpm test:e2e)"),
    }
}

pub async fn client(name: &str) -> Arc<Hermes> {
    let dir = std::env::temp_dir().join(format!("hermes-it-{name}-{}", Uuid::new_v4()));
    let h = Hermes::open(dir, Some(config()), &MemoryVault::default()).unwrap();
    h.set_display_name(name).await.unwrap();
    h
}

/// Superuser connection, used only to arrange time (expire codes) and to read
/// raw ciphertext the way a compromised server could.
pub async fn db() -> tokio_postgres::Client {
    let url = std::env::var("HERMES_TEST_DB_URL").unwrap_or_else(|_| "postgresql://postgres:postgres@127.0.0.1:55322/postgres".into());
    let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(conn);
    client
}

pub fn raw_code(invite: &str) -> String {
    invite.replace('-', "")
}

/// A owns a group; B is a member (A's sync accepts, B's sync finishes the join).
pub async fn group_with(a: &Hermes, b: &Hermes) -> Uuid {
    let g = a.create_group("Ordem").await.unwrap();
    let invite = a.create_invite(g.id).await.unwrap();
    assert_eq!(b.join(&invite.code).await.unwrap(), g.id);
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    let groups = b.groups().await;
    assert!(groups.iter().any(|x| x.id == g.id && x.name == "Ordem" && !x.removed), "B joined: {groups:?}");
    g.id
}

pub async fn latest_application_payload(db: &tokio_postgres::Client, group: Uuid) -> String {
    db.query_one(
        "select payload from public.messages where group_id = $1::text::uuid and kind = 'application' order by id desc limit 1",
        &[&group.to_string()],
    )
    .await
    .unwrap()
    .get(0)
}

pub fn texts(msgs: &[hermes_core::ChatMessage]) -> Vec<String> {
    msgs.iter().map(|m| m.text.clone()).collect()
}

