//! A compromised server: the database's admin check is switched off, so a
//! plain member's modified client gets an Add commit accepted. Honest clients
//! must still refuse it.
//!
//! This binary swaps a database function for the duration of one test, so it
//! is kept apart from `local_supabase.rs` (cargo runs test binaries one after
//! another). Run with `pnpm test:e2e`.

mod common;

use common::*;
use hermes_core::supabase::{JoinRequestRow, Supabase};
use hermes_core::{Error, HermesEvent, generate_invite_code};

/// `private.require_admin` that lets every member through.
const ADMIN_CHECK_OFF: &str = "
create or replace function private.require_admin(p_group_id uuid)
returns public.group_role
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  perform private.require_user();
  return coalesce(private.my_role(p_group_id), 'member');
end
$$;";

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn clients_refuse_an_add_from_a_plain_member_that_the_server_accepted() {
    let (a, b, c) = (client("ana").await, client("bruno").await, client("carla").await);
    let g = group_with(&a, &b).await;
    let epoch_before = a.epoch(g).await.unwrap();
    let db = db().await;

    // ---- the server stops checking roles ----------------------------------------
    let original: String = db
        .query_one("select pg_get_functiondef('private.require_admin(uuid)'::regprocedure)", &[])
        .await
        .unwrap()
        .get(0);
    db.batch_execute(ADMIN_CHECK_OFF).await.unwrap();

    let attack = async {
        // B is a plain member. With the check off the server lets B create a
        // code, and B's modified client commits the Add for whoever uses it.
        let code = generate_invite_code();
        Supabase::new(config()).create_invite(&b.access_token().await?, g, &code).await?;
        c.join(&code).await?;
        let c_id = c.user_id().await.expect("C signed in");
        let row = db
            .query_one(
                "select id::text, group_id::text, requester_id::text, credential, key_package, status
                 from public.join_requests where requester_id = $1::text::uuid",
                &[&c_id.to_string()],
            )
            .await
            .expect("C's join request");
        let req = JoinRequestRow {
            id: row.get::<_, String>(0).parse().unwrap(),
            group_id: row.get::<_, String>(1).parse().unwrap(),
            requester_id: row.get::<_, String>(2).parse().unwrap(),
            credential: row.get(3),
            key_package: row.get(4),
            status: row.get(5),
            welcome: None,
        };
        b.force_accept_join(&req).await
    }
    .await;

    // ---- restore the server before asserting anything ----------------------------
    db.batch_execute(&original).await.unwrap();
    attack.expect("with its admin check off, the server accepts the plain member's commit");

    let server_epoch: i64 = db
        .query_one("select epoch from public.groups where id = $1::text::uuid", &[&g.to_string()])
        .await
        .unwrap()
        .get(0);
    assert_eq!(server_epoch, epoch_before + 1, "the server stored the commit and moved on");
    println!("server accepted the plain member's Add: epoch {epoch_before} -> {server_epoch}");

    // ---- the owner's client refuses it ---------------------------------------------
    let events = a.sync().await.unwrap();
    let reason = events
        .iter()
        .find_map(|e| match e {
            HermesEvent::InvalidChange { group_id, reason } if *group_id == g => Some(reason.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("A must report an invalid change, got {events:?}"));
    println!("A refused it: {reason}");
    assert!(reason.contains("cannot add members"), "{reason}");
    assert_eq!(a.epoch(g).await.unwrap(), epoch_before, "A did not advance its epoch");
    let group = a.groups().await.into_iter().find(|x| x.id == g).unwrap();
    assert_eq!(group.halted.as_deref(), Some(reason.as_str()), "A froze the group");
    assert!(matches!(a.send(g, "ainda dá?").await, Err(Error::InvalidChange(_))));
    // Later syncs keep it frozen and don't report it again.
    let again = a.sync().await.unwrap();
    assert!(!again.iter().any(|e| matches!(e, HermesEvent::InvalidChange { .. })), "{again:?}");
    assert_eq!(a.epoch(g).await.unwrap(), epoch_before);

    // ---- the new "member" refuses the Welcome too ----------------------------------
    let events = c.sync().await.unwrap();
    let failure = events
        .iter()
        .find_map(|e| match e {
            HermesEvent::JoinFailed { reason } => Some(reason.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("C must refuse the Welcome, got {events:?}"));
    println!("C refused the Welcome: {failure}");
    assert!(failure.contains("not issued by an owner or admin"), "{failure}");
    assert!(c.groups().await.iter().all(|x| x.id != g), "C is not in the group");
}
