//! Integration tests against a real local Supabase stack (`pnpm db:start`).
//!
//! Ignored by default; run them with `pnpm test:e2e`, which reads the local
//! stack's URL and keys and runs `cargo test -- --ignored`. Every test uses
//! real `Hermes` clients: real anonymous sign-ins, real RPCs and RLS, real MLS.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use hermes_core::supabase::Supabase;
use hermes_core::{Error, Hermes, HermesEvent, Role};
use tokio::sync::mpsc;


// ---- invites --------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn expired_code_fails() {
    let (a, b) = (client("ana").await, client("bruno").await);
    let g = a.create_group("Ordem").await.unwrap();
    let invite = a.create_invite(g.id).await.unwrap();
    db().await
        .execute(
            "update private.invites set expires_at = now() - interval '1 second'
             where code_hash = encode(extensions.digest($1, 'sha256'), 'hex')",
            &[&raw_code(&invite.code)],
        )
        .await
        .unwrap();
    assert!(matches!(b.join(&invite.code).await, Err(Error::InvalidInvite)));
}

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn reused_code_fails() {
    let (a, b, c) = (client("ana").await, client("bruno").await, client("carla").await);
    let g = a.create_group("Ordem").await.unwrap();
    let invite = a.create_invite(g.id).await.unwrap();
    b.join(&invite.code).await.unwrap();
    assert!(matches!(c.join(&invite.code).await, Err(Error::InvalidInvite)));
}

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn only_admins_create_codes() {
    let (a, b) = (client("ana").await, client("bruno").await);
    let g = group_with(&a, &b).await;
    assert!(b.create_invite(g).await.is_err(), "a plain member cannot create codes");
    let b_id = b.user_id().await.unwrap();
    a.set_role(g, b_id, Role::Admin).await.unwrap();
    b.sync().await.unwrap();
    assert_eq!(b.groups().await[0].role, Role::Admin, "the promotion arrived as a commit");

    // B's app now admits people, and the owner's client accepts that commit.
    let c = client("carla").await;
    c.join(&b.create_invite(g).await.unwrap().code).await.unwrap();
    b.sync().await.unwrap();
    c.sync().await.unwrap();
    let events = a.sync().await.unwrap();
    assert!(!events.iter().any(|e| matches!(e, HermesEvent::InvalidChange { .. })), "{events:?}");
    assert_eq!(a.members(g).await.unwrap().len(), 3);
    assert!(c.groups().await.iter().any(|x| x.id == g));
}

// ---- epoch order ------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn out_of_order_and_concurrent_commits_are_refused() {
    let (a, b, c) = (client("ana").await, client("bruno").await, client("carla").await);
    let g = a.create_group("Ordem").await.unwrap();
    b.join(&a.create_invite(g.id).await.unwrap().code).await.unwrap();
    c.join(&a.create_invite(g.id).await.unwrap().code).await.unwrap();

    // Talk to the server directly with A's session, as a buggy or malicious
    // admin client could. Payloads are opaque to the server.
    let sb = Supabase::new(config());
    let token = a.access_token().await.unwrap();
    let requests = sb.pending_requests(&token).await.unwrap();
    let (rb, rc) = (requests[0].id, requests[1].id);

    let future = sb.add_member(&token, rb, 5, "Y29tbWl0", "d2VsY29tZQ==").await;
    assert!(matches!(future, Err(Error::Api { status: 409, .. })), "future epoch: {future:?}");

    let (x, y) = tokio::join!(
        sb.add_member(&token, rb, 0, "Y29tbWl0", "d2VsY29tZQ=="),
        sb.add_member(&token, rc, 0, "Y29tbWl0", "d2VsY29tZQ=="),
    );
    let accepted = [&x, &y].iter().filter(|r| r.is_ok()).count();
    assert_eq!(accepted, 1, "exactly one of two concurrent commits for epoch 0 wins: {x:?} / {y:?}");
    let loser = if x.is_ok() { rc } else { rb };
    let stale = sb.add_member(&token, loser, 0, "Y29tbWl0", "d2VsY29tZQ==").await;
    assert!(matches!(stale, Err(Error::Api { status: 409, .. })), "stale epoch: {stale:?}");
    assert_eq!(sb.add_member(&token, loser, 1, "Y29tbWl0", "d2VsY29tZQ==").await.unwrap(), 2);
}

// ---- MLS guarantees end to end ----------------------------------------------------

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn removed_member_cannot_decrypt_new_messages() {
    let (a, b) = (client("ana").await, client("bruno").await);
    let g = group_with(&a, &b).await;
    a.send(g, "antes").await.unwrap();
    b.sync().await.unwrap();
    assert_eq!(texts(&b.messages(g).await.unwrap()), ["antes"]);

    let b_id = b.user_id().await.unwrap();
    a.remove_member(g, b_id).await.unwrap();
    a.send(g, "depois da remoção").await.unwrap();

    // Even handed the ciphertext directly (as a malicious server could), B's
    // keys from before the removal can't open it.
    let payload = latest_application_payload(&db().await, g).await;
    let err = b.try_decrypt_payload(g, &payload).await;
    assert!(matches!(err, Err(Error::Mls(_))), "must fail in MLS, got {err:?}");

    // And through the normal path B learns it was removed and gets nothing.
    b.sync().await.unwrap();
    assert!(b.groups().await.iter().any(|x| x.id == g && x.removed));
    assert_eq!(texts(&b.messages(g).await.unwrap()), ["antes"]);
    assert!(b.send(g, "ainda aqui?").await.is_err());
}

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn late_joiner_cannot_read_older_messages() {
    let (a, b) = (client("ana").await, client("bruno").await);
    let g = a.create_group("Ordem").await.unwrap();
    a.send(g.id, "segredo antigo").await.unwrap();
    let old_payload = latest_application_payload(&db().await, g.id).await;

    let invite = a.create_invite(g.id).await.unwrap();
    b.join(&invite.code).await.unwrap();
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    a.send(g.id, "bem-vindo").await.unwrap();
    b.sync().await.unwrap();

    assert_eq!(texts(&b.messages(g.id).await.unwrap()), ["bem-vindo"]);
    // The server doesn't serve the old row to B...
    let sb = Supabase::new(config());
    let rows = sb.messages_after(&b.access_token().await.unwrap(), g.id, 0, 100).await.unwrap();
    assert!(rows.iter().all(|r| r.payload != old_payload), "RLS hides pre-join rows");
    // ...and B could not decrypt it even if it did.
    let err = b.try_decrypt_payload(g.id, &old_payload).await;
    assert!(matches!(err, Err(Error::Mls(_))), "must fail in MLS, got {err:?}");
}

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn duplicate_message_appears_once() {
    let (a, b) = (client("ana").await, client("bruno").await);
    let g = group_with(&a, &b).await;
    // A resend after a lost response: same body id, new ciphertext, new row.
    a.send_with_id(g, "msg-1", "uma vez só").await.unwrap();
    a.send_with_id(g, "msg-1", "uma vez só").await.unwrap();
    b.sync().await.unwrap();

    let rows: i64 = db()
        .await
        .query_one(
            "select count(*) from public.messages where group_id = $1::text::uuid and kind = 'application'",
            &[&g.to_string()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 2, "the server really holds two copies");
    assert_eq!(texts(&b.messages(g).await.unwrap()), ["uma vez só"]);
    assert_eq!(texts(&a.messages(g).await.unwrap()), ["uma vez só"]);
}

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn lost_anonymous_session_reclaims_the_membership() {
    let (a, b) = (client("ana").await, client("bruno").await);
    let g = group_with(&a, &b).await;
    let old_user = b.user_id().await.unwrap();

    b.forget_session().await.unwrap();
    b.send(g, "voltei").await.unwrap();
    let new_user = b.user_id().await.unwrap();
    assert_ne!(old_user, new_user);

    a.sync().await.unwrap();
    assert_eq!(texts(&a.messages(g).await.unwrap()), ["voltei"]);
    let members = a.members(g).await.unwrap();
    assert_eq!(members.len(), 2, "no ghost member left behind: {members:?}");
    assert!(members.iter().any(|m| m.user_id == new_user && m.role == Role::Member));
    let gone: i64 = db()
        .await
        .query_one("select count(*) from auth.users where id = $1::text::uuid", &[&old_user.to_string()])
        .await
        .unwrap()
        .get(0);
    assert_eq!(gone, 0, "the abandoned anonymous user was deleted");
}

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn member_who_leaves_is_removed_from_mls_by_an_admin() {
    let (a, b) = (client("ana").await, client("bruno").await);
    let g = group_with(&a, &b).await;
    // Leave through the server only, so B still holds its old MLS keys.
    Supabase::new(config()).leave_group(&b.access_token().await.unwrap(), g).await.unwrap();
    a.sync().await.unwrap(); // A's app commits the Remove for B's leaf
    a.send(g, "só nós").await.unwrap();
    assert_eq!(a.members(g).await.unwrap().len(), 1);
    let payload = latest_application_payload(&db().await, g).await;
    let err = b.try_decrypt_payload(g, &payload).await;
    assert!(matches!(err, Err(Error::Mls(_))), "must fail in MLS, got {err:?}");
}

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn admin_steps_down_then_leaves() {
    let (a, b) = (client("ana").await, client("bruno").await);
    let g = group_with(&a, &b).await;
    a.set_role(g, b.user_id().await.unwrap(), Role::Admin).await.unwrap();
    b.sync().await.unwrap();

    // Leaving as an admin first commits the step-down, then leaves; the
    // owner's app accepts both commits and removes B from the MLS group.
    b.leave_group(g).await.unwrap();
    let events = a.sync().await.unwrap();
    assert!(!events.iter().any(|e| matches!(e, HermesEvent::InvalidChange { .. })), "{events:?}");
    assert_eq!(a.members(g).await.unwrap().len(), 1);
    a.send(g, "sozinha").await.unwrap();
}

// ---- two live clients ----------------------------------------------------------

struct Live {
    hermes: Arc<Hermes>,
    events: mpsc::UnboundedReceiver<HermesEvent>,
}

fn live(hermes: Arc<Hermes>) -> Live {
    let (tx, events) = mpsc::unbounded_channel();
    let h = hermes.clone();
    tokio::spawn(async move { h.run(move |e| tx.send(e).is_ok()).await });
    Live { hermes, events }
}

impl Live {
    async fn wait_for(&mut self, what: &str, mut pred: impl FnMut(&HermesEvent) -> bool) -> HermesEvent {
        tokio::time::timeout(WAIT, async {
            loop {
                let e = self.events.recv().await.expect("event stream ended");
                if pred(&e) {
                    return e;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
    }

    async fn wait_message(&mut self, text: &str) {
        self.wait_for(&format!("message {text:?}"), |e| matches!(e, HermesEvent::Message { message } if message.text == text))
            .await;
    }
}

#[tokio::test]
#[ignore = "needs the local Supabase stack; run `pnpm test:e2e`"]
async fn two_live_clients_join_chat_and_removal() {
    let mut a = live(client("ana").await);
    let mut b = live(client("bruno").await);
    a.wait_for("A online", |e| matches!(e, HermesEvent::Online)).await;
    b.wait_for("B online", |e| matches!(e, HermesEvent::Online)).await;

    // A creates the group and an invite; B enters the code. Nobody calls
    // sync by hand: A's app accepts the request on its own.
    let g = a.hermes.create_group("Ordem Carmesim").await.unwrap();
    let invite = a.hermes.create_invite(g.id).await.unwrap();
    println!("invite {} expires at {}", invite.code, invite.expires_at);
    b.hermes.join(&invite.code).await.unwrap();
    b.wait_for("B in the group", |e| matches!(e, HermesEvent::GroupsChanged)).await;
    let groups = b.hermes.groups().await;
    assert!(groups.iter().any(|x| x.id == g.id && x.name == "Ordem Carmesim"), "{groups:?}");

    a.hermes.send(g.id, "olá, Bruno").await.unwrap();
    b.wait_message("olá, Bruno").await;
    b.hermes.send(g.id, "olá, Ana").await.unwrap();
    a.wait_message("olá, Ana").await;

    let b_id = b.hermes.user_id().await.unwrap();
    a.hermes.remove_member(g.id, b_id).await.unwrap();
    b.wait_for("B notices the removal", |e| matches!(e, HermesEvent::GroupsChanged)).await;
    assert!(b.hermes.groups().await.iter().any(|x| x.id == g.id && x.removed));

    a.hermes.send(g.id, "Bruno não lê isto").await.unwrap();
    // Give Realtime and the periodic sync time to (not) deliver it.
    let leaked = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(HermesEvent::Message { message }) = b.events.recv().await
                && message.text == "Bruno não lê isto"
            {
                return;
            }
        }
    })
    .await;
    assert!(leaked.is_err(), "removed member received a message sent after removal");
    assert_eq!(texts(&b.hermes.messages(g.id).await.unwrap()), ["olá, Bruno", "olá, Ana"]);
}
