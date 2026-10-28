//! Supabase Realtime (Phoenix channels, protocol vsn 1.0.0) subscription to
//! new rows in `public.messages`.
//!
//! No filter is sent: Realtime applies row-level security per subscriber, so
//! the server only forwards rows from groups this user is a member of, and
//! groups joined later are picked up without resubscribing.

use std::future::Future;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::supabase::MessageRow;
use crate::{Error, Result};

const TOPIC: &str = "realtime:hermes-messages";
const HEARTBEAT: Duration = Duration::from_secs(25);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum RealtimeEvent {
    /// Subscribed; anything that arrived while offline must be fetched separately.
    Connected,
    Insert(MessageRow),
    Disconnected(String),
}

/// Runs until `tx` is closed, reconnecting with exponential backoff.
/// `token` is called on every (re)connect and heartbeat so refreshed JWTs are
/// forwarded to the server before the old one expires.
pub async fn run<F, Fut>(ws_url: String, mut token: F, tx: mpsc::Sender<RealtimeEvent>)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let mut backoff = Duration::from_secs(1);
    while !tx.is_closed() {
        let started = tokio::time::Instant::now();
        let reason = match session(&ws_url, &mut token, &tx).await {
            Ok(()) => return,
            Err(e) => e.to_string(),
        };
        if tx.send(RealtimeEvent::Disconnected(reason)).await.is_err() {
            return;
        }
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// One connection's lifetime. Returns `Ok` only when the receiver is gone.
async fn session<F, Fut>(ws_url: &str, token: &mut F, tx: &mpsc::Sender<RealtimeEvent>) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let rt_err = |e: tokio_tungstenite::tungstenite::Error| Error::Realtime(e.to_string());
    let mut access_token = token().await?;
    let (ws, _) = tokio_tungstenite::connect_async(ws_url).await.map_err(rt_err)?;
    let (mut sink, mut stream) = ws.split();

    let mut next_ref = 1u64;
    let mut frame = |topic: &str, event: &str, payload: Value| {
        let r = next_ref.to_string();
        next_ref += 1;
        Message::Text(json!({ "topic": topic, "event": event, "payload": payload, "ref": r, "join_ref": "1" }).to_string().into())
    };

    let join = frame(
        TOPIC,
        "phx_join",
        json!({
            "config": {
                "broadcast": { "self": false },
                "presence": { "key": "" },
                "postgres_changes": [{ "event": "INSERT", "schema": "public", "table": "messages" }],
            },
            "access_token": access_token,
        }),
    );
    sink.send(join).await.map_err(rt_err)?;

    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.tick().await;
    let mut awaiting_reply = false;

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if awaiting_reply {
                    return Err(Error::Realtime("heartbeat timed out".into()));
                }
                let fresh = token().await?;
                if fresh != access_token {
                    access_token = fresh;
                    sink.send(frame(TOPIC, "access_token", json!({ "access_token": access_token }))).await.map_err(rt_err)?;
                }
                sink.send(frame("phoenix", "heartbeat", json!({}))).await.map_err(rt_err)?;
                awaiting_reply = true;
            }
            _ = tx.closed() => return Ok(()),
            msg = stream.next() => {
                let msg = match msg {
                    Some(m) => m.map_err(rt_err)?,
                    None => return Err(Error::Realtime("connection closed".into())),
                };
                let text = match &msg {
                    Message::Text(t) => t.as_str(),
                    Message::Ping(p) => {
                        sink.send(Message::Pong(p.clone())).await.map_err(rt_err)?;
                        continue;
                    }
                    Message::Close(_) => return Err(Error::Realtime("server closed the connection".into())),
                    _ => continue,
                };
                let Ok(v) = serde_json::from_str::<Value>(text) else { continue };
                let event = v["event"].as_str().unwrap_or_default();
                let payload = &v["payload"];
                match (v["topic"].as_str().unwrap_or_default(), event) {
                    ("phoenix", "phx_reply") => awaiting_reply = false,
                    (TOPIC, "phx_reply") => {
                        if payload["status"] != "ok" {
                            return Err(Error::Realtime(format!("subscription rejected: {}", payload["response"])));
                        }
                        if !payload["response"]["postgres_changes"].is_null() && tx.send(RealtimeEvent::Connected).await.is_err() {
                            return Ok(());
                        }
                    }
                    (TOPIC, "postgres_changes") => {
                        let record = &payload["data"]["record"];
                        match serde_json::from_value::<MessageRow>(record.clone()) {
                            Ok(row) => if tx.send(RealtimeEvent::Insert(row)).await.is_err() { return Ok(()) },
                            Err(e) => tracing::warn!("ignoring malformed realtime record: {e}"),
                        }
                    }
                    (TOPIC, "system") if payload["status"] == "error" => {
                        return Err(Error::Realtime(format!("{}", payload["message"])));
                    }
                    (TOPIC, "phx_error" | "phx_close") => {
                        return Err(Error::Realtime(format!("channel {event}")));
                    }
                    _ => {}
                }
            }
        }
    }
}
