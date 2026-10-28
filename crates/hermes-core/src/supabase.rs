//! Minimal Supabase client: anonymous auth (GoTrue) and PostgREST.
//!
//! Supabase is treated as an untrusted relay. Everything that leaves this
//! module is either ciphertext or a public identifier.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::crypto::SealedMessage;
use crate::{Error, Result, now_ms};

#[derive(Debug, Clone)]
pub struct SupabaseConfig {
    pub url: String,
    pub anon_key: String,
}

impl SupabaseConfig {
    /// Reads `HERMES_SUPABASE_URL` / `HERMES_SUPABASE_ANON_KEY`, preferring the
    /// values baked in at build time (needed on mobile, where there is no shell
    /// environment) and falling back to the runtime environment.
    pub fn from_env() -> Option<Self> {
        let url = option_env!("HERMES_SUPABASE_URL")
            .map(str::to_owned)
            .or_else(|| std::env::var("HERMES_SUPABASE_URL").ok())?;
        let anon_key = option_env!("HERMES_SUPABASE_ANON_KEY")
            .map(str::to_owned)
            .or_else(|| std::env::var("HERMES_SUPABASE_ANON_KEY").ok())?;
        Some(Self { url: url.trim_end_matches('/').to_owned(), anon_key })
    }

    pub fn realtime_url(&self) -> String {
        let ws = self
            .url
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        format!("{ws}/realtime/v1/websocket?apikey={}&vsn=1.0.0", self.anon_key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix seconds.
    pub expires_at: i64,
    pub user_id: String,
}

impl Session {
    pub fn needs_refresh(&self) -> bool {
        self.expires_at - now_ms() / 1000 < 120
    }
}

#[derive(Deserialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    user: AuthUser,
}

#[derive(Deserialize)]
struct AuthUser {
    id: String,
}

impl From<AuthResponse> for Session {
    fn from(r: AuthResponse) -> Self {
        Session {
            access_token: r.access_token,
            refresh_token: r.refresh_token,
            expires_at: now_ms() / 1000 + r.expires_in,
            user_id: r.user.id,
        }
    }
}

/// A message row as stored in `public.messages`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRow {
    pub id: i64,
    pub group_id: String,
    #[serde(flatten)]
    pub sealed: SealedMessage,
    pub created_at: String,
}

const MESSAGE_COLUMNS: &str = "id,group_id,sender_pub,nonce,ciphertext,signature,created_at";

pub struct Supabase {
    cfg: SupabaseConfig,
    http: reqwest::Client,
}

impl Supabase {
    pub fn new(cfg: SupabaseConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("hermes/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client");
        Self { cfg, http }
    }

    pub fn config(&self) -> &SupabaseConfig {
        &self.cfg
    }

    pub async fn sign_in_anonymously(&self) -> Result<Session> {
        let res = self
            .http
            .post(format!("{}/auth/v1/signup", self.cfg.url))
            .header("apikey", &self.cfg.anon_key)
            .json(&json!({}))
            .send()
            .await?;
        Ok(parse::<AuthResponse>(res).await?.into())
    }

    pub async fn refresh(&self, session: &Session) -> Result<Session> {
        let res = self
            .http
            .post(format!("{}/auth/v1/token?grant_type=refresh_token", self.cfg.url))
            .header("apikey", &self.cfg.anon_key)
            .json(&json!({ "refresh_token": session.refresh_token }))
            .send()
            .await?;
        Ok(parse::<AuthResponse>(res).await?.into())
    }

    fn rest(&self, method: reqwest::Method, path: &str, token: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}/rest/v1/{path}", self.cfg.url))
            .header("apikey", &self.cfg.anon_key)
            .bearer_auth(token)
    }

    async fn rpc(&self, token: &str, name: &str, args: Value) -> Result<Value> {
        let res = self
            .rest(reqwest::Method::POST, &format!("rpc/{name}"), token)
            .json(&args)
            .send()
            .await?;
        parse(res).await
    }

    pub async fn create_group(&self, token: &str, group_id: &str, name_ct: &str, sign_pub: &str) -> Result<()> {
        self.rpc(token, "create_group", json!({ "p_id": group_id, "p_name_ct": name_ct, "p_sign_pub": sign_pub }))
            .await?;
        Ok(())
    }

    /// Registers this user as a member and returns the group's sealed name.
    pub async fn join_group(&self, token: &str, group_id: &str, sign_pub: &str) -> Result<String> {
        let v = self
            .rpc(token, "join_group", json!({ "p_id": group_id, "p_sign_pub": sign_pub }))
            .await?;
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::Malformed("join_group response".into()))
    }

    pub async fn leave_group(&self, token: &str, group_id: &str, user_id: &str) -> Result<()> {
        let res = self
            .rest(reqwest::Method::DELETE, "members", token)
            .query(&[("group_id", format!("eq.{group_id}")), ("user_id", format!("eq.{user_id}"))])
            .send()
            .await?;
        check(res).await
    }

    /// Newest-first page of messages, optionally strictly older than `before_id`.
    pub async fn messages_before(&self, token: &str, group_id: &str, before_id: Option<i64>, limit: u32) -> Result<Vec<MessageRow>> {
        let mut query = vec![
            ("select", MESSAGE_COLUMNS.to_owned()),
            ("group_id", format!("eq.{group_id}")),
            ("order", "id.desc".to_owned()),
            ("limit", limit.to_string()),
        ];
        if let Some(id) = before_id {
            query.push(("id", format!("lt.{id}")));
        }
        let res = self.rest(reqwest::Method::GET, "messages", token).query(&query).send().await?;
        parse(res).await
    }

    /// Oldest-first messages strictly newer than `after_id`, used to fill gaps after reconnecting.
    pub async fn messages_after(&self, token: &str, group_id: &str, after_id: i64, limit: u32) -> Result<Vec<MessageRow>> {
        let query = [
            ("select", MESSAGE_COLUMNS.to_owned()),
            ("group_id", format!("eq.{group_id}")),
            ("id", format!("gt.{after_id}")),
            ("order", "id.asc".to_owned()),
            ("limit", limit.to_string()),
        ];
        let res = self.rest(reqwest::Method::GET, "messages", token).query(&query).send().await?;
        parse(res).await
    }

    pub async fn post_message(&self, token: &str, group_id: &str, sealed: &SealedMessage) -> Result<MessageRow> {
        let res = self
            .rest(reqwest::Method::POST, "messages", token)
            .query(&[("select", MESSAGE_COLUMNS)])
            .header("Prefer", "return=representation")
            .json(&json!({
                "group_id": group_id,
                "sender_pub": sealed.sender_pub,
                "nonce": sealed.nonce,
                "ciphertext": sealed.ciphertext,
                "signature": sealed.signature,
            }))
            .send()
            .await?;
        let mut rows: Vec<MessageRow> = parse(res).await?;
        rows.pop().ok_or_else(|| Error::Malformed("insert returned no row".into()))
    }
}

async fn check(res: reqwest::Response) -> Result<()> {
    if res.status().is_success() {
        return Ok(());
    }
    Err(api_error(res).await)
}

async fn parse<T: serde::de::DeserializeOwned>(res: reqwest::Response) -> Result<T> {
    if !res.status().is_success() {
        return Err(api_error(res).await);
    }
    Ok(res.json().await?)
}

async fn api_error(res: reqwest::Response) -> Error {
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    let message = ["message", "msg", "error_description", "error"]
        .iter()
        .find_map(|k| body.get(k).and_then(Value::as_str))
        .unwrap_or("request failed")
        .to_owned();
    Error::Api { status, message }
}
