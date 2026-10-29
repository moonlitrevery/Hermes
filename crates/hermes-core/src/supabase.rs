//! Minimal Supabase client: anonymous auth (GoTrue), PostgREST reads and the
//! Hermes RPCs. Supabase is treated as an untrusted relay: everything sent
//! here is MLS ciphertext, a public key, or an opaque id.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{Error, Result, Role, now_ms};

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
        let ws = self.url.replacen("https://", "wss://", 1).replacen("http://", "ws://", 1);
        format!("{ws}/realtime/v1/websocket?apikey={}&vsn=1.0.0", self.anon_key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix seconds.
    pub expires_at: i64,
    pub user_id: Uuid,
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
    id: Uuid,
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

#[derive(Debug, Clone, Deserialize)]
pub struct MessageRow {
    pub id: i64,
    pub epoch: i64,
    pub kind: String,
    pub sender_credential: String,
    pub payload: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JoinRequestRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub requester_id: Uuid,
    pub credential: String,
    pub key_package: String,
    pub status: String,
    pub welcome: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DepartureRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub credential: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemberRow {
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub role: Role,
    pub credential: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JoinReply {
    pub status: String,
    pub request_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
}

pub struct Supabase {
    cfg: SupabaseConfig,
    http: reqwest::Client,
}

impl Supabase {
    pub fn new(cfg: SupabaseConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("hermes/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
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

    pub async fn rpc<T: DeserializeOwned>(&self, token: &str, name: &str, args: Value) -> Result<T> {
        let res = self
            .rest(reqwest::Method::POST, &format!("rpc/{name}"), token)
            .json(&args)
            .send()
            .await?;
        parse(res).await
    }

    /// For RPCs returning void (HTTP 204, no body).
    async fn rpc_unit(&self, token: &str, name: &str, args: Value) -> Result<()> {
        let res = self
            .rest(reqwest::Method::POST, &format!("rpc/{name}"), token)
            .json(&args)
            .send()
            .await?;
        if res.status().is_success() { Ok(()) } else { Err(api_error(res).await) }
    }

    async fn select<T: DeserializeOwned>(&self, token: &str, table: &str, query: &[(&str, String)]) -> Result<Vec<T>> {
        let res = self.rest(reqwest::Method::GET, table, token).query(query).send().await?;
        parse(res).await
    }

    // ---- RPCs ---------------------------------------------------------------

    pub async fn claim_device(&self, token: &str, secret: &str) -> Result<()> {
        self.rpc_unit(token, "claim_device", json!({ "p_secret": secret })).await
    }

    pub async fn create_group(&self, token: &str, id: Uuid, credential: &str) -> Result<()> {
        self.rpc_unit(token, "create_group", json!({ "p_id": id, "p_credential": credential })).await
    }

    /// Returns the expiry timestamp as reported by the server.
    pub async fn create_invite(&self, token: &str, group_id: Uuid, code: &str) -> Result<String> {
        self.rpc(token, "create_invite", json!({ "p_group_id": group_id, "p_code": code })).await
    }

    pub async fn request_join(&self, token: &str, code: &str, credential: &str, key_package: &str) -> Result<JoinReply> {
        let mut rows: Vec<JoinReply> = self
            .rpc(
                token,
                "request_join",
                json!({ "p_code": code, "p_credential": credential, "p_key_package": key_package }),
            )
            .await?;
        rows.pop().ok_or_else(|| Error::Malformed("request_join returned nothing".into()))
    }

    pub async fn add_member(&self, token: &str, request_id: Uuid, epoch: i64, commit: &str, welcome: &str) -> Result<i64> {
        self.rpc(
            token,
            "add_member",
            json!({ "p_request_id": request_id, "p_epoch": epoch, "p_commit": commit, "p_welcome": welcome }),
        )
        .await
    }

    pub async fn remove_member(&self, token: &str, group_id: Uuid, user_id: Uuid, epoch: i64, commit: &str) -> Result<i64> {
        self.rpc(
            token,
            "remove_member",
            json!({ "p_group_id": group_id, "p_user_id": user_id, "p_epoch": epoch, "p_commit": commit }),
        )
        .await
    }

    pub async fn complete_departure(&self, token: &str, departure_id: Uuid, epoch: i64, commit: &str) -> Result<i64> {
        self.rpc(
            token,
            "complete_departure",
            json!({ "p_departure_id": departure_id, "p_epoch": epoch, "p_commit": commit }),
        )
        .await
    }

    pub async fn leave_group(&self, token: &str, group_id: Uuid) -> Result<()> {
        self.rpc_unit(token, "leave_group", json!({ "p_group_id": group_id })).await
    }

    pub async fn set_role(&self, token: &str, group_id: Uuid, user_id: Uuid, role: Role, epoch: i64, commit: &str) -> Result<i64> {
        self.rpc(
            token,
            "set_role",
            json!({ "p_group_id": group_id, "p_user_id": user_id, "p_role": role, "p_epoch": epoch, "p_commit": commit }),
        )
        .await
    }

    pub async fn post_message(&self, token: &str, group_id: Uuid, epoch: i64, payload: &str) -> Result<i64> {
        self.rpc(token, "post_message", json!({ "p_group_id": group_id, "p_epoch": epoch, "p_payload": payload }))
            .await
    }

    // ---- reads ----------------------------------------------------------------

    pub async fn messages_after(&self, token: &str, group_id: Uuid, after_id: i64, limit: u32) -> Result<Vec<MessageRow>> {
        self.select(
            token,
            "messages",
            &[
                ("select", "id,epoch,kind,sender_credential,payload".into()),
                ("group_id", format!("eq.{group_id}")),
                ("id", format!("gt.{after_id}")),
                ("order", "id.asc".into()),
                ("limit", limit.to_string()),
            ],
        )
        .await
    }

    pub async fn commit_at(&self, token: &str, group_id: Uuid, epoch: i64) -> Result<Option<MessageRow>> {
        let mut rows = self
            .select(
                token,
                "messages",
                &[
                    ("select", "id,epoch,kind,sender_credential,payload".into()),
                    ("group_id", format!("eq.{group_id}")),
                    ("kind", "eq.commit".into()),
                    ("epoch", format!("eq.{epoch}")),
                ],
            )
            .await?;
        Ok(rows.pop())
    }

    pub async fn join_request(&self, token: &str, id: Uuid) -> Result<Option<JoinRequestRow>> {
        let mut rows = self
            .select(token, "join_requests", &[("select", "*".into()), ("id", format!("eq.{id}"))])
            .await?;
        Ok(rows.pop())
    }

    /// Pending requests visible to this user (as admin, or their own).
    pub async fn pending_requests(&self, token: &str) -> Result<Vec<JoinRequestRow>> {
        self.select(
            token,
            "join_requests",
            &[("select", "*".into()), ("status", "eq.pending".into()), ("order", "created_at.asc".into())],
        )
        .await
    }

    pub async fn departures(&self, token: &str) -> Result<Vec<DepartureRow>> {
        self.select(token, "departures", &[("select", "id,group_id,credential".into())]).await
    }

    pub async fn my_memberships(&self, token: &str, user_id: Uuid) -> Result<Vec<MemberRow>> {
        self.select(
            token,
            "members",
            &[("select", "group_id,user_id,role,credential".into()), ("user_id", format!("eq.{user_id}"))],
        )
        .await
    }

    pub async fn members(&self, token: &str, group_id: Uuid) -> Result<Vec<MemberRow>> {
        self.select(
            token,
            "members",
            &[
                ("select", "group_id,user_id,role,credential".into()),
                ("group_id", format!("eq.{group_id}")),
                ("order", "joined_at.asc".into()),
            ],
        )
        .await
    }
}

async fn parse<T: DeserializeOwned>(res: reqwest::Response) -> Result<T> {
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
