//! Tauri shell around `hermes-core`. Keys never leave Rust: the webview only
//! receives decrypted messages for display and sends plain user input.

use std::sync::Arc;

use hermes_core::supabase::SupabaseConfig;
use hermes_core::{ChatMessage, GroupInfo, Hermes, Invite, MemberInfo, Profile, Role, SystemKeyring};
use tauri::{Emitter, Manager, State};
use uuid::Uuid;

type Res<T> = Result<T, String>;

/// The core, or why it could not open (e.g. no system keystore available).
struct Core(Result<Arc<Hermes>, String>);
type App<'a> = State<'a, Core>;

impl Core {
    fn get(&self) -> Res<&Arc<Hermes>> {
        self.0.as_ref().map_err(Clone::clone)
    }
}

fn err(e: hermes_core::Error) -> String {
    e.to_string()
}

#[tauri::command]
async fn profile(core: App<'_>) -> Res<Profile> {
    Ok(core.get()?.profile().await)
}

#[tauri::command]
async fn set_display_name(core: App<'_>, name: String) -> Res<Profile> {
    core.get()?.set_display_name(&name).await.map_err(err)
}

#[tauri::command]
async fn list_groups(core: App<'_>) -> Res<Vec<GroupInfo>> {
    Ok(core.get()?.groups().await)
}

#[tauri::command]
async fn pending_joins(core: App<'_>) -> Res<Vec<Uuid>> {
    Ok(core.get()?.pending_joins().await)
}

#[tauri::command]
async fn messages(core: App<'_>, group_id: Uuid) -> Res<Vec<ChatMessage>> {
    core.get()?.messages(group_id).await.map_err(err)
}

#[tauri::command]
async fn create_group(core: App<'_>, name: String) -> Res<GroupInfo> {
    core.get()?.create_group(&name).await.map_err(err)
}

#[tauri::command]
async fn create_invite(core: App<'_>, group_id: Uuid) -> Res<Invite> {
    core.get()?.create_invite(group_id).await.map_err(err)
}

#[tauri::command]
async fn join_group(core: App<'_>, code: String) -> Res<Uuid> {
    core.get()?.join(&code).await.map_err(err)
}

#[tauri::command]
async fn members(core: App<'_>, group_id: Uuid) -> Res<Vec<MemberInfo>> {
    core.get()?.members(group_id).await.map_err(err)
}

#[tauri::command]
async fn set_role(core: App<'_>, group_id: Uuid, user_id: Uuid, role: Role) -> Res<()> {
    core.get()?.set_role(group_id, user_id, role).await.map_err(err)
}

#[tauri::command]
async fn remove_member(core: App<'_>, group_id: Uuid, user_id: Uuid) -> Res<()> {
    core.get()?.remove_member(group_id, user_id).await.map_err(err)
}

#[tauri::command]
async fn leave_group(core: App<'_>, group_id: Uuid) -> Res<()> {
    core.get()?.leave_group(group_id).await.map_err(err)
}

/// `id` is chosen by the UI so a retry after an unknown outcome reuses it.
#[tauri::command]
async fn send_message(core: App<'_>, group_id: Uuid, id: String, text: String) -> Res<ChatMessage> {
    core.get()?.send_with_id(group_id, &id, &text).await.map_err(err)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "hermes_core=info".into()))
        .init();

    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let config = SupabaseConfig::from_env();
            let configured = config.is_some();
            let opened = Hermes::open(data_dir.clone(), config, &SystemKeyring::for_data_dir(&data_dir)).map_err(err);
            match &opened {
                Ok(hermes) if configured => {
                    let hermes = hermes.clone();
                    let handle = app.handle().clone();
                    tauri::async_runtime::spawn(async move {
                        if let Err(e) = hermes.run(move |event| handle.emit("hermes", event).is_ok()).await {
                            tracing::error!("sync loop stopped: {e}");
                        }
                    });
                }
                Ok(_) => {}
                Err(e) => tracing::error!("could not open Hermes: {e}"),
            }
            app.manage(Core(opened));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            profile,
            set_display_name,
            list_groups,
            pending_joins,
            messages,
            create_group,
            create_invite,
            join_group,
            members,
            set_role,
            remove_member,
            leave_group,
            send_message,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Hermes");
}
