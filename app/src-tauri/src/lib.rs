//! Tauri shell around `hermes-core`. Keys never leave Rust: the webview only
//! receives decrypted messages for display and sends plain user input.

use std::sync::Arc;

use hermes_core::supabase::SupabaseConfig;
use hermes_core::{ChatMessage, GroupInfo, Hermes, Profile};
use tauri::{Emitter, Manager, State};

type Res<T> = Result<T, String>;
type App<'a> = State<'a, Arc<Hermes>>;

fn err(e: hermes_core::Error) -> String {
    e.to_string()
}

#[tauri::command]
fn profile(h: App<'_>) -> Profile {
    h.profile()
}

#[tauri::command]
fn set_display_name(h: App<'_>, name: String) -> Res<Profile> {
    h.set_display_name(&name).map_err(err)
}

#[tauri::command]
fn list_groups(h: App<'_>) -> Vec<GroupInfo> {
    h.groups()
}

#[tauri::command]
async fn create_group(h: App<'_>, name: String) -> Res<GroupInfo> {
    h.create_group(&name).await.map_err(err)
}

#[tauri::command]
async fn join_group(h: App<'_>, invite: String) -> Res<GroupInfo> {
    h.join_group(&invite).await.map_err(err)
}

#[tauri::command]
async fn leave_group(h: App<'_>, group_id: String) -> Res<()> {
    h.leave_group(&group_id).await.map_err(err)
}

#[tauri::command]
async fn history(h: App<'_>, group_id: String, before_id: Option<i64>) -> Res<Vec<ChatMessage>> {
    h.history(&group_id, before_id).await.map_err(err)
}

#[tauri::command]
async fn send_message(h: App<'_>, group_id: String, text: String) -> Res<ChatMessage> {
    h.send(&group_id, &text).await.map_err(err)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "hermes_core=info".into()))
        .init();

    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let hermes = Hermes::open(data_dir, SupabaseConfig::from_env())?;
            app.manage(hermes.clone());

            if hermes.profile().configured {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let result = hermes
                        .run_realtime(move |event| handle.emit("hermes", event).is_ok())
                        .await;
                    if let Err(e) = result {
                        tracing::error!("realtime stopped: {e}");
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            profile,
            set_display_name,
            list_groups,
            create_group,
            join_group,
            leave_group,
            history,
            send_message,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Hermes");
}
