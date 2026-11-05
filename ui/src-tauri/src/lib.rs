//! Tauri 코어: 프런트는 `invoke` 로만 서비스에 닿는다 (파이프에 직접 붙지 않음, 14차 4-1).
//! 명령: connect(endpoint) / rpc(method, params). 알림은 `svc-notify` 이벤트로 프런트에 보낸다.

pub mod approve;
#[cfg(windows)]
pub mod approve_win;
mod client;
pub mod elevate;
pub mod tray;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::{Emitter, Manager as _, State};

use client::Client;

#[derive(Default)]
struct AppState {
    client: Mutex<Option<Arc<Client>>>,
    /// 서비스 연결 상태 (트레이 감시가 읽는다, A28)
    link: Arc<tray::Link>,
}

/// 감시용: 마지막 끝점(없으면 파이프)에 새로 붙어 hello 만 하고 놓는다
pub(crate) fn probe_service_at(ep: &str) -> bool {
    match Client::connect(ep, Box::new(|_| {})) {
        Ok(c) => c.call("rpc.hello", serde_json::json!({"client_version": env!("CARGO_PKG_VERSION"), "api": [1, 0]}), Duration::from_secs(3)).is_ok(),
        Err(_) => false,
    }
}

/// 마지막으로 붙은 끝점 (감시의 probe 가 같은 곳에 붙는다)
static PROBE_EP: Mutex<Option<String>> = Mutex::new(None);
pub(crate) fn probe_service() -> bool {
    let ep = PROBE_EP.lock().unwrap().clone().unwrap_or_else(|| "pipe".to_string());
    probe_service_at(&ep)
}

pub(crate) fn notify(app: &tauri::AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
}

// 명령은 async + spawn_blocking: 동기 명령은 메인(창) 스레드에서 돈다 — 파이프 응답을 기다리는 동안 창이 멈추고,
// 잠금을 쥔 채 기다리면 모든 요청이 한 줄로 선다 (A22 러너에서 화면 멈춤으로 드러남).

#[tauri::command]
async fn connect(app: tauri::AppHandle, state: State<'_, AppState>, endpoint: String) -> Result<serde_json::Value, String> {
    // 이전 연결을 먼저 닫는다: 화면을 다시 읽거나 다시 연결할 때 예전 연결이 파이프 인스턴스를 쥐고 있으면 새 연결이 막힌다
    drop(state.client.lock().unwrap().take());
    let app2 = app.clone();
    let link = state.link.clone();
    let link2 = link.clone();
    let ep = endpoint.clone();
    let c = tauri::async_runtime::spawn_blocking(move || -> Result<(Client, serde_json::Value), String> {
        let c = Client::connect(&ep, Box::new(move |v| {
            if v.get("method").and_then(|m| m.as_str()) == Some("client.disconnected") {
                link2.up.store(false, std::sync::atomic::Ordering::SeqCst);
            }
            let _ = app2.emit("svc-notify", v);
        }))
        .map_err(|e| format!("connect {ep}: {e}"))?;
        // 첫 메시지는 rpc.hello (13차 Q4)
        let hello = c.call("rpc.hello", serde_json::json!({"client_version": env!("CARGO_PKG_VERSION"), "api": [1, 0]}), Duration::from_secs(5))?;
        Ok((c, hello))
    })
    .await
    .map_err(|e| e.to_string())??;
    let (client, hello) = c;
    *state.client.lock().unwrap() = Some(Arc::new(client));
    *PROBE_EP.lock().unwrap() = Some(endpoint);
    link.up.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(hello)
}

#[tauri::command]
async fn rpc(state: State<'_, AppState>, method: String, params: serde_json::Value) -> Result<serde_json::Value, String> {
    // 잠금은 Arc 를 꺼낼 때만 잡는다
    let c = state.client.lock().unwrap().clone().ok_or_else(|| "not connected".to_string())?;
    tauri::async_runtime::spawn_blocking(move || c.call(&method, params, Duration::from_secs(10))).await.map_err(|e| e.to_string())?
}

/// 이 UI 가 승격(관리자) 상태인가 — 변경 단추를 쓸 수 있는지 화면에 보여 준다
#[tauri::command]
fn elevated() -> bool {
    elevate::is_elevated()
}

/// 승인 도우미를 UAC 로 띄우고 끝날 때까지 기다린다 (A23). 반환: 도우미 종료 코드 (approve::EXIT_*)
/// UI 를 통째로 승격하지 않는다: WebView2 호스트는 일반 권한에 두라는 Microsoft 권고 (WebView2 보안 문서)
#[tauri::command]
async fn approve(change_id: String) -> Result<i32, String> {
    if !approve::is_uuid(&change_id) {
        return Err("change_id 형식".into());
    }
    tauri::async_runtime::spawn_blocking(move || elevate::run_helper(&change_id)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
fn endpoint(state: State<'_, AppState>) -> Option<String> {
    state.client.lock().unwrap().as_ref().map(|c| c.endpoint.clone())
}

pub fn run() {
    tauri::Builder::default()
        // 가장 먼저 등록해야 한다(플러그인 문서). 승인 도우미(--approve)는 main 에서 이 앞에 끝나므로 막히지 않는다
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !args.iter().any(|a| a == "--tray") {
                tray::show_main(app);
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![connect, rpc, endpoint, elevated, approve])
        .on_window_event(|w, e| {
            // 닫기(X) = 트레이로 숨김. 끝내기는 트레이 메뉴 (A28)
            if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                if w.label() == "main" {
                    api.prevent_close();
                    let _ = w.hide();
                }
            }
        })
        .setup(|app| {
            tray::install(app)?;
            if tray::started_in_tray() {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            let link = app.state::<AppState>().link.clone();
            tray::spawn_watchdog(app.handle().clone(), link);
            // L061: 브라우저 금고 경비의 미끼 폴더를 **사용자 권한**으로 만든다(서비스는 읽기만 해서 등록).
            // 실제 프로그램 폴더가 있으면 건드리지 않고, 나중에 그 프로그램이 들어오면 우리 파일만 지우고 물러난다
            std::thread::spawn(|| {
                if let Some(home) = std::env::var_os("USERPROFILE") {
                    let _ = decoy::ensure(std::path::Path::new(&home));
                }
            });
            // 배포 빌드에서는 개발자 도구를 열지 않는다 (14차 Q4)
            #[cfg(debug_assertions)]
            if let Some(w) = app.get_webview_window("main") {
                w.open_devtools();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("tauri");
}
