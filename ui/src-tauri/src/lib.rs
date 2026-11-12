//! Tauri 코어: 프런트는 `invoke` 로만 서비스에 닿는다 (파이프에 직접 붙지 않음, 14차 4-1).
//! 명령: connect(endpoint) / rpc(method, params). 알림은 `svc-notify` 이벤트로 프런트에 보낸다.

pub mod approve;
#[cfg(windows)]
pub mod approve_win;
mod client;
pub mod elevate;
pub mod hud;
pub mod rack;
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
    probe_service_at(&probe_endpoint())
}

/// 감시·HUD 가 붙을 끝점: 화면이 마지막으로 붙은 곳(없으면 파이프)
pub(crate) fn probe_endpoint() -> String {
    PROBE_EP.lock().unwrap().clone().unwrap_or_else(|| "pipe".to_string())
}

/// events.new 중 원격 세션 시작이면 알림 본문(서비스가 만든 사실 문장)
fn remote_session_toast(v: &serde_json::Value) -> Option<(String, bool)> {
    if v.get("method").and_then(|m| m.as_str()) != Some("events.new") {
        return None;
    }
    let p = v.get("params")?;
    // 34차 Q3: RDP 섀도·세션 가로채기도 같은 즉시 알림(새 세션 없이 붙는 원격 조작)
    if !matches!(p.get("kind").and_then(|k| k.as_str()), Some("remote_session_start" | "rdp_shadow" | "rdp_hijack")) {
        return None;
    }
    // 문장에는 외부에서 온 이름이 섞이지 않는다(도구 표시 이름은 서비스 목록의 상수) — 길이만 자른다
    let body: String = p.get("detail").and_then(|d| d.as_str()).unwrap_or("").chars().take(240).collect();
    Some((body, p.get("severity").and_then(|s| s.as_u64()).unwrap_or(3) >= 3))
}

/// 실시간 2(사용자 "실시간으로 문제를 찾아야 바로 해결가능함" 2026-11-07, 제품): 새 의심 사건(장이 올라갈 때만 — 서비스 should_notify)을
/// 창을 열지 않아도 Windows 알림으로. 설정에서 끌 수 있다(기본 켬, 화면이 시작할 때 알려 준다)
static STORY_TOAST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

#[tauri::command]
fn set_story_toast(on: bool) {
    STORY_TOAST.store(on, std::sync::atomic::Ordering::SeqCst);
}

/// 의심 사건 알림 → (제목, 본문). 프로그램 이름은 외부에서 온 문자열이라 자료로만: 제어·방향 바꿈(RLO 등) 문자를 빼고 길이를 자른다.
/// 의도를 단정하지 않는다 — 어느 장까지 이어졌는지 사실만
pub(crate) fn story_toast(v: &serde_json::Value) -> Option<(String, String)> {
    if v.get("method").and_then(|m| m.as_str()) != Some("events.new") {
        return None;
    }
    let p = v.get("params")?;
    if p.get("kind").and_then(|k| k.as_str()) != Some("story_suspicious") {
        return None;
    }
    let label: String = p.get("label").and_then(|l| l.as_str()).unwrap_or("").chars().filter(|c| !c.is_control() && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')).take(80).collect();
    let label = if label.is_empty() { "알 수 없는 프로그램".to_string() } else { label };
    let ch = match p.get("chapter").and_then(|c| c.as_i64()).unwrap_or(0) {
        1 => "1장 유입",
        2 => "2장 실행",
        3 => "3장 자리잡기",
        4 => "4장 외부 접속",
        5 => "5장 파괴 징후",
        _ => "",
    };
    let body = if ch.is_empty() { "트레이 아이콘을 눌러 '이야기'에서 확인하세요.".to_string() } else { format!("{ch}까지 이어졌습니다. 트레이 아이콘을 눌러 '이야기'에서 확인하세요.") };
    Some((format!("의심 사건: {label}"), body))
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
            // 14판 20-4: 원격 제어 세션 시작은 창을 열지 않아도 바로 Windows 알림(조용함 원칙의 예외)
            // 33차 Gemini Q4: 사용자가 "내가 쓰는 원격 도구"로 표시한 도구만 "알림"으로 낮춘다(알림 자체는 끄지 않음)
            if let Some((body, alarm)) = remote_session_toast(&v) {
                notify(&app2, if alarm { "원격 제어 경보" } else { "원격 제어 알림 (내가 쓰는 도구)" }, &body);
            }
            if STORY_TOAST.load(std::sync::atomic::Ordering::SeqCst) {
                if let Some((title, body)) = story_toast(&v) {
                    notify(&app2, &title, &body);
                }
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

/// 공개 빌드에서만 업데이트를 쓴다(릴리스 워크플로가 SF_UPDATER=1 로 빌드). 개발 빌드는 늘 꺼짐 —
/// 개발판이 공개판으로 덮어써지지 않게
fn updater_on() -> bool {
    option_env!("SF_UPDATER") == Some("1")
}

#[tauri::command]
fn update_enabled() -> bool {
    updater_on()
}

/// 새 판 확인: GitHub Releases 의 latest.json 한 번. 새 판이 없으면 null
#[tauri::command]
async fn update_check(app: tauri::AppHandle) -> Result<Option<serde_json::Value>, String> {
    if !updater_on() {
        return Ok(None);
    }
    use tauri_plugin_updater::UpdaterExt;
    let u = app.updater().map_err(|e| e.to_string())?;
    Ok(u.check().await.map_err(|e| e.to_string())?.map(|up| {
        serde_json::json!({ "version": up.version, "current": up.current_version, "notes": up.body, "date": up.date.map(|d| d.to_string()) })
    }))
}

/// 받고 → 서명(minisign, 앱에 박힌 공개 키) 검사 → 설치 프로그램 실행(passive, UAC 한 번). 서명이 맞지 않으면 설치하지 않는다
#[tauri::command]
async fn update_install(app: tauri::AppHandle) -> Result<(), String> {
    if !updater_on() {
        return Err("이 빌드에서는 업데이트를 쓰지 않습니다".into());
    }
    use tauri_plugin_updater::UpdaterExt;
    let u = app.updater().map_err(|e| e.to_string())?;
    let up = u.check().await.map_err(|e| e.to_string())?.ok_or_else(|| "새 판이 없습니다".to_string())?;
    up.download_and_install(|_, _| {}, || {}).await.map_err(|e| e.to_string())
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
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![connect, rpc, endpoint, elevated, approve, update_enabled, update_check, update_install, set_story_toast, hud::hud_state, hud::hud_mode, hud::set_hud_mode, hud::hud_last, hud::open_main, rack::netx_registered, rack::netx_diagnose])
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
            tray::spawn_watchdog(app.handle().clone(), link.clone());
            // 대시보드 개편안 3판 4-1 HUD ②: 트레이 아이콘 점 색·툴팁(미조치 심각·높음, 최근 사건, 긴급 차단)
            hud::spawn(app.handle().clone(), link);
            // HUD ①(작은 상시 창)을 고른 사용자면 바로 연다
            // setup 안에서 바로 만들면 본 창과 같은 순간에 WebView2 를 만든다 → 별도 스레드에서(Tauri 문서 권고)
            let h = app.handle().clone();
            std::thread::spawn(move || {
                let mode = hud::read_mode(&h);
                hud::apply_mode(&h, &mode);
            });
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

#[cfg(test)]
mod tests {
    use super::story_toast;
    #[test]
    fn story_toast_only_for_suspicious_story_and_strips_control_chars() {
        let v = serde_json::json!({"method": "events.new", "params": {"kind": "story_suspicious", "label": "pay\u{202e}load.exe", "chapter": 4}});
        let (t, b) = story_toast(&v).unwrap();
        assert_eq!(t, "의심 사건: payload.exe");
        assert!(b.starts_with("4장 외부 접속까지 이어졌습니다"));
        let other = serde_json::json!({"method": "events.new", "params": {"kind": "remote_session_start"}});
        assert!(story_toast(&other).is_none());
    }
}
