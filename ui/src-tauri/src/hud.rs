//! HUD (대시보드 개편안 3판 4-1, 사용자 결정 2026-11-07·승인 2026-11-08) — ② 트레이 아이콘 방식.
//!
//! - 트레이 아이콘 오른쪽 아래에 점: 빨강 = 미조치 심각, 주황 = 미조치 높음, 초록 = 없음, 회색 = 서비스 연결 끊김.
//! - 툴팁: 보호 상태 · 미조치 심각/높음 수 · 가장 최근 사건 한 줄 · 긴급 차단 중이면 남은 시간.
//! - 창을 숨긴 동안 화면 스크립트 타이머가 늦춰질 수 있어(tray.rs 주석) 상태 조회는 여기서(Rust) 직접 서비스에 묻는다.
//! - 문장에는 외부에서 온 이름(파일명)이 섞일 수 있어 길이를 자르고 제어 문자를 뺀다. 툴팁 상한 127자(NOTIFYICONDATAW.szTip).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::{Emitter, Manager};

/// 갱신 간격(서비스가 붙어 있을 때)
pub const REFRESH_EVERY: Duration = Duration::from_secs(20);
/// Windows 트레이 툴팁 상한(문자 수, NUL 제외)
pub const TIP_MAX: usize = 127;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Critical,
    High,
    Ok,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HudState {
    pub tone: Tone,
    pub critical: usize,
    pub high: usize,
    pub latest: Option<String>,
    /// 긴급 차단 남은 분(걸려 있을 때)
    pub emergency_left_min: Option<i64>,
}

fn clean(s: &str, max: usize) -> String {
    let t: String = s.chars().filter(|c| !c.is_control()).collect();
    // 제목 앞의 "[심각] " 같은 칩 글자는 숫자로 이미 보이므로 뺀다
    let t = t.trim();
    let t = match (t.starts_with('['), t.find("] ")) {
        (true, Some(i)) => &t[i + 2..],
        _ => t,
    };
    if t.chars().count() > max {
        let mut o: String = t.chars().take(max.saturating_sub(1)).collect();
        o.push('…');
        o
    } else {
        t.to_string()
    }
}

/// story.events(level_min=suspicious, triage=open) 응답 + emergency.status 응답 → 상태
pub fn summarize(events: &serde_json::Value, emergency: &serde_json::Value) -> HudState {
    // 대시보드 "미조치 심각·높음"과 같은 기준: 오늘 새 활동이 있는 것만(fresh != false), 수준은 대소문자 무관
    let items: Vec<serde_json::Value> = events
        .get("items")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter(|x| x["fresh"] != serde_json::json!(false)).cloned().collect())
        .unwrap_or_default();
    let lv = |x: &serde_json::Value| x["level"].as_str().unwrap_or("").to_ascii_lowercase();
    let critical = items.iter().filter(|x| lv(x) == "critical").count();
    let high = items.iter().filter(|x| lv(x) == "suspicious").count();
    // 가장 최근(last_ts 큰 것) 하나
    let latest = items
        .iter()
        .max_by_key(|x| x["last_ts"].as_i64().unwrap_or(0))
        .and_then(|x| x["title"].as_str())
        .map(|t| clean(t, 48));
    let emergency_left_min = (emergency["active"] == serde_json::json!(true))
        .then(|| (emergency["remaining_secs"].as_i64().unwrap_or(0).max(0) + 59) / 60);
    let tone = if critical > 0 {
        Tone::Critical
    } else if high > 0 {
        Tone::High
    } else {
        Tone::Ok
    };
    HudState { tone, critical, high, latest, emergency_left_min }
}

pub fn tooltip(st: &HudState) -> String {
    let mut t = match st.tone {
        Tone::Down => "Story Firewall — 서비스 연결 끊김".to_string(),
        _ if st.critical + st.high == 0 => "Story Firewall — 보호 중 · 미조치 심각·높음 없음".to_string(),
        _ => format!("Story Firewall — 미조치 심각 {} · 높음 {}", st.critical, st.high),
    };
    if st.tone != Tone::Down {
        if let Some(m) = st.emergency_left_min {
            t.push_str(&format!("\n긴급 차단 중 · {m}분 남음"));
        }
        if let Some(l) = &st.latest {
            t.push_str(&format!("\n최근: {l}"));
        }
    }
    if t.chars().count() > TIP_MAX {
        t = t.chars().take(TIP_MAX - 1).collect::<String>() + "…";
    }
    t
}

/// 작은 상시 창(HUD ①)에 보낼 상태 JSON
pub fn state_json(st: &HudState) -> serde_json::Value {
    serde_json::json!({
        "tone": match st.tone { Tone::Critical => "critical", Tone::High => "high", Tone::Ok => "ok", Tone::Down => "down" },
        "critical": st.critical,
        "high": st.high,
        "latest": st.latest,
        "emergency_left_min": st.emergency_left_min,
    })
}

/// 점 색(RGBA). 색만으로 뜻을 전하지 않도록 툴팁에 같은 내용이 있다
pub fn tone_color(t: Tone) -> [u8; 4] {
    match t {
        Tone::Critical => [0xC8, 0x10, 0x2E, 0xFF],
        // 검수 2026-11-08: 높음은 빨강 계열(대시보드 --bad), 주황은 "주의"에만(UI 명세 2판 2-1). 점 색 + 툴팁 글자로 구분
        Tone::High => [0xFF, 0x6B, 0x6B, 0xFF],
        Tone::Ok => [0x22, 0xC5, 0x5E, 0xFF],
        Tone::Down => [0x8A, 0x8F, 0x98, 0xFF],
    }
}

/// 아이콘 RGBA(w×h) 오른쪽 아래에 지름 w·0.45 의 점(어두운 테두리 1px)을 찍은 복사본
pub fn badge_rgba(base: &[u8], w: u32, h: u32, color: [u8; 4]) -> Vec<u8> {
    let mut out = base.to_vec();
    if out.len() != (w * h * 4) as usize || w == 0 || h == 0 {
        return out;
    }
    let d = (w.min(h) as f32 * 0.45).max(6.0);
    let r = d / 2.0;
    let cx = w as f32 - r - 0.5;
    let cy = h as f32 - r - 0.5;
    for y in 0..h {
        for x in 0..w {
            let dx = x as f32 + 0.5 - cx;
            let dy = y as f32 + 0.5 - cy;
            let dist = (dx * dx + dy * dy).sqrt();
            let px = ((y * w + x) * 4) as usize;
            if dist <= r - 1.0 {
                out[px..px + 4].copy_from_slice(&color);
            } else if dist <= r {
                out[px..px + 4].copy_from_slice(&[0x10, 0x12, 0x16, 0xFF]);
            }
        }
    }
    out
}

/// 마지막 상태(상시 창이 처음 열릴 때 바로 그리게)
static LAST: Mutex<Option<HudState>> = Mutex::new(None);

/// HUD 방식: "tray"(② 트레이 아이콘만, 기본) | "window"(① 작은 상시 창 + 트레이). 사용자별 설정 파일에 둔다(자동 시작 때도 적용)
fn mode_file(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    app.path().app_config_dir().ok().map(|d| d.join("hud-mode.txt"))
}

pub fn read_mode(app: &tauri::AppHandle) -> String {
    mode_file(app)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| s == "window")
        .unwrap_or_else(|| "tray".into())
}

/// 마지막 상시 창 열기·닫기 결과(설정 화면에 보여 준다 — install-111: 창이 안 떠도 이유가 어디에도 남지 않았다)
static LAST_APPLY: Mutex<String> = Mutex::new(String::new());
/// 창 이름 일련번호: 막 destroy 한 창 이름이 아직 남아 있으면 같은 이름으로 다시 만들 때 실패한다 → 매번 새 이름(hud-N)
static HUD_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn note(msg: String) {
    if let Ok(mut g) = LAST_APPLY.lock() {
        *g = msg;
    }
}

/// HUD 창(이름이 "hud" 로 시작)을 모두 찾는다
fn hud_windows(app: &tauri::AppHandle) -> Vec<tauri::WebviewWindow> {
    app.webview_windows().into_iter().filter(|(k, _)| k.starts_with("hud")).map(|(_, w)| w).collect()
}

/// 상시 창을 열거나 닫는다. 창은 서비스에 붙지 않고 `hud-state` 이벤트만 그린다(권한 최소)
pub fn apply_mode(app: &tauri::AppHandle, mode: &str) {
    let existing = hud_windows(app);
    if mode != "window" {
        // close() 는 빈 창(페이지를 못 읽은 창)에서 듣지 않았다(install-109 실측) → destroy
        let n = existing.len();
        for w in existing {
            let _ = w.destroy();
        }
        note(format!("상시 창 닫음({n}개)"));
        return;
    }
    if !existing.is_empty() {
        note("상시 창이 이미 열려 있음".into());
        return;
    }
    // install-109 실측: "index.html#hud" 는 앱 URL 에서 해시가 경로로 바뀌어 빈 창이 됐다 → 주소는 그대로, 창 이름(hud…)으로 알아본다.
    // 위치는 만들 때 논리 좌표로(만든 뒤 set_position 은 왼쪽 위에 그대로 있었다)
    let (w_l, h_l) = (340.0, 84.0); // 검수: 최근 인시던트 줄이 잘려 넓힘([열기] 단추 없앰 — 창을 누르면 열림)
    let label = format!("hud-{}", HUD_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let mut b = tauri::WebviewWindowBuilder::new(app, &label, tauri::WebviewUrl::App("index.html".into()))
        .title("Story Firewall HUD")
        .inner_size(w_l, h_l)
        .resizable(false)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .focused(false);
    // install-112 실측: 0x8007139F(올바른 상태 아님) — 본 창은 additionalBrowserArgs(외부 통신 줄임)를 쓰는데
    // 같은 사용자 데이터 폴더에서 다른 인자로 WebView2 환경을 만들면 실패한다 → 본 창 설정의 인자를 그대로 쓴다
    if let Some(args) = app.config().app.windows.first().and_then(|w| w.additional_browser_args.clone()) {
        b = b.additional_browser_args(&args);
    }
    let mut pos = String::from("위치 기본값");
    if let Ok(Some(m)) = app.primary_monitor() {
        let sc = m.scale_factor();
        let (mw, mh) = (m.size().width as f64 / sc, m.size().height as f64 / sc);
        let (x, y) = ((mw - w_l - 16.0).max(0.0), (mh - h_l - 64.0).max(0.0));
        b = b.position(x, y);
        pos = format!("위치 {x:.0},{y:.0}(배율 {sc})");
    }
    match b.build() {
        Ok(_) => note(format!("상시 창 만듦: {label} · {pos}")),
        Err(e) => note(format!("상시 창을 만들지 못함: {e}")),
    }
}

/// 마지막 열기·닫기 결과(설정 화면 표시용)
#[tauri::command]
pub fn hud_last() -> String {
    LAST_APPLY.lock().map(|g| g.clone()).unwrap_or_default()
}

#[tauri::command]
pub fn hud_state() -> serde_json::Value {
    LAST.lock()
        .ok()
        .and_then(|g| g.as_ref().map(state_json))
        .unwrap_or_else(|| serde_json::json!({"tone": "down", "critical": 0, "high": 0, "latest": null, "emergency_left_min": null}))
}

#[tauri::command]
pub fn hud_mode(app: tauri::AppHandle) -> String {
    read_mode(&app)
}

/// install-110 실측: 동기 명령 안에서 창을 만들면 Windows(WebView2)에서 교착되어 빈 흰 창만 남는다
/// (Tauri 문서 Known issues: "async 명령에서 창을 만들 것") → async 명령으로 둔다
#[tauri::command]
pub async fn set_hud_mode(app: tauri::AppHandle, mode: String) -> Result<(), String> {
    if mode != "tray" && mode != "window" {
        return Err("mode 는 tray|window".into());
    }
    if let Some(p) = mode_file(&app) {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::write(&p, &mode).map_err(|e| e.to_string())?;
    }
    apply_mode(&app, &mode);
    Ok(())
}

#[tauri::command]
pub fn open_main(app: tauri::AppHandle) {
    crate::tray::show_main(&app);
}

/// 갱신 스레드: 서비스가 붙어 있으면 REFRESH_EVERY 마다 상태를 묻고 아이콘·툴팁을 바꾼다. 상태가 같으면 그대로 둔다
pub fn spawn(app: tauri::AppHandle, link: Arc<crate::tray::Link>) {
    std::thread::spawn(move || {
        let mut last: Option<HudState> = None;
        loop {
            let st = if link.up.load(Ordering::SeqCst) {
                query().unwrap_or(HudState { tone: Tone::Down, critical: 0, high: 0, latest: None, emergency_left_min: None })
            } else {
                HudState { tone: Tone::Down, critical: 0, high: 0, latest: None, emergency_left_min: None }
            };
            if last.as_ref() != Some(&st) {
                apply(&app, &st);
                if let Ok(mut g) = LAST.lock() {
                    *g = Some(st.clone());
                }
                let _ = app.emit("hud-state", state_json(&st));
                last = Some(st);
            }
            std::thread::sleep(REFRESH_EVERY);
        }
    });
}

/// JSON-RPC 응답 봉투 → result (error 면 None)
pub fn result_of(v: serde_json::Value) -> Option<serde_json::Value> {
    if v.get("error").is_some_and(|e| !e.is_null()) {
        return None;
    }
    v.get("result").cloned()
}

fn query() -> Option<HudState> {
    let ep = crate::probe_endpoint();
    let c = crate::client::Client::connect(&ep, Box::new(|_| {})).ok()?;
    let t = Duration::from_secs(5);
    c.call("rpc.hello", serde_json::json!({"client_version": env!("CARGO_PKG_VERSION"), "api": [1, 0]}), t).ok()?;
    // install-113 실측: call 은 응답 봉투 전체({"jsonrpc","id","result"|"error"})를 돌려준다 —
    // 봉투에서 바로 items 를 찾아 늘 0건("보호 중")이 됐다 → result 를 꺼내고, error 면 끊김으로 본다
    let ev = result_of(c.call("story.events", serde_json::json!({"level_min": "suspicious", "triage": "open", "cursor": {"limit": 200}}), t).ok()?)?;
    let em = c.call("emergency.status", serde_json::json!({}), t).ok().and_then(result_of).unwrap_or_default();
    Some(summarize(&ev, &em))
}

fn apply(app: &tauri::AppHandle, st: &HudState) {
    let Some(tray) = app.tray_by_id("main") else { return };
    let _ = tray.set_tooltip(Some(tooltip(st)));
    if let Some(base) = app.default_window_icon() {
        let (w, h) = (base.width(), base.height());
        let rgba = badge_rgba(base.rgba(), w, h, tone_color(st.tone));
        let _ = tray.set_icon(Some(tauri::image::Image::new_owned(rgba, w, h)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(items: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "items": items })
    }

    #[test]
    fn tone_and_counts_follow_open_critical_and_high() {
        let e = ev(serde_json::json!([
            {"level": "Suspicious", "title": "[높음] a.exe — 4장", "last_ts": 10},
            {"level": "Critical", "title": "[심각] invoice-viewer.exe — 5장 파괴 행위까지 진행", "last_ts": 30},
            {"level": "Suspicious", "title": "[높음] b.exe", "last_ts": 20},
        ]));
        let st = summarize(&e, &serde_json::json!({"active": false}));
        assert_eq!((st.tone, st.critical, st.high), (Tone::Critical, 1, 2));
        assert_eq!(st.latest.as_deref(), Some("invoice-viewer.exe — 5장 파괴 행위까지 진행"));
        let st = summarize(&ev(serde_json::json!([{"level": "Suspicious", "title": "x", "last_ts": 1}])), &serde_json::json!({}));
        assert_eq!(st.tone, Tone::High);
        let st = summarize(&ev(serde_json::json!([])), &serde_json::json!({"active": false}));
        assert_eq!(st.tone, Tone::Ok);
        // 소문자 수준·오늘 새 활동 없는 것(fresh=false)은 빼기
        let st2 = summarize(&ev(serde_json::json!([
            {"level": "critical", "title": "c", "last_ts": 1},
            {"level": "Suspicious", "title": "old", "last_ts": 2, "fresh": false},
        ])), &serde_json::json!({}));
        assert_eq!((st2.critical, st2.high), (1, 0));
        // 응답 봉투에서 result 꺼내기 · error 는 None
        assert_eq!(result_of(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"items": []}})), Some(serde_json::json!({"items": []})));
        assert_eq!(result_of(serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -1}})), None);
        assert_eq!(tooltip(&st), "Story Firewall — 보호 중 · 미조치 심각·높음 없음");
    }

    #[test]
    fn tooltip_has_emergency_and_is_capped() {
        let long = "가".repeat(300);
        let e = ev(serde_json::json!([{"level": "Critical", "title": format!("[심각] {long}\u{7}"), "last_ts": 1}]));
        let st = summarize(&e, &serde_json::json!({"active": true, "remaining_secs": 61}));
        assert_eq!(st.emergency_left_min, Some(2));
        let t = tooltip(&st);
        assert!(t.contains("긴급 차단 중 · 2분 남음"), "{t}");
        assert!(t.chars().count() <= TIP_MAX, "{}", t.chars().count());
        assert!(!t.chars().any(|c| c == '\u{7}'));
        let down = HudState { tone: Tone::Down, critical: 3, high: 0, latest: Some("x".into()), emergency_left_min: Some(5) };
        assert_eq!(tooltip(&down), "Story Firewall — 서비스 연결 끊김");
    }

    #[test]
    fn badge_paints_bottom_right_only() {
        let (w, h) = (32u32, 32u32);
        let base = vec![0u8; (w * h * 4) as usize];
        let out = badge_rgba(&base, w, h, tone_color(Tone::Critical));
        let px = |x: u32, y: u32| &out[((y * w + x) * 4) as usize..((y * w + x) * 4 + 4) as usize];
        assert_eq!(px(0, 0), &[0, 0, 0, 0], "왼쪽 위는 그대로");
        assert_eq!(px(w - 8, h - 8), &tone_color(Tone::Critical), "오른쪽 아래 점");
        // 크기가 안 맞으면 그대로 돌려준다
        assert_eq!(badge_rgba(&[1, 2, 3], 2, 2, [9, 9, 9, 9]), vec![1, 2, 3]);
    }
}
