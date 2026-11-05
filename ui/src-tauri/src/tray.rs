//! 트레이·자동 시작·서비스 끊김 감시 (A28, 21차 Q3).
//!
//! - 설치 프로그램이 HKLM Run 에 `story-firewall-ui.exe --tray` 를 등록한다 → 로그온하면 창 없이 트레이에만 뜬다.
//! - 창의 닫기(X)는 트레이로 숨긴다. 끝내기는 트레이 메뉴의 "종료"로만.
//! - 서비스 연결이 30초 넘게 끊겨 있으면 알림을 한 번 띄운다(보호가 멈췄을 수 있음). 다시 닿으면 화면에 `svc-available` 을 보내
//!   프런트가 다시 연결한다. 끊김 감시는 프런트가 아니라 여기서 한다 — 숨긴 창의 스크립트는 타이머가 늦춰질 수 있다.
//!
//! 탐지(probe)는 같은 끝점에 새로 붙어 hello 만 하고 놓는다. 서비스 쪽에서는 서명 검사를 통과한 짧은 연결 하나다.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};

/// 끊김 알림까지 기다리는 시간
pub const DOWN_NOTIFY_AFTER: Duration = Duration::from_secs(30);
/// 끊긴 동안 다시 닿는지 보는 간격
pub const PROBE_EVERY: Duration = Duration::from_secs(10);
/// 끊김 알림(토스트) 사이 최소 간격 (22차 S1·Q4: 끊겼다 붙었다를 반복시켜 알림으로 사용자를 지치게 하는 것 방지).
/// 그 사이의 끊김은 트레이 툴팁·화면 상태 표시줄로만 보인다
pub const NOTIFY_MIN_GAP: Duration = Duration::from_secs(10 * 60);
/// 끊긴 뒤 첫 probe 까지 (시작 직후 화면이 붙기 전에 쓸데없는 연결을 만들지 않게)
pub const PROBE_GRACE: Duration = Duration::from_secs(5);

/// 서비스 연결 상태 (connect 성공 = true, client.disconnected = false)
#[derive(Default)]
pub struct Link {
    pub up: AtomicBool,
}

/// `--tray` 로 시작했는가 (자동 시작)
pub fn started_in_tray() -> bool {
    std::env::args().any(|a| a == "--tray")
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn install(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "열기", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "종료 (보호는 서비스가 계속합니다)", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut b = TrayIconBuilder::with_id("main")
        .tooltip("Story Firewall")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id.as_ref() {
            "open" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        b = b.icon(icon.clone());
    }
    b.build(app)?;
    Ok(())
}

/// 끊김 감시 스레드. `probe` = 서비스에 닿는지 (새 연결 + hello). `notify` = 알림 띄우기.
/// 트레이 툴팁으로 상태를 늘 보여 준다 (토스트는 드물게, 상태는 늘)
fn set_tray_state(app: &AppHandle, up: bool) {
    if let Some(t) = app.tray_by_id("main") {
        let _ = t.set_tooltip(Some(if up { "Story Firewall — 보호 중" } else { "Story Firewall — 서비스 연결 끊김" }));
    }
}

pub fn spawn_watchdog(app: AppHandle, link: Arc<Link>) {
    std::thread::spawn(move || {
        watchdog_loop(
            &link,
            || crate::probe_service(),
            |title, body| crate::notify(&app, title, body),
            || {
                let _ = app.emit("svc-available", ());
            },
            |up| set_tray_state(&app, up),
            Duration::from_secs(1),
            None,
        )
    });
}

/// 감시 본체 (시험 가능하게 분리). `tick` 마다 상태를 본다. `max_ticks` 가 있으면 그만큼 돌고 끝낸다(시험용).
pub fn watchdog_loop(
    link: &Link,
    mut probe: impl FnMut() -> bool,
    mut notify: impl FnMut(&str, &str),
    mut available: impl FnMut(),
    mut state: impl FnMut(bool),
    tick: Duration,
    max_ticks: Option<u64>,
) {
    let mut down_since: Option<Instant> = None;
    let mut notified = false;
    let mut last_notice: Option<Instant> = None;
    let mut shown: Option<bool> = None;
    let mut last_probe: Option<Instant> = None;
    let mut n = 0u64;
    loop {
        if max_ticks.is_some_and(|m| n >= m) {
            return;
        }
        n += 1;
        std::thread::sleep(tick);
        let up = link.up.load(Ordering::SeqCst);
        if shown != Some(up) {
            state(up);
            shown = Some(up);
        }
        if up {
            if notified {
                notify("Story Firewall", "서비스에 다시 연결되었습니다.");
            }
            down_since = None;
            notified = false;
            continue;
        }
        let since = *down_since.get_or_insert_with(Instant::now);
        if !notified && since.elapsed() >= DOWN_NOTIFY_AFTER && last_notice.is_none_or(|t| t.elapsed() >= NOTIFY_MIN_GAP) {
            last_notice = Some(Instant::now());
            notify("Story Firewall — 서비스 연결 끊김", "보호 서비스에 30초 넘게 연결되지 않습니다. 차단 정책은 Windows 에 남아 있지만 새 기록·판정이 멈췄을 수 있습니다.");
            notified = true;
        }
        if since.elapsed() >= PROBE_GRACE && last_probe.is_none_or(|t| t.elapsed() >= PROBE_EVERY) {
            last_probe = Some(Instant::now());
            if probe() {
                // 화면이 다시 붙으면 connect 가 up 을 세운다
                available();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_notifies_once_after_threshold_and_probes() {
        // 상수(30초·5초)는 줄이지 않는다: 짧게 돌리면 "임계 전에는 알리지도 probe 하지도 않음"을 보고,
        // 유예(5초) 넘게 돌리면 probe 가 불리는지 본다
        let link = Link::default();
        let mut notes = vec![];
        let mut probes = 0;
        watchdog_loop(&link, || { probes += 1; false }, |t, _| notes.push(t.to_string()), || {}, |_| {}, Duration::from_millis(1), Some(5));
        assert!(notes.is_empty(), "30초 전에는 알림 없음: {notes:?}");
        assert_eq!(probes, 0, "유예 전에는 probe 없음");
        let mut avail = 0;
        watchdog_loop(&link, || { probes += 1; true }, |t, _| notes.push(t.to_string()), || avail += 1, |_| {}, Duration::from_millis(1100), Some(6));
        assert!(probes >= 1 && avail >= 1, "유예 뒤 probe → available ({probes}, {avail})");
        assert!(notes.is_empty());
        // 연결됨이면 알림·probe 없음
        let link = Link::default();
        link.up.store(true, Ordering::SeqCst);
        let mut probes2 = 0;
        let mut states = vec![];
        watchdog_loop(&link, || { probes2 += 1; true }, |_, _| panic!("알림 없어야"), || {}, |u| states.push(u), Duration::from_millis(1), Some(5));
        assert_eq!(probes2, 0);
        assert_eq!(states, vec![true], "상태는 바뀔 때만 한 번");
    }
}
