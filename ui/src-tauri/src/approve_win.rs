//! 승인 창 (A24): MessageBox 대신 자체 Win32 창. 클릭재킹(18차 답변 시나리오 1) 대비.
//!
//! 위협: 일반 권한 악성코드가 승인 창 위에 투명한(WS_EX_LAYERED·WS_EX_TRANSPARENT) 최상위 창을 덮고 그럴듯한 그림을 그린다.
//! 사용자의 **진짜** 마우스 클릭은 투명 창을 지나 아래의 "적용"에 닿는다 — 주입된 입력이 아니므로 UIPI 가 막지 않는다.
//! (UIPI 는 SendInput·창 메시지 같은 **주입**을 막을 뿐, 사람의 클릭이 어느 창에 닿는지는 막지 않는다.)
//!
//! 대책 (드라이버 없이 가능한 범위):
//! 1. "적용" 단추는 창이 앞에 나온 뒤 1.5초가 지나야 켜진다. 창이 비활성이 되면 다시 꺼지고, 돌아오면 1.5초 뒤 다시 켜진다
//!    (덮개를 치우는 순간·두 번 클릭 유도에 바로 눌리지 않게).
//! 2. 적용을 누른 순간 (a) 이 창이 전경 창인지 (b) z-순서에서 이 창보다 위에 있는 다른 프로세스의 보이는 창이 이 창과 겹치는지
//!    검사한다. 투명·반투명 덮개도 "보이는 창"이라 걸린다. 걸리면 적용하지 않고 이유를 창 안에 적는다.
//! 3. 기본 단추는 "취소", Esc = 취소, Enter 는 포커스가 있는 단추만.
//!
//! 한계: 덮개가 클릭 직전에만 나타났다 사라지는 경우(수 ms)는 (2)의 순간 검사를 비켜갈 수 있다 — (1)의 지연이 그 창을 좁힌다.
//! 다른 프로세스가 자기 창을 우리 창 **아래**에 두고 승인 창 일부를 가리킬 수는 없다(아래 창은 안 보임).

use std::cell::RefCell;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows_sys::Win32::Graphics::Gdi::{CreateFontW, DeleteObject, GetSysColorBrush, IntersectRect, SetBkMode, SetTextColor, COLOR_WINDOW, HBRUSH, HDC, HFONT, TRANSPARENT};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const ID_APPLY: usize = 100;
/// IDCANCEL — Esc 가 IsDialogMessage 로 이 id 를 보낸다
const ID_CANCEL: usize = 2;
const TIMER_ARM: usize = 1;
/// 적용 단추가 켜지기까지 (창이 앞에 나온 뒤)
pub const ARM_MS: u32 = 1500;

struct St {
    apply: HWND,
    note: HWND,
    /// 회색으로 그릴 보조 글(바닥 줄·안내 줄)
    muted: Vec<HWND>,
    bold: HFONT,
    armed: bool,
    result: Option<bool>,
}
thread_local! {
    static ST: RefCell<Option<St>> = const { RefCell::new(None) };
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 창 프로시저는 다시 들어올 수 있다(EnableWindow·SetWindowText 가 메시지를 보냄). extern "system" 안의 panic 은 프로세스를
/// 끝내므로 이중 빌림은 panic 대신 건너뛴다.
fn with<R>(f: impl FnOnce(&mut St) -> R) -> Option<R> {
    ST.with(|s| {
        let mut b = s.try_borrow_mut().ok()?;
        b.as_mut().map(f)
    })
}

fn disarm(hwnd: HWND) {
    with(|s| {
        s.armed = false;
        unsafe { EnableWindow(s.apply, 0) };
    });
    unsafe { KillTimer(hwnd, TIMER_ARM) };
}

/// z-순서에서 `hwnd` 보다 위에 있고 겹치는 보이는 창이 있는가. `ignore_own` = 우리 프로세스의 창(편집 상자 툴팁 등)은 뺀다.
pub fn covered(hwnd: HWND, ignore_own: bool) -> bool {
    let mut me: RECT = unsafe { std::mem::zeroed() };
    if unsafe { GetWindowRect(hwnd, &mut me) } == 0 {
        return true;
    }
    let mypid = unsafe { GetCurrentProcessId() };
    let mut cur = unsafe { GetWindow(hwnd, GW_HWNDPREV) };
    let mut n = 0;
    while !cur.is_null() && n < 4096 {
        n += 1;
        if unsafe { IsWindowVisible(cur) } != 0 {
            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(cur, &mut pid) };
            if !(ignore_own && pid == mypid) {
                // 가상 데스크톱·일시 중단된 앱의 숨김(cloaked) 창은 화면에 없다
                let mut cloaked: u32 = 0;
                let hr = unsafe { DwmGetWindowAttribute(cur, DWMWA_CLOAKED as u32, &mut cloaked as *mut u32 as *mut _, 4) };
                if hr != 0 || cloaked == 0 {
                    let mut r: RECT = unsafe { std::mem::zeroed() };
                    let mut x: RECT = unsafe { std::mem::zeroed() };
                    if unsafe { GetWindowRect(cur, &mut r) } != 0 && unsafe { IntersectRect(&mut x, &r, &me) } != 0 {
                        return true;
                    }
                }
            }
        }
        cur = unsafe { GetWindow(cur, GW_HWNDPREV) };
    }
    false
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_TIMER if wp == TIMER_ARM => {
            KillTimer(hwnd, TIMER_ARM);
            with(|s| {
                s.armed = true;
                EnableWindow(s.apply, 1);
                // 켜지면 안내문을 지운다(가려짐 경고는 다시 눌렀을 때 새로 적힌다)
                SetWindowTextW(s.note, w("").as_ptr());
            });
            0
        }
        WM_ACTIVATE => {
            if (wp & 0xffff) as u32 == WA_INACTIVE {
                disarm(hwnd);
            } else {
                // 다시 앞에 나오면 잠시 뒤에 켠다
                SetTimer(hwnd, TIMER_ARM, ARM_MS, None);
            }
            DefWindowProcW(hwnd, msg, wp, lp)
        }
        WM_COMMAND => {
            let id = wp & 0xffff;
            if id == ID_APPLY {
                let armed = with(|s| s.armed).unwrap_or(false);
                if !armed {
                    return 0;
                }
                let fg = GetForegroundWindow() == hwnd;
                if !fg || covered(hwnd, true) {
                    let why = if !fg { "이 창이 맨 앞에 있지 않아" } else { "다른 프로그램의 창이 이 승인 창을 가리고 있어" };
                    with(|s| {
                        SetWindowTextW(s.note, w(&format!("{why} 적용하지 않았습니다. 가린 창을 닫거나 이 창을 눌러 앞으로 가져온 뒤 다시 누르세요.")).as_ptr());
                    });
                    disarm(hwnd);
                    SetTimer(hwnd, TIMER_ARM, ARM_MS, None);
                    return 0;
                }
                with(|s| s.result = Some(true));
                DestroyWindow(hwnd);
            } else if id == ID_CANCEL {
                with(|s| s.result = Some(false));
                DestroyWindow(hwnd);
            }
            // IDOK(Enter, 포커스가 단추가 아닐 때)는 무시: Enter 연타로 승인되지 않게
            0
        }
        WM_CLOSE => {
            with(|s| s.result = Some(false));
            DestroyWindow(hwnd);
            0
        }
        // 읽기 전용 EDIT·STATIC 은 기본이 회색 바탕 → 창 바탕(흰색)과 같게. 보조 글은 회색 글자
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT => {
            let hdc = wp as HDC;
            let child = lp as HWND;
            SetBkMode(hdc, TRANSPARENT as i32);
            let muted = with(|s| s.muted.contains(&child)).unwrap_or(false);
            if muted {
                SetTextColor(hdc, 0x0080_726B); // #6B7280 (COLORREF 는 BGR)
            }
            GetSysColorBrush(COLOR_WINDOW) as LRESULT
        }
        WM_DESTROY => {
            with(|s| {
                if !s.bold.is_null() {
                    DeleteObject(s.bold as _);
                }
            });
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

/// 창을 만들고 보여 준다 (메시지 루프는 호출자). 반환: (창, 글꼴)
pub fn create(title: &str, text: &str, apply_label: &str, cancel_label: &str) -> (HWND, HFONT) {
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let cls = w("StoryFirewallApprove");
        let mut wc: WNDCLASSEXW = std::mem::zeroed();
        wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinst;
        wc.hCursor = LoadCursorW(std::ptr::null_mut(), IDC_ARROW);
        wc.hbrBackground = (COLOR_WINDOW + 1) as usize as HBRUSH;
        wc.lpszClassName = cls.as_ptr();
        // 두 번째 창부터는 이미 등록됨(실패해도 됨)
        RegisterClassExW(&wc);
        // 2026-11-07 다듬기(사용자 "이 창 좀 잘"): 내용 길이에 맞춰 창 높이를 정하고(빈 공간 없이), 첫 줄은 굵은 머리글,
        // 본문은 테두리 없는 읽기 전용 상자, "요청한 프로그램" 은 회색 바닥 줄, 안내 줄에는 왜 '적용'이 잠깐 꺼져 있는지 적는다
        let norm = text.replace("\r\n", "\n");
        let (head, rest) = match norm.find("\n\n") {
            Some(i) => (norm[..i].to_string(), norm[i + 2..].to_string()),
            None => (String::new(), norm.clone()),
        };
        // 바닥 줄: 마지막 문단이 "요청한 프로그램:" 이면 본문에서 떼어 낸다
        let (body_txt, foot) = match rest.rfind("\n\n요청한 프로그램:") {
            Some(i) => (rest[..i].to_string(), rest[i + 2..].to_string()),
            None => (rest.clone(), String::new()),
        };
        let line_h = 22;
        let body_lines = body_txt.lines().count().max(1) as i32;
        let body_h = (body_lines * line_h + 16).clamp(3 * line_h, 14 * line_h);
        let need_scroll = body_lines * line_h + 16 > body_h;
        let ww = 720;
        let pad = 20;
        let head_h = if head.is_empty() { 0 } else { 30 };
        let foot_h = if foot.is_empty() { 0 } else { 24 };
        // 머리글 + 본문 + 바닥 줄 + 안내 줄(40) + 단추 줄(60) + 여백
        let wh = 36 + pad + head_h + 8 + body_h + 8 + foot_h + 8 + 40 + 60;
        let x = (GetSystemMetrics(SM_CXSCREEN) - ww) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - wh) / 2;
        let hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_DLGMODALFRAME, cls.as_ptr(), w(title).as_ptr(), WS_POPUP | WS_CAPTION | WS_SYSMENU, x, y, ww, wh, std::ptr::null_mut(), std::ptr::null_mut(), hinst, std::ptr::null());
        // 맑은 고딕 (없으면 시스템이 대체). 머리글은 굵게
        let font = CreateFontW(-15, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, w("Malgun Gothic").as_ptr());
        let bold = CreateFontW(-17, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0, w("Malgun Gothic").as_ptr());
        let child = |class: &str, txt: &str, style: u32, ex: u32, x: i32, y: i32, cw: i32, ch: i32, id: usize, f: HFONT| -> HWND {
            let h = CreateWindowExW(ex, w(class).as_ptr(), w(txt).as_ptr(), WS_CHILD | WS_VISIBLE | style, x, y, cw, ch, hwnd, id as _, hinst, std::ptr::null());
            SendMessageW(h, WM_SETFONT, f as usize, 1);
            h
        };
        let mut cy = pad;
        if !head.is_empty() {
            child("STATIC", &head, 0, 0, pad, cy, ww - 2 * pad - 16, head_h, 12, bold);
            cy += head_h + 8;
        }
        // 편집 상자는 CRLF 만 줄바꿈으로 본다. 테두리 없이(창 배경과 같은 흰색), 넘칠 때만 세로 스크롤
        let body = body_txt.replace('\n', "\r\n");
        let edit_style = WS_TABSTOP | (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32 | if need_scroll { WS_VSCROLL } else { 0 };
        child("EDIT", &body, edit_style, 0, pad, cy, ww - 2 * pad - 16, body_h, 10, font);
        cy += body_h + 8;
        let mut muted = Vec::new();
        if !foot.is_empty() {
            muted.push(child("STATIC", &foot, 0, 0, pad, cy, ww - 2 * pad - 16, foot_h, 13, font));
            cy += foot_h + 8;
        }
        let note = child("STATIC", "'적용'은 이 창이 앞에 나온 뒤 잠시 후 켜집니다 — 가짜 창으로 덮어 클릭을 가로채는 공격을 막기 위해서입니다.", 0, 0, pad, cy, ww - 2 * pad - 16, 40, 11, font);
        let by = wh - 36 - 60 + 10;
        let apply = child("BUTTON", apply_label, WS_TABSTOP | WS_DISABLED | BS_PUSHBUTTON as u32, 0, ww - 16 - 2 * 120 - 8 - pad, by, 120, 36, ID_APPLY, font);
        let cancel = child("BUTTON", cancel_label, WS_TABSTOP | BS_DEFPUSHBUTTON as u32, 0, ww - 16 - 120 - pad, by, 120, 36, ID_CANCEL, font);
        muted.push(note);
        ST.with(|s| *s.borrow_mut() = Some(St { apply, note, muted, bold, armed: false, result: None }));
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(cancel);
        SetTimer(hwnd, TIMER_ARM, ARM_MS, None);
        (hwnd, font)
    }
}

fn pump(hwnd: HWND) {
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

/// 묻고 결과를 돌려준다 (적용/유지 = true). 창을 닫거나 취소 = false
pub fn ask(title: &str, text: &str, apply_label: &str, cancel_label: &str) -> bool {
    let (hwnd, font) = create(title, text, apply_label, cancel_label);
    pump(hwnd);
    unsafe { DeleteObject(font as _) };
    ST.with(|s| s.borrow_mut().take()).and_then(|s| s.result).unwrap_or(false)
}

/// 시험 빌드 전용 자기 시험 (poc5): 승인 창을 띄워 스크린샷을 찍을 시간을 주고, 투명 최상위 덮개를 씌워 겹침 검사가 잡는지 본다.
/// 반환: (기록 줄, 모두 기대대로인가)
#[cfg(feature = "e2e-cdp")]
pub fn selftest(show_ms: u32) -> (Vec<String>, bool) {
    let mut log = Vec::new();
    let text = "서비스가 계산한 실행 내용입니다. 확인을 누르면 적용합니다.\n\n끝낼 프로세스 1개 (생성 시각이 맞을 때만):\n  PID 2200 C:\\Users\\pjg\\AppData\\Local\\Temp\\payload.exe\n통신을 막을 프로그램 1개 (경로 기준):\n  C:\\Users\\pjg\\AppData\\Local\\Temp\\payload.exe\n24시간 막을 접속지 1개 (주소·포트·프로토콜):\n  203.0.113.9:8443/tcp — target (payload.exe)\n\n요청한 프로그램: (자기 시험)";
    let (hwnd, font) = create("Story Firewall - 변경 승인 (자기 시험)", text, "적용", "취소");
    // 스크린샷용으로 잠시 메시지를 돌린다
    let until = std::time::Instant::now() + std::time::Duration::from_millis(show_ms as u64);
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while std::time::Instant::now() < until {
            while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    let armed = with(|s| s.armed).unwrap_or(false);
    let fg = unsafe { GetForegroundWindow() } == hwnd;
    log.push(format!("armed_after_{show_ms}ms={armed} foreground={fg}"));
    // 덮개 없음 → 겹침 없음 (같은 프로세스 창도 센다: 아래 덮개를 같은 프로세스에서 만들기 때문)
    let before = covered(hwnd, false);
    log.push(format!("covered_before={before}"));
    // 투명 최상위 덮개 = 클릭재킹 도구
    let mut r: RECT = unsafe { std::mem::zeroed() };
    unsafe { GetWindowRect(hwnd, &mut r) };
    let overlay = unsafe {
        let h = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            w("STATIC").as_ptr(),
            w("").as_ptr(),
            WS_POPUP | WS_VISIBLE,
            r.left + 100,
            r.top + 100,
            300,
            200,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        );
        SetLayeredWindowAttributes(h, 0, 1, LWA_ALPHA);
        SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        h
    };
    let with_overlay = covered(hwnd, false);
    log.push(format!("covered_with_transparent_overlay={with_overlay}"));
    // 덮개를 비켜 놓으면 다시 깨끗
    unsafe { SetWindowPos(overlay, HWND_TOPMOST, r.right + 50, r.bottom + 50, 10, 10, SWP_NOACTIVATE) };
    let moved = covered(hwnd, false);
    log.push(format!("covered_after_moving_overlay_away={moved}"));
    unsafe {
        DestroyWindow(overlay);
        DestroyWindow(hwnd);
        DeleteObject(font as _);
    }
    ST.with(|s| s.borrow_mut().take());
    // 러너 화면에 다른 최상위 창이 우리 창과 겹칠 수 있어 before 는 기록만, 판정은 덮개를 씌우면 잡히는가 + 단추 무장
    let ok = with_overlay && armed;
    (log, ok)
}
