//! 상세 보고서 저장(통합프로젝트 「상세 보고서 기능 — 공통 규칙과 개발 의뢰 (1판)」 2장·3.2).
//!
//! 화면(일반 권한)이 조회 결과로 만든 보고서 모형을 받아 여기서 가리기 → HTML → 사용자가 고른 위치에 쓴다.
//! **서비스는 거치지 않는다**(서비스는 파일을 쓰지 않는다). 저장 위치는 웹뷰가 주지 않는다 — 코어가 띄운 저장 대화상자에서
//! 사용자가 고른 경로에만 쓴다. [열기]·[폴더 열기]도 코어가 마지막으로 쓴 경로만 연다(웹뷰가 경로를 넘기지 못한다).
//! 가리기·HTML·파일 쓰기의 본체는 `report` 크레이트(순수 함수, Linux 에서 시험)에 있다.
use std::path::PathBuf;
use std::sync::Mutex;

/// 마지막으로 쓴 보고서 파일(앱을 켠 동안만)
static LAST: Mutex<Option<PathBuf>> = Mutex::new(None);

/// 모형 크기 상한(직렬화한 글자 수). 구역마다 2,000행 상한이 있어 정상 보고서는 이보다 훨씬 작다
const MAX_MODEL_BYTES: usize = 64 * 1024 * 1024;

/// 이 PC 가 바깥으로 나갈 때 쓰는 주소. UDP 소켓의 connect 는 패킷을 보내지 않는다(경로만 고른다)
fn local_ips() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    for (bind, to) in [("0.0.0.0:0", "198.51.100.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        if let Ok(s) = std::net::UdpSocket::bind(bind) {
            if s.connect(to).is_ok() {
                if let Ok(a) = s.local_addr() {
                    out.push(a.ip());
                }
            }
        }
    }
    out
}

/// 가릴 이름들을 OS 에 묻는다(PC 이름, 사용자 이름, `C:\Users` 아래 폴더 이름, PC 에 바로 붙은 공인 주소)
fn who() -> report::Who {
    let dirs = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .and_then(|p| p.parent().map(|x| x.to_path_buf()))
        .and_then(|p| std::fs::read_dir(p).ok())
        .map(|rd| rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).filter_map(|e| e.file_name().into_string().ok()).collect())
        .unwrap_or_default();
    report::out::who_from(std::env::var("COMPUTERNAME").ok(), std::env::var("USERNAME").ok(), dirs, local_ips())
}

#[cfg(windows)]
mod win {
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::Controls::Dialogs::{GetSaveFileNameW, OFN_EXPLORER, OFN_HIDEREADONLY, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 저장 대화상자. 취소하면 None. `owner` = 본 창(없으면 0)
    pub fn save_dialog(owner: isize, default_name: &str) -> Option<PathBuf> {
        let mut file = [0u16; 1024];
        for (i, c) in default_name.encode_utf16().take(file.len() - 1).enumerate() {
            file[i] = c;
        }
        // "설명\0*.html\0\0"
        let filter: Vec<u16> = "HTML 파일 (*.html)\0*.html\0\0".encode_utf16().collect();
        let title = wide("보고서 저장");
        let ext = wide("html");
        let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        ofn.hwndOwner = owner as HWND;
        ofn.lpstrFilter = filter.as_ptr();
        ofn.lpstrFile = file.as_mut_ptr();
        ofn.nMaxFile = file.len() as u32;
        ofn.lpstrTitle = title.as_ptr();
        ofn.lpstrDefExt = ext.as_ptr();
        ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;
        if unsafe { GetSaveFileNameW(&mut ofn) } == 0 {
            return None;
        }
        let n = file.iter().position(|c| *c == 0).unwrap_or(file.len());
        String::from_utf16(&file[..n]).ok().filter(|s| !s.is_empty()).map(PathBuf::from)
    }

    /// 탐색기·기본 프로그램으로 연다
    pub fn shell_open(path: &std::path::Path) -> bool {
        let p = wide(&path.to_string_lossy());
        let op = wide("open");
        let r = unsafe { ShellExecuteW(std::ptr::null_mut(), op.as_ptr(), p.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
        r as isize > 32
    }
}

/// 보고서를 만들어 사용자가 고른 위치에 쓴다. 반환: `{saved:false}`(대화상자에서 취소 — 아무 파일도 남기지 않는다)
/// 또는 `{saved:true, path, bytes}`. `stamp` = "YYYYMMDD-HHMMSS"(파일 이름용)
#[tauri::command]
pub async fn report_save(app: tauri::AppHandle, model: report::Report, stamp: String) -> Result<serde_json::Value, String> {
    if model.program != "storyfirewall" {
        return Err("보고서 모형의 프로그램 이름이 다릅니다".into());
    }
    #[cfg(windows)]
    let owner: isize = {
        use tauri::Manager as _;
        app.get_webview_window("main").and_then(|w| w.hwnd().ok()).map(|h| h.0 as isize).unwrap_or(0)
    };
    #[cfg(not(windows))]
    let _ = &app;
    tauri::async_runtime::spawn_blocking(move || -> Result<serde_json::Value, String> {
        // 가리기(2.4) → HTML(2.1·2.2). 모형의 글자는 모두 바깥에서 온 자료로 보고 전부 바꿔 쓴다
        let masked = report::masked_copy(&model, &who());
        let html = report::render_html(&masked);
        if html.len() > MAX_MODEL_BYTES {
            return Err("보고서가 너무 큽니다. 기간이나 구역을 줄여 주세요".into());
        }
        let name = report::file_name(&model.program, &stamp);
        #[cfg(windows)]
        let chosen = win::save_dialog(owner, &name);
        #[cfg(not(windows))]
        let chosen: Option<PathBuf> = {
            let _ = name;
            return Err("이 운영체제에서는 저장 대화상자를 쓸 수 없습니다".into());
        };
        let Some(path) = chosen else {
            return Ok(serde_json::json!({ "saved": false }));
        };
        let path = report::out::write_whole(&path, html.as_bytes()).map_err(|e| format!("파일을 쓰지 못했습니다: {e}"))?;
        let shown = path.to_string_lossy().to_string();
        *LAST.lock().unwrap() = Some(path);
        Ok(serde_json::json!({ "saved": true, "path": shown, "bytes": html.len() }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 마지막으로 쓴 보고서를 연다. `what` = "file"(기본 브라우저로) | "folder"(그 폴더를 탐색기로).
/// 웹뷰는 경로를 넘기지 못한다 — 코어가 방금 쓴 `.html` 파일만 연다
#[tauri::command]
pub fn report_open(what: String) -> Result<(), String> {
    let path = LAST.lock().unwrap().clone().ok_or_else(|| "이번에 만든 보고서가 없습니다".to_string())?;
    if !path.is_file() {
        return Err("보고서 파일이 그 자리에 없습니다(옮기거나 지웠습니다)".into());
    }
    let target = match what.as_str() {
        "file" => path,
        "folder" => path.parent().map(|p| p.to_path_buf()).ok_or_else(|| "폴더를 찾지 못했습니다".to_string())?,
        _ => return Err("what".into()),
    };
    #[cfg(windows)]
    {
        if win::shell_open(&target) {
            Ok(())
        } else {
            Err("열지 못했습니다".into())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        Err("이 운영체제에서는 열 수 없습니다".into())
    }
}
