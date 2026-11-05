//! 관리자 권한 (A22 발견): 서비스는 변경 메서드에 **활성화된** Administrators SID 를 요구한다(CheckTokenMembership).
//! UAC 에서 일반으로 띄운 UI 는 관리자 계정이어도 그 SID 가 deny-only 라 모든 변경이 -32001 로 거부된다.
//! → (A23 정정) UI 는 늘 일반 권한(보기)으로 돌고, 변경은 서비스에 맡긴 뒤 **승인 도우미**(웹뷰 없는 같은 실행 파일)를 UAC 로 띄워
//! 서비스가 계산한 요약을 보여 주고 실행한다(approve.rs). A22 의 "UI 를 통째로 관리자 권한으로 다시 열기"는 WebView2 호스트를
//! 승격하지 말라는 Microsoft 권고와 반대라 없앴다. 승인 도우미는 High 무결성이라 비관리자 악성코드가 창 메시지로 누르지 못한다(UIPI).

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
        return false;
    }
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    let ok = unsafe { GetTokenInformation(tok, TokenElevation, &mut e as *mut _ as *mut _, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len) };
    unsafe { CloseHandle(tok) };
    ok != 0 && e.TokenIsElevated != 0
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// 승인 도우미 = 자기 실행 파일을 `runas` + `--approve <id>` 로 띄우고(UAC) 끝날 때까지 기다린다. 반환: 도우미 종료 코드.
/// UAC 에서 아니요 = ERROR_CANCELLED(1223) → EXIT_CANCEL.
/// 주의: 실행 파일 경로가 일반 사용자가 쓸 수 있는 곳이면(포터블 설치) 악성코드가 파일을 바꿔치기해 UAC 동의를 가로챌 수 있다.
/// 설치 프로그램은 Program Files(관리자만 쓰기)에 둔다. UAC 창은 서명자를 보여 주므로 바꿔치기한 파일은 "알 수 없는 게시자"로 뜬다.
#[cfg(windows)]
pub fn run_helper(change_id: &str) -> Result<i32, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    if !crate::approve::is_uuid(change_id) {
        return Err("change_id 형식".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let file: Vec<u16> = exe.as_os_str().encode_wide_z();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    #[allow(unused_mut)]
    let mut args = format!("--approve {change_id}");
    // 시험 빌드만: 대화상자 대신 자동 응답 (승격된 자식은 환경 변수를 물려받지 않으므로 인자로 넘긴다)
    #[cfg(feature = "e2e-cdp")]
    if let Ok(out) = std::env::var("STORYFW_E2E_APPROVE_OUT") {
        if !out.contains('"') {
            args.push_str(&format!(" --e2e-auto \"{out}\""));
        }
    }
    // 시험 빌드만(A27): UAC 대역 — 표준 사용자 UI 의 승인 요청을 파일로 넘기고, 러너의 관리자 쪽이 도우미를 관리자로 띄운다.
    // (러너에서는 UAC 자격 증명 창을 누를 수 없다. 권한 구도 = UI 표준 사용자, 도우미 관리자 는 실제와 같다)
    #[cfg(feature = "e2e-cdp")]
    if let Ok(dir) = std::env::var("STORYFW_E2E_UAC_DIR") {
        return e2e_uac_standin(&dir, change_id);
    }
    let params: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = 1; // SW_SHOWNORMAL
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(1223) {
            return Ok(crate::approve::EXIT_CANCEL);
        }
        return Err(format!("승인 창 실행 실패 {e}"));
    }
    if info.hProcess.is_null() {
        return Err("승인 창 프로세스 핸들 없음".into());
    }
    // 사용자가 읽고 고를 시간: 10분
    let w = unsafe { WaitForSingleObject(info.hProcess, 10 * 60 * 1000) };
    let mut code = 0u32;
    let ok = w == WAIT_OBJECT_0 && unsafe { GetExitCodeProcess(info.hProcess, &mut code) } != 0;
    unsafe { CloseHandle(info.hProcess) };
    if !ok {
        return Err("승인 창이 10분 안에 끝나지 않았습니다".into());
    }
    Ok(code as i32)
}

/// 시험 빌드만(A27): `<dir>\\req-<id>.txt` 를 쓰고 `<dir>\\done-<id>.txt`(종료 코드)를 2분까지 기다린다
#[cfg(all(windows, feature = "e2e-cdp"))]
fn e2e_uac_standin(dir: &str, change_id: &str) -> Result<i32, String> {
    let d = std::path::Path::new(dir);
    std::fs::write(d.join(format!("req-{change_id}.txt")), change_id).map_err(|e| format!("UAC 대역 요청 쓰기: {e}"))?;
    let done = d.join(format!("done-{change_id}.txt"));
    for _ in 0..240 {
        if let Ok(t) = std::fs::read_to_string(&done) {
            if let Ok(c) = t.trim().parse::<i32>() {
                return Ok(c);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err("UAC 대역 응답 없음(2분)".into())
}

/// 시험 빌드만(A27): `--e2e-env KEY=VALUE` (여러 번) 을 환경 변수로. 허용 목록만. 배포 빌드에서는 아무것도 하지 않는다.
/// 다른 사용자로 띄우면(Start-Process -Credential) 부모 환경이 이어지지 않아 CDP 포트·자동 응답 경로를 인자로 넘긴다.
pub fn e2e_env_from_args(args: &[String]) {
    if !cfg!(feature = "e2e-cdp") {
        return;
    }
    const ALLOW: [&str; 3] = ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "STORYFW_E2E_APPROVE_OUT", "STORYFW_E2E_UAC_DIR"];
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--e2e-env" {
            if let Some((k, v)) = args.get(i + 1).and_then(|kv| kv.split_once('=')) {
                if ALLOW.contains(&k) {
                    std::env::set_var(k, v);
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
}

#[cfg(not(windows))]
pub fn run_helper(_change_id: &str) -> Result<i32, String> {
    Err("Windows 에서만".into())
}

#[cfg(windows)]
trait WideZ {
    fn encode_wide_z(&self) -> Vec<u16>;
}
#[cfg(windows)]
impl WideZ for std::ffi::OsStr {
    fn encode_wide_z(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

/// 배포 빌드에서 WebView2 를 바꿀 수 있는 환경 변수를 지운다 (A22 발견).
/// 같은 사용자의 악성코드가 이 변수를 심으면 UI 에 원격 디버깅 포트를 열거나(`--remote-debugging-port`) 다른 WebView2 런타임
/// 폴더를 쓰게 할 수 있다. 시험 빌드(`e2e-cdp` feature)만 남긴다. 웹뷰가 만들어지기 전(main 시작)에 불러야 한다.
pub fn harden_webview_env() {
    if cfg!(feature = "e2e-cdp") {
        return;
    }
    for k in ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", "WEBVIEW2_USER_DATA_FOLDER", "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE", "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER"] {
        // 단일 스레드인 시작 시점에만 부른다 (2024 판에서 unsafe 가 된 이유: 다른 스레드의 동시 읽기)
        std::env::remove_var(k);
    }
}
