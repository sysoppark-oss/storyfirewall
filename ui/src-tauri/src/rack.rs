//! 안디옥 첫 연동: 사건 카드의 [NetX로 정밀 진단] (통합 설계 0.15판 8.1 "첫 연동", 8.3, 6.3, 6.7 — 확정 2026-11-12).
//!
//! 화면(일반 권한)이 NetX 의 파이프에 직접 붙는다. **서비스는 거치지 않는다.**
//! 순서: HKLM 등록부에서 NetX 의 Exe → 관리자만 쓸 수 있는 폴더 아래인지 → HKCU 의 실행 중 파이프 이름(형식 검사)
//! → 접속 → 파이프 서버 프로세스의 실행 파일이 등록된 Exe 와 같은지 → rack.hello → rack.handoff(diagnose.target).
//! 보내는 값은 접속지 주소·포트뿐이다. 이 인계로는 아무것도 실행·차단되지 않는다(NetX 가 입력칸을 채우고, 실행은 사용자가 누른다).
//! 형식 검사·메시지 모양은 `rack` 크레이트(순수 함수, Linux 에서 시험)에 있다.

/// NetX 가 꺼져 있을 때의 안내 (8.1: 첫 판에서는 대신 실행해 주지 않는다)
pub const NETX_OFF: &str = "NetX를 먼저 켜 주세요";

#[cfg(windows)]
mod win {
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, VOLUME_NAME_DOS};
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath};

    use crate::client::{pipe, Client};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 닫히는 핸들
    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    /// 등록부의 글자열 값. 없거나 글자열이 아니거나 너무 길면 None. 값은 자료다 — 부르는 쪽이 형식을 검사한다
    fn reg_sz(hive: HKEY, key: &str, value: &str) -> Option<String> {
        let (k, v) = (wide(key), wide(value));
        let mut buf = [0u16; 1024];
        let mut cb = (buf.len() * 2) as u32;
        let r = unsafe { RegGetValueW(hive, k.as_ptr(), v.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut cb) };
        if r != 0 {
            return None;
        }
        let n = (cb as usize / 2).min(buf.len());
        let s = String::from_utf16(&buf[..n]).ok()?;
        let s = s.trim_end_matches('\0').to_string();
        (!s.is_empty()).then_some(s)
    }

    /// HKLM\SOFTWARE\Antioch\Modules\netx 의 Exe (설치 프로그램이 관리자 권한으로 쓴 값)
    fn netx_exe() -> Option<String> {
        reg_sz(HKEY_LOCAL_MACHINE, &format!(r"{}\{}", rack::MODULES_KEY, rack::NETX_ID), "Exe")
    }

    /// Program Files 폴더들 — 환경 변수가 아니라 운영체제에 묻는다(환경 변수는 실행한 쪽이 바꿀 수 있다)
    fn admin_roots() -> Vec<String> {
        let mut out = Vec::new();
        for id in [&FOLDERID_ProgramFiles, &FOLDERID_ProgramFilesX86] {
            let mut p: *mut u16 = std::ptr::null_mut();
            let hr = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut p) };
            if hr >= 0 && !p.is_null() {
                let mut n = 0usize;
                while unsafe { *p.add(n) } != 0 && n < 4096 {
                    n += 1;
                }
                if let Ok(s) = String::from_utf16(unsafe { std::slice::from_raw_parts(p, n) }) {
                    out.push(s);
                }
            }
            if !p.is_null() {
                unsafe { CoTaskMemFree(p as *const _) };
            }
        }
        out
    }

    /// 운영체제가 알려 주는 최종 경로(짧은 이름·링크를 푼 것, 8.3 의 5번). 파일을 열 수 없으면 None
    fn final_path(path: &str) -> Option<String> {
        let w = wide(path);
        // 권한 0 으로 연다(속성만) — 읽기 권한이 없어도 경로는 얻는다
        let h = unsafe { CreateFileW(w.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, std::ptr::null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let h = Owned(h);
        let mut buf = vec![0u16; 2048];
        let n = unsafe { GetFinalPathNameByHandleW(h.0, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) } as usize;
        if n == 0 || n >= buf.len() {
            return None;
        }
        String::from_utf16(&buf[..n]).ok()
    }

    /// 프로세스의 실행 파일 전체 경로. 핸들을 먼저 잡고 그 핸들로 읽는다(PID 재사용 틈, 8.3)
    fn process_image(pid: u32) -> Option<String> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let h = Owned(h);
        let mut buf = vec![0u16; 2048];
        let mut n = buf.len() as u32;
        if unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) } == 0 {
            return None;
        }
        String::from_utf16(&buf[..n as usize]).ok()
    }

    /// NetX 가 설치돼 등록부에 올라 있는가 — 단추를 보일지 정한다(8.1). 켜져 있는지는 누를 때 본다
    pub fn registered() -> bool {
        netx_exe().is_some()
    }

    pub fn diagnose(ip: &str, port: Option<u16>) -> Result<serde_json::Value, String> {
        // 보낼 값을 먼저 검사한다(주소가 아니면 NetX 에 붙지도 않는다)
        let mut rnd = [0u8; 16];
        getrandom::getrandom(&mut rnd).map_err(|e| format!("난수: {e}"))?;
        let params = rack::handoff_params(&rack::uuid_v4(rnd), ip, port)?;

        let exe = netx_exe().ok_or("NetX 가 설치돼 있지 않습니다")?;
        let exe_final = final_path(&exe).ok_or("등록된 NetX 실행 파일을 찾지 못했습니다")?;
        // 8.3 의 4번: 관리자만 쓸 수 있는 폴더 아래가 아니면 등록돼 있어도 믿지 않는다
        if !rack::under_admin_root(&exe_final, &admin_roots()) {
            return Err("등록된 NetX 가 Program Files 아래에 있지 않아 접속하지 않았습니다(PC 전체 설치가 필요합니다)".into());
        }
        // HKCU 는 일반 권한 프로그램이 고칠 수 있다 → 이름 형식을 검사하고, 접속한 뒤 서버를 확인한다
        let name = reg_sz(HKEY_CURRENT_USER, &format!(r"{}\{}", rack::RUNNING_KEY, rack::NETX_ID), "PipeName").filter(|n| rack::valid_pipe_name(rack::NETX_ID, n)).ok_or(super::NETX_OFF)?;
        // 파이프가 없으면(NetX 가 꺼졌는데 값만 남음) 켜 달라고만 한다
        let (h, spid) = pipe::open_unchecked(&name).map_err(|_| super::NETX_OFF.to_string())?;
        // 8.3 의 3번: 파이프 서버 프로세스의 실행 파일이 등록된 Exe 와 같은가. 다르면 한 글자도 보내지 않고 놓는다
        let server = process_image(spid).and_then(|p| final_path(&p)).ok_or("NetX 파이프의 상대 프로그램을 확인하지 못해 접속하지 않았습니다")?;
        if !rack::same_path(&server, &exe_final) {
            return Err("NetX 파이프의 상대가 등록된 NetX 가 아니어서 접속하지 않았습니다".into());
        }
        let c = Client::over_pipe(h, "netx").map_err(|e| format!("NetX 연결: {e}"))?;
        let hello = c.call("rack.hello", rack::hello_params(env!("CARGO_PKG_VERSION")), Duration::from_secs(5)).map_err(|e| format!("NetX 응답 없음: {e}"))?;
        rack::check_hello(&hello)?;
        let reply = c.call("rack.handoff", params, Duration::from_secs(5)).map_err(|e| format!("NetX 응답 없음: {e}"))?;
        let (accepted, opened) = rack::check_handoff(&reply)?;
        Ok(serde_json::json!({ "accepted": accepted, "opened": opened }))
    }
}

/// NetX 가 등록돼 있는가 (단추 표시 여부). Windows 가 아니면 늘 false
#[tauri::command]
pub fn netx_registered() -> bool {
    #[cfg(windows)]
    {
        win::registered()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// 사건의 접속지 주소·포트를 NetX 로 넘긴다. 결과: {accepted, opened}. 실패는 화면에 그대로 보일 한국어 문장
#[tauri::command]
pub async fn netx_diagnose(ip: String, port: Option<u16>) -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(move || win::diagnose(&ip, port)).await.map_err(|e| e.to_string())?
    }
    #[cfg(not(windows))]
    {
        let _ = (ip, port);
        Err("이 운영체제에서는 NetX 연동을 쓸 수 없습니다".into())
    }
}
