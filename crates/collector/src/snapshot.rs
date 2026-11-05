//! 수집 시작 시 프로세스 스냅샷 (명세 4판 2-2 시작 순서 ②)
//!
//! Toolhelp 로 PID·PPID·exe 이름을, OpenProcess 로 생성 시각(GetProcessTimes)과 전체 경로
//! (QueryFullProcessImageName)를 얻는다. 보호된 프로세스는 열리지 않으므로 exe 이름만 쓰고
//! "경로 미확인"으로 둔다. 생성 시각은 ETW ProcessStart 의 CreateTime 과 같은 FILETIME 기준이다.

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    /// 전체 경로. 못 얻으면 exe 이름만
    pub image: String,
    pub path_known: bool,
    /// FILETIME. 못 얻으면 0 (Ingester 가 이벤트 시각으로 대신)
    pub create_time: i64,
}

fn filetime_to_i64(ft: &FILETIME) -> i64 {
    ((ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64) as i64
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|c| *c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

pub fn take() -> Result<Vec<ProcInfo>, u32> {
    let mut out = Vec::new();
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(unsafe { windows_sys::Win32::Foundation::GetLastError() });
    }
    let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut ok = unsafe { Process32FirstW(snap, &mut pe) };
    while ok != 0 {
        let pid = pe.th32ProcessID;
        let exe = wide_to_string(&pe.szExeFile);
        let mut info = ProcInfo {
            pid,
            ppid: pe.th32ParentProcessID,
            image: exe,
            path_known: false,
            create_time: 0,
        };
        if pid != 0 {
            let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if !h.is_null() {
                let mut c: FILETIME = unsafe { std::mem::zeroed() };
                let (mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME) =
                    unsafe { std::mem::zeroed() };
                if unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) } != 0 {
                    info.create_time = filetime_to_i64(&c);
                }
                let mut buf = vec![0u16; 1024];
                let mut len = buf.len() as u32;
                if unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) } != 0 {
                    info.image = String::from_utf16_lossy(&buf[..len as usize]);
                    info.path_known = true;
                }
                unsafe { CloseHandle(h) };
            }
        }
        out.push(info);
        ok = unsafe { Process32NextW(snap, &mut pe) };
    }
    unsafe { CloseHandle(snap) };
    Ok(out)
}

/// PID 의 생성 시각(FILETIME). 열지 못하면 None (L048: SCM 매핑을 정확한 프로세스 노드에 붙이는 데 쓴다)
pub fn create_time_of(pid: u32) -> Option<i64> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut c: FILETIME = unsafe { std::mem::zeroed() };
    let (mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME) = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) } != 0;
    unsafe { CloseHandle(h) };
    ok.then(|| filetime_to_i64(&c))
}

/// 프로세스의 로그온 세션 (A30). `ProcessIdToSessionId` — 서비스(SYSTEM)는 모든 프로세스에 대해 성공한다.
pub fn session_of(pid: u32) -> Option<u32> {
    let mut s = 0u32;
    let ok =
        unsafe { windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut s) };
    (ok != 0).then_some(s)
}

/// 이번 부팅 시각(FILETIME, 지금 시계 기준) = 지금 − 부팅 뒤 경과(GetTickCount64, 절전 시간 포함).
/// L023: 부팅 직후 RTC 가 틀렸다가 동기화된 PC 에서는 그 사이에 만들어진 프로세스의 CreateTime 이 부팅보다 이르게 남는다
pub fn boot_filetime(now: i64) -> i64 {
    let ms = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
    now - ms as i64 * 10_000
}
