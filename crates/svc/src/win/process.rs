//! 프로세스 종료: `TerminateProcess` + 생성 시각 대조. 명세 7판 2-6장 ("여기서부터 끊기").
//!
//! PID 는 재사용되므로 종료 전에 `GetProcessTimes` 의 생성 시각(FILETIME)이 수집기가 기록한 값과 같은지 확인한다.
//! 다르면 종료하지 않는다 (엉뚱한 새 프로세스를 죽이는 것을 막음). 시스템 핵심 프로세스는 engine 이 걸러서 여기까지 오지 않는다.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FILETIME};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

/// 종료 결과
#[derive(Debug, PartialEq, Eq)]
pub enum Kill {
    Terminated,
    /// 생성 시각이 달라 종료하지 않음 (PID 재사용)
    CreateTimeMismatch {
        actual: i64,
    },
    /// 프로세스 없음 또는 열 수 없음
    OpenFailed(u32),
    TerminateFailed(u32),
}

fn ft(f: FILETIME) -> i64 {
    ((f.dwHighDateTime as i64) << 32) | f.dwLowDateTime as i64
}

/// PID 의 생성 시각 (FILETIME, 100ns). 없으면 None.
pub fn create_time(pid: u32) -> Option<i64> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut c: FILETIME = unsafe { std::mem::zeroed() };
    let mut e = c;
    let mut k = c;
    let mut u = c;
    let ok = unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        None
    } else {
        Some(ft(c))
    }
}

/// `expected_create` 가 Some 이면 생성 시각이 같을 때만 종료한다. 종료 코드는 1.
pub fn terminate(pid: u32, expected_create: Option<i64>) -> Kill {
    let h = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if h.is_null() {
        return Kill::OpenFailed(unsafe { GetLastError() });
    }
    if let Some(exp) = expected_create {
        let mut c: FILETIME = unsafe { std::mem::zeroed() };
        let mut e = c;
        let mut k = c;
        let mut u = c;
        if unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) } == 0 {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(h) };
            return Kill::OpenFailed(err);
        }
        let actual = ft(c);
        if actual != exp {
            unsafe { CloseHandle(h) };
            return Kill::CreateTimeMismatch { actual };
        }
    }
    let ok = unsafe { TerminateProcess(h, 1) };
    let err = unsafe { GetLastError() };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        Kill::TerminateFailed(err)
    } else {
        Kill::Terminated
    }
}

/// Windows 호스트: 리스닝 포트(GetExtendedTcpTable/UdpTable), 종료(생성 시각 대조)
pub struct WinHost;
impl crate::host::Host for WinHost {
    fn listeners(&self) -> Result<Vec<crate::host::Listener>, String> {
        let ls =
            collector::conntable::listeners().map_err(|e| format!("연결 표 조회 실패 {e:#x}"))?;
        Ok(ls
            .into_iter()
            .map(|l| crate::host::Listener {
                proto: l.proto.into(),
                laddr: l.local.to_string(),
                lport: l.lport,
                pid: l.pid,
                any_addr: l.local.is_unspecified(),
            })
            .collect())
    }
    fn terminate(&self, pid: u32, create_ft: Option<i64>) -> String {
        format!("{:?}", terminate(pid, create_ft))
    }
    fn live_image(&self, pid: u32, create_ft: i64, seen_ft: i64) -> Option<(String, i64)> {
        // 같은 프로세스일 때만(PID 재사용 방지): 생성 시각이 기록과 같거나, 처음 본 시각 전에 생겼다
        let same = |ct: i64| ct == create_ft || (seen_ft > 0 && ct > 0 && ct <= seen_ft);
        if pid == 0 {
            return None;
        }
        let ct = create_time(pid)?;
        if !same(ct) {
            return None;
        }
        let img = super::authn::image_of_pid(pid)?;
        // 읽는 사이 PID 가 바뀌지 않았는지 한 번 더
        (create_time(pid)? == ct).then_some((img, ct))
    }
    fn interfaces(&self) -> Result<Vec<crate::host::NetIf>, String> {
        super::netif::interfaces()
    }
    fn rdp_sessions(&self) -> Vec<(u32, String)> {
        super::wts::rdp_sessions().unwrap_or_default()
    }
    fn rdp_port(&self) -> u16 {
        super::wts::rdp_port()
    }
    fn original_name(&self, path: &str) -> Option<String> {
        // Windows 폴더 밖의 실행 파일만(이름 바꾼 복사본은 보통 사용자 폴더에 있다) — 모든 시스템 프로세스마다 파일을 읽지 않게
        let l = path.to_ascii_lowercase();
        if l.contains(":\\windows\\") {
            return None;
        }
        // 같은 경로를 다시 읽지 않게 캐시(크기 상한). 바꿔치기된 같은 경로는 다음 재시작까지 옛 이름 — 섀도·tscon 대조에만 쓰는 값이라 감수
        static CACHE: std::sync::Mutex<Option<std::collections::HashMap<String, Option<String>>>> =
            std::sync::Mutex::new(None);
        let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let m = g.get_or_insert_with(std::collections::HashMap::new);
        if let Some(v) = m.get(&l) {
            return v.clone();
        }
        if m.len() > 4096 {
            m.clear();
        }
        let v = collector::cmdline::original_file_name(path)
            .map(|n| collector::cmdline::norm_original(&n));
        m.insert(l, v.clone());
        v
    }
}
