//! SCM 매핑: PID → 서비스 이름 목록 (명세 4판 2-1)
//!
//! `EnumServicesStatusEx(SC_ENUM_PROCESS_INFO)` 로 실행 중인 Win32 서비스와 호스트 PID 를 읽는다.
//! 공유 svchost 는 한 PID 에 서비스가 여럿이므로 목록으로 둔다. 1초 폴링.

use std::collections::HashMap;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_MORE_DATA};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};

fn pwstr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

pub fn map() -> Result<HashMap<u32, Vec<String>>, u32> {
    let scm = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if scm.is_null() {
        return Err(unsafe { GetLastError() });
    }
    let mut out: HashMap<u32, Vec<String>> = HashMap::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut needed = 0u32;
    let mut returned = 0u32;
    let mut resume = 0u32;
    let mut result = Ok(());
    for _ in 0..4 {
        let ok = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut needed,
                &mut returned,
                &mut resume,
                std::ptr::null(),
            )
        };
        if ok != 0 {
            let rows = unsafe {
                std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    returned as usize,
                )
            };
            for r in rows {
                let pid = r.ServiceStatusProcess.dwProcessId;
                if pid == 0 {
                    continue;
                }
                out.entry(pid)
                    .or_default()
                    .push(pwstr_to_string(r.lpServiceName));
            }
            break;
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_MORE_DATA {
            result = Err(err);
            break;
        }
        buf = vec![0u8; needed as usize + 4096];
        resume = 0;
    }
    unsafe { CloseServiceHandle(scm) };
    result.map(|_| out)
}
