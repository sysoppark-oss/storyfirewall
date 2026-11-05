//! 프로세스 토큰이 시스템 계정(SYSTEM / LocalService / NetworkService)인가 (명세 5판 2-3 서비스 판별 3조건)
//!
//! 보호 프로세스(PPL)는 OpenProcess/OpenProcessToken 이 실패하므로 None 을 돌려주고, 호출자는 SCM+서명자로 판단한다.

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalServiceSid, WinLocalSystemSid,
    WinNetworkServiceSid, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn system_token(pid: u32) -> Option<bool> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut tok: HANDLE = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(h, TOKEN_QUERY, &mut tok) };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        return None;
    }
    let mut buf = vec![0u8; 256];
    let mut len = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            tok,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            &mut len,
        )
    };
    unsafe { CloseHandle(tok) };
    if ok == 0 {
        return None;
    }
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = tu.User.Sid;
    let is = |t| unsafe { IsWellKnownSid(sid, t) } != 0;
    Some(is(WinLocalSystemSid) || is(WinLocalServiceSid) || is(WinNetworkServiceSid))
}
