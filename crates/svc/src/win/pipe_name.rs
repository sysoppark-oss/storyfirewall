//! 파이프 이름 공개·조회와 가로채기(squatting) 점검 (A25, 18차 답변 S3).
//!
//! 문제: 이름이 고정(`\\.\pipe\story-firewall`)이면, 서비스가 멈췄거나 다시 시작하는 틈에 일반 사용자 악성코드가 같은 이름으로
//! 첫 인스턴스를 먼저 만들 수 있다. 그러면 진짜 서비스는 `FILE_FLAG_FIRST_PIPE_INSTANCE` 로 실패해 UI 가 서비스에 못 닿는다
//! (클라이언트의 session 0 확인 덕에 가짜 데이터는 못 보여 주지만, 가용성이 깨진다).
//!
//! 대책:
//! 1. 서비스는 시작할 때마다 **무작위 이름**(`\\.\pipe\story-firewall-<128비트 hex>`)으로 첫 인스턴스를 **먼저 만들고 나서**
//!    HKLM\SOFTWARE\StoryFirewall\PipeName 에 공개한다. 이름을 알기 전에는 선점할 수 없다. 공개 뒤에는 파이프 목록에서 이름이
//!    보이지만, 이미 우리가 첫 인스턴스를 가졌고 DACL 이 일반 사용자에게 인스턴스 만들기를 주지 않으므로(pipe.rs SDDL) 끼어들 수 없다.
//!    HKLM\SOFTWARE 아래 키는 상속으로 Users 읽기·Administrators/SYSTEM 쓰기다.
//! 2. 클라이언트는 공개된 이름을 읽는다(형식 검사). 값이 없으면 고정 이름(개발·시험 서버)으로 — 그래도 session 0 확인은 그대로.
//! 3. 서비스는 고정 이름을 만들지 않는다 → 고정 이름을 누가 들고 있으면 그 자체가 가로채기 시도다. 시작할 때 점검해 사건으로 남긴다.
//! 4. 정상 중지 때 공개 값을 지운다(비정상 종료면 남지만 다음 시작이 덮어쓴다).

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_SHARE_NONE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, GetNamedPipeServerSessionId};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegGetValueW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE, REG_SZ,
    RRF_RT_REG_SZ,
};

use super::wide;

pub const REG_KEY: &str = r"SOFTWARE\StoryFirewall";
pub const REG_VALUE: &str = "PipeName";
pub const PREFIX: &str = r"\\.\pipe\story-firewall-";

/// 클라이언트가 파이프를 여는 권한: 읽기 + 데이터 쓰기 + 속성 쓰기(SetNamedPipeHandleState 메시지 모드).
/// `GENERIC_WRITE` 를 쓰지 않는다 — 파이프에서 FILE_GENERIC_WRITE 는 FILE_APPEND_DATA = FILE_CREATE_PIPE_INSTANCE 를 포함해,
/// 서버 DACL 이 이것을 주면 클라이언트 쪽 누구나 서버 인스턴스를 더 만들 수 있다(Microsoft 문서). 서버 SDDL 도 같은 권한만 준다.
pub const CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;

/// 시작마다 새 이름
pub fn random_name() -> String {
    format!("{PREFIX}{}", crate::change::new_uuid().replace('-', ""))
}

/// 공개된 이름이 우리 형식인가 (HKLM 은 관리자만 쓰지만, 그래도 읽은 값을 그대로 경로로 쓰지 않는다)
pub fn valid(name: &str) -> bool {
    name.strip_prefix(PREFIX)
        .is_some_and(|h| h.len() == 32 && h.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// HKLM\SOFTWARE\StoryFirewall 의 문자열 값 쓰기 (관리자·SYSTEM 만 성공)
pub fn reg_set(value: &str, data: &str) -> Result<(), String> {
    let mut key: HKEY = std::ptr::null_mut();
    let r = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(REG_KEY).as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if r != 0 {
        return Err(format!("RegCreateKeyExW {r}"));
    }
    let v: Vec<u16> = wide(data);
    let r = unsafe {
        RegSetValueExW(
            key,
            wide(value).as_ptr(),
            0,
            REG_SZ,
            v.as_ptr() as *const u8,
            (v.len() * 2) as u32,
        )
    };
    unsafe { RegCloseKey(key) };
    if r != 0 {
        return Err(format!("RegSetValueExW {r}"));
    }
    Ok(())
}

/// 같은 키의 문자열 값 읽기 (누구나). 없거나 길면 None
pub fn reg_get(value: &str) -> Option<String> {
    let mut buf = [0u16; 512];
    let mut cb = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide(REG_KEY).as_ptr(),
            wide(value).as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut cb,
        )
    };
    if r != 0 {
        return None;
    }
    let n = (cb as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

pub fn reg_delete(value: &str) {
    unsafe {
        RegDeleteKeyValueW(
            HKEY_LOCAL_MACHINE,
            wide(REG_KEY).as_ptr(),
            wide(value).as_ptr(),
        )
    };
}

/// 서비스: 첫 인스턴스를 만든 **뒤** 부른다
pub fn publish(name: &str) -> Result<(), String> {
    reg_set(REG_VALUE, name)
}

pub fn unpublish() {
    reg_delete(REG_VALUE);
}

/// 클라이언트: 공개된 이름(형식 맞을 때) 또는 고정 이름
pub fn resolve() -> String {
    match reg_get(REG_VALUE) {
        Some(s) if valid(&s) => s,
        _ => super::pipe::PIPE_NAME.to_string(),
    }
}

/// 이름을 이미 누가 서버로 들고 있으면 (PID, session). 식별 수준(SQOS)으로만 붙는다 — 상대가 악성 서버여도 우리 토큰(SYSTEM)으로
/// 행동 못 하게. session 은 파이프 핸들에서 얻는다(프로세스를 열 권한이 필요 없음).
pub fn holder_of(name: &str) -> Option<(u32, Option<u32>)> {
    let h = unsafe {
        CreateFileW(
            wide(name).as_ptr(),
            CLIENT_ACCESS,
            FILE_SHARE_NONE,
            std::ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        // 없음(2) 또는 바쁨(231: 인스턴스가 모두 연결 중 — 그래도 누군가 들고 있다)
        let e = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return if e == 231 { Some((0, None)) } else { None };
    }
    let r = server_of(h);
    unsafe { CloseHandle(h) };
    Some(r)
}

/// 열린 클라이언트 핸들의 서버 (PID, session). session 은 `GetNamedPipeServerSessionId` — 일반 사용자도 된다.
/// (A25 실측: 일반 사용자가 `ProcessIdToSessionId`·`OpenProcess(QUERY_LIMITED)` 를 LocalSystem 서비스에 쓰면 접근 거부)
pub fn server_of(h: windows_sys::Win32::Foundation::HANDLE) -> (u32, Option<u32>) {
    let mut pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(h, &mut pid) };
    let mut sess = 0u32;
    let s = if unsafe { GetNamedPipeServerSessionId(h, &mut sess) } != 0 {
        Some(sess)
    } else {
        None
    };
    (pid, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn name_format() {
        let n = random_name();
        assert!(valid(&n), "{n}");
        assert_ne!(n, random_name());
        assert!(!valid(r"\\.\pipe\story-firewall"));
        assert!(!valid(r"\\.\pipe\story-firewall-..\..\x"));
        assert!(!valid(&format!("{PREFIX}{}", "g".repeat(32))));
    }
}
