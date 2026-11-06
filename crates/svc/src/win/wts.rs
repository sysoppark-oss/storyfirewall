//! 원격 데스크톱(RDP) 세션 보기 (32차 Gemini Q1, 14판 20-4): WTS API 로 지금 활성 세션 중 접속 방식이 RDP 인 것.
//! 드라이버·주입 없이 사용자 모드에서 된다. 서비스(SYSTEM)는 모든 세션을 볼 수 있다.

use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
use windows_sys::Win32::System::RemoteDesktop::{
    WTSActive, WTSClientAddress, WTSClientName, WTSClientProtocolType, WTSEnumerateSessionsW,
    WTSFreeMemory, WTSQuerySessionInformationW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};

/// WTSClientProtocolType 값: 0 콘솔, 1 예전 ICA, 2 RDP
const PROTOCOL_RDP: u16 = 2;

/// 세션 하나의 정보 칸을 읽는다(버퍼는 WTSFreeMemory 로 돌려준다)
fn query(session: u32, class: i32) -> Option<Vec<u8>> {
    let mut buf: windows_sys::core::PWSTR = std::ptr::null_mut();
    let mut len: u32 = 0;
    // SAFETY: 출력 포인터는 이 함수 안의 지역 변수. 성공하면 buf 는 len 바이트이고 아래에서 복사 뒤 해제한다
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            class,
            &mut buf,
            &mut len,
        )
    };
    if ok == 0 || buf.is_null() {
        return None;
    }
    // SAFETY: WTS 가 len 바이트를 할당해 돌려줬다
    let bytes = unsafe { std::slice::from_raw_parts(buf as *const u8, len as usize) }.to_vec();
    unsafe { WTSFreeMemory(buf as *mut core::ffi::c_void) };
    Some(bytes)
}

/// WTS_CLIENT_ADDRESS(AddressFamily u32 + Address[20]) → IPv4 문자열. AF_INET(2) 은 Address[2..6] 에 들어 있다
/// (Microsoft 문서 WTS_CLIENT_ADDRESS). IPv6 등은 None
fn client_ip(b: &[u8]) -> Option<String> {
    if b.len() < 4 + 6 {
        return None;
    }
    let fam = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    if fam != 2 {
        return None;
    }
    let a = &b[4..];
    Some(format!("{}.{}.{}.{}", a[2], a[3], a[4], a[5]))
}

/// RDP 가 듣는 포트(레지스트리 RDP-Tcp PortNumber). 못 읽으면 3389
pub fn rdp_port() -> u16 {
    let key = super::wide(r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
    let val = super::wide("PortNumber");
    let mut v: u32 = 0;
    let mut cb = 4u32;
    // SAFETY: 출력은 지역 u32
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            &mut v as *mut u32 as *mut _,
            &mut cb,
        )
    };
    if r == 0 && v > 0 && v <= u16::MAX as u32 {
        v as u16
    } else {
        3389
    }
}

/// 지금 활성 상태인 RDP 세션들: (세션 id, 접속한 쪽 이름과 주소 — 이름은 접속한 쪽이 정하는 값이라 자료로만)
pub fn rdp_sessions() -> Result<Vec<(u32, String)>, String> {
    let mut p: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut n: u32 = 0;
    // SAFETY: 출력 포인터는 지역 변수. 성공하면 p 는 n 개 배열이고 끝에 해제한다
    let ok = unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut p, &mut n) };
    if ok == 0 || p.is_null() {
        return Err("WTSEnumerateSessionsW 실패".into());
    }
    // SAFETY: 위에서 받은 n 개 배열
    let list = unsafe { std::slice::from_raw_parts(p, n as usize) };
    let mut out = Vec::new();
    for s in list {
        if s.State != WTSActive {
            continue;
        }
        let proto = query(s.SessionId, WTSClientProtocolType)
            .filter(|b| b.len() >= 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .unwrap_or(0);
        if proto != PROTOCOL_RDP {
            continue;
        }
        let name = query(s.SessionId, WTSClientName)
            .map(|b| {
                let w: Vec<u16> = b
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|c| *c != 0)
                    .collect();
                String::from_utf16_lossy(&w)
            })
            .unwrap_or_default();
        // 34차 Gemini Q4: 주소를 앞에, 이름은 바꿀 수 있는 값으로 깎아 둔다(문장은 remote_watch 가 만든다)
        let ip = query(s.SessionId, WTSClientAddress)
            .and_then(|b| client_ip(&b))
            .unwrap_or_default();
        let name: String = name.chars().take(64).collect();
        out.push((s.SessionId, format!("{ip}\u{1f}{name}")));
    }
    // SAFETY: WTSEnumerateSessionsW 가 준 배열
    unsafe { WTSFreeMemory(p as *mut core::ffi::c_void) };
    Ok(out)
}
