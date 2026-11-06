//! 원격 데스크톱(RDP) 세션 보기 (32차 Gemini Q1, 14판 20-4): WTS API 로 지금 활성 세션 중 접속 방식이 RDP 인 것.
//! 드라이버·주입 없이 사용자 모드에서 된다. 서비스(SYSTEM)는 모든 세션을 볼 수 있다.

use windows_sys::Win32::System::RemoteDesktop::{
    WTSActive, WTSClientName, WTSClientProtocolType, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSQuerySessionInformationW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
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

/// 지금 활성 상태인 RDP 세션들: (세션 id, 접속한 쪽 컴퓨터 이름 — 접속한 쪽이 정하는 값이라 자료로만)
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
        out.push((s.SessionId, name.chars().take(64).collect()));
    }
    // SAFETY: WTSEnumerateSessionsW 가 준 배열
    unsafe { WTSFreeMemory(p as *mut core::ffi::c_void) };
    Ok(out)
}
