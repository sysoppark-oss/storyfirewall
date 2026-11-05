//! 인증: 클라이언트 이미지 서명(우리 서명자 CN) + 관리자 그룹 검사. 명세 7판 2-8장, 10차 Q5.
//!
//! - 서명: `GetNamedPipeClientProcessId` → `OpenProcess(QUERY_LIMITED_INFORMATION)` → `QueryFullProcessImageNameW`
//!   → collector::signature::verify (오프라인 WinVerifyTrust) → status == valid ∧ signer == 기대 CN.
//!   실패면 연결을 끊는다(조회도 없음). 개발 중에는 기대 CN 을 테스트 인증서 CN 으로 둔다.
//! - 관리자: `ImpersonateNamedPipeClient` → `OpenThreadToken` → `CheckTokenMembership(Administrators)` → `RevertToSelf`.
//!   파이프 핸들이 필요하므로 연결마다 `WinAuthn { pipe }` 를 만든다.
//!   주의: Impersonate 는 그 파이프에서 데이터를 한 번 읽은 뒤에만 성공한다(ERROR_CANNOT_IMPERSONATE 0x558).
//!   핸들러는 hello 를 읽은 뒤 `is_admin` 을 부른다.

use std::ptr::null_mut;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CheckTokenMembership, FreeSid, RevertToSelf, PSID,
    SECURITY_NT_AUTHORITY, SID_IDENTIFIER_AUTHORITY, TOKEN_QUERY,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenThreadToken, QueryFullProcessImageNameW,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::handler::Authn;

const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x20;
const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x220;

pub fn image_of_pid(pid: u32) -> Option<String> {
    let h: HANDLE = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    let ok: BOOL = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// 파이프 클라이언트 토큰이 BUILTIN\Administrators 에 속하는가. 파이프 핸들을 가진 쪽(서버)에서 부른다.
pub fn client_is_admin(pipe: HANDLE) -> Result<bool, String> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(format!("ImpersonateNamedPipeClient 실패 {:#x}", unsafe {
            GetLastError()
        }));
    }
    let mut token: HANDLE = null_mut();
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let result = if opened == 0 {
        Err(format!("OpenThreadToken 실패 {:#x}", unsafe {
            GetLastError()
        }))
    } else {
        let auth: SID_IDENTIFIER_AUTHORITY = SECURITY_NT_AUTHORITY;
        let mut sid: PSID = null_mut();
        let ok = unsafe {
            AllocateAndInitializeSid(
                &auth,
                2,
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };
        let r = if ok == 0 {
            Err(format!("AllocateAndInitializeSid 실패 {:#x}", unsafe {
                GetLastError()
            }))
        } else {
            let mut member: BOOL = 0;
            let ok2 = unsafe { CheckTokenMembership(token, sid, &mut member) };
            unsafe { FreeSid(sid) };
            if ok2 == 0 {
                Err(format!("CheckTokenMembership 실패 {:#x}", unsafe {
                    GetLastError()
                }))
            } else {
                Ok(member != 0)
            }
        };
        unsafe { CloseHandle(token) };
        r
    };
    unsafe { RevertToSelf() };
    result
}

/// 서명 검사: 유효 ∧ 서명자 CN 일치
pub fn client_signature_ok(pid: u32, expected_signer: &str) -> (bool, String) {
    let Some(img) = image_of_pid(pid) else {
        return (false, "이미지 경로 없음".into());
    };
    let r = collector::signature::verify(&img);
    let ok = r.status == "valid" && r.signer.as_deref() == Some(expected_signer);
    (
        ok,
        format!(
            "{img}: status={} signer={:?} catalog={}",
            r.status, r.signer, r.catalog
        ),
    )
}

/// 제품 서명자 CN (컴파일 시 고정). OV 인증서 발급 뒤 실제 CN 으로 바꾼다 — README 열린 질문.
/// 실행 인자·설정 파일로는 바꿀 수 없다: 인자 조작 한 번으로 인증이 무력화되는 것을 막기 위함(제안 3).
pub const PRODUCT_SIGNER_CN: &str = "StoryFirewall";

/// Authn 구현. `pipe` 는 지금 처리 중인 연결의 핸들(관리자 검사에 필요).
pub struct WinAuthn {
    expected_signer: String,
    /// 시험 빌드 전용: 잎 인증서 SHA-256 고정 (있으면 CN·루트 신뢰 대신 이것으로 검사)
    pin: Option<String>,
    /// 배포 빌드: 클라이언트 실행 파일이 이 폴더(서비스 자신의 설치 폴더, 관리자만 쓰기) 아래여야 한다.
    /// 서명된 우리 UI 를 사용자 폴더로 복사하고 옆에 DLL 을 두는 사이드로딩을 막는다(24차 반영). 비어 있으면 검사 안 함(시험 빌드)
    client_dirs: Vec<String>,
    pipe: HANDLE,
}
unsafe impl Send for WinAuthn {}

impl WinAuthn {
    /// 제품 CN 으로 검사한다.
    pub fn new(pipe: HANDLE) -> Self {
        // 자기 폴더를 모르면 아무 클라이언트도 통과시키지 않는다(안전한 쪽으로 실패): 존재하지 않는 경로를 넣는다
        let own = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.display().to_string()))
            .unwrap_or_else(|| "\\\\?\\no-install-dir".into());
        Self {
            expected_signer: PRODUCT_SIGNER_CN.to_string(),
            pin: None,
            client_dirs: vec![judge::norm_dir(own)],
            pipe,
        }
    }
    /// 테스트 인증서 CN 으로 검사한다. `test-signer` feature 가 켜진 빌드에만 존재한다.
    #[cfg(feature = "test-signer")]
    pub fn with_test_signer(cn: &str, pipe: HANDLE) -> Self {
        Self {
            expected_signer: cn.to_string(),
            pin: None,
            client_dirs: Vec::new(),
            pipe,
        }
    }
}

#[cfg(feature = "test-signer")]
impl WinAuthn {
    /// 시험 인증서 잎 지문으로 검사한다(개발 PC 실사용 설치). 시험 인증서를 PC 의 신뢰할 루트에 넣지 않는다.
    pub fn with_test_pin(pin: &str, pipe: HANDLE) -> Self {
        Self {
            expected_signer: String::new(),
            pin: Some(pin.to_ascii_lowercase()),
            client_dirs: Vec::new(),
            pipe,
        }
    }
}

impl Authn for WinAuthn {
    fn client_image(&self, pid: u32) -> Option<String> {
        image_of_pid(pid)
    }
    fn signature_ok(&self, pid: u32) -> bool {
        if !self.client_dirs.is_empty() {
            let img = image_of_pid(pid).unwrap_or_default();
            if !judge::under_dirs(&img, &self.client_dirs) {
                println!("authn: client outside install dir: {img}");
                return false;
            }
        }
        if let Some(pin) = &self.pin {
            let Some(img) = image_of_pid(pid) else {
                return false;
            };
            let (ok, why) = collector::signature::pinned_leaf_ok(&img, pin);
            println!("authn: pinned {ok} {img} {why}");
            return ok;
        }
        client_signature_ok(pid, &self.expected_signer).0
    }
    fn is_admin(&self, _pid: u32) -> bool {
        match client_is_admin(self.pipe) {
            Ok(b) => {
                println!("authn: admin={b}");
                b
            }
            Err(e) => {
                println!("authn: admin check failed: {e}");
                false
            }
        }
    }
}
