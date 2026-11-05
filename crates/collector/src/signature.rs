//! 서명 검증 (명세 5판 2-3): 오프라인 WinVerifyTrust + 카탈로그 서명
//!
//! - `WTD_REVOKE_NONE` + `WTD_CACHE_ONLY_URL_RETRIEVAL`: 외부 통신 없음 (제품 원칙). 폐기된 인증서는 못 잡는다.
//! - 파일 안에 서명이 없으면(TRUST_E_NOSIGNATURE) 카탈로그 경로: 해시 → 카탈로그 찾기 → WTD_CHOICE_CATALOG.
//! - 서명자·발급자 이름은 WTHelperProvDataFromStateData → 첫 서명자 → 체인[0] 인증서에서 읽는다.

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    CertGetCertificateContextProperty, CertGetNameStringW, BCRYPT_SHA256_ALGORITHM,
    CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_SHA256_HASH_PROP_ID,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigResult {
    pub signer: Option<String>,
    pub issuer: Option<String>,
    /// "valid" | "nosignature" | "untrusted:root" | "untrusted:distrusted" | "untrusted:bad_digest" | "error:<hex>"
    pub status: String,
    pub catalog: bool,
}

const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
const TRUST_E_BAD_DIGEST: i32 = 0x80096010u32 as i32;
const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111u32 as i32;
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B0109u32 as i32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 상태 데이터에서 (서명자, 발급자) 이름
unsafe fn signer_names(
    state: windows_sys::Win32::Foundation::HANDLE,
) -> (Option<String>, Option<String>) {
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return (None, None);
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
    if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
        return (None, None);
    }
    let cert = (*(*sgnr).pasCertChain).pCert;
    if cert.is_null() {
        return (None, None);
    }
    let name = |flags: u32| -> Option<String> {
        let mut buf = vec![0u16; 256];
        let n = CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            std::ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if n <= 1 {
            None
        } else {
            Some(String::from_utf16_lossy(&buf[..(n - 1) as usize]))
        }
    };
    (name(0), name(CERT_NAME_ISSUER_FLAG))
}

fn status_of(rc: i32) -> String {
    match rc {
        0 => "valid".into(),
        TRUST_E_NOSIGNATURE => "nosignature".into(),
        TRUST_E_BAD_DIGEST => "untrusted:bad_digest".into(),
        // 둘을 나눈다(L015): 명시적 불신은 깨짐과 같은 무게, 신뢰 체인 없음(자체 서명·사설 인증서)은 내용은 온전한 서명
        TRUST_E_EXPLICIT_DISTRUST => "untrusted:distrusted".into(),
        CERT_E_UNTRUSTEDROOT => "untrusted:root".into(),
        other => format!("error:{:08x}", other as u32),
    }
}

/// 파일 내장 서명 검증 (오프라인)
fn verify_embedded(path: &str) -> (i32, Option<String>, Option<String>) {
    let wpath = wide(path);
    let mut fi: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
    fi.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
    fi.pcwszFilePath = wpath.as_ptr();
    fi.hFile = std::ptr::null_mut();
    let mut wd: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    wd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.Anonymous.pFile = &mut fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let rc = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut wd as *mut _ as *mut _,
        )
    };
    let names = if rc == 0 {
        unsafe { signer_names(wd.hWVTStateData) }
    } else {
        (None, None)
    };
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut wd as *mut _ as *mut _,
        )
    };
    (rc, names.0, names.1)
}

/// 카탈로그 서명 검증: 파일 해시 → 카탈로그 → WTD_CHOICE_CATALOG
fn verify_catalog(path: &str) -> Option<(i32, Option<String>, Option<String>)> {
    let wpath = wide(path);
    let h = unsafe {
        CreateFileW(
            wpath.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut admin: isize = 0;
    let driver_action: GUID = GUID::from_u128(0xf750e6c3_38ee_11d1_85e5_00c04fc295ee); // DRIVER_ACTION_VERIFY
    if unsafe {
        CryptCATAdminAcquireContext2(
            &mut admin,
            &driver_action,
            BCRYPT_SHA256_ALGORITHM,
            std::ptr::null(),
            0,
        )
    } == 0
    {
        unsafe { CloseHandle(h) };
        return None;
    }
    let mut hash_len: u32 = 0;
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut hash_len, std::ptr::null_mut(), 0)
    };
    let mut hash = vec![0u8; hash_len.max(32) as usize];
    let ok = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut hash_len, hash.as_mut_ptr(), 0)
    };
    let mut result = None;
    if ok != 0 {
        let mut prev: isize = 0;
        let cat = unsafe {
            CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), hash_len, 0, &mut prev)
        };
        if cat != 0 {
            let mut info: CATALOG_INFO = unsafe { std::mem::zeroed() };
            info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
            if unsafe { CryptCATCatalogInfoFromContext(cat, &mut info, 0) } != 0 {
                // 멤버 태그 = 해시 16진 문자열
                let tag: String = hash[..hash_len as usize]
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect();
                let wtag = wide(&tag);
                let mut ci: WINTRUST_CATALOG_INFO = unsafe { std::mem::zeroed() };
                ci.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
                ci.pcwszCatalogFilePath = info.wszCatalogFile.as_ptr();
                ci.pcwszMemberTag = wtag.as_ptr();
                ci.pcwszMemberFilePath = wpath.as_ptr();
                ci.hMemberFile = h;
                ci.pbCalculatedFileHash = hash.as_mut_ptr();
                ci.cbCalculatedFileHash = hash_len;
                ci.hCatAdmin = admin;
                let mut wd: WINTRUST_DATA = unsafe { std::mem::zeroed() };
                wd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
                wd.dwUIChoice = WTD_UI_NONE;
                wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                wd.Anonymous.pCatalog = &mut ci;
                wd.dwStateAction = WTD_STATEACTION_VERIFY;
                wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
                let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                let rc = unsafe {
                    WinVerifyTrust(
                        std::ptr::null_mut(),
                        &mut action,
                        &mut wd as *mut _ as *mut _,
                    )
                };
                let names = if rc == 0 {
                    unsafe { signer_names(wd.hWVTStateData) }
                } else {
                    (None, None)
                };
                wd.dwStateAction = WTD_STATEACTION_CLOSE;
                unsafe {
                    WinVerifyTrust(
                        std::ptr::null_mut(),
                        &mut action,
                        &mut wd as *mut _ as *mut _,
                    )
                };
                result = Some((rc, names.0, names.1));
            }
            unsafe { CryptCATAdminReleaseCatalogContext(admin, cat, 0) };
        }
    }
    unsafe {
        CryptCATAdminReleaseContext(admin, 0);
        CloseHandle(h);
    }
    result
}

pub fn verify(path: &str) -> SigResult {
    let (rc, signer, issuer) = verify_embedded(path);
    if rc != TRUST_E_NOSIGNATURE {
        return SigResult {
            signer,
            issuer,
            status: status_of(rc),
            catalog: false,
        };
    }
    match verify_catalog(path) {
        Some((rc, signer, issuer)) => SigResult {
            signer,
            issuer,
            status: status_of(rc),
            catalog: true,
        },
        None => SigResult {
            signer: None,
            issuer: None,
            status: "nosignature".into(),
            catalog: false,
        },
    }
}

/// 개발 빌드 전용 인증(시험 인증서 지문 고정, 2026-11-02 사용자 결정 — 노트북 실사용).
/// 파일에 **내장된** Authenticode 서명이 암호학적으로 맞고(WinVerifyTrust 가 0 또는 "신뢰할 수 없는 루트"만 문제),
/// 서명자(잎) 인증서의 SHA-256 지문이 `pin`(소문자 16진 64자)과 같을 때만 true.
/// 시험 인증서를 컴퓨터의 신뢰할 루트에 넣지 않으려는 것 — 넣으면 그 인증서로 서명한 아무 프로그램이나 PC 전체에서 믿게 된다.
/// 카탈로그 서명은 보지 않는다. 다이제스트 불일치(TRUST_E_BAD_DIGEST)·서명 없음·명시적 불신은 거부.
pub fn pinned_leaf_ok(path: &str, pin: &str) -> (bool, String) {
    let wpath = wide(path);
    let mut fi: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
    fi.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
    fi.pcwszFilePath = wpath.as_ptr();
    let mut wd: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    wd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.Anonymous.pFile = &mut fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let rc = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut wd as *mut _ as *mut _,
        )
    };
    let hash = if rc == 0 || rc == CERT_E_UNTRUSTEDROOT {
        unsafe { leaf_sha256(wd.hWVTStateData) }
    } else {
        None
    };
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut wd as *mut _ as *mut _,
        )
    };
    let ok = hash
        .as_deref()
        .is_some_and(|h| pin.len() == 64 && h == pin.to_ascii_lowercase());
    (
        ok,
        format!(
            "rc={:08x} leaf_sha256={}",
            rc as u32,
            hash.unwrap_or_else(|| "-".into())
        ),
    )
}

unsafe fn leaf_sha256(state: windows_sys::Win32::Foundation::HANDLE) -> Option<String> {
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return None;
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
    if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
        return None;
    }
    let cert = (*(*sgnr).pasCertChain).pCert;
    if cert.is_null() {
        return None;
    }
    let mut buf = [0u8; 32];
    let mut len = buf.len() as u32;
    if CertGetCertificateContextProperty(
        cert,
        CERT_SHA256_HASH_PROP_ID,
        buf.as_mut_ptr() as *mut _,
        &mut len,
    ) == 0
        || len != 32
    {
        return None;
    }
    Some(buf.iter().map(|b| format!("{b:02x}")).collect())
}
