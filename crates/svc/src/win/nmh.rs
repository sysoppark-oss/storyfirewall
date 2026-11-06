//! 자동 조사: 브라우저 확장 보조 프로그램(네이티브 메시징 호스트) 등록 읽기.
//! 위치: HKLM(64·32비트 보기)과 HKEY_USERS\<SID>(로그온한 사용자의 HKCU) 아래 브라우저별 NativeMessagingHosts\<이름> 의 기본값 = 매니페스트 경로.
//! 매니페스트 JSON 의 "path" 가 실행 파일(상대 경로면 매니페스트 폴더 기준). 읽기만(KEY_READ), 파일은 64KB 까지만 읽는다.
//! 이름·경로는 외부에서 온 문자열 — 비교와 표시(자료)에만 쓴다.
use crate::host::NativeHost;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ,
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, RRF_RT_REG_SZ,
};

const BROWSERS: &[(&str, &str)] = &[
    ("chrome", r"Software\Google\Chrome\NativeMessagingHosts"),
    ("edge", r"Software\Microsoft\Edge\NativeMessagingHosts"),
    ("brave", r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts"),
    ("chromium", r"Software\Chromium\NativeMessagingHosts"),
    ("firefox", r"Software\Mozilla\NativeMessagingHosts"),
];

fn open(root: HKEY, sub: &str, extra: u32) -> Option<HKEY> {
    let w = super::wide(sub);
    let mut k: HKEY = std::ptr::null_mut();
    // SAFETY: 출력 핸들은 지역 변수
    let r = unsafe { RegOpenKeyExW(root, w.as_ptr(), 0, KEY_READ | extra, &mut k) };
    (r == 0).then_some(k)
}

fn subkeys(k: HKEY) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..1024u32 {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: 이름 버퍼와 길이는 지역 변수
        let r = unsafe {
            RegEnumKeyExW(k, i, name.as_mut_ptr(), &mut len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        if r != 0 {
            break;
        }
        out.push(String::from_utf16_lossy(&name[..len as usize]));
    }
    out
}

/// 하위 키의 기본값(문자열)
fn default_value(k: HKEY, sub: &str) -> Option<String> {
    let mut buf = [0u16; 1024];
    let mut cb = (buf.len() * 2) as u32;
    let w = super::wide(sub);
    // SAFETY: 출력 버퍼는 지역 배열. 값 이름 null = 기본값
    let r = unsafe { RegGetValueW(k, w.as_ptr(), std::ptr::null(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut cb) };
    if r != 0 {
        return None;
    }
    let n = (cb as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

/// 매니페스트 → 실행 파일 경로(상대면 매니페스트 폴더 기준)
pub fn manifest_exe(manifest: &str) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(manifest).ok()?;
    let mut buf = Vec::new();
    f.by_ref().take(64 * 1024).read_to_end(&mut buf).ok()?;
    // 일부 매니페스트는 BOM 이 있다
    let text = String::from_utf8_lossy(&buf);
    let v: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let p = v.get("path")?.as_str()?.to_string();
    Some(resolve(manifest, &p))
}

/// 상대 경로를 매니페스트 폴더 기준으로
pub fn resolve(manifest: &str, p: &str) -> String {
    let is_abs = p.len() > 2 && p.as_bytes()[1] == b':' || p.starts_with("\\\\");
    if is_abs {
        return p.replace('/', "\\");
    }
    let dir = std::path::Path::new(manifest).parent().map(|d| d.to_path_buf()).unwrap_or_default();
    dir.join(p.replace('/', "\\")).to_string_lossy().into_owned()
}

fn scan(root: HKEY, scope: &str, prefix: &str, extra: u32, out: &mut Vec<NativeHost>) {
    for (browser, sub) in BROWSERS {
        let path = if prefix.is_empty() { sub.to_string() } else { format!("{prefix}\\{sub}") };
        let Some(k) = open(root, &path, extra) else { continue };
        for name in subkeys(k) {
            if let Some(manifest) = default_value(k, &name) {
                let exe = manifest_exe(&manifest).unwrap_or_default();
                let h = NativeHost { browser: browser.to_string(), name, scope: scope.to_string(), manifest, path: exe };
                if !out.contains(&h) {
                    out.push(h);
                }
            }
        }
        // SAFETY: 위에서 연 키
        unsafe { RegCloseKey(k) };
    }
}

/// 이 PC 의 등록 전부(HKLM 64·32비트 보기 + 불러와 있는 사용자 하이브)
pub fn native_hosts() -> Vec<NativeHost> {
    let mut out = Vec::new();
    scan(HKEY_LOCAL_MACHINE, "HKLM", "", KEY_WOW64_64KEY, &mut out);
    scan(HKEY_LOCAL_MACHINE, "HKLM", "", KEY_WOW64_32KEY, &mut out);
    for sid in subkeys(HKEY_USERS) {
        // .DEFAULT·서비스 계정(S-1-5-18/19/20)·_Classes 하이브는 건너뛴다
        if !sid.starts_with("S-1-5-21-") || sid.ends_with("_Classes") {
            continue;
        }
        scan(HKEY_USERS, &format!("HKU\\{sid}"), &sid, 0, &mut out);
    }
    out
}
