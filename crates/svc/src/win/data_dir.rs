//! 서비스 데이터 폴더 (A26, 21차 반영): `%ProgramData%\StoryFirewall` — 그래프 DB·정책 DB·서비스 기록.
//!
//! 위협: `C:\ProgramData` 는 일반 사용자도 하위 폴더를 **만들 수** 있다. 서비스보다 먼저 `StoryFirewall` 폴더를 만들고
//! 자기 권한(또는 정션)으로 두면, 악성코드가 서비스가 읽을 정책 DB 를 심거나 서비스 기록을 바꿀 수 있다.
//! 대책:
//! 1. 쓰던 폴더는 HKLM\SOFTWARE\StoryFirewall\DataDir 에 적어 둔다(관리자·SYSTEM 만 씀). 다음 시작 때 그 폴더가 형식에 맞고
//!    소유자가 SYSTEM·Administrators 이고 재분석 지점이 아니면 그대로 쓴다.
//! 2. 기본 폴더가 이미 있는데 믿을 수 없으면(소유자 불명·정션) 옆으로 치우고(`StoryFirewall.untrusted-<시각>`) 새로 만든다.
//!    새 폴더 DACL = SYSTEM·Administrators 전체만(보호 — 상위 상속 끊음).
//! 3. (21차에서 찾은 구멍) 공격자가 미리 만든 폴더의 핸들을 **삭제 공유 없이** 쥐고 있으면 치우기(MoveFile)가 실패해
//!    서비스가 시작조차 못 한다(보호 꺼짐 DoS). → 무작위 이름의 대체 폴더(`StoryFirewall.<16 hex>`)를 만들어 쓰고 1의 값에 적는다.
//! 4. 치운 폴더는 증거로 두되 최근 5개만(디스크 고갈 방지, 21차 Q2). 지우기는 std::fs::remove_dir_all — 1.58.1 부터 정션을
//!    따라가지 않고 링크만 지운다(CVE-2022-21658 수정).
//! UI 는 일반 권한이라 이 폴더를 직접 읽지 않는다(파이프로만).

use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_ALREADY_EXISTS};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, GetFileAttributesW, MoveFileExW, FILE_ATTRIBUTE_REPARSE_POINT,
    INVALID_FILE_ATTRIBUTES,
};

use super::wide;

/// 보호 DACL: SYSTEM·Administrators 전체(하위 상속), 그 밖에는 없음
pub const DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
pub const REG_DATA_DIR: &str = "DataDir";
pub const NAME: &str = "StoryFirewall";
pub const KEEP_UNTRUSTED: usize = 5;

pub fn program_data() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
}

pub fn base() -> PathBuf {
    program_data().join(NAME)
}

/// 고른 데이터 폴더와 그 과정
#[derive(Debug, Default)]
pub struct Chosen {
    pub path: PathBuf,
    /// 치운 믿을 수 없는 폴더
    pub moved: Option<PathBuf>,
    /// 치우지 못해 대체 폴더를 씀 (사유)
    pub fallback: Option<String>,
    /// 상한으로 지운 예전 치운 폴더 수
    pub pruned: usize,
}

/// 우리 이름 형식인가: `<parent>\StoryFirewall` 또는 `<parent>\StoryFirewall.<16 hex>`
pub fn our_name(p: &Path, parent: &Path) -> bool {
    if p.parent() != Some(parent) {
        return false;
    }
    let Some(n) = p.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    n == NAME
        || n.strip_prefix(&format!("{NAME}."))
            .is_some_and(|h| h.len() == 16 && h.bytes().all(|c| c.is_ascii_hexdigit()))
}

fn attrs(p: &Path) -> u32 {
    unsafe { GetFileAttributesW(wide(&p.to_string_lossy()).as_ptr()) }
}

/// 이미 있고, 정션이 아니고, 소유자가 SYSTEM·Administrators
pub fn trusted_existing(p: &Path) -> bool {
    let a = attrs(p);
    a != INVALID_FILE_ATTRIBUTES && a & FILE_ATTRIBUTE_REPARSE_POINT == 0 && owner_trusted(p)
}

/// 제거 때 기록 지우기 (A28): 기준 폴더와 HKLM DataDir(대체 폴더)를 **우리 이름 형식 + 정션 아님 + 소유자 SYSTEM·Administrators** 일 때만 지운다.
/// 설치 프로그램(관리자)이 경로를 그대로 지우면, 일반 사용자가 ProgramData 에 미리 만든 정션으로 다른 폴더를 지우게 할 수 있다.
/// `std::fs::remove_dir_all` 은 안쪽 정션·심볼릭 링크를 따라가지 않는다(Rust 1.58 수정). 반환: 지운 폴더들
pub fn purge(base: &Path, extra: Option<PathBuf>) -> Vec<PathBuf> {
    let Some(parent) = base.parent() else {
        return vec![];
    };
    let mut out = vec![];
    for p in std::iter::once(base.to_path_buf()).chain(extra) {
        if our_name(&p, parent) && trusted_existing(&p) && std::fs::remove_dir_all(&p).is_ok() {
            out.push(p);
        }
    }
    out
}

/// 보호 DACL 로 새로 만든다. 이미 있으면(경쟁) 믿을 수 있을 때만 성공
fn create_protected(p: &Path) -> Result<(), String> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(DIR_SDDL).as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(format!(
            "SDDL 변환 실패 {}",
            std::io::Error::last_os_error()
        ));
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let ok = unsafe { CreateDirectoryW(wide(&p.to_string_lossy()).as_ptr(), &sa) } != 0;
    let e = unsafe { GetLastError() };
    unsafe { LocalFree(sd as _) };
    if ok {
        return Ok(());
    }
    if e == ERROR_ALREADY_EXISTS && trusted_existing(p) {
        return Ok(());
    }
    Err(format!("폴더 생성 실패 {}: {e}", p.display()))
}

fn random_hex16() -> String {
    crate::change::new_uuid().replace('-', "")[..16].to_string()
}

/// 데이터 폴더를 고른다. `persist` = HKLM 에 기록·조회 (시험용 대체 기준 폴더에서는 끈다)
pub fn ensure(base: &Path, persist: bool) -> Result<Chosen, String> {
    let parent = base
        .parent()
        .ok_or("기준 폴더에 상위가 없음")?
        .to_path_buf();
    let mut c = Chosen::default();
    // 1. 지난번에 쓰던 폴더
    if persist {
        if let Some(prev) = super::pipe_name::reg_get(REG_DATA_DIR).map(PathBuf::from) {
            if our_name(&prev, &parent) && trusted_existing(&prev) {
                c.path = prev;
                c.pruned = prune_untrusted(&parent, base);
                return Ok(c);
            }
        }
    }
    // 2. 기본 폴더
    let a = attrs(base);
    let mut usable = a == INVALID_FILE_ATTRIBUTES;
    if !usable {
        if trusted_existing(base) {
            c.path = base.to_path_buf();
        } else {
            let aside = parent.join(format!(
                "{}.untrusted-{}",
                base.file_name().and_then(|n| n.to_str()).unwrap_or(NAME),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            if unsafe {
                MoveFileExW(
                    wide(&base.to_string_lossy()).as_ptr(),
                    wide(&aside.to_string_lossy()).as_ptr(),
                    0,
                )
            } != 0
            {
                c.moved = Some(aside);
                usable = true;
            } else {
                // 3. 치우지 못함 (공유 위반 등) → 대체 폴더
                c.fallback = Some(format!("{}", std::io::Error::last_os_error()));
            }
        }
    }
    if c.path.as_os_str().is_empty() {
        if usable {
            create_protected(base)?;
            c.path = base.to_path_buf();
        } else {
            let mut last = String::new();
            for _ in 0..5 {
                let p = parent.join(format!(
                    "{}.{}",
                    base.file_name().and_then(|n| n.to_str()).unwrap_or(NAME),
                    random_hex16()
                ));
                match create_protected(&p) {
                    Ok(()) => {
                        c.path = p;
                        break;
                    }
                    Err(e) => last = e,
                }
            }
            if c.path.as_os_str().is_empty() {
                return Err(format!("대체 데이터 폴더도 만들지 못함: {last}"));
            }
        }
    }
    if persist {
        super::pipe_name::reg_set(REG_DATA_DIR, &c.path.to_string_lossy())?;
    }
    c.pruned = prune_untrusted(&parent, base);
    Ok(c)
}

/// 치운 폴더(`<기준>.untrusted-<시각>`)는 최근 KEEP_UNTRUSTED 개만 남긴다 (시각 = 이름, 오래된 것부터 지움)
pub fn prune_untrusted(parent: &Path, base: &Path) -> usize {
    let prefix = format!(
        "{}.untrusted-",
        base.file_name().and_then(|n| n.to_str()).unwrap_or(NAME)
    );
    let Ok(rd) = std::fs::read_dir(parent) else {
        return 0;
    };
    let mut v: Vec<(u128, PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_prefix(&prefix)
                .and_then(|t| t.parse::<u128>().ok())
                .map(|t| (t, e.path()))
        })
        .collect();
    v.sort();
    let extra = v.len().saturating_sub(KEEP_UNTRUSTED);
    let mut n = 0;
    for (_, p) in v.into_iter().take(extra) {
        if std::fs::remove_dir_all(&p).is_ok() {
            n += 1;
        }
    }
    n
}

/// 소유자가 SYSTEM 또는 Administrators 인가
pub fn owner_trusted(path: &Path) -> bool {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let r = unsafe {
        GetNamedSecurityInfoW(
            wide(&path.to_string_lossy()).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if r != 0 || owner.is_null() {
        if !sd.is_null() {
            unsafe { LocalFree(sd as _) };
        }
        return false;
    }
    let ok = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
    };
    unsafe { LocalFree(sd as _) };
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn our_name_only_accepts_our_folders() {
        let pd = PathBuf::from(r"C:\ProgramData");
        assert!(our_name(&pd.join("StoryFirewall"), &pd));
        assert!(our_name(&pd.join("StoryFirewall.0123456789abcdef"), &pd));
        assert!(!our_name(&pd.join("StoryFirewall.untrusted-1"), &pd));
        assert!(!our_name(&PathBuf::from(r"C:\Users\x\StoryFirewall"), &pd));
        assert!(!our_name(&pd.join("StoryFirewall.0123"), &pd));
    }
}
