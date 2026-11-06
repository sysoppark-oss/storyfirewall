//! 미끼(카나리) 폴더 (기획서 17판 23-2 ②, L061).
//!
//! 보안 설계:
//! - **만들기는 사용자 권한(UI)에서만** 한다(`ensure`). 서비스(SYSTEM)가 사용자 폴더에 쓰면, 악성 프로그램이 미끼 자리에
//!   정션·심볼릭 링크를 미리 심어 SYSTEM 이 엉뚱한 곳(예: System32)에 쓰게 만드는 권한 상승 공격의 표적이 된다.
//! - **서비스는 읽기만** 한다(`discover`). 경로 구간 중 하나라도 재해석 지점(정션·링크)이면 그 미끼는 버린다.
//!   표시 파일(MARKER)은 누구나 만들 수 있지만, 그래 봐야 후보 위치의 "미끼 열기" 알림이 늘 뿐이다(권한 상승 없음).
//! - 실제 사용자 프로그램 폴더를 미끼로 오인하지 않게, 폴더가 이미 있으면(표시 파일 없음) 건드리지 않는다.
//!   나중에 그 프로그램이 설치돼 미끼 폴더에 다른 파일이 생기면 우리 파일만 지우고 물러난다(`ensure` 의 Retired).
//! - 미끼 파일에는 실제 정보를 넣지 않는다.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// 미끼 후보 폴더 하나
#[derive(Debug)]
pub struct Candidate {
    /// 사용자 프로필(`x:\users\<u>\`) 다음 부분(소문자, 구분자 `\`, 끝 `\`)
    pub under_profile: &'static str,
    /// 수집기 1차 거르기용 부분 문자열
    pub fragment: &'static str,
    /// 화면 이름
    pub label: &'static str,
    /// 미끼 폴더 안에 만들 가짜 파일(상대 경로, 구분자 `\`)
    pub files: &'static [&'static str],
    /// 우리 미끼라는 표시 파일 — 그 프로그램에 있을 법한 이름(L062, 30차 Q9-c: 뻔한 이름은 탈취 도구가 건너뛰는 표식이 된다).
    /// 이름만 보고는 미끼인지 알 수 없고, 내용을 보려고 여는 순간 미끼 열기로 잡힌다
    pub marker: &'static str,
    /// 그 프로그램의 이름 조각(소문자). 설치 엑스레이가 이 이름의 설치를 찾으면 미끼를 미리 물러나게 한다(L066, 30차 Q9-d)
    pub keyword: &'static str,
}

/// 미끼 후보: 정보 탈취 도구가 흔히 뒤지는 위치 중 국내에서 드물게 쓰는 프로그램의 폴더
pub const CANDIDATES: &[Candidate] = &[
    Candidate {
        under_profile: "appdata\\local\\centbrowser\\user data\\",
        fragment: "\\centbrowser\\user data\\",
        label: "미끼 브라우저 프로필",
        files: &[
            "Local State",
            "Default\\Login Data",
            "Default\\Network\\Cookies",
        ],
        marker: "Last Version",
        keyword: "centbrowser",
    },
    Candidate {
        under_profile: "appdata\\roaming\\exodus\\exodus.wallet\\",
        fragment: "\\exodus\\exodus.wallet\\",
        label: "미끼 지갑 폴더",
        files: &["seed.seco", "passphrase.json"],
        marker: "storage.seco",
        keyword: "exodus",
    },
    Candidate {
        under_profile: "appdata\\roaming\\electrum\\wallets\\",
        fragment: "\\electrum\\wallets\\",
        label: "미끼 지갑 폴더",
        files: &["default_wallet"],
        marker: ".lock",
        keyword: "electrum",
    },
];

/// 표시 파일 내용 — 이름은 후보마다 그럴듯하게(Candidate::marker), 우리 것인지는 내용으로 안다
const MARKER_BODY: &[u8] = b"sfdc1\n";

/// 옛 표시 파일 이름(9b424d6). 보이면 새 표시로 옮긴다
const LEGACY_MARKER: &str = ".storyfirewall-decoy";

/// 이 폴더의 표시가 우리 것인가(새 표시: 이름 + 내용, 옛 표시: 이름)
fn is_ours(dir: &Path, c: &Candidate) -> bool {
    fs::read(dir.join(c.marker))
        .map(|b| b == MARKER_BODY)
        .unwrap_or(false)
        || dir.join(LEGACY_MARKER).is_file()
}

/// 가짜 파일 내용 — 실제 정보 없음
const FAKE: &[u8] = b"Story Firewall decoy file. No real data.\n";

/// `ensure` 결과
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ensured {
    /// 새로 만들었다
    Created,
    /// 이미 우리 미끼다
    Ours,
    /// 실제 프로그램 폴더라 건드리지 않았다
    Real,
    /// 우리 미끼였는데 다른 파일이 생겨(실제 프로그램 설치) 우리 파일만 지우고 물러났다
    Retired,
    /// 만들다 실패(권한 등) — 사유
    Failed(String),
}

fn join_rel(base: &Path, rel: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    for c in rel.split('\\').filter(|c| !c.is_empty()) {
        p.push(c);
    }
    p
}

/// 우리 파일(표시 + 가짜 파일 + 그 사이 폴더) 말고 다른 것이 있는가
fn has_foreign(dir: &Path, c: &Candidate) -> bool {
    let ours: Vec<PathBuf> = [dir.join(c.marker), dir.join(LEGACY_MARKER)]
        .into_iter()
        .chain(c.files.iter().map(|f| join_rel(dir, f)))
        .collect();
    fn walk(d: &Path, ours: &[PathBuf]) -> bool {
        let Ok(rd) = fs::read_dir(d) else {
            return false;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = fs::symlink_metadata(&p) else {
                continue;
            };
            if m.is_dir() {
                // 우리 가짜 파일이 들어 있는 중간 폴더면 안으로
                if ours.iter().any(|o| o.starts_with(&p)) {
                    if walk(&p, ours) {
                        return true;
                    }
                } else {
                    return true;
                }
            } else if !ours.iter().any(|o| o == &p) {
                return true;
            }
        }
        false
    }
    walk(dir, &ours)
}

/// (사용자 권한에서) 이 프로필의 미끼를 맞춘다. 서비스(SYSTEM)에서 부르지 말 것
pub fn ensure(profile: &Path) -> Vec<(PathBuf, Ensured)> {
    let mut out = Vec::new();
    for c in CANDIDATES {
        let dir = join_rel(profile, c.under_profile);
        let r = if dir.exists() {
            if is_ours(&dir, c) {
                // 옛 표시 → 새 표시
                if dir.join(LEGACY_MARKER).is_file() {
                    let _ = fs::write(dir.join(c.marker), MARKER_BODY);
                    let _ = fs::remove_file(dir.join(LEGACY_MARKER));
                }
                if has_foreign(&dir, c) {
                    // 실제 프로그램이 들어왔다 → 우리 파일만 지운다(폴더는 그 프로그램 것이 됐으니 남긴다)
                    let _ = fs::remove_file(dir.join(c.marker));
                    for f in c.files {
                        let p = join_rel(&dir, f);
                        if fs::read(&p).map(|b| b == FAKE).unwrap_or(false) {
                            let _ = fs::remove_file(p);
                        }
                    }
                    Ensured::Retired
                } else {
                    Ensured::Ours
                }
            } else {
                Ensured::Real
            }
        } else {
            match create(&dir, c) {
                Ok(()) => Ensured::Created,
                Err(e) => Ensured::Failed(e.to_string()),
            }
        };
        out.push((dir, r));
    }
    out
}

fn create(dir: &Path, c: &Candidate) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    for f in c.files {
        let p = join_rel(dir, f);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)?
            .write_all(FAKE)?;
    }
    // 표시 파일은 마지막에 — 중간에 실패하면 다음번에 "실제 폴더"로 보고 건드리지 않는다(안전한 쪽)
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(c.marker))?
        .write_all(MARKER_BODY)?;
    Ok(())
}

/// 재해석 지점(정션·심볼릭 링크)인가 — 읽기만
fn is_reparse(p: &Path) -> bool {
    let Ok(m) = fs::symlink_metadata(p) else {
        return true;
    };
    if m.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// (서비스, 읽기만) `users_root`(예: `C:\Users`) 아래 각 사용자 프로필에서 우리 미끼 폴더를 찾는다.
/// 프로필부터 미끼 폴더까지 경로 구간 중 하나라도 재해석 지점이면 버린다. 쓰지 않는다
pub fn discover(users_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(users_root) else {
        return out;
    };
    for e in rd.flatten() {
        let profile = e.path();
        if is_reparse(&profile) || !profile.is_dir() {
            continue;
        }
        for c in CANDIDATES {
            let mut p = profile.clone();
            let mut ok = true;
            for comp in c.under_profile.split('\\').filter(|s| !s.is_empty()) {
                p.push(comp);
                if is_reparse(&p) || !p.is_dir() {
                    ok = false;
                    break;
                }
            }
            // 이름만 확인(읽지 않음 — 서비스는 내용을 열지 않는다). 내용 확인은 사용자 권한의 ensure 가 한다
            let marker_ok = |name: &str| {
                fs::symlink_metadata(p.join(name))
                    .map(|m| m.is_file())
                    .unwrap_or(false)
            };
            if ok && (marker_ok(c.marker) || marker_ok(LEGACY_MARKER)) {
                out.push(p);
            }
        }
    }
    out
}

/// 등록할 미끼 폴더 가운데 그 프로그램의 실제 설치가 보이는 것을 뺀다(L066, 30차 Q9-d).
/// `installs` = 최근 설치마다 (설치 프로그램 경로, 설치가 쓴 파일 경로들). 설치 프로그램 이름에 후보 이름 조각이 있거나,
/// 설치가 쓴 파일 경로에 `\<이름 조각>` 이 들어 있으면(미끼 폴더 안 제외) 그 후보는 실제 프로그램이 들어온 것으로 본다.
/// 실제 프로그램이 자기 폴더를 여는 것을 "미끼 열기"로 오탐하지 않으려는 것 — 판정 등록만 뺀다(파일 지우기는 UI 의 `ensure`).
/// 돌려주는 값: (남길 폴더, 물러난 폴더)
pub fn retire_for_installs(
    dirs: Vec<String>,
    installs: &[(String, Vec<String>)],
) -> (Vec<String>, Vec<String>) {
    let mut keep = Vec::new();
    let mut retired = Vec::new();
    for d in dirs {
        let dl = d.replace('/', "\\").to_ascii_lowercase();
        let dl_slash = if dl.ends_with('\\') {
            dl.clone()
        } else {
            format!("{dl}\\")
        };
        let Some(c) = CANDIDATES
            .iter()
            .find(|c| dl_slash.ends_with(c.under_profile))
        else {
            keep.push(d);
            continue;
        };
        let seg = format!("\\{}", c.keyword);
        let hit = installs.iter().any(|(image, files)| {
            let img = image.replace('/', "\\").to_ascii_lowercase();
            let name = img.rsplit('\\').next().unwrap_or(&img);
            name.contains(c.keyword)
                || (img.contains(&seg) && !img.starts_with(&dl_slash))
                || files.iter().any(|f| {
                    let fl = f.replace('/', "\\").to_ascii_lowercase();
                    fl.contains(&seg) && !fl.starts_with(&dl_slash)
                })
        });
        if hit {
            retired.push(d);
        } else {
            keep.push(d);
        }
    }
    (keep, retired)
}

/// L070(30차 Q9-b): 지난번 등록했던 미끼 중 이번 찾기에서 사라진 것(실제 프로그램이 들어와 물러난 것은 뺀다).
/// 사라진 사실만 남긴다 — 누가 지웠는지는 이 비교만으로 알 수 없다(사용자 정리·백신·탈취 도구 모두 가능)
pub fn vanished(prev: &[String], found: &[String], retired: &[String]) -> Vec<String> {
    let norm = |d: &String| {
        d.replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    let found: std::collections::HashSet<String> = found.iter().chain(retired).map(norm).collect();
    prev.iter()
        .filter(|d| !found.contains(&norm(d)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sf-decoy-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn creates_then_ours_then_discovered() {
        let users = tmp("a");
        let prof = users.join("u");
        fs::create_dir_all(&prof).unwrap();
        let r = ensure(&prof);
        assert!(r.iter().all(|(_, e)| *e == Ensured::Created), "{r:?}");
        assert!(join_rel(
            &prof,
            "appdata\\local\\centbrowser\\user data\\Default\\Login Data"
        )
        .is_file());
        let r = ensure(&prof);
        assert!(r.iter().all(|(_, e)| *e == Ensured::Ours), "{r:?}");
        assert_eq!(discover(&users).len(), CANDIDATES.len());
    }

    #[test]
    fn real_program_folder_is_left_alone() {
        let users = tmp("b");
        let prof = users.join("u");
        let real = join_rel(&prof, "appdata\\roaming\\exodus\\exodus.wallet\\");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("seed.seco"), b"real").unwrap();
        let r = ensure(&prof);
        assert!(r.iter().any(|(p, e)| p == &real && *e == Ensured::Real));
        assert_eq!(
            fs::read(real.join("seed.seco")).unwrap(),
            b"real",
            "실제 파일은 그대로"
        );
        assert!(!real.join("storage.seco").exists());
        assert!(!discover(&users).iter().any(|p| p == &real));
    }

    #[test]
    fn retires_when_real_program_moves_in() {
        let users = tmp("c");
        let prof = users.join("u");
        ensure(&prof);
        let dir = join_rel(&prof, "appdata\\roaming\\electrum\\wallets\\");
        fs::write(dir.join("my_wallet"), b"real").unwrap();
        let r = ensure(&prof);
        assert!(r.iter().any(|(p, e)| p == &dir && *e == Ensured::Retired));
        assert!(!dir.join(".lock").exists() && !dir.join("default_wallet").exists());
        assert!(dir.join("my_wallet").exists(), "실제 파일은 남긴다");
    }

    #[test]
    fn marker_name_is_plausible_and_legacy_marker_migrates() {
        assert!(CANDIDATES
            .iter()
            .all(|c| !c.marker.contains("storyfirewall") && !c.marker.contains("decoy")));
        let users = tmp("e");
        let prof = users.join("u");
        let dir = join_rel(&prof, "appdata\\roaming\\electrum\\wallets\\");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(LEGACY_MARKER), b"1\n").unwrap();
        fs::write(dir.join("default_wallet"), FAKE).unwrap();
        let r = ensure(&prof);
        assert!(
            r.iter().any(|(p, e)| p == &dir && *e == Ensured::Ours),
            "{r:?}"
        );
        assert!(!dir.join(LEGACY_MARKER).exists() && dir.join(".lock").is_file());
        // 같은 이름이라도 내용이 우리 것이 아니면(실제 프로그램 파일) 우리 미끼로 보지 않는다
        let real = join_rel(&prof, "appdata\\roaming\\exodus\\exodus.wallet\\");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("storage.seco"), b"real exodus data").unwrap();
        let r = ensure(&prof);
        assert!(
            r.iter().any(|(p, e)| p == &real && *e == Ensured::Real),
            "{r:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn discover_skips_links() {
        let users = tmp("d");
        let prof = users.join("u");
        let elsewhere = tmp("d-elsewhere");
        ensure(&elsewhere);
        fs::create_dir_all(prof.join("appdata")).unwrap();
        // appdata\local 을 다른 곳으로 가리키는 링크 → 버린다
        std::os::unix::fs::symlink(
            elsewhere.join("appdata").join("local"),
            prof.join("appdata").join("local"),
        )
        .unwrap();
        assert!(discover(&users)
            .iter()
            .all(|p| !p.to_string_lossy().contains("centbrowser")));
    }

    #[test]
    fn retires_registration_when_real_install_seen() {
        let cent = r"C:\Users\u\AppData\Local\CentBrowser\User Data".to_string();
        let exo = r"C:\Users\u\AppData\Roaming\Exodus\exodus.wallet\".to_string();
        let ele = r"C:\Users\u\AppData\Roaming\Electrum\wallets".to_string();
        let dirs = vec![cent.clone(), exo.clone(), ele.clone()];
        // 설치 없음 → 그대로
        let (k, r) = retire_for_installs(dirs.clone(), &[]);
        assert_eq!((k.len(), r.len()), (3, 0));
        // Exodus 설치(Squirrel: 이름 + %LOCALAPPDATA%\exodus 에 씀), 관련 없는 설치
        let ins = vec![
            (
                r"C:\Users\u\Downloads\exodus-windows-x64-24.41.3.exe".to_string(),
                vec![r"C:\Users\u\AppData\Local\exodus\app-24.41.3\Exodus.exe".to_string()],
            ),
            (
                r"C:\Users\u\Downloads\HncSetup.exe".to_string(),
                vec![r"C:\Program Files (x86)\Hnc\Office\x.dll".to_string()],
            ),
        ];
        let (k, r) = retire_for_installs(dirs.clone(), &ins);
        assert_eq!(r, vec![exo.clone()]);
        assert_eq!(k, vec![cent.clone(), ele.clone()]);
        // 이름은 다르지만 설치가 Cent Browser 폴더에 씀
        let ins = vec![(
            r"C:\Users\u\Downloads\setup_x64.exe".to_string(),
            vec![r"C:\Users\u\AppData\Local\CentBrowser\Application\chrome.exe".to_string()],
        )];
        let (_, r) = retire_for_installs(dirs.clone(), &ins);
        assert_eq!(r, vec![cent.clone()]);
        // 미끼 폴더 안 파일만(우리 파일)은 실제 설치 근거가 아니다
        let ins = vec![(
            r"C:\Users\u\Downloads\x.exe".to_string(),
            vec![format!(r"{ele}\default_wallet")],
        )];
        let (k, _) = retire_for_installs(dirs.clone(), &ins);
        assert_eq!(k.len(), 3);
        // 설치로 안 잡혀도 그 프로그램 폴더에서 실행되면(Cent Browser 의 chrome.exe)
        let ran = vec![(
            r"C:\Users\u\AppData\Local\CentBrowser\Application\chrome.exe".to_string(),
            vec![],
        )];
        let (_, r) = retire_for_installs(dirs, &ran);
        assert_eq!(r, vec![cent]);
    }

    #[test]
    fn vanished_reports_only_disappeared_not_retired() {
        let a = r"C:\Users\u\AppData\Local\CentBrowser\User Data".to_string();
        let b = r"C:\Users\u\AppData\Roaming\Exodus\exodus.wallet".to_string();
        let c = r"C:\Users\u\AppData\Roaming\Electrum\wallets".to_string();
        let prev = vec![a.clone(), b.clone(), c.clone()];
        // 그대로(끝 구분자·대소문자 달라도 같은 폴더)
        assert!(vanished(
            &prev,
            &[format!("{}\\", a.to_uppercase()), b.clone(), c.clone()],
            &[]
        )
        .is_empty());
        // b 는 실제 설치로 물러남(사라짐 아님), c 는 사라짐
        assert_eq!(vanished(&prev, &[a.clone()], &[b.clone()]), vec![c.clone()]);
        // 처음(지난번 없음)은 아무것도 사라지지 않았다
        assert!(vanished(&[], &[a], &[]).is_empty());
    }
}
