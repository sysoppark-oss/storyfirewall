//! 브라우저 금고 경비 (기획서 17판 23-2 ②) — 경로·이름 규칙
//!
//! 수집기(감시 경로 거르기)와 판정(누가 열었나)이 같은 규칙을 쓰도록 여기 둔다. 문자열 규칙뿐이며 OS 호출은 없다
//! (경로 모양이 Windows 경로일 뿐 Windows 전용 코드가 아니다 — Linux 단위 테스트로 확인한다).
//!
//! 1. 금고 파일: 브라우저가 저장된 로그인 정보·쿠키·암호화 키 설정을 두는 파일.
//!    Chromium 계열(Chrome·Edge·Whale·Brave): `<사용자>\AppData\Local\<제조사>\User Data\` 아래
//!    `Local State`, `<프로필>\Login Data`, `<프로필>\Login Data For Account`, `<프로필>\Web Data`,
//!    `<프로필>\Cookies`, `<프로필>\Network\Cookies`.
//!    Firefox: `<사용자>\AppData\Roaming\Mozilla\Firefox\Profiles\<프로필>\` 의 `logins.json`, `key4.db`, `cookies.sqlite`.
//!    SQLite 보조 파일(-journal, -wal)은 이름이 달라 금고 파일로 치지 않는다(본 파일 열기가 같이 일어난다).
//! 2. 브라우저 자신: **이미지 파일 이름**과 **설치 위치**가 둘 다 맞아야 한다(이름만 같은 복사본 — 예: Temp 의 chrome.exe — 은 브라우저가 아님).
//!    설치 위치 = 시스템 드라이브의 Program Files·Program Files (x86) 아래 제조사 폴더, 또는 사용자별 설치
//!    (`<시스템 드라이브>:\Users\<한 구간>\AppData\Local\<제조사 폴더>\`). 사용자별 설치 폴더는 그 사용자가 쓸 수 있으므로
//!    같은 사용자 권한의 프로그램이 그 자리에 복사본을 둘 수 있다(한계 — 그 경우 브라우저 실행 파일 자체도 바꿀 수 있는 권한이다).
//!    판정(judge)은 여기에 서명 조건(서명 없음·깨짐·신뢰 체인 없음이면 브라우저 아님)을 더한다.
//!    경로 위장(`..`·`.` 구간, `\\?\`·`\\.\`·장치 경로, 대체 데이터 스트림 `:`)은 브라우저로 인정하지 않는다(안전한 쪽으로 실패).
//! 3. 미끼 파일: Story Firewall 이 사용자 프로필 아래 두는 가짜 브라우저 프로필·가짜 지갑 폴더(DECOY_CANDIDATES).
//!    만들기는 UI(사용자 권한)가 decoy::ensure 로, 등록은 서비스가 decoy::discover(읽기만) → judge::rules::set_decoy_dirs 로 한다(L061).
//!    등록 전에는 미끼 규칙이 판정에 쓰이지 않는다.
//! 4. 디버깅 모드 실행: 명령줄의 `--remote-debugging-port`·`--remote-debugging-pipe`. 브라우저 명령줄에는 방문 주소 같은
//!    개인 정보가 들 수 있어 수집기는 이 스위치들만 남긴 명령줄(`debug_flags_only`)을 보낸다.

use serde::Serialize;

/// 브라우저 종류
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Browser {
    Chrome,
    Edge,
    Whale,
    Brave,
    Firefox,
}

impl Browser {
    /// 화면 이름
    pub fn name(self) -> &'static str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Edge => "Edge",
            Browser::Whale => "Whale",
            Browser::Brave => "Brave",
            Browser::Firefox => "Firefox",
        }
    }
    /// 판정이 "ABE(App-Bound Encryption) 권한 상승 서비스"를 쓰는 Chromium 계열인가
    pub fn chromium(self) -> bool {
        !matches!(self, Browser::Firefox)
    }
}

/// 금고 파일 종류
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VaultWhat {
    /// Chromium `Login Data`(·For Account), Firefox `logins.json`
    Logins,
    /// Chromium `Cookies`·`Network\Cookies`, Firefox `cookies.sqlite`
    Cookies,
    /// Chromium `Local State` (저장 정보의 암호화 키가 들어 있는 설정 파일)
    LocalState,
    /// Chromium `Web Data` (자동 완성·카드 정보)
    WebData,
    /// Firefox `key4.db` (저장된 로그인 정보의 키 데이터베이스)
    KeyDb,
}

impl VaultWhat {
    /// 사실 문장용 이름(조사 없이)
    pub fn label(self) -> &'static str {
        match self {
            VaultWhat::Logins => "저장된 로그인 정보",
            VaultWhat::Cookies => "쿠키",
            VaultWhat::LocalState => "암호화 키가 들어 있는 설정",
            VaultWhat::WebData => "자동 완성·카드 정보",
            VaultWhat::KeyDb => "로그인 정보 키 데이터베이스",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VaultFile {
    pub browser: Browser,
    pub what: VaultWhat,
}

/// Chromium 계열 `User Data` 폴더: AppData\Local 아래 제조사 경로(소문자) → 브라우저
/// 추측: Whale 의 사용자 데이터 위치(`Naver\Naver Whale\User Data`)는 공개 자료 기준이며 실기기 확인 전이다
const CHROMIUM_USER_DATA: &[(&str, Browser)] = &[
    ("google\\chrome", Browser::Chrome),
    ("google\\chrome beta", Browser::Chrome),
    ("google\\chrome dev", Browser::Chrome),
    ("google\\chrome sxs", Browser::Chrome),
    ("microsoft\\edge", Browser::Edge),
    ("microsoft\\edge beta", Browser::Edge),
    ("microsoft\\edge dev", Browser::Edge),
    ("microsoft\\edge sxs", Browser::Edge),
    ("naver\\naver whale", Browser::Whale),
    ("bravesoftware\\brave-browser", Browser::Brave),
    ("bravesoftware\\brave-browser-beta", Browser::Brave),
    ("bravesoftware\\brave-browser-nightly", Browser::Brave),
];

/// 수집기의 값싼 1차 거르기(소문자 경로, NT·Win32 어느 모양이든). 참이면 `classify`·`decoy_candidate` 로 정밀 검사한다.
/// Kernel-File Create 는 초당 수천 건이 될 수 있어 부분 문자열 몇 개만 본다
pub fn watch_prefilter(lower: &str) -> bool {
    lower.contains("\\user data\\")
        || lower.contains("\\mozilla\\firefox\\profiles\\")
        || DECOY_CANDIDATES.iter().any(|d| lower.contains(d.fragment))
}

/// 경로를 비교용으로: 소문자·역슬래시. 위장 모양(`\\` 시작, 드라이브 뒤 `:`, `..`·`.` 구간)이면 None
fn norm(path: &str) -> Option<String> {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    if p.starts_with("\\\\") || p.get(2..).is_some_and(|r| r.contains(':')) {
        return None;
    }
    if p.split('\\').any(|seg| seg == ".." || seg == ".") {
        return None;
    }
    let b = p.as_bytes();
    if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
        return None;
    }
    Some(p)
}

/// L062(30차 Q3-a): 금고·미끼 **대상 파일** 경로 정규화. 브라우저 판별(`norm`)과 달리 위장 접두를 거부하면 감지를 놓치는
/// 쪽(안전하지 않은 쪽)으로 실패하므로, 알려진 접두를 벗겨 같은 파일로 본다:
/// `\\?\X:\`·`\\.\X:\`(Win32 긴 경로) → `X:\`, `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\`·`\Device\HarddiskVolumeShadowCopyN\`(섀도 복사본) → `c:\`
/// (드라이브는 금고 판정에 쓰지 않는다). 그 밖의 `\\` 시작·`..`·대체 스트림은 그대로 거부
fn norm_target(path: &str) -> Option<String> {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    let strip_shadow = |s: &str| -> Option<String> {
        let rest = s.strip_prefix("harddiskvolumeshadowcopy")?;
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits == 0 {
            return None;
        }
        let tail = rest[digits..].strip_prefix('\\')?;
        Some(format!("c:\\{tail}"))
    };
    let q = if let Some(r) = p.strip_prefix("\\\\?\\globalroot\\device\\") {
        strip_shadow(r)?
    } else if let Some(r) = p.strip_prefix("\\device\\") {
        strip_shadow(r)?
    } else if let Some(r) = p
        .strip_prefix("\\\\?\\")
        .or_else(|| p.strip_prefix("\\\\.\\"))
    {
        r.to_string()
    } else {
        p
    };
    norm(&q)
}

/// 섀도 복사본 경로인가(이야기 문장에 사실로 밝힐 때)
pub fn is_shadow_copy_path(path: &str) -> bool {
    path.to_ascii_lowercase()
        .contains("harddiskvolumeshadowcopy")
}

/// `x:\users\<한 구간>\` 다음 부분. 드라이브는 가리지 않는다(금고·미끼 파일은 프로필 위치 자체가 기준)
fn after_user_profile(p: &str) -> Option<&str> {
    let rest = p.get(2..)?.strip_prefix("\\users\\")?;
    let (user, tail) = rest.split_once('\\')?;
    if user.is_empty() {
        return None;
    }
    Some(tail)
}

/// 금고 파일인가 — 브라우저·종류. 사용자 프로필 아래의 정해진 위치만
pub fn classify(path: &str) -> Option<VaultFile> {
    let p = norm_target(path)?;
    let tail = after_user_profile(&p)?;
    if let Some(local) = tail.strip_prefix("appdata\\local\\") {
        for (vendor, browser) in CHROMIUM_USER_DATA {
            let Some(rest) = local
                .strip_prefix(vendor)
                .and_then(|r| r.strip_prefix("\\user data\\"))
            else {
                continue;
            };
            let segs: Vec<&str> = rest.split('\\').collect();
            let what = match segs.as_slice() {
                ["local state"] => VaultWhat::LocalState,
                [_, "login data"] | [_, "login data for account"] => VaultWhat::Logins,
                [_, "web data"] => VaultWhat::WebData,
                [_, "cookies"] | [_, "network", "cookies"] => VaultWhat::Cookies,
                _ => return None,
            };
            return Some(VaultFile {
                browser: *browser,
                what,
            });
        }
        return None;
    }
    if let Some(rest) = tail.strip_prefix("appdata\\roaming\\mozilla\\firefox\\profiles\\") {
        let segs: Vec<&str> = rest.split('\\').collect();
        let what = match segs.as_slice() {
            [_, "logins.json"] => VaultWhat::Logins,
            [_, "key4.db"] => VaultWhat::KeyDb,
            [_, "cookies.sqlite"] => VaultWhat::Cookies,
            _ => return None,
        };
        return Some(VaultFile {
            browser: Browser::Firefox,
            what,
        });
    }
    None
}

/// 미끼 후보 폴더 하나 — 목록은 decoy 크레이트에 있다(UI 가 사용자 권한으로 만들고, 서비스는 읽기만, L061)
pub use decoy::Candidate as Decoy;

/// 미끼 후보: 정보 탈취 도구가 흔히 뒤지는 위치 중 국내에서 드물게 쓰는 프로그램의 폴더 (decoy::CANDIDATES)
pub const DECOY_CANDIDATES: &[Decoy] = decoy::CANDIDATES;

/// 미끼 후보 폴더 아래의 파일인가(등록 여부와 무관 — 수집기가 보낼지 정할 때 쓴다). 맞으면 그 후보
pub fn decoy_candidate(path: &str) -> Option<&'static Decoy> {
    let p = norm_target(path)?;
    let tail = after_user_profile(&p)?;
    DECOY_CANDIDATES
        .iter()
        .find(|d| tail.starts_with(d.under_profile) && tail.len() > d.under_profile.len())
}

/// 브라우저 설치 위치 하나: (설치 범위, 폴더) — 폴더는 Program Files 또는 AppData\Local 다음 부분(소문자, 끝 `\`)
enum Root {
    /// `<sys>:\program files\` 와 `<sys>:\program files (x86)\` 아래
    ProgramFiles(&'static str),
    /// `<sys>:\users\<u>\appdata\local\` 아래(사용자별 설치)
    UserLocal(&'static str),
}

struct BrowserFiles {
    browser: Browser,
    names: &'static [&'static str],
    roots: &'static [Root],
}

/// 브라우저와 그 도우미 실행 파일(이름은 소문자). 이름·위치 둘 다 맞아야 한다.
/// 추측: Whale·Brave 의 업데이트 폴더 이름과 도우미 목록은 공개 자료 기준이며 실기기 확인 전이다
static BROWSERS: &[BrowserFiles] = &[
    BrowserFiles {
        browser: Browser::Chrome,
        names: &[
            "chrome.exe",
            "chrome_proxy.exe",
            "chrome_pwa_launcher.exe",
            "elevation_service.exe",
            "notification_helper.exe",
            "setup.exe",
            "googleupdate.exe",
            "googlecrashhandler.exe",
            "googlecrashhandler64.exe",
            "googleupdatecore.exe",
            "updater.exe",
            "software_reporter_tool.exe",
        ],
        roots: &[
            Root::ProgramFiles("google\\chrome\\application\\"),
            Root::ProgramFiles("google\\chrome beta\\application\\"),
            Root::ProgramFiles("google\\chrome dev\\application\\"),
            Root::ProgramFiles("google\\update\\"),
            Root::ProgramFiles("google\\googleupdater\\"),
            Root::UserLocal("google\\chrome\\application\\"),
            Root::UserLocal("google\\chrome beta\\application\\"),
            Root::UserLocal("google\\chrome dev\\application\\"),
            Root::UserLocal("google\\chrome sxs\\application\\"),
            Root::UserLocal("google\\update\\"),
            Root::UserLocal("google\\googleupdater\\"),
            // Chrome 정리 도구(구성 요소 업데이트로 받음)
            Root::UserLocal("google\\chrome\\user data\\swreporter\\"),
        ],
    },
    BrowserFiles {
        browser: Browser::Edge,
        names: &[
            "msedge.exe",
            "msedge_proxy.exe",
            "msedge_pwa_launcher.exe",
            "elevation_service.exe",
            "identity_helper.exe",
            "cookie_exporter.exe",
            "notification_helper.exe",
            "pwahelper.exe",
            "setup.exe",
            "ie_to_edge_stub.exe",
            "microsoftedgeupdate.exe",
            "microsoftedgeupdatecore.exe",
            "msedgewebview2.exe",
        ],
        roots: &[
            Root::ProgramFiles("microsoft\\edge\\application\\"),
            Root::ProgramFiles("microsoft\\edge beta\\application\\"),
            Root::ProgramFiles("microsoft\\edge dev\\application\\"),
            Root::ProgramFiles("microsoft\\edgeupdate\\"),
            Root::ProgramFiles("microsoft\\edgewebview\\application\\"),
            Root::UserLocal("microsoft\\edge sxs\\application\\"),
            Root::UserLocal("microsoft\\edge beta\\application\\"),
            Root::UserLocal("microsoft\\edge dev\\application\\"),
        ],
    },
    BrowserFiles {
        browser: Browser::Whale,
        names: &[
            "whale.exe",
            "whale_proxy.exe",
            "elevation_service.exe",
            "notification_helper.exe",
            "setup.exe",
            "naverupdate.exe",
        ],
        roots: &[
            Root::ProgramFiles("naver\\naver whale\\application\\"),
            Root::ProgramFiles("naver\\naver update\\"),
            Root::UserLocal("naver\\naver whale\\application\\"),
        ],
    },
    BrowserFiles {
        browser: Browser::Brave,
        names: &[
            "brave.exe",
            "brave_proxy.exe",
            "elevation_service.exe",
            "notification_helper.exe",
            "setup.exe",
            "braveupdate.exe",
            "updater.exe",
        ],
        roots: &[
            Root::ProgramFiles("bravesoftware\\brave-browser\\application\\"),
            Root::ProgramFiles("bravesoftware\\brave-browser-beta\\application\\"),
            Root::ProgramFiles("bravesoftware\\update\\"),
            Root::UserLocal("bravesoftware\\brave-browser\\application\\"),
            Root::UserLocal("bravesoftware\\update\\"),
        ],
    },
    BrowserFiles {
        browser: Browser::Firefox,
        names: &[
            "firefox.exe",
            "default-browser-agent.exe",
            "pingsender.exe",
            "crashreporter.exe",
            "crashhelper.exe",
            "minidump-analyzer.exe",
            "plugin-container.exe",
            "private_browsing.exe",
            "updater.exe",
            "maintenanceservice.exe",
        ],
        roots: &[
            Root::ProgramFiles("mozilla firefox\\"),
            Root::ProgramFiles("mozilla maintenance service\\"),
            Root::UserLocal("mozilla firefox\\"),
        ],
    },
];

/// 이 실행 파일이 브라우저(또는 그 도우미)인가 — 이름과 설치 위치가 둘 다 맞을 때만.
/// `sys_drive`: 시스템 드라이브 글자(소문자, 예: b'c'). 다른 드라이브의 같은 모양(이동식 매체·ISO 의 `D:\Program Files\…`)은 인정하지 않는다
pub fn browser_of_image(image: &str, sys_drive: u8) -> Option<Browser> {
    let p = norm(image)?;
    if p.as_bytes()[0] != sys_drive.to_ascii_lowercase() {
        return None;
    }
    let (dir, name) = p.rsplit_once('\\')?;
    let dir = format!("{dir}\\");
    let rest = &dir[2..];
    let pf = rest
        .strip_prefix("\\program files\\")
        .or_else(|| rest.strip_prefix("\\program files (x86)\\"));
    let local = rest.strip_prefix("\\users\\").and_then(|r| {
        let (user, tail) = r.split_once('\\')?;
        if user.is_empty() {
            return None;
        }
        tail.strip_prefix("appdata\\local\\")
    });
    BROWSERS
        .iter()
        .find(|b| {
            b.names.contains(&name)
                && b.roots.iter().any(|r| match r {
                    Root::ProgramFiles(f) => pf.is_some_and(|x| x.starts_with(f)),
                    Root::UserLocal(f) => local.is_some_and(|x| x.starts_with(f)),
                })
        })
        .map(|b| b.browser)
}

/// 브라우저 본체 이름(경로 무관, 소문자 비교). 수집기가 명령줄을 읽을지 정하는 값싼 기준 — 판정은 `browser_of_image` 로 다시 본다
pub const BROWSER_MAIN_NAMES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "whale.exe",
    "brave.exe",
    "firefox.exe",
];

pub fn is_browser_main_name(image: &str) -> bool {
    let name = image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase();
    BROWSER_MAIN_NAMES.contains(&name.as_str())
}

/// Chromium 권한 상승 서비스(ABE 키를 푸는 COM 서비스) 실행 파일 이름
pub const ELEVATION_SERVICE: &str = "elevation_service.exe";

/// 명령줄에서 디버깅 관련 스위치만 남긴다. 디버깅 스위치(`remote-debugging-port`·`remote-debugging-pipe`)가 없으면 None.
/// 남기는 것: 실행 파일 이름(경로 없이) + `remote-debugging-*`·`remote-allow-origins`·`headless` 스위치. 나머지(주소·프로필 경로 등)는 버린다.
/// Chromium 은 Windows 에서 `--`·`-`·`/` 접두와 대소문자를 가리지 않는다 — 모두 같은 스위치로 본다
pub fn debug_flags_only(cmdline: &str) -> Option<String> {
    let toks = split_cmdline(cmdline);
    let exe = toks
        .first()
        .map(|t| {
            t.rsplit(['\\', '/'])
                .next()
                .unwrap_or(t)
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let mut kept: Vec<String> = Vec::new();
    let mut debug = false;
    for t in toks.iter().skip(1) {
        let Some(sw) = switch_of(t) else { continue };
        let key = sw.split('=').next().unwrap_or("");
        if key == "remote-debugging-port" || key == "remote-debugging-pipe" {
            debug = true;
        }
        if key.starts_with("remote-debugging-")
            || key == "remote-allow-origins"
            || key == "headless"
        {
            kept.push(format!("--{sw}"));
        }
    }
    if !debug {
        return None;
    }
    let mut out = exe;
    for k in kept {
        out.push(' ');
        out.push_str(&k);
    }
    Some(out)
}

/// 디버깅 포트(`remote-debugging-port=N`). 0(무작위)이나 숫자가 아니면 None
pub fn debug_port(cmdline: &str) -> Option<u16> {
    split_cmdline(cmdline).iter().skip(1).find_map(|t| {
        let sw = switch_of(t)?;
        let v = sw.strip_prefix("remote-debugging-port=")?;
        v.trim().parse::<u16>().ok().filter(|p| *p != 0)
    })
}

/// 기본 디버깅 포트(문서·도구들의 관례값). 포트를 모르는 디버깅 실행(=0, pipe)은 이 포트만 본다
pub const DEFAULT_DEBUG_PORT: u16 = 9222;

/// `--x`·`-x`·`/x` → 소문자 `x`(값 포함). 스위치가 아니면 None
fn switch_of(t: &str) -> Option<String> {
    let s = t
        .strip_prefix("--")
        .or_else(|| t.strip_prefix('-'))
        .or_else(|| t.strip_prefix('/'))?;
    if s.is_empty() {
        return None;
    }
    // 값 부분의 따옴표는 지운다(--remote-allow-origins="*")
    Some(s.replace('"', "").to_ascii_lowercase())
}

/// 공백 기준으로 자르되 큰따옴표 안의 공백은 잇는다(Windows 명령줄 규칙의 근사 — 역슬래시 이스케이프는 다루지 않는다)
pub(crate) fn split_cmdline(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                cur.push(ch);
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    // 첫 토큰(실행 파일)의 따옴표는 지운다
    if let Some(f) = out.first_mut() {
        *f = f.replace('"', "");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: &str = r"C:\Users\pjg\AppData";

    #[test]
    fn vault_files_are_classified() {
        let c = |p: &str| classify(p).map(|v| (v.browser, v.what));
        assert_eq!(
            c(&format!(
                r"{U}\Local\Google\Chrome\User Data\Default\Login Data"
            )),
            Some((Browser::Chrome, VaultWhat::Logins))
        );
        assert_eq!(
            c(&format!(
                r"{U}\Local\Google\Chrome\User Data\Profile 2\Login Data For Account"
            )),
            Some((Browser::Chrome, VaultWhat::Logins))
        );
        assert_eq!(
            c(&format!(
                r"{U}\Local\Microsoft\Edge\User Data\Default\Network\Cookies"
            )),
            Some((Browser::Edge, VaultWhat::Cookies))
        );
        assert_eq!(
            c(&format!(r"{U}\Local\Microsoft\Edge\User Data\Local State")),
            Some((Browser::Edge, VaultWhat::LocalState))
        );
        assert_eq!(
            c(&format!(
                r"{U}\Local\Naver\Naver Whale\User Data\Default\Web Data"
            )),
            Some((Browser::Whale, VaultWhat::WebData))
        );
        assert_eq!(
            c(&format!(
                r"{U}\Local\BraveSoftware\Brave-Browser\User Data\Default\Cookies"
            )),
            Some((Browser::Brave, VaultWhat::Cookies))
        );
        assert_eq!(
            c(&format!(
                r"{U}\Roaming\Mozilla\Firefox\Profiles\ab12.default-release\key4.db"
            )),
            Some((Browser::Firefox, VaultWhat::KeyDb))
        );
        assert_eq!(
            c(&format!(
                r"{U}\Roaming\Mozilla\Firefox\Profiles\ab12.default-release\logins.json"
            )),
            Some((Browser::Firefox, VaultWhat::Logins))
        );
        // 아닌 것: 보조 파일, 다른 파일, 깊이 다름, 위장 경로
        for p in [
            format!(r"{U}\Local\Google\Chrome\User Data\Default\Login Data-journal"),
            format!(r"{U}\Local\Google\Chrome\User Data\Default\History"),
            format!(r"{U}\Local\Google\Chrome\User Data\Login Data"),
            format!(r"{U}\Local\Google\Chrome\User Data\Default\Cache\Cookies"),
            format!(r"{U}\Local\Google\Chrome\User Data\..\User Data\Default\Login Data"),
            r"C:\Temp\Google\Chrome\User Data\Default\Login Data".to_string(),
            format!(r"{U}\Roaming\Mozilla\Firefox\Profiles\x\places.sqlite"),
        ] {
            assert_eq!(classify(&p), None, "{p}");
        }
        // 1차 거르기는 정밀 검사가 맞는 경로를 놓치지 않는다
        assert!(watch_prefilter(
            &r"\device\harddiskvolume3\users\pjg\appdata\local\google\chrome\user data\default\login data"
        ));
        assert!(!watch_prefilter(r"c:\windows\system32\kernel32.dll"));
    }

    #[test]
    fn browser_needs_name_and_install_dir() {
        let b = |p: &str| browser_of_image(p, b'c');
        assert_eq!(
            b(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Some(Browser::Chrome)
        );
        assert_eq!(
            b(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            Some(Browser::Edge)
        );
        assert_eq!(
            b(r"C:\Program Files\Google\Chrome\Application\131.0.6778.86\elevation_service.exe"),
            Some(Browser::Chrome)
        );
        assert_eq!(
            b(r"C:\Users\pjg\AppData\Local\Google\Chrome\Application\chrome.exe"),
            Some(Browser::Chrome)
        );
        assert_eq!(
            b(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
            Some(Browser::Firefox)
        );
        // 이름만 같은 복사본, 다른 드라이브, 위장 경로, 이름이 다른 파일
        for p in [
            r"C:\Users\pjg\AppData\Local\Temp\chrome.exe",
            r"C:\Users\pjg\Downloads\Google\Chrome\Application\chrome.exe",
            r"D:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\..\..\..\..\Temp\chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\stealer.exe",
            r"C:\Program Files\Google Evil\Chrome\Application\chrome.exe",
            r"\\?\C:\Program Files\Google\Chrome\Application\chrome.exe",
        ] {
            assert_eq!(b(p), None, "{p}");
        }
    }

    #[test]
    fn decoy_candidates() {
        assert!(decoy_candidate(
            r"C:\Users\pjg\AppData\Local\CentBrowser\User Data\Default\Login Data"
        )
        .is_some());
        assert!(
            decoy_candidate(r"C:\Users\pjg\AppData\Roaming\Exodus\exodus.wallet\seed.seco")
                .is_some()
        );
        assert!(decoy_candidate(r"C:\Users\pjg\AppData\Roaming\Exodus\exodus.wallet\").is_none());
        assert!(decoy_candidate(r"C:\Temp\Exodus\exodus.wallet\seed.seco").is_none());
        assert!(watch_prefilter(
            r"c:\users\pjg\appdata\roaming\electrum\wallets\default_wallet"
        ));
    }

    #[test]
    fn debug_flags_are_kept_and_the_rest_dropped() {
        let line = r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="C:\Users\pjg\AppData\Local\Temp\x" https://bank.example/login --headless=new"#;
        assert_eq!(
            debug_flags_only(line).as_deref(),
            Some("chrome.exe --remote-debugging-port=9222 --headless=new")
        );
        assert_eq!(debug_port(line), Some(9222));
        assert_eq!(
            debug_flags_only("msedge.exe -Remote-Debugging-Pipe").as_deref(),
            Some("msedge.exe --remote-debugging-pipe")
        );
        assert_eq!(debug_port("msedge.exe --remote-debugging-pipe"), None);
        assert_eq!(debug_port("chrome.exe --remote-debugging-port=0"), None);
        assert_eq!(
            debug_flags_only("chrome.exe --type=renderer https://x.example/"),
            None
        );
        assert_eq!(debug_flags_only(""), None);
        // 주소는 남지 않는다
        assert!(!debug_flags_only(line).unwrap().contains("bank"));
    }

    #[test]
    fn shadow_copy_and_long_path_prefix_are_still_vault_files() {
        // L062(30차 Q3-a): 위장 접두를 벗겨 같은 금고 파일로 본다(감지를 놓치는 쪽으로 실패하지 않게)
        for p in [
            r"\\?\C:\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"\Device\HarddiskVolumeShadowCopy12\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        ] {
            assert!(classify(p).is_some(), "{p}");
            assert_eq!(is_shadow_copy_path(p), p.contains("ShadowCopy"));
        }
        // 숫자 없는 섀도 접두·다른 장치·대체 스트림은 여전히 거부
        for p in [
            r"\Device\HarddiskVolumeShadowCopy\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"\Device\HarddiskVolume3\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"C:\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\Login Data:x",
        ] {
            assert!(classify(p).is_none(), "{p}");
        }
    }
}
