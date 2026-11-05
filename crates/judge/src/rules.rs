//! 뿌리 찾기 · 사슬 모으기 · 장 매기기 (8차 의뢰서 2·3장)

use std::collections::{HashMap, HashSet, VecDeque};

use graph::{Edge, Node};

use crate::View;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Chapter {
    Ingress = 1,
    Execute = 2,
    Persist = 3,
    Egress = 4,
    /// 10판 5-9 제5장 파괴 징후(감지만, 원칙 22: 자동 대응 없음)
    Destroy = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum RootKind {
    /// (가) 외부 유입 파일
    IngressFile,
    /// (나) 서명 없거나 깨진 실행 파일의 프로세스
    UnsignedProcess,
    /// (다) 고립 svchost
    IsolatedSvchost,
    /// (라) 문서 처리기가 낳은 LOLBin
    LolbinFromDocApp,
    /// (마) 서명된 프로그램의 자리잡기 (보여 주되 점수 낮음)
    SignedPersist,
    /// (바) 복구 수단을 지우는 명령을 실행한 프로세스 (10판 5-9 (1), MITRE ATT&CK T1490). 다른 사건의 사슬에 들면 그쪽이 가진다
    RecoveryInhibit,
    /// (사) 브라우저 금고 경비 (17판 23-2 ②): 브라우저가 아닌 프로그램의 금고 파일 열기·미끼 파일 열기·디버깅 모드 브라우저 실행·
    /// 디버깅 포트 접속·권한 상승 서비스 실행. 뿌리는 그 행위를 한 프로세스. 다른 사건의 사슬에 들면 그쪽이 가진다
    VaultAccess,
}

pub static LOLBINS: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| lines(include_str!("../data/lolbins.txt")));
/// 1장 유입 경로가 되는 프로그램 (브라우저·메일·압축·메신저) 과 (라) 의 문서 처리기
pub static INGRESS_APPS: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| lines(include_str!("../data/ingress-apps.txt")));
pub static DOC_APPS: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| lines(include_str!("../data/doc-apps.txt")));
pub static KNOWN_MS_SERVICES: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| lines(include_str!("../data/known-ms-services.txt")));
pub const EXE_EXT: &[&str] = &["exe", "dll", "scr", "com", "msi", "cpl"];
pub const SCRIPT_EXT: &[&str] = &[
    "ps1", "bat", "cmd", "vbs", "js", "jse", "wsf", "hta", "lnk", "url", "iso", "img", "vhd",
];
pub const AUTOSTART_DIRS: &[&str] = &[
    "\\start menu\\programs\\startup\\",
    "\\windows\\system32\\tasks\\",
    "\\windows\\tasks\\",
];

/// 목록 파일(data/*.txt): 한 줄에 하나, `#` 주석. 제품 갱신 경로(2차: 서명된 룰 파일)를 위해 코드 상수가 아니라 파일로 둔다 (제안 5②)
fn lines(src: &'static str) -> Vec<&'static str> {
    src.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

pub fn file_name_lower(p: &str) -> String {
    p.rsplit(['\\', '/'])
        .next()
        .unwrap_or(p)
        .to_ascii_lowercase()
}
/// 복구 수단 삭제(T1490) 명령의 종류. 명령줄(따옴표·대소문자·공백 무시)로만 판별한다 — 의도는 말하지 않는다.
/// 이미지 이름은 명령줄 첫 토큰에서 본다(수집기가 같은 도구에서만 명령줄을 읽는다).
/// 판별하지 못하는 것(추측 아님, 구조상 한계): diskshadow 스크립트 모드(/s 파일 안의 명령), PowerShell·WMI COM 으로 지우기
pub fn t1490_kind(cmdline: &str) -> Option<&'static str> {
    t1490_kind_as(cmdline, None)
}

/// `tool`: 실행 파일의 원래 이름(버전 리소스 OriginalFileName — 이름 바꾼 복사본, 29차 Q1). 있으면 첫 토큰 대신 이것으로 도구를 정한다
pub fn t1490_kind_as(cmdline: &str, tool: Option<&str>) -> Option<&'static str> {
    // 29차 Q4: 따옴표 제거, 캐럿(^) 제거, 구분자는 공백뿐 아니라 쉼표·세미콜론·등호도(wmic,shadowcopy,delete · /for=c:).
    // %변수% 와 ^ 는 cmd 가 프로세스를 만들기 전에 풀어 우리가 받는 명령줄에는 보통 없다 — 남아 있어도 같은 결과가 되게 지운다
    let c: String = cmdline
        .to_ascii_lowercase()
        .replace('^', "")
        .replace(['"', '\''], " ");
    let toks: Vec<&str> = c
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';' | '='))
        .filter(|t| !t.is_empty())
        .collect();
    let first = match tool {
        Some(t) => t.to_ascii_lowercase(),
        None => toks.first().map(|t| file_name_lower(t)).unwrap_or_default(),
    };
    let tool = first.strip_suffix(".exe").unwrap_or(&first).to_string();
    let has = |w: &str| toks.iter().any(|t| t.trim_start_matches(['/', '-']) == w);
    // 이웃한 두 토큰(키 값) — "recoveryenabled no", "recoveryenabled=no", "bootstatuspolicy ignoreallfailures"
    let has_kv = |k: &str, v: &str| {
        toks.windows(2)
            .any(|w| w[0].trim_start_matches(['/', '-']) == k && w[1] == v)
            || toks.iter().any(|t| *t == format!("{k}:{v}"))
    };
    match tool.as_str() {
        "vssadmin" if has("delete") && has("shadows") => Some("그림자 복사본 삭제"),
        // 저장 공간을 아주 작게 줄이면 기존 복사본이 지워진다(maxsize 값은 보지 않는다 — 줄이기 자체를 사실로)
        "vssadmin" if has("resize") && has("shadowstorage") => Some("그림자 복사본 저장 공간 변경"),
        "wmic" if has("shadowcopy") && has("delete") => Some("그림자 복사본 삭제"),
        "diskshadow" if has("delete") && has("shadows") => Some("그림자 복사본 삭제"),
        "wbadmin"
            if has("delete") && (has("catalog") || has("systemstatebackup") || has("backup")) =>
        {
            Some("백업 기록 삭제")
        }
        "bcdedit" if has_kv("recoveryenabled", "no") => Some("자동 복구 끄기"),
        "bcdedit" if has_kv("bootstatuspolicy", "ignoreallfailures") => Some("부팅 실패 무시 설정"),
        "reagentc" if has("disable") => Some("복구 환경 끄기"),
        _ => None,
    }
}
/// 명령 노드가 T1490 명령인가(원래 도구 이름 없이 — 첫 토큰으로)
pub fn command_t1490(n: &Node) -> Option<&'static str> {
    if n.kind != "command" {
        return None;
    }
    t1490_kind(&n.key)
}
/// `ran` 선이 T1490 명령인가. 선 속성 tool(원래 도구 이름)이 있으면 그것으로
pub fn ran_kind(e: &Edge, cmd: &Node) -> Option<&'static str> {
    if e.rel != "ran" || cmd.kind != "command" {
        return None;
    }
    let tool = e
        .attrs_json
        .as_deref()
        .and_then(|a| serde_json::from_str::<serde_json::Value>(a).ok())
        .and_then(|v| {
            v.get("tool")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        });
    t1490_kind_as(&cmd.key, tool.as_deref())
}

pub fn ext_lower(p: &str) -> String {
    file_name_lower(p)
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_string()
}
pub fn is_pe(p: &str) -> bool {
    EXE_EXT.contains(&ext_lower(p).as_str())
}
pub fn is_script_or_container(p: &str) -> bool {
    SCRIPT_EXT.contains(&ext_lower(p).as_str())
}
pub fn attr_str(n: &Node, k: &str) -> Option<String> {
    n.attr(k).and_then(|v| v.as_str().map(|s| s.to_string()))
}
pub fn attr_u64(n: &Node, k: &str) -> Option<u64> {
    n.attr(k).and_then(|v| v.as_u64())
}
pub fn proc_image_name(n: &Node) -> String {
    attr_str(n, "image")
        .map(|s| file_name_lower(&s))
        .unwrap_or_else(|| n.label.to_ascii_lowercase())
}

/// 서명 상태. None = 아직 모름(확인 중)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    Microsoft,
    Valid,
    None_,
    /// D035-4: Windows 스토어 앱 패키지 폴더(\Program Files\WindowsApps\, TrustedInstaller 만 쓰기)의 파일.
    /// 파일마다가 아니라 패키지(AppxSignature)로 서명되므로 WinVerifyTrust 는 "서명 없음"을 돌려준다 — 확인 못 한 것이지 없는 것이 아니다
    Package,
    /// 서명과 내용이 맞지 않음(서명 뒤 파일이 바뀜) 또는 명시적으로 불신된 인증서
    Broken,
    /// 서명은 내용과 맞지만 이 PC 가 신뢰하는 인증 기관으로 이어지지 않음(자체 서명·사설 인증서), 또는 확인 오류
    Untrusted,
}
pub fn sig_of(file: &Node) -> Option<Sig> {
    let status = attr_str(file, "sig_status")?;
    Some(match status.as_str() {
        "valid" => {
            let signer = attr_str(file, "signer").unwrap_or_default();
            if signer.starts_with("Microsoft") {
                Sig::Microsoft
            } else {
                Sig::Valid
            }
        }
        "nosignature" if is_package_path(&file.key) => Sig::Package,
        "nosignature" => Sig::None_,
        "untrusted:bad_digest" | "untrusted:distrusted" => Sig::Broken,
        // "untrusted:root", 예전 값 "untrusted"(루트·불신 구분 전), "error:..."
        _ => Sig::Untrusted,
    })
}
/// 스토어 앱 패키지 설치 폴더 아래인가(대소문자·구분자 무시)
/// 28차 Q1: 경로 중간의 같은 이름 폴더(C:\Users\u\x\Program Files\WindowsApps\…)는 인정하지 않는다 — 드라이브 바로 아래만.
/// \\?\ 접두는 떼고 본다
/// 28차 Gemini Q1: 일반 사용자도 이동식 매체·ISO 를 붙여 D:\Program Files\WindowsApps\ 를 만들 수 있다 — 시스템 드라이브(set_system_drive)만
pub fn is_package_path(path: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    let p = p.strip_prefix("\\\\?\\").unwrap_or(&p);
    let b = p.as_bytes();
    let sys = SYSTEM_DRIVE.get().copied().unwrap_or(b'c');
    b.len() > 3
        && b[0] == sys
        && b[1] == b':'
        && p[2..].starts_with("\\program files\\windowsapps\\")
}

/// 갈래 C: 판정 설정(시스템 드라이브·설치 폴더·미끼 폴더)이 바뀐 횟수. 증분 판정은 이 값이 달라지면 뿌리·사슬을 모두 다시 만든다
/// (설정은 그래프 변경 기록에 남지 않는데 뿌리 분류·사슬의 장이 기댄다)
static CONFIG_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 판정 설정 세대(증분 판정용)
pub fn config_gen() -> u64 {
    CONFIG_GEN.load(std::sync::atomic::Ordering::SeqCst)
}

fn bump_config() {
    CONFIG_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

static SYSTEM_DRIVE: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
/// 시스템 드라이브 글자(서비스 시작 때 %SystemDrive% 로 한 번). 정하지 않으면 C
pub fn set_system_drive(d: &str) {
    if let Some(c) = d.bytes().next().filter(|c| c.is_ascii_alphabetic()) {
        let _ = SYSTEM_DRIVE.set(c.to_ascii_lowercase());
        bump_config();
    }
}

static SELF_DIRS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// 제품 설치 폴더(관리자만 쓰기). 서비스 시작 때 한 번 정한다. 정하지 않으면 자기 구성요소 구분을 하지 않는다
pub fn set_self_dirs(dirs: Vec<String>) {
    let norm = dirs.into_iter().map(norm_dir).collect();
    let _ = SELF_DIRS.set(norm);
    bump_config();
}

/// 폴더 경로를 비교용 모양으로(소문자·역슬래시·끝 `\\`). `under_dirs` 의 `dirs` 는 이 모양이어야 한다
pub fn norm_dir(d: String) -> String {
    let mut d = d.replace('/', "\\").to_ascii_lowercase();
    if !d.ends_with('\\') {
        d.push('\\');
    }
    d
}

/// 우리 제품 구성요소 파일인가(설치 폴더 바로 아래·하위). 서명 판단은 부르는 쪽이 따로 한다
pub fn is_self_file(file: &Node) -> bool {
    let Some(dirs) = SELF_DIRS.get() else {
        return false;
    };
    under_dirs(&file.key, dirs)
}

/// 경로가 `dirs`(정규화된 설치 폴더) 아래인가. **안전한 쪽으로 실패**한다(24차 Q2):
/// 8.3 짧은 이름·`\\?\`·`\\.\`·장치 경로·다른 볼륨은 접두가 달라 "우리 것 아님"이 된다.
/// 문자열 접두는 같아도 실제로는 밖을 가리키는 `..`·`.` 구간과 대체 데이터 스트림(`:`)은 거부한다.
/// 파일이 이미 지워졌을 수 있어 OS 정규화(GetFinalPathNameByHandle·canonicalize)는 쓰지 않는다 —
/// 대신 정규화되지 않은 모양은 아예 받지 않는다
pub fn under_dirs(path: &str, dirs: &[String]) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    if p.starts_with("\\\\") || p.get(2..).is_some_and(|r| r.contains(':')) {
        return false;
    }
    if p.split('\\').any(|seg| seg == ".." || seg == ".") {
        return false;
    }
    dirs.iter().any(|d| p.starts_with(d.as_str()))
}

/// 시스템 드라이브 글자(소문자). 정하지 않았으면 c
pub fn system_drive() -> u8 {
    SYSTEM_DRIVE.get().copied().unwrap_or(b'c')
}

// ---- (사) 브라우저 금고 경비 (17판 23-2 ②) ----

/// 등록된 미끼 폴더(정규화 — norm_dir). svc 가 실제로 만든 미끼만 등록한다(graph::vault 3번 주석). 비어 있으면 미끼 규칙이 쓰이지 않는다
static DECOY_DIRS: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// 미끼 폴더 등록(바꿔 쓰기). graph::vault::DECOY_CANDIDATES 후보 폴더 밖이면 받지 않는다(실제 프로그램 폴더를 잘못 등록해 오탐하지 않게)
pub fn set_decoy_dirs(dirs: Vec<String>) {
    let v: Vec<String> = dirs
        .into_iter()
        .map(norm_dir)
        .filter(|d| graph::vault::decoy_candidate(&format!("{d}x")).is_some())
        .collect();
    if let Ok(mut g) = DECOY_DIRS.write() {
        if *g != v {
            *g = v;
            bump_config();
        }
    }
}

/// 등록된 미끼 폴더 아래의 파일인가
pub fn is_decoy(path: &str) -> bool {
    DECOY_DIRS
        .read()
        .map(|d| !d.is_empty() && under_dirs(path, &d))
        .unwrap_or(false)
}

/// 프로세스 노드의 실행 파일 경로(attrs image, 소문자·역슬래시)
fn proc_image_lower(n: &Node) -> String {
    attr_str(n, "image")
        .unwrap_or_default()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// 이 프로세스가 브라우저(또는 그 도우미) 자신인가: 이름 + 설치 위치(graph::vault::browser_of_image) + 서명 조건.
/// 실행 파일의 서명이 없음·깨짐·신뢰 체인 없음으로 확인됐으면 위치가 맞아도 브라우저로 보지 않는다(서명 확인 전이면 위치만으로)
pub fn browser_of_proc(v: &View, proc_id: i64) -> Option<graph::vault::Browser> {
    let n = v.node(proc_id);
    if n.kind != "process" {
        return None;
    }
    let b = graph::vault::browser_of_image(&attr_str(n, "image")?, system_drive())?;
    // L062(30차 Q3-c): 다른 프로세스가 코드를 주입한 브라우저는 브라우저로 믿지 않는다(주입 코드가 금고를 열 수 있다)
    if v.inc
        .get(&proc_id)
        .is_some_and(|ix| ix.iter().any(|&i| v.edges[i].rel == "injected"))
    {
        return None;
    }
    if let Some(f) = v.image_file(proc_id) {
        if matches!(
            sig_of(f),
            Some(Sig::None_) | Some(Sig::Broken) | Some(Sig::Untrusted)
        ) {
            return None;
        }
    }
    Some(b)
}

/// 금고·미끼 파일을 여는 것이 일상인 시스템 구성요소(백신 검사·색인)와 우리 제품. 이름 + 시스템 드라이브의 정해진 위치 + (알면) Microsoft 서명.
/// 추측: 실기기에서 다른 백신·백업 도구가 금고 파일을 여는지 측정 전이다(오탐 측정 대상)
pub fn exempt_reader(v: &View, proc_id: i64) -> bool {
    let n = v.node(proc_id);
    // System(PID 4): 캐시 관리자·지연 쓰기 등 커널이 대신 하는 입출력
    if attr_u64(n, "pid") == Some(4) {
        return true;
    }
    if let Some(f) = v.image_file(proc_id) {
        if is_self_file(f) && sig_of(f) != Some(Sig::Broken) {
            return true;
        }
        if matches!(sig_of(f), Some(s) if s != Sig::Microsoft) {
            return false;
        }
    }
    let img = proc_image_lower(n);
    if img.split('\\').any(|seg| seg == ".." || seg == ".") {
        return false;
    }
    let name = file_name_lower(&img);
    let sys = system_drive() as char;
    let under = |d: &str| img.starts_with(&format!("{sys}:{d}"));
    match name.as_str() {
        "msmpeng.exe" | "mpdefendercoreservice.exe" | "nissrv.exe" | "mpcopyaccelerator.exe" => {
            under(r"\programdata\microsoft\windows defender\platform\")
                || under(r"\program files\windows defender\")
        }
        "searchprotocolhost.exe" | "searchindexer.exe" | "searchfilterhost.exe" => {
            under(r"\windows\system32\")
        }
        _ => false,
    }
}

/// 디버깅 실행 판정에서 "평범한 부모"(사용자가 바로가기·작업 표시줄로 연 경우): 브라우저 자신 또는 Windows 탐색기
fn ordinary_browser_parent(v: &View, parent: i64) -> bool {
    if browser_of_proc(v, parent).is_some() {
        return true;
    }
    proc_image_lower(v.node(parent)) == format!(r"{}:\windows\explorer.exe", system_drive() as char)
}

/// (사) 신호 종류. 각각 점수표 항목 하나
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultSignal {
    /// 브라우저가 아닌 프로그램이 금고 파일을 엶 (opened)
    VaultOpen,
    /// 등록된 미끼 파일을 엶 (opened)
    DecoyOpen,
    /// 브라우저가 디버깅 스위치로 실행됨 — 부모가 브라우저·탐색기가 아님 (ran)
    DebugLaunch,
    /// 브라우저가 아닌 프로그램이 이 PC 안(루프백)의 디버깅 포트에 접속 (connected)
    DebugPortConnect,
    /// 브라우저가 아닌 프로그램(서비스 관리자도 아님)이 브라우저 권한 상승 서비스를 실행 (spawned)
    ElevationByNonBrowser,
}

/// 디버깅 실행 명령줄에서 본 포트들 + 기본 포트(9222). View::load 가 한 번 만든다
pub fn debug_ports_of(
    edges: &[Edge],
    nodes: &std::collections::HashMap<i64, Node>,
) -> HashSet<u16> {
    let mut out: HashSet<u16> = HashSet::from([graph::vault::DEFAULT_DEBUG_PORT]);
    for e in edges.iter().filter(|e| e.rel == "ran") {
        if let Some(c) = nodes.get(&e.dst) {
            if let Some(p) = graph::vault::debug_port(&c.key) {
                out.insert(p);
            }
        }
    }
    out
}

/// 선 하나가 (사) 신호인가 — (신호, 행위자 프로세스 id). 행위자 = 사건의 뿌리가 될 프로세스
pub fn vault_signal(v: &View, e: &Edge) -> Option<(VaultSignal, i64)> {
    match e.rel.as_str() {
        "opened" => {
            let f = v.node(e.dst);
            if exempt_reader(v, e.src) {
                return None;
            }
            // 미끼: 어떤 프로그램이든(브라우저 포함 — 미끼 폴더는 실제 브라우저가 쓰지 않는 위치)
            if is_decoy(&f.key) {
                return Some((VaultSignal::DecoyOpen, e.src));
            }
            // 브라우저끼리(가져오기 기능)는 신호가 아니다
            if graph::vault::classify(&f.key).is_some() && browser_of_proc(v, e.src).is_none() {
                return Some((VaultSignal::VaultOpen, e.src));
            }
            None
        }
        "ran" => {
            let cmd = v.node(e.dst);
            if cmd.kind != "command" || graph::vault::debug_flags_only(&cmd.key).is_none() {
                return None;
            }
            // 행위자 = 디버깅 모드 브라우저를 실행한 부모. 부모를 모르면 신호로 치지 않는다(보수적)
            let parent = v.ins(e.src).find(|x| x.rel == "spawned")?.src;
            if ordinary_browser_parent(v, parent) {
                return None;
            }
            Some((VaultSignal::DebugLaunch, parent))
        }
        "connected" => {
            let r = v.node(e.dst);
            // 값싼 거르기 먼저(접속 선은 많다): 원격 노드 키 "ip:port" 의 포트
            let kport = r.key.rsplit(':').next()?.parse::<u16>().ok()?;
            if !v.debug_ports.contains(&kport) {
                return None;
            }
            let ip = attr_str(r, "ip")?;
            let port = u16::try_from(attr_u64(r, "port")?).ok()?;
            let lo = ip
                .parse::<std::net::IpAddr>()
                .map(|a| a.is_loopback())
                .unwrap_or(false);
            if !lo || !v.debug_ports.contains(&port) {
                return None;
            }
            if browser_of_proc(v, e.src).is_some() || exempt_reader(v, e.src) {
                return None;
            }
            Some((VaultSignal::DebugPortConnect, e.src))
        }
        "spawned" => {
            let c = v.node(e.dst);
            // 값싼 거르기 먼저: 프로세스 노드 이름(= 실행 파일 이름)
            if !c
                .label
                .eq_ignore_ascii_case(graph::vault::ELEVATION_SERVICE)
                || proc_image_name(c) != graph::vault::ELEVATION_SERVICE
            {
                return None;
            }
            if !browser_of_proc(v, e.dst).is_some_and(|b| b.chromium()) {
                return None;
            }
            let pimg = proc_image_lower(v.node(e.src));
            // 이미지를 모르는 부모(수집 전부터 있던 알 수 없는 프로그램)는 서비스 관리자일 수 있어 치지 않는다(보수적)
            if pimg.is_empty()
                || pimg == format!(r"{}:\windows\system32\services.exe", system_drive() as char)
                || browser_of_proc(v, e.src).is_some()
            {
                return None;
            }
            Some((VaultSignal::ElevationByNonBrowser, e.src))
        }
        _ => None,
    }
}

/// 브라우저가 끝난 뒤 권한 상승 서비스가 이 시간 안에 시작되면 보조 근거(100ns, 10초)
pub const ELEVATION_AFTER_BROWSER_END: i64 = 10 * 10_000_000;

/// 보조 근거: 같은 계열 브라우저 프로세스가 끝난 뒤 10초 안에 권한 상승 서비스가 시작됐고, 그때 `actors` 중 하나가 살아 있었다.
/// 돌려주는 값 = 권한 상승 서비스 프로세스로 들어오는 선 id(spawned, 없으면 executed_as). 판정은 이것만으로 사건을 만들지 않는다
pub fn elevation_after_browser_end(v: &View, actors: &[i64]) -> Option<i64> {
    // 노드 id 순으로(갈래 C: HashMap 순서면 근거 선이 실행마다·뷰마다 달랐다 — 증분 뷰와 전체 뷰의 결과가 같아야 한다)
    let mut elev: Vec<&Node> = v
        .nodes
        .values()
        .filter(|n| {
            n.kind == "process"
                && n.label
                    .eq_ignore_ascii_case(graph::vault::ELEVATION_SERVICE)
                && proc_image_name(n) == graph::vault::ELEVATION_SERVICE
        })
        .collect();
    elev.sort_unstable_by_key(|n| n.id);
    for n in elev {
        let Some(b) = browser_of_proc(v, n.id).filter(|b| b.chromium()) else {
            continue;
        };
        let t = n.first_ts;
        // 시각 조건을 먼저(값싼 것), 그다음 속성 JSON
        let ended_before = v.nodes.values().any(|m| {
            m.kind == "process"
                && m.id != n.id
                && m.last_ts <= t
                && t - m.last_ts <= ELEVATION_AFTER_BROWSER_END
                && !m
                    .label
                    .eq_ignore_ascii_case(graph::vault::ELEVATION_SERVICE)
                && m.attr("ended").and_then(|x| x.as_bool()).unwrap_or(false)
                && browser_of_proc(v, m.id) == Some(b)
        });
        if !ended_before {
            continue;
        }
        let alive = actors.iter().any(|a| {
            let p = v.node(*a);
            let ended = p.attr("ended").and_then(|x| x.as_bool()).unwrap_or(false);
            p.first_ts <= t && (!ended || p.last_ts >= t)
        });
        if !alive {
            continue;
        }
        if let Some(e) = v
            .ins(n.id)
            .find(|e| e.rel == "spawned")
            .or_else(|| v.ins(n.id).find(|e| e.rel == "executed_as"))
        {
            return Some(e.id);
        }
    }
    None
}

pub fn zone_is_internet(file: &Node) -> bool {
    matches!(attr_u64(file, "zone_id"), Some(3) | Some(4))
}
pub fn is_lan_or_local(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        return v4.is_private()
            || v4.is_loopback()
            || v4.is_link_local()
            || (o[0] == 100 && (64..128).contains(&o[1]))
            || v4.is_multicast()
            || v4.is_broadcast()
            || o[0] == 0;
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        let s = v6.segments();
        return v6.is_loopback()
            || (s[0] & 0xfe00) == 0xfc00
            || (s[0] & 0xffc0) == 0xfe80
            || v6.is_multicast()
            || v6.is_unspecified();
    }
    true
}
/// 원격지 노드가 "외부"인가 (4장 조건)
pub fn remote_is_external(n: &Node) -> bool {
    attr_str(n, "ip").map_or(false, |ip| !is_lan_or_local(&ip))
}
pub fn via_high(e: &Edge) -> bool {
    e.attrs_json
        .as_deref()
        .and_then(|a| serde_json::from_str::<serde_json::Value>(a).ok())
        .and_then(|v| {
            v.get("confidence")
                .and_then(|c| c.as_str())
                .map(|c| c == "high")
        })
        .unwrap_or(false)
}

/// 규칙 순위: (가)→(나)→(다)→(라)→(바)→(사)→(마). 같은 노드는 먼저 걸린(순위가 낮은) 규칙이 가진다
pub fn rule_rank(k: RootKind) -> u8 {
    match k {
        RootKind::IngressFile => 0,
        RootKind::UnsignedProcess => 1,
        RootKind::IsolatedSvchost => 2,
        RootKind::LolbinFromDocApp => 3,
        RootKind::RecoveryInhibit => 4,
        RootKind::VaultAccess => 5,
        RootKind::SignedPersist => 6,
    }
}

/// (사) 이 노드가 어떤 금고 신호 선의 행위자인가. 신호 선은 행위자의 나가는 선(opened·connected·spawned)이거나
/// 행위자가 낳은 자식의 디버깅 실행(ran) 선이다(`vault_signal` 의 행위자 정의와 같다)
pub fn is_vault_actor(v: &View, id: i64) -> bool {
    // 접속 선은 수만일 수 있다 — 원격지 키의 포트가 디버깅 포트가 아닌 선은 원격지마다 한 번만 보고 거른다
    let mut no_port: HashSet<i64> = HashSet::new();
    v.outs(id).any(|e| match e.rel.as_str() {
        "connected" => {
            if no_port.contains(&e.dst) {
                return false;
            }
            let hit = vault_signal(v, e).is_some_and(|(_, a)| a == id);
            if !hit {
                let port_ok = v
                    .node(e.dst)
                    .key
                    .rsplit(':')
                    .next()
                    .and_then(|p| p.parse::<u16>().ok())
                    .is_some_and(|p| v.debug_ports.contains(&p));
                if !port_ok {
                    no_port.insert(e.dst);
                }
            }
            hit
        }
        "opened" => vault_signal(v, e).is_some_and(|(_, a)| a == id),
        "spawned" => {
            vault_signal(v, e).is_some_and(|(_, a)| a == id)
                || v.outs(e.dst)
                    .any(|r| r.rel == "ran" && vault_signal(v, r).is_some_and(|(_, a)| a == id))
        }
        _ => false,
    })
}

/// 뿌리 후보를 규칙 순서대로 찾는다 ((가)→(나)→(다)→(라)→(바)→(사)→(마)). 같은 노드는 먼저 걸린 규칙이 가진다.
/// 같은 규칙 안에서는 노드 id 순(갈래 C: 전에는 HashMap 순서라 실행마다 달랐다 — 두 뿌리의 사슬이 겹치면
/// 어느 쪽이 사건을 가지는지가 실행마다 바뀌었다. 증분 판정과 전체 판정을 같게 하려면 순서가 정해져 있어야 한다)
pub fn find_roots(v: &View) -> Vec<(i64, RootKind)> {
    let mut out: Vec<(u8, i64, RootKind)> = v
        .nodes
        .values()
        .filter_map(|n| root_kind_of(v, n).map(|k| (rule_rank(k), n.id, k)))
        .collect();
    out.sort_unstable_by_key(|(r, id, _)| (*r, *id));
    out.into_iter().map(|(_, id, k)| (id, k)).collect()
}

/// 노드 하나가 어느 뿌리 규칙에 걸리는가(순위 순으로 처음 걸린 것). 노드 자신과 이웃만 본다 —
/// 증분 판정이 바뀐 노드 근처만 다시 분류할 수 있게(무엇에 기대는지는 `incremental` 의 후보 넓히기 참고)
pub fn root_kind_of(v: &View, n: &Node) -> Option<RootKind> {
    if n.kind == "file" {
        // (가) 외부 유입 파일: downloaded 선의 대상 또는 Zone 3·4. 실행 파일·스크립트·컨테이너만.
        if is_pe(&n.key) || is_script_or_container(&n.key) {
            let downloaded = v.ins(n.id).any(|e| e.rel == "downloaded");
            if downloaded || zone_is_internet(n) {
                return Some(RootKind::IngressFile);
            }
        }
        // (나) 서명 없거나 깨진 PE 의 프로세스 (뿌리는 파일 노드로 둔다: 같은 파일의 여러 실행을 한 사건으로)
        // 자기 구성요소(설치 폴더, 서명 내용 온전)는 뿌리로 삼지 않는다(L015 자기 자신 오탐). 내용이 바뀐(Broken) 우리 파일은 그대로 뿌리
        if is_pe(&n.key) {
            let sig = sig_of(n);
            let self_ok = is_self_file(n) && sig != Some(Sig::Broken);
            if !self_ok
                && matches!(
                    sig,
                    Some(Sig::None_) | Some(Sig::Broken) | Some(Sig::Untrusted)
                )
                && v.outs(n.id).any(|e| e.rel == "executed_as")
            {
                return Some(RootKind::UnsignedProcess);
            }
        }
    }
    // 이미지 이름은 JSON 을 풀어야 해서 필요할 때 한 번만
    let mut image: Option<String> = None;
    let mut image_of = |n: &Node| image.get_or_insert_with(|| proc_image_name(n)).clone();
    // (다) 고립 svchost: 귀속 없는 외부 접속 + 알려진 Microsoft 서비스 없음
    if n.kind == "process" && image_of(n) == "svchost.exe" {
        let services: Vec<String> = n
            .attr("services")
            .and_then(|s| serde_json::from_value(s).ok())
            .unwrap_or_default();
        let known = services
            .iter()
            .any(|s| KNOWN_MS_SERVICES.contains(&s.to_ascii_lowercase().as_str()));
        if !known {
            // 원격지 판단은 원격지마다 한 번(속성 JSON 풀기) — svchost 는 접속 선이 수만이라 선마다 풀면 수십 ms(갈래 C perf_scale)
            let mut memo: HashMap<i64, bool> = HashMap::new();
            let isolated = v.outs(n.id).any(|e| {
                e.rel == "connected"
                    && !v.table_only.contains(&e.id)
                    && *memo.entry(e.dst).or_insert_with(|| {
                        remote_is_external(v.node(e.dst))
                            && !v.ins(e.dst).any(|x| x.rel == "connected_via")
                    })
            });
            if isolated {
                return Some(RootKind::IsolatedSvchost);
            }
        }
    }
    // (라) 문서 처리기 → LOLBin: 뿌리는 그 자손 프로세스(이 노드). 부모가 문서 처리기인 spawned 선이 있는가
    if v.ins(n.id).any(|e| e.rel == "spawned") && LOLBINS.contains(&image_of(n).as_str()) {
        let from_doc = v.ins(n.id).any(|e| {
            if e.rel != "spawned" {
                return false;
            }
            let p = v.node(e.src);
            p.kind == "process" && DOC_APPS.contains(&proc_image_name(p).as_str())
        });
        if from_doc {
            return Some(RootKind::LolbinFromDocApp);
        }
    }
    // (바) 복구 수단 삭제 명령을 실행한 프로세스. 뿌리는 그 프로세스(서명된 Windows 도구라 파일을 뿌리로 하면 모든 실행이 한 사건이 된다)
    if n.kind == "process"
        && v.outs(n.id)
            .any(|e| e.rel == "ran" && ran_kind(e, v.node(e.dst)).is_some())
    {
        return Some(RootKind::RecoveryInhibit);
    }
    // (사) 브라우저 금고 경비: 신호를 낸 행위자 프로세스. 뿌리는 프로세스((바)와 같은 이유 — 서명된 Windows 도구(PowerShell 등)의
    // 파일을 뿌리로 하면 그 도구의 모든 실행이 한 사건이 된다). (마)보다 먼저: 자리잡기도 한 서명 프로그램이면 이쪽이 가진다.
    // 행위자 = 신호 선의 출발 노드(opened·connected·spawned), 또는 디버깅 실행(ran)을 한 프로세스의 부모 — 이 노드가 행위자인 신호 선이 있는가
    if is_vault_actor(v, n.id) {
        return Some(RootKind::VaultAccess);
    }
    // (마) 서명된 프로그램의 자리잡기: 보여 주기용. 뿌리는 실행 파일 = 자리잡기(registered)를 한 프로세스의 image_file
    if matches!(sig_of(n), Some(Sig::Microsoft) | Some(Sig::Valid)) {
        let persisted = v.outs(n.id).any(|e| {
            if e.rel != "executed_as" {
                return false;
            }
            let p = v.node(e.dst);
            p.kind == "process"
                && v.outs(p.id).any(|x| x.rel == "registered")
                && v.image_file(p.id).map(|f| f.id) == Some(n.id)
        });
        if persisted {
            return Some(RootKind::SignedPersist);
        }
    }
    None
}

pub struct Chain {
    /// (선 id, 장). 장이 없는 선(resolved 등)은 None.
    pub edges: Vec<(i64, Option<Chapter>)>,
    pub chapter: Chapter,
    pub ingress_unknown: bool,
    /// 사건에 속한 프로세스 노드
    pub procs: Vec<i64>,
    /// 사건에 속한 파일 노드 (뿌리 포함)
    pub files: Vec<i64>,
    /// 갈래 C: 이 사슬을 만들 때 읽은 노드(정렬·중복 없음). 이 중 하나라도 바뀌거나(속성) 선이 붙고 떨어지면
    /// 사슬을 다시 모은다 — 뿌리, 뿌리로 들어온 선의 출발 노드, 따라간 노드, 따라간 노드에서 나간 선의 도착 노드
    pub deps: Vec<i64>,
}

/// `vault_signal(v, e)` 가 선의 두 끝점 말고 읽는 노드(갈래 C 사슬 의존). 끝점의 실행 파일(서명 — 브라우저·면제 판단),
/// 디버깅 실행(ran)이면 실행한 프로세스의 부모와 그 실행 파일. 이 노드들로 가는 선이 바뀌면 끝점이 바뀐 것으로 잡힌다
pub fn vault_signal_deps(v: &View, e: &Edge, deps: &mut Vec<i64>) {
    for n in [e.src, e.dst] {
        if let Some(f) = v.image_file(n) {
            deps.push(f.id);
        }
    }
    if e.rel == "ran" {
        if let Some(p) = v.ins(e.src).find(|x| x.rel == "spawned") {
            deps.push(p.src);
            if let Some(f) = v.image_file(p.src) {
                deps.push(f.id);
            }
        }
    }
}

/// 뿌리에서 닿는 선을 모으고 장을 매긴다.
pub fn collect_chain(v: &View, root: i64, kind: RootKind) -> Chain {
    let mut edges: Vec<(i64, Option<Chapter>)> = Vec::new();
    let mut procs = Vec::new();
    let mut files = Vec::new();
    let mut seen_nodes: HashSet<i64> = HashSet::new();
    let mut seen_edges: HashSet<i64> = HashSet::new();
    let mut top: Option<Chapter> = None;
    let bump = |c: Chapter, top: &mut Option<Chapter>| {
        if top.map_or(true, |t| c > t) {
            *top = Some(c);
        }
    };
    let root_node = v.node(root);
    let mut ingress_unknown = true;
    let mut deps: Vec<i64> = vec![root];
    // 1장: 뿌리 파일로 들어온 선 (downloaded, 유입 앱의 wrote)
    if root_node.kind == "file" {
        files.push(root);
        for e in v.ins(root) {
            deps.push(e.src);
            let ch = match e.rel.as_str() {
                "downloaded" => Some(Chapter::Ingress),
                "wrote" if INGRESS_APPS.contains(&proc_image_name(v.node(e.src)).as_str()) => {
                    Some(Chapter::Ingress)
                }
                _ => None,
            };
            if let Some(c) = ch {
                ingress_unknown = false;
                bump(c, &mut top);
                if seen_edges.insert(e.id) {
                    edges.push((e.id, Some(c)));
                }
            }
        }
        if zone_is_internet(root_node) {
            ingress_unknown = false;
            bump(Chapter::Ingress, &mut top);
        }
    }
    // (사): 뿌리 프로세스의 실행 파일을 사건 파일 첫 자리에 — 서명·위치·출신 가중치와 "정상" 피드백이 그 파일을 본다
    if kind == RootKind::VaultAccess && root_node.kind == "process" {
        if let Some(f) = v.image_file(root) {
            deps.push(f.id);
            files.push(f.id);
            if zone_is_internet(f) {
                ingress_unknown = false;
                bump(Chapter::Ingress, &mut top);
            }
        }
    }
    // (라): 문서 처리기 → 뿌리(LOLBin) 의 spawned 선이 신호 자체다. 2장 근거로 넣는다
    // (바): 누가 복구 수단 도구를 실행했는지(부모) — 카드의 "실행한 프로그램" 근거
    if matches!(kind, RootKind::LolbinFromDocApp | RootKind::RecoveryInhibit) {
        for e in v.ins(root).filter(|e| e.rel == "spawned") {
            deps.push(e.src);
            if seen_edges.insert(e.id) {
                bump(Chapter::Execute, &mut top);
                edges.push((e.id, Some(Chapter::Execute)));
            }
        }
    }
    // 2장 이후: 뿌리에서 앞으로 (파일→프로세스→자손·쓴 파일·등록·접속)
    let mut q: VecDeque<i64> = VecDeque::new();
    q.push_back(root);
    seen_nodes.insert(root);
    while let Some(id) = q.pop_front() {
        let n = v.node(id);
        // 큐에는 seen_nodes 로 한 번씩만 들어오므로 중복 검사(Vec::contains, 사슬 크기의 제곱)가 필요 없다(L064)
        if n.kind == "process" {
            procs.push(id);
        }
        for e in v.outs(id) {
            // 이미 본 선도 도착 노드는 의존(같은 선은 같은 도착 — 중복은 아래에서 지운다)
            deps.push(e.dst);
            if !seen_edges.insert(e.id) {
                continue;
            }
            // (사) 신호 판단이 끝점 밖에서 읽는 노드(끝점의 실행 파일, 디버깅 실행의 부모와 그 실행 파일)
            vault_signal_deps(v, e, &mut deps);
            let dst = v.node(e.dst);
            let ch = match e.rel.as_str() {
                // (사) 신호 선은 2장(실행 중 한 일)으로 남긴다 — 디버깅 포트 접속(이 PC 안)·금고 열기는 4장 조건이 아니다
                _ if vault_signal(v, e).is_some() => Some(Chapter::Execute),
                "executed_as" | "spawned" => Some(Chapter::Execute),
                "wrote" => {
                    let lower = dst.key.to_ascii_lowercase();
                    if AUTOSTART_DIRS.iter().any(|d| lower.contains(d)) {
                        Some(Chapter::Persist)
                    } else if is_pe(&dst.key) || is_script_or_container(&dst.key) {
                        Some(Chapter::Execute)
                    } else {
                        None
                    }
                }
                "registered" => Some(Chapter::Persist),
                "connected" if remote_is_external(dst) && !v.table_only.contains(&e.id) => {
                    Some(Chapter::Egress)
                }
                "connected_via" if via_high(e) && remote_is_external(dst) => Some(Chapter::Egress),
                "ran" if ran_kind(e, dst).is_some() => Some(Chapter::Destroy),
                _ => None,
            };
            if let Some(c) = ch {
                bump(c, &mut top);
            }
            edges.push((e.id, ch));
            // 다음 노드로: 프로세스·파일만 따라간다 (원격지·도메인·자동실행은 끝)
            let follow = matches!(e.rel.as_str(), "executed_as" | "spawned" | "wrote");
            if follow && seen_nodes.insert(e.dst) {
                if dst.kind == "file" {
                    files.push(e.dst);
                }
                q.push_back(e.dst);
            }
        }
    }
    // 뿌리가 프로세스이거나 1장이 없으면 2장부터
    let chapter = top.unwrap_or(Chapter::Execute);
    let chapter = if matches!(
        kind,
        RootKind::IsolatedSvchost
            | RootKind::LolbinFromDocApp
            | RootKind::UnsignedProcess
            | RootKind::RecoveryInhibit
            | RootKind::VaultAccess
    ) && chapter < Chapter::Execute
    {
        Chapter::Execute
    } else {
        chapter
    };
    // 따라간 노드(seen_nodes)는 모두 어떤 선의 도착 노드이거나 뿌리라 deps 에 이미 있다
    deps.sort_unstable();
    deps.dedup();
    Chain {
        edges,
        chapter,
        ingress_unknown,
        procs,
        files,
        deps,
    }
}

#[cfg(test)]
mod self_path_tests {
    use super::under_dirs;

    #[test]
    fn self_dir_match_fails_closed_on_unnormalized_paths() {
        let d = vec![r"c:\program files\story firewall\".to_string()];
        assert!(under_dirs(
            r"C:\Program Files\Story Firewall\story-firewall-ui.exe",
            &d
        ));
        assert!(under_dirs("C:/Program Files/Story Firewall/geo/x.mmdb", &d));
        // 24차 Q2: 위장 경로는 전부 "우리 것 아님"
        assert!(!under_dirs(
            r"C:\Program Files\Story Firewall\..\..\Users\u\evil.exe",
            &d
        ));
        assert!(!under_dirs(r"C:\Program Files\Story Firewall\.\x.exe", &d));
        assert!(!under_dirs(
            r"\\?\C:\Program Files\Story Firewall\x.exe",
            &d
        ));
        assert!(!under_dirs(
            r"\\.\C:\Program Files\Story Firewall\x.exe",
            &d
        ));
        assert!(!under_dirs(
            r"\Device\HarddiskVolume3\Program Files\Story Firewall\x.exe",
            &d
        ));
        assert!(!under_dirs(r"C:\PROGRA~1\STORYF~1\x.exe", &d));
        assert!(!under_dirs(r"D:\Program Files\Story Firewall\x.exe", &d));
        assert!(!under_dirs(
            r"C:\Program Files\Story Firewall Evil\x.exe",
            &d
        ));
        assert!(!under_dirs(
            r"C:\Program Files\Story Firewall\ui.exe:payload",
            &d
        ));
    }
}
