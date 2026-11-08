//! 파괴 행위 자동 대응 판정(대시보드 개편안 2판 4-2). 판정만 한다 — 집행(종료·차단·격리)은 서비스(svc)가
//! 기존 "여기서부터 끊기" 경로로 한다. OS 의존 없음(뷰 위에서만).
//!
//! 세 조건이 모두 맞을 때만 대응한다:
//! - (나) 사건 안의 어떤 프로세스가 T1490 명령(`rules::ran_kind`: vssadmin delete shadows, wmic shadowcopy delete,
//!   bcdedit recoveryenabled no, wbadmin delete catalog …)을 실행했다.
//! - (가)·(다) 그 프로세스에서 위로 `\Windows\` 아래 도구(cmd·powershell·wscript·explorer·svchost…)를 건너뛰고
//!   처음 만나는 Windows 밖 조상(= 명령을 일으킨 프로그램)이 Microsoft 서명도 사용자 허용 목록 서명자도 아니다.
//!   그 위로는 올라가지 않는다(A29 실측 — 아래 judge() 주석; 대시보드 개편안 3판 4-2). Windows 도구를 빼는 까닭: 거의 모든 파괴 명령은
//!   cmd.exe 를 거치고 cmd.exe 는 Microsoft 서명이라, 빼지 않으면 예외가 항상 성립한다. Microsoft 가 아닌 유효 서명은
//!   예외가 아니다(2판 4-2 그대로 — 산 인증서로 서명한 랜섬웨어가 흔하다; 정당한 백업 도구는 허용 목록으로).
//! - Windows 바깥 조상이 하나도 없으면(explorer·svchost 같은 핵심 프로세스나 Windows 도구만) 원인 프로그램을
//!   모른다 — "핵심 프로세스가 부모" 경우로 자식(명령을 실행한 프로세스)만 종료한다(`Mode::ChildOnly`).
//! - 끊기 대상(`origin`)은 그 프로그램이다. 서명을 아직 모르면(서비스보다 먼저 켜짐) 끊지 않고 ChildOnly.
//!
//! 한계(설정 문구에 그대로 적는다): ETW 는 사후 통지라 이 대응은 피해를 "줄이기"이지 "막기"가 아니다.

use crate::rules::{self, Sig};
use crate::{Story, View};

/// 대응 범위
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// 원인 프로그램(사건 뿌리)부터 끊기: 뿌리·자손 종료 + 뿌리 경로 차단 + 자리잡기 제거
    Full,
    /// 핵심 프로세스·Windows 도구가 부모: 명령을 실행한 프로세스(와 그 자손)만 종료, 접속지 차단
    ChildOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoResponse {
    pub story_root: i64,
    pub mode: Mode,
    /// 끊기 대상 — 명령을 일으킨 첫 Windows 밖 조상(Full), ChildOnly 면 trigger_proc 과 같다
    pub origin: i64,
    /// T1490 명령을 실행한 프로세스 노드 id
    pub trigger_proc: i64,
    /// 명령 종류 설명(예: "그림자 복사본 삭제")
    pub what: &'static str,
    /// 사슬에서 서명이 확인되지 않은 조상(뿌리 쪽부터) — 사건 카드의 근거 문장용
    pub unsigned_chain: Vec<i64>,
}

/// 조상 사슬에 서명 예외가 있으면 그 노드 id(대응하지 않는 이유)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Respond(AutoResponse),
    /// 조상이 Microsoft 서명 또는 허용 목록 서명자 — 대응하지 않음
    TrustedAncestor {
        proc_id: i64,
        signer: String,
    },
    /// T1490 명령이 없음
    NoDestroy,
}

fn image_path_lower(view: &View, proc_id: i64) -> Option<String> {
    view.image_file(proc_id).map(|f| f.key.to_ascii_lowercase())
}

/// 일반 사용자가 쓸 수 있는 Windows 폴더 아래 경로(소문자, `x:\windows\` 다음 부분). 여기 놓인 실행 파일은 Windows 도구가 아니다.
/// 출처: 기본 ACL 에서 Users 쓰기·실행이 허용되는 것으로 알려진 폴더(AppLocker 우회 목록으로 널리 정리된 것). 44차 Q1-①
const USER_WRITABLE_UNDER_WINDOWS: &[&str] = &[
    "temp\\",
    "tasks\\",
    "tracing\\",
    "debug\\",
    "registration\\crmlog\\",
    "system32\\tasks\\",
    "system32\\fxstmp\\",
    "system32\\com\\dmp\\",
    "system32\\spool\\",
    "system32\\microsoft\\crypto\\rsa\\machinekeys\\",
    "syswow64\\tasks\\",
    "syswow64\\fxstmp\\",
    "syswow64\\com\\dmp\\",
];

/// 경로가 Windows 시스템 폴더(`<드라이브>:\Windows\`) **바로 아래에서 시작**하고 사용자 쓰기 가능 하위 폴더가 아닌가(소문자 경로).
/// 44차 Q1-①: 예전 부분 문자열 판정은 `C:\Windows\Temp\x.exe`·`D:\backup\windows\x.exe` 를 Windows 도구로 건너뛰었다.
pub fn is_windows_tool(path_lower: &str) -> bool {
    let p = path_lower.replace('/', "\\");
    let p = p.strip_prefix("\\\\?\\").unwrap_or(&p);
    let b = p.as_bytes();
    // get(): 여러 바이트 문자에서 자를 때 패닉하지 않게
    if b.is_empty() || !b[0].is_ascii_alphabetic() || p.get(1..11) != Some(":\\windows\\") {
        return false;
    }
    let rest = p.get(11..).unwrap_or("");
    !USER_WRITABLE_UNDER_WINDOWS
        .iter()
        .any(|w| rest.starts_with(w))
}

/// 건너뛸 Windows 도구인가: 위치(is_windows_tool) + 서명 사실이 있으면 Microsoft 서명이어야 한다.
/// 서명 사실이 아직 없으면(서비스보다 먼저 켜짐) 위치만으로 판단한다.
fn windows_tool(view: &View, proc_id: i64, path_lower: &str) -> bool {
    if !is_windows_tool(path_lower) {
        return false;
    }
    match view.image_file(proc_id).and_then(rules::sig_of) {
        None | Some(Sig::Microsoft) => true,
        Some(_) => false, // Windows 폴더에 있는데 Microsoft 서명이 아니다 → 프로그램으로 본다
    }
}

/// 허용 목록 항목과 서명자 이름이 같은가(정확 일치 — 앞뒤 공백·대소문자·연속 공백만 정규화)
pub fn signer_matches(allowed: &str, signer: &str) -> bool {
    let norm = |s: &str| {
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    let a = norm(allowed);
    !a.is_empty() && a == norm(signer)
}

fn parent_of(view: &View, proc_id: i64) -> Option<i64> {
    view.ins(proc_id)
        .find(|e| e.rel == "spawned")
        .map(|e| e.src)
}

/// 사건 하나를 판정한다. `allow_signers`: 사용자 허용 목록 서명자(**정확 일치**, 앞뒤 공백·대소문자만 무시).
/// 44차 Q1-②: 앞부분 일치는 "Acme" 허용이 "Acme Evil Ltd"까지 통과시켰다.
pub fn judge(view: &View, story: &Story, allow_signers: &[String]) -> Verdict {
    // (나) 사건의 선 가운데 T1490 `ran` 선 — 가장 이른 것 하나
    let mut trigger: Option<(i64, &'static str, i64)> = None; // (proc, what, ts)
    for &eid in &story.edges {
        let Some(e) = view.edge(eid) else { continue };
        let Some(cmd) = view.nodes.get(&e.dst) else {
            continue;
        };
        if let Some(what) = rules::ran_kind(e, cmd) {
            if trigger.is_none_or(|(_, _, ts)| e.ts < ts) {
                trigger = Some((e.src, what, e.ts));
            }
        }
    }
    let Some((trigger_proc, what, _)) = trigger else {
        return Verdict::NoDestroy;
    };
    // (가)(다) A29 러너 실측(2026-11-08)으로 좁힌 규칙: 명령 실행 프로세스에서 위로 올라가며 `\Windows\` 도구를
    // 건너뛰고, **처음 만나는 Windows 밖 조상 하나**(= 명령을 일으킨 프로그램)만 본다. 그 위로는 올라가지 않는다.
    // - 예전(맨 위까지): 서비스보다 먼저 켜진 프로세스는 서명 사실이 없어 "서명 없음"으로 세어졌고, 끊기 대상이
    //   가장 위의 미확인 조상(러너 에이전트 = Runner.Listener)이 되어 그 트리를 종료했다. 실제 PC 라면 먼저 켜진
    //   정상 프로그램이 죽는다. 거꾸로 사슬 어딘가의 Microsoft 서명(msedge.exe, pwsh.exe)이 면제를 줘서
    //   Edge 에서 바로 실행한 악성 프로그램이 빠져나갔다.
    // - 서명 사실이 없는(미확인) 조상은 끊지 않는다 — 명령 실행 프로세스만 종료(ChildOnly).
    let mut cur = Some(trigger_proc);
    let mut hops = 0;
    let mut actor: Option<i64> = None;
    while let Some(p) = cur {
        if hops >= 64 {
            break;
        }
        hops += 1;
        match image_path_lower(view, p) {
            Some(path) if windows_tool(view, p, &path) => cur = parent_of(view, p),
            Some(_) => {
                actor = Some(p);
                break;
            }
            None => break, // 실행 파일을 모르면 더 오르지 않는다
        }
    }
    let mut unsigned_chain = Vec::new();
    let mut mode = Mode::ChildOnly;
    if let Some(p) = actor {
        let file = view
            .image_file(p)
            .expect("image_path_lower 가 Some 이면 image_file 도 Some");
        let signer = rules::attr_str(file, "signer").unwrap_or_default();
        let allowed = || allow_signers.iter().any(|a| signer_matches(a, &signer));
        match rules::sig_of(file) {
            Some(Sig::Microsoft) => return Verdict::TrustedAncestor { proc_id: p, signer },
            Some(Sig::Valid) | Some(Sig::Package) if allowed() => {
                return Verdict::TrustedAncestor { proc_id: p, signer }
            }
            // 서명 없음·깨짐·불신·Microsoft 아닌 유효 서명(2판 4-2: 예외 아님) → 이 프로그램부터 끊기
            Some(_) => {
                unsigned_chain.push(p);
                mode = Mode::Full;
            }
            // 서명을 아직 모름(서비스보다 먼저 켜짐 등) → 끊지 않고 명령 실행 프로세스만
            None => {}
        }
    }
    let origin = unsigned_chain.first().copied().unwrap_or(trigger_proc);
    Verdict::Respond(AutoResponse {
        story_root: story.root,
        mode,
        origin,
        trigger_proc,
        what,
        unsigned_chain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_tool_is_exact_system_root_prefix_without_user_writable_folders() {
        // 진짜 Windows 도구
        assert!(is_windows_tool(r"c:\windows\system32\cmd.exe"));
        assert!(is_windows_tool(r"c:\windows\system32\wbem\wmiprvse.exe"));
        assert!(is_windows_tool(r"d:\windows\explorer.exe"));
        assert!(is_windows_tool(r"\\?\c:\windows\system32\vssadmin.exe"));
        // 44차 Q1-①: 일반 사용자가 쓸 수 있는 Windows 하위 폴더 · 경로 중간의 windows 는 도구가 아니다
        assert!(!is_windows_tool(r"c:\windows\temp\malware.exe"));
        assert!(!is_windows_tool(r"c:\windows\tasks\a.exe"));
        assert!(!is_windows_tool(r"c:\windows\tracing\a.exe"));
        assert!(!is_windows_tool(
            r"c:\windows\system32\spool\drivers\color\a.exe"
        ));
        assert!(!is_windows_tool(r"c:\windows\system32\tasks\a.exe"));
        assert!(!is_windows_tool(r"d:\backup\windows\malware.exe"));
        assert!(!is_windows_tool(r"c:\users\u\appdata\local\windows\x.exe"));
        assert!(!is_windows_tool(r"c:\windowsapps\x.exe"));
        // 여러 바이트 문자에서 패닉하지 않는다
        assert!(!is_windows_tool("c:\\windows한\\x.exe"));
        assert!(!is_windows_tool("가:\\windows\\x.exe"));
        assert!(!is_windows_tool(""));
    }

    #[test]
    fn signer_match_is_exact_after_normalizing_case_and_spaces() {
        assert!(signer_matches("acme software inc.", "Acme Software Inc."));
        assert!(signer_matches(
            "  Acme   Software Inc. ",
            "Acme Software Inc."
        ));
        assert!(!signer_matches("Acme", "Acme Evil Ltd"));
        assert!(!signer_matches("Acme Software", "Acme Software Inc."));
        assert!(!signer_matches("", "Acme"));
    }
}
