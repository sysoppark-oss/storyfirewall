//! 파괴 행위 자동 대응 판정(대시보드 개편안 2판 4-2). 판정만 한다 — 집행(종료·차단·격리)은 서비스(svc)가
//! 기존 "여기서부터 끊기" 경로로 한다. OS 의존 없음(뷰 위에서만).
//!
//! 세 조건이 모두 맞을 때만 대응한다:
//! - (나) 사건 안의 어떤 프로세스가 T1490 명령(`rules::ran_kind`: vssadmin delete shadows, wmic shadowcopy delete,
//!   bcdedit recoveryenabled no, wbadmin delete catalog …)을 실행했다.
//! - (가)·(다) 그 프로세스에서 맨 위까지 올라가는 부모 사슬(사건 뿌리에서 멈추지 않는다 — 서명된 프로그램은 뿌리가
//!   되지 않으므로)에서, `\Windows\` 아래 도구(cmd·powershell·wscript·explorer·svchost…)를 뺀 나머지 조상 가운데
//!   Microsoft 서명 또는 사용자 허용 목록 서명자가 **하나도 없다**. Windows 도구를 빼는 까닭: 거의 모든 파괴 명령은
//!   cmd.exe 를 거치고 cmd.exe 는 Microsoft 서명이라, 빼지 않으면 예외가 항상 성립한다. Microsoft 가 아닌 유효 서명은
//!   예외가 아니다(2판 4-2 그대로 — 산 인증서로 서명한 랜섬웨어가 흔하다; 정당한 백업 도구는 허용 목록으로).
//! - Windows 바깥 조상이 하나도 없으면(explorer·svchost 같은 핵심 프로세스나 Windows 도구만) 원인 프로그램을
//!   모른다 — "핵심 프로세스가 부모" 경우로 자식(명령을 실행한 프로세스)만 종료한다(`Mode::ChildOnly`).
//! - 끊기 대상(`origin`)은 가장 바깥의 Windows 밖 조상(원인 프로그램)이다.
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
    /// 끊기 대상 — 가장 바깥의 Windows 밖 조상(Full), ChildOnly 면 trigger_proc 과 같다
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
    TrustedAncestor { proc_id: i64, signer: String },
    /// T1490 명령이 없음
    NoDestroy,
}

fn image_path_lower(view: &View, proc_id: i64) -> Option<String> {
    view.image_file(proc_id).map(|f| f.key.to_ascii_lowercase())
}

/// `\Windows\` 아래 실행 파일인가(cmd·powershell·wscript·vssadmin 등 Windows 도구)
pub fn is_windows_tool(path_lower: &str) -> bool {
    let p = path_lower.replace('/', "\\");
    p.contains("\\windows\\")
}

fn parent_of(view: &View, proc_id: i64) -> Option<i64> {
    view.ins(proc_id).find(|e| e.rel == "spawned").map(|e| e.src)
}

/// 사건 하나를 판정한다. `allow_signers`: 사용자 허용 목록 서명자(앞부분 일치, 대소문자 무시).
pub fn judge(view: &View, story: &Story, allow_signers: &[String]) -> Verdict {
    // (나) 사건의 선 가운데 T1490 `ran` 선 — 가장 이른 것 하나
    let mut trigger: Option<(i64, &'static str, i64)> = None; // (proc, what, ts)
    for &eid in &story.edges {
        let Some(e) = view.edge(eid) else { continue };
        let Some(cmd) = view.nodes.get(&e.dst) else { continue };
        if let Some(what) = rules::ran_kind(e, cmd) {
            if trigger.is_none_or(|(_, _, ts)| e.ts < ts) {
                trigger = Some((e.src, what, e.ts));
            }
        }
    }
    let Some((trigger_proc, what, _)) = trigger else {
        return Verdict::NoDestroy;
    };
    // (가)(다) 명령 실행 프로세스 → 맨 위까지 부모 사슬(순환·끊긴 기록 대비 상한 64)
    let mut chain = Vec::new();
    let mut cur = Some(trigger_proc);
    while let Some(p) = cur {
        if chain.contains(&p) || chain.len() >= 64 {
            break;
        }
        chain.push(p);
        cur = parent_of(view, p);
    }
    let mut unsigned_chain = Vec::new();
    for &p in chain.iter().rev() {
        let Some(path) = image_path_lower(view, p) else {
            // 실행 파일을 모르는 프로세스: 확인 불가 → 미확인으로 센다
            unsigned_chain.push(p);
            continue;
        };
        if is_windows_tool(&path) {
            continue;
        }
        let file = view.image_file(p).expect("image_path_lower 가 Some 이면 image_file 도 Some");
        let signer = rules::attr_str(file, "signer").unwrap_or_default();
        match rules::sig_of(file) {
            Some(Sig::Microsoft) => {
                return Verdict::TrustedAncestor { proc_id: p, signer };
            }
            Some(Sig::Valid) | Some(Sig::Package)
                if allow_signers
                    .iter()
                    .any(|a| !a.is_empty() && signer.to_ascii_lowercase().starts_with(&a.to_ascii_lowercase())) =>
            {
                return Verdict::TrustedAncestor { proc_id: p, signer };
            }
            _ => unsigned_chain.push(p),
        }
    }
    let mode = if unsigned_chain.is_empty() { Mode::ChildOnly } else { Mode::Full };
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
