//! 장면 → 문장. 템플릿 기반, 외부 모델 없음.
//!
//! 화법 (이야기형 3판 5-6장)
//! - Expert : 시각(초 단위), PID, 원격지 IP:포트, 횟수까지
//! - Plain  : 쉬운 문장, 프로그램 이름과 도메인 위주
//! - OneLine: 장면 하나를 한 문장으로
//!
//! 금지어: 의도를 단정하는 말("몰래", "훔치", "숨기", "악성"). 테스트에서 검사한다.

use crate::facts::Verb;
use crate::scenes::{Action, Scene};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Voice {
    Expert,
    Plain,
    OneLine,
}

#[derive(Debug, Clone, Serialize)]
pub struct Sentence {
    pub text: String,
    /// 이 문장을 뒷받침하는 원시 이벤트 id 들
    pub evidence: Vec<i64>,
    pub edge_ids: Vec<i64>,
    /// 주인공 프로세스 노드 id (마인드맵 연동: 문장 ↔ 가지)
    pub actor_id: i64,
    pub ts: i64,
    pub chapter: Option<i64>,
    /// 구조형 문장(D003-2): "[주체] → [동작] [대상]". 화면은 동작만 굵게 그린다. 없으면 text 만
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts: Option<Parts>,
    /// 수집 시작 때 이미 열려 있던 연결(연결 테이블 첫 폴링, 시작 1분 안)만 근거인 문장(D006-1). 화면은 회색 + "(수집 시작 때 이미 열려 있음)"
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub already_open: bool,
    /// 근거 출처별 수(B1): [("etw", 2), ("conntable", 1)]. 화면이 사용자 말로 바꾼다
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<(String, u32)>,
    /// D028-1: 서비스 경유 귀속 문장이면 짝지은 두 이벤트의 시각 차(ms). 화면은 근거 배지 툴팁에
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_lag_ms: Option<i64>,
}

/// D028-1: 경유 귀속의 근거 이름. 확신 정도("~로 보임")가 아니라 무엇을 대조했는지를 쓴다
pub fn via_basis_name(a: &Action) -> &'static str {
    match a.via_basis.as_ref().map(|(m, _)| m.as_str()) {
        Some("capi2") => "인증서 확인 기록 대조",
        _ => "시각 대조",
    }
}

fn via_lag(a: &Action) -> Option<i64> {
    a.via_basis.as_ref().and_then(|(_, l)| *l)
}

/// 25차 Q7: 주체·대상은 외부 문자열(파일 이름·도메인)이다. 문장의 구분자 "→"(와 닮은 화살표)가 들어 있으면
/// "누가 → 무엇을" 구조를 거짓으로 만들 수 있으므로 "->" 로 바꾼다(사실 값은 근거 원시 이벤트에 그대로 있다)
pub fn no_arrows(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '→' | '⇒' | '⟶' | '➔' | '➜' | '➝' | '➞' | '⮕' | '🡒') {
            out.push_str("->");
        } else {
            out.push(c);
        }
    }
    out
}

/// 조사 없는 문장 조각. 주체·대상은 외부 문자열일 수 있다 — 화면은 텍스트 노드로만 넣는다
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Parts {
    pub subject: String,
    pub verb: String,
    pub object: String,
}

impl Parts {
    fn new(subject: impl Into<String>, verb: impl Into<String>, object: impl Into<String>) -> Self {
        Self {
            subject: no_arrows(&subject.into()),
            verb: verb.into(),
            object: no_arrows(&object.into()),
        }
    }
    /// 평문: "chrome.exe → 접속 www.google.com"
    pub fn text(&self) -> String {
        if self.object.is_empty() {
            format!("{} → {}", self.subject, self.verb)
        } else {
            format!("{} → {} {}", self.subject, self.verb, self.object)
        }
    }
}

pub fn render(scenes: &[Scene], voice: Voice) -> Vec<Sentence> {
    let mut out = Vec::new();
    for s in scenes {
        match voice {
            // 실행만 한 장면(부모 역할뿐)은 자식 문장이 "X → 실행 …"으로 이미 말하므로 생략
            Voice::OneLine
                if s.actions
                    .iter()
                    .all(|a| matches!(a.verb, Verb::Spawned | Verb::Resolved))
                    && !s.actions.is_empty() => {}
            Voice::OneLine => out.push(one_line(s)),
            Voice::Plain => out.extend(plain(s)),
            Voice::Expert => out.extend(expert(s)),
        }
    }
    out
}

// ---------- 공통 조각 ----------

fn actor_name(s: &Scene) -> String {
    s.actor.label.clone()
}

fn object_name(a: &Action, voice: Voice) -> String {
    match (a.object.kind.as_str(), voice) {
        // remote 라벨은 "도메인:포트" 또는 "ip:포트". Plain 은 포트를 뗀다.
        ("remote", Voice::Expert) => format!("{}{}", a.object.label, where_suffix(a, voice)),
        ("remote", _) => format!(
            "{}{}",
            a.object
                .label
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or(a.object.label.clone()),
            where_suffix(a, voice)
        ),
        _ => a.object.label.clone(),
    }
}

/// 접속 대상 표기(D032-1): 도메인 이름을 알면 도메인(쉬운 화법은 포트를 뗀다), 모르면 "주소:포트"(포트를 떼면 무엇에 접속했는지 사실이 줄어든다)
fn conn_object(a: &Action, voice: Voice) -> String {
    if voice == Voice::Expert || has_domain_name(a) {
        return object_name(a, voice);
    }
    format!("{}{}", a.object.label, where_suffix(a, voice))
}

/// 접속지의 "어디" 꼬리: "(미국 · Cloudflare, Inc.)", "(로컬망)". 나라는 IP 위치 정보(DB-IP) — D026 사용자 결정으로 "등록"·"추정"을 붙이지 않는다.
/// 한 문장 화법은 국가만. DB 가 없거나 모르는 주소는 붙이지 않는다
fn where_suffix(a: &Action, voice: Voice) -> String {
    let Some(ip) = a
        .object
        .attr("ip")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
    else {
        return String::new();
    };
    let Some(w) = geo::global().lookup_str(&ip) else {
        return String::new();
    };
    // D026(사용자 결정 2026-11-03): DB-IP Lite 국가는 위치 정보다 — "등록"을 붙이지 않는다("추정"도 쓰지 않는다)
    let reg = "";
    match (w.scope, &w.country, &w.org) {
        (geo::Scope::Public, Some(c), Some(o)) if voice != Voice::OneLine => {
            format!(" ({c}{reg} · {o})")
        }
        (geo::Scope::Public, Some(c), _) => format!(" ({c}{reg})"),
        (geo::Scope::Public, None, Some(o)) if voice != Voice::OneLine => format!(" ({o})"),
        (geo::Scope::Public, _, _) => String::new(),
        (s, _, _) => format!(" ({})", s.label_ko()),
    }
}

fn times(n: usize) -> String {
    if n <= 1 {
        String::new()
    } else {
        format!(" ({n}번)")
    }
}

/// FILETIME → "hh:mm:ss" (UTC). 화면 쪽에서 지역 시간으로 바꾼다.
pub fn hms(filetime: i64) -> String {
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000; // 1601→1970
    let secs = (filetime - EPOCH_DIFF) / 10_000_000;
    let s = secs.rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// 접속 대상이 도메인 이름을 가졌는가 (IP 만 있으면 용도 이름을 앞에 붙인다)
fn has_domain_name(a: &Action) -> bool {
    a.object.attr("domain").map_or(false, |d| !d.is_null())
}

fn verb_phrase(a: &Action, voice: Voice) -> Option<String> {
    let obj = object_name(a, voice);
    let via = a.via.as_ref().map(|v| v.label.clone());
    Some(match (a.verb, voice) {
        // D032-1: 포트 번호만으로 "웹 서버"·"DNS 서버"라고 부르지 않는다(내용을 보지 않으므로 확인한 사실이 아니다).
        // 도메인을 알면 도메인, 모르면 주소:포트 그대로
        (Verb::Connected, Voice::Expert) => format!("{obj} 에 접속{}", times(a.count)),
        (Verb::Connected, _) => format!(
            "{} 에 접속했습니다{}",
            conn_object(a, voice),
            times(a.count)
        ),
        // 귀속은 해석이다(이야기형 4판 7장 8번). D026·D028: "추정"·"~로 보임" 대신 무엇을 대조했는지(근거)를 쓴다
        (Verb::ConnectedVia, Voice::Expert) => format!(
            "{obj} 에 접속 (시스템 서비스 {} 경유 · {}){}",
            via.unwrap_or_else(|| "?".into()),
            via_basis_name(a),
            times(a.count)
        ),
        (Verb::ConnectedVia, _) => format!(
            "{obj} 에 접속했습니다 (시스템 서비스 {} 경유 · {}){}",
            via.unwrap_or_else(|| "?".into()),
            via_basis_name(a),
            times(a.count)
        ),
        (Verb::Resolved, Voice::Expert) => format!("{obj} 주소 조회{}", times(a.count)),
        (Verb::Resolved, Voice::Plain) => format!("{obj} 의 주소를 찾았습니다{}", times(a.count)),
        (Verb::Resolved, Voice::OneLine) => return None, // 한 문장 화법에서는 DNS 생략
        (Verb::Spawned, Voice::Expert) => format!("{obj} 실행{}", times(a.count)),
        (Verb::Spawned, _) => format!("{obj} 실행{}", times(a.count)),
        (Verb::Wrote, Voice::Expert) => format!("{obj} 파일 생성"),
        (Verb::Wrote, _) => format!("{obj} 파일을 만들었습니다"),
        (Verb::Downloaded, _) => format!("{obj} 받음"),
        (Verb::Registered, Voice::Expert) => format!("{obj} 자동 실행 등록"),
        (Verb::Registered, _) => format!("시작 프로그램에 {obj} 등록"),
        (Verb::Injected, Voice::Expert) => format!("{obj} 프로세스에 코드 주입"),
        // D003-3: 주입 판정은 메모리 검사 결과다. 행위("들어갔다")를 단정하지 않는다
        (Verb::Injected, _) => {
            format!("{obj} 메모리에 파일 근거 없는 실행 코드가 있습니다 (코드 주입 의심)")
        }
        (Verb::ExecutedAs, _) => return None, // 장면의 image 로 표현됨
        // 명령줄은 외부 문자열(자료). 사실만: "명령줄"
        (Verb::Ran, Voice::Expert) => format!("명령줄 {obj}"),
        (Verb::Ran, _) => format!("명령줄: {obj}"),
        // 17판 23-2 ②: 열었다는 사실만(읽은 내용은 모른다)
        (Verb::Opened, Voice::Expert) => format!("{obj} 파일 열기"),
        (Verb::Opened, _) => format!("{obj} 파일을 열었습니다"),
    })
}

/// 쉬운 화법의 구조형 문장(D003-2): (동작 한 단어, 대상). 조사를 쓰지 않는다. 대상은 외부 문자열일 수 있다
fn action_parts(a: &Action) -> Option<(String, String)> {
    let obj = object_name(a, Voice::Plain);
    let n = times(a.count);
    Some(match a.verb {
        // D032-1: 포트로 용도 이름을 붙이지 않는다 — 도메인이 있으면 도메인, 없으면 주소:포트
        Verb::Connected => (
            "접속".into(),
            format!("{}{n}", conn_object(a, Voice::Plain)),
        ),
        Verb::ConnectedVia => (
            format!("접속(경유 · {})", via_basis_name(a)),
            format!(
                "{obj} · 시스템 서비스 {} 경유{n}",
                a.via
                    .as_ref()
                    .map(|v| v.label.clone())
                    .unwrap_or_else(|| "알 수 없음".into())
            ),
        ),
        Verb::Resolved => ("주소 조회".into(), format!("{obj}{n}")),
        Verb::Spawned => ("실행".into(), format!("{obj}{n}")),
        Verb::Wrote => ("파일 만듦".into(), obj),
        Verb::Downloaded => ("받음".into(), obj),
        Verb::Registered => ("시작 프로그램 등록".into(), obj),
        Verb::Injected => (
            "코드 주입 의심".into(),
            format!("{obj} 메모리에 파일 근거 없는 실행 코드{n}"),
        ),
        Verb::ExecutedAs => return None,
        Verb::Ran => ("명령줄".into(), obj),
        Verb::Opened => ("파일 열기".into(), obj),
    })
}

fn all_evidence(s: &Scene) -> (Vec<i64>, Vec<i64>) {
    let mut ev = Vec::new();
    let mut ed = Vec::new();
    for a in &s.actions {
        ev.extend(&a.evidence);
        ed.extend(&a.edge_ids);
    }
    (ev, ed)
}

fn max_chapter(s: &Scene) -> Option<i64> {
    s.actions.iter().filter_map(|a| a.chapter).max()
}

// ---------- 화법 ----------

fn one_line(s: &Scene) -> Sentence {
    let name = actor_name(s);
    let (ev, ed) = all_evidence(s);
    let text = if s.is_proxy_only {
        format!("{name} → 다른 프로그램을 대신한 통신만 있음")
    } else {
        // 접속지 목록: 중복 제거 후 도메인 이름이 있는 것을 앞에 (사람에게는 IP 보다 이름이 먼저)
        let mut targets: Vec<String> = s
            .actions
            .iter()
            .filter(|a| matches!(a.verb, Verb::Connected | Verb::ConnectedVia))
            .map(|a| {
                // D032-1: IP 만 있는 대상은 주소:포트 그대로(포트로 용도 이름을 붙이지 않는다)
                conn_object(a, Voice::OneLine)
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        targets.sort_by_key(|t| !t.chars().any(|c| c.is_ascii_alphabetic()));
        // D003-2: 조사 없는 형식. "explorer.exe → 실행 chrome.exe → 접속 www.google.com 등 3곳"
        let origin = match (&s.parent, &s.image) {
            (Some(p), _) => format!("{} → 실행 ", no_arrows(&p.label)),
            _ => String::new(),
        };
        let name = no_arrows(&name);
        let targets: Vec<String> = targets.iter().map(|t| no_arrows(t)).collect();
        match targets.len() {
            0 => format!("{origin}{name} → 외부 접속 없음"),
            1 => format!("{origin}{name} → 접속 {}", targets[0]),
            n => format!("{origin}{name} → 접속 {} 등 {n}곳", targets[0]),
        }
    };
    Sentence {
        text,
        evidence: ev,
        edge_ids: ed,
        actor_id: s.actor.id,
        ts: s.first_ts,
        chapter: max_chapter(s),
        parts: None,
        already_open: false,
        sources: Vec::new(),
        via_lag_ms: None,
    }
}

fn plain(s: &Scene) -> Vec<Sentence> {
    let name = actor_name(s);
    let mut out = Vec::new();
    // 머리 문장: 누가 실행했나
    if let Some(p) = &s.parent {
        // 모든 문장은 근거에 잇는다: 부모 → 주인공 실행 선 (전에는 비어 있었다 — 원칙 위반이자 A30 범위 필터가 못 거르는 문장)
        let (ev, ed) = s
            .parent_edge
            .as_ref()
            .map(|(e, ev)| (ev.clone(), vec![*e]))
            .unwrap_or_default();
        let parts = Parts::new(p.label.clone(), "실행", name.clone());
        out.push(Sentence {
            text: parts.text(),
            evidence: ev,
            edge_ids: ed,
            actor_id: s.actor.id,
            ts: s.first_ts,
            chapter: None,
            parts: Some(parts),
            already_open: false,
            sources: Vec::new(),
            via_lag_ms: None,
        });
    }
    if s.is_proxy_only {
        out.push(Sentence {
            text: format!("{name} → 다른 프로그램을 대신한 통신만 있음"),
            evidence: all_evidence(s).0,
            edge_ids: all_evidence(s).1,
            actor_id: s.actor.id,
            ts: s.first_ts,
            chapter: None,
            parts: None,
            already_open: false,
            sources: Vec::new(),
            via_lag_ms: None,
        });
        return out;
    }
    for a in &s.actions {
        // 자식 실행은 자식 장면의 머리 문장("X → 실행 Y")이 이미 말한다
        if a.verb == Verb::Spawned {
            continue;
        }
        let Some((verb, object)) = action_parts(a) else {
            continue;
        };
        let parts = Parts::new(name.clone(), verb, object);
        out.push(Sentence {
            text: parts.text(),
            evidence: a.evidence.clone(),
            edge_ids: a.edge_ids.clone(),
            actor_id: s.actor.id,
            ts: a.first_ts,
            chapter: a.chapter,
            parts: Some(parts),
            already_open: false,
            sources: Vec::new(),
            via_lag_ms: via_lag(a),
        });
    }
    out
}

fn expert(s: &Scene) -> Vec<Sentence> {
    let name = actor_name(s);
    let pid = s.actor.key.split('@').next().unwrap_or("");
    let mut out = Vec::new();
    let head = match (&s.parent, &s.image) {
        (Some(p), Some(img)) => format!(
            "[{}] {name} (pid {pid}) 시작. 부모 {} , 이미지 {}",
            hms(s.first_ts),
            p.label,
            img.key
        ),
        (Some(p), None) => format!(
            "[{}] {name} (pid {pid}) 시작. 부모 {}",
            hms(s.first_ts),
            p.label
        ),
        _ => format!(
            "[{}] {name} (pid {pid}) — 수집 시작 전부터 실행 중",
            hms(s.first_ts)
        ),
    };
    out.push(Sentence {
        text: head,
        evidence: vec![],
        edge_ids: vec![],
        actor_id: s.actor.id,
        ts: s.first_ts,
        chapter: None,
        parts: None,
        already_open: false,
        sources: Vec::new(),
        via_lag_ms: None,
    });
    for a in &s.actions {
        let Some(vp) = verb_phrase(a, Voice::Expert) else {
            continue;
        };
        out.push(Sentence {
            text: format!("  [{}] {vp}", hms(a.first_ts)),
            evidence: a.evidence.clone(),
            edge_ids: a.edge_ids.clone(),
            actor_id: s.actor.id,
            ts: a.first_ts,
            chapter: a.chapter,
            parts: None,
            already_open: false,
            sources: Vec::new(),
            via_lag_ms: via_lag(a),
        });
    }
    if s.is_proxy_only {
        out.push(Sentence {
            text: "  (위 접속은 다른 프로세스를 대신한 것으로 귀속됨)".into(),
            evidence: vec![],
            edge_ids: vec![],
            actor_id: s.actor.id,
            ts: s.last_ts,
            chapter: None,
            parts: None,
            already_open: false,
            sources: Vec::new(),
            via_lag_ms: None,
        });
    }
    out
}

/// 의도 단정 금지어 + 페이로드를 본 것처럼 쓰는 말. 테스트가 모든 출력에서 검사한다.
/// 암호화된 내용은 보지 못하므로 "보냈다/유출/내용"류 표현은 쓰지 않는다 (접속·용량만 말한다).
pub const FORBIDDEN: &[&str] = &[
    "몰래",
    "훔치",
    "숨기",
    "악성",
    "해킹",
    "공격자",
    "유출",
    "빼돌",
    "개인정보",
    "내용을",
    // 10판 5-9: 파괴 징후도 사실만 — 무엇을 지웠는지는 쓰고 왜(의도·악성 이름)는 쓰지 않는다
    "랜섬",
    "암호화하려",
    // D043-5: 목적 표현도 쓰지 않는다
    "복구를 막으려",
    "막으려고",
    // 17판 23-2 ② 브라우저 금고 경비: 파일을 열었다는 사실만 — 무엇을 가져갔는지는 모른다
    "훔쳤",
    "탈취",
];

#[cfg(test)]
mod arrow_tests {
    use super::*;

    #[test]
    fn external_arrows_cannot_fake_sentence_structure() {
        let p = Parts::new("evil → 실행 explorer.exe", "접속", "a⇒b.example");
        assert_eq!(p.text(), "evil -> 실행 explorer.exe → 접속 a->b.example");
        assert_eq!(p.text().matches('→').count(), 1, "구분자는 하나뿐");
    }
}
