//! 변경 승인 (18차 설계, A23).
//!
//! 배경: Microsoft 는 WebView2 호스트를 승격(High IL)으로 돌리지 말고, 관리자 작업은 따로 떼어 낸 프로세스에서 하라고 권한다
//! (WebView2 보안 문서). A22 의 "UI 를 통째로 관리자 권한으로 다시 열기"는 그 권고와 반대였다. 그래서:
//!
//! 1. 보기 모드(일반 권한) UI 가 변경을 **맡긴다**: `change.stage{method, params}` — 누구나(서명된 클라이언트) 가능, 실행은 안 됨.
//!    맡길 때 안쪽 메서드의 검증(needs_ack 포함)을 미리 돌려, 사용자가 확인할 것은 UI 에서 먼저 묻는다.
//! 2. UI 가 승인 도우미(같은 서명 실행 파일의 `--approve <id>`, 웹뷰 없음)를 UAC 로 띄운다.
//! 3. 도우미(관리자)가 `change.get` 으로 **서비스가 만든 요약**을 받아 OS 기본 대화상자로 보여 준다. 요약은 UI 가 보낸 글이 아니라
//!    서비스가 지금 그래프·엔진으로 다시 계산한 것이다 → 같은 세션의 악성코드가 UI 를 조작해 다른 변경을 맡겨도, 사용자가 보는 것은
//!    실제로 실행될 내용이다.
//! 4. 사용자가 적용을 누르면 `change.commit{change_id, digest}`. 서비스가 요약을 다시 계산해 digest 가 다르면(그사이 자손이 생김,
//!    뿌리 파일이 바뀜 등) 거부하고 도우미는 새 요약을 다시 보여 준다(보지 않은 내용은 실행하지 않는다).
//! 5. 실행 결과는 `change.result` 로 UI 가 읽는다(누구나). 정책 확인(60초)은 도우미가 실행 직후 스스로 묻는다.
//!
//! 한도: 대기 8건, 5분. 넘치면 가장 오래된 것부터 버린다(맡기기 폭주로 메모리를 늘리지 못하게).

use std::collections::VecDeque;

use api::{ErrorCode, Method, RpcError};
use sha2::{Digest, Sha256};

/// 맡긴 변경의 수명 (초)
pub const CHANGE_TTL_SECS: i64 = 300;
/// 동시에 대기할 수 있는 맡긴 변경 수
pub const CHANGE_MAX: usize = 8;
/// 요약 한 줄 / 줄 수 상한 (대화상자에 넣는다)
pub const LINE_MAX: usize = 200;
pub const LINES_MAX: usize = 60;

#[derive(Debug, Clone)]
pub enum ChangeState {
    Pending,
    Done {
        result: serde_json::Value,
        committed_by: String,
    },
    Failed {
        error: String,
    },
}

#[derive(Debug, Clone)]
pub struct Staged {
    pub id: String,
    pub method: Method,
    pub params: serde_json::Value,
    pub staged_by: String,
    pub staged_at: i64,
    /// 승인 도우미(관리자)가 처음 요약을 연 시각 (22차 S2): UAC 통과에 시간이 걸려도 연 뒤 5분은 읽을 시간을 준다.
    /// 처음 한 번만 정해진다(다시 열어도 늘지 않음) → 최대 수명 = 맡긴 뒤 5분 안에 열고 + 연 뒤 5분
    pub opened_at: Option<i64>,
    pub state: ChangeState,
}

impl Staged {
    fn alive(&self, now: i64) -> bool {
        now - self.staged_at <= CHANGE_TTL_SECS
            || self.opened_at.is_some_and(|o| now - o <= CHANGE_TTL_SECS)
    }
    /// 도우미가 요약을 열었다 (첫 번째만)
    pub fn mark_opened(&mut self, now: i64) {
        self.opened_at.get_or_insert(now);
    }
}

#[derive(Default)]
pub struct ChangeBook {
    items: VecDeque<Staged>,
}

impl ChangeBook {
    /// 맡긴다. 반환: change_id
    pub fn stage(
        &mut self,
        method: Method,
        params: serde_json::Value,
        staged_by: String,
        now: i64,
    ) -> String {
        self.expire(now);
        while self.items.len() >= CHANGE_MAX {
            self.items.pop_front();
        }
        let id = new_uuid();
        self.items.push_back(Staged {
            id: id.clone(),
            method,
            params,
            staged_by,
            staged_at: now,
            opened_at: None,
            state: ChangeState::Pending,
        });
        id
    }
    pub fn get(&mut self, id: &str, now: i64) -> Option<&mut Staged> {
        self.expire(now);
        self.items.iter_mut().find(|s| s.id == id)
    }
    fn expire(&mut self, now: i64) {
        self.items.retain(|s| s.alive(now));
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// 맡긴 변경의 id. 추측할 수 없게 OS 난수(getrandom: BCryptGenRandom / getrandom(2)) 로 만든다.
/// 비밀은 아니다(실행에는 관리자 + 사용자 승인이 필요) — 다른 사람이 맡긴 변경을 골라 결과를 엿보지 못하게 할 뿐.
pub fn new_uuid() -> String {
    let mut b = [0u8; 16];
    if getrandom::getrandom(&mut b).is_err() {
        // 난수 원천이 없으면 시각·주소로라도 (실패는 사실상 없음)
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        b = (t ^ (&b as *const _ as usize as u128)).to_le_bytes();
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// 대화상자에 넣을 줄의 문자 정리: 제어·양방향·폭0 문자 제거. 경로·도메인은 외부 문자열이다.
pub fn clean_chars(s: &str) -> String {
    s.chars().filter(|c| !c.is_control() && !matches!(*c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF)).collect()
}

/// 표시용으로 줄을 줄인다. **꼬리를 살린다**(18차 답변 Q1-a): 경로·접속지는 끝(파일 이름, IP:포트, "(주입당한 프로그램)")이
/// 핵심이라, 앞만 남기면 긴 가짜 폴더 이름으로 진짜 파일 이름을 말줄임 너머로 밀어낼 수 있다. 앞 60자 + … + 뒤.
pub fn clean_line(s: &str) -> String {
    let t = clean_chars(s);
    let n = t.chars().count();
    if n <= LINE_MAX {
        return t;
    }
    let head: String = t.chars().take(60).collect();
    let tail: String = t.chars().skip(n - (LINE_MAX - 61)).collect();
    format!("{head}…{tail}")
}

/// 요약 줄 목록 → (표시 줄, digest).
/// digest 는 **표시 줄이 아니라 전체 내용**(정리만 한 원래 줄 전부 + 맡긴 params)에서 만든다. 표시 줄로만 만들면
/// 말줄임·줄 수 상한 때문에 "보이는 것은 같고 실행 내용은 다른" 두 계획이 같은 digest 를 가질 수 있다(A24, 18차 Q1-b 검토 중 발견).
pub fn finish(
    method: Method,
    raw: Vec<String>,
    params: &serde_json::Value,
) -> (Vec<String>, String) {
    let mut h = Sha256::new();
    h.update(method.name().as_bytes());
    for l in &raw {
        h.update(b"\n");
        h.update(clean_chars(l).as_bytes());
    }
    h.update(b"\n--params--\n");
    // serde_json 의 Map 은 키 정렬(BTreeMap) — 같은 값이면 같은 문자열
    h.update(serde_json::to_string(params).unwrap_or_default().as_bytes());
    let digest = h.finalize().iter().map(|x| format!("{x:02x}")).collect();
    let mut lines: Vec<String> = raw.iter().map(|l| clean_line(l)).collect();
    if lines.len() > LINES_MAX {
        let more = lines.len() - (LINES_MAX - 1);
        lines.truncate(LINES_MAX - 1);
        lines.push(format!("… 그 밖에 {more}줄 (전체는 화면의 미리보기)"));
    }
    (lines, digest)
}

/// 묶음 하나: 머리줄(개수) + 항목 최대 `SECTION_MAX`개 + "외 N개". 한 묶음을 부풀려 다른 묶음(끝낼 프로세스·접속지)을
/// 화면 밖으로 밀어내지 못하게 묶음마다 상한을 둔다(마인드맵 쪽별 할당과 같은 생각).
pub const SECTION_MAX: usize = 8;
pub fn section(out: &mut Vec<String>, head: String, items: Vec<String>) {
    section_n(out, head, items, SECTION_MAX);
}
pub fn section_n(out: &mut Vec<String>, head: String, items: Vec<String>, max: usize) {
    out.push(head);
    let n = items.len();
    for it in items.into_iter().take(max) {
        out.push(format!("  {it}"));
    }
    if n > max {
        out.push(format!("  … 외 {}개 (전체는 화면의 미리보기)", n - max));
    }
}
/// 정책 원문 표시 줄 수 (맨 끝 묶음)
pub const YAML_LINES_MAX: usize = 30;

pub fn not_found(id: &str) -> RpcError {
    RpcError::with(
        ErrorCode::InvalidParams,
        format!("맡긴 변경 없음(만료 5분 또는 없음): {id}"),
    )
}

pub fn changed() -> RpcError {
    RpcError::with(
        ErrorCode::VersionMismatch,
        "승인 창에 보인 뒤 내용이 바뀌었습니다 — 새 요약을 다시 확인하세요",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_shape_and_uniqueness() {
        let a = new_uuid();
        let b = new_uuid();
        assert_ne!(a, b);
        assert!(api::methods::is_uuid(&a), "{a}");
        assert_eq!(&a[14..15], "4");
    }

    #[test]
    fn book_caps_and_expires() {
        let mut bk = ChangeBook::default();
        let first = bk.stage(Method::PolicyPause, serde_json::json!({}), "x".into(), 0);
        for _ in 0..CHANGE_MAX {
            bk.stage(Method::PolicyPause, serde_json::json!({}), "x".into(), 1);
        }
        assert_eq!(bk.len(), CHANGE_MAX);
        assert!(
            bk.get(&first, 1).is_none(),
            "넘치면 가장 오래된 것부터 버림"
        );
        let id = bk.stage(Method::PolicyPause, serde_json::json!({}), "x".into(), 10);
        assert!(bk.get(&id, 10 + CHANGE_TTL_SECS).is_some());
        assert!(bk.get(&id, 11 + CHANGE_TTL_SECS).is_none(), "5분 뒤 만료");
        // 22차 S2: UAC 가 늦어도 도우미가 연 뒤 5분은 남는다. 다시 열어도 늘지 않는다
        let id = bk.stage(Method::PolicyPause, serde_json::json!({}), "x".into(), 1000);
        bk.get(&id, 1000 + 290).unwrap().mark_opened(1000 + 290);
        assert!(
            bk.get(&id, 1000 + 290 + CHANGE_TTL_SECS).is_some(),
            "연 뒤 5분"
        );
        bk.get(&id, 1000 + 500).unwrap().mark_opened(1000 + 500);
        assert!(
            bk.get(&id, 1000 + 291 + CHANGE_TTL_SECS).is_none(),
            "다시 열어도 늘지 않음"
        );
        // 5분 안에 열지 않으면 만료(맡긴 쪽만으로는 늘릴 수 없다)
        let id = bk.stage(Method::PolicyPause, serde_json::json!({}), "x".into(), 5000);
        assert!(bk.get(&id, 5001 + CHANGE_TTL_SECS).is_none());
    }

    #[test]
    fn lines_are_cleaned_tail_kept_and_digest_covers_full_content() {
        let p = serde_json::json!({"a": 1});
        // 양방향 문자로 "exe.txt" 처럼 보이게 하는 위장, 줄바꿈으로 가짜 줄 만들기
        let (l, d1) = finish(
            Method::CutApply,
            vec![
                "막을 프로그램: C:\\u\\evil\u{202E}txt.exe".into(),
                "a\nb".into(),
            ],
            &p,
        );
        assert_eq!(l[0], "막을 프로그램: C:\\u\\eviltxt.exe");
        assert_eq!(l[1], "ab");
        let (_, d2) = finish(
            Method::CutApply,
            vec!["막을 프로그램: C:\\u\\eviltxt.exe".into(), "ab".into()],
            &p,
        );
        assert_eq!(d1, d2, "정리 결과가 같으면 같은 digest");
        let (_, d3) = finish(
            Method::PolicyApply,
            vec!["막을 프로그램: C:\\u\\eviltxt.exe".into(), "ab".into()],
            &p,
        );
        assert_ne!(d1, d3, "메서드도 digest 에 든다");
        let (_, d4) = finish(
            Method::CutApply,
            vec!["막을 프로그램: C:\\u\\eviltxt.exe".into(), "ab".into()],
            &serde_json::json!({"a": 2}),
        );
        assert_ne!(d1, d4, "params 도 digest 에 든다");
        // 긴 가짜 폴더로 파일 이름 밀어내기 → 꼬리는 남는다
        let long = format!("  C:\\Users\\a\\{}\\evil.exe", "svchost_".repeat(60));
        let shown = clean_line(&long);
        assert_eq!(shown.chars().count(), LINE_MAX);
        assert!(shown.ends_with("\\evil.exe"), "{shown}");
        // 보이는 줄은 같고(가운데가 잘림) 실제 경로만 다른 두 계획 → digest 달라야 한다
        let a = format!("C:\\x\\{}A{}\\evil.exe", "p".repeat(150), "q".repeat(150));
        let b = format!("C:\\x\\{}B{}\\evil.exe", "p".repeat(150), "q".repeat(150));
        let (la, da) = finish(Method::CutApply, vec![a], &p);
        let (lb, db) = finish(Method::CutApply, vec![b], &p);
        assert_eq!(la, lb, "표시는 같다");
        assert_ne!(da, db, "digest 는 전체 내용 기준 (A24)");
        // 줄 수 상한
        let many: Vec<String> = (0..100).map(|i| format!("줄 {i}")).collect();
        let (l, _) = finish(Method::CutApply, many, &p);
        assert_eq!(l.len(), LINES_MAX);
        assert!(l.last().unwrap().contains("41줄"));
    }

    #[test]
    fn sections_are_capped_so_later_sections_stay_visible() {
        let mut out = Vec::new();
        section(
            &mut out,
            "막을 프로그램 100개:".into(),
            (0..100).map(|i| format!("C:\\t\\{i}.exe")).collect(),
        );
        section(
            &mut out,
            "24시간 막을 접속지 1개:".into(),
            vec!["203.0.113.9:8443/tcp".into()],
        );
        assert_eq!(out.len(), 1 + SECTION_MAX + 1 + 2);
        assert!(out.iter().any(|l| l.contains("외 92개")));
        assert!(
            out.iter().any(|l| l.contains("203.0.113.9:8443/tcp")),
            "뒤 묶음이 밀려나지 않는다"
        );
    }
}
