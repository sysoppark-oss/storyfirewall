//! 사건(judge 결과) → 문장. 8차·9차 검증 반영, 이야기형 4판 5-2·5-3장.
//!
//! - 사건마다 제목 한 줄(어디까지 진행됐는가) + 근거 항목마다 문장 하나. 모든 문장은 근거 선 id·원시 이벤트 id 를 가진다.
//! - 점수·가중치는 사실을 설명하는 말로만 옮긴다. 의도 단정 금지어(render::FORBIDDEN)는 쓰지 않는다.
//! - 등급 말: 평범 / 주의 / 의심. "악성"은 쓰지 않는다 (판정은 추정이다).

use graph::store::Store;
use judge::{Chapter, Level, Reason, Story};
use serde::Serialize;

use crate::render::{hms, Sentence, Voice};
use crate::Result;

#[derive(Debug, Clone, Serialize)]
pub struct Narrative {
    pub root: i64,
    pub level: Level,
    pub score: u8,
    pub chapter: Chapter,
    pub title: String,
    pub sentences: Vec<Sentence>,
    /// 항목형(D002): 카드 제목에 프로그램 이름이 있으므로 본문은 "출신: 확인되지 않음"처럼. 문장과 같은 근거를 가진다
    pub items: Vec<Item>,
    /// 도달한 장(1~4) — 화면의 4칸 진행 표시
    pub reached: Vec<u8>,
    /// 사건의 마지막 활동 시각(FILETIME, 장이 있는 선 중 가장 늦은 것을 **관측한** 시각). 카드 시각은 이것을 쓴다.
    /// 수집 시작 전부터 실행 중이던 프로세스(스냅샷 출신)의 실행 선은 생성 시각이 아니라 처음 관측한 시각(수집 시작)으로 센다 —
    /// 수개월 절전·재개만 한 노트북에서 4월에 시작한 서비스가 "4월 14일" 카드가 되던 문제(L021·L024)
    pub last_ts: i64,
    /// 수집 시작 전부터 실행 중이던 프로세스가 사건에 있으면 그 가장 이른 시작 시각(FILETIME). 화면: "수집 시작 전부터 실행 중(시작 …)"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running_since: Option<i64>,
    /// 25차 Q1: 수집 전부터 실행 중인 프로세스가 "기록 없는 구간"(서비스 중지·절전) 안에서 시작됐으면 그 구간 (from, to FILETIME).
    /// 서비스를 멈추고 띄운 뒤 다시 켜는 순서를 숨기지 않는다 — 이 사건은 접힌 묶음으로 내리지 않는다(fresh = true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_in_gap: Option<(i64, i64)>,
    /// D022-4: 가장 늦은 외부 접속지(원격 노드 이름 "host:port")와 그 노드 id — 화면의 발생 시각 목록·접속 항목
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_node: Option<i64>,
    /// 10판 5-9 (1)·D043: 5장 파괴 징후(가장 이른 것). 화면은 4칸 막대 아래 한 줄 + 복구 수단 항목 밑 명령줄(고정폭)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroy: Option<Destroy>,
    /// 오늘(관측 뒤) 새 활동이 있는가(D004-2). 수집 전부터 실행 중이고 관측 1분 뒤 새 선이 없으면 false — 화면은 접힌 묶음으로
    pub fresh: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Destroy {
    /// 종류(사람 말): "그림자 복사본 삭제" 등
    pub kind: &'static str,
    /// 사실 문장: "그림자 복사본을 지우는 명령을 실행했습니다"
    pub sentence: &'static str,
    /// 명령줄 원문(외부 문자열 — 화면은 텍스트 노드로만)
    pub cmdline: String,
    pub ts: i64,
    pub edge_id: i64,
}

/// T1490 종류 → 사실 문장(의도 없음)
pub fn destroy_sentence(kind: &str) -> &'static str {
    match kind {
        "그림자 복사본 삭제" => "그림자 복사본(복원 지점)을 지우는 명령을 실행했습니다",
        "그림자 복사본 저장 공간 변경" => {
            "그림자 복사본 저장 공간을 바꾸는 명령을 실행했습니다"
        }
        "백업 기록 삭제" => "Windows 백업 기록을 지우는 명령을 실행했습니다",
        "자동 복구 끄기" => "부팅 자동 복구를 끄는 명령을 실행했습니다",
        "부팅 실패 무시 설정" => "부팅 실패를 무시하도록 바꾸는 명령을 실행했습니다",
        "복구 환경 끄기" => "Windows 복구 환경을 끄는 명령을 실행했습니다",
        _ => "Windows 복구 수단을 바꾸는 명령을 실행했습니다",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub label: &'static str,
    pub value: String,
    pub edge_ids: Vec<i64>,
    /// 근거 출처별 수(B1)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<(String, u32)>,
}

/// 가중치 항목 → (항목 이름, 짧은 값). 문장(reason_text)과 같은 사실, 조사·주어 없이
fn reason_item(what: &str) -> Option<(&'static str, &'static str)> {
    Some(match what {
        "장 기본점" => return None,
        "서명 없음" => ("서명", "없음"),
        "서명 깨짐·신뢰할 수 없음" => ("서명", "파일 내용과 맞지 않거나 불신 인증서"),
        "신뢰 체인 없는 서명" => ("서명", "있지만 신뢰하는 인증 기관이 아님(자체 서명 등)"),
        "실행 파일이 아닌 뿌리(문서·스크립트·컨테이너)" => {
            ("시작", "문서·스크립트·디스크 이미지에서 시작")
        }
        "인터넷에서 받은 파일(Zone 3·4)" => ("출신", "인터넷에서 받은 파일"),
        "사용자 쓰기 가능 경로에서 실행" => {
            ("위치", "누구나 쓸 수 있는 폴더(임시·다운로드 등)에서 실행")
        }
        "자손에 LOLBin(스크립트·시스템 도구)" => {
            ("실행", "스크립트 해석기·시스템 도구를 불러 씀")
        }
        "자리잡기 대상이 서명 없는 파일" => ("자동 실행", "등록된 파일에 서명 없음"),
        "관리자만 쓰는 설치 위치의 서명 없는 프로그램" => {
            ("위치", "관리자만 쓸 수 있는 설치 폴더(Program Files)")
        }
        "이 프로그램이 처음 접속한 곳" => {
            ("접속", "이 프로그램이 평소 접속하지 않던 곳")
        }
        "이 PC 에서 처음 보는 곳" => ("접속", "이 PC 에서 처음 보는 곳"),
        "도메인 없이 IP 로 직접 접속" => ("접속", "도메인 없이 IP 로 바로 접속"),
        "평소 없던 포트" => ("접속", "평소 쓰지 않던 포트"),
        "고립 svchost(귀속 없는 접속, 알려진 Microsoft 서비스 없음)" => (
            "접속",
            "서비스 호스트가 요청한 프로그램 없이 외부 접속(알려진 Windows 서비스 없음)",
        ),
        "문서 처리기가 LOLBin 을 실행" => {
            ("실행", "문서 프로그램이 스크립트·시스템 도구를 실행")
        }
        "Microsoft 서명(카탈로그)" => ("서명", "Windows 에 포함된 서명된 프로그램"),
        "신뢰하는 서명(Microsoft 아님)" => {
            ("서명", "있음 · 신뢰하는 인증 기관이 확인한 서명")
        }
        "서명 확인 결과 없음" => ("서명", "아직 확인하지 못함"),
        // D035-4: WindowsApps 에는 스토어 밖(사이드로드) 패키지도 들어간다 — 확인한 사실(설치 폴더)만 쓴다
        "스토어 패키지" => (
            "출신",
            "Windows 앱 패키지 폴더(WindowsApps)에 설치됨 · 파일 서명 대신 패키지 서명",
        ),
        "평소 접속하던 곳" => ("접속", "평소에도 접속하던 곳"),
        // 실제 명령을 알면 아래 D023-2 블록이 "종류 — 명령"으로 바꾼다
        "복구 수단을 지우는 명령(T1490)" => {
            ("복구 수단", "Windows 복구 수단을 지우거나 끄는 명령 실행")
        }
        "사용자가 정상으로 확인한 프로그램" => ("확인", "사용자가 정상으로 확인함"),
        // 17판 23-2 ②: 열었다·실행했다·접속했다는 사실만. 읽은 값·의도는 말하지 않는다(실제 파일을 알면 vault_detail 이 바꾼다)
        "브라우저가 아닌 프로그램이 브라우저 저장소를 엶" => (
            "브라우저 저장소",
            "브라우저가 아닌 프로그램이 저장된 로그인 정보·쿠키 파일을 엶",
        ),
        "미끼 파일 접근" => ("미끼 파일", "Story Firewall 이 둔 미끼 파일을 엶"),
        "디버깅 모드로 브라우저 실행" => (
            "브라우저 디버깅",
            "원격 디버깅 기능을 켠 채 브라우저를 실행",
        ),
        "브라우저 디버깅 포트 접속" => (
            "브라우저 디버깅",
            "이 PC 안의 브라우저 원격 디버깅 포트에 접속",
        ),
        "브라우저가 아닌 프로그램이 브라우저 권한 상승 서비스를 실행" => {
            (
                "권한 상승 서비스",
                "브라우저가 아닌 프로그램이 브라우저 권한 상승 서비스를 실행",
            )
        }
        "브라우저 종료 직후 권한 상승 서비스 시작" => (
            "권한 상승 서비스",
            "브라우저가 끝난 지 10초 안에 브라우저 권한 상승 서비스가 시작됨",
        ),
        _ => return None,
    })
}

/// 17판 23-2 ②: 금고 신호의 근거 선에서 실제 대상(어느 브라우저의 어떤 파일, 어떤 스위치, 어느 포트)을 꺼내 (문장, 항목 값)을 만든다.
/// 근거 선을 못 찾거나 모양이 다르면 None — 일반 문구(reason_text·reason_item)를 쓴다
fn vault_detail(store: &Store, r: &Reason) -> Option<(String, String)> {
    let e = graph::query::edge_by_id(store, r.edge_id?).ok()?;
    let src = store.node(e.src).ok()?;
    let dst = store.node(e.dst).ok()?;
    let actor = crate::render::no_arrows(&src.label);
    Some(match r.what {
        "브라우저가 아닌 프로그램이 브라우저 저장소를 엶" => {
            let vf = graph::vault::classify(&dst.key)?;
            let b = vf.browser.name();
            let what = vf.what.label();
            let fname = crate::render::no_arrows(&dst.label);
            (
                format!(
                    "{actor}: 브라우저가 아닌 프로그램이 {b} 의 {what} 파일({fname})을 열었습니다."
                ),
                format!("{b} · {what}({fname}) · 연 프로그램 {actor}"),
            )
        }
        "미끼 파일 접근" => {
            let fname = crate::render::no_arrows(&dst.label);
            (
                format!("{actor}: Story Firewall 이 둔 미끼 파일({fname})을 열었습니다. 미끼 파일은 실제 프로그램이 쓰지 않는 파일입니다."),
                format!("{fname} · 연 프로그램 {actor}"),
            )
        }
        "디버깅 모드로 브라우저 실행" => {
            // 근거 선 = 브라우저 → 명령(ran). 명령은 수집기가 디버깅 스위치만 남긴 것
            let flags = graph::vault::debug_flags_only(&dst.key)?;
            let parent: Option<String> = store
                .conn()
                .query_row(
                    "SELECT n.label FROM edges x JOIN nodes n ON n.id = x.src WHERE x.dst = ?1 AND x.rel = 'spawned' ORDER BY x.ts DESC LIMIT 1",
                    [e.src],
                    |row| row.get(0),
                )
                .ok();
            let parent = crate::render::no_arrows(&parent?);
            (
                format!("{parent} → 실행 {actor}: 원격 디버깅 기능을 켠 채 브라우저를 실행했습니다({flags})."),
                format!("{parent} → 실행 {actor} · {flags}"),
            )
        }
        "브라우저 디버깅 포트 접속" => {
            let port = dst.attr("port").and_then(|p| p.as_u64())?;
            (
                format!("{actor}: 브라우저가 아닌 프로그램이 이 PC 안의 브라우저 원격 디버깅 포트({port})에 접속했습니다."),
                format!("{actor} → 이 PC 안 포트 {port}"),
            )
        }
        _ => return None,
    })
}

pub fn chapter_name(c: Chapter) -> &'static str {
    match c {
        Chapter::Ingress => "1장 유입",
        Chapter::Execute => "2장 실행",
        Chapter::Persist => "3장 자리잡기",
        Chapter::Egress => "4장 외부 접속",
        Chapter::Destroy => "5장 파괴 행위",
    }
}
pub fn level_name(l: Level) -> &'static str {
    match l {
        Level::Normal => "낮음",
        Level::Watch => "중간",
        Level::Suspicious => "높음",
        Level::Critical => "심각",
    }
}

/// 가중치 항목 → 사실 문장. 점수는 말하지 않는다(Expert 화법만 괄호로 덧붙임).
fn reason_text(r: &Reason, root: &str, voice: Voice) -> Option<String> {
    let t = match r.what {
        "장 기본점" => return None,
        "서명 없음" => format!("{root} 에는 코드 서명이 없습니다."),
        // 사실만: 내용 불일치는 "서명 뒤 바뀜"이 관찰 사실, 신뢰 체인 없음은 바뀐 것이 아니다(L015)
        "서명 깨짐·신뢰할 수 없음" => format!("{root} 의 서명이 파일 내용과 맞지 않거나, 이 PC 가 불신하도록 지정된 인증서입니다."),
        "신뢰 체인 없는 서명" => format!("{root}: 서명돼 있지만, 이 PC 가 신뢰하는 인증 기관의 서명이 아닙니다(자체 서명 등)."),
        "실행 파일이 아닌 뿌리(문서·스크립트·컨테이너)" => format!("{root}: 문서·스크립트·디스크 이미지 같은 파일이며, 여기서 실행이 시작됐습니다."),
        "인터넷에서 받은 파일(Zone 3·4)" => format!("{root}: 인터넷에서 받은 파일로 표시되어 있습니다."),
        "사용자 쓰기 가능 경로에서 실행" => format!("{root}: 임시·다운로드 폴더처럼 누구나 쓸 수 있는 위치에서 실행됐습니다."),
        "자손에 LOLBin(스크립트·시스템 도구)" => "실행 과정에서 스크립트 해석기나 시스템 도구(PowerShell, rundll32 등)를 불러 썼습니다.".to_string(),
        "자리잡기 대상이 서명 없는 파일" => "자동 실행에 등록된 파일에 서명이 없습니다.".to_string(),
        "관리자만 쓰는 설치 위치의 서명 없는 프로그램" => format!("{root}: 서명은 없지만 관리자만 쓸 수 있는 설치 폴더(Program Files)에 있고, 인터넷에서 받은 표시도 없습니다."),
        "이 프로그램이 처음 접속한 곳" => "이 프로그램이 평소에 접속하지 않던 곳에 접속했습니다.".to_string(),
        "이 PC 에서 처음 보는 곳" => "이 PC 에서 처음 보는 곳에 접속했습니다.".to_string(),
        "도메인 없이 IP 로 직접 접속" => "도메인 이름 없이 IP 주소로 바로 접속했습니다.".to_string(),
        "평소 없던 포트" => "평소 쓰지 않던 포트로 접속했습니다.".to_string(),
        "고립 svchost(귀속 없는 접속, 알려진 Microsoft 서비스 없음)" => "시스템 서비스 호스트(svchost)가 어떤 프로그램의 요청과도 연결되지 않은 채 외부에 접속했고, 그 호스트에 알려진 Windows 서비스가 없습니다.".to_string(),
        "문서 처리기가 LOLBin 을 실행" => "문서를 다루는 프로그램(오피스·브라우저·PDF 리더)이 스크립트 해석기나 시스템 도구를 실행했습니다.".to_string(),
        "Microsoft 서명(카탈로그)" => "Windows 에 포함된 서명된 프로그램입니다.".to_string(),
        "신뢰하는 서명(Microsoft 아님)" => "신뢰하는 인증 기관이 확인한 서명이 있습니다.".to_string(),
        "서명 확인 결과 없음" => "서명을 아직 확인하지 못했습니다.".to_string(),
        "스토어 패키지" => "Windows 앱 패키지 폴더(WindowsApps)에 설치된 프로그램입니다.".to_string(),
        "평소 접속하던 곳" => "평소에도 접속하던 곳입니다.".to_string(),
        // 사실만(10판 5-9): 무엇을 지우는 명령인지. "랜섬웨어"·"암호화하려" 같은 의도는 말하지 않는다
        "복구 수단을 지우는 명령(T1490)" => "Windows 복구 수단(그림자 복사본·백업·복구 환경)을 지우거나 끄는 명령을 실행했습니다.".to_string(),
        "사용자가 정상으로 확인한 프로그램" => "사용자가 정상으로 확인한 프로그램입니다.".to_string(),
        // 17판 23-2 ②: 사실만(열었다·실행했다·접속했다). 무엇을 읽었는지·왜 했는지는 말하지 않는다
        "브라우저가 아닌 프로그램이 브라우저 저장소를 엶" => "브라우저가 아닌 프로그램이 브라우저의 저장된 로그인 정보·쿠키 파일을 열었습니다.".to_string(),
        "미끼 파일 접근" => "Story Firewall 이 둔 미끼 파일을 열었습니다. 미끼 파일은 실제 프로그램이 쓰지 않는 파일입니다.".to_string(),
        "디버깅 모드로 브라우저 실행" => "원격 디버깅 기능을 켠 채 브라우저를 실행했습니다(다른 프로그램이 브라우저를 조종할 수 있는 상태).".to_string(),
        "브라우저 디버깅 포트 접속" => "브라우저가 아닌 프로그램이 이 PC 안의 브라우저 원격 디버깅 포트에 접속했습니다.".to_string(),
        "브라우저가 아닌 프로그램이 브라우저 권한 상승 서비스를 실행" => "브라우저가 아닌 프로그램이 브라우저의 권한 상승 서비스(elevation_service.exe)를 실행했습니다.".to_string(),
        "브라우저 종료 직후 권한 상승 서비스 시작" => "브라우저가 끝난 지 10초 안에 브라우저의 권한 상승 서비스(elevation_service.exe)가 시작됐습니다.".to_string(),
        other => other.to_string(),
    };
    Some(match voice {
        Voice::Expert => format!("{t} ({:+})", r.points),
        _ => t,
    })
}

/// 수집 시작 관측 뒤 이만큼 지나서 생긴 선이 있으면 "오늘 새 활동"(100ns 단위, 60초). 시작 직후 연결 테이블 첫 폴링 등은 새 활동이 아니다
const NEW_ACTIVITY_AFTER: i64 = 60 * 10_000_000;

/// 스냅샷 시각과 생성 시각 차이가 이 안이면 수집 시작 무렵 시작으로 본다(100ns 단위, 10초)
const SNAPSHOT_FRESH: i64 = 10 * 10_000_000;

/// 뿌리가 Windows 폴더의 파일(또는 그 파일로 실행된 프로세스)인가 — 시스템 핵심 프로세스에는 "다시 시작" 권고를 내지 않는다
fn is_windows_file(store: &Store, id: i64) -> bool {
    let Ok(n) = store.node(id) else { return false };
    let path = if n.kind == "process" {
        n.attrs_json
            .as_deref()
            .and_then(|a| serde_json::from_str::<serde_json::Value>(a).ok())
            .and_then(|v| {
                v.get("image")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default()
    } else {
        n.key
    };
    path.replace('/', "\\")
        .to_ascii_lowercase()
        .starts_with("c:\\windows\\")
}

/// judge 결과를 문장으로. OneLine 은 제목만.
pub fn narrate(store: &Store, stories: &[Story], voice: Voice) -> Result<Vec<Narrative>> {
    let mut out = Vec::new();
    for s in stories {
        let root = &s.root_label;
        let title = match voice {
            Voice::Expert => format!(
                "[{}] {} — {}까지 진행 (점수 {}, 근거 {}건)",
                level_name(s.level),
                root,
                chapter_name(s.chapter),
                s.score,
                s.edges.len()
            ),
            _ => format!(
                "[{}] {} — {}까지 진행",
                level_name(s.level),
                root,
                chapter_name(s.chapter)
            ),
        };
        let mut sentences = Vec::new();
        let mut items: Vec<Item> = Vec::new();
        let mut reached_out: Vec<u8> = Vec::new();
        let mut last_ts: i64 = 0;
        let mut running_since: Option<i64> = None;
        let mut first_obs: Option<i64> = None;
        let mut fresh = true;
        let mut started_in_gap: Option<(i64, i64)> = None;
        let mut egress: Option<(String, i64, i64)> = None; // (이름, 노드 id, 선 id)
        let mut destroy: Option<Destroy> = None;
        if voice != Voice::OneLine {
            // 진행 경로 문장: 사건의 선 중 장이 있는 것을 시각순으로
            let mut by_ch: Vec<(Chapter, i64, i64)> = Vec::new(); // (장, edge_id, ts)
            for eid in &s.edges {
                if let Ok(e) = graph::query::edge_by_id(store, *eid) {
                    if let Some(c) = e.chapter {
                        let ch = match c {
                            1 => Chapter::Ingress,
                            2 => Chapter::Execute,
                            3 => Chapter::Persist,
                            5 => Chapter::Destroy,
                            _ => Chapter::Egress,
                        };
                        // 스냅샷 출신 선: 관측 시각(원시 이벤트 시각)으로 세고, 원래 시각은 running_since 로
                        let mut ts = e.ts;
                        if let Some(raw) = e.evidence_id {
                            let obs: Option<(i64, String)> = store
                                .conn()
                                .query_row(
                                    "SELECT ts, source FROM raw_events WHERE id = ?1",
                                    [raw],
                                    |r| Ok((r.get(0)?, r.get(1)?)),
                                )
                                .ok();
                            if let Some((obs_ts, src)) = obs {
                                // 25차 Q1: 스냅샷 출신이면 시작 시각이 기록 없는 구간 안인지(10초 문턱과 상관없이 — Q2 경계 맞추기 방지)
                                if src == "snapshot" && started_in_gap.is_none() {
                                    if let Ok(Some(g)) = graph::views::no_record_gap_at(store, e.ts)
                                    {
                                        started_in_gap = Some((g.from_ts, g.to_ts));
                                    }
                                }
                                // 수집 시작 몇 초 안에 막 시작된 것은 "전부터 실행 중"이 아니다(L025: 스냅샷에 걸린 짧은 sh.exe)
                                if src == "snapshot" && obs_ts - e.ts > SNAPSHOT_FRESH {
                                    running_since =
                                        Some(running_since.map_or(e.ts, |r: i64| r.min(e.ts)));
                                    first_obs =
                                        Some(first_obs.map_or(obs_ts, |f: i64| f.min(obs_ts)));
                                    ts = obs_ts;
                                }
                            }
                        }
                        by_ch.push((ch, e.id, ts));
                    }
                }
            }
            by_ch.sort_by_key(|x| x.2);
            if let Some(obs) = first_obs {
                fresh = by_ch.iter().any(|x| x.2 > obs + NEW_ACTIVITY_AFTER);
            }
            last_ts = by_ch.last().map(|x| x.2).unwrap_or(0);
            let mut reached: Vec<Chapter> = Vec::new();
            for (c, _, _) in &by_ch {
                if !reached.contains(c) {
                    reached.push(*c);
                }
            }
            reached.sort();
            reached_out = reached.iter().map(|c| *c as u8).collect();
            if !reached.is_empty() {
                let path = reached
                    .iter()
                    .map(|c| chapter_name(*c))
                    .collect::<Vec<_>>()
                    .join(" → ");
                let first_ts = by_ch.first().map(|x| x.2).unwrap_or(0);
                let edge_ids: Vec<i64> = by_ch.iter().map(|x| x.1).collect();
                let mut evidence = Vec::new();
                for eid in &edge_ids {
                    evidence.extend(store.evidence_of(*eid)?);
                }
                let text = match voice {
                    Voice::Expert => format!("{} {}: {}.", hms(first_ts), root, path),
                    _ => format!("{root}: {path}."),
                };
                sentences.push(Sentence {
                    text,
                    evidence,
                    edge_ids,
                    actor_id: s.root,
                    ts: first_ts,
                    chapter: Some(s.chapter as i64),
                    parts: None,
                    already_open: false,
                    sources: Vec::new(),
                    via_lag_ms: None,
                });
            }
            if started_in_gap.is_some() {
                fresh = true;
            }
            if s.ingress_unknown && started_in_gap.is_some() {
                items.push(Item {
                    label: "시작 경위",
                    value: "기록 없는 구간에 시작 — Story Firewall 이 멈췄거나 PC 가 절전 중이던 동안 시작됐습니다. 그 사이의 일은 기록에 없습니다.".into(),
                    edge_ids: vec![],
                    sources: Vec::new(),
                });
            } else if s.ingress_unknown && running_since.is_some() {
                // D004-3: 기록 시작 전의 일 — 겁주지 않고 정확하게. 유입을 단정하는 말("출처 불명", "침입")은 쓰지 않는다
                items.push(Item {
                    label: "시작 경위",
                    value: "기록 없음 — Story Firewall 이 기록을 시작하기 전에 실행됐습니다. 기록이 없다는 것은 안전하다는 뜻도, 위험하다는 뜻도 아닙니다.".into(),
                    edge_ids: vec![],
                    sources: Vec::new(),
                });
            } else if s.ingress_unknown {
                items.push(Item {
                    label: "출신",
                    value: "확인되지 않음".into(),
                    edge_ids: vec![],
                    sources: Vec::new(),
                });
            }
            if s.ingress_unknown {
                sentences.push(Sentence {
                    text: format!("{root}: 어떻게 들어왔는지 확인되지 않음"),
                    evidence: vec![],
                    edge_ids: vec![],
                    actor_id: s.root,
                    ts: 0,
                    chapter: None,
                    parts: None,
                    already_open: false,
                    sources: Vec::new(),
                    via_lag_ms: None,
                });
            }
            for r in &s.reasons {
                let Some(mut text) = reason_text(r, root, voice) else {
                    continue;
                };
                // 17판 23-2 ②: 근거 선에서 실제 대상을 알면 구체 문장·항목 값으로
                let detail = vault_detail(store, r);
                if let Some((t, _)) = &detail {
                    text = match voice {
                        Voice::Expert => format!("{t} ({:+})", r.points),
                        _ => t.clone(),
                    };
                }
                let (edge_ids, evidence) = match r.edge_id {
                    Some(eid) => (vec![eid], store.evidence_of(eid)?),
                    None => (vec![], vec![]),
                };
                let sources = crate::sources_of(store, &evidence);
                if let Some((label, value)) = reason_item(r.what) {
                    items.push(Item {
                        label,
                        value: detail
                            .as_ref()
                            .map(|(_, v)| v.clone())
                            .unwrap_or_else(|| value.into()),
                        edge_ids: edge_ids.clone(),
                        sources: sources.clone(),
                    });
                }
                sentences.push(Sentence {
                    text,
                    evidence,
                    edge_ids,
                    actor_id: r.node_id.unwrap_or(s.root),
                    ts: 0,
                    chapter: None,
                    parts: None,
                    already_open: false,
                    sources,
                    via_lag_ms: None,
                });
            }
            // D023-2: 4칸 중 채운 칸마다 본문에 근거 항목이 하나는 있어야 한다. 판정 이유 항목으로 이미 말했으면 더하지 않는다
            {
                let has = |items: &Vec<Item>, labels: &[&str]| {
                    items.iter().any(|i| labels.contains(&i.label))
                };
                for (c, eid, _) in by_ch.iter().rev() {
                    let Ok(e) = graph::query::edge_by_id(store, *eid) else {
                        continue;
                    };
                    match c {
                        Chapter::Egress if egress.is_none() => {
                            if let Ok(n) = store.node(e.dst) {
                                egress = Some((n.label.clone(), n.id, e.id));
                            }
                        }
                        _ => {}
                    }
                }
                if reached_out.contains(&(Chapter::Execute as u8))
                    && !has(
                        &items,
                        &["위치", "실행", "실행한 프로그램", "시작", "시작 경위"],
                    )
                {
                    if let Some((_, eid, _)) = by_ch.iter().find(|x| x.0 == Chapter::Execute) {
                        if let Ok(e) = graph::query::edge_by_id(store, *eid) {
                            let src = store.node(e.src).map(|n| n.label).unwrap_or_default();
                            let dst = store.node(e.dst).map(|n| n.label).unwrap_or_default();
                            // D037-2: 조사 병기("이(가)") 대신 구조형(주체 → 실행 대상)
                            if e.rel == "spawned" {
                                let value = format!(
                                    "{} → 실행 {}",
                                    crate::render::no_arrows(&src),
                                    crate::render::no_arrows(&dst)
                                );
                                items.push(Item {
                                    label: "실행한 프로그램",
                                    value,
                                    edge_ids: vec![e.id],
                                    sources: crate::sources_of(store, &store.evidence_of(e.id)?),
                                });
                            } else {
                                // D039-2: 뿌리가 파일(executed_as)이면 "sh.exe 실행"은 자기 자신을 실행한 것처럼 읽힌다 —
                                // "이 파일이 N번 실행됨 · 부모 X"(시각 범위는 화면이 지역 시각으로 붙인다)
                                let n: i64 = store.conn().query_row("SELECT COUNT(*) FROM edges WHERE src = ?1 AND rel = 'executed_as'", [e.src], |r| r.get(0)).unwrap_or(1);
                                let parent: Option<String> = store
                                    .conn()
                                    .query_row("SELECT n.label FROM edges x JOIN nodes n ON n.id = x.src WHERE x.dst = ?1 AND x.rel = 'spawned' ORDER BY x.ts DESC LIMIT 1", [e.dst], |r| r.get(0))
                                    .ok();
                                // 실행 파일 선이 없으면(시작 이벤트를 못 본 프로세스) 횟수를 세지 않는다 — "0번 실행됨"은 틀린 문장(2026-11-07 노트북 실측)
                                let value = match parent {
                                    _ if n == 0 => "시작 기록 없음 — 수집 전부터 실행 중이었거나 시작 기록을 놓쳤습니다".to_string(),
                                    Some(p) => format!(
                                        "이 파일이 {n}번 실행됨 · 부모 {}",
                                        crate::render::no_arrows(&p)
                                    ),
                                    None => format!("이 파일이 {n}번 실행됨"),
                                };
                                items.push(Item {
                                    label: "실행",
                                    value,
                                    edge_ids: vec![e.id],
                                    sources: crate::sources_of(store, &store.evidence_of(e.id)?),
                                });
                            }
                        }
                    }
                }
                if reached_out.contains(&(Chapter::Persist as u8)) && !has(&items, &["자동 실행"])
                {
                    if let Some((_, eid, _)) = by_ch.iter().find(|x| x.0 == Chapter::Persist) {
                        if let Ok(e) = graph::query::edge_by_id(store, *eid) {
                            let dst = store.node(e.dst).map(|n| n.label).unwrap_or_default();
                            items.push(Item {
                                label: "자동 실행",
                                value: format!("{} 등록", crate::render::no_arrows(&dst)),
                                edge_ids: vec![e.id],
                                sources: crate::sources_of(store, &store.evidence_of(e.id)?),
                            });
                        }
                    }
                }
                if reached_out.contains(&(Chapter::Destroy as u8)) {
                    // 10판 5-9 (1): 종류 + 실제 명령(근거 선 = ran). 판정 이유의 일반 문구는 이것으로 바꾼다
                    items.retain(|i| i.label != "복구 수단");
                    for (_, eid, ts) in by_ch.iter().filter(|x| x.0 == Chapter::Destroy) {
                        if let Ok(e) = graph::query::edge_by_id(store, *eid) {
                            if let Ok(cmd) = store.node(e.dst) {
                                let kind =
                                    judge::rules::ran_kind(&e, &cmd).unwrap_or("복구 수단 변경");
                                // D043-2: 항목 값은 사람 말(종류)만, 명령줄은 destroy.cmdline 으로 따로(화면이 고정폭 줄)
                                items.push(Item {
                                    label: "복구 수단",
                                    value: kind.to_string(),
                                    edge_ids: vec![e.id],
                                    sources: crate::sources_of(store, &store.evidence_of(e.id)?),
                                });
                                if destroy.is_none() {
                                    destroy = Some(Destroy {
                                        kind,
                                        sentence: destroy_sentence(kind),
                                        cmdline: cmd.key.clone(),
                                        ts: *ts,
                                        edge_id: e.id,
                                    });
                                }
                            }
                        }
                    }
                }
                if let Some((name, _, eid)) = &egress {
                    if !has(&items, &["접속"]) {
                        items.push(Item {
                            label: "접속",
                            value: crate::render::no_arrows(name),
                            edge_ids: vec![*eid],
                            sources: crate::sources_of(store, &store.evidence_of(*eid)?),
                        });
                    }
                }
            }
            // D004-3 권고: 주의 이상이고 시스템 핵심 프로세스(Windows 폴더)가 아닐 때만. 재부팅 강요가 아니라 방법 안내
            if running_since.is_some()
                && s.ingress_unknown
                && s.score >= 40
                && !is_windows_file(store, s.root)
            {
                items.push(Item {
                    label: "확인 방법",
                    value: "다시 시작하면 처음부터 기록됩니다. 출신을 확인하려면 이 프로그램을 다시 시작하거나 PC 를 재부팅하세요.".into(),
                    edge_ids: vec![],
                    sources: Vec::new(),
                });
            }
        }
        out.push(Narrative {
            root: s.root,
            level: s.level,
            score: s.score,
            chapter: s.chapter,
            title,
            sentences,
            items,
            reached: reached_out,
            last_ts,
            running_since,
            started_in_gap,
            egress: egress.as_ref().map(|x| x.0.clone()),
            egress_node: egress.as_ref().map(|x| x.1),
            destroy,
            fresh,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod item_tests {
    use super::reason_item;

    /// 점수표의 모든 항목에 항목형 문구가 있다(새 가중치를 넣고 화면 문구를 빠뜨리지 않게)
    #[test]
    fn every_weight_has_an_item_label() {
        for (what, _) in judge::score::WEIGHTS {
            assert!(reason_item(what).is_some(), "항목형 문구 없음: {what}");
        }
        assert!(reason_item("장 기본점").is_none());
        // 단정 금지(render::FORBIDDEN)와 같은 낱말이 항목 값에 없다
        for (what, _) in judge::score::WEIGHTS {
            let (_, v) = reason_item(what).unwrap();
            for bad in crate::render::FORBIDDEN {
                assert!(!v.contains(bad), "{what}: {v} 에 {bad}");
            }
        }
    }
}
