//! 출처 그래프 엔진
//!
//! 모든 수집 이벤트를 "누가 무엇을 낳고, 어디에 접속했는가"의 그래프로 저장한다.
//! 스키마는 이야기형 연결 분석 기획서 3판 3-1장을 따른다.
//!
//! 원칙
//! - 그래프가 사실의 원천이다. 이야기·마인드맵은 이 그래프의 다른 표현이다.
//! - 모든 선(edge)은 근거 원시 이벤트(raw_events)를 가리킨다.
//! - 그래프는 나무가 아니라 그물(DAG)이다. 마인드맵은 주인공 기준 투영으로 꺼낸다.
//! - 프로세스 고유 키는 "PID@생성시각". PID 재사용에 안전하다.
//!
//! 이 크레이트는 OS 의존이 없다. Windows 이벤트는 `event::Event` 로 정규화되어 들어온다.

pub mod changes;
pub mod event;
pub mod hash;
pub mod ingest;
pub mod install;
pub mod query;
pub mod retention;
pub mod schema;
pub mod store;
pub mod textlog;
pub mod vault;
pub mod views;

pub use event::{Event, EventKind};
pub use store::Store;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GraphError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("노드를 찾을 수 없음: {0}")]
    NodeNotFound(String),
}

pub type Result<T> = std::result::Result<T, GraphError>;

/// 노드 종류. 문자열로 저장되며 DB 의 nodes.kind 와 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    Process,
    File,
    Remote,
    Domain,
    Autorun,
    UserAction,
    /// 실행 명령줄 (10판 5-9: 복구 수단 삭제 도구만 수집). 키 = 명령줄(소문자 아님, 원문)
    Command,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Process => "process",
            NodeKind::File => "file",
            NodeKind::Remote => "remote",
            NodeKind::Domain => "domain",
            NodeKind::Autorun => "autorun",
            NodeKind::UserAction => "user_action",
            NodeKind::Command => "command",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "process" => NodeKind::Process,
            "file" => NodeKind::File,
            "remote" => NodeKind::Remote,
            "domain" => NodeKind::Domain,
            "autorun" => NodeKind::Autorun,
            "user_action" => NodeKind::UserAction,
            "command" => NodeKind::Command,
            _ => return None,
        })
    }
}

/// 관계 종류. DB 의 edges.rel 과 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rel {
    /// 프로세스가 자식 프로세스를 실행함
    Spawned,
    /// 프로세스가 파일을 만듦
    Wrote,
    /// 프로세스가 파일을 다운로드함 (MOTW)
    Downloaded,
    /// 프로세스가 원격지에 접속함
    Connected,
    /// 프로세스가 도메인을 조회함, 또는 도메인이 원격지로 풀림
    Resolved,
    /// 프로세스가 자동 실행 항목을 등록함
    Registered,
    /// 프로세스가 다른 프로세스에 코드를 주입함 (빙의)
    Injected,
    /// 파일이 프로세스로 실행됨 (파일 → 프로세스)
    ExecutedAs,
    /// 서비스가 대신 접속함 (해석 선). attrs_json 에 method/confidence
    ConnectedVia,
    /// 프로세스가 이 명령줄로 실행됨 (프로세스 → 명령, 10판 5-9)
    Ran,
    /// 프로세스가 감시 경로의 파일(브라우저 금고·미끼)을 엶 (프로세스 → 파일, 17판 23-2 ②)
    Opened,
}

impl Rel {
    pub fn as_str(self) -> &'static str {
        match self {
            Rel::Spawned => "spawned",
            Rel::Wrote => "wrote",
            Rel::Downloaded => "downloaded",
            Rel::Connected => "connected",
            Rel::Resolved => "resolved",
            Rel::Registered => "registered",
            Rel::Injected => "injected",
            Rel::ExecutedAs => "executed_as",
            Rel::ConnectedVia => "connected_via",
            Rel::Ran => "ran",
            Rel::Opened => "opened",
        }
    }
}

/// 그래프의 한 노드 (질의 결과용)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Node {
    pub id: i64,
    pub kind: String,
    pub key: String,
    pub label: String,
    pub first_ts: i64,
    pub last_ts: i64,
    /// 종류별 부가 정보 JSON (remote: ip/port/proto/domain, process: image/pid/ppid …)
    pub attrs_json: Option<String>,
}

impl Node {
    /// attrs_json 에서 키 하나를 꺼낸다
    pub fn attr(&self, key: &str) -> Option<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_str(self.attrs_json.as_deref()?).ok()?;
        v.get(key).cloned()
    }
}

/// 그래프의 한 선 (질의 결과용)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Edge {
    pub id: i64,
    pub src: i64,
    pub dst: i64,
    pub rel: String,
    pub ts: i64,
    pub evidence_id: Option<i64>,
    pub chapter: Option<i64>,
    /// connected_via: {"method":"capi2"|"window","confidence":"high"|"low"} 등
    pub attrs_json: Option<String>,
}
