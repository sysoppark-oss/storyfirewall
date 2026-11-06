//! 메서드 목록과 파라미터 타입 (10차 3장). 권한(Role)과 멱등 키 요구를 메서드 표에 둔다.
//! 디스패처(svc)는 `Method::parse` 로 메서드를 알아보고, `role()` 로 권한을 확인하고, `params_of` 로 파라미터를 꺼낸다.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, RpcError};
use crate::page::Cursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// 인증된 사용자(조회)
    User,
    /// 로컬 관리자 그룹(변경)
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    RpcHello,
    ConnectionsList,
    ConnectionsSubscribe,
    ListenersList,
    GraphNeighbors,
    GraphRewind,
    GraphTimeline,
    ProcessDetail,
    StoryToday,
    StoryExplain,
    StoryEvents,
    EventsSubscribe,
    JudgeFeedbackNormal,
    JudgeBaselineStatus,
    PolicyValidate,
    PolicyDryrun,
    PolicyApply,
    PolicyConfirm,
    PolicyRollback,
    PolicyPause,
    PolicyReleaseAddressBlocks,
    PolicyHistory,
    PolicyList,
    CutPreview,
    CutApply,
    RetentionGet,
    RetentionSet,
    SettingsGet,
    SettingsSet,
    /// 변경 승인 (18차 설계): 보기 모드 UI 가 변경을 맡겨 두고(stage), 승격된 승인 도우미가 서비스가 만든 요약을 보여 준 뒤 실행(commit)
    ChangeStage,
    ChangeGet,
    ChangeCommit,
    ChangeResult,
    /// 서비스 사건 목록 (A29): 파이프 가로채기·데이터 폴더 점유·끊기 결과 등. 조회(사용자)
    ServiceEvents,
    /// 수집 상태 한 줄(제안 C1): 마지막 사건 시각·기록 손실 구간·시계 변경. 조회(사용자)
    CollectorHealth,
    /// 설치 엑스레이 (기획서 14판 20-3): 최근 설치 한 번마다 한 일. 조회(사용자)
    InstallsList,
    /// AI 에이전트 감시 (기획서 14판 20-5): AI 도구별 통신한 곳·실행한 명령·만든 파일. 조회(사용자)
    AgentsList,
    /// 변경 장부 (17판 23-2 ③): 첫 실행 관찰 대상(프로세스 노드)과 자손이 만든 파일·자동 실행·접속. 조회(사용자 범위)
    LedgerGet,
}

impl Method {
    pub const ALL: &'static [(&'static str, Method)] = &[
        ("rpc.hello", Method::RpcHello),
        ("connections.list", Method::ConnectionsList),
        ("connections.subscribe", Method::ConnectionsSubscribe),
        ("listeners.list", Method::ListenersList),
        ("graph.neighbors", Method::GraphNeighbors),
        ("graph.rewind", Method::GraphRewind),
        ("graph.timeline", Method::GraphTimeline),
        ("process.detail", Method::ProcessDetail),
        ("story.today", Method::StoryToday),
        ("story.explain", Method::StoryExplain),
        ("story.events", Method::StoryEvents),
        ("installs.list", Method::InstallsList),
        ("agents.list", Method::AgentsList),
        ("ledger.get", Method::LedgerGet),
        ("events.subscribe", Method::EventsSubscribe),
        ("judge.feedback_normal", Method::JudgeFeedbackNormal),
        ("judge.baseline_status", Method::JudgeBaselineStatus),
        ("policy.validate", Method::PolicyValidate),
        ("policy.dryrun", Method::PolicyDryrun),
        ("policy.apply", Method::PolicyApply),
        ("policy.confirm", Method::PolicyConfirm),
        ("policy.rollback", Method::PolicyRollback),
        ("policy.pause", Method::PolicyPause),
        (
            "policy.release_address_blocks",
            Method::PolicyReleaseAddressBlocks,
        ),
        ("policy.history", Method::PolicyHistory),
        ("policy.list", Method::PolicyList),
        ("cut.preview", Method::CutPreview),
        ("cut.apply", Method::CutApply),
        ("retention.get", Method::RetentionGet),
        ("retention.set", Method::RetentionSet),
        ("settings.get", Method::SettingsGet),
        ("settings.set", Method::SettingsSet),
        ("change.stage", Method::ChangeStage),
        ("change.get", Method::ChangeGet),
        ("change.commit", Method::ChangeCommit),
        ("change.result", Method::ChangeResult),
        ("service.events", Method::ServiceEvents),
        ("collector.health", Method::CollectorHealth),
    ];

    pub fn parse(name: &str) -> Result<Method, RpcError> {
        Self::ALL
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, m)| *m)
            .ok_or_else(|| RpcError::with(ErrorCode::MethodNotFound, name))
    }
    pub fn name(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(_, m)| *m == self)
            .map(|(n, _)| *n)
            .unwrap()
    }
    /// 변경 메서드 = 관리자 + 멱등 키 필수
    pub fn role(self) -> Role {
        match self {
            Method::JudgeFeedbackNormal
            | Method::PolicyApply
            | Method::PolicyConfirm
            | Method::PolicyRollback
            | Method::PolicyPause
            | Method::PolicyReleaseAddressBlocks
            | Method::CutApply
            | Method::RetentionSet
            | Method::SettingsSet
            | Method::ChangeGet
            | Method::ChangeCommit => Role::Admin,
            _ => Role::User,
        }
    }
    pub fn needs_request_id(self) -> bool {
        // change.get 은 관리자만 읽지만 바꾸지 않는다
        self.role() == Role::Admin && self != Method::ChangeGet
    }
    /// 승인 도우미를 거쳐 실행할 수 있는 변경 (확인 policy.confirm 은 도우미가 실행 직후 스스로 한다, change.* 는 중첩 금지)
    pub fn stageable(self) -> bool {
        matches!(
            self,
            Method::JudgeFeedbackNormal
                | Method::PolicyApply
                | Method::PolicyRollback
                | Method::PolicyPause
                | Method::PolicyReleaseAddressBlocks
                | Method::CutApply
                | Method::RetentionSet
                | Method::SettingsSet
        )
    }
    pub fn is_subscription(self) -> bool {
        matches!(self, Method::ConnectionsSubscribe | Method::EventsSubscribe)
    }
}

/// 변경 메서드 공통: 멱등 키
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mutation {
    pub request_id: String,
}

pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// service.events (A29)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceEventsParams {
    #[serde(default = "default_service_events_since")]
    pub since_secs: i64,
    #[serde(default = "default_service_events_limit")]
    pub limit: usize,
}
fn default_service_events_since() -> i64 {
    7 * 86_400
}
fn default_service_events_limit() -> usize {
    50
}

/// 메서드별 파라미터
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyApplyParams {
    pub request_id: String,
    pub yaml: String,
    /// 서비스가 UI 확인을 받은 항목: [(정책 이름, "self"|"wide"|"svchost")]
    #[serde(default)]
    pub acknowledge: Vec<(String, String)>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyApplyReply {
    pub policy_id: i64,
    pub version: i64,
    pub filters: usize,
    pub confirm_deadline_ts: i64,
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_block_notice: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRef {
    pub request_id: String,
    pub policy_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    /// policy.release_address_blocks 에서만: 주소 차단 필터 하나만 푼다(D036). 없으면 policy_id 의 것 전부(0 = 모든 정책)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_id: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyValidateParams {
    pub yaml: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationReply {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub needs_ack: Vec<(String, String)>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoryEventsParams {
    #[serde(default)]
    pub since_ts: i64,
    /// "normal" | "watch" | "suspicious"
    #[serde(default = "StoryEventsParams::default_level")]
    pub level_min: String,
    #[serde(default = "StoryEventsParams::default_voice")]
    pub voice: String,
    #[serde(default)]
    pub cursor: Cursor,
}
impl StoryEventsParams {
    fn default_level() -> String {
        "watch".into()
    }
    fn default_voice() -> String {
        "plain".into()
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoryTodayParams {
    /// "YYYY-MM-DD" 로컬. 없으면 오늘
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// L030: 이 시각(FILETIME) 이후만. 화면은 "오늘"이면 지역 0시, "최근 24시간"이면 지금-24h. 없으면 지금-24h
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_ts: Option<i64>,
    #[serde(default = "StoryEventsParams::default_voice")]
    pub voice: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeRef {
    pub edge_id: i64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeQuery {
    pub node_id: i64,
    #[serde(default = "NodeQuery::default_depth")]
    pub max_depth: i64,
}
impl NodeQuery {
    fn default_depth() -> i64 {
        6
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeRange {
    pub from_ts: i64,
    pub to_ts: i64,
    #[serde(default = "TimeRange::default_buckets")]
    pub buckets: usize,
}
impl TimeRange {
    fn default_buckets() -> usize {
        96
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedbackNormalParams {
    pub request_id: String,
    pub root: i64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CutParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub story_root: i64,
    #[serde(default)]
    pub also: Vec<String>,
}
/// change.stage: 맡길 변경 (method 는 stageable, params 는 그 메서드 검증을 통과해야 한다 — request_id 포함)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeStageParams {
    pub method: String,
    pub params: serde_json::Value,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeRef {
    pub change_id: String,
}
/// change.commit: 도우미가 보여 준 요약의 digest. 그사이 내용이 바뀌면(그래프가 자람 등) 거부한다
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeCommitParams {
    pub request_id: String,
    pub change_id: String,
    pub digest: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Listed {
    #[serde(default)]
    pub cursor: Cursor,
}

/// 파라미터 공통 검증: 변경 메서드의 request_id(UUID) 존재, 페이지 상한, 메서드별 필드.
/// 반환: 정규화된 params (cursor.limit 자름)
pub fn validate_params(
    method: Method,
    params: &serde_json::Value,
) -> Result<serde_json::Value, RpcError> {
    let mut p = if params.is_null() {
        serde_json::json!({})
    } else {
        params.clone()
    };
    if method.needs_request_id() {
        let rid = p
            .get("request_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::with(ErrorCode::InvalidParams, "request_id(UUID) 필수"))?;
        if !is_uuid(rid) {
            return Err(RpcError::with(
                ErrorCode::InvalidParams,
                "request_id 는 UUID 형식",
            ));
        }
    }
    if let Some(c) = p.get("cursor") {
        let cur: Cursor = serde_json::from_value(c.clone())
            .map_err(|e| RpcError::with(ErrorCode::InvalidParams, format!("cursor: {e}")))?;
        p["cursor"] = serde_json::to_value(cur.normalized()).unwrap();
    }
    let check = |ok: bool, msg: &str| {
        if ok {
            Ok(())
        } else {
            Err(RpcError::with(ErrorCode::InvalidParams, msg))
        }
    };
    match method {
        Method::RpcHello => {
            let _: crate::rpc::Hello = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
        }
        Method::PolicyValidate | Method::PolicyDryrun => {
            let v: PolicyValidateParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(
                !v.yaml.trim().is_empty() && v.yaml.len() <= 256 * 1024,
                "yaml 은 비어 있지 않고 256KB 이하",
            )?;
        }
        Method::PolicyApply => {
            let v: PolicyApplyParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(
                !v.yaml.trim().is_empty() && v.yaml.len() <= 256 * 1024,
                "yaml 은 비어 있지 않고 256KB 이하",
            )?;
            check(
                v.acknowledge
                    .iter()
                    .all(|(_, k)| matches!(k.as_str(), "self" | "wide" | "svchost")),
                "acknowledge 종류는 self|wide|svchost",
            )?;
        }
        Method::PolicyConfirm => {
            let v: PolicyRef = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(v.version.is_some(), "confirm 은 version 필수")?;
        }
        Method::PolicyRollback | Method::PolicyPause | Method::PolicyReleaseAddressBlocks => {
            let _: PolicyRef = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
        }
        Method::StoryEvents => {
            let v: StoryEventsParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(
                matches!(v.level_min.as_str(), "normal" | "watch" | "suspicious"),
                "level_min 은 normal|watch|suspicious",
            )?;
            check(
                matches!(v.voice.as_str(), "plain" | "expert" | "one_line"),
                "voice 는 plain|expert|one_line",
            )?;
        }
        Method::StoryToday => {
            let v: StoryTodayParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(
                matches!(v.voice.as_str(), "plain" | "expert" | "one_line"),
                "voice 는 plain|expert|one_line",
            )?;
            if let Some(d) = &v.date {
                check(
                    d.len() == 10 && d.as_bytes()[4] == b'-' && d.as_bytes()[7] == b'-',
                    "date 는 YYYY-MM-DD",
                )?;
            }
        }
        Method::InstallsList => {
            let v: InstallsParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check((1..=100).contains(&v.limit), "limit 은 1~100")?;
            check((1..=30).contains(&v.days), "days 는 1~30")?;
        }
        Method::LedgerGet => {
            let _: LedgerParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
        }
        Method::AgentsList => {
            let v: AgentsParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check((1..=50).contains(&v.limit), "limit 은 1~50")?;
            check((1..=7).contains(&v.days), "days 는 1~7")?;
        }
        Method::StoryExplain => {
            let _: EdgeRef = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
        }
        Method::GraphNeighbors | Method::GraphRewind | Method::ProcessDetail => {
            let v: NodeQuery = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check((1..=32).contains(&v.max_depth), "max_depth 는 1~32")?;
        }
        Method::GraphTimeline => {
            let v: TimeRange = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(
                v.from_ts < v.to_ts && (1..=2_000).contains(&v.buckets),
                "from<to, buckets 1~2000",
            )?;
        }
        Method::JudgeFeedbackNormal => {
            let _: FeedbackNormalParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
        }
        Method::CutPreview | Method::CutApply => {
            let v: CutParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(
                v.also.iter().all(|a| {
                    matches!(
                        a.as_str(),
                        "terminate" | "terminate_injected" | "quarantine" | "remove_autorun"
                    )
                }),
                "also 는 terminate|terminate_injected|quarantine|remove_autorun",
            )?;
        }
        Method::ConnectionsList
        | Method::ListenersList
        | Method::PolicyHistory
        | Method::PolicyList => {
            let _: Listed = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
        }
        Method::ConnectionsSubscribe
        | Method::EventsSubscribe
        | Method::JudgeBaselineStatus
        | Method::RetentionGet
        | Method::SettingsGet
        | Method::CollectorHealth => {}
        Method::ServiceEvents => {
            let v: ServiceEventsParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(
                (1..=604_800).contains(&v.since_secs),
                "since_secs 는 1~604800",
            )?;
            check((1..=200).contains(&v.limit), "limit 은 1~200")?;
        }
        Method::ChangeStage => {
            let v: ChangeStageParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let inner = Method::parse(&v.method)?;
            check(
                inner.stageable(),
                "맡길 수 없는 메서드 (policy.confirm·change.* 는 안 됨)",
            )?;
            // 안쪽 메서드 검증을 그대로 적용하고, 정규화된 결과로 바꿔 둔다
            p["params"] = validate_params(inner, &v.params)?;
        }
        Method::ChangeGet | Method::ChangeResult => {
            let v: ChangeRef = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(is_uuid(&v.change_id), "change_id 는 UUID 형식")?;
        }
        Method::ChangeCommit => {
            let v: ChangeCommitParams = serde_json::from_value(p.clone())
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            check(is_uuid(&v.change_id), "change_id 는 UUID 형식")?;
            check(
                v.digest.len() == 64 && v.digest.bytes().all(|c| c.is_ascii_hexdigit()),
                "digest 는 SHA-256 hex",
            )?;
        }
        Method::RetentionSet | Method::SettingsSet => {
            check(
                p.is_object() && p.as_object().unwrap().len() >= 2,
                "설정 값 필요",
            )?;
            // 첫 실행 관찰실 (17판 23-2 ①): 값이 있을 때만 검사 — 다른 설정만 바꾸는 호출은 그대로
            if let Some(v) = p.get("first_run_watch") {
                check(
                    matches!(v.as_str(), Some("off" | "notify" | "block")),
                    "first_run_watch 는 off|notify|block",
                )?;
            }
            if let Some(v) = p.get("first_run_minutes") {
                check(
                    matches!(v.as_u64(), Some(5 | 10 | 30)),
                    "first_run_minutes 는 5|10|30",
                )?;
            }
            // 33차 Gemini Q4: 사용자가 "내가 쓰는 원격 도구"로 표시한 도구(graph::remote::TOOLS 의 key). 이 도구의 세션 시작만 알림을 낮춘다
            if let Some(v) = p.get("remote_trusted_tools") {
                let ok = v.as_array().is_some_and(|a| {
                    a.len() <= 16
                        && a.iter().all(|x| {
                            x.as_str().is_some_and(|s| {
                                !s.is_empty()
                                    && s.len() <= 40
                                    && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
                            })
                        })
                });
                check(ok, "remote_trusted_tools 는 도구 이름(소문자·_) 16개까지의 배열")?;
            }
        }
    }
    Ok(p)
}

/// 알림 이름 (서버 → 클라이언트)
pub const NOTIFY_CONNECTIONS: &str = "connections.tick";
pub const NOTIFY_EVENT: &str = "events.new";

/// installs.list 파라미터: 최근 며칠(기본 7일), 최대 몇 건(기본 30)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstallsParams {
    #[serde(default = "default_install_days")]
    pub days: u32,
    #[serde(default = "default_install_limit")]
    pub limit: u32,
}
/// ledger.get 파라미터: 관찰 대상 프로세스 노드
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerParams {
    pub node_id: i64,
}

/// agents.list 파라미터: 최근 며칠(기본 1일, 최대 7일 — 미리 계산 범위), 최대 몇 건(기본 20)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentsParams {
    #[serde(default = "default_agent_days")]
    pub days: u32,
    #[serde(default = "default_agent_limit")]
    pub limit: u32,
}
fn default_agent_days() -> u32 {
    1
}
fn default_agent_limit() -> u32 {
    20
}
fn default_install_days() -> u32 {
    7
}
fn default_install_limit() -> u32 {
    30
}
