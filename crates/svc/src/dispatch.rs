//! 디스패처: 메서드 → engine·judge·story 호출. 엔진 스레드 안에서만 실행된다.

use api::rpc::Id;
use api::{ErrorCode, Method, Page, Response, RpcError};
use engine::EngineError;
use story::Voice;

use crate::runtime::World;

/// 연결 핸들러가 확인한 호출자 정보
#[derive(Debug, Clone)]
pub struct Caller {
    pub pid: u32,
    pub image: String,
    pub is_admin: bool,
    /// 로그온 세션 (A30). None = 알 수 없음/개발 전송 → 범위 제한 없음
    pub session: Option<u32>,
}

impl Caller {
    /// 조회 범위 (A30, 22차 Q6): 관리자는 전부, 일반 사용자는 자기 세션 + 시스템(0)
    pub fn scope(&self) -> Scope {
        match (self.is_admin, self.session) {
            (true, _) | (false, None) => Scope::All,
            (false, Some(s)) => Scope::Session(s),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    All,
    Session(u32),
}

impl Scope {
    /// 프로세스 노드를 볼 수 있는가: 세션이 없거나(모름) 0(시스템) 이거나 내 세션
    pub fn process_visible(self, g: &graph::Store, node: i64) -> bool {
        match self {
            Scope::All => true,
            Scope::Session(me) => match g.node(node) {
                Ok(n) if n.kind == graph::NodeKind::Process.as_str() => {
                    match n.attr("session").and_then(|v| v.as_u64()) {
                        None => true,
                        Some(s) => s == 0 || s == me as u64,
                    }
                }
                // 프로세스가 아닌 노드(파일·원격·도메인)는 이 검사로 막지 않는다 — 보이는 프로세스에서만 닿게 응답을 거른다
                Ok(_) => true,
                Err(_) => false,
            },
        }
    }
    /// 여러 노드 중 하나라도 다른 사용자 세션의 프로세스면 false (이야기 단위로 숨김)
    pub fn all_visible(self, g: &graph::Store, nodes: impl IntoIterator<Item = i64>) -> bool {
        self == Scope::All || nodes.into_iter().all(|n| self.process_visible(g, n))
    }
    /// 선들의 양 끝이 모두 보이는가
    pub fn edges_visible(self, g: &graph::Store, edges: &[i64]) -> bool {
        if self == Scope::All {
            return true;
        }
        edges.iter().all(|e| match g.edge(*e) {
            Ok(ed) => self.process_visible(g, ed.src) && self.process_visible(g, ed.dst),
            Err(_) => true,
        })
    }
}

/// L030: 무거운 조회(판정·오늘 한 일) 캐시 수명(초)
pub(crate) const CACHE_SECS: i64 = 30;
/// L030: 오늘 한 일이 문장으로 만드는 선 상한(가장 늦은 것부터). 넘으면 truncated=true
pub(crate) const TODAY_MAX_EDGES: usize = 20_000;

/// 범위 밖 = "없음"과 같은 오류로 답한다 (다른 사용자의 노드가 있는지 없는지도 알리지 않게)
pub fn out_of_scope() -> RpcError {
    RpcError::with(ErrorCode::InvalidParams, "노드 없음")
}

/// 확인 항목 이름: 응답(needs_ack)과 입력(acknowledge)이 **같은 낱말**을 쓴다 (A23 에서 찾은 접점 결함: 응답은 Debug 이름
/// "selfblock" 을 내보내고 입력 검증은 "self" 만 받아, UI 가 받은 항목을 그대로 돌려보내면 InvalidParams 로 거부됐다)
pub fn ack_name(a: &dsl::Ack) -> &'static str {
    match a {
        dsl::Ack::SelfBlock => "self",
        dsl::Ack::Wide => "wide",
        dsl::Ack::Svchost => "svchost",
    }
}

fn ack_of(k: &str) -> dsl::Ack {
    match k {
        "self" => dsl::Ack::SelfBlock,
        "wide" => dsl::Ack::Wide,
        _ => dsl::Ack::Svchost,
    }
}

fn needs_ack_err(items: &[(String, dsl::Ack)]) -> RpcError {
    RpcError::new(ErrorCode::NeedsAck).data(serde_json::json!({ "items": items.iter().map(|(n, a)| (n.clone(), ack_name(a))).collect::<Vec<_>>() }))
}

fn engine_err(e: EngineError) -> RpcError {
    match e {
        EngineError::NeedsAck(items) => needs_ack_err(&items),
        EngineError::Guard(m) => RpcError::with(ErrorCode::GuardRejected, m),
        EngineError::Invalid(v) => RpcError::with(ErrorCode::InvalidParams, v.join("; ")),
        EngineError::Dsl(d) => RpcError::with(ErrorCode::InvalidParams, d.to_string()),
        EngineError::BadState(m) if m.contains("버전 불일치") => {
            RpcError::with(ErrorCode::VersionMismatch, m)
        }
        EngineError::BadState(m) => RpcError::with(ErrorCode::NotConfirmedYet, m),
        EngineError::NotFound(id) => {
            RpcError::with(ErrorCode::InvalidParams, format!("없음: {id}"))
        }
        other => RpcError::with(ErrorCode::Internal, other.to_string()),
    }
}

/// 마인드맵 가지 상한 (A21)
pub const MINDMAP_CAP: usize = 600;

fn apply_reply(r: engine::ApplyResult) -> api::methods::PolicyApplyReply {
    api::methods::PolicyApplyReply {
        policy_id: r.policy_id,
        version: r.version,
        filters: r.filters,
        confirm_deadline_ts: r.confirm_deadline,
        warnings: r.warnings,
        address_block_notice: r.address_block_notice,
    }
}

pub(crate) fn internal<E: std::fmt::Display>(e: E) -> RpcError {
    RpcError::with(ErrorCode::Internal, e.to_string())
}

pub(crate) fn voice_of(s: &str) -> Voice {
    match s {
        "expert" => Voice::Expert,
        "one_line" => Voice::OneLine,
        _ => Voice::Plain,
    }
}

fn actor(c: &Caller) -> String {
    format!("pid {} {}", c.pid, c.image)
}

fn from<T: serde::de::DeserializeOwned>(p: &serde_json::Value) -> Result<T, RpcError> {
    serde_json::from_value(p.clone())
        .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))
}

/// 승인 창에 보일 요약 (서비스가 지금 상태로 계산). 맡길 때(stage)·보여 줄 때(get)·실행 직전(commit) 세 번 같은 함수로 만든다.
/// 맡길 때는 실행 전 검증(대상 없음, needs_ack 미확인)도 여기서 걸러 UI 가 먼저 묻게 한다.
fn summarize(
    world: &mut World,
    method: Method,
    p: &serde_json::Value,
) -> Result<Vec<String>, RpcError> {
    use api::methods::*;
    let mut l: Vec<String> = Vec::new();
    match method {
        Method::CutApply => {
            let v: CutParams = from(p)?;
            let plan =
                crate::cut::plan_with(&world.graph, v.story_root, &v.also, &|pid, ft, seen| {
                    world.host.live_image(pid, ft, seen)
                })
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e))?;
            if plan.yaml.is_empty() {
                return Err(RpcError::with(
                    ErrorCode::InvalidParams,
                    "끊을 대상이 없습니다 (막을 경로도 접속지도 없음)",
                ));
            }
            l.push(format!(
                "여기서부터 끊기 — 뿌리 #{} {}",
                plan.root, plan.root_label
            ));
            // 묶음 순서: 사용자가 가장 먼저 봐야 할 것(끝낼 것·막을 것)부터. 묶음마다 상한(18차 Q1-a)
            use crate::change::section;
            if plan.terminate.is_empty() {
                l.push("끝낼 프로세스: 없음".into());
            } else {
                section(
                    &mut l,
                    format!(
                        "끝낼 프로세스 {}개 (생성 시각이 맞을 때만):",
                        plan.terminate.len()
                    ),
                    plan.terminate
                        .iter()
                        .map(|t| {
                            format!(
                                "PID {} {}{}",
                                t.pid,
                                t.image,
                                if t.injected_host {
                                    " (주입당한 프로그램)"
                                } else {
                                    ""
                                }
                            )
                        })
                        .collect(),
                );
            }
            section(
                &mut l,
                format!(
                    "통신을 막을 프로그램 {}개 (경로 기준):",
                    plan.block_images.len()
                ),
                plan.block_images.clone(),
            );
            // 접속지는 IP:포트를 줄 앞에 (말줄임이 와도 남게)
            section(
                &mut l,
                format!(
                    "24시간 막을 접속지 {}개 (주소·포트·프로토콜):",
                    plan.addresses.len()
                ),
                plan.addresses
                    .iter()
                    .map(|a| {
                        format!(
                            "{}:{}/{} — {} ({})",
                            a.ip,
                            a.port,
                            if a.proto == 17 { "udp" } else { "tcp" },
                            a.who,
                            // 승인 창에 영어 내부 말(target 등)이 나가던 것 — 화면과 같은 말로
                            match a.why.as_str() {
                                "system" => "핵심 프로세스의 접속",
                                "injected" => "주입당한 프로그램의 접속",
                                _ => "대상",
                            }
                        )
                    })
                    .collect(),
            );
            if !plan.injected_hosts.is_empty() {
                section(
                    &mut l,
                    format!(
                        "코드를 주입당한 정상 프로그램 {}개 — 통째로 막지 않음:",
                        plan.injected_hosts.len()
                    ),
                    plan.injected_hosts
                        .iter()
                        .map(|t| format!("PID {} {}", t.pid, t.image))
                        .collect(),
                );
            }
            if !plan.excluded_system.is_empty() {
                l.push(format!(
                    "시스템 프로세스 {}개 — 막거나 끝내지 않음",
                    plan.excluded_system.len()
                ));
            }
            l.push(format!("뿌리 파일 해시 대조: {}", plan.root_hash.status));
            l.extend(plan.warnings.iter().map(|w| format!("경고: {w}")));
        }
        Method::PolicyApply => {
            let v: PolicyApplyParams = from(p)?;
            let val = world.engine.validate(&v.yaml).map_err(engine_err)?;
            if !val.errors.is_empty() {
                return Err(RpcError::with(
                    ErrorCode::InvalidParams,
                    val.errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; "),
                ));
            }
            let missing: Vec<(String, dsl::Ack)> = val
                .needs_ack
                .iter()
                .filter(|(n, a)| {
                    !v.acknowledge
                        .iter()
                        .any(|(m, k)| m == n && k == ack_name(a))
                })
                .cloned()
                .collect();
            if !missing.is_empty() {
                return Err(needs_ack_err(&missing));
            }
            let doc = dsl::parse(&v.yaml)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            l.push(format!(
                "정책 적용 {}건 (60초 안에 유지를 누르지 않으면 되돌립니다)",
                doc.policies.len()
            ));
            for pol in &doc.policies {
                l.push(format!("  '{}' — {:?}", pol.name, pol.action).to_lowercase());
            }
            l.extend(
                v.acknowledge
                    .iter()
                    .map(|(n, k)| format!("확인한 항목: {n} ({k})")),
            );
            l.extend(val.warnings.iter().map(|w| format!("경고: {w}")));
            // 원문은 맨 끝, 30줄까지 (digest 는 params 전체를 덮으므로 잘린 뒷부분도 바뀌면 거부된다)
            crate::change::section_n(
                &mut l,
                "정책 원문:".into(),
                v.yaml.lines().map(|x| x.to_string()).collect(),
                crate::change::YAML_LINES_MAX,
            );
        }
        Method::PolicyRollback | Method::PolicyPause | Method::PolicyReleaseAddressBlocks => {
            let v: PolicyRef = from(p)?;
            let what = match method {
                Method::PolicyRollback => "되돌리기",
                Method::PolicyPause => "일시 중지",
                _ => "주소 차단 해제",
            };
            if method == Method::PolicyReleaseAddressBlocks
                && (v.policy_id == 0 || v.filter_id.is_some())
            {
                // D036: 승인 창에도 풀릴 주소를 하나하나
                let blocks = world.engine.address_blocks().unwrap_or_default();
                let picked: Vec<_> = blocks
                    .iter()
                    .filter(|b| v.filter_id.is_none_or(|f| f == b.filter_id))
                    .collect();
                l.push(if v.filter_id.is_some() {
                    "주소 차단 1건 해제".into()
                } else {
                    format!("모든 정책의 24시간 주소 차단 {}건 해제", picked.len())
                });
                for b in picked {
                    l.push(format!("  {}", crate::policy_view::address_text(&b.spec)));
                }
            } else {
                let name = world
                    .engine
                    .store
                    .policy(v.policy_id)
                    .ok()
                    .flatten()
                    .map(|r| r.name)
                    .unwrap_or_else(|| "(없음)".into());
                l.push(format!(
                    "정책 #{} '{}' {}{}",
                    v.policy_id,
                    name,
                    what,
                    v.version.map(|x| format!(" (판 {x})")).unwrap_or_default()
                ));
            }
        }
        Method::JudgeFeedbackNormal => {
            let v: FeedbackNormalParams = from(p)?;
            let label = world
                .graph
                .node(v.root)
                .ok()
                .map(|n| n.label.clone())
                .unwrap_or_default();
            l.push(format!(
                "사건 #{} {} 를 '평소 행동'으로 학습 (같은 행동은 다음부터 덜 의심합니다)",
                v.root, label
            ));
        }
        Method::SettingsSet | Method::RetentionSet => {
            l.push("설정 변경:".into());
            if let Some(o) = p.as_object() {
                for (k, x) in o.iter().filter(|(k, _)| k.as_str() != "request_id") {
                    l.push(format!("  {k} = {x}"));
                }
            }
            // 첫 실행 관찰실: 이 승인이 정책을 만들거나 지우는지 요약에 밝힌다 (보지 않은 것은 실행하지 않는다)
            if let Some(m) = p
                .get("first_run_watch")
                .and_then(|v| v.as_str())
                .and_then(crate::first_run::Mode::parse)
            {
                let cur = crate::first_run::umbrella(&world.engine.store);
                let state = cur.as_ref().map(|r| r.state);
                if m == crate::first_run::Mode::Block {
                    if !matches!(
                        state,
                        Some(engine::State::Applied | engine::State::Confirmed)
                    ) {
                        l.push(format!("정책 '{}'(첫 실행 관찰실 차단)을 만듭니다 — 처음 실행된 인터넷에서 받은 서명 없는 프로그램의 나가는 연결을 관찰 시간 동안 막습니다. 적용 뒤 60초 안에 유지를 확인해야 켜집니다", crate::first_run::UMBRELLA_NAME));
                    }
                } else if let Some(r) = cur.filter(|_| {
                    matches!(
                        state,
                        Some(
                            engine::State::Applied
                                | engine::State::Confirmed
                                | engine::State::Paused
                        )
                    )
                }) {
                    let n = world
                        .engine
                        .store
                        .filters_of(r.id)
                        .map(|f| f.len())
                        .unwrap_or(0);
                    l.push(format!(
                        "정책 #{} '{}'(첫 실행 관찰실 차단)과 그 아래 필터 {n}개를 지웁니다",
                        r.id, r.name
                    ));
                }
            }
        }
        _ => {
            return Err(RpcError::with(
                ErrorCode::InvalidParams,
                "맡길 수 없는 메서드",
            ))
        }
    }
    Ok(l)
}

pub fn dispatch(
    world: &mut World,
    id: Id,
    method: Method,
    params: serde_json::Value,
    caller: &Caller,
) -> Response {
    // 개발 서버 D013 캡처: 목록 조회만 빈 응답·오류로(실제 서비스는 dev_force 를 설정하지 않는다)
    if let Some(f) = world.dev_force.as_deref() {
        let list = matches!(
            method,
            Method::StoryEvents
                | Method::StoryToday
                | Method::ConnectionsList
                | Method::ListenersList
                | Method::PolicyList
        );
        if list && f == "busy" {
            // D030-1 캡처: 엔진 대기 시간 초과와 같은 오류(일시 상태 화면)
            return Response::err(
                Some(id),
                RpcError::with(ErrorCode::Busy, "엔진 대기 5초 초과(시연)"),
            );
        }
        if list && f == "error" {
            return Response::err(
                Some(id),
                RpcError::with(ErrorCode::Internal, "시연: 강제 오류"),
            );
        }
        if list && f == "delay" {
            // D015-5: "불러오는 중" 캡처용 2.5초 지연(엔진 스레드를 잠깐 멈춘다 — 개발 서버 전용)
            std::thread::sleep(std::time::Duration::from_millis(2500));
        }
        if list && f == "empty" {
            let v = if method == Method::StoryToday {
                serde_json::json!({ "sentences": [] })
            } else {
                serde_json::json!({ "items": [] })
            };
            return Response::ok(id, v);
        }
    }
    // L030 캐시: 변경 요청(모두 request_id 를 가진다 — 멱등 키)은 판정·이야기를 바꿀 수 있으니 버린다
    if params.get("request_id").is_some() {
        world.judge_cache = None;
        world.invalidate_reads();
        world.judged = None;
    }
    match handle(world, method, params, caller) {
        Ok(v) => Response::ok(id, v),
        Err(e) => Response::err(Some(id), e),
    }
}

fn handle(
    world: &mut World,
    method: Method,
    p: serde_json::Value,
    caller: &Caller,
) -> Result<serde_json::Value, RpcError> {
    use api::methods::*;
    let j = |v: serde_json::Value| Ok(v);
    match method {
        Method::RpcHello => {
            let h: api::rpc::Hello = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            api::rpc::negotiate(h.api)?;
            j(serde_json::to_value(api::rpc::HelloReply {
                server_version: world.server_version.clone(),
                api: api::API_VERSION,
            })
            .unwrap())
        }
        Method::PolicyValidate => {
            let v: PolicyValidateParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let val = world.engine.validate(&v.yaml).map_err(engine_err)?;
            j(serde_json::to_value(ValidationReply {
                errors: val.errors.iter().map(|e| e.to_string()).collect(),
                warnings: val.warnings,
                needs_ack: val
                    .needs_ack
                    .iter()
                    .map(|(n, a)| (n.clone(), ack_name(a).to_string()))
                    .collect(),
            })
            .unwrap())
        }
        Method::PolicyDryrun => {
            // 1차: 검증 + 전개 결과(필터 수·경고)만. 최근 7일 그래프 대입은 실기기 데이터 뒤
            let v: PolicyValidateParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let val = world.engine.validate(&v.yaml).map_err(engine_err)?;
            j(
                serde_json::json!({ "errors": val.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>(), "warnings": val.warnings, "needs_ack": val.needs_ack.len(), "note": "드라이런 영향 보고는 실기기 데이터 뒤" }),
            )
        }
        Method::PolicyApply => {
            let v: PolicyApplyParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let acks: Vec<(String, dsl::Ack)> = v
                .acknowledge
                .iter()
                .map(|(n, k)| (n.clone(), ack_of(k)))
                .collect();
            let r = world
                .engine
                .apply(&v.yaml, &acks, &v.request_id, &actor(caller))
                .map_err(engine_err)?;
            j(serde_json::to_value(apply_reply(r)).unwrap())
        }
        Method::PolicyConfirm => {
            let v: PolicyRef = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            world
                .engine
                .confirm(v.policy_id, v.version.unwrap_or(0), &actor(caller))
                .map_err(engine_err)?;
            j(serde_json::json!({ "ok": true }))
        }
        Method::PolicyRollback => {
            let v: PolicyRef = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            world
                .engine
                .rollback(v.policy_id, v.version, &actor(caller))
                .map_err(engine_err)?;
            j(serde_json::json!({ "ok": true }))
        }
        Method::PolicyPause => {
            let v: PolicyRef = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            world
                .engine
                .pause(v.policy_id, &actor(caller))
                .map_err(engine_err)?;
            j(serde_json::json!({ "ok": true }))
        }
        Method::PolicyReleaseAddressBlocks => {
            let v: PolicyRef = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let n = match v.filter_id {
                Some(fid) => world.engine.release_address_block(fid, &actor(caller)),
                None => world
                    .engine
                    .release_address_blocks(v.policy_id, &actor(caller)),
            }
            .map_err(engine_err)?;
            j(serde_json::json!({ "released": n }))
        }
        Method::PolicyList => {
            let mut rows = Vec::new();
            for st in [
                engine::State::Applied,
                engine::State::Confirmed,
                engine::State::Paused,
                engine::State::Expired,
                engine::State::RolledBack,
            ] {
                for r in world.engine.store.policies_in(st).map_err(engine_err)? {
                    // D006-4: 사람 말 요약·만료·만든 곳(이야기 뿌리면 그 이름과 시각)·상태 한국어
                    let st_s = serde_json::to_value(st)
                        .ok()
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                        .unwrap_or_default();
                    let (st_ko, st_tip) = crate::policy_view::state_ko(&st_s);
                    let created_ts = world
                        .engine
                        .store
                        .history_of(r.id)
                        .ok()
                        .and_then(|h| h.first().map(|x| x.0));
                    let origin = match crate::policy_view::story_root(&r.name) {
                        Some(root) => {
                            let label = world.graph.node(root).map(|n| n.label).unwrap_or_default();
                            serde_json::json!({ "kind": "story", "root": root, "label": label })
                        }
                        // 첫 실행 관찰실 우산 정책(설정에서 '알리고 인터넷 막기'를 고를 때 관리자 요청으로 생긴다)
                        None if r.name.starts_with(crate::first_run::POLICY_PREFIX) => {
                            serde_json::json!({ "kind": crate::first_run::KIND })
                        }
                        None => serde_json::json!({ "kind": "manual" }),
                    };
                    let umbrella = r.name == crate::first_run::UMBRELLA_NAME;
                    let summary = if umbrella {
                        "첫 실행 관찰실: 처음 실행된 인터넷에서 받은 서명 없는 프로그램의 나가는 연결을 관찰 시간 동안 차단".to_string()
                    } else {
                        crate::policy_view::summary(&r.yaml)
                    };
                    let mut row = serde_json::json!({
                        "id": r.id, "name": r.name, "state": st, "version": r.version, "confirm_deadline": r.confirm_deadline,
                        "state_ko": st_ko, "state_tip": st_tip,
                        "summary": summary,
                        "expires": if umbrella { None } else { crate::policy_view::expires(&r.yaml) },
                        "created_ts": created_ts,
                        "origin": origin,
                    });
                    // ACL 정책 관리: 정책 화면의 ACL 표가 지금 걸린 규칙을 다시 읽는다(원문 YAML — 사용자가 쓴 것)
                    if r.name == engine::ACL_RECORD_NAME {
                        row["acl_yaml"] = serde_json::Value::String(r.yaml.clone());
                    }
                    if umbrella {
                        // 우산 아래 지금 걸린 기한부 실행 파일 차단 (필터 번호로 하나씩 풀 수 있다: policy.release_address_blocks filter_id)
                        let kids: Vec<serde_json::Value> = world
                            .engine
                            .store
                            .filters_of(r.id)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|f| f.expires_at.is_some())
                            .map(|f| serde_json::json!({ "filter_id": f.filter_id, "path": f.spec.app_path, "expires_at": f.expires_at }))
                            .collect();
                        row["child_blocks"] = serde_json::Value::Array(kids);
                    }
                    rows.push(row);
                }
            }
            // D032-3: 지금 걸려 있는 기한부 주소 차단 수 — 0 이면 화면이 "주소 차단 모두 해제" 단추를 숨긴다
            let mut v = serde_json::to_value(Page {
                items: rows,
                next: None,
            })
            .unwrap();
            // D036: 해제될 것이 무엇인지 — 주소·정책·만료(엔진 unix 초)
            let blocks = world.engine.address_blocks().map_err(engine_err)?;
            v["address_blocks"] = serde_json::json!(blocks.len());
            v["address_block_items"] = serde_json::Value::Array(
                blocks
                    .iter()
                    .map(|b| {
                        let pname = world.engine.store.policy(b.policy_id).ok().flatten().map(|r| r.name).unwrap_or_default();
                        serde_json::json!({ "filter_id": b.filter_id, "policy_id": b.policy_id, "policy_name": pname,
                            "address": crate::policy_view::address_text(&b.spec), "expires_at": b.expires_at })
                    })
                    .collect(),
            );
            j(v)
        }
        Method::PolicyHistory => {
            let pid = p
                .get("policy_id")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| RpcError::with(ErrorCode::InvalidParams, "policy_id"))?;
            let h = world.engine.store.history_of(pid).map_err(engine_err)?;
            let items: Vec<serde_json::Value> = h.into_iter().map(|(ts, a, r, who)| serde_json::json!({ "ts": ts, "action": a, "result": r, "actor": who })).collect();
            j(serde_json::to_value(Page { items, next: None }).unwrap())
        }
        Method::StoryEvents => {
            let v: StoryEventsParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            // L030: 판정은 무겁다(노트북 24h 10초) — 30초 캐시. 같은 since_ts 면 다시 계산하지 않는다
            // L052(노트북 이야기 목록 평균 3.4초): 어느 단계가 느린지 진단 처리 시간 표에 나누어 남긴다
            let t_judge = std::time::Instant::now();
            let stories = judged_stories(world, v.since_ts)
                .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?;
            world
                .timings
                .record("이야기 목록: 판정 결과", t_judge.elapsed());
            let t_narr = std::time::Instant::now();
            let min = match v.level_min.as_str() {
                "normal" => 0,
                "watch" => 40,
                _ => 70,
            };
            let scope = caller.scope();
            // A30: 다른 사용자 세션의 프로세스가 든 이야기는 통째로 숨긴다
            let kept: Vec<judge::Story> = stories
                .iter()
                .filter(|s| {
                    s.score as i32 >= min
                        && scope.process_visible(&world.graph, s.root)
                        && scope.edges_visible(&world.graph, &s.edges)
                })
                .cloned()
                .collect();
            let cur = v.cursor.normalized();
            let start = cur
                .after
                .as_deref()
                .and_then(|a| a.parse::<usize>().ok())
                .unwrap_or(0);
            // L043·L044(대시보드 7~10초): 전에는 해당 수준 사건 전부를 매 호출 문장으로 만들었다. 이제 이 쪽에 보일 것만,
            // 같은 판정 결과(Arc)·같은 화법이면 만든 문장을 다시 쓴다(판정은 1분마다 바뀐다)
            let page_stories: Vec<judge::Story> = kept
                .iter()
                .skip(start)
                .take(cur.limit + 1)
                .cloned()
                .collect();
            let gen = if v.since_ts == 0 {
                world.judged_gen
            } else {
                world.judge_cache_gen
            };
            let mut nar: Vec<story::events::Narrative> = Vec::with_capacity(page_stories.len());
            for s in &page_stories {
                nar.push(narrative_cached(world, gen, v.since_ts, &v.voice, s)?);
            }
            world.timings.record("이야기 목록: 문장", t_narr.elapsed());
            let t_extra = std::time::Instant::now();
            let slice: Vec<serde_json::Value> = nar
                .iter()
                .map(|n| {
                    let mut v = serde_json::to_value(n).unwrap();
                    // D020-1: 뿌리가 Windows 핵심 프로세스면 화면이 "끊기" 대신 "이 접속지만 차단"을 보이고 서명·위치를 밝힌다.
                    // (끊기 계획도 이미 핵심 프로세스는 막거나 끝내지 않는다 — cut.rs)
                    let root_kind = world.graph.node(n.root).map(|x| x.kind).unwrap_or_default();
                    // 정상 처리(judge.feedback_normal)는 파일 뿌리만 된다 — 화면이 단추를 숨긴다
                    // L063: 금고 경비 사건(프로세스 뿌리)도 정상 처리 가능(그 판정에 한정)
                    let vault = page_stories.iter().any(|s| s.root == n.root && s.root_kind == judge::RootKind::VaultAccess);
                    v["feedback_ok"] = serde_json::json!(root_kind == "file" || vault);
                    // 프로세스 뿌리만 process_detail(파일 노드에도 Ok 를 돌려주지만 경로가 빈다 — L046 "위치 줄 없음")
                    let pd = if root_kind == "process" { graph::views::process_detail(&world.graph, n.root, 0).ok() } else { None };
                    if let Some(d) = pd {
                        v["root_core"] = serde_json::json!(graph::views::is_system_image(&d.image));
                        v["root_image"] = serde_json::json!(d.image);
                        v["root_signature"] = d.signature.clone().unwrap_or(serde_json::Value::Null);
                    } else if let Ok(f) = world.graph.node(n.root) {
                        // D039-2: 뿌리가 파일(서명 없는 실행 파일 등)이면 경로·서명은 파일 노드에, 이름 단추는 그 파일로 실행된 가장 최근 프로세스로
                        if f.kind == "file" {
                            v["root_image"] = serde_json::json!(f.key);
                            v["root_signature"] = serde_json::json!({ "signer": f.attr("signer"), "sig_status": f.attr("sig_status"), "issuer": f.attr("issuer") });
                            let ex: Option<(i64, i64, i64, i64)> = world
                                .graph
                                .conn()
                                .query_row(
                                    "SELECT COUNT(*), MIN(ts), MAX(ts), (SELECT dst FROM edges WHERE src = ?1 AND rel = 'executed_as' ORDER BY ts DESC LIMIT 1) FROM edges WHERE src = ?1 AND rel = 'executed_as'",
                                    [f.id],
                                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                                )
                                .ok();
                            if let Some((c, first, last, latest)) = ex {
                                v["root_exec"] = serde_json::json!({ "count": c, "first_ts": first, "last_ts": last, "latest_proc": latest });
                            }
                        }
                    }
                    // 첫 실행 관찰실(17판 23-2 ①): 뿌리 실행 파일을 관찰한 기록이 있으면 카드에 사실 한 줄
                    if let Some(w) = v["root_image"]
                        .as_str()
                        .and_then(|path| crate::first_run::watch_of(&world.graph, path))
                    {
                        v["first_run_watch"] = serde_json::to_value(w).unwrap_or_default();
                    }
                    // D022-4: 접속지의 등록 국가(발생 시각 목록 줄)
                    if let Some(w) = n
                        .egress_node
                        .and_then(|id| world.graph.node(id).ok())
                        .and_then(|nd| nd.attr("ip").and_then(|ip| ip.as_str().map(|s| s.to_string())))
                        .and_then(|ip| geo::global().lookup_str(&ip))
                    {
                        v["egress_where"] = serde_json::to_value(w).unwrap_or_default();
                    }
                    v
                })
                .collect();
            let page = Page::from_overfetch(
                slice.into_iter().enumerate().collect::<Vec<_>>(),
                cur.limit,
                |(i, _)| (start + i + 1).to_string(),
            );
            world
                .timings
                .record("이야기 목록: 부가 정보", t_extra.elapsed());
            // 저장 실패로 버린 구간 (17차 Q3): 이야기 위에 "기록 일부 누락" 표시
            let t_gaps = std::time::Instant::now();
            let gaps =
                graph::views::gaps_between(&world.graph, v.since_ts, i64::MAX).unwrap_or_default();
            world
                .timings
                .record("이야기 목록: 기록 없는 구간", t_gaps.elapsed());
            j(
                serde_json::json!({ "items": page.items.into_iter().map(|(_, v)| v).collect::<Vec<_>>(), "next": page.next, "gaps": gaps }),
            )
        }
        Method::StoryToday => {
            // 구조 개선 C: 읽기 작업자가 없을 때(메모리 DB 테스트·작업자 실패)만 엔진에서 직접
            let now = world.engine_wall();
            crate::reads::story_today(&world.graph, &mut world.read, now, p, caller)
        }
        Method::StoryExplain => {
            let v: EdgeRef = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            if !caller.scope().edges_visible(&world.graph, &[v.edge_id]) {
                return Err(out_of_scope());
            }
            let ev = world
                .graph
                .evidence_of(v.edge_id)
                .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?;
            j(serde_json::json!({ "edge_id": v.edge_id, "evidence": ev }))
        }
        Method::GraphTimeline => {
            let v: TimeRange = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let b = graph::query::timeline(&world.graph, v.from_ts, v.to_ts, v.buckets)
                .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?;
            j(serde_json::to_value(b).unwrap())
        }
        Method::GraphRewind => {
            let v: NodeQuery = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let scope = caller.scope();
            if !scope.process_visible(&world.graph, v.node_id) {
                return Err(out_of_scope());
            }
            let r: Vec<_> = graph::query::rewind(&world.graph, v.node_id, v.max_depth)
                .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?
                .into_iter()
                .filter(|st| {
                    scope.process_visible(&world.graph, st.node.id)
                        && st
                            .via
                            .as_ref()
                            .is_none_or(|e| scope.edges_visible(&world.graph, &[e.id]))
                })
                .collect();
            j(serde_json::to_value(r).unwrap())
        }
        Method::GraphNeighbors => {
            let p_cap = p
                .get("max_branches")
                .and_then(|x| x.as_u64())
                .map(|x| x as usize);
            let v: NodeQuery = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let cap = p_cap.unwrap_or(MINDMAP_CAP).clamp(1, MINDMAP_CAP);
            let scope = caller.scope();
            if !scope.process_visible(&world.graph, v.node_id) {
                return Err(out_of_scope());
            }
            let (r, truncated) =
                graph::query::project_capped(&world.graph, v.node_id, v.max_depth, cap)
                    .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?;
            // A30: 다른 사용자 세션의 프로세스와 그 프로세스를 거쳐 닿은 가지는 뺀다
            let r: Vec<_> = r
                .into_iter()
                .filter(|b| {
                    scope.process_visible(&world.graph, b.node.id)
                        && b.via
                            .as_ref()
                            .is_none_or(|e| scope.edges_visible(&world.graph, &[e.id]))
                })
                .collect();
            // 접속지 노드에 "어디"(주소 종류·등록 국가·ASN)를 붙인다 — 마인드맵 라벨·국기
            let branches: Vec<serde_json::Value> = r
                .iter()
                .map(|b| {
                    let mut v = serde_json::to_value(b).unwrap_or_default();
                    if b.node.kind == "remote" {
                        if let Some(w) = b
                            .node
                            .attr("ip")
                            .and_then(|ip| ip.as_str().map(|s| s.to_string()))
                            .and_then(|ip| geo::global().lookup_str(&ip))
                        {
                            v["where"] = serde_json::to_value(w).unwrap_or_default();
                        }
                    }
                    v
                })
                .collect();
            // D012: 접속지 노드에도 "오늘 처음"(ASN·등록 국가) — 마인드맵에서 이것만 주황 테두리
            let now = world.engine_wall();
            let (new_asn, new_cc) =
                crate::reads::new_today(&world.graph, &mut world.read, now, &branches);
            let branches: Vec<serde_json::Value> = branches
                .into_iter()
                .map(|mut v| {
                    if v.get("where").is_some_and(|w| !w.is_null()) {
                        let asn = v["where"]["asn"].as_u64().map(|a| a as u32);
                        let cc = v["where"]["cc"].as_str().map(|s| s.to_string());
                        v["new_asn"] = serde_json::json!(asn.is_some_and(|a| new_asn.contains(&a)));
                        v["new_cc"] = serde_json::json!(cc.is_some_and(|c| new_cc.contains(&c)));
                    }
                    v
                })
                .collect();
            j(serde_json::json!({ "branches": branches, "truncated": truncated, "cap": cap }))
        }
        Method::JudgeFeedbackNormal => {
            let v: FeedbackNormalParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let node = world
                .graph
                .node(v.root)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            // 판정은 뿌리 **파일** 키로만 정상 처리를 대조한다. 프로세스 뿌리((다) 고립 svchost·(라)·(바) 복구 수단 삭제)를 받으면
            // 전에는 기록만 하고 아무 효과가 없었다(화면은 성공). 실행 파일로 바꿔 기록하면 svchost.exe·vssadmin.exe 전체가 정상이 되므로
            // 정상 처리 단위가 정해질 때까지 거부한다(10판 구현 중 발견)
            if node.kind != "file" {
                // L063: 브라우저 금고 경비 사건(프로세스 뿌리)만 예외 — 그 실행 파일의 금고 경비 판정만 정상으로
                let vault = world.judged.as_ref().is_some_and(|(_, ss)| {
                    ss.iter()
                        .any(|s| s.root == v.root && s.root_kind == judge::RootKind::VaultAccess)
                });
                let image = if vault {
                    graph::views::image_file_of(&world.graph, v.root)
                } else {
                    None
                };
                let Some(f) = image else {
                    return Err(RpcError::with(ErrorCode::InvalidParams, "이 종류의 사건(프로세스에서 시작한 사건)은 아직 '이건 정상입니다'를 지원하지 않습니다".to_string()));
                };
                world
                    .baseline
                    .mark_normal_vault(&world.graph, &f)
                    .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?;
                world.judge_inc.invalidate();
                return j(serde_json::json!({ "ok": true, "scope": "vault" }));
            }
            world
                .baseline
                .mark_normal(&world.graph, &node)
                .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?;
            // 갈래 C: 다음 주기 판정은 전체 다시(점수는 캐시하지 않아 결과에는 필요 없지만 안전망 — 드문 일)
            world.judge_inc.invalidate();
            j(serde_json::json!({ "ok": true }))
        }
        Method::JudgeBaselineStatus => {
            let learned = world
                .baseline
                .pc_learned(&world.graph)
                .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?;
            j(
                serde_json::json!({ "pc_learned": learned, "learn_days": judge::baseline::LEARN_DAYS }),
            )
        }
        Method::SettingsGet => {
            let mut v = serde_json::to_value(&world.settings).unwrap();
            // 첫 실행 관찰실 우산 정책의 지금 상태 — 설정 화면이 "막기가 켜졌는지"를 사실대로 보인다
            v["first_run_umbrella"] = match crate::first_run::umbrella(&world.engine.store) {
                Some(r) => {
                    serde_json::json!({ "policy_id": r.id, "version": r.version, "state": r.state })
                }
                None => serde_json::Value::Null,
            };
            j(v)
        }
        Method::RetentionGet => {
            // 27차: 실제로 적용되는 정책(설정 + 기본값)과 마지막 정리 결과
            let mut v = serde_json::to_value(crate::runtime::retention_policy(world)).unwrap();
            v["last"] = world
                .graph
                .get_meta("retention_last")
                .ok()
                .flatten()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null);
            j(v)
        }
        Method::SettingsSet | Method::RetentionSet => {
            // 첫 실행 관찰실(방식 나): 모드를 바꾸는 요청이면 이 관리자 요청으로 우산 정책을 만들거나 지운다.
            // 우산 적용이 실패하면(가드·DB 등) 설정도 저장하지 않는다
            let mut policies: Vec<serde_json::Value> = Vec::new();
            if let Some(m) = p
                .get("first_run_watch")
                .and_then(|v| v.as_str())
                .and_then(crate::first_run::Mode::parse)
            {
                let rid = p
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if let Some(r) =
                    crate::first_run::sync_umbrella(&mut world.engine, m, &rid, &actor(caller))
                        .map_err(engine_err)?
                {
                    // 승인 도우미·UI 가 이 목록으로 60초 확인을 한다(policy.apply·cut.apply 와 같은 모양)
                    policies.push(serde_json::to_value(apply_reply(r)).unwrap());
                }
            }
            if let Some(obj) = p.as_object() {
                for (k, v) in obj {
                    if k != "request_id" {
                        world.settings.insert(k.clone(), v.clone());
                    }
                }
            }
            // 재시작 뒤에도 남게 그래프 DB meta 에 저장
            let s = serde_json::to_string(&world.settings).unwrap();
            world.graph.set_meta("settings", &s).map_err(internal)?;
            if policies.is_empty() {
                j(serde_json::json!({ "ok": true }))
            } else {
                j(serde_json::json!({ "ok": true, "policies": policies }))
            }
        }
        Method::ChangeStage => {
            let v: ChangeStageParams = from(&p)?;
            let inner = Method::parse(&v.method)?;
            // 맡길 때 미리 검증: 대상 없음·needs_ack 미확인·YAML 오류는 승인 창을 띄우기 전에 UI 로 돌려준다
            summarize(world, inner, &v.params)?;
            let now = world.engine_wall();
            let id = world.changes.stage(inner, v.params, actor(caller), now);
            j(serde_json::json!({ "change_id": id, "expires_in": crate::change::CHANGE_TTL_SECS }))
        }
        Method::ChangeGet => {
            let v: ChangeRef = from(&p)?;
            let now = world.engine_wall();
            let (inner, params, staged_by, staged_at) = {
                let s = world
                    .changes
                    .get(&v.change_id, now)
                    .ok_or_else(|| crate::change::not_found(&v.change_id))?;
                if !matches!(s.state, crate::change::ChangeState::Pending) {
                    return Err(RpcError::with(ErrorCode::InvalidParams, "이미 처리된 변경"));
                }
                s.mark_opened(now);
                (
                    s.method,
                    s.params.clone(),
                    s.staged_by.clone(),
                    s.opened_at.unwrap_or(s.staged_at),
                )
            };
            let (lines, digest) =
                crate::change::finish(inner, summarize(world, inner, &params)?, &params);
            j(
                serde_json::json!({ "method": inner.name(), "lines": lines, "digest": digest, "staged_by": crate::change::clean_line(&staged_by), "expires_in": crate::change::CHANGE_TTL_SECS - (now - staged_at) }),
            )
        }
        Method::ChangeCommit => {
            let v: ChangeCommitParams = from(&p)?;
            let now = world.engine_wall();
            let (inner, params, staged_by, state) = {
                let s = world
                    .changes
                    .get(&v.change_id, now)
                    .ok_or_else(|| crate::change::not_found(&v.change_id))?;
                (
                    s.method,
                    s.params.clone(),
                    s.staged_by.clone(),
                    s.state.clone(),
                )
            };
            match state {
                // 같은 승인을 두 번 눌러도 한 번만 (도우미 재시도)
                crate::change::ChangeState::Done { result, .. } => {
                    return j(serde_json::json!({ "method": inner.name(), "result": result }))
                }
                crate::change::ChangeState::Failed { error } => {
                    return Err(RpcError::with(ErrorCode::InvalidParams, error))
                }
                crate::change::ChangeState::Pending => {}
            }
            // 보여 준 요약과 지금 요약이 같아야 실행한다 (보지 않은 것은 실행하지 않는다)
            let (_, digest) =
                crate::change::finish(inner, summarize(world, inner, &params)?, &params);
            if digest != v.digest {
                return Err(crate::change::changed());
            }
            // 기록에는 승인한 쪽과 맡긴 쪽을 함께 남긴다
            let approver = Caller {
                pid: caller.pid,
                image: format!("{} (승인; 맡김: {})", caller.image, staged_by),
                is_admin: caller.is_admin,
                session: caller.session,
            };
            let out = handle(world, inner, params, &approver);
            let s = world
                .changes
                .get(&v.change_id, now)
                .ok_or_else(|| crate::change::not_found(&v.change_id))?;
            match out {
                Ok(result) => {
                    s.state = crate::change::ChangeState::Done {
                        result: result.clone(),
                        committed_by: actor(&approver),
                    };
                    j(serde_json::json!({ "method": inner.name(), "result": result }))
                }
                Err(e) => {
                    // 엔진 거부(가드 등)는 같은 내용으로 다시 해도 같으므로 실패로 닫는다
                    s.state = crate::change::ChangeState::Failed {
                        error: e.message.clone(),
                    };
                    Err(e)
                }
            }
        }
        Method::CollectorHealth => {
            // C1: 원인을 단정하지 않는 사실만 — 마지막 사건 시각, 최근 24시간 기록 손실 구간, 시계 변경 시각
            let now = world.engine_wall();
            let now_ft = now * 10_000_000 + 116_444_736_000_000_000;
            let day_ft = 86_400 * 10_000_000i64;
            let last_event_ft: Option<i64> = world
                .graph
                .conn()
                // L028: MAX(ts)+WHERE 는 전체 훑기 — 시각 색인을 뒤에서부터 읽다 첫 비스냅샷 행에서 멈춘다
                .query_row(
                    "SELECT ts FROM raw_events WHERE source <> 'snapshot' ORDER BY ts DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            let gaps = graph::views::gaps_between(&world.graph, now_ft - day_ft, now_ft)
                .unwrap_or_default();
            let lost: i64 = gaps.iter().map(|g| g.events).sum();
            let clock: Vec<i64> = world
                .clock_changes
                .iter()
                .copied()
                .filter(|t| *t >= now - 86_400)
                .collect();
            if let Some(d) = &world.dev_health {
                // 개발 서버 시연: 마지막 사건을 "방금"으로, 손실·시계 변경은 시연값
                let mut v = d.clone();
                v["now"] = serde_json::json!(now);
                // "stalled" 시연(D013 수집 안 됨): 마지막 사건 없음
                v["last_event_ft"] = if v["stalled"] == serde_json::json!(true) {
                    serde_json::Value::Null
                } else {
                    serde_json::json!(now_ft - 3 * 10_000_000)
                };
                if v.get("defender").is_none() {
                    // 시연: Windows 기본값(CFA 설정 없음 = 꺼짐, 실시간 보호 켜짐)
                    v["defender"] = crate::defender::status_json(None, None, Some(0), None);
                }
                return j(v);
            }
            j(serde_json::json!({
                "now": now,
                "last_event_ft": last_event_ft,
                "lost_24h": lost,
                "gaps_24h": gaps,
                "clock_changes_24h": clock,
                // 진단 "처리 시간"(서비스 시작 뒤, 최대가 큰 순 15개) — 느린 곳을 diag 없이 찾는다
                "timings": world.timings.to_json(15),
                // 10판 5-9 (3): Windows 기본 보호 설정 값(레지스트리). Windows 아니면 null
                "defender": crate::defender::read(),
                // 29차 미결: 명령줄 수집(커널 세션) 상태. 수집기가 없으면(시험·개발 서버) null
                "cmdline": crate::defender::COLLECTOR_COUNTS.get().map(|f| crate::defender::cmdline_counts(&f())),
            }))
        }
        Method::ServiceEvents => {
            let v: api::methods::ServiceEventsParams = from(&p)?;
            let since = world.engine_wall() - v.since_secs;
            let rows = world
                .engine
                .list_events(since, v.limit)
                .map_err(engine_err)?;
            let scope = caller.scope();
            let items: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|e| service_event_json(&world.graph, e, scope))
                .collect();
            j(serde_json::to_value(Page { items, next: None }).unwrap())
        }
        Method::ChangeResult => {
            let v: ChangeRef = from(&p)?;
            let now = world.engine_wall();
            let state = world
                .changes
                .get(&v.change_id, now)
                .map(|s| s.state.clone());
            let Some(state) = state else {
                return j(serde_json::json!({ "state": "expired" }));
            };
            match state {
                crate::change::ChangeState::Pending => j(serde_json::json!({ "state": "pending" })),
                crate::change::ChangeState::Failed { error } => {
                    j(serde_json::json!({ "state": "failed", "error": error }))
                }
                crate::change::ChangeState::Done { result, .. } => {
                    // 결과에 든 정책의 지금 상태 (도우미가 60초 확인을 했는지)
                    let mut ids: Vec<i64> = Vec::new();
                    if let Some(id) = result.get("policy_id").and_then(|x| x.as_i64()) {
                        ids.push(id);
                    }
                    for pol in result
                        .get("policies")
                        .and_then(|x| x.as_array())
                        .into_iter()
                        .flatten()
                    {
                        if let Some(id) = pol.get("policy_id").and_then(|x| x.as_i64()) {
                            ids.push(id);
                        }
                    }
                    let states: Vec<serde_json::Value> = ids
                        .iter()
                        .map(|id| serde_json::json!({ "policy_id": id, "state": world.engine.store.policy(*id).ok().flatten().map(|r| serde_json::to_value(r.state).unwrap_or_default()) }))
                        .collect();
                    j(serde_json::json!({ "state": "done", "result": result, "policies": states }))
                }
            }
        }
        // 구독은 핸들러가 Subscribe 명령으로 처리한다. 여기 오면 등록 완료 응답만
        Method::ConnectionsSubscribe | Method::EventsSubscribe => {
            j(serde_json::json!({ "subscribed": true }))
        }
        // 1차 골격에서 아직 없음 (연결 테이블·리스너·프로세스 상세는 수집기 연결 뒤, 끊기 preview/apply 는 dsl 전개 경로로)
        Method::ConnectionsList => {
            let now = world.engine_wall();
            crate::reads::connections_list(&world.graph, &mut world.read, now, p, caller)
        }
        Method::InstallsList => {
            let v: api::methods::InstallsParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            // 읽기만(설치 엑스레이는 판정하지 않는다). 보이는 범위 밖 프로세스는 빼고 센다
            let since_ft = (world.engine_wall() - v.days as i64 * 86_400) * 10_000_000
                + 116_444_736_000_000_000;
            // L060: 부모 연결 없이 이어 시작한 설치 과정은 시간으로 묶는다(graph::install::installs)
            let scope = caller.scope();
            // L069: 주기 작업이 미리 계산한 것을 읽는다. 아직 한 번도 계산 전(시작 직후)이면 그때만 바로 계산
            let items = if world.install_cache.primed {
                world.install_cache.list(since_ft, v.limit as usize, |r| {
                    scope.process_visible(&world.graph, r)
                })
            } else {
                graph::install::installs(&world.graph, since_ft, v.limit as usize, 300, |r| {
                    scope.process_visible(&world.graph, r)
                })
                .map_err(internal)?
            };
            j(serde_json::json!({ "items": items }))
        }
        Method::LedgerGet => {
            let v: api::methods::LedgerParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            // 관찰 대상으로 기록된 프로세스만(아무 프로세스의 자손 트리를 여는 통로가 되지 않게), 보이는 범위 검사
            let watched: bool = world
                .graph
                .conn()
                .query_row(
                    "SELECT 1 FROM first_run_watch WHERE proc_node = ?1",
                    [v.node_id],
                    |_| Ok(()),
                )
                .is_ok();
            if !watched || !caller.scope().process_visible(&world.graph, v.node_id) {
                return Err(RpcError::with(
                    ErrorCode::InvalidParams,
                    "관찰 대상이 아닙니다".to_string(),
                ));
            }
            // 자손 300까지(상한을 넘으면 접속·쓰기를 한 자손 먼저 — install_xray)
            let run =
                graph::install::install_xray(&world.graph, v.node_id, 300).map_err(internal)?;
            // 33차 Q1: 대리 실행(예약 작업·WMI·서비스)으로 이어 적은 파일 — 추정. 관찰 기간(시작~끝) 안에서 뿌리 꼬리표로
            let (start, until): (i64, i64) = world
                .graph
                .conn()
                .query_row(
                    "SELECT start_ts, until_ts FROM first_run_watch WHERE proc_node = ?1",
                    [v.node_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap_or((0, 0));
            let node = world.graph.node(v.node_id).map_err(internal)?;
            let root = node
                .key
                .rsplit_once('@')
                .and_then(|(p, t)| Some((p.parse::<u32>().ok()?, t.parse::<i64>().ok()?)));
            let inferred = match root {
                Some(r) => graph::ledger::inferred_files(
                    &world.graph,
                    r,
                    crate::runtime::unix_to_filetime(start),
                    // 35차 Q2: 관찰이 끝난 뒤(재부팅 뒤 포함) 이은 작업·서비스가 실행돼 적힌 것까지 — 지금까지
                    crate::runtime::unix_to_filetime(world.engine_wall().max(until + 60)),
                    200,
                )
                .map_err(internal)?,
                None => Vec::new(),
            };
            let inferred: Vec<serde_json::Value> = inferred
                .into_iter()
                .map(|(path, source)| serde_json::json!({ "path": path, "bulk": source.contains(":bulk:") }))
                .collect();
            j(serde_json::json!({ "run": run, "inferred": inferred }))
        }
        Method::AgentsList => {
            let v: api::methods::AgentsParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            // 읽기만(판정하지 않는다). 미리 계산 전(시작 직후 몇 분)이면 빈 목록과 ready=false — 조회 때 계산하지 않는다
            let since_ft =
                crate::runtime::unix_to_filetime(world.engine_wall() - v.days as i64 * 86_400);
            let scope = caller.scope();
            let (ready, mut items): (bool, Vec<&graph::agent::AgentRun>) = match &world.agent_cache
            {
                Some((_, all)) => (
                    true,
                    all.iter()
                        // 기간 안에 시작했거나 그 뒤까지 일한 것(아직 도는 데스크톱 앱 포함)
                        .filter(|a| a.run.last_ts >= since_ft || a.run.start_ts >= since_ft)
                        .filter(|a| scope.process_visible(&world.graph, a.run.root))
                        .collect(),
                ),
                None => (false, Vec::new()),
            };
            // 화면 검수 7: 잘렸는지 알 수 있게 전체 건수도(미리 계산 상한 50 안에서)
            let total = items.len();
            items.truncate(v.limit as usize);
            j(serde_json::json!({ "ready": ready, "items": items, "total": total }))
        }
        Method::NetInterfaces => {
            let items = world
                .host
                .interfaces()
                .map_err(|e| RpcError::with(ErrorCode::Internal, e))?;
            j(serde_json::json!({ "items": items }))
        }
        Method::ListenersList => {
            let ls = world
                .host
                .listeners()
                .map_err(|e| RpcError::with(ErrorCode::Internal, e))?;
            // 리스닝 PID → 그래프의 이미지 (가장 최근 같은 PID)
            let now_ft = crate::runtime::unix_to_filetime(world.engine_wall());
            let scope = caller.scope();
            let items: Vec<serde_json::Value> = ls
                .into_iter()
                .filter(|l| world.graph.latest_process_by_pid(l.pid, now_ft).ok().flatten().is_none_or(|n| scope.process_visible(&world.graph, n)))
                .map(|l| {
                    let node = world.graph.latest_process_by_pid(l.pid, now_ft).ok().flatten();
                    let image = node.and_then(|id| world.graph.node(id).ok()).and_then(|n| n.attr("image")).and_then(|v| v.as_str().map(|s| s.to_string()));
                    serde_json::json!({ "proto": l.proto, "laddr": l.laddr, "lport": l.lport, "pid": l.pid, "any_addr": l.any_addr, "process_id": node, "image": image })
                })
                .collect();
            j(serde_json::json!({ "items": items }))
        }
        Method::ProcessDetail => {
            let v: NodeQuery = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let n = world.graph.node(v.node_id).map_err(|_| {
                RpcError::with(ErrorCode::InvalidParams, format!("없음: {}", v.node_id))
            })?;
            if !caller.scope().process_visible(&world.graph, v.node_id) {
                return Err(out_of_scope());
            }
            if n.kind != "process" {
                return Err(RpcError::with(
                    ErrorCode::InvalidParams,
                    format!("프로세스 노드가 아님: {}", n.kind),
                ));
            }
            let d = graph::views::process_detail(&world.graph, v.node_id, 200).map_err(internal)?;
            let rewind =
                graph::query::rewind(&world.graph, v.node_id, v.max_depth).map_err(internal)?;
            let mut out = serde_json::to_value(d).unwrap();
            out["create_ft"] = out["create_ts"].take();
            out["rewind"] = serde_json::to_value(rewind).unwrap();
            // D025: 핵심 프로세스(끊기 대신 "이 접속지만 차단"), 판정 칩(최근 판정에 이 프로세스가 뿌리인 사건), 접속·받은 연결의 "어디"
            let image = out["image"].as_str().unwrap_or_default().to_string();
            out["core"] = serde_json::json!(graph::views::is_system_image(&image));
            // 구조 개선 B: 주기 판정 결과(story.events 기본과 같은 것)만 읽는다. 시작 직후 비었으면 쓰지 않는 판정으로 한 번 채운다
            let judged = judged_stories(world, 0).ok();
            // D027-2: 이 프로세스가 뿌리이거나, 뿌리 파일(executed_as)로 실행된 주인공이면 그 사건
            let exe_file: Option<i64> = world
                .graph
                .conn()
                .query_row(
                    "SELECT src FROM edges WHERE dst = ?1 AND rel = 'executed_as' LIMIT 1",
                    [v.node_id],
                    |r| r.get(0),
                )
                .ok();
            out["story"] = match judged.as_ref().and_then(|s| {
                s.iter()
                    .find(|x| x.root == v.node_id || Some(x.root) == exe_file)
                    .map(|x| (x.score, x.level, x.root))
            }) {
                Some((score, level, root)) => {
                    serde_json::json!({ "score": score, "level": format!("{level:?}"), "root": root })
                }
                None => serde_json::Value::Null,
            };
            for key in ["connections", "inbound"] {
                if let Some(arr) = out[key].as_array_mut() {
                    for r in arr.iter_mut() {
                        let ip = r["node_id"]
                            .as_i64()
                            .and_then(|id| world.graph.node(id).ok())
                            .and_then(|nd| {
                                nd.attr("ip")
                                    .and_then(|x| x.as_str().map(|s| s.to_string()))
                            });
                        if let Some(w) = ip.and_then(|ip| geo::global().lookup_str(&ip)) {
                            r["where"] = serde_json::to_value(w).unwrap_or_default();
                        }
                    }
                }
            }
            j(out)
        }
        Method::CutPreview => {
            let v: CutParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            if !caller.scope().process_visible(&world.graph, v.story_root) {
                return Err(out_of_scope());
            }
            let plan =
                crate::cut::plan_with(&world.graph, v.story_root, &v.also, &|pid, ft, seen| {
                    world.host.live_image(pid, ft, seen)
                })
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e))?;
            let val = if plan.yaml.is_empty() {
                None
            } else {
                world.engine.validate(&plan.yaml).ok()
            };
            let mut out = serde_json::to_value(&plan).unwrap();
            if let Some(val) = val {
                out["validation"] = serde_json::json!({ "errors": val.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>(), "warnings": val.warnings });
            }
            j(out)
        }
        Method::CutApply => {
            let v: CutParams = serde_json::from_value(p)
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
            let rid = v
                .request_id
                .clone()
                .ok_or_else(|| RpcError::with(ErrorCode::InvalidParams, "request_id 필수"))?;
            let plan =
                crate::cut::plan_with(&world.graph, v.story_root, &v.also, &|pid, ft, seen| {
                    world.host.live_image(pid, ft, seen)
                })
                .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e))?;
            if plan.yaml.is_empty() {
                return Err(RpcError::with(
                    ErrorCode::InvalidParams,
                    "끊을 대상이 없습니다 (막을 경로도 접속지도 없음)",
                ));
            }
            let src = Some(dsl::model::Source::Cut);
            // 접속지 (IP·포트·프로토콜) 는 같은 판의 24시간 주소 차단으로 — 한 정책, 한 번의 확인
            let extra: Vec<(String, String, u16, u8)> = plan
                .addresses
                .iter()
                .map(|a| {
                    (
                        format!("{} ({})", a.who, a.why),
                        a.ip.clone(),
                        a.port,
                        a.proto,
                    )
                })
                .collect();
            // 순서: 막고 → 끊는다 (종료 중에 밖으로 나가지 못하게)
            let r = world
                .engine
                .apply_full(&plan.yaml, &[], &rid, &actor(caller), src, &extra)
                .map_err(engine_err)?;
            let applied = vec![serde_json::to_value(apply_reply(r)).unwrap()];
            let mut killed = Vec::new();
            for t in &plan.terminate {
                let outcome = world.host.terminate(t.pid, Some(t.create_ts));
                let _ = world.engine.record_event(
                    "cut_terminate",
                    2,
                    format!("pid {} {} → {outcome}", t.pid, t.image),
                );
                killed.push(
                    serde_json::json!({ "pid": t.pid, "image": t.image, "outcome": outcome }),
                );
            }
            let pending: Vec<&str> = v
                .also
                .iter()
                .map(|s| s.as_str())
                .filter(|a| *a == "quarantine" || *a == "remove_autorun")
                .collect();
            let _ = world.engine.record_event(
                "cut_applied",
                2,
                format!(
                    "뿌리 {} {} — 정책 {}건, 종료 {}건",
                    plan.root,
                    plan.root_label,
                    applied.len(),
                    killed.len()
                ),
            );
            crate::runtime::flush_events(world);
            j(
                serde_json::json!({ "policies": applied, "terminated": killed, "pending": pending, "autoruns": plan.autoruns, "written_executables": plan.written_executables, "warnings": plan.warnings }),
            )
        }
    }
}

/// 서비스 사건 → 응답 (A29). 대상이 프로세스 {pid, create_ft} 면 그래프의 프로세스 노드(`pid@create_ft`)를 찾아 `node_id` 를 붙인다 —
/// UI 가 프로세스 상세·이야기로 잇는다. 그래프에 없으면(수집 전 종료 등) node_id 없이 사실만.
/// A30: 대상이 다른 사용자 세션이면(대상 기록의 session 으로 판정) 대상과 경로가 든 문장을 감춘다 — 사건이 있었다는 사실만 남긴다.
pub(crate) fn service_event_json(
    g: &graph::Store,
    e: engine::store::StoredEvent,
    scope: Scope,
) -> serde_json::Value {
    let mut target = e
        .ref_json
        .as_deref()
        .and_then(|r| serde_json::from_str::<serde_json::Value>(r).ok());
    if let (Scope::Session(me), Some(t)) = (scope, target.as_ref()) {
        if let Some(s) = t.get("session").and_then(|x| x.as_u64()) {
            if s != 0 && s != me as u64 {
                return serde_json::json!({ "id": e.id, "ts": e.ts, "kind": e.kind, "severity": e.severity, "detail": "다른 사용자 세션의 프로그램과 관련된 사건입니다 (관리자만 자세히 볼 수 있습니다).", "target": null });
            }
        }
    }
    if let Some(t) = target.as_mut() {
        if let (Some(pid), Some(ft)) = (
            t.get("pid").and_then(|x| x.as_u64()),
            t.get("create_ft").and_then(|x| x.as_i64()),
        ) {
            if let Ok(Some(id)) = g.find_node(graph::NodeKind::Process, &format!("{pid}@{ft}")) {
                t["node_id"] = serde_json::json!(id);
            }
        }
    }
    serde_json::json!({ "id": e.id, "ts": e.ts, "kind": e.kind, "severity": e.severity, "detail": e.detail, "target": target })
}

/// story.events 문장 하나(캐시). 열쇠 = (판정 결과 세대, since, 화법) — 결과가 바뀌면 세대가 달라 새 칸을 쓴다.
/// 살아 있는 결과(judged·judge_cache)의 세대가 아닌 칸은 버린다(메모리 상한 = 결과 2개 × 화법 수)
fn narrative_cached(
    world: &mut World,
    _gen: u64,
    _since: i64,
    voice: &str,
    s: &judge::Story,
) -> Result<story::events::Narrative, RpcError> {
    use std::hash::{Hash, Hasher};
    // 사건 내용 해시: 같은 뿌리라도 선·점수·이유가 달라지면 다른 문장
    let mut h = std::collections::hash_map::DefaultHasher::new();
    format!("{s:?}").hash(&mut h);
    let key = (s.root, voice.to_string(), h.finish());
    let now = world.engine_wall();
    if let Some((t, n)) = world.narr_cache.get(&key) {
        if now - *t < NARR_TTL_SECS && now >= *t {
            return Ok(n.clone());
        }
    }
    let n = story::narrate(&world.graph, std::slice::from_ref(s), voice_of(voice))
        .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?
        .pop()
        .ok_or_else(|| RpcError::with(ErrorCode::Internal, "narrate"))?;
    // 오래된 칸은 버리고, 그래도 많으면(사건이 아주 많은 PC) 통째로 비운다 — 메모리 상한
    if world.narr_cache.len() >= NARR_CAP {
        world
            .narr_cache
            .retain(|_, (t, _)| now - *t < NARR_TTL_SECS && now >= *t);
        if world.narr_cache.len() >= NARR_CAP {
            world.narr_cache.clear();
        }
    }
    world.narr_cache.insert(key, (now, n.clone()));
    Ok(n)
}

/// 문장 캐시: 10분 지나면 다시 만든다(실행 횟수 등 사건 밖 숫자), 최대 칸 수
const NARR_TTL_SECS: i64 = 600;
const NARR_CAP: usize = 4096;

/// L052: 주기 판정 직후 대시보드·이야기 목록 첫 쪽(주의 이상, 기본 화법 plain, 21건)의 문장을 미리 만든다.
/// 조회는 캐시만 읽어 2초 안에 끝난다(CLAUDE.md: 무거운 계산은 조회 때가 아니라 주기 작업으로)
pub fn warm_story_narratives(world: &mut World) {
    let Some((_, stories)) = world.judged.clone() else {
        return;
    };
    let gen = world.judged_gen;
    // 대시보드는 의심 이상(70), 이야기 화면 기본은 주의 이상(40) — 각 첫 쪽
    for min in [70u8, 40] {
        for s in stories.iter().filter(|s| s.score >= min).take(21) {
            let _ = narrative_cached(world, gen, 0, "plain", s);
        }
    }
}

/// 지금 목록의 ASN·국가 중 "오늘 처음"인 것. 기준 집합은 10분마다 다시 센다(연결 목록은 2초마다 불린다)
/// 구조 개선 B: 조회가 보는 판정 결과. since 0(기본)은 주기 판정 결과를 그대로 읽고,
/// 비었거나 다른 since 면 DB 에 쓰지 않는 판정(assess)으로 계산해 메모리에만 둔다
fn judged_stories(
    world: &mut World,
    since: i64,
) -> judge::Result<std::sync::Arc<Vec<judge::Story>>> {
    if since == 0 {
        if let Some((_, s)) = &world.judged {
            return Ok(s.clone());
        }
        let s = std::sync::Arc::new(judge::assess(&world.graph, 0, i64::MAX, &world.baseline)?);
        world.judged = Some((world.engine_wall(), s.clone()));
        world.judge_gen += 1;
        world.judged_gen = world.judge_gen;
        return Ok(s);
    }
    let now = world.engine_wall();
    if let Some((t, sc, s)) = &world.judge_cache {
        if *sc == since && now - *t < CACHE_SECS {
            return Ok(s.clone());
        }
    }
    let s = std::sync::Arc::new(judge::assess(
        &world.graph,
        since,
        i64::MAX,
        &world.baseline,
    )?);
    world.judge_cache = Some((now, since, s.clone()));
    world.judge_gen += 1;
    world.judge_cache_gen = world.judge_gen;
    Ok(s)
}
