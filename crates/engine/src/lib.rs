//! engine: 정책 엔진 골격 (10차 검증 반영). OS 를 직접 만지지 않는다.
//!
//! 흐름: YAML → dsl 검증(규칙 1~9, needs_ack) → 전개 → 가드 → `WfpBackend::apply`(트랜잭션 1건)
//!       → DB 기록 → Applied(미확인) → 60초 안 confirm 없으면 자동 롤백(F19).
//! - 백업·롤백: 버전마다 specs 를 `policy_versions` 에. rollback 은 한 정책 단위.
//! - 스케줄: WFP 에 시간 조건이 없으므로 경계 시각에 필터를 넣고 뺀다. 단조 시계로 타이머, 벽시계는 경계 판정만.
//! - 틈 메우기: 활성 정책의 열린 조건(와일드카드 디렉터리·descendants_of 뿌리)에 ProcessStart 를 대조해
//!   같은 버전에 필터를 추가(버전은 안 올림). 정책당 필터 상한 2,000.
//! - 자가 치유 서킷 브레이커: 60초 창 5회 초과 → 1·2·4…초(상한 60초) 백오프, 멈추지 않음, 최상위 경보.
//!   사용자가 지우는 중인 필터는 콜백에서 구분한다.
//! - excluded_system: dsl 이 뺀 시스템 프로세스의 사건 구간 접속 주소를 `GraphQuery` 로 받아
//!   앱 조건 없는 주소 차단을 같은 정책에 추가. 기본 기한 24시간, 경고문·즉시 해제 가능(10차 Q4).
//! - 멱등: `request_id` 가 같으면 이전 결과를 돌려준다(10차 Q5).
//! - 재시작: `reconcile()` 이 BFE(`list_ours`)와 DB 를 대조 — 누락 재등록, 고아 제거 + 변조 사건.

pub mod backend;
pub mod clock;
pub mod store;

use std::collections::{HashMap, HashSet};

use dsl::expand::Resolver;
use policy::guard::Guard;
use policy::spec::{Action, BlockSpec, Direction, PortRange, V4Range, V6Prefix};

pub use backend::{GraphQuery, WfpBackend};
pub use clock::Clock;
pub use store::{EngineStore, FilterRow, PolicyRow, State};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("dsl: {0}")]
    Dsl(#[from] dsl::DslError),
    #[error("검증 실패: {0:?}")]
    Invalid(Vec<String>),
    #[error("확인 필요: {0:?}")]
    NeedsAck(Vec<(String, dsl::Ack)>),
    #[error("가드 거부: {0}")]
    Guard(String),
    #[error("백엔드: {0}")]
    Backend(String),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("정책 없음: {0}")]
    NotFound(i64),
    #[error("상태 오류: {0}")]
    BadState(String),
}
pub type Result<T> = std::result::Result<T, EngineError>;

pub const CONFIRM_SECS: i64 = 60;
pub const MAX_FILTERS_PER_POLICY: usize = 2_000;
pub const BREAKER_WINDOW_SECS: i64 = 60;
pub const BREAKER_MAX: usize = 5;
pub const BREAKER_BACKOFF_CAP_SECS: i64 = 60;
pub const EXCLUDED_ADDR_TTL_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Schedule {
    pub minutes: Vec<(u16, u16)>,
    pub days: Vec<String>,
    /// 만료 벽시각 (unix 초). None = 만료 없음
    pub expires_at: Option<i64>,
    pub notify_on_expire: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApplyResult {
    pub policy_id: i64,
    pub version: i64,
    pub filters: usize,
    pub confirm_deadline: i64,
    pub warnings: Vec<String>,
    /// 10차 Q4: 앱 조건 없는 주소 차단이 포함됐을 때의 경고문
    pub address_block_notice: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct EventRecord {
    pub ts: i64,
    pub kind: String,
    pub severity: u8,
    pub detail: String,
}

/// 열린 조건 (틈 메우기 인덱스). 판별로 `open_conds` 표에 저장된다.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OpenCond {
    policy_id: i64,
    version: i64,
    /// 소문자 디렉터리 접두 (와일드카드) 또는 뿌리 이미지(descendants_of)
    dir_prefixes: Vec<String>,
    root_images: Vec<String>,
    template: BlockSpec,
    terminate: bool,
}

pub struct Engine<'a> {
    pub store: EngineStore,
    backend: &'a mut dyn WfpBackend,
    graph: &'a dyn GraphQuery,
    clock: &'a dyn Clock,
    resolver: &'a dyn Resolver,
    guard: Guard,
    open_conds: Vec<OpenCond>,
    /// 우리가 지우는 중인 필터 (삭제 콜백에서 변조와 구분)
    removing: HashSet<u64>,
    /// 서킷 브레이커: 정책별 재등록 시각(단조 초)
    reregs: HashMap<i64, Vec<i64>>,
    backoff_until: HashMap<i64, i64>,
    backoff_step: HashMap<i64, u32>,
    /// 백오프 중 대기 중인 재등록 (정책, 필터 행)
    pending_rereg: Vec<(i64, FilterRow)>,
    /// 60초 확인 시한 (단조 초). 벽시계 조작으로 늘거나 줄지 않는다 (11차 Q3)
    confirm_mono: HashMap<i64, i64>,
    pub events: Vec<EventRecord>,
}

fn day_name(unix_secs: i64) -> &'static str {
    // 1970-01-01 은 목요일. 로컬 시각 초(Clock::local)를 받는다.
    const NAMES: [&str; 7] = ["thu", "fri", "sat", "sun", "mon", "tue", "wed"];
    NAMES[((unix_secs.div_euclid(86_400)) % 7) as usize]
}

impl<'a> Engine<'a> {
    pub fn new(conn: rusqlite::Connection, backend: &'a mut dyn WfpBackend, graph: &'a dyn GraphQuery, clock: &'a dyn Clock, resolver: &'a dyn Resolver, protected: &[&str]) -> Result<Self> {
        let store = EngineStore::new(conn)?;
        Ok(Self {
            store,
            backend,
            graph,
            clock,
            resolver,
            guard: Guard::new(protected),
            open_conds: Vec::new(),
            removing: HashSet::new(),
            reregs: HashMap::new(),
            backoff_until: HashMap::new(),
            backoff_step: HashMap::new(),
            pending_rereg: Vec::new(),
            confirm_mono: HashMap::new(),
            events: Vec::new(),
        })
    }

    fn event(&mut self, kind: &str, severity: u8, detail: String) -> Result<()> {
        self.event_ref(kind, severity, detail, None)
    }

    fn event_ref(&mut self, kind: &str, severity: u8, detail: String, ref_json: Option<&str>) -> Result<()> {
        let ts = self.clock.wall();
        let id = self.store.insert_event(ts, kind, severity, &detail)?;
        if let Some(r) = ref_json {
            self.store.set_event_ref(id, r)?;
        }
        self.events.push(EventRecord { ts, kind: kind.into(), severity, detail });
        Ok(())
    }

    /// 서비스가 남기는 사건 (끊기·종료 등). 저장 + 알림 대기열. `store.insert_event` 를 직접 쓰면 알림이 안 간다(A19 발견).
    pub fn record_event(&mut self, kind: &str, severity: u8, detail: String) -> Result<()> {
        self.event(kind, severity, detail)
    }

    /// 대상(프로세스 등)을 가리키는 서비스 사건 (A29: 파이프 가로채기 점유자 → 이야기·프로세스 상세로 잇는다)
    pub fn record_event_ref(&mut self, kind: &str, severity: u8, detail: String, ref_json: Option<String>) -> Result<()> {
        self.event_ref(kind, severity, detail, ref_json.as_deref())
    }

    /// 서비스 사건 목록 (A29)
    pub fn list_events(&self, since: i64, limit: usize) -> Result<Vec<store::StoredEvent>> {
        self.store.list_events(since, limit)
    }

    /// 검증만 (UI 의 policy.validate)
    pub fn validate(&self, yaml: &str) -> Result<dsl::Validation> {
        let doc = dsl::parse(yaml)?;
        Ok(dsl::validate(&doc))
    }

    /// 적용: 트랜잭션 1건. `acks` 는 UI 확인을 받은 항목(서비스가 붙인다).
    pub fn apply(&mut self, yaml: &str, acks: &[(String, dsl::Ack)], request_id: &str, actor: &str) -> Result<ApplyResult> {
        self.apply_with_source(yaml, acks, request_id, actor, None)
    }

    /// `source` 는 서비스만 붙인다(입력 YAML 에는 쓸 수 없음). `Some(Cut)` 이면 명시한 `process` 목록도 뿌리 이미지로 보고
    /// 새 자손을 보충한다 — 뿌리 파일이 사라져 descendants_of 를 쓸 수 없는 끊기(A19)를 위해.
    pub fn apply_with_source(&mut self, yaml: &str, acks: &[(String, dsl::Ack)], request_id: &str, actor: &str, source: Option<dsl::model::Source>) -> Result<ApplyResult> {
        self.apply_full(yaml, acks, request_id, actor, source, &[])
    }

    /// 끊기(A22): 서비스가 그래프에서 뽑은 주소 (누구, IP, 포트, 프로토콜 번호) 를 같은 판에 24시간 주소 차단으로 넣는다.
    pub fn apply_full(&mut self, yaml: &str, acks: &[(String, dsl::Ack)], request_id: &str, actor: &str, source: Option<dsl::model::Source>, extra_addresses: &[(String, String, u16, u8)]) -> Result<ApplyResult> {
        if let Some(prev) = self.store.idempotent_lookup(request_id)? {
            return Ok(prev);
        }
        let mut doc = dsl::parse(yaml)?;
        for p in &mut doc.policies {
            p.source = source;
        }
        for p in &mut doc.policies {
            for (name, ack) in acks {
                if &p.name == name && !p.acknowledge.contains(ack) {
                    p.acknowledge.push(*ack);
                }
            }
        }
        let v = dsl::validate(&doc);
        if !v.errors.is_empty() {
            return Err(EngineError::Invalid(v.errors.iter().map(|e| e.to_string()).collect()));
        }
        if !v.needs_ack.is_empty() {
            return Err(EngineError::NeedsAck(v.needs_ack));
        }
        // 1차: 문서 1건 = 정책 1건 (여러 정책 문서는 UI 가 나눠 보낸다)
        let p = doc.policies.first().ok_or_else(|| EngineError::Invalid(vec!["정책 없음".into()]))?;
        let expanded = dsl::expand(p, self.resolver)?;
        let mut warnings = expanded.warnings.clone();
        let mut specs = expanded.specs.clone();

        // 주소 차단 (앱 조건 없음, 24시간 기한, (IP, 포트, 프로토콜) 단위 — 16차 Q2: IP 통째 차단은 CDN 공용 IP 의 다른 서비스까지 끊는다)
        // ① excluded_system: 전개에서 빠진 시스템 프로세스가 사건 구간에 접속한 주소
        // ② extra_addresses: 서비스가 넘긴 주소(끊기: 주입당한 프로그램·대상 프로세스의 접속지 — 다른 프로세스로 옮겨 가도 같은 곳엔 못 닿게)
        let mut address_block_notice = None;
        let mut addrs: Vec<(String, String, u16, u8)> = Vec::new();
        for img in &expanded.excluded_system {
            for (ip, port, proto) in self.graph.event_addresses_of(img) {
                addrs.push((rules_file_name(img), ip, port, proto));
            }
        }
        for (who, ip, port, proto) in extra_addresses {
            addrs.push((who.clone(), ip.clone(), *port, *proto));
        }
        let mut seen_addr = HashSet::new();
        let mut addr_specs = Vec::new();
        for (who, ip, port, proto) in addrs {
            if !seen_addr.insert((ip.clone(), port, proto)) {
                continue;
            }
            let (v4, v6) = match ip.parse::<std::net::Ipv4Addr>() {
                Ok(a) => (vec![V4Range { lo: a, hi: a }], vec![]),
                Err(_) => match ip.parse::<std::net::Ipv6Addr>() {
                    Ok(a) => (vec![], vec![V6Prefix { addr: a, prefix: 128 }]),
                    Err(_) => continue,
                },
            };
            addr_specs.push(BlockSpec {
                name: format!("{} (주소 차단: {who})", p.name),
                action: Action::Block,
                direction: Direction::Out,
                app_path: None,
                remote_v4: v4,
                remote_v6: v6,
                remote_ports: vec![PortRange { lo: port, hi: port }],
                local_ports: vec![],
                protocols: vec![proto],
                weight: None,
                ip_family: None,
            });
        }
        if !addr_specs.is_empty() {
            if !expanded.excluded_system.is_empty() {
                warnings.push(format!("[주소 차단] 시스템 프로세스 {:?} 는 막지 않고, 사건 구간에 접속한 주소만 24시간 차단합니다. 재부팅을 권고합니다", expanded.excluded_system));
            }
            warnings.push(format!("[주소 차단] 주소 {}곳(주소·포트·프로토콜 단위)을 24시간 차단합니다", addr_specs.len()));
            address_block_notice = Some("해당 주소가 공용 서버(CDN 등)일 경우 같은 포트를 쓰는 다른 프로그램의 통신도 함께 차단될 수 있습니다. 문제가 생기면 '즉시 차단 해제'를 누르십시오.".into());
            specs.extend(addr_specs);
        }
        // 가드: 전개 뒤에도 마지막으로 한 번 더
        for s in &specs {
            self.guard.check(s).map_err(|e| EngineError::Guard(e.to_string()))?;
        }
        // 상한은 실제 WFP 필터 수로 센다 (명세 하나가 V4·V6 두 필터가 될 수 있다)
        let real: usize = specs.iter().map(|s| s.filter_count()).sum();
        if real > MAX_FILTERS_PER_POLICY {
            return Err(EngineError::Invalid(vec![format!("정책당 필터 상한 {MAX_FILTERS_PER_POLICY} 초과: {real}")]));
        }
        let schedule = expanded.schedule.as_ref().map(|s| Schedule {
            minutes: s.minutes.clone(),
            days: s.days.clone(),
            expires_at: s.expires_in_minutes.map(|m| self.clock.wall() + m as i64 * 60),
            notify_on_expire: s.on_expire == dsl::model::OnExpire::Notify,
        });
        let addr_expires_at = if address_block_notice.is_some() { Some(self.clock.wall() + EXCLUDED_ADDR_TTL_SECS) } else { None };

        // DB: 정책·버전 (백업 = 버전 행 자체)
        let now = self.clock.wall();
        let (policy_id, version) = self.store.new_version(&p.name, yaml, &specs, schedule.as_ref(), now, actor)?;
        // 활성 여부(스케줄 구간 안인가)
        let active = schedule.as_ref().map_or(true, |s| self.in_window(s));
        // 이전 판 → 새 판 을 한 WFP 트랜잭션으로 (11차 Q1: 보호 공백 없음). 실패하면 이전 판이 그대로 남는다.
        let prev_ids: Vec<u64> = self.store.filters_of(policy_id)?.iter().map(|r| r.filter_id).collect();
        let add: &[BlockSpec] = if active { &specs } else { &[] };
        let filters = match self.swap(policy_id, version, &prev_ids, add) {
            Ok(n) => n,
            Err(err) => {
                if version > 1 {
                    self.store.set_version(policy_id, version - 1)?;
                }
                return Err(err);
            }
        };
        let _ = addr_expires_at;
        let confirm_deadline = now + CONFIRM_SECS; // UI 표시용 벽시각
        self.confirm_mono.insert(policy_id, self.clock.mono() + CONFIRM_SECS);
        self.store.set_state(policy_id, State::Applied, Some(confirm_deadline))?;
        self.store.history(now, policy_id, "apply", actor, &format!("version {version}, filters {filters}, active {active}"))?;
        self.register_open_conds(policy_id, version, p, &expanded);
        let result = ApplyResult { policy_id, version, filters, confirm_deadline, warnings, address_block_notice };
        self.store.idempotent_save(request_id, &result)?;
        Ok(result)
    }

    /// 우산 정책 (첫 실행 관찰실, 방식 나): 필터 없는 정책 1건을 **관리자 요청**으로 만든다. 일반 적용과 같이 Applied(60초 확인 대기)로
    /// 두고 F19(미확인 자동 롤백)·멱등 키·정책 기록을 그대로 따른다. 확인(Confirmed)된 뒤에만 `add_child_blocks` 가 그 아래에
    /// 기한부 경로 차단을 더할 수 있다. 우산을 되돌리거나·일시 중지하거나·지우면 그 아래 필터도 함께 내려간다(필터는 우산 정책 번호로 저장).
    pub fn apply_umbrella(&mut self, name: &str, note: &str, request_id: &str, actor: &str) -> Result<ApplyResult> {
        if let Some(prev) = self.store.idempotent_lookup(request_id)? {
            return Ok(prev);
        }
        if name.is_empty() || name.chars().count() > 64 {
            return Err(EngineError::Invalid(vec!["name 은 1~64자".into()]));
        }
        let now = self.clock.wall();
        let (policy_id, version) = self.store.new_version(name, note, &[], None, now, actor)?;
        // 이전 판에 남은 필터가 있으면 걷는다 — 새 판은 필터 없이 시작(되살린 우산 아래 옛 차단이 다시 살지 않게)
        let prev_ids: Vec<u64> = self.store.filters_of(policy_id)?.iter().map(|r| r.filter_id).collect();
        self.swap(policy_id, version, &prev_ids, &[])?;
        let confirm_deadline = now + CONFIRM_SECS;
        self.confirm_mono.insert(policy_id, self.clock.mono() + CONFIRM_SECS);
        self.store.set_state(policy_id, State::Applied, Some(confirm_deadline))?;
        self.store.history(now, policy_id, "apply", actor, &format!("version {version}, umbrella"))?;
        let result = ApplyResult { policy_id, version, filters: 0, confirm_deadline, warnings: vec![], address_block_notice: None };
        self.store.idempotent_save(request_id, &result)?;
        Ok(result)
    }

    /// 확인된 우산 정책 아래에 기한부 경로 차단을 더한다 (자동 집행). 새 정책을 만들지 않는다 — 사람이 확인한 우산의 범위 안에서만.
    /// 조건: 우산이 Confirmed, 기한이 미래, 명세는 모두 실행 파일 경로가 있는 차단, 시스템 핵심 프로세스 아님, 가드 통과.
    /// 정책 기록: 우산 정책 번호로 `child_block` (행위자 = 호출자, 결과 = 무엇을·언제까지·필터 번호)
    pub fn add_child_blocks(&mut self, parent: i64, specs: &[BlockSpec], expires_at: i64, actor: &str, note: &str) -> Result<Vec<u64>> {
        let row = self.store.policy(parent)?.ok_or(EngineError::NotFound(parent))?;
        if row.state != State::Confirmed {
            return Err(EngineError::BadState(format!("우산 정책이 확인된 상태가 아님: {:?}", row.state)));
        }
        let now = self.clock.wall();
        if expires_at <= now {
            return Err(EngineError::Invalid(vec!["기한이 이미 지났습니다".into()]));
        }
        if specs.is_empty() {
            return Ok(vec![]);
        }
        for s in specs {
            let Some(app) = s.app_path.as_deref() else {
                return Err(EngineError::Invalid(vec!["자동 차단은 실행 파일 경로 조건이 있어야 합니다".into()]));
            };
            if s.action != Action::Block {
                return Err(EngineError::Invalid(vec!["자동 차단은 차단만".into()]));
            }
            if dsl::validate::is_system_image(app) {
                return Err(EngineError::Guard(format!("시스템 핵심 프로세스: {}", rules_file_name(app))));
            }
            self.guard.check(s).map_err(|e| EngineError::Guard(e.to_string()))?;
        }
        let add: Vec<BlockSpec> = specs.iter().flat_map(|s| s.split_family()).collect();
        let have = self.store.filters_of(parent)?.len();
        if have + add.len() > MAX_FILTERS_PER_POLICY {
            return Err(EngineError::Invalid(vec![format!("정책당 필터 상한 {MAX_FILTERS_PER_POLICY} 초과")]));
        }
        let ids = self.backend.replace(&[], &add).map_err(EngineError::Backend)?;
        if ids.len() != add.len() {
            return Err(EngineError::Backend(format!("필터 수 불일치 {} != {}", ids.len(), add.len())));
        }
        let tx = self.store.conn.unchecked_transaction()?;
        for (id, s) in ids.iter().zip(&add) {
            EngineStore::insert_filter_tx(&tx, *id, parent, row.version, s, Some(expires_at))?;
        }
        tx.commit()?;
        self.record_keys(&ids);
        self.store.history(now, parent, "child_block", actor, &format!("{note} until {expires_at} filters {ids:?}"))?;
        Ok(ids)
    }

    /// 필터 교체의 유일한 경로: `remove` 를 지우고 `add` 를 넣는 것을 한 WFP 트랜잭션 + 한 DB 트랜잭션으로.
    /// 주소 차단 명세의 기한은 그 판이 만들어진 시각 + 24시간. 이미 지났으면 넣지 않는다(영구 차단 방지).
    fn swap(&mut self, policy_id: i64, version: i64, remove: &[u64], add: &[BlockSpec]) -> Result<usize> {
        let vts = self.store.version_ts(policy_id, version)?.unwrap_or_else(|| self.clock.wall());
        let addr_exp = vts + EXCLUDED_ADDR_TTL_SECS;
        let now = self.clock.wall();
        // 명세 1개 = 필터 1개 가 되도록 주소 체계별로 나눈다 (A26 접점: 실제 WFP 는 주소 조건 없는 명세를 V4·V6 둘로 만든다)
        let add: Vec<BlockSpec> = add.iter().filter(|s| !(is_address_block(s) && now >= addr_exp)).flat_map(|s| s.split_family()).collect();
        if remove.is_empty() && add.is_empty() {
            return Ok(0);
        }
        self.removing.extend(remove.iter().copied());
        let res = self.backend.replace(remove, &add);
        for id in remove {
            self.removing.remove(id);
        }
        let ids = res.map_err(EngineError::Backend)?;
        if ids.len() != add.len() {
            return Err(EngineError::Backend(format!("필터 수 불일치 {} != {}", ids.len(), add.len())));
        }
        let tx = self.store.conn.unchecked_transaction()?;
        for id in remove {
            tx.execute("DELETE FROM wfp_filters WHERE filter_id = ?1", [*id as i64])?;
        }
        for (id, s) in ids.iter().zip(&add) {
            let exp = if is_address_block(s) { Some(addr_exp) } else { None };
            EngineStore::insert_filter_tx(&tx, *id, policy_id, version, s, exp)?;
        }
        tx.commit()?;
        self.record_keys(&ids);
        Ok(ids.len())
    }

    /// 필터만 지운다 (정책 무관, 주소 차단 만료 등)
    fn drop_filters(&mut self, ids: &[u64]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        self.removing.extend(ids.iter().copied());
        let res = self.backend.replace(ids, &[]);
        for id in ids {
            self.removing.remove(id);
        }
        res.map_err(EngineError::Backend)?;
        self.store.delete_filters(ids)?;
        Ok(())
    }

    fn uninstall_policy(&mut self, policy_id: i64) -> Result<usize> {
        let ids: Vec<u64> = self.store.filters_of(policy_id)?.iter().map(|r| r.filter_id).collect();
        self.drop_filters(&ids)?;
        Ok(ids.len())
    }

    pub fn confirm(&mut self, policy_id: i64, version: i64, actor: &str) -> Result<()> {
        let row = self.store.policy(policy_id)?.ok_or(EngineError::NotFound(policy_id))?;
        if row.version != version {
            return Err(EngineError::BadState(format!("버전 불일치 {} != {version}", row.version)));
        }
        if row.state != State::Applied {
            return Err(EngineError::BadState(format!("{:?} 상태에서는 confirm 불가", row.state)));
        }
        if self.confirm_mono.get(&policy_id).map_or(true, |d| self.clock.mono() >= *d) {
            return Err(EngineError::BadState("확인 시한(60초)이 지났습니다".into()));
        }
        self.confirm_mono.remove(&policy_id);
        self.store.set_state(policy_id, State::Confirmed, None)?;
        self.store.history(self.clock.wall(), policy_id, "confirm", actor, "")?;
        Ok(())
    }

    /// 특정 판으로 되돌리기 (None = 제거). 판 교체는 한 트랜잭션.
    pub fn rollback(&mut self, policy_id: i64, to_version: Option<i64>, actor: &str) -> Result<()> {
        let row = self.store.policy(policy_id)?.ok_or(EngineError::NotFound(policy_id))?;
        self.open_conds.retain(|c| c.policy_id != policy_id);
        self.confirm_mono.remove(&policy_id);
        let cur: Vec<u64> = self.store.filters_of(policy_id)?.iter().map(|r| r.filter_id).collect();
        match to_version {
            None => {
                let n = cur.len();
                self.drop_filters(&cur)?;
                self.store.delete_open_conds(policy_id)?;
                self.store.set_state(policy_id, State::RolledBack, None)?;
                self.store.history(self.clock.wall(), policy_id, "rollback", actor, &format!("removed {n}"))?;
            }
            Some(v) => {
                let specs = self.store.version_specs(policy_id, v)?.ok_or(EngineError::NotFound(v))?;
                let n = self.swap(policy_id, v, &cur, &specs)?;
                self.store.set_version(policy_id, v)?;
                self.store.set_state(policy_id, State::Confirmed, None)?;
                // 그 판의 틈 메우기도 되살린다 (이전에는 재시작 전까지 사라졌다)
                self.restore_open_cond(policy_id, v);
                self.store.history(self.clock.wall(), policy_id, "rollback", actor, &format!("to version {v}, filters {n} (was {})", row.version))?;
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, policy_id: i64, actor: &str) -> Result<()> {
        self.uninstall_policy(policy_id)?;
        self.open_conds.retain(|c| c.policy_id != policy_id);
        self.store.delete_open_conds(policy_id)?;
        self.store.set_state(policy_id, State::Removed, None)?;
        self.store.history(self.clock.wall(), policy_id, "remove", actor, "")?;
        Ok(())
    }

    /// 사용자가 "일시 중지": 필터 제거, 재등록 중단
    pub fn pause(&mut self, policy_id: i64, actor: &str) -> Result<()> {
        self.uninstall_policy(policy_id)?;
        self.pending_rereg.retain(|(p, _)| *p != policy_id);
        self.store.set_state(policy_id, State::Paused, None)?;
        self.store.history(self.clock.wall(), policy_id, "pause", actor, "")?;
        Ok(())
    }

    /// 10차 Q4: 주소 차단 즉시 해제 (정책은 유지)
    /// 기한부 주소 차단 필터를 지금 푼다. policy_id 0 = 모든 정책(UI "주소 차단 모두 해제").
    /// 27차 결함: 전에는 0 을 그대로 정책 번호로 찾아 늘 0건이었다(필터는 실제 정책 번호로 저장된다)
    /// 지금 걸려 있는 기한부 주소 차단 필터 수(모든 정책)
    pub fn address_block_count(&self) -> Result<usize> {
        Ok(self.address_blocks()?.len())
    }

    /// 지금 걸려 있는 기한부 주소 차단 필터(모든 정책). D036: 화면이 "무엇을 해제하는지" 보인다
    pub fn address_blocks(&self) -> Result<Vec<FilterRow>> {
        // 우산 아래 기한부 경로 차단(add_child_blocks)도 기한이 있지만 "주소 차단"이 아니다 — 주소 차단 목록·일괄 해제에서 뺀다
        Ok(self.store.all_filters()?.into_iter().filter(|r| r.expires_at.is_some() && is_address_block(&r.spec)).collect())
    }

    /// 주소 차단 필터 하나만 지금 푼다(D036 줄마다 "해제"). 기한부 주소 차단이 아니면 거부
    pub fn release_address_block(&mut self, filter_id: u64, actor: &str) -> Result<usize> {
        let Some(row) = self.store.filter(filter_id)? else { return Ok(0) };
        if row.expires_at.is_none() {
            return Err(EngineError::Invalid(vec![format!("주소 차단 필터가 아님: {filter_id}")]));
        }
        self.drop_filters(&[filter_id])?;
        self.store.history(self.clock.wall(), row.policy_id, "release_address_blocks", actor, "1")?;
        Ok(1)
    }

    pub fn release_address_blocks(&mut self, policy_id: i64, actor: &str) -> Result<usize> {
        let all = if policy_id == 0 { self.store.all_filters()? } else { self.store.filters_of(policy_id)? };
        let rows: Vec<FilterRow> = all.into_iter().filter(|r| r.expires_at.is_some() && is_address_block(&r.spec)).collect();
        let ids: Vec<u64> = rows.iter().map(|r| r.filter_id).collect();
        self.drop_filters(&ids)?;
        self.store.history(self.clock.wall(), policy_id, "release_address_blocks", actor, &format!("{}", ids.len()))?;
        Ok(ids.len())
    }

    fn in_window(&self, s: &Schedule) -> bool {
        if let Some(exp) = s.expires_at {
            if self.clock.wall() >= exp {
                return false;
            }
        }
        // 요일·분은 로컬 시각으로 (만료는 UTC)
        let wall = self.clock.local();
        if s.minutes.is_empty() && s.days.is_empty() {
            return true;
        }
        if !s.days.is_empty() && !s.days.iter().any(|d| d == day_name(wall)) {
            return false;
        }
        if s.minutes.is_empty() {
            return true;
        }
        let m = ((wall.rem_euclid(86_400)) / 60) as u16;
        s.minutes.iter().any(|(a, b)| *a <= m && m < *b)
    }

    /// 타이머 틱 (1분마다 + 이벤트 때). 확인 시한·스케줄 경계·만료·백오프 재등록.
    pub fn tick(&mut self) -> Result<()> {
        let wall = self.clock.wall();
        let mono = self.clock.mono();
        // 1) 60초 미확인 → 자동 롤백 (단조 시계. 시한 기록이 없으면 = 재시작 뒤 → 즉시 롤백)
        for row in self.store.policies_in(State::Applied)? {
            if self.confirm_mono.get(&row.id).map_or(true, |d| mono >= *d) {
                self.rollback(row.id, None, "system:confirm-timeout")?;
                self.event("policy_auto_rollback", 2, format!("정책 {} 이(가) 60초 안에 확인되지 않아 되돌렸습니다", row.name))?;
            }
        }
        // 2) 만료·스케줄 경계 (확인 대기 중인 정책도 경계는 지킨다)
        let mut rows = self.store.policies_in(State::Confirmed)?;
        rows.extend(self.store.policies_in(State::Applied)?);
        for row in rows {
            let Some(sch) = row.schedule.clone() else { continue };
            if sch.expires_at.map_or(false, |e| wall >= e) {
                self.uninstall_policy(row.id)?;
                self.open_conds.retain(|c| c.policy_id != row.id);
                self.store.delete_open_conds(row.id)?;
                self.store.set_state(row.id, State::Expired, None)?;
                if sch.notify_on_expire {
                    self.event("policy_expired", 1, format!("정책 {} 만료", row.name))?;
                }
                continue;
            }
            if let Some(e) = sch.expires_at {
                if e - wall <= 600 && e - wall > 540 {
                    self.event("policy_expiring", 1, format!("정책 {} 10분 뒤 만료", row.name))?;
                }
            }
            let want = self.in_window(&sch);
            let have = !self.store.filters_of(row.id)?.is_empty();
            if want && !have {
                let specs = self.store.version_specs(row.id, row.version)?.unwrap_or_default();
                let n = self.swap(row.id, row.version, &[], &specs)?;
                self.store.history(wall, row.id, "schedule_on", "system", &format!("{n}"))?;
            } else if !want && have {
                let n = self.uninstall_policy(row.id)?;
                self.store.history(wall, row.id, "schedule_off", "system", &format!("{n}"))?;
            }
        }
        // 3) 주소 차단 24시간 만료
        // 우산 아래 기한부 경로 차단(add_child_blocks)도 여기서 만료 — 우산 정책 기록에 남긴다
        let expired = self.store.filters_expired(wall)?;
        let (addr, child): (Vec<FilterRow>, Vec<FilterRow>) = expired.into_iter().partition(|r| is_address_block(&r.spec));
        if !addr.is_empty() {
            let ids: Vec<u64> = addr.iter().map(|r| r.filter_id).collect();
            self.drop_filters(&ids)?;
            self.event("address_block_expired", 1, format!("주소 차단 {}건 24시간 만료", ids.len()))?;
        }
        if !child.is_empty() {
            let ids: Vec<u64> = child.iter().map(|r| r.filter_id).collect();
            self.drop_filters(&ids)?;
            let mut by_policy: HashMap<i64, Vec<u64>> = HashMap::new();
            for r in &child {
                by_policy.entry(r.policy_id).or_default().push(r.filter_id);
            }
            for (pid, fs) in by_policy {
                self.store.history(wall, pid, "child_expired", "system:expire", &format!("filters {fs:?}"))?;
            }
            self.event("child_block_expired", 1, format!("기한부 실행 파일 차단 {}건 만료", ids.len()))?;
        }
        // 4) 물리 상한 (12차 Q6) — 하루 한 번이면 충분하지만 틱마다 해도 싸다
        self.store.enforce_caps(wall)?;
        // 5) 백오프가 풀린 재등록
        let due: Vec<(i64, FilterRow)> = self.pending_rereg.iter().filter(|(p, _)| self.backoff_until.get(p).map_or(true, |u| mono >= *u)).cloned().collect();
        self.pending_rereg.retain(|(p, _)| self.backoff_until.get(p).map_or(false, |u| mono < *u));
        for (policy_id, row) in due {
            self.reregister(policy_id, row)?;
        }
        Ok(())
    }

    /// 다음에 깨어날 때까지의 초 (11차 Q2). 확인 시한·백오프·스케줄 경계·만료·주소 차단 기한 중 가장 이른 것,
    /// 1~60초로 자른다(60초 상한은 놓친 이벤트에 대한 안전망). 서비스는 이만큼 자고 `tick()`.
    pub fn next_wakeup(&self) -> Result<i64> {
        let wall = self.clock.wall();
        let mono = self.clock.mono();
        let mut best: i64 = 60;
        let mut consider = |d: i64| {
            if d < best {
                best = d;
            }
        };
        for d in self.confirm_mono.values() {
            consider(d - mono);
        }
        for d in self.backoff_until.values() {
            if *d > mono {
                consider(d - mono);
            }
        }
        let mut rows = self.store.policies_in(State::Confirmed)?;
        rows.extend(self.store.policies_in(State::Applied)?);
        for row in rows {
            let Some(sch) = row.schedule else { continue };
            if let Some(e) = sch.expires_at {
                consider(e - wall);
                consider(e - 600 - wall); // 10분 전 알림
            }
            // 경계는 로컬 시각 기준 (차이만 쓰므로 오프셋은 상쇄된다)
            let local = self.clock.local();
            let day_start = local - local.rem_euclid(86_400);
            for (a, b) in &sch.minutes {
                for m in [*a, *b] {
                    for day in [0i64, 1] {
                        let t = day_start + day * 86_400 + m as i64 * 60;
                        if t > local {
                            consider(t - local);
                        }
                    }
                }
            }
            if !sch.days.is_empty() {
                consider(day_start + 86_400 - local); // 요일 경계 = 로컬 자정
            }
        }
        for f in self.store.all_filters()? {
            if let Some(e) = f.expires_at {
                consider(e - wall);
            }
        }
        Ok(best.clamp(1, 60))
    }

    /// 절전·최대 절전에서 깨어남 (WM_POWERBROADCAST / PBT_APMRESUMEAUTOMATIC). 단조 시계가 멈춰 있었을 수 있으므로
    /// 벽시계 기준 판정(스케줄·만료)을 즉시 다시 한다. 확인 창은 단조 기준 그대로.
    pub fn on_resume(&mut self) -> Result<()> {
        self.event("power_resume", 0, "절전에서 깨어나 스케줄을 다시 평가합니다".into())?;
        self.tick()
    }

    /// 시스템 시각 변경 (WM_TIMECHANGE). 스케줄 경계를 즉시 다시 평가.
    pub fn on_time_changed(&mut self) -> Result<()> {
        self.event("time_changed", 1, "시스템 시각이 바뀌어 스케줄을 다시 평가합니다".into())?;
        self.tick()
    }

    /// 백엔드가 우리 필터 삭제를 알릴 때 (자가 치유 + 서킷 브레이커)
    pub fn on_filter_deleted(&mut self, filter_id: u64) -> Result<()> {
        if self.removing.contains(&filter_id) {
            return Ok(()); // 우리가 지우는 중
        }
        let Some(row) = self.store.filter(filter_id)? else { return Ok(()) };
        let policy = self.store.policy(row.policy_id)?;
        if policy.as_ref().map_or(true, |p| !matches!(p.state, State::Applied | State::Confirmed)) {
            return Ok(());
        }
        let mono = self.clock.mono();
        let pid = row.policy_id;
        let hist = self.reregs.entry(pid).or_default();
        hist.retain(|t| mono - *t < BREAKER_WINDOW_SECS);
        hist.push(mono);
        let count = hist.len();
        self.event("policy_tampered", 3, format!("정책 {} 의 필터 {filter_id} 가 외부에서 지워졌습니다 ({count}회/60초)", pid))?;
        if count > BREAKER_MAX {
            let step = self.backoff_step.entry(pid).or_insert(0);
            let delay = (1i64 << (*step).min(6)).min(BREAKER_BACKOFF_CAP_SECS);
            *step += 1;
            self.backoff_until.insert(pid, mono + delay);
            self.pending_rereg.push((pid, row));
            self.event("policy_tamper_backoff", 3, format!("정책 {pid} 재등록을 {delay}초 뒤로 늦춥니다 (멈추지 않음)"))?;
            return Ok(());
        }
        self.reregister(pid, row)
    }

    fn reregister(&mut self, policy_id: i64, row: FilterRow) -> Result<()> {
        // 지워진 필터의 DB 행을 새 ID 행으로 바꾼다 (BFE 에는 이미 없음)
        self.store.delete_filters(&[row.filter_id])?;
        // 저장된 명세는 이미 한 주소 체계(split_family 뒤)지만, 예전 행이면 여기서 나눈다
        let specs = row.spec.split_family();
        let ids = self.backend.replace(&[], &specs).map_err(EngineError::Backend)?;
        if ids.len() != specs.len() {
            return Err(EngineError::Backend(format!("필터 수 불일치 {} != {}", ids.len(), specs.len())));
        }
        let tx = self.store.conn.unchecked_transaction()?;
        for (id, s) in ids.iter().zip(&specs) {
            EngineStore::insert_filter_tx(&tx, *id, policy_id, row.version, s, row.expires_at)?;
        }
        tx.commit()?;
        self.record_keys(&ids);
        self.store.history(self.clock.wall(), policy_id, "self_heal", "system", &format!("filter {} -> {:?}", row.filter_id, ids))?;
        Ok(())
    }

    fn register_open_conds(&mut self, policy_id: i64, version: i64, p: &dsl::Policy, expanded: &dsl::Expanded) {
        // 새 판은 이전 판의 조건을 대신한다. 새 판에 열린 조건이 없어도 이전 판 조건은 내려야 한다
        // (A19 발견: 와일드카드 1판 → 명시 2판으로 바꿔도 1판 보충이 계속 돌았다).
        self.open_conds.retain(|c| c.policy_id != policy_id);
        let m = &p.matcher;
        let dir_prefixes: Vec<String> = m.process.iter().filter_map(|x| x.replace('/', "\\").to_ascii_lowercase().strip_suffix("\\*").map(|d| format!("{d}\\"))).collect();
        let mut root_images: Vec<String> = Vec::new();
        if p.source == Some(dsl::model::Source::Cut) {
            // 끊기: 명시 목록(뿌리 + 지금까지의 자손)이 곧 부모 후보
            root_images.extend(m.process.iter().filter(|x| !x.ends_with('*')).map(|x| x.replace('/', "\\").to_ascii_lowercase()));
        }
        if m.descendants_of.is_some() {
            // 뿌리와 지금까지의 자손 이미지(앱 조건이 있는 차단 명세) 모두 부모가 될 수 있다
            root_images.extend(expanded.specs.iter().filter(|s| s.action == Action::Block).filter_map(|s| s.app_path.clone()).map(|a| a.to_ascii_lowercase()));
        }
        if dir_prefixes.is_empty() && root_images.is_empty() {
            return;
        }
        root_images.sort();
        root_images.dedup();
        let Some(template) = expanded.specs.iter().find(|s| s.action == Action::Block).cloned() else { return };
        let oc = OpenCond { policy_id, version, dir_prefixes, root_images, template, terminate: p.also.contains(&dsl::model::Also::Terminate) };
        if let Ok(js) = serde_json::to_string(&oc) {
            let _ = self.store.save_open_cond(policy_id, version, &js);
        }
        self.open_conds.retain(|c| c.policy_id != policy_id);
        self.open_conds.push(oc);
    }

    /// 저장된 열린 조건 복원 (재시작·판 되돌리기). 있으면 true
    fn restore_open_cond(&mut self, policy_id: i64, version: i64) -> bool {
        let Ok(Some(js)) = self.store.open_cond(policy_id, version) else { return false };
        let Ok(oc) = serde_json::from_str::<OpenCond>(&js) else { return false };
        self.open_conds.retain(|c| c.policy_id != policy_id);
        self.open_conds.push(oc);
        true
    }

    /// 수집기의 ProcessStart. 반환: 종료해야 할 PID 목록(also: terminate)
    pub fn on_process_start(&mut self, pid: u32, image: &str, parent_image: &str) -> Result<Vec<u32>> {
        let img = image.replace('/', "\\").to_ascii_lowercase();
        let parent = parent_image.replace('/', "\\").to_ascii_lowercase();
        let mut terminate = Vec::new();
        let conds = self.open_conds.clone();
        for c in conds {
            let hit = c.dir_prefixes.iter().any(|d| img.starts_with(d)) || c.root_images.contains(&parent);
            if !hit {
                continue;
            }
            let Some(row) = self.store.policy(c.policy_id)? else { continue };
            if !matches!(row.state, State::Applied | State::Confirmed) {
                continue;
            }
            if dsl::validate::is_system_image(&img) {
                continue;
            }
            if self.store.has_app(c.policy_id, image)? {
                continue;
            }
            let mut spec = c.template.clone();
            spec.app_path = Some(image.to_string());
            spec.name = format!("{} (보충)", c.template.name);
            // 상한은 실제 필터 수로: 이번 보충이 만들 필터(V4·V6)까지 더해 넘으면 멈춘다
            if self.store.filter_count(c.policy_id)? + spec.filter_count() > MAX_FILTERS_PER_POLICY {
                self.event("policy_fill_limit", 2, format!("정책 {} 필터 상한 {MAX_FILTERS_PER_POLICY} 도달 — 보충 중단", row.name))?;
                continue;
            }
            if self.guard.check(&spec).is_err() {
                continue;
            }
            // 자손의 자손도 잡히도록 뿌리 집합에 추가
            if c.root_images.contains(&parent) {
                if let Some(oc) = self.open_conds.iter_mut().find(|o| o.policy_id == c.policy_id && o.version == c.version) {
                    if !oc.root_images.contains(&img) {
                        oc.root_images.push(img.clone());
                        if let Ok(js) = serde_json::to_string(&*oc) {
                            let _ = self.store.save_open_cond(c.policy_id, c.version, &js);
                        }
                    }
                }
            }
            self.swap(c.policy_id, c.version, &[], &[spec])?;
            self.store.history(self.clock.wall(), c.policy_id, "fill", "system", &format!("pid {pid} {image}"))?;
            if c.terminate {
                terminate.push(pid);
            }
        }
        Ok(terminate)
    }

    fn normalize_legacy_rows(&mut self) -> Result<()> {
        let live: HashSet<u64> = self.backend.list_ours().map_err(EngineError::Backend)?.into_iter().collect();
        for row in self.store.all_filters()? {
            if row.spec.ip_family.is_some() || !live.contains(&row.filter_id) {
                continue;
            }
            let exp = row.expires_at;
            // 기한이 있는 주소 차단은 swap 이 판 시각으로 기한을 다시 계산하므로 같은 값이 된다
            let n = self.swap(row.policy_id, row.version, &[row.filter_id], std::slice::from_ref(&row.spec))?;
            let _ = exp;
            self.store.history(self.clock.wall(), row.policy_id, "normalize", "system", &format!("filter {} -> {n} (ip_family)", row.filter_id))?;
        }
        Ok(())
    }

    /// 새로 넣은 필터의 filterKey 를 DB 에 남긴다(실패해도 정책 적용은 성공 — 다음 대조 때 채운다)
    fn record_keys(&mut self, ids: &[u64]) {
        if let Ok(keys) = self.backend.list_keys() {
            for (id, k) in keys {
                if ids.contains(&id) {
                    let _ = self.store.set_filter_key(id, &k);
                }
            }
        }
    }

    /// 재시작 대조 전: 키가 같은데 번호가 달라진 필터는 DB 번호만 고친다(재등록·고아 제거·변조 사건을 만들지 않는다).
    /// 키가 비어 있는 예전 행은 번호가 같으면 키를 채운다. 돌려주는 값 = 번호를 고친 수
    fn sync_filter_keys(&mut self) -> Result<usize> {
        let live = self.backend.list_keys().map_err(EngineError::Backend)?;
        if live.is_empty() {
            return Ok(0);
        }
        let db_ids: HashSet<u64> = self.store.all_filters()?.into_iter().map(|r| r.filter_id).collect();
        let live_ids: HashSet<u64> = live.iter().map(|x| x.0).collect();
        let by_key = self.store.filter_ids_by_key()?;
        let mut renumbered = 0;
        for (id, key) in &live {
            if db_ids.contains(id) {
                self.store.set_filter_key(*id, key)?;
            } else if let Some(old) = by_key.get(key) {
                // 옛 번호가 지금 살아 있는 다른 필터 번호와 같다면(번호 재사용) 그쪽은 따로 대조된다 — 옛 번호가 죽었을 때만
                if !live_ids.contains(old) {
                    self.store.renumber_filter(*old, *id)?;
                    renumbered += 1;
                }
            }
        }
        if renumbered > 0 {
            self.event("policy_filters_renumbered", 1, format!("BFE 가 필터 번호를 새로 매겨 기록 {renumbered}건의 번호를 맞췄습니다(같은 필터 키)"))?;
        }
        Ok(renumbered)
    }

    /// 서비스 시작 시: BFE 와 DB 대조
    pub fn reconcile(&mut self) -> Result<(usize, usize)> {
        self.sync_filter_keys()?;
        // 예전 형식(ip_family 없음) 행 정규화 (21차 Q4): 예전 행 1개 = 필터 1개였는데 명세는 두 체계를 원할 수 있다.
        // 그대로 두면 자가 치유가 그 행을 두 체계로 다시 넣어 필터가 늘어난다(시험에서 재현). → 살아 있는 예전 필터를
        // 지우고 주소 체계별로 다시 넣는 것을 한 트랜잭션으로(swap). 살아 있지 않으면 아래 재등록이 나눠서 넣는다.
        self.normalize_legacy_rows()?;
        let live: HashSet<u64> = self.backend.list_ours().map_err(EngineError::Backend)?.into_iter().collect();
        let mut db_ids: HashSet<u64> = HashSet::new();
        let mut restored = 0;
        for row in self.store.all_filters()? {
            db_ids.insert(row.filter_id);
            let active = self.store.policy(row.policy_id)?.map_or(false, |p| matches!(p.state, State::Applied | State::Confirmed));
            if !live.contains(&row.filter_id) && active {
                self.reregister(row.policy_id, row)?;
                restored += 1;
            }
        }
        let orphans: Vec<u64> = live.difference(&db_ids).copied().collect();
        if !orphans.is_empty() {
            self.removing.extend(orphans.iter().copied());
            let res = self.backend.replace(&orphans, &[]);
            for id in &orphans {
                self.removing.remove(id);
            }
            res.map_err(EngineError::Backend)?;
            self.event("orphan_filters_removed", 3, format!("우리 Provider 에 기록에 없는 필터 {}개가 있어 제거했습니다 (변조 의심)", orphans.len()))?;
        }
        // 재시작 시 미확인(Applied) 정책 = 승인이 끝나지 않은 불완전 상태 → 즉시 롤백 (11차 Q3)
        for row in self.store.policies_in(State::Applied)? {
            self.rollback(row.id, None, "system:restart-unconfirmed")?;
            self.event("policy_auto_rollback", 2, format!("재시작 시 확인되지 않은 정책 {} 을(를) 되돌렸습니다", row.name))?;
        }
        // 열린 조건 복원: 저장된 판의 조건이 우선. 없을 때(이전 판 DB)만 다시 전개한다.
        for row in self.store.policies_in(State::Confirmed)? {
            if self.restore_open_cond(row.id, row.version) {
                continue;
            }
            if let Ok(doc) = dsl::parse(&row.yaml) {
                if let Some(p) = doc.policies.first() {
                    if let Ok(exp) = dsl::expand(p, self.resolver) {
                        self.register_open_conds(row.id, row.version, p, &exp);
                    }
                }
            }
        }
        if restored > 0 {
            self.event("policy_restored", 2, format!("재시작 대조: 빠진 필터 {restored}개 재등록"))?;
        }
        Ok((restored, orphans.len()))
    }
}

fn is_address_block(s: &BlockSpec) -> bool {
    s.app_path.is_none() && s.name.contains("(주소 차단")
}

fn rules_file_name(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_ascii_lowercase()
}
