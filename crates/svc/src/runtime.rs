//! 엔진 스레드와 명령 큐

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use api::rpc::Id;
use api::{Method, Response};
use dsl::expand::Resolver;
use engine::backend::{GraphQuery, WfpBackend};
use engine::{Clock, Engine};
use graph::ingest::Ingester;
use graph::store::Store;
use graph::Event;
use judge::Baseline;

use crate::dispatch::{dispatch, Caller};

/// 엔진이 지금 처리 중인 명령을 시작한 시각(프로세스 시작 기준 ms + 1, 0 = 쉬는 중). hello 가 엔진 밖에서 읽는다(27차 Gemini Q1)
static ENGINE_BUSY_SINCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PROC_T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
fn mono_ms() -> u64 {
    PROC_T0
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
        + 1
}
/// 엔진이 한 명령을 지금 몇 ms 째 처리 중인가(쉬는 중이면 0)
pub fn engine_busy_ms() -> u64 {
    let s = ENGINE_BUSY_SINCE.load(std::sync::atomic::Ordering::SeqCst);
    if s == 0 {
        0
    } else {
        mono_ms().saturating_sub(s)
    }
}

/// 서버 판(hello 를 엔진 밖에서 답하려고 한 번 정해 둔다)
pub static SERVER_VERSION: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

/// 실시간 3(사용자 "실시간으로 문제를 찾아야 바로 해결가능함" 2026-11-07): 주기 판정 간격(초). 노트북 실측 증분 판정 평균 360ms·최대 471ms(diag-25)
pub const JUDGE_EVERY_SECS: u64 = 15;

/// 엔진 스레드에 보내는 명령
pub enum Command {
    /// 개발 서버(svc-dev) 전용: 수집 상태 한 줄(C1)을 시연값으로 — 실제 서비스는 보내지 않는다(수집기 없음)
    DevHealth(serde_json::Value),
    /// 개발 서버(svc-dev) 전용: 목록 조회를 빈 응답(empty)·오류(error)로 (D013 캡처)
    DevForce(String),
    /// 개발 서버(svc-dev) 시연: 살아 있음 표시(FILETIME). 실제 서비스는 수집기가 직접 남긴다(25차 Q1 기록 없는 구간)
    DevHeartbeat(i64),
    /// RPC 요청 (이미 파싱·검증·권한 확인됨)
    Rpc {
        id: Id,
        method: Method,
        params: serde_json::Value,
        caller: Caller,
        reply: Sender<Response>,
        /// 핸들러가 넣은 시각 — 엔진 대기열에서 기다린 시간을 잰다(진단 "처리 시간")
        queued: std::time::Instant,
    },
    /// L061·L066: 미끼 폴더 찾기 스레드(읽기만)가 찾은 폴더. 최근 30일 설치 엑스레이에 그 프로그램의 실제 설치가
    /// 보이면 등록에서 뺀 뒤 판정에 등록한다
    DecoyDirs(Vec<String>),
    /// 수집기 ProcessStart (틈 메우기)
    ProcessStart {
        pid: u32,
        image: String,
        parent_image: String,
    },
    /// 수집 이벤트 배치 (저장 스레드 → 그래프). 테스트·재현용: 엔진이 직접 그래프에 넣는다
    Ingest(Vec<Event>),
    /// 수집 세션이 이미 저장한 배치의 복사본 (A18). 그래프에 다시 넣지 않고 ProcessStart 틈 메우기·종료만 한다
    Batch(Vec<Event>),
    /// 주기 판정(JUDGE_EVERY_SECS 마다)
    Judge,
    /// 기준선 학습 (하루 1회 자동 + 명시 호출)
    Learn,
    Tick,
    Resume,
    TimeChanged,
    /// 알림 구독: 연결의 송신기 등록. kind = "events" | "connections"
    Subscribe {
        conn_id: u64,
        kind: String,
        sink: Sender<String>,
    },
    Unsubscribe {
        conn_id: u64,
    },
    /// 서비스가 남기는 사건 (A26: 파이프 이름 점유자, 데이터 폴더 치움 등). 알림 대기열 경유
    RecordEvent {
        kind: String,
        severity: u8,
        detail: String,
    },
    /// 대상(JSON: 프로세스 {pid, create_ft, image} 등)을 가리키는 사건 (A29)
    RecordEventRef {
        kind: String,
        severity: u8,
        detail: String,
        target: String,
    },
    /// 10판 5-9 (3): Defender 운영 로그에서 읽은 CFA 기록(읽기 스레드가 보낸다). 책갈피로 새 것만 서비스 사건이 된다
    DefenderEvents(Vec<crate::defender::DefEvent>),
    Shutdown,
}

/// 엔진 스레드가 들고 있는 상태
pub struct World<'a> {
    pub engine: Engine<'a>,
    pub graph: Store,
    pub baseline: Baseline,
    pub server_version: String,
    pub settings: HashMap<String, serde_json::Value>,
    pub subs: HashMap<u64, (String, Sender<String>)>,
    pub last_judge_ts: i64,
    /// 기준선 학습 마지막 시각 (unix 초). 하루 1회
    pub last_learn_wall: i64,
    /// 알림 보낸 사건 (뿌리 → 마지막 장). 장이 올라갈 때만 다시 알린다
    pub notified: HashMap<i64, i64>,
    /// OS 부품: 리스닝 포트, 프로세스 종료 (NoHost 면 사건만 남긴다)
    pub host: Box<dyn Host>,
    /// 승인 대기 중인 맡긴 변경 (A23)
    pub changes: crate::change::ChangeBook,
    /// 시스템 시각 변경을 받은 때(unix 초, 최근 것 32개) — 수집 상태 한 줄(C1)
    pub clock_changes: Vec<i64>,
    /// "오늘 처음"(A2) 판정용: 하루 전까지 30일 안에 본 ASN·국가 코드. (계산한 unix 초, ASN, 국가) — 10분마다 다시 센다
    /// svc-dev 시연값(C1). 실제 서비스에서는 늘 None
    pub dev_health: Option<serde_json::Value>,
    /// 개발 서버(svc-dev --force empty|error) 전용: D013 목록 상태 캡처용으로 목록 조회를 빈 응답·오류로
    pub dev_force: Option<String>,
    /// 엔진에서 직접 처리할 때의 읽기 캐시(오늘 한 일·"오늘 처음"). 작업자가 있으면 작업자 쪽 캐시를 쓴다
    pub read: crate::reads::ReadState,
    /// 읽기 캐시 세대 — 올리면 작업자도 오늘 한 일 캐시를 버린다
    pub read_gen: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// 구조 개선 C: 읽기 작업자(story.today·connections.list). None 이면 엔진이 직접
    pub reader: Option<Sender<crate::reads::ReadJob>>,
    /// L030: 판정 결과 캐시 (계산 시각 wall, since_ts, 사건들)
    pub judge_cache: Option<(i64, i64, std::sync::Arc<Vec<judge::Story>>)>,
    /// 구조 개선 B: 주기 판정(1분, 보관 기간 전체)의 결과. 조회(story.events 기본·process.detail)는 이것만 읽는다.
    /// None 이면(시작 직후·변경 요청 뒤) 조회가 쓰지 않는 판정(judge::assess)으로 한 번 채운다
    pub judged: Option<(i64, std::sync::Arc<Vec<judge::Story>>)>,
    /// 마지막 보관 정리 시각(엔진 wall). 0 = 아직(시작 뒤 첫 주기 판정 다음에 돈다)
    pub last_retention_wall: i64,
    /// 실시간 3: 판정은 15초마다, 설치 목록 미리 계산은 그대로 1분마다(마지막 계산 벽시각)
    pub last_install_wall: i64,
    /// 진단 "처리 시간"
    pub timings: Timings,
    /// story.events 문장 캐시: (뿌리, 화법, 사건 내용 해시) → (만든 시각 wall, 문장).
    /// L052: 판정 결과 세대로 열쇠를 삼으면 이야기 화면의 30초 판정 캐시가 바뀔 때마다 모든 문장을 다시 만들었다(노트북 평균 2.5초).
    /// 사건 내용(선·점수·이유)이 같으면 같은 문장이다 — 내용으로 열쇠를 삼고, 실행 횟수처럼 사건 밖에서 변하는 숫자를 위해 10분이 지나면 다시 만든다
    pub narr_cache: std::collections::HashMap<(i64, String, u64), (i64, story::events::Narrative)>,
    /// judged·judge_cache 를 새로 넣을 때마다 오르는 세대(결과마다 따로 기억 — judged_gen·judge_cache_gen)
    pub judge_gen: u64,
    /// judged 를 넣을 때의 세대
    pub judged_gen: u64,
    /// judge_cache 를 넣을 때의 세대
    pub judge_cache_gen: u64,
    /// 첫 실행 관찰실(17판 23-2 ①): 서명·출신 확인을 기다리는 프로세스 (프로세스 키 `pid@생성 시각`, 넣은 엔진 벽시각)
    pub first_run_pending: Vec<(String, i64)>,
    /// L066: 실제 설치가 보여 판정 등록에서 뺀 미끼 폴더
    pub decoys_retired: Vec<String>,
    /// L070: 지난번 찾기에서 찾은 미끼 폴더(사라짐 비교용). None = 아직 한 번도 안 찾음
    pub decoys_seen: Option<Vec<String>>,
    /// L069: 설치 목록 미리 계산(주기 판정 뒤). installs.list 는 이것만 읽는다
    pub install_cache: graph::install::InstallCache,
    /// 원격 제어 사기 경보(14판 20-4): 원격 도구 프로세스와 세션 모양 추적
    pub remote: crate::remote_watch::RemoteWatch,
    /// AI 에이전트 감시(14판 20-5) 미리 계산: (계산한 엔진 벽시각, 최근 7일 목록). agents.list 는 이것만 읽는다
    pub agent_cache: Option<(i64, Vec<graph::agent::AgentRun>)>,
    /// 37차 Q2: 지난번 본 (별칭, LUID) 짝. 바뀌면 인터페이스 조건 규칙을 지금 LUID 로 다시 건다. None = 아직 못 봄
    pub if_seen: Option<Vec<(String, u64)>>,
    /// 개편안 2판 1-2②: 우리 WFP 필터 id 집합 — 차단 집계 스레드와 공유, 주기 판정마다 갱신
    pub our_filters: crate::blocked::OurFilters,
    /// 갈래 C: 증분 주기 판정기(메모리 뷰·사슬 캐시). 결과는 전체 판정과 같다(judge 시험).
    /// 30번에 한 번·보관 정리 뒤·기준선 학습 뒤·"정상" 피드백 뒤·오류 뒤에는 전체를 다시 읽는다.
    /// SF_JUDGE_INCREMENTAL=0 이면 매번 전체(현장에서 되돌리기용)
    pub judge_inc: judge::Incremental,
}

pub struct Runtime {
    pub tx: Sender<Command>,
    handle: Option<JoinHandle<()>>,
    /// 차단 집계 스레드가 참조하는 우리 필터 집합(엔진 스레드가 채움)
    pub our_filters: crate::blocked::OurFilters,
}

pub use crate::host::{Host, NoHost};

/// 엔진 스레드가 쓸 OS 의존 부품을 만드는 공장. 스레드 안에서 호출되므로 `Send` 만 필요.
pub trait Parts: Send + 'static {
    fn build(
        self: Box<Self>,
    ) -> (
        Box<dyn WfpBackend>,
        Box<dyn GraphQuery>,
        Box<dyn Clock>,
        Box<dyn Resolver>,
        rusqlite::Connection,
        Store,
        Vec<String>,
    );
}

impl Runtime {
    /// 엔진 스레드를 띄운다. `parts` 가 백엔드·시계·DB 를 스레드 안에서 만든다.
    pub fn start(parts: Box<dyn Parts>, server_version: &str) -> Runtime {
        Self::start_with(parts, server_version, None)
    }

    /// OS 부품(리스닝 포트·종료)을 붙여 띄운다 (서비스). None 이면 NoHost.
    pub fn start_with(
        parts: Box<dyn Parts>,
        server_version: &str,
        host: Option<Box<dyn Host>>,
    ) -> Runtime {
        let our_filters: crate::blocked::OurFilters = Default::default();
        let our_filters_thread = our_filters.clone();
        let host: Box<dyn Host> = host.unwrap_or_else(|| Box::new(NoHost));
        let (tx, rx) = mpsc::channel::<Command>();
        let ver = server_version.to_string();
        if let Ok(mut g) = SERVER_VERSION.write() {
            *g = ver.clone();
        }
        let handle = std::thread::Builder::new()
            .name("engine".into())
            .spawn(move || {
                let (mut backend, graph_q, clock, resolver, conn, graph, protected) = parts.build();
                let protected_refs: Vec<&str> = protected.iter().map(|s| s.as_str()).collect();
                let engine = Engine::new(
                    conn,
                    backend.as_mut(),
                    graph_q.as_ref(),
                    clock.as_ref(),
                    resolver.as_ref(),
                    &protected_refs,
                )
                .expect("engine");
                // graph·judge 는 FILETIME(100ns, 1601 기준), engine·api 는 unix 초. 경계는 여기 한 곳에서만 바꾼다.
                let baseline =
                    Baseline::open(&graph, unix_to_filetime(clock.wall())).expect("baseline");
                let read_gen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let db_path = graph.path();
                let last_learn: i64 = graph
                    .get_meta("baseline_learned_at")
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                // 27차: 설정(보관 정책 포함)은 그래프 DB meta 에 저장 — 재시작 뒤에도 남는다(전에는 메모리에만)
                let settings: HashMap<String, serde_json::Value> = graph
                    .get_meta("settings")
                    .ok()
                    .flatten()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                let mut world = World {
                    engine,
                    graph,
                    baseline,
                    server_version: ver,
                    settings,
                    last_retention_wall: 0,
                    last_install_wall: 0,
                    timings: Timings::default(),
                    narr_cache: std::collections::HashMap::new(),
                    judge_gen: 0,
                    judged_gen: 0,
                    judge_cache_gen: 0,
                    judge_inc: {
                        let mut j = judge::Incremental::new();
                        // 실시간 3: 판정 주기 60초 → 15초. 전체 판정은 지금처럼 30분마다(15초 × 120)
                        j.full_every = (30 * 60 / JUDGE_EVERY_SECS) as u32;
                        j.enabled =
                            std::env::var("SF_JUDGE_INCREMENTAL").map_or(true, |v| v != "0");
                        j
                    },
                    subs: HashMap::new(),
                    last_judge_ts: 0,
                    // L047(시작 직후 엔진을 7.4초 잡음): 마지막 학습 시각을 DB 에 남겨, 재시작마다 다시 배우지 않는다(하루 1회 그대로)
                    last_learn_wall: last_learn,
                    notified: HashMap::new(),
                    host,
                    changes: Default::default(),
                    clock_changes: Vec::new(),
                    read: Default::default(),
                    read_gen: read_gen.clone(),
                    reader: crate::reads::spawn(&db_path, read_gen),
                    judge_cache: None,
                    judged: None,
                    dev_health: None,
                    dev_force: None,
                    first_run_pending: Vec::new(),
                    decoys_retired: Vec::new(),
                    decoys_seen: None,
                    install_cache: graph::install::InstallCache::default(),
                    remote: Default::default(),
                    agent_cache: None,
                    if_seen: None,
                    our_filters: our_filters_thread.clone(),
                };
                crate::first_run::ensure_table(&world.graph);
                crate::triage::ensure_table(&world.graph);
                // 35차 Q2: 보관했던 장부 이름 되살리기(기한 지난 것은 버림)
                if let Some(js) = world.graph.get_meta("ledger_names").ok().flatten() {
                    if let Ok(rows) =
                        serde_json::from_str::<Vec<(String, Vec<(u32, i64)>, i64)>>(&js)
                    {
                        graph::ledger::import_names(rows, unix_to_filetime(world.engine_wall()));
                    }
                }
                // 재시작 대조: 누락 재등록·고아 제거·미확인 롤백
                let _ = world.engine.reconcile();
                run_loop(&mut world, rx, clock.as_ref());
            })
            .expect("spawn engine thread");
        Runtime {
            tx,
            handle: Some(handle),
            our_filters,
        }
    }

    pub fn shutdown(mut self) {
        let _ = self.tx.send(Command::Shutdown);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// unix 초 → Windows FILETIME (100ns, 1601-01-01 기준)
pub fn unix_to_filetime(unix_secs: i64) -> i64 {
    (unix_secs + 11_644_473_600) * 10_000_000
}

/// AI 도구 목록을 다시 계산하는 간격(초)
const AGENT_EVERY_SECS: i64 = 300;

fn run_loop(world: &mut World, rx: Receiver<Command>, clock: &dyn Clock) {
    // TIMECHANGE 합치기 중에 받은 다른 명령을 다음 바퀴로 넘기는 자리
    let mut pending: Option<Command> = None;
    loop {
        // 기준선 시계를 엔진 시계에 맞춘다 (judge 는 FILETIME)
        world.baseline.now_ts = unix_to_filetime(clock.wall());
        // 하루 1회 기준선 학습 (판정 전에)
        if clock.wall() - world.last_learn_wall >= 86_400 {
            let t = std::time::Instant::now();
            ENGINE_BUSY_SINCE.store(mono_ms(), std::sync::atomic::Ordering::SeqCst);
            let _idle = BusyGuard;
            if let Ok(view) = judge::View::load(&world.graph, 0, i64::MAX) {
                let _ = world.baseline.learn(&world.graph, &view);
            }
            world.last_learn_wall = clock.wall();
            let _ = world
                .graph
                .set_meta("baseline_learned_at", &world.last_learn_wall.to_string());
            world
                .timings
                .record("엔진: 하루 1회 기준선 학습", t.elapsed());
        }
        let wait = world.engine.next_wakeup().unwrap_or(60).max(1) as u64;
        let cmd = match pending.take() {
            Some(c) => c,
            None => match rx.recv_timeout(Duration::from_secs(wait)) {
                Ok(c) => c,
                Err(mpsc::RecvTimeoutError::Timeout) => Command::Tick,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            },
        };
        let label = cmd_label(&cmd);
        let t0 = std::time::Instant::now();
        ENGINE_BUSY_SINCE.store(mono_ms(), std::sync::atomic::Ordering::SeqCst);
        let _idle = BusyGuard;
        match cmd {
            Command::Shutdown => return,
            Command::RecordEvent {
                kind,
                severity,
                detail,
            } => {
                let _ = world.engine.record_event(&kind, severity, detail);
                flush_events(world);
            }
            Command::RecordEventRef {
                kind,
                severity,
                detail,
                target,
            } => {
                let _ = world
                    .engine
                    .record_event_ref(&kind, severity, detail, Some(target));
                flush_events(world);
            }
            Command::DefenderEvents(evs) => defender_events(world, evs),
            Command::Tick => {
                // 35차 Q2: 변경 장부가 이은 예약 작업·서비스 이름(30일)을 그래프 DB 에 보관 — 서비스·PC 재시작 뒤에도 잇게
                if let Some(rows) = graph::ledger::take_dirty_names() {
                    if let Ok(js) = serde_json::to_string(&rows) {
                        let _ = world.graph.set_meta("ledger_names", &js);
                    }
                }
                let _ = world.engine.tick();
                crate::first_run::sweep(world);
                crate::remote_watch::sample(world);
                flush_events(world);
            }
            Command::Resume => {
                let _ = world.engine.on_resume();
                flush_events(world);
            }
            Command::TimeChanged => {
                // SCM 은 시각 변경 1회에 TIMECHANGE 를 2건 보낸다(A17 러너 실측). 1초 안에 잇달아 온 것은 하나로 합친다.
                loop {
                    match rx.recv_timeout(Duration::from_secs(1)) {
                        Ok(Command::TimeChanged) => continue,
                        Ok(other) => {
                            pending = Some(other);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => break,
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
                let _ = world.engine.on_time_changed();
                let now = world.engine_wall();
                world.clock_changes.push(now);
                if world.clock_changes.len() > 32 {
                    world.clock_changes.remove(0);
                }
                flush_events(world);
            }
            Command::ProcessStart {
                pid,
                image,
                parent_image,
            } => {
                process_start(world, pid, &image, &parent_image, None);
                flush_events(world);
            }
            Command::Batch(events) => {
                for ev in &events {
                    if let graph::event::EventKind::ProcessStart {
                        pid,
                        ppid,
                        image,
                        create_time,
                    } = &ev.kind
                    {
                        // 부모 이미지는 그래프에서 (같은 PID 중 가장 최근 시작)
                        let parent_image = world
                            .graph
                            .latest_process_by_pid(*ppid, ev.ts)
                            .ok()
                            .flatten()
                            .and_then(|id| world.graph.node(id).ok())
                            .and_then(|n| n.attr("image"))
                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                            .unwrap_or_default();
                        process_start(world, *pid, image, &parent_image, *create_time);
                    }
                }
                // 첫 실행 관찰실: 이 배치의 ProcessStart 를 대기 목록에 넣고, 서명·출신이 온 것을 판단한다
                crate::first_run::on_batch(world, &events);
                // 원격 제어 사기 경보: 도구 시작·끝을 받고, 때가 됐으면 송신량을 잰다
                crate::remote_watch::on_batch(world, &events);
                crate::remote_watch::sample(world);
                flush_events(world);
            }
            Command::Ingest(events) => {
                let mut ing = Ingester::new(&world.graph);
                let _ = ing.ingest_all(&events);
                world.judged = None;
                world.judge_cache = None;
                world.invalidate_reads();
            }
            Command::Judge => {
                // 1분마다: 새로 쌓인 기록이 다음 조회에 보이게(캐시는 그 사이 30초만 산다)
                world.judge_cache = None;
                world.invalidate_reads();
                // L050: 판정과 보관 정리를 처리 시간 표에 따로 남긴다(87초가 어느 쪽인지 가르게)
                let tj = std::time::Instant::now();
                judge_and_notify(world);
                world.timings.record("엔진: 주기 판정", tj.elapsed());
                refresh_our_filters(world);
                // L069(32차 검수 4): 설치 목록 미리 계산 — 조회 때 계산하지 않는다(2초 원칙)
                if world.engine_wall() - world.last_install_wall >= 60 {
                    world.last_install_wall = world.engine_wall();
                    let ti = std::time::Instant::now();
                    let now_ft = unix_to_filetime(world.engine_wall());
                    if let Err(e) = world.install_cache.refresh(&world.graph, now_ft, 300) {
                        eprintln!("installs: refresh failed: {e}");
                    }
                    world
                        .timings
                        .record("엔진: 설치 목록 미리 계산", ti.elapsed());
                }
                // 14판 20-5: AI 도구 목록 미리 계산(5분마다, 최근 7일). 조회 때 계산하지 않는다(2초 원칙)
                if world
                    .agent_cache
                    .as_ref()
                    .is_none_or(|(at, _)| world.engine_wall() - at >= AGENT_EVERY_SECS)
                {
                    let ta = std::time::Instant::now();
                    let since = unix_to_filetime(world.engine_wall() - 7 * 86_400);
                    match graph::agent::agent_activity(&world.graph, since, 50, 300) {
                        Ok(v) => world.agent_cache = Some((world.engine_wall(), v)),
                        Err(e) => eprintln!("agents: refresh failed: {e}"),
                    }
                    world
                        .timings
                        .record("엔진: AI 도구 미리 계산", ta.elapsed());
                }
                // 37차 Q2: 어댑터 재설치·이름 바꾸기로 별칭↔LUID 짝이 바뀌면 인터페이스 규칙을 다시 건다(시작 때는 reconcile 이 함)
                if let Ok(ifs) = world.host.interfaces() {
                    let mut now: Vec<(String, u64)> =
                        ifs.into_iter().map(|i| (i.alias, i.luid)).collect();
                    now.sort();
                    if world.if_seen.as_ref().is_some_and(|prev| *prev != now) {
                        match world.engine.rebind_interfaces() {
                            Ok(n) => eprintln!("netif: changed, rebound {n} filters"),
                            Err(e) => eprintln!("netif: rebind failed: {e}"),
                        }
                    }
                    world.if_seen = Some(now);
                }
                // 27차: 보관 정리 — 판정이 먼저 장(chapter)을 남긴 뒤(의심 사건 선은 30일 보존), 1시간마다
                if world.engine_wall() - world.last_retention_wall >= RETENTION_EVERY_SECS {
                    let tr = std::time::Instant::now();
                    run_retention(world);
                    world.timings.record("엔진: 보관 정리", tr.elapsed());
                }
                // L056: 처리 시간 표를 데이터 폴더에 남긴다 — 노트북 확인을 화면 제어 없이(작업 실행기 diag 가 읽는다)
                write_timings_file(world);
            }
            Command::DevHealth(v) => {
                world.dev_health = Some(v);
            }
            Command::DevForce(f) => {
                world.dev_force = Some(f);
            }
            Command::DevHeartbeat(ft) => {
                let _ = graph::views::heartbeat(&world.graph, ft);
            }
            Command::DecoyDirs(dirs) => register_decoys(world, dirs),
            Command::Learn => {
                if let Ok(view) = judge::View::load(&world.graph, 0, i64::MAX) {
                    let _ = world.baseline.learn(&world.graph, &view);
                }
                // 갈래 C: 기준선이 바뀌었다 — 다음 주기 판정은 전체 다시(점수는 캐시하지 않아 결과에는 필요 없지만 안전망)
                world.judge_inc.invalidate();
                world.last_learn_wall = clock.wall();
                let _ = world
                    .graph
                    .set_meta("baseline_learned_at", &world.last_learn_wall.to_string());
            }
            Command::Subscribe {
                conn_id,
                kind,
                sink,
            } => {
                world.subs.insert(conn_id, (kind, sink));
            }
            Command::Unsubscribe { conn_id } => {
                world.subs.remove(&conn_id);
            }
            Command::Rpc {
                id,
                method,
                params,
                caller,
                reply,
                queued,
            } => {
                world.timings.record("(대기열)", queued.elapsed());
                // 구조 개선 C: 무거운 읽기는 작업자로 넘기고 기다리지 않는다(응답은 작업자가 reply 로).
                // 개발 서버 강제 모드(dev_force)는 엔진의 dispatch 가 처리하므로 넘기지 않는다
                if crate::reads::is_heavy_read(method) && world.dev_force.is_none() {
                    if let Some(rd) = &world.reader {
                        let job = crate::reads::ReadJob {
                            id,
                            method,
                            params,
                            caller,
                            now: world.engine_wall(),
                            reply,
                            enqueued: std::time::Instant::now(),
                        };
                        if let Err(mpsc::SendError(job)) = rd.send(job) {
                            // 작업자가 죽었다 → 이후로는 엔진이 직접
                            world.reader = None;
                            let resp = dispatch(world, job.id, job.method, job.params, &job.caller);
                            let _ = job.reply.send(resp);
                        }
                        continue;
                    }
                }
                let resp = dispatch(world, id, method, params, &caller);
                let _ = reply.send(resp);
                flush_events(world);
                world.timings.record(method.name(), t0.elapsed());
                continue;
            }
        }
        world.timings.record(label, t0.elapsed());
    }
}

/// 명령 하나가 끝나면(continue·return 포함) 쉬는 중으로
struct BusyGuard;
impl Drop for BusyGuard {
    fn drop(&mut self) {
        ENGINE_BUSY_SINCE.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

/// 진단 "처리 시간": 엔진 명령·RPC 메서드별 횟수·평균·최대·마지막(ms). 노트북에서 diag 없이 느린 곳을 찾는다
#[derive(Default)]
pub struct Timings(pub HashMap<&'static str, (u64, u128, u128, u128)>);
impl Timings {
    pub fn record(&mut self, name: &'static str, d: Duration) {
        let ms = d.as_millis();
        let e = self.0.entry(name).or_insert((0, 0, 0, 0));
        e.0 += 1;
        e.1 += ms;
        e.2 = e.2.max(ms);
        e.3 = ms;
    }
    /// 최대가 큰 순, 상위 n
    pub fn to_json(&self, n: usize) -> serde_json::Value {
        let mut v: Vec<_> = self.0.iter().collect();
        v.sort_by(|a, b| b.1 .2.cmp(&a.1 .2));
        serde_json::Value::Array(
            v.into_iter()
                .take(n)
                .map(|(k, (c, tot, max, last))| serde_json::json!({ "name": k, "count": c, "avg_ms": (*tot / (*c).max(1) as u128) as u64, "max_ms": *max as u64, "last_ms": *last as u64 }))
                .collect(),
        )
    }
}

fn cmd_label(c: &Command) -> &'static str {
    match c {
        Command::DevHealth(_) => "dev.health",
        Command::DevForce(_) => "dev.force",
        Command::DevHeartbeat(_) => "dev.heartbeat",
        Command::Rpc { .. } => "rpc",
        Command::ProcessStart { .. } => "엔진: 프로세스 시작",
        Command::Ingest(_) => "엔진: 수집 넣기",
        Command::Batch(_) => "엔진: 수집 배치",
        Command::Judge => "엔진: 주기 판정·보관 정리",
        Command::Learn => "엔진: 기준선 학습",
        Command::DecoyDirs(_) => "엔진: 미끼 등록",
        Command::Tick => "엔진: 틱",
        Command::Resume => "엔진: 재개",
        Command::TimeChanged => "엔진: 시계 변경",
        Command::DefenderEvents(_) => "엔진: Defender 기록",
        _ => "엔진: 기타",
    }
}

impl<'a> World<'a> {
    /// 엔진 시계의 벽시각(unix 초). 기준선 now_ts(FILETIME)에서 되돌린다
    /// 읽기 캐시(오늘 한 일)를 버린다 — 엔진 쪽 캐시와 작업자 캐시 모두
    pub fn invalidate_reads(&mut self) {
        self.read.today_cache = None;
        self.read_gen
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn engine_wall(&self) -> i64 {
        self.baseline.now_ts / 10_000_000 - 11_644_473_600
    }
    pub fn notify(&mut self, kind: &str, params: serde_json::Value) {
        let line = api::Notification::new(kind, params).to_line();
        let mut dead = Vec::new();
        let want = if kind == api::methods::NOTIFY_EVENT {
            "events"
        } else {
            "connections"
        };
        for (id, (k, sink)) in &self.subs {
            if k == want && sink.send(line.clone()).is_err() {
                dead.push(*id);
            }
        }
        for id in dead {
            self.subs.remove(&id);
        }
    }
}

/// 엔진이 쌓은 사건을 구독자에게 흘리고 비운다
/// Defender CFA 기록 → 서비스 사건. 책갈피(graph meta "defender_last_record")는 서비스를 다시 켜도 같은 기록을 두 번 남기지 않게 한다
pub fn defender_events(world: &mut World, evs: Vec<crate::defender::DefEvent>) {
    let last = world
        .graph
        .get_meta("defender_last_record")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<u64>().ok());
    let (keep, next) = crate::defender::select_new(evs, last, world.engine_wall());
    for e in &keep {
        if let Some((kind, sev, detail, target)) = crate::defender::to_service_event(e) {
            let _ = world
                .engine
                .record_event_ref(&kind, sev, detail, Some(target.to_string()));
        }
    }
    if let Some(n) = next {
        if Some(n) != last {
            let _ = world.graph.set_meta("defender_last_record", &n.to_string());
        }
    }
    if !keep.is_empty() {
        flush_events(world);
    }
}

pub fn flush_events(world: &mut World) {
    let evs: Vec<engine::EventRecord> = world.engine.events.drain(..).collect();
    for e in evs {
        world.notify(api::methods::NOTIFY_EVENT, serde_json::json!({"kind": e.kind, "severity": e.severity, "detail": e.detail, "ts": e.ts}));
    }
}

/// 마지막 판정 이후 구간을 판정하고, 새 의심 사건(장이 올라간 것)만 알린다
/// ProcessStart 틈 메우기: 열린 조건에 맞으면 필터 추가, `also: terminate` 면 종료기 호출(없으면 사건만)
fn process_start(
    world: &mut World,
    pid: u32,
    image: &str,
    parent_image: &str,
    create_time: Option<i64>,
) {
    if let Ok(kill) = world.engine.on_process_start(pid, image, parent_image) {
        for p in kill {
            // 생성 시각: 이 ProcessStart 의 것(같은 PID). 모르면 None → Windows 종료기는 이미지 대조 없이는 거부하지 않으므로
            // 틈 메우기 경로에서는 ProcessStart 직후라 PID 재사용 창이 거의 없다.
            let outcome = world
                .host
                .terminate(p, if p == pid { create_time } else { None });
            let _ = world.engine.record_event(
                "terminate_requested",
                2,
                format!("pid {p} {image} → {outcome}"),
            );
        }
    }
}

/// 의심 사건 알림 규칙 (14차 Q1). `prev` = 이 뿌리로 마지막에 알린 장(의심일 때만 기록됨).
/// ① 처음 의심 등급(70점)을 넘은 때: 장이 그대로여도 알린다 — 기록이 없으므로 prev=None
/// ② 이미 알린 뒤에는 장이 올라갈 때만
pub fn should_notify(prev: Option<i64>, level: judge::Level, chapter: i64) -> bool {
    matches!(level, judge::Level::Suspicious | judge::Level::Critical) && chapter > prev.unwrap_or(0)
}

/// 우리 WFP 필터 id 집합을 차단 집계 스레드와 맞춘다(엔진 장부 기준, 주기 판정마다)
fn refresh_our_filters(world: &mut World) {
    if let Ok(rows) = world.engine.store.all_filters() {
        let set: std::collections::HashSet<u64> = rows.iter().map(|r| r.filter_id).collect();
        if let Ok(mut g) = world.our_filters.write() {
            if *g != set {
                *g = set;
            }
        }
    }
}

/// 보관 정리 주기(초)
pub const RETENTION_EVERY_SECS: i64 = 3600;

/// 현재 보관 정책: 설정의 같은 이름 항목(raw_days 등) + 나머지는 기본값, 안전 범위로
pub fn retention_policy(world: &World) -> graph::retention::RetentionPolicy {
    let obj: serde_json::Map<String, serde_json::Value> = world
        .settings
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    serde_json::from_value::<graph::retention::RetentionPolicy>(serde_json::Value::Object(obj))
        .unwrap_or_default()
        .sanitized()
}

/// 보관 정책 적용(이야기형 3판 11장). 결과는 meta "retention_last" 에 남겨 retention.get·diag 로 본다
pub fn run_retention(world: &mut World) {
    let now = world.engine_wall();
    world.last_retention_wall = now;
    let policy = retention_policy(world);
    let t = std::time::Instant::now();
    // 27차 Gemini Q9: 하루씩 나눠 짧은 트랜잭션으로(수집기 쓰기를 오래 막지 않게)
    let r = graph::retention::apply_chunked(&world.graph, unix_to_filetime(now), policy);
    let ms = t.elapsed().as_millis() as i64;
    let rec = match &r {
        Ok(rep) => serde_json::json!({
            "at": now, "ms": ms, "ok": true,
            "raw_deleted": rep.raw_deleted + rep.raw_deleted_by_size, "edges_compacted": rep.edges_compacted,
            "provenance_deleted": rep.provenance_deleted, "suspicious_deleted": rep.suspicious_deleted,
            "summaries_deleted": rep.summaries_deleted, "nodes_deleted": rep.nodes_deleted, "raw_bytes_after": rep.raw_bytes_after,
            // L050: 단계별(ms) — 접기·출신·의심 / 원시 / 용량 / 고아 노드 / 파일 회수·통계
            "phases": { "fold": rep.ms_fold, "raw": rep.ms_raw, "size": rep.ms_size, "nodes": rep.ms_nodes },
        }),
        Err(e) => serde_json::json!({ "at": now, "ms": ms, "ok": false, "error": e.to_string() }),
    };
    // 28차 Gemini 아이디어 1: 지운 자리를 파일에서 돌려주고(INCREMENTAL 인 새 DB 만 — 아니면 효과 없음) 질의 통계 갱신
    let tv = std::time::Instant::now();
    let _ = world
        .graph
        .conn()
        .execute_batch("PRAGMA incremental_vacuum(4096); PRAGMA optimize;");
    let mut rec = rec;
    if rec["phases"].is_object() {
        rec["phases"]["vacuum_optimize"] = serde_json::json!(tv.elapsed().as_millis() as u64);
    }
    let _ = world.graph.set_meta("retention_last", &rec.to_string());
    // 사건 추적: 1년 넘은 처리 기록, 뿌리가 사라진 상태 행
    let _ = crate::triage::prune(&world.graph, now);
    if let Ok(rep) = r {
        if rep.edges_compacted + rep.provenance_deleted + rep.suspicious_deleted + rep.nodes_deleted
            > 0
        {
            // 지운 선을 가리키는 판정 결과·캐시는 버린다(다음 조회가 쓰지 않는 판정으로 다시 채운다)
            // 증분 판정기도 다음 번에 전체를 다시 읽는다(보관 정리가 남긴 "전체 다시" 표시와 같은 뜻 — 이중 안전)
            world.judge_inc.invalidate();
            world.judged = None;
            world.judge_cache = None;
            world.invalidate_reads();
        }
    }
}

/// 주기 판정: 장(chapter)을 DB 에 쓰고 결과를 World 에 둔다 — 조회는 이 결과만 읽는다(구조 개선 B)
/// 처리 시간 표를 graph.db 옆 timings.json 으로(메모리 DB 면 건너뜀). 실패해도 엔진은 계속
fn write_timings_file(world: &World) {
    let Some(db) = world.graph.conn().path().map(std::path::PathBuf::from) else {
        return;
    };
    let Some(dir) = db.parent() else { return };
    if db.as_os_str().is_empty() {
        return;
    }
    let body =
        serde_json::json!({ "wall": world.engine_wall(), "timings": world.timings.to_json(40) });
    let tmp = dir.join("timings.json.tmp");
    if std::fs::write(&tmp, body.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join("timings.json"));
    }
}

pub fn judge_and_notify(world: &mut World) {
    let from = world.last_judge_ts;
    let t0 = std::time::Instant::now();
    let stories = match world
        .judge_inc
        .run(&world.graph, from, i64::MAX, &world.baseline)
    {
        Ok((s, p)) => {
            // 갈래 C: 증분과 전체(30분마다·보관 정리 뒤)를 따로 — 평소(증분) 시간이 전체에 가려지지 않게
            let label = if p.mode == "incremental" {
                "엔진: 주기 판정(증분)"
            } else {
                "엔진: 주기 판정(전체)"
            };
            world.timings.record(label, t0.elapsed());
            // L055: 주기 판정이 노트북에서 5초대 — 어느 구간인지 진단 화면에서 보이게
            world.timings.record("엔진: 주기 판정: 불러오기", p.load);
            world.timings.record("엔진: 주기 판정: 후보 찾기", p.roots);
            world
                .timings
                .record("엔진: 주기 판정: 사슬 모으기", p.chain);
            world.timings.record("엔진: 주기 판정: 점수", p.score);
            world.timings.record("엔진: 주기 판정: 장 기록", p.write);
            std::sync::Arc::new(s)
        }
        Err(_) => return,
    };
    if from == 0 {
        world.judged = Some((world.engine_wall(), stories.clone()));
        world.judge_gen += 1;
        world.judged_gen = world.judge_gen;
        // L052: 무거운 문장 만들기는 조회 때가 아니라 주기 작업에서 — 대시보드 첫 쪽(기본 화법)을 미리 만들어 둔다
        let t = std::time::Instant::now();
        crate::dispatch::warm_story_narratives(world);
        world
            .timings
            .record("엔진: 이야기 문장 미리 만들기", t.elapsed());
    }
    // 사건 추적: 조치함·닫힘인 사건은 알리지 않는다. 다만 조치 때보다 높은 장까지 이어졌으면(재발) 새 사건으로 되돌리고 알린다
    let triage = crate::triage::all(&world.graph);
    let now = world.engine_wall();
    for s in stories.iter() {
        let ch = s.chapter as i64;
        let mut quiet = false;
        if let Some(rec) = triage.get(&s.root).filter(|r| !r.state.is_open()) {
            let dst = crate::dispatch::story_dst(&world.graph, s);
            let Some(why) = crate::triage::recur_if_escalated(&world.graph, s.root, rec, ch, s.score, &dst, now) else {
                continue;
            };
            world.notified.remove(&s.root);
            let text = match why {
                crate::triage::Recur::Escalated { from, to } => format!("{from}장에서 조치했는데 {to}장까지 이어짐"),
                crate::triage::Recur::NewDst(k) => format!("조치 뒤 새 접속지·등록 {k}곳"),
            };
            let _ = world.engine.record_event(
                "story_recurred",
                2,
                format!("뿌리 {} {} — {}", s.root, s.root_label, text),
            );
            // 39차 Q2③: 재발 알림 상한 — 그 뒤로는 카드에만 남는다
            quiet = rec.recur_count + 1 > crate::triage::RECUR_NOTIFY_MAX;
        }
        if quiet {
            world.notified.insert(s.root, ch);
            continue;
        }
        if should_notify(world.notified.get(&s.root).copied(), s.level, ch) {
            world.notified.insert(s.root, ch);
            world.notify(api::methods::NOTIFY_EVENT, serde_json::json!({"kind": "story_suspicious", "severity": 2, "root": s.root, "label": s.root_label, "chapter": ch, "score": s.score}));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::should_notify;
    use judge::Level;
    #[test]
    fn engine_busy_ms_counts_while_guarded() {
        use super::{engine_busy_ms, mono_ms, BusyGuard, ENGINE_BUSY_SINCE};
        {
            ENGINE_BUSY_SINCE.store(mono_ms(), std::sync::atomic::Ordering::SeqCst);
            let _g = BusyGuard;
            std::thread::sleep(std::time::Duration::from_millis(120));
            assert!(engine_busy_ms() >= 100);
        }
        assert_eq!(engine_busy_ms(), 0);
    }
    #[test]
    fn first_crossing_notifies_even_without_chapter_change() {
        // 2장 65점(주의) → 알림 없음, 기록 없음
        assert!(!should_notify(None, Level::Watch, 2));
        // 같은 2장에서 75점(의심) → 처음 넘었으니 알림
        assert!(should_notify(None, Level::Suspicious, 2));
        // 알린 뒤 같은 장 → 알림 없음, 장이 오르면 알림
        assert!(!should_notify(Some(2), Level::Suspicious, 2));
        assert!(should_notify(Some(2), Level::Suspicious, 3));
    }
}

/// L066(30차 Q9-d): 실제 프로그램 설치가 보이는 미끼는 판정에 등록하지 않는다. 물러난 폴더는 World 에 둔다(화면 표시는 후속)
pub fn register_decoys(world: &mut World, dirs: Vec<String>) {
    let since = unix_to_filetime(world.engine_wall() - 30 * 86_400);
    let mut installs: Vec<(String, Vec<String>)> =
        graph::install::installs(&world.graph, since, 50, 300, |_| true)
            // 31차 Gemini Q3: 이름 조각만으로 미끼를 빼면 탈취 도구가 싸게 끈다 — 설치 파일이 유효 서명일 때만
            .map(|v| {
                v.into_iter()
                    .filter(|r| r.signer.is_some())
                    .map(|r| (r.image, r.files))
                    .collect()
            })
            .unwrap_or_default();
    // 설치로 잡히지 않은 설치(이름에 setup 없음)도 그 프로그램이 실행되면 보인다: 이름 조각이 든 실행 파일
    for c in decoy::CANDIDATES {
        installs.extend(ran_images_like(&world.graph, c.keyword, since));
    }
    // L070(30차 Q9-b): 지난번에 있던 미끼가 사라졌으면 사실로 남긴다(물러난 것은 빼고). 판단은 하지 않는다
    if let Some(prev) = &world.decoys_seen {
        let gone = decoy::vanished(prev, &dirs, &world.decoys_retired);
        for d in &gone {
            let _ = world.engine.record_event(
                "decoy_missing",
                2,
                format!("미끼 폴더가 사라졌습니다: {d} — 누가 지웠는지는 이 기록만으로 알 수 없습니다(사용자 정리·백신·다른 프로그램 모두 가능)"),
            );
        }
        if !gone.is_empty() {
            flush_events(world);
        }
    }
    world.decoys_seen = Some(dirs.clone());
    let (keep, retired) = decoy::retire_for_installs(dirs, &installs);
    world.decoys_retired = retired;
    judge::rules::set_decoy_dirs(keep);
}

/// 이 시각 이후 실행된(executed_as) 실행 파일 중 경로에 `kw` 가 든 것(최대 20개). 근거 목록용 — 쓴 파일은 비운다
fn ran_images_like(g: &graph::Store, kw: &str, since: i64) -> Vec<(String, Vec<String>)> {
    let pat = format!("%{}%", kw.replace(['%', '_'], ""));
    let Ok(mut st) = g.conn().prepare_cached(
        // 31차 Gemini Q3: 유효 서명이 있는 실행 파일만(이름에 'exodus' 가 든 아무 파일로 미끼를 끄지 못하게)
        "SELECT DISTINCT n.key FROM nodes n JOIN edges e ON e.src = n.id AND e.rel = 'executed_as' \
         WHERE n.kind = 'file' AND lower(n.key) LIKE ?1 AND e.ts >= ?2 \
           AND json_extract(n.attrs_json, '$.sig_status') = 'valid' LIMIT 20",
    ) else {
        return Vec::new();
    };
    st.query_map(rusqlite::params![pat, since], |r| r.get::<_, String>(0))
        .map(|rows| {
            rows.filter_map(|r| r.ok())
                .map(|k| (k, Vec::new()))
                .collect()
        })
        .unwrap_or_default()
}
