//! 수집 파이프라인: 세션 시작 → 스냅샷 → 저장 스레드 → 폴링 스레드 → 종료 → 보고

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ferrisetw::trace::{KernelTrace, TraceProperties, UserTrace};
use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::Store;

use crate::ctx::Ctx;
use crate::{
    conntable, etw, origin, paths, scm, session_stats, snapshot, token, CollectorError, Result,
};

pub const SESSION_NAME: &str = "StoryFirewall-Collector";
/// 10판 5-9 (1): 명령줄용 커널 세션(시스템 로거 모드, 프로세스 플래그만)
pub const KERNEL_SESSION_NAME: &str = "StoryFirewall-Kernel";

#[derive(Debug, Clone)]
pub struct Config {
    pub db_path: String,
    pub duration: Duration,
    /// P6 실험 공급자(RPC·WinHttp·CAPI2) 활성화
    pub experimental: bool,
    /// 채널 상한 (명세 4판 2-2: 10만)
    pub channel_capacity: usize,
    /// 저장 트랜잭션 묶음: 건수 또는 시간
    pub batch_events: usize,
    pub batch_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: "collector.db".into(),
            duration: Duration::from_secs(20),
            experimental: false,
            channel_capacity: 100_000,
            batch_events: 100,
            batch_interval: Duration::from_millis(200),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Report {
    pub events_ingested: u64,
    pub edges_created: u64,
    pub dropped: u64,
    /// PID 별 초당 상한(PER_PID_PER_SEC)을 넘겨 버린 이벤트 수 (로컬 DoS 완화)
    pub rate_limited: u64,
    pub missing_fields: u64,
    pub counts: HashMap<String, u64>,
    pub snapshot_processes: usize,
    pub snapshot_path_unknown: usize,
    pub scm_pids: usize,
    pub conntable_missed: u64,
    pub bytes_rows_flushed: u64,
    pub file_ring_len: usize,
    pub session: Option<session_stats::SessionStats>,
    pub session_error: Option<u32>,
    pub schema_notes: Vec<(String, u16)>,
    pub experimental_dumps: Vec<String>,
    pub elapsed: Duration,
    pub skipped_no_client_pid: u64,
    pub chains_found: u64,
    pub new_images: Vec<String>,
    pub file_ring_tail: Vec<String>,
    pub volumes: Vec<(String, String)>,
    pub rename_methods: HashMap<String, u64>,
    /// P8: 용량 flush 1회 최대 소요(ms), flush 간격 최대(ms) — 1초 flush 가 2초를 넘으면 실패
    pub max_flush_ms: u128,
    pub max_flush_gap_ms: u128,
    pub max_bytes_rows_per_flush: usize,
    pub motw_found: u64,
    pub signatures_done: u64,
    pub capi2_chains: u64,
    pub capi2_fetches: u64,
    /// A20: 해시한 파일 수 (서명 없음·MOTW 실행 파일)
    pub hashes: u64,
    /// 17판 23-2 ②: Kernel-File 열기(12) 받은 총수 — 브라우저 금고 경비가 늘린 부하 진단(보낸 수는 counts 의 vault_open)
    pub file_opens_seen: u64,
    /// 저장에 실패해 버린 배치 수 (세션은 계속). 0 이 아니면 그래프에 구멍이 있다
    pub store_failed: u64,
    /// 수집 중 감지한 시스템 시각 변경 수와 가장 큰 변경(ms). ETW 시각은 QPC 로 받아 영향이 없다 (qpc.rs)
    pub clock_jumps: u64,
    pub clock_max_jump_ms: i64,
}

/// FILETIME 현재 시각 (100ns, 1601 기준)
pub fn now_filetime() -> i64 {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    unix.as_nanos() as i64 / 100 + 116_444_736_000_000_000
}

/// 배치형: `duration` 만큼 돌고 보고서를 돌려준다 (A3 PoC·러너용).
pub fn run(cfg: Config) -> Result<Report> {
    let dur = cfg.duration;
    let session = start(cfg, None)?;
    thread::sleep(dur);
    session.stop()
}

/// 상시 세션 (A18, 서비스용). `stop()` 할 때까지 돈다.
pub struct Session {
    stop: Arc<AtomicBool>,
    ctx: Arc<Ctx>,
    handle: Option<JoinHandle<Result<Report>>>,
    pub session_start: i64,
}

impl Session {
    /// 세션을 멈추고 보고서를 돌려준다. 남은 큐·출신 성분 작업을 마저 처리한다.
    pub fn stop(mut self) -> Result<Report> {
        self.stop.store(true, Ordering::Relaxed);
        match self.handle.take() {
            Some(h) => h
                .join()
                .unwrap_or_else(|_| Err(CollectorError::Trace("저장 스레드 panic".into()))),
            None => Err(CollectorError::Trace("이미 멈춤".into())),
        }
    }
    /// 29차 미결: 살아 있는 동안 진단 카운터(공급자별 콜백 수 + 명령줄 수집 상태)를 읽는 함수. 서비스 진단이 부른다
    pub fn counts_reader(&self) -> impl Fn() -> Vec<(String, u64)> + Send + Sync + 'static {
        let ctx = self.ctx.clone();
        move || {
            let mut v: Vec<(String, u64)> = ctx
                .counts
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect();
            v.push((
                "cmdline_unmatched".into(),
                ctx.cmd_rv.lock().unwrap().unmatched,
            ));
            v.sort();
            v
        }
    }
    /// 저장 스레드가 아직 살아 있는가
    pub fn is_alive(&self) -> bool {
        self.handle.as_ref().map_or(false, |h| !h.is_finished())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// 세션을 시작한다: ETW 세션 → 스냅샷(동기) → 저장 스레드. `sink` 가 있으면 저장한 배치의 복사본을 보낸다
/// (서비스가 ProcessStart 틈 메우기·판정 트리거에 쓴다). 저장은 이 세션만 한다(단일 기록자).
pub fn start(cfg: Config, sink: Option<Sender<Vec<Event>>>) -> Result<Session> {
    let started = Instant::now();
    let store = Store::open(&cfg.db_path)?;
    let volumes = paths::volume_table();
    let (tx, rx) = sync_channel::<Event>(cfg.channel_capacity);
    let ctx = Arc::new(Ctx::new(tx, volumes));
    let ctx_out = ctx.clone();

    // ① ETW 세션 시작 — 스냅샷보다 먼저. 그 사이 생긴 프로세스는 큐에 쌓인다 (명세 4판 2-2).
    let _ = ferrisetw::trace::stop_trace_by_name(SESSION_NAME);
    // 3차 검증 Q4: 가벼운 러너에서도 25초에 버퍼 20개를 썼다. 실사용 PC 를 생각해 128KB × 128 (16MB) 를
    // 최소로 잡고 상한은 512 로 열어 둔다. 메모리를 아낄 곳이 아니다 (EventsLost 는 영구 구멍).
    let props = TraceProperties {
        buffer_size: 128,
        min_buffer: 128,
        max_buffer: 512,
        flush_timer: Duration::from_secs(1),
        ..TraceProperties::default()
    };
    // ETW 시각을 QPC 원시 값으로 받는다 (ctx.ts 가 벽시계로 바꾼다, qpc.rs). 세션을 열기 전에 켜야 한다
    ferrisetw::RAW_TIMESTAMP.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut builder = UserTrace::new()
        .named(SESSION_NAME.to_string())
        .set_trace_properties(props)
        .enable(etw::process_provider(ctx.clone()))
        .enable(etw::network_provider(ctx.clone()))
        .enable(etw::dns_provider(ctx.clone()))
        .enable(etw::file_provider(ctx.clone()))
        .enable(etw::task_provider(ctx.clone()))
        .enable(etw::capi2_provider(ctx.clone()));
    if cfg.experimental {
        builder = builder.enable(etw::experimental_provider(
            ctx.clone(),
            etw::WINHTTP,
            "exp:winhttp",
            None,
        ));
    }
    // 출신 성분 작업 스레드 (MOTW·서명). 세션 시작 전에 띄워 큐가 바로 받게 한다.
    let (origin_tx, origin_rx) = sync_channel::<origin::OriginJob>(10_000);
    *ctx.origin_tx.lock().unwrap() = Some(origin_tx);
    let origin_stop = Arc::new(AtomicBool::new(false));
    let origin_worker = {
        let ctx = ctx.clone();
        let st = origin_stop.clone();
        thread::spawn(move || origin::worker(origin_rx, ctx, st))
    };
    let trace = builder
        .start_and_process()
        .map_err(|e| CollectorError::Trace(format!("{e:?}")))?;
    // 명령줄 커널 세션: 실패해도 수집은 계속(직접 읽기 대비 경로만 남는다)
    let _ = ferrisetw::trace::stop_trace_by_name(KERNEL_SESSION_NAME);
    let ktrace = match KernelTrace::new()
        .named(KERNEL_SESSION_NAME.to_string())
        .enable(etw::kernel_process_provider(ctx.clone()))
        .start_and_process()
    {
        Ok(t) => {
            ctx.count("kernel_session_ok");
            Some(t)
        }
        Err(e) => {
            eprintln!("kernel session failed: {e:?}");
            ctx.count("kernel_session_failed");
            None
        }
    };
    let session_start = now_filetime();

    // ② 프로세스 스냅샷 + SCM 매핑. Ingester 가 PID@CreateTime 으로 중복을 걸러 준다.
    let snap =
        snapshot::take().map_err(|e| CollectorError::Win32(e, "CreateToolhelp32Snapshot"))?;
    let services = scm::map().unwrap_or_default();
    let mut report = Report {
        snapshot_processes: snap.len(),
        snapshot_path_unknown: snap.iter().filter(|p| !p.path_known).count(),
        scm_pids: services.len(),
        ..Report::default()
    };
    let snap_ts = session_start;
    {
        let mut ing = Ingester::new(&store);
        ing.set_boot_time(snapshot::boot_filetime(snap_ts));
        let tx = store.begin_write()?;
        for p in &snap {
            if p.pid == 0 {
                continue;
            }
            let ct = if p.create_time > 0 {
                p.create_time
            } else {
                snap_ts
            };
            let ev = Event::new(
                snap_ts,
                "snapshot",
                EventKind::ProcessSnapshot {
                    pid: p.pid,
                    ppid: p.ppid,
                    image: p.image.clone(),
                    create_time: ct,
                    services: services.get(&p.pid).cloned().unwrap_or_default(),
                },
            );
            report.edges_created += ing.ingest(&ev)? as u64;
            report.events_ingested += 1;
            // A30: 로그온 세션 (서비스는 SYSTEM 이라 모든 프로세스에 대해 된다. 실패하면 비워 둔다 = 범위 판정에서 "모름")
            if let Some(session) = snapshot::session_of(p.pid) {
                ing.ingest(&Event::new(
                    snap_ts,
                    "snapshot",
                    EventKind::ProcessSession {
                        pid: p.pid,
                        create_time: ct,
                        session,
                    },
                ))?;
            }
            // 서비스 호스트 PID 의 토큰과 서명 (3조건 판별 재료)
            if let Some(svcs) = services.get(&p.pid) {
                let tok = token::system_token(p.pid);
                let ev = Event::new(
                    snap_ts,
                    "scm",
                    EventKind::ServiceMap {
                        pid: p.pid,
                        services: svcs.clone(),
                        system_token: tok,
                        create_time: (p.create_time > 0).then_some(p.create_time),
                    },
                );
                ing.ingest(&ev)?;
                if p.path_known {
                    ctx.enqueue_origin(&p.image, Duration::from_millis(0), false, true);
                }
            }
        }
        tx.commit()?;
    }
    store.set_meta("session_start", &session_start.to_string())?;
    store.set_meta("os_version", &os_version())?;

    // ④ 폴링 스레드: 연결 테이블(누락 대조)·SCM·용량 flush·세션 통계. 저장은 저장 스레드가 한다.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_out = stop.clone();
    let handle = thread::Builder::new()
        .name("collector-store".into())
        .spawn(move || -> Result<Report> {
            let mut ing = Ingester::new(&store);
            let mut gaps: Vec<graph::views::Gap> = Vec::new();
            // 25차 Q1: 시작하자마자 살아 있음 표시 — 직전 실행의 마지막 표시와 벌어진 사이(서비스 중지·절전)가 "기록 없는 구간"으로 남는다
            let _ = graph::views::heartbeat(&store, now_filetime());
            let mut last_beat = Instant::now();
            let poll_tx = ctx.tx.clone();
            let poll_ctx = ctx.clone();
            let poll_stop = stop.clone();
            // 35차 Q3: 서비스 레지스트리 변경 알림 — 새 서비스·ImagePath 바꿔치기를 바로(5초 목록 비교의 틈을 메움)
            let reg_stop = stop.clone();
            let reg_ctx = ctx.clone();
            let _svcreg = thread::spawn(move || {
                crate::svcreg::watch(reg_stop, |name| {
                    if graph::ledger::service_registered(name, now_filetime()) {
                        reg_ctx.count("ledger_service_reg_notify");
                    }
                });
            });
            let poller = thread::spawn(move || -> (u64, Vec<session_stats::SessionStats>) {
                let mut reported: HashSet<(u32, String, u16)> = HashSet::new();
                let mut last_services: HashMap<u32, Vec<String>> = HashMap::new();
                // 34차 Q1 보강: 모든 서비스 이름(5초마다 비교). None = 아직 기준 없음(처음 읽은 목록은 새 등록으로 치지 않는다)
                let mut all_services: Option<HashSet<String>> = None;
                let mut tick: u64 = 0;
                let mut missed = 0u64;
                let mut stats = Vec::new();
                while !poll_stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(1));
                    poll_ctx.sample_clock();
                    let ts = now_filetime();
                    tick += 1;
                    if tick % 5 == 0 {
                        if let Ok(names) = scm::all_names() {
                            if let Some(prev) = &all_services {
                                for n in names.difference(prev) {
                                    if graph::ledger::service_registered(n, ts) {
                                        poll_ctx.count("ledger_service_register");
                                    }
                                }
                            }
                            all_services = Some(names);
                        }
                    }
                    // SCM 변화분만 ServiceMap 으로
                    if let Ok(map) = scm::map() {
                        for (pid, svcs) in &map {
                            if last_services.get(pid) != Some(svcs) {
                                // 장부에 이은 서비스가 새 호스트 pid 로 시작됨 → 그 pid 를 물려받음
                                for sv in svcs {
                                    if graph::ledger::service_launched(sv, *pid, ts) {
                                        poll_ctx.count("ledger_service_launch");
                                    }
                                }
                                let tok = token::system_token(*pid);
                                let _ = poll_tx.try_send(Event::new(
                                    ts,
                                    "scm",
                                    EventKind::ServiceMap {
                                        pid: *pid,
                                        services: svcs.clone(),
                                        system_token: tok,
                                        create_time: snapshot::create_time_of(*pid),
                                    },
                                ));
                            }
                        }
                        // 사라진 서비스 호스트 PID: 빈 매핑을 보내 그래프의 PID→서비스 기억을 지운다(전에는 남아 PID 재사용 프로세스가 물려받았다)
                        for pid in last_services.keys().filter(|p| !map.contains_key(p)) {
                            let _ = poll_tx.try_send(Event::new(
                                ts,
                                "scm",
                                EventKind::ServiceMap {
                                    pid: *pid,
                                    services: Vec::new(),
                                    system_token: None,
                                    create_time: None,
                                },
                            ));
                        }
                        // 34차 Q2: 변경 장부 대리 창 — 작업 스케줄러 서비스(Schedule)를 담은 svchost 만 예약 작업 호스트로
                        let sched: Vec<u32> = map
                            .iter()
                            .filter(|(_, svcs)| svcs.iter().any(|s| s.eq_ignore_ascii_case("Schedule")))
                            .map(|(p, _)| *p)
                            .collect();
                        graph::ledger::set_schedule_hosts(&sched);
                        last_services = map;
                    }
                    // 연결 테이블: ETW 가 못 본 ESTABLISHED 아웃바운드
                    if let Ok(conns) = conntable::tcp_connections() {
                        let seen = poll_ctx.seen_connects.lock().unwrap().clone();
                        for c in conntable::missed_by_etw(&conns, &seen, &mut reported) {
                            missed += 1;
                            let _ = poll_tx.try_send(Event::new(
                                ts,
                                "conntable",
                                EventKind::Connect {
                                    proc: ProcRef::new(c.pid, None),
                                    proto: Proto::Tcp,
                                    direction: Direction::Out,
                                    laddr: c.local.to_string(),
                                    lport: c.lport,
                                    raddr: c.remote.to_string(),
                                    rport: c.rport,
                                },
                            ));
                        }
                    }
                    if let Ok(s) = session_stats::query(SESSION_NAME) {
                        stats.push(s);
                    }
                }
                (missed, stats)
            });

            // ③ 저장 루프: 채널 → Ingester → SQLite, 배치 트랜잭션. 1초마다 용량 카운터 flush. stop 플래그까지.
            let mut last_flush = Instant::now();
            loop {
                let (n_ev, n_edges) = drain_batch_resilient(
                    &rx,
                    &store,
                    &mut ing,
                    cfg.batch_events,
                    cfg.batch_interval,
                    sink.as_ref(),
                    &mut report.store_failed,
                    &mut gaps,
                );
                report.events_ingested += n_ev;
                report.edges_created += n_edges;
                if last_flush.elapsed() >= Duration::from_secs(1) {
                    report.max_flush_gap_ms = report
                        .max_flush_gap_ms
                        .max(last_flush.elapsed().as_millis());
                    let t0 = Instant::now();
                    let n = flush_bytes(&ctx, &store).unwrap_or_else(|_| {
                        report.store_failed += 1;
                        0
                    });
                    report.max_flush_ms = report.max_flush_ms.max(t0.elapsed().as_millis());
                    report.max_bytes_rows_per_flush =
                        report.max_bytes_rows_per_flush.max(n as usize);
                    report.bytes_rows_flushed += n;
                    last_flush = Instant::now();
                }
                if last_beat.elapsed()
                    >= Duration::from_secs(graph::views::HEARTBEAT_EVERY_SECS as u64)
                {
                    let _ = graph::views::heartbeat(&store, now_filetime());
                    last_beat = Instant::now();
                }
                if stop.load(Ordering::Relaxed) {
                    // 정상 종료: 마지막 표시 — 다음 시작까지가 "기록 없는 구간"이 된다
                    let _ = graph::views::heartbeat(&store, now_filetime());
                    break;
                }
            }

            // 종료: 폴링 중단 → 세션 통계 마지막 조회 → 세션 중지 → 남은 큐 비우기
            stop.store(true, Ordering::Relaxed);
            let final_stats = session_stats::query(SESSION_NAME);
            let _ = trace.stop();
            if let Some(k) = ktrace {
                let _ = k.stop();
            }
            let (missed, _hist) = poller.join().unwrap_or((0, Vec::new()));
            report.conntable_missed = missed;
            loop {
                let (n_ev, n_edges) = drain_batch_resilient(
                    &rx,
                    &store,
                    &mut ing,
                    cfg.batch_events,
                    Duration::from_millis(50),
                    sink.as_ref(),
                    &mut report.store_failed,
                    &mut gaps,
                );
                report.events_ingested += n_ev;
                report.edges_created += n_edges;
                if n_ev == 0 {
                    break;
                }
            }
            report.bytes_rows_flushed += flush_bytes(&ctx, &store)?;
            // 출신 성분 큐를 마저 비우고 결과를 저장
            origin_stop.store(true, Ordering::Relaxed);
            *ctx.origin_tx.lock().unwrap() = None;
            let (motw_found, sigs_done) = origin_worker.join().unwrap_or((0, 0));
            report.motw_found = motw_found;
            report.signatures_done = sigs_done;
            loop {
                let (n_ev, n_edges) = drain_batch_resilient(
                    &rx,
                    &store,
                    &mut ing,
                    cfg.batch_events,
                    Duration::from_millis(50),
                    sink.as_ref(),
                    &mut report.store_failed,
                    &mut gaps,
                );
                report.events_ingested += n_ev;
                report.edges_created += n_edges;
                if n_ev == 0 {
                    break;
                }
            }
            report.capi2_chains = ctx.capi2_chains.load(Ordering::Relaxed);
            report.capi2_fetches = ctx.capi2_fetches.load(Ordering::Relaxed);
            report.hashes = ctx.hashes.load(Ordering::Relaxed);
            report.file_opens_seen = ctx.file_opens_seen.load(Ordering::Relaxed);

            match final_stats {
                Ok(s) => report.session = Some(s),
                Err(e) => report.session_error = Some(e),
            }
            report.dropped = ctx.dropped.load(Ordering::Relaxed);
            report.rate_limited = ctx.rate_limited.load(Ordering::Relaxed);
            report.missing_fields = ctx.missing_fields.load(Ordering::Relaxed);
            report.counts = ctx
                .counts
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect();
            report.file_ring_len = ctx.files.lock().unwrap().len();
            report.experimental_dumps = ctx.exp_dumps.lock().unwrap().clone();
            report.skipped_no_client_pid = ctx.skipped_no_client_pid.load(Ordering::Relaxed);
            report.chains_found = ctx.chains_found.load(Ordering::Relaxed);
            report.new_images = ctx.new_images.lock().unwrap().clone();
            report.file_ring_tail = ctx
                .files
                .lock()
                .unwrap()
                .tail(30)
                .iter()
                .map(|f| format!("{} {} {:?} <- {:?}", f.ts, f.kind, f.path, f.from))
                .collect();
            report.volumes = ctx.volumes.clone();
            report.rename_methods = ctx
                .rename_methods
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect();
            {
                let notes = ctx.schema_notes.lock().unwrap();
                for ((prov, id), js) in notes.iter() {
                    store.set_meta(&format!("schema:{prov}:{id}"), js)?;
                    report.schema_notes.push((prov.clone(), *id));
                }
                report.schema_notes.sort();
            }
            {
                let c = ctx.clock.lock().unwrap();
                report.clock_jumps = c.jumps;
                report.clock_max_jump_ms = c.max_jump / 10_000;
            }
            store.set_meta("clock_jumps", &report.clock_jumps.to_string())?;
            store.set_meta("clock_max_jump_ms", &report.clock_max_jump_ms.to_string())?;
            store.set_meta("events_dropped", &report.dropped.to_string())?;
            store.set_meta("store_failed_batches", &report.store_failed.to_string())?;
            store.set_meta("events_rate_limited", &report.rate_limited.to_string())?;
            store.set_meta("events_missing_fields", &report.missing_fields.to_string())?;
            if let Some(s) = &report.session {
                store.set_meta("etw_events_lost", &s.events_lost.to_string())?;
                store.set_meta(
                    "etw_realtime_buffers_lost",
                    &s.realtime_buffers_lost.to_string(),
                )?;
            }
            report.elapsed = started.elapsed();
            Ok(report)
        })
        .map_err(|e| CollectorError::Trace(format!("저장 스레드 생성 실패: {e}")))?;
    Ok(Session {
        stop: stop_out,
        ctx: ctx_out,
        handle: Some(handle),
        session_start,
    })
}

/// 채널에서 최대 `max` 건 또는 `window` 동안 받아 한 트랜잭션으로 넣는다. (받은 수, 만든 선 수)
/// 저장 실패가 수집 세션을 끝내지 않게 감싼다 (17차 질문 3 ①). 쓰기 잠금은 begin_write 에서 최대 3번(각 busy_timeout 5초) 기다리고,
/// 그래도 실패하거나 넣는 도중 실패하면 그 배치를 버리고(store_failed 에 셈) Ingester 를 새로 만든다 —
/// 되돌린 트랜잭션의 선 id 를 캐시가 쥐고 있으면, 다시 배정된 같은 id 에 근거가 잘못 붙을 수 있기 때문.
fn drain_batch_resilient<'s>(
    rx: &Receiver<Event>,
    store: &'s Store,
    ing: &mut Ingester<'s>,
    max: usize,
    window: Duration,
    sink: Option<&Sender<Vec<Event>>>,
    failed: &mut u64,
    gaps: &mut Vec<graph::views::Gap>,
) -> (u64, u64) {
    match drain_batch(rx, store, ing, max, window, sink, gaps) {
        Ok(r) => r,
        Err(gap) => {
            *failed += 1;
            *ing = Ingester::new(store);
            if let Some(g) = gap {
                // 구멍은 다음에 성공한 트랜잭션에 함께 적는다 (지금은 쓰기가 안 되므로)
                gaps.push(g);
            }
            (0, 0)
        }
    }
}

/// 배치 하나를 저장. 실패하면 버린 배치의 시각 구간(구멍)을 돌려준다 (17차 Q3 답변: 이야기에 "기록 일부 누락" 표시).
fn drain_batch(
    rx: &Receiver<Event>,
    store: &Store,
    ing: &mut Ingester,
    max: usize,
    window: Duration,
    sink: Option<&Sender<Vec<Event>>>,
    gaps: &mut Vec<graph::views::Gap>,
) -> std::result::Result<(u64, u64), Option<graph::views::Gap>> {
    let mut batch: Vec<Event> = Vec::with_capacity(max);
    let until = Instant::now() + window;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || batch.len() >= max {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(ev) => batch.push(ev),
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    if batch.is_empty() {
        return Ok((0, 0));
    }
    // 같은 배치 안에서는 시각 순으로 (공급자별 콜백 순서가 섞일 수 있음)
    batch.sort_by_key(|e| e.ts);
    let gap = graph::views::Gap {
        from_ts: batch[0].ts,
        to_ts: batch[batch.len() - 1].ts,
        events: batch.len() as i64,
        reason: "store_failed".into(),
    };
    let mut tries = 0;
    let tx = loop {
        match store.begin_write() {
            Ok(t) => break t,
            Err(graph::GraphError::Sqlite(e))
                if tries < 2
                    && matches!(
                        e.sqlite_error_code(),
                        Some(
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        )
                    ) =>
            {
                tries += 1
            }
            Err(_) => return Err(Some(gap)),
        }
    };
    // 밀린 구멍 기록
    for g in gaps.iter() {
        if graph::views::record_gap(&tx, g).is_err() {
            return Err(Some(gap));
        }
    }
    let mut edges = 0u64;
    for ev in &batch {
        match ing.ingest(ev) {
            Ok(n) => edges += n as u64,
            Err(_) => return Err(Some(gap)),
        }
    }
    if tx.commit().is_err() {
        return Err(Some(gap));
    }
    gaps.clear();
    let n = batch.len() as u64;
    if let Some(sk) = sink {
        let _ = sk.send(batch);
    }
    Ok((n, edges))
}

fn flush_bytes(ctx: &Ctx, store: &Store) -> Result<u64> {
    let taken = ctx.take_bytes();
    if taken.is_empty() {
        return Ok(0);
    }
    let ts = now_filetime();
    let tx = store.begin_write()?;
    for (k, b) in &taken {
        store.add_conn_bytes(k.pid, k.proto, &k.raddr, k.rport, b.sent, b.recv, ts)?;
    }
    tx.commit()?;
    Ok(taken.len() as u64)
}

fn os_version() -> String {
    // 레지스트리 없이 간단히: 환경 변수와 cmd ver 는 쓰지 않고, RtlGetVersion 대신 빌드 번호는 러너 로그에서 확인
    std::env::var("OS").unwrap_or_else(|_| "windows".into())
}
