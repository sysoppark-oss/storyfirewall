//! 구조 개선 C(2026-11-03): 무거운 읽기 조회(story.today·connections.list)를 엔진 스레드 밖의 읽기 작업자에서.
//! 작업자는 읽기 전용 SQLite 연결(query_only)을 따로 가지고, 엔진은 현재 시각만 붙여 넘긴 뒤 응답을 기다리지 않는다.
//! 메모리 DB(테스트)·작업자 시작 실패면 엔진이 같은 함수를 직접 부른다(같은 코드 경로).
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;

use api::rpc::Id;
use api::{ErrorCode, Method, Response, RpcError};
use graph::store::Store;

use crate::dispatch::{internal, voice_of, Caller, Scope, CACHE_SECS, TODAY_MAX_EDGES};

/// 읽기 조회의 캐시 (작업자 또는 엔진이 가진다)
#[derive(Default)]
pub struct ReadState {
    /// L030: 오늘 한 일 캐시 (계산 시각 wall, since 분, voice, 문장, 잘림)
    pub today_cache: Option<(i64, i64, String, Arc<Vec<story::render::Sentence>>, bool)>,
    /// "오늘 처음"(A2): 하루 전까지 30일 안에 본 ASN·국가 (계산 시각, ASN, 국가) — 10분마다
    pub seen_before: Option<(
        i64,
        std::collections::HashSet<u32>,
        std::collections::HashSet<String>,
    )>,
    /// 엔진이 캐시를 버리라고 올린 세대(수집·판정·변경 요청). 다르면 today_cache 를 버린다
    gen: u64,
}

/// 작업자에게 넘기는 조회 한 건
pub struct ReadJob {
    pub id: Id,
    pub method: Method,
    pub params: serde_json::Value,
    pub caller: Caller,
    /// 엔진 시계의 벽시각(unix 초) — 시험 시계·시계 변경과 같은 기준을 쓰도록 엔진이 붙인다
    pub now: i64,
    /// 엔진이 넘긴 순간 — 대기열에서 너무 오래 기다린 요청은 버린다(27차 Gemini Q4)
    pub enqueued: std::time::Instant,
    pub reply: Sender<Response>,
}

/// 50차 1단계: 파이프 연결 스레드(handler)가 엔진을 거치지 않고 읽기 작업자에게 조회를 직접 넘기는 문.
/// 엔진이 판정·정리로 바쁜 동안에도 story.today·connections.list 가 답한다. 엔진 스레드가 작업자를 띄운 뒤 채운다.
#[derive(Clone, Default)]
pub struct Gate(Arc<GateInner>);

#[derive(Default)]
struct GateInner {
    tx: std::sync::Mutex<Option<Sender<ReadJob>>>,
    /// 50차 Q3(Gemini 수용): 이야기 목록(스냅숏) 전용 작업자 — 넓은 범위 연결 목록 같은 무거운 DB 조회가 줄을 잡아도 인시던트 목록은 따로 답한다.
    /// None 이면 위 작업자가 함께 맡는다
    tx_story: std::sync::Mutex<Option<Sender<ReadJob>>>,
    /// 이야기 목록 작업자 줄에 들어가 아직 꺼내지 않은 조회 수
    pending_story: Arc<std::sync::atomic::AtomicUsize>,
    /// 엔진 시계의 벽시각(unix 초) — 엔진이 한 바퀴 돌 때마다 맞춘다. 엔진이 바쁜 동안은 그만큼 늦다(범위가 조금 앞에서 시작할 뿐)
    now: std::sync::atomic::AtomicI64,
    /// 작업자 대기열에 들어가 아직 꺼내지 않은 조회 수
    pending: Arc<std::sync::atomic::AtomicUsize>,
    /// 개발 서버 강제 모드(dev_force) — 엔진의 dispatch 가 처리해야 하므로 직접 넘기지 않는다
    forced: std::sync::atomic::AtomicBool,
    /// 작업자 길의 처리 시간(진단 "처리 시간" 표에 엔진 것과 함께 나간다) — 엔진을 거치지 않아 엔진 표에는 안 남는다
    stats: std::sync::Mutex<crate::runtime::Timings>,
    /// 50차 2단계: 엔진이 판정 결과가 바뀔 때 내놓는 조회용 스냅숏(분당 몇 번 바뀜 — 잠깐 잠그고 Arc 만 복제)
    snap: std::sync::Mutex<Option<Arc<crate::events::StorySnap>>>,
    /// 문장 캐시(엔진·문장 스레드·작업자가 함께 쓴다). 엔진의 World 가 이것을 그대로 쓴다
    narr: crate::events::NarrCache,
    /// 작업자가 문장을 못 만든 사건을 만났다 — 엔진이 다음 정리에서 미리 만들기를 하도록
    warm_wanted: std::sync::atomic::AtomicBool,
}

/// 작업자 대기열 상한(50차 Q3): 일반 사용자 조회 홍수가 작업자 줄을 끝없이 늘리지 않게 — 넘으면 바로 busy
pub const MAX_PENDING_READS: usize = 16;

/// 직접 넘기기 결과
pub enum Direct {
    /// 넘겼다 — 응답은 reply 로 온다
    Sent,
    /// 줄이 가득 찼다 — busy 로 답한다
    Full(ReadJob),
    /// 문이 닫혀 있다(작업자 없음·강제 모드) — 엔진으로 보낸다
    Closed(ReadJob),
}

impl Gate {
    /// 엔진 스레드: 작업자를 띄운 뒤 문을 연다
    pub fn open(&self, tx: Sender<ReadJob>, now: i64) {
        self.set_now(now);
        if let Ok(mut g) = self.0.tx.lock() {
            *g = Some(tx);
        }
    }
    /// 엔진 스레드: 이야기 목록 전용 작업자를 띄운 뒤 그 길을 연다
    pub fn open_story(&self, tx: Sender<ReadJob>) {
        if let Ok(mut g) = self.0.tx_story.lock() {
            *g = Some(tx);
        }
    }
    /// 작업자가 죽었다 — 이후로는 엔진이 직접
    pub fn close(&self) {
        if let Ok(mut g) = self.0.tx.lock() {
            *g = None;
        }
    }
    pub fn set_now(&self, now: i64) {
        self.0.now.store(now, Ordering::SeqCst);
    }
    pub fn set_forced(&self) {
        self.0.forced.store(true, Ordering::SeqCst);
    }
    pub fn now(&self) -> i64 {
        self.0.now.load(Ordering::SeqCst)
    }
    fn record(&self, name: &'static str, d: std::time::Duration) {
        if let Ok(mut t) = self.0.stats.lock() {
            t.record(name, d);
        }
    }
    /// 작업자 길의 처리 시간 사본(엔진이 진단 표에 합친다)
    pub fn stats(&self) -> Vec<(&'static str, (u64, u128, u128, u128))> {
        self.0
            .stats
            .lock()
            .map(|t| t.0.iter().map(|(k, v)| (*k, *v)).collect())
            .unwrap_or_default()
    }
    /// 엔진: 새 조회용 스냅숏을 바꿔 끼운다
    pub fn publish(&self, snap: Arc<crate::events::StorySnap>) {
        if let Ok(mut g) = self.0.snap.lock() {
            *g = Some(snap);
        }
    }
    /// 작업자: 지금 스냅숏(없으면 None — 첫 판정 전)
    pub fn snapshot(&self) -> Option<Arc<crate::events::StorySnap>> {
        self.0.snap.lock().ok().and_then(|g| g.clone())
    }
    /// 함께 쓰는 문장 캐시
    pub fn narr_cache(&self) -> crate::events::NarrCache {
        self.0.narr.clone()
    }
    /// 엔진: 작업자가 미리 만들기를 부탁했는가(읽으면 내린다)
    pub fn take_warm(&self) -> bool {
        self.0.warm_wanted.swap(false, Ordering::SeqCst)
    }
    /// handler: 조회를 작업자에게 직접 넘긴다
    pub fn submit(&self, job: ReadJob) -> Direct {
        if self.0.forced.load(Ordering::SeqCst) {
            return Direct::Closed(job);
        }
        // 이야기 목록은 전용 작업자가 있으면 그쪽으로(줄·상한도 따로)
        if job.method == Method::StoryEvents {
            match Self::send(&self.0.tx_story, &self.0.pending_story, job) {
                Ok(d) => {
                    if matches!(d, Direct::Full(_)) {
                        self.record("작업자: (가득 차 busy)", std::time::Duration::ZERO);
                    }
                    return d;
                }
                // 전용 작업자가 없거나 죽었다 → 함께 쓰는 작업자로
                Err(job) => {
                    if let Ok(mut g) = self.0.tx_story.lock() {
                        *g = None;
                    }
                    return self.submit_shared(job);
                }
            }
        }
        self.submit_shared(job)
    }

    fn submit_shared(&self, job: ReadJob) -> Direct {
        match Self::send(&self.0.tx, &self.0.pending, job) {
            Ok(d) => {
                if matches!(d, Direct::Full(_)) {
                    self.record("작업자: (가득 차 busy)", std::time::Duration::ZERO);
                }
                d
            }
            Err(job) => {
                self.close();
                Direct::Closed(job)
            }
        }
    }

    /// 한 줄에 넣는다. Err = 그 줄이 없거나 받는 쪽이 죽었다
    fn send(
        slot: &std::sync::Mutex<Option<Sender<ReadJob>>>,
        pending: &std::sync::atomic::AtomicUsize,
        job: ReadJob,
    ) -> Result<Direct, ReadJob> {
        let Ok(g) = slot.lock() else {
            return Err(job);
        };
        let Some(tx) = g.as_ref() else {
            return Err(job);
        };
        if pending.load(Ordering::SeqCst) >= MAX_PENDING_READS {
            return Ok(Direct::Full(job));
        }
        pending.fetch_add(1, Ordering::SeqCst);
        match tx.send(job) {
            Ok(()) => Ok(Direct::Sent),
            Err(mpsc::SendError(job)) => {
                dec(pending);
                Err(job)
            }
        }
    }
}

/// 0 아래로 내려가지 않게
fn dec(n: &std::sync::atomic::AtomicUsize) {
    crate::runtime::dec_saturating(n);
}

/// 작업자가 맡는 조회. story.events 는 전체 구간(since_ts 없음·0)만 — 구간 지정 판정은 엔진이 한다(50차 2-8)
pub fn is_heavy_read(m: Method, params: &serde_json::Value) -> bool {
    match m {
        Method::StoryToday | Method::ConnectionsList => true,
        Method::StoryEvents => params
            .get("since_ts")
            .is_none_or(|v| v.is_null() || v.as_i64() == Some(0)),
        _ => false,
    }
}

/// 읽기 작업자를 띄운다. 파일 DB 가 아니거나 열기에 실패하면 None (엔진이 직접 처리)
pub fn spawn(path: &str, gen: Arc<AtomicU64>) -> Option<Sender<ReadJob>> {
    spawn_counted(path, gen, &Gate::default())
}

/// `gate`: 대기 수(작업자가 한 건 꺼낼 때마다 내린다)와 처리 시간을 이 문에 남긴다
pub fn spawn_counted(path: &str, gen: Arc<AtomicU64>, gate: &Gate) -> Option<Sender<ReadJob>> {
    let gate = gate.clone();
    if path.is_empty() || path == ":memory:" {
        return None;
    }
    let store = Store::open_read_only(path).ok()?;
    let (tx, rx) = mpsc::channel::<ReadJob>();
    let pending = gate.0.pending.clone();
    std::thread::Builder::new()
        .name("reader".into())
        .spawn(move || run(store, rx, gen, gate, pending))
        .ok()?;
    Some(tx)
}

/// 이야기 목록 전용 작업자(읽기 전용 연결을 따로 가진다). 띄우지 못하면 None — 함께 쓰는 작업자가 맡는다
pub fn spawn_story(path: &str, gen: Arc<AtomicU64>, gate: &Gate) -> Option<Sender<ReadJob>> {
    let gate = gate.clone();
    if path.is_empty() || path == ":memory:" {
        return None;
    }
    let store = Store::open_read_only(path).ok()?;
    let (tx, rx) = mpsc::channel::<ReadJob>();
    let pending = gate.0.pending_story.clone();
    std::thread::Builder::new()
        .name("reader-story".into())
        .spawn(move || run(store, rx, gen, gate, pending))
        .ok()?;
    Some(tx)
}

/// 27차 Gemini Q4: 대기열에서 이보다 오래 기다린 요청은 처리하지 않고 busy 로 돌려준다(오래된 now 로 엉뚱한 범위를 보이지 않게)
pub const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(8);
/// 27차 Gemini Q5: 읽기 질의 하나가 이보다 오래 걸리면 끊는다(긴 읽기 트랜잭션이 WAL 체크포인트를 막지 않게)
pub const QUERY_LIMIT: std::time::Duration = std::time::Duration::from_secs(6);

fn run(
    store: Store,
    rx: Receiver<ReadJob>,
    gen: Arc<AtomicU64>,
    gate: Gate,
    pending: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut rs = ReadState::default();
    // 감시 스레드: 질의 마감(t0 기준 ms, 0 = 없음)이 지나면 sqlite3_interrupt — hooks 기능 없이 InterruptHandle 로
    let deadline = Arc::new(AtomicU64::new(0));
    let t0 = std::time::Instant::now();
    {
        let h = store.conn().get_interrupt_handle();
        let d = deadline.clone();
        let _ = std::thread::Builder::new()
            .name("reader-watchdog".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(250));
                let dl = d.load(Ordering::SeqCst);
                if dl != 0 && (t0.elapsed().as_millis() as u64) > dl {
                    h.interrupt();
                    d.store(0, Ordering::SeqCst);
                }
            });
    }
    for job in rx {
        dec(&pending);
        gate.record("작업자: (대기열)", job.enqueued.elapsed());
        if job.enqueued.elapsed() > STALE_AFTER {
            gate.record("작업자: (낡은 조회 건너뜀)", job.enqueued.elapsed());
            let _ = job.reply.send(Response::err(
                Some(job.id),
                RpcError::with(ErrorCode::Busy, "읽기 대기열에서 너무 오래 기다림"),
            ));
            continue;
        }
        deadline.store(
            t0.elapsed().as_millis() as u64 + QUERY_LIMIT.as_millis() as u64,
            Ordering::SeqCst,
        );
        let g = gen.load(Ordering::SeqCst);
        if g != rs.gen {
            rs.today_cache = None;
            rs.gen = g;
        }
        let tw = std::time::Instant::now();
        let r = match job.method {
            Method::StoryToday => story_today(&store, &mut rs, job.now, job.params, &job.caller),
            Method::ConnectionsList => {
                connections_list(&store, &mut rs, job.now, job.params, &job.caller)
            }
            Method::StoryEvents => {
                let mut tl = Vec::new();
                let snap = gate.snapshot();
                let cache = gate.narr_cache();
                let r = crate::events::story_events(
                    &store,
                    snap.as_deref(),
                    &cache,
                    job.now,
                    job.params,
                    &job.caller,
                    &mut tl,
                );
                for (stage, d) in tl {
                    gate.record(crate::events::reader_stage_name(stage), d);
                }
                r.map(|(v, pending)| {
                    if pending > 0 {
                        gate.0.warm_wanted.store(true, Ordering::SeqCst);
                    }
                    v
                })
            }
            _ => Err(RpcError::with(
                ErrorCode::Internal,
                "읽기 작업자가 맡지 않는 메서드",
            )),
        };
        deadline.store(0, Ordering::SeqCst);
        gate.record(
            match job.method {
                Method::StoryToday => "작업자: story.today",
                Method::ConnectionsList => "작업자: connections.list",
                Method::StoryEvents => "작업자: story.events",
                _ => "작업자: 기타",
            },
            tw.elapsed(),
        );
        // 끊긴 질의(interrupted)는 일시 상태로 — 화면은 busy 처럼 다시 부른다
        let r = r.map_err(|e| {
            if e.message.contains("interrupt") {
                RpcError::with(ErrorCode::Busy, "읽기 질의가 너무 오래 걸려 끊음")
            } else {
                e
            }
        });
        let resp = match r {
            Ok(v) => Response::ok(job.id, v),
            Err(e) => Response::err(Some(job.id), e),
        };
        let _ = job.reply.send(resp);
    }
}

/// story.today
pub fn story_today(
    g: &Store,
    rs: &mut ReadState,
    now: i64,
    p: serde_json::Value,
    caller: &Caller,
) -> Result<serde_json::Value, RpcError> {
    use api::methods::StoryTodayParams;

    let v: StoryTodayParams = serde_json::from_value(p)
        .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
    let scope = caller.scope();
    // L030(노트북): 전에는 DB 전체(7일)를 매번 문장으로 만들었다(24h 만으로 237초·문장 3만 8천).
    // 범위(기본 24시간) + 가장 늦은 선 TODAY_MAX_EDGES 개 + 30초 캐시
    let now_ft = crate::runtime::unix_to_filetime(now);
    let since = v
        .since_ts
        .unwrap_or(now_ft - 86_400 * 10_000_000)
        .max(now_ft - 8 * 86_400 * 10_000_000);
    // 캐시 열쇠의 since 는 분 단위로 — 화면이 "지금-24h"를 매번 조금씩 다르게 보내도 같은 계산으로
    let since_key = since / (60 * 10_000_000);
    let (all, truncated) = match &rs.today_cache {
        Some((t, k, voice, s, tr))
            if *k == since_key && *voice == v.voice && now - *t < CACHE_SECS =>
        {
            (s.clone(), *tr)
        }
        _ => {
            let (s, tr) =
                story::tell_recent(g, since, i64::MAX, voice_of(&v.voice), TODAY_MAX_EDGES)
                    .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?;
            let s = std::sync::Arc::new(s);
            rs.today_cache = Some((now, since_key, v.voice.clone(), s.clone(), tr));
            (s, tr)
        }
    };
    // A30 범위: 같은 노드를 몇 번이고 다시 묻지 않게 기억
    let mut vis: std::collections::HashMap<i64, bool> = std::collections::HashMap::new();
    let mut node_ok = |id: i64| {
        *vis.entry(id)
            .or_insert_with(|| scope.process_visible(g, id))
    };
    let mut sentences: Vec<&story::render::Sentence> = Vec::with_capacity(all.len());
    for st in all.iter() {
        if scope == Scope::All {
            sentences.push(st);
            continue;
        }
        let edges_ok = st.edge_ids.iter().all(|e| match g.edge(*e) {
            Ok(ed) => node_ok(ed.src) && node_ok(ed.dst),
            // 52차 Q2: 근거 선을 못 찾으면 숨긴다
            Err(_) => false,
        });
        if node_ok(st.actor_id) && edges_ok {
            sentences.push(st);
        }
    }
    let gaps = graph::views::gaps_between(g, since, i64::MAX).unwrap_or_default();
    Ok(
        serde_json::json!({ "sentences": sentences, "gaps": gaps, "truncated": truncated, "since_ts": since }),
    )
}

/// connections.list
pub fn connections_list(
    g: &Store,
    rs: &mut ReadState,
    now: i64,
    p: serde_json::Value,
    caller: &Caller,
) -> Result<serde_json::Value, RpcError> {
    // 시각: 그래프 사실은 FILETIME(100ns) — 응답 필드 이름에 _ft 를 붙인다 (정책·엔진은 unix 초)
    let since_secs = p
        .get("since_secs")
        .and_then(|v| v.as_i64())
        .unwrap_or(300)
        .clamp(1, 7 * 86_400);
    let cur: api::page::Cursor = p
        .get("cursor")
        .cloned()
        .map(serde_json::from_value::<api::page::Cursor>)
        .transpose()
        .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?
        .unwrap_or_default()
        .normalized();
    let now_ft = crate::runtime::unix_to_filetime(now);
    let scope = caller.scope();
    let rows: Vec<_> = graph::views::connections(g, now_ft - since_secs * 10_000_000, cur.limit)
        .map_err(internal)?
        .into_iter()
        .filter(|r| scope.process_visible(g, r.process_id))
        .collect();
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| serde_json::json!({
            "process_id": r.process_id, "pid": r.pid, "image": r.image, "remote_id": r.remote_id,
            "raddr": r.raddr, "rport": r.rport, "proto": r.proto, "domain": r.domain, "direction": r.direction,
            "count": r.count, "first_ft": r.first_ts, "last_ft": r.last_ts, "sent": r.sent, "recv": r.recv, "proxied_for": r.proxied_for,
            // 등록 국가·ASN·주소 종류 (오프라인 DB-IP Lite, 등록 국가이지 서버 위치가 아님)
            "where": geo::global().lookup_str(&r.raddr),
        }))
        .collect();
    // A2 "오늘 처음": 하루 전까지 30일 안에 한 번도 본 적 없는 ASN·등록 국가. 기록이 하루치도 없으면 표시하지 않는다
    let (new_asn, new_cc) = new_today(g, rs, now, &items);
    let items: Vec<serde_json::Value> = items
        .into_iter()
        .map(|mut it| {
            let asn = it["where"]["asn"].as_u64().map(|a| a as u32);
            let cc = it["where"]["cc"].as_str().map(|s| s.to_string());
            it["new_asn"] = serde_json::json!(asn.is_some_and(|a| new_asn.contains(&a)));
            it["new_cc"] = serde_json::json!(cc.is_some_and(|c| new_cc.contains(&c)));
            it
        })
        .collect();
    let g = geo::global();
    Ok(
        serde_json::json!({ "items": items, "since_secs": since_secs, "geo": { "country_db": g.has_country(), "built": g.country_built, "source": "DB-IP Lite (CC BY 4.0) https://db-ip.com" } }),
    )
}

pub(crate) fn new_today(
    g: &Store,
    rs: &mut ReadState,
    now: i64,
    items: &[serde_json::Value],
) -> (
    std::collections::HashSet<u32>,
    std::collections::HashSet<String>,
) {
    use std::collections::HashSet;
    let stale = rs
        .seen_before
        .as_ref()
        .is_none_or(|(t, _, _)| now - *t > 600);
    if stale {
        let now_ft = crate::runtime::unix_to_filetime(now);
        let day = 86_400 * 10_000_000i64;
        let mut asn = HashSet::new();
        let mut cc = HashSet::new();
        if let Ok(mut st) = g.conn().prepare(
            "SELECT attrs_json FROM nodes WHERE kind = 'remote' AND first_ts < ?1 AND last_ts >= ?2 LIMIT 50000",
        ) {
            let rows = st
                .query_map(rusqlite::params![now_ft - day, now_ft - 30 * day], |r| r.get::<_, Option<String>>(0))
                .map(|it| it.filter_map(|x| x.ok().flatten()).collect::<Vec<_>>())
                .unwrap_or_default();
            for a in rows {
                let ip = serde_json::from_str::<serde_json::Value>(&a)
                    .ok()
                    .and_then(|v| v.get("ip").and_then(|x| x.as_str()).map(|s| s.to_string()));
                if let Some(w) = ip.and_then(|ip| geo::global().lookup_str(&ip)) {
                    if let Some(n) = w.asn {
                        asn.insert(n);
                    }
                    if let Some(c) = w.cc {
                        cc.insert(c);
                    }
                }
            }
        }
        rs.seen_before = Some((now, asn, cc));
    }
    let (_, seen_asn, seen_cc) = rs.seen_before.as_ref().unwrap();
    // 기록이 하루치도 없는 새 설치: 모든 것이 "처음"이 되므로 표시하지 않는다
    if seen_asn.is_empty() && seen_cc.is_empty() {
        return (HashSet::new(), HashSet::new());
    }
    let mut na = HashSet::new();
    let mut nc = HashSet::new();
    for it in items {
        if it["where"]["scope"].as_str() != Some("public") {
            continue;
        }
        if let Some(a) = it["where"]["asn"].as_u64().map(|a| a as u32) {
            if !seen_asn.contains(&a) {
                na.insert(a);
            }
        }
        if let Some(c) = it["where"]["cc"].as_str() {
            if !seen_cc.contains(c) {
                nc.insert(c.to_string());
            }
        }
    }
    (na, nc)
}
