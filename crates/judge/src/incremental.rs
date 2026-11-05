//! 증분 주기 판정 (갈래 C)
//!
//! 노트북 install-27 실측: 주기 판정 평균 3.3초·최대 7.8초(1분마다, 엔진 스레드 하나를 막는다).
//! 그중 보관 기간 전체 불러오기가 1.8초, 뿌리 찾기 0.5초. 1분 사이 바뀌는 것은 전체의 아주 작은 부분이다.
//!
//! 방식
//! 1. 메모리 뷰(`View`)를 판정 사이에 들고 있다가 바뀐 것만 반영한다.
//!    - 새 선: `edges.id > 마지막으로 본 최대 id`
//!    - 제자리 변경·삭제: `graph_changes`(트리거 기록, `graph::changes` 참고)
//!    - 둘 다 **한 읽기 트랜잭션**(같은 스냅숏) 안에서 읽는다. 변경 기록 seq 와 새 선이 어긋나지 않게.
//! 2. 바뀐 노드(dirty) = 바뀐 선의 옛·새 끝점 + 속성이 바뀐 노드(attr). 귀속 선이 바뀐 원격지(via)는 따로 안다.
//! 3. 뿌리 분류는 바뀐 노드와 그 이웃(규칙이 기대는 이웃)만 다시 한다(`rules::root_kind_of`).
//! 4. 사슬은 (뿌리, 종류)별로 캐시하고, 사슬이 읽은 노드(`Chain::deps`) 중 하나라도 dirty 면 버린다.
//! 5. 앞 사건이 가진 노드 빼기(claimed)·점수·정렬은 매번 전체에 대해 다시 한다(`assemble` — 전체 판정과 같은 코드).
//!    점수는 기준선·피드백·시각에 기대므로 캐시하지 않는다. 그래서 기준선 학습·"정상" 피드백은 뷰를 버릴 필요가 없다.
//! 6. 장 기록은 지난번에 쓴 값과 다른 선만 보낸다.
//!
//! 전체 다시(안전망)
//! - 처음, 구간(from/to)이 바뀌었을 때, 증분 `full_every` 번마다(기본 30 = 30분)
//! - 부르는 쪽이 `invalidate` 했을 때(서비스: 보관 정리 뒤·기준선 다시 학습·"정상" 피드백 — 점수는 캐시하지 않아 결과에는
//!   필요 없지만 안전망으로)
//! - 판정 설정(시스템 드라이브·설치 폴더·미끼 폴더, `rules::config_gen`)이나 DB 스키마(`PRAGMA schema_version`)가 바뀌었을 때
//! - (사) 디버깅 포트 집합(`View::debug_ports`)이 바뀔 변경이 있을 때(그 집합은 모든 접속 선의 신호 판단에 걸린다)
//! - 변경 기록에 "전체 다시" 표시가 있을 때(보관 정리 등 대량 변경 — `graph::changes::end_bulk`)
//! - 변경분이 `max_delta` 를 넘을 때, 뷰에 반영하다 어긋난 것(끝점 노드 없음 등)을 볼 때, 어떤 단계든 오류가 났을 때
//!
//! 불변식(결과가 전체 판정과 같아야 하는 근거)
//! - 뷰: `View` 의 불변식(선 목록 (ts, id) 순, 살아 있는 선의 끝점만 노드) — 전체 불러오기와 같은 내용
//! - 뿌리: 노드 n 의 분류는 n 의 속성과 n 에 붙은 선, 그리고 아래 이웃에만 기댄다. 그 이웃이 바뀌면 n 을 다시 분류한다.
//!   (다) 원격지 r 이 바뀜 → r 로 connected 한 프로세스 / (라) 부모 p 가 바뀜 → p 가 spawned 한 자식 /
//!   (바) 명령 c 가 바뀜 → c 를 ran 한 프로세스 / (마) 프로세스 p 가 바뀜 → p 로 executed_as 한 파일
//!   (사) 행위자 a 의 신호 선(opened·connected·spawned)의 도착 노드가 바뀜 → 그 선의 출발 노드 /
//!        파일 f(서명 — 브라우저·면제 판단)가 바뀜 → f 로 실행된 프로세스 / 프로세스 x 가 행위자 후보가 되는 까닭이
//!        x 의 자식 쪽에 있음(디버깅 실행 ran·권한 상승 서비스) → 그 자식을 낳은 부모(두 번째 걸음)
//! - 사슬: (사) 신호 판단이 끝점 밖에서 읽는 노드(끝점의 실행 파일, 디버깅 실행의 부모)도 deps 에 넣는다(`rules::vault_signal_deps`)
//! - 사슬: `collect_chain` 이 읽는 것 = deps 노드의 속성과 그 노드에 붙은 선. 선이 붙고 떨어지면 끝점이 dirty.
//! - 순서: 뿌리는 (규칙 순위, 노드 id) 순 — 전체 판정도 같은 순서(`rules::find_roots`)

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use graph::store::Store;
use graph::Edge;

use crate::rules::{self, Chain, RootKind};
use crate::{Baseline, Profile, Result, Story, View};

/// (뿌리, 종류)별 사슬 캐시와 "이 노드가 바뀌면 버릴 사슬" 색인
#[derive(Default)]
pub struct ChainCache {
    chains: HashMap<(i64, RootKind), Chain>,
    dep_index: HashMap<i64, Vec<(i64, RootKind)>>,
}

impl ChainCache {
    pub(crate) fn get_or_build(
        &mut self,
        v: &View,
        root: i64,
        kind: RootKind,
        built: &mut usize,
    ) -> &Chain {
        let key = (root, kind);
        if !self.chains.contains_key(&key) {
            let c = rules::collect_chain(v, root, kind);
            for d in &c.deps {
                let list = self.dep_index.entry(*d).or_default();
                if list.last() != Some(&key) {
                    list.push(key);
                }
            }
            self.chains.insert(key, c);
            *built += 1;
        }
        &self.chains[&key]
    }

    /// 노드가 바뀌었다 → 그 노드를 읽은 사슬을 버린다. 색인의 낡은 항목(이미 버린 사슬)은 그냥 지나친다
    fn invalidate(&mut self, node: i64) {
        if let Some(keys) = self.dep_index.remove(&node) {
            for k in keys {
                self.chains.remove(&k);
            }
        }
    }
}

struct State {
    view: View,
    from_ts: i64,
    to_ts: i64,
    /// 반영한 마지막 변경 기록 seq
    seq: i64,
    /// 뷰에 반영한 가장 큰 선 id (이보다 큰 id 가 새 선)
    max_edge: i64,
    /// 지운 변경 기록의 끝 seq
    pruned: i64,
    /// 노드 → 뿌리 종류 (뿌리인 노드만)
    roots: HashMap<i64, RootKind>,
    cache: ChainCache,
    /// 선 → 지난번에 DB 에 쓴 장. 같은 값은 다시 보내지 않는다(바뀐·지운 선은 지운다)
    written: HashMap<i64, Option<i64>>,
    /// 마지막 전체 다시 뒤 증분 횟수
    incr_runs: u32,
    /// 만들 때의 판정 설정 세대(`rules::config_gen`)와 DB 스키마 버전
    config_gen: u64,
    schema_version: i64,
}

/// 엔진이 들고 있는 증분 판정기
pub struct Incremental {
    state: Option<State>,
    /// 증분 이 횟수마다 전체 다시(안전망). 1분 주기면 30 = 30분
    pub full_every: u32,
    /// 한 번에 반영할 변경 상한(새 선·변경 기록 각각). 넘으면 전체 다시가 더 싸다
    pub max_delta: usize,
    /// false 면 매번 전체 판정(증분을 끄는 스위치 — 결과는 같고 느리다)
    pub enabled: bool,
}

impl Default for Incremental {
    fn default() -> Self {
        Self::new()
    }
}

impl Incremental {
    pub fn new() -> Self {
        Self {
            state: None,
            full_every: 30,
            max_delta: 200_000,
            enabled: true,
        }
    }

    /// 다음 판정이 전체를 다시 읽게 한다
    pub fn invalidate(&mut self) {
        self.state = None;
    }

    /// 들고 있는 뷰가 있는가(시험·진단용)
    pub fn is_warm(&self) -> bool {
        self.state.is_some()
    }

    /// 들고 있는 뷰(시험용: 전체 불러오기와 같은 내용인지 비교한다)
    pub fn view(&self) -> Option<&View> {
        self.state.as_ref().map(|s| &s.view)
    }

    /// 주기 판정(쓰기 있음). 결과는 `crate::run_profiled(store, from_ts, to_ts, baseline)` 과 같다.
    /// 오류가 나면 들고 있던 상태를 버린다(다음 번은 전체 다시)
    pub fn run(
        &mut self,
        store: &Store,
        from_ts: i64,
        to_ts: i64,
        baseline: &Baseline,
    ) -> Result<(Vec<Story>, Profile)> {
        let r = self.run_inner(store, from_ts, to_ts, baseline);
        if r.is_err() {
            self.state = None;
        }
        r
    }

    fn run_inner(
        &mut self,
        store: &Store,
        from_ts: i64,
        to_ts: i64,
        baseline: &Baseline,
    ) -> Result<(Vec<Story>, Profile)> {
        let mut prof = Profile::default();
        let t0 = std::time::Instant::now();
        let schema_version = schema_version(store)?;
        let want_full = match &self.state {
            _ if !self.enabled => true,
            None => true,
            Some(s) => {
                s.from_ts != from_ts
                    || s.to_ts != to_ts
                    || s.incr_runs >= self.full_every
                    || s.config_gen != rules::config_gen()
                    || s.schema_version != schema_version
            }
        };
        let mut delta: Option<Delta> = None;
        if !want_full {
            let st = self.state.as_mut().expect("상태");
            delta = apply_delta(st, store, self.max_delta, &mut prof)?;
        }
        let st = match delta {
            Some(delta) => {
                // 증분: 바뀐 노드 근처만 다시 분류하고, 그 노드를 읽은 사슬을 버린다
                prof.mode = "incremental";
                prof.load = t0.elapsed();
                let t1 = std::time::Instant::now();
                let st = self.state.as_mut().expect("상태");
                st.incr_runs += 1;
                reclassify(st, &delta);
                for n in &delta.dirty {
                    st.cache.invalidate(*n);
                }
                prof.dirty_nodes = delta.dirty.len();
                prof.roots = t1.elapsed();
                st
            }
            None => {
                prof.mode = "full";
                self.state = None;
                let st = build(store, from_ts, to_ts)?;
                prof.load = t0.elapsed();
                let t1 = std::time::Instant::now();
                let st = self.state.insert(st);
                st.roots = st
                    .view
                    .nodes
                    .values()
                    .filter_map(|n| rules::root_kind_of(&st.view, n).map(|k| (n.id, k)))
                    .collect();
                prof.roots = t1.elapsed();
                st
            }
        };
        // 뿌리 순서 = (규칙 순위, 노드 id) — rules::find_roots 와 같다
        let mut roots: Vec<(u8, i64, RootKind)> = st
            .roots
            .iter()
            .map(|(id, k)| (rules::rule_rank(*k), *id, *k))
            .collect();
        roots.sort_unstable_by_key(|(r, id, _)| (*r, *id));
        let roots: Vec<(i64, RootKind)> = roots.into_iter().map(|(_, id, k)| (id, k)).collect();
        prof.n_roots = roots.len();
        let (stories, updates) = crate::assemble(
            &st.view,
            &roots,
            store,
            baseline,
            Some(&mut st.cache),
            &mut prof,
        )?;
        // 지금 뿌리가 아닌 사슬은 버린다(메모리)
        let live: HashSet<(i64, RootKind)> = roots.iter().copied().collect();
        st.cache.chains.retain(|k, _| live.contains(k));
        // 장 기록: 같은 선이 두 사건에 들면 뒤의 것이 이긴다(전체 판정의 UPDATE 순서와 같게) → 선마다 마지막 값 하나로 줄이고,
        // 지난번에 쓴 값과 다른 것만 보낸다
        let t2 = std::time::Instant::now();
        let mut last: HashMap<i64, Option<i64>> = HashMap::with_capacity(updates.len());
        for (e, c) in updates {
            last.insert(e, c);
        }
        let send: Vec<(i64, Option<i64>)> = last
            .into_iter()
            .filter(|(e, c)| st.written.get(e) != Some(c))
            .collect();
        let prune = (st.seq > st.pruned).then_some(st.seq);
        crate::write_chapters(store, &send, prune)?;
        if let Some(p) = prune {
            st.pruned = p;
        }
        prof.updates = send.len();
        st.written.extend(send);
        prof.write = t2.elapsed();
        prof.print();
        Ok((stories, prof))
    }
}

/// 읽기 트랜잭션: 여러 질의를 한 스냅숏으로. 놓으면(drop) 끝낸다
struct ReadTx<'a> {
    conn: &'a rusqlite::Connection,
    done: bool,
}
impl<'a> ReadTx<'a> {
    fn begin(conn: &'a rusqlite::Connection) -> Result<Self> {
        conn.execute_batch("BEGIN DEFERRED")?;
        Ok(Self { conn, done: false })
    }
    fn commit(mut self) -> Result<()> {
        self.done = true;
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }
}
impl Drop for ReadTx<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

/// 전체 다시: 한 스냅숏 안에서 변경 기록 위치·최대 선 id·뷰를 함께 읽는다
fn build(store: &Store, from_ts: i64, to_ts: i64) -> Result<State> {
    let conn = store.conn();
    // 설정 세대는 읽기 전에(읽는 사이 바뀌면 다음 번에 다시 전체)
    let config_gen = rules::config_gen();
    let tx = ReadTx::begin(conn)?;
    let schema_version = schema_version(store)?;
    let seq = graph::changes::last_seq(conn)?;
    let max_edge: i64 =
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM edges", [], |r| r.get(0))?;
    let view = View::load(store, from_ts, to_ts)?;
    tx.commit()?;
    Ok(State {
        view,
        from_ts,
        to_ts,
        seq,
        max_edge,
        pruned: 0,
        roots: HashMap::new(),
        cache: ChainCache::default(),
        written: HashMap::new(),
        incr_runs: 0,
        config_gen,
        schema_version,
    })
}

fn schema_version(store: &Store) -> Result<i64> {
    Ok(store
        .conn()
        .query_row("PRAGMA schema_version", [], |r| r.get(0))?)
}

const EDGE_COLS: &str = "id, src, dst, rel, ts, evidence_id, chapter, attrs_json";

fn row_to_edge(r: &rusqlite::Row) -> rusqlite::Result<Edge> {
    Ok(Edge {
        id: r.get(0)?,
        src: r.get(1)?,
        dst: r.get(2)?,
        rel: r.get(3)?,
        ts: r.get(4)?,
        evidence_id: r.get(5)?,
        chapter: r.get(6)?,
        attrs_json: r.get(7)?,
    })
}

/// 반영한 변경분
struct Delta {
    /// 바뀐 노드: 바뀐 선(새·바뀐·지운)의 옛·새 끝점 + 속성이 바뀐 노드. 사슬 버리기·다시 분류의 출발점
    dirty: HashSet<i64>,
    /// 그중 속성(kind·key·label·attrs, 프로세스 시각)이 바뀐 노드 — 이웃의 분류가 이 노드의 속성에 기대는 규칙만 이웃으로 넓힌다
    attr: HashSet<i64>,
    /// 귀속 선(connected_via)이 붙거나 떨어진 원격지 — (다) 고립 svchost 판단이 바뀐다
    via: HashSet<i64>,
}

/// 변경분을 뷰에 반영한다. None = 전체 다시가 필요(뷰는 건드리지 않았다)
fn apply_delta(
    st: &mut State,
    store: &Store,
    max_delta: usize,
    prof: &mut Profile,
) -> Result<Option<Delta>> {
    let conn = store.conn();
    let tx = ReadTx::begin(conn)?;
    // 1) 변경 기록
    let changes = graph::changes::since(conn, st.seq, max_delta + 1)?;
    if changes.len() > max_delta {
        return Ok(None);
    }
    let mut changed_edges: BTreeSet<i64> = BTreeSet::new();
    let mut changed_nodes: BTreeSet<i64> = BTreeSet::new();
    for (_, tbl, id) in &changes {
        match tbl.as_str() {
            "e" => {
                changed_edges.insert(*id);
            }
            "n" => {
                changed_nodes.insert(*id);
            }
            // '*' (대량 변경) 또는 모르는 표시
            _ => return Ok(None),
        }
    }
    let new_seq = changes.last().map_or(st.seq, |c| c.0);
    // 2) 새 선 (id > max_edge)
    let new_rows: Vec<Edge> = {
        let mut s = conn.prepare_cached(&format!(
            "SELECT {EDGE_COLS} FROM edges WHERE id > ?1 ORDER BY id LIMIT ?2"
        ))?;
        let rows = s.query_map(
            rusqlite::params![st.max_edge, (max_delta + 1) as i64],
            row_to_edge,
        )?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    if new_rows.len() > max_delta {
        return Ok(None);
    }
    // 3) 바뀐·지운 옛 선(id ≤ max_edge)의 지금 모습. 없으면 지워진 것
    let mut rows: BTreeMap<i64, Option<Edge>> =
        changed_edges.iter().map(|id| (*id, None)).collect();
    let old_ids: Vec<i64> = changed_edges
        .iter()
        .copied()
        .filter(|id| *id <= st.max_edge)
        .collect();
    for ch in old_ids.chunks(500) {
        let marks = vec!["?"; ch.len()].join(",");
        let mut s = conn.prepare(&format!(
            "SELECT {EDGE_COLS} FROM edges WHERE id IN ({marks})"
        ))?;
        for e in s.query_map(rusqlite::params_from_iter(ch.iter()), row_to_edge)? {
            let e = e?;
            rows.insert(e.id, Some(e));
        }
    }
    // 다음 번의 "새 선" 기준은 지금 스냅숏의 실제 MAX(id) 다(지금까지 본 가장 큰 id 가 아니다).
    // edges.id 는 AUTOINCREMENT 가 아니라 가장 큰 id 의 선이 지워지면 다음 선이 그 id 를 다시 쓴다(시험에서 발견:
    // 지운 것을 이미 반영한 뒤 같은 id 로 새 선이 들어오면 변경 기록에도 "id > 기준"에도 걸리지 않았다).
    // 실제 MAX 를 기준으로 하면: 이후 새 선의 id 는 그때의 MAX+1 > 지금 MAX 이거나(→ 새 선 질의),
    // 지금 이후 지워진 id 를 다시 쓴 것이다(→ 그 삭제가 다음 변경 기록에 있어 id 로 다시 읽는다)
    let new_max: i64 =
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM edges", [], |r| r.get(0))?;
    for e in new_rows {
        rows.insert(e.id, Some(e));
    }
    let (from_ts, to_ts) = (st.from_ts, st.to_ts);
    let in_window = |e: &Edge| e.ts >= from_ts && e.ts <= to_ts;
    // 4) 노드: 새 끝점 + 뷰에 있는데 속성이 바뀐 노드
    let mut need: Vec<i64> = rows
        .values()
        .flatten()
        .filter(|e| in_window(e))
        .flat_map(|e| [e.src, e.dst])
        .filter(|id| !st.view.nodes.contains_key(id))
        .collect();
    need.extend(
        changed_nodes
            .iter()
            .copied()
            .filter(|id| st.view.nodes.contains_key(id)),
    );
    let loaded = graph::query::nodes_by_ids(store, &need)?;
    // 5) 근거가 연결 표뿐인 접속 선
    let conn_ids: Vec<i64> = rows
        .values()
        .flatten()
        .filter(|e| e.rel == "connected" && in_window(e))
        .map(|e| e.id)
        .collect();
    let table_only = crate::table_only_among(store, &conn_ids)?;
    tx.commit()?;

    // 반영 전 검사(뷰를 고치기 시작한 뒤에는 실패하지 않게): 끝점 노드가 모두 있는가, 지워진 노드가 뷰에 있는가
    for e in rows.values().flatten().filter(|e| in_window(e)) {
        for n in [e.src, e.dst] {
            if !st.view.nodes.contains_key(&n) && !loaded.contains_key(&n) {
                return Ok(None);
            }
        }
    }
    if changed_nodes
        .iter()
        .any(|id| st.view.nodes.contains_key(id) && !loaded.contains_key(id))
    {
        // 노드 삭제는 보관 정리(대량 변경)에서만 일어난다 — 그 밖의 삭제는 전체 다시로
        return Ok(None);
    }
    // (사) 디버깅 포트 집합이 바뀌는가: 바뀌면 모든 접속 선의 신호 판단이 바뀔 수 있어 전체 다시(드물다 — 디버깅 실행 명령줄).
    // 빠지는 쪽: 뷰에서 빠지거나 바뀌는 ran 선, 키가 바뀌는 명령 노드가 기본 아닌 포트를 가졌으면.
    // 느는 쪽: 새로 들어오는 ran 선의 명령이 집합에 없는 포트를 가졌으면
    let port_of = |key: &str| {
        graph::vault::debug_port(key).filter(|p| *p != graph::vault::DEFAULT_DEBUG_PORT)
    };
    for id in rows.keys() {
        if let Some(old) = st.view.edge(*id) {
            if old.rel == "ran" && port_of(&st.view.node(old.dst).key).is_some() {
                return Ok(None);
            }
        }
    }
    for id in &changed_nodes {
        if let (Some(old), Some(new)) = (st.view.nodes.get(id), loaded.get(id)) {
            if old.key != new.key && (port_of(&old.key).is_some() || port_of(&new.key).is_some()) {
                return Ok(None);
            }
        }
    }
    for e in rows
        .values()
        .flatten()
        .filter(|e| in_window(e) && e.rel == "ran")
    {
        let key = loaded
            .get(&e.dst)
            .or_else(|| st.view.nodes.get(&e.dst))
            .map(|n| n.key.as_str())
            .unwrap_or("");
        if port_of(key).is_some_and(|p| !st.view.debug_ports.contains(&p)) {
            return Ok(None);
        }
    }

    // 6) 반영
    let mut dirty: HashSet<i64> = HashSet::new();
    let mut attr: HashSet<i64> = HashSet::new();
    let mut via: HashSet<i64> = HashSet::new();
    for id in rows.keys() {
        st.written.remove(id);
        if let Some(old) = st.view.remove_edge(*id) {
            dirty.insert(old.src);
            dirty.insert(old.dst);
            if old.rel == "connected_via" {
                via.insert(old.dst);
            }
        }
    }
    for id in &changed_nodes {
        if let (Some(slot), Some(n)) = (st.view.nodes.get_mut(id), loaded.get(id)) {
            *slot = n.clone();
            dirty.insert(*id);
            attr.insert(*id);
        }
    }
    // 새 선 + 바뀐 선 + 지운 선
    let delta = rows.len();
    for e in rows.into_values().flatten() {
        if !in_window(&e) {
            continue;
        }
        for n in [e.src, e.dst] {
            if !st.view.nodes.contains_key(&n) {
                st.view.nodes.insert(n, loaded[&n].clone());
            }
            dirty.insert(n);
        }
        if e.rel == "connected_via" {
            via.insert(e.dst);
        }
        if table_only.contains(&e.id) {
            st.view.table_only.insert(e.id);
        }
        st.view.add_edge(e);
    }
    // 살아 있는 선이 없어진 노드는 뷰에서 뺀다(전체 불러오기와 같은 노드 집합)
    for id in &dirty {
        if st.view.is_isolated(*id) {
            st.view.nodes.remove(id);
        }
    }
    prof.delta_edges = delta;
    st.seq = new_seq;
    st.max_edge = new_max;
    Ok(Some(Delta { dirty, attr, via }))
}

/// 바뀐 노드와, 규칙이 기대는 이웃을 다시 분류한다(모듈 머리말의 불변식).
///
/// 이웃 넓히기는 "이웃의 무엇이 바뀌었나"로 나눈다 — 새 선이 붙은 것만으로는 이웃의 분류가 바뀌지 않는 규칙이 많고,
/// 자식·접속이 수만인 프로세스(허브)가 선을 얻을 때마다 그 이웃 전체를 다시 분류하면 증분이 전체만큼 느려진다(perf_scale 에서 발견).
/// - 속성이 바뀐 노드 d: (라) 자식(부모 이미지 이름) / (사) d 로 실행된 프로세스(실행 파일 서명) /
///   (다) d 로 접속한 프로세스(원격지 주소) / (바) d 를 실행한 프로세스(명령) / (사) d 를 연 프로세스(파일 키)
/// - 선이 바뀐 노드 d(속성 포함 모두): (마) d 로 executed_as 한 파일(첫 실행 파일·자리잡기 선) / (사) d 를 낳은 부모(자식 쪽 신호)
/// - 귀속 선이 바뀐 원격지 r: (다) r 로 접속한 프로세스
fn reclassify(st: &mut State, delta: &Delta) {
    let v = &st.view;
    let mut cand: HashSet<i64> = delta.dirty.clone();
    for &d in &delta.attr {
        for e in v.outs(d) {
            if matches!(e.rel.as_str(), "spawned" | "executed_as") {
                cand.insert(e.dst);
            }
        }
        for e in v.ins(d) {
            if matches!(e.rel.as_str(), "connected" | "ran" | "opened") {
                cand.insert(e.src);
            }
        }
    }
    for &d in &delta.dirty {
        for e in v.ins(d) {
            if matches!(e.rel.as_str(), "executed_as" | "spawned") {
                cand.insert(e.src);
            }
        }
    }
    for &r in &delta.via {
        for e in v.ins(r) {
            if e.rel == "connected" {
                cand.insert(e.src);
            }
        }
    }
    // (사) 두 번째 걸음: 후보 x 가 디버깅 실행(ran)을 했거나 권한 상승 서비스이면 행위자는 x 를 낳은 부모다
    let parents: Vec<i64> = cand
        .iter()
        .flat_map(|x| v.ins(*x).filter(|e| e.rel == "spawned").map(|e| e.src))
        .collect();
    cand.extend(parents);
    for c in cand {
        match v.nodes.get(&c).and_then(|n| rules::root_kind_of(v, n)) {
            Some(k) => {
                st.roots.insert(c, k);
            }
            None => {
                st.roots.remove(&c);
            }
        }
    }
}
