//! judge: 4장 판정 엔진 (8차 검증 반영)
//!
//! 판정 단위는 선 하나가 아니라 **사건(Story)** = 뿌리 + 뿌리에서 닿는 선들.
//! - 뿌리: (가) 외부 유입 파일(MOTW Zone 3·4 / downloaded), (나) 서명 없거나 깨진 실행 파일의 프로세스,
//!   (다) 고립 svchost(귀속 없는 접속 + 알려진 Microsoft 서비스 없음), (라) 문서 처리기가 낳은 LOLBin,
//!   (마) 서명된 프로그램이라도 자리잡기(registered)를 했으면 사건으로 보여 준다(점수는 낮음).
//!   (바) 복구 수단 삭제 명령, (사) 브라우저 금고 경비(17판 23-2 ②: 브라우저가 아닌 프로그램의 금고 파일 열기·미끼 파일 열기·
//!   디버깅 모드 브라우저 실행·디버깅 포트 접속·권한 상승 서비스 실행 — rules::vault_signal).
//! - 장: 도달한 최고 장. `connected_via(low)`·창 폴백은 장을 올리지 않는다.
//! - 점수 = 장 기본점(10/30/55/70) + 가중치, 0~100. 0~39 평범 / 40~69 주의 / 70~ 의심(알림).
//! - 서명 가중치는 PE(실행 파일)에만. 문서·스크립트 뿌리는 "실행 파일 아님" 가중치.
//! - 뿌리 (다)·(라) 에는 Microsoft 서명 감점(−40)을 적용하지 않는다(신호 자체가 부모-자식 쌍이므로).
//! - 기준선: (경로, 서명자) 키, 14일 학습. 서명 없거나 Zone 3·4 로 들어온 실행 파일은 학습 제외
//!   (기준선 오염 방지). 제외된 프로그램의 "처음 보는 곳"은 PC 전체 도메인 집합과 비교한다.
//! - 1차 한계(8차 Q1): DLL 하이재킹·WMI 구독은 장 조건이 아니다. 그 프로세스의 후속 4장 행위로 잡는다.
//! - 주기 판정은 증분(`incremental::Incremental`)으로 돈다. 결과는 전체 판정과 같아야 한다(시험으로 고정).
//!
//! 언어 모델은 쓰지 않는다. 모든 점수 항목은 근거 선 id 를 가진다.

pub mod baseline;
pub mod incremental;
pub mod rules;
pub mod score;

use std::collections::{HashMap, HashSet};

use graph::store::Store;
use graph::{Edge, Node};

pub use baseline::Baseline;
pub use incremental::Incremental;
pub use rules::{norm_dir, set_decoy_dirs, set_self_dirs, under_dirs, Chapter, RootKind};
pub use score::{Level, Reason};
pub mod recur;
pub mod respond;

#[derive(Debug, thiserror::Error)]
pub enum JudgeError {
    #[error("graph: {0}")]
    Graph(#[from] graph::GraphError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}
pub type Result<T> = std::result::Result<T, JudgeError>;

/// 판정 결과 한 건 (사건)
#[derive(Debug, Clone, serde::Serialize)]
pub struct Story {
    pub root: i64,
    pub root_label: String,
    pub root_kind: RootKind,
    /// 도달한 최고 장 (1~4). 뿌리 (나)·(다)·(라) 는 2장부터.
    pub chapter: Chapter,
    pub score: u8,
    pub level: Level,
    pub reasons: Vec<Reason>,
    /// 사건에 속한 선 id (chapter 열을 채운 선)
    pub edges: Vec<i64>,
    /// 1장 없이 시작한 사건: "유입 경로 불명"
    pub ingress_unknown: bool,
}

/// 그래프 한 구간의 노드·선을 메모리에 올린 뷰. 판정은 이 위에서만 한다(OS 의존 없음).
///
/// 불변식(갈래 C — 증분 판정이 이 뷰를 제자리에서 고친다):
/// - `out[n]`·`inc[n]` 의 선 위치 목록은 (선 ts, 선 id) 오름차순이다. 사슬의 선 순서·`image_file`(첫 executed_as)이
///   이 순서에 기댄다. 전체 불러오기도 `ORDER BY ts, id` 로 같은 순서를 만든다.
/// - `edges` 는 위치가 바뀌지 않는다(목록이 위치를 가리킨다). 증분 뷰에서는 지운·바뀐 선의 옛 칸이 남아 있을 수 있다 —
///   살아 있는 선은 `by_id`·`outs`·`ins` 로만 찾는다(`edges` 를 직접 훑지 않는다).
/// - `nodes` 는 살아 있는 선의 끝점만 가진다. 노드의 `first_ts`·`last_ts` 는 증분 뷰에서 낡을 수 있다 — 단 판정이 읽는
///   프로세스의 first_ts 와 끝난(ended) 프로세스의 last_ts 는 변경 기록으로 새로 읽는다(`graph::changes` 참고).
pub struct View {
    pub nodes: HashMap<i64, Node>,
    pub edges: Vec<Edge>,
    pub out: HashMap<i64, Vec<usize>>,
    pub inc: HashMap<i64, Vec<usize>>,
    /// L030: 선 id → edges 위치(점수 매길 때 선을 찾느라 전체를 훑던 이중 반복 제거)
    pub by_id: HashMap<i64, usize>,
    /// D042-3·L048: 근거가 연결 표(1초 폴링)뿐인 접속 선. PID 재사용·짧은 수명 프로세스에서 귀속이 틀릴 수 있어
    /// 4장(외부 접속)을 올리지 않는다(사건에는 남는다)
    pub table_only: HashSet<i64>,
    /// (사) 브라우저 디버깅 포트: 구간 안 디버깅 실행 명령줄에서 본 포트 + 기본 9222
    pub debug_ports: HashSet<u16>,
}

impl View {
    pub fn load(store: &Store, from_ts: i64, to_ts: i64) -> Result<Self> {
        let edges = graph::query::edges_between(store, from_ts, to_ts)?;
        // L030: 노드는 묶음 조회로 한 번에(선마다 따로 묻지 않는다)
        let ids: Vec<i64> = edges.iter().flat_map(|e| [e.src, e.dst]).collect();
        let nodes = graph::query::nodes_by_ids(store, &ids)?;
        let mut out: HashMap<i64, Vec<usize>> = HashMap::new();
        let mut inc: HashMap<i64, Vec<usize>> = HashMap::new();
        let mut by_id: HashMap<i64, usize> = HashMap::with_capacity(edges.len());
        for (i, e) in edges.iter().enumerate() {
            for id in [e.src, e.dst] {
                if !nodes.contains_key(&id) {
                    return Err(graph::GraphError::NodeNotFound(format!("node {id}")).into());
                }
            }
            by_id.insert(e.id, i);
            out.entry(e.src).or_default().push(i);
            inc.entry(e.dst).or_default().push(i);
        }
        let table_only = table_only_connects(store, from_ts, to_ts)?;
        let debug_ports = rules::debug_ports_of(&edges, &nodes);
        Ok(Self {
            nodes,
            edges,
            out,
            inc,
            by_id,
            table_only,
            debug_ports,
        })
    }
    /// 선 id 로 찾기(없으면 None)
    pub fn edge(&self, id: i64) -> Option<&Edge> {
        self.by_id.get(&id).map(|i| &self.edges[*i])
    }
    pub fn node(&self, id: i64) -> &Node {
        &self.nodes[&id]
    }
    pub fn outs(&self, id: i64) -> impl Iterator<Item = &Edge> {
        self.out
            .get(&id)
            .into_iter()
            .flatten()
            .map(move |i| &self.edges[*i])
    }
    pub fn ins(&self, id: i64) -> impl Iterator<Item = &Edge> {
        self.inc
            .get(&id)
            .into_iter()
            .flatten()
            .map(move |i| &self.edges[*i])
    }
    /// 프로세스 노드 → 실행 파일 노드 (executed_as 의 src)
    /// 프로세스가 아닌 노드(원격지·파일)는 바로 None — executed_as 는 프로세스로만 들어온다.
    /// L064: 전에는 원격지·파일 노드의 들어온 선을 모두 훑었다. 사슬의 선마다 도착 노드에 이것을 불러(vault_signal_deps)
    /// 수천 번 접속한 원격지 하나가 (사슬 선 수 × 그 원격지로 들어온 선 수)가 되어 노트북 주기 판정이 3초 → 12초가 됐다(diag-4)
    pub fn image_file(&self, proc_id: i64) -> Option<&Node> {
        if self.nodes.get(&proc_id).is_none_or(|n| n.kind != "process") {
            return None;
        }
        self.ins(proc_id)
            .find(|e| e.rel == "executed_as")
            .map(|e| self.node(e.src))
    }

    /// 프로세스에서 시작한 사건의 정상 처리 단위(부모 → 도구(뿌리) → 띄운 프로그램 · (바)는 명령 종류까지).
    /// 뿌리가 프로세스가 아니거나 실행 파일을 모르면 None. 판정(score)과 정상 처리(svc)가 같은 뷰로 같은 키를 만든다
    pub fn chain_unit(&self, root: i64) -> Option<baseline::ChainUnit<'_>> {
        let tool = self.image_file(root)?;
        let parent = self
            .ins(root)
            .find(|e| e.rel == "spawned")
            .and_then(|e| self.image_file(e.src));
        let children: Vec<&Node> = self
            .outs(root)
            .filter(|e| e.rel == "spawned")
            .filter_map(|e| self.image_file(e.dst))
            .collect();
        let commands: Vec<&'static str> = self
            .outs(root)
            .filter_map(|e| rules::ran_kind(e, self.node(e.dst)))
            .collect();
        Some(baseline::ChainUnit {
            parent,
            tool,
            children,
            commands,
        })
    }

    /// 증분: 선 하나를 뺀다(목록·id 색인·table_only 에서). `edges` 의 칸은 남는다. 뺀 선을 돌려준다
    pub(crate) fn remove_edge(&mut self, id: i64) -> Option<Edge> {
        let idx = self.by_id.remove(&id)?;
        let e = self.edges[idx].clone();
        for (map, key) in [(&mut self.out, e.src), (&mut self.inc, e.dst)] {
            if let Some(list) = map.get_mut(&key) {
                if let Some(p) = list.iter().position(|i| *i == idx) {
                    list.remove(p);
                }
                if list.is_empty() {
                    map.remove(&key);
                }
            }
        }
        self.table_only.remove(&id);
        Some(e)
    }

    /// 증분: 선 하나를 더한다. 두 끝점 노드가 `nodes` 에 이미 있어야 한다. 목록의 (ts, id) 순서를 지킨다
    pub(crate) fn add_edge(&mut self, e: Edge) {
        let idx = self.edges.len();
        let key = (e.ts, e.id);
        let (src, dst, id) = (e.src, e.dst, e.id);
        self.edges.push(e);
        self.by_id.insert(id, idx);
        let edges = &self.edges;
        for (map, node) in [(&mut self.out, src), (&mut self.inc, dst)] {
            let list = map.entry(node).or_default();
            // 새 선은 대개 가장 늦다 — 끝에 붙이는 경우를 먼저
            let pos = if list
                .last()
                .map_or(true, |i| (edges[*i].ts, edges[*i].id) < key)
            {
                list.len()
            } else {
                list.partition_point(|i| (edges[*i].ts, edges[*i].id) < key)
            };
            list.insert(pos, idx);
        }
    }

    /// 노드에 살아 있는 선이 하나도 없는가
    pub(crate) fn is_isolated(&self, id: i64) -> bool {
        !self.out.contains_key(&id) && !self.inc.contains_key(&id)
    }
}

/// 구간의 접속 선 중 근거 원시 이벤트가 모두 연결 표(source = 'conntable')인 것
fn table_only_connects(store: &Store, from_ts: i64, to_ts: i64) -> Result<HashSet<i64>> {
    let mut st = store.conn().prepare(
        "SELECT e.id FROM edges e JOIN raw_events r ON r.id = e.evidence_id
         WHERE e.rel = 'connected' AND e.ts >= ?1 AND e.ts <= ?2 AND r.source = 'conntable'
           AND NOT EXISTS (SELECT 1 FROM edge_evidence x JOIN raw_events r2 ON r2.id = x.raw_id
                           WHERE x.edge_id = e.id AND r2.source <> 'conntable')",
    )?;
    let rows = st.query_map(rusqlite::params![from_ts, to_ts], |r| r.get::<_, i64>(0))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// `table_only_connects` 와 같은 조건을 선 id 목록에만(증분)
pub(crate) fn table_only_among(store: &Store, ids: &[i64]) -> Result<HashSet<i64>> {
    let mut out = HashSet::new();
    for ch in ids.chunks(500) {
        let marks = vec!["?"; ch.len()].join(",");
        let sql = format!(
            "SELECT e.id FROM edges e JOIN raw_events r ON r.id = e.evidence_id
             WHERE e.id IN ({marks}) AND e.rel = 'connected' AND r.source = 'conntable'
               AND NOT EXISTS (SELECT 1 FROM edge_evidence x JOIN raw_events r2 ON r2.id = x.raw_id
                               WHERE x.edge_id = e.id AND r2.source <> 'conntable')"
        );
        let mut st = store.conn().prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(ch.iter()), |r| {
            r.get::<_, i64>(0)
        })?;
        for r in rows {
            out.insert(r?);
        }
    }
    Ok(out)
}

/// 구간 [from_ts, to_ts] 의 사건을 판정하고 edges.chapter 를 갱신한다(주기 판정 전용 — 쓰기가 있다).
pub fn run(store: &Store, from_ts: i64, to_ts: i64, baseline: &Baseline) -> Result<Vec<Story>> {
    judge(store, from_ts, to_ts, baseline, true).map(|(s, _)| s)
}

/// L055: 주기 판정의 구간별 시간(서비스가 진단 화면 처리 시간 표에 남긴다)
#[derive(Debug, Clone, Default)]
pub struct Profile {
    /// 전체: 보관 기간 전체 불러오기 / 증분: 변경분을 읽어 메모리 뷰에 반영
    pub load: std::time::Duration,
    pub roots: std::time::Duration,
    pub chain: std::time::Duration,
    pub score: std::time::Duration,
    pub write: std::time::Duration,
    pub n_roots: usize,
    /// 갈래 C: "full" 전체 판정 / "incremental" 증분 / "assess" 쓰지 않는 전체 판정
    pub mode: &'static str,
    /// 증분: 반영한 선 수(새 선 + 바뀐·지운 선)
    pub delta_edges: usize,
    /// 증분: 바뀐 노드 수(바뀐 선의 끝점 포함)
    pub dirty_nodes: usize,
    /// 새로 모은 사슬 수(전체 판정은 사건 후보 중 앞 사건에 묶이지 않은 것 수)
    pub chains_built: usize,
    pub stories: usize,
    /// 실제로 보낸 장 기록 수
    pub updates: usize,
}

impl Profile {
    /// SF_JUDGE_PROFILE=1 일 때 표준 오류로 — 노트북 5.3초가 어디서 나는지 가르기(L055)
    pub fn print(&self) {
        if std::env::var_os("SF_JUDGE_PROFILE").is_none() {
            return;
        }
        eprintln!(
            "JUDGE_PROFILE mode={} load_ms={} roots_ms={} roots={} stories={} chain_ms={} chains_built={} score_ms={} write_ms={} updates={} delta_edges={} dirty_nodes={}",
            self.mode,
            self.load.as_millis(),
            self.roots.as_millis(),
            self.n_roots,
            self.stories,
            self.chain.as_millis(),
            self.chains_built,
            self.score.as_millis(),
            self.write.as_millis(),
            self.updates,
            self.delta_edges,
            self.dirty_nodes,
        );
    }
}

/// run 과 같고, 구간별 시간을 함께 돌려준다
pub fn run_profiled(
    store: &Store,
    from_ts: i64,
    to_ts: i64,
    baseline: &Baseline,
) -> Result<(Vec<Story>, Profile)> {
    judge(store, from_ts, to_ts, baseline, true)
}

/// run 과 같은 판정이지만 DB 에 쓰지 않는다(조회 경로용 — 보기 모드 사용자의 조회가 쓰기를 일으키지 않게)
pub fn assess(store: &Store, from_ts: i64, to_ts: i64, baseline: &Baseline) -> Result<Vec<Story>> {
    judge(store, from_ts, to_ts, baseline, false).map(|(s, _)| s)
}

fn judge(
    store: &Store,
    from_ts: i64,
    to_ts: i64,
    baseline: &Baseline,
    write: bool,
) -> Result<(Vec<Story>, Profile)> {
    let t0 = std::time::Instant::now();
    let view = View::load(store, from_ts, to_ts)?;
    let load = t0.elapsed();
    let t1 = std::time::Instant::now();
    let roots = rules::find_roots(&view);
    let mut prof = Profile {
        load,
        roots: t1.elapsed(),
        n_roots: roots.len(),
        mode: if write { "full" } else { "assess" },
        ..Default::default()
    };
    let (stories, updates) = assemble(&view, &roots, store, baseline, None, &mut prof)?;
    let t2 = std::time::Instant::now();
    if write {
        write_chapters(store, &updates, None)?;
        prof.updates = updates.len();
    }
    prof.write = t2.elapsed();
    prof.print();
    Ok((stories, prof))
}

/// 뿌리 목록(규칙 순위·id 순)에서 사건을 만든다. 전체 판정과 증분 판정이 같이 쓴다 — 결과가 같아야 하는 부분은 이 한 곳에만 둔다.
/// `cache` 가 있으면 (뿌리, 종류)별 사슬을 거기서 꺼내 쓰고 없으면 모아 넣는다(증분). `None` 이면 매번 모은다(전체).
/// 점수는 캐시하지 않는다: 기준선(학습 14일 경과는 시각에 따라 바뀐다)·PC 도메인·"정상" 피드백을 매번 DB 에서 읽는다.
/// 두 번째 값 = 사건 선의 (선 id, 장). 쓰기는 부르는 쪽이 한다
pub(crate) fn assemble(
    view: &View,
    roots: &[(i64, RootKind)],
    store: &Store,
    baseline: &Baseline,
    mut cache: Option<&mut incremental::ChainCache>,
    prof: &mut Profile,
) -> Result<(Vec<Story>, Vec<(i64, Option<i64>)>)> {
    let feedback = baseline.feedback_keys(store)?;
    let pc_domains = baseline.pc_domains(store)?;
    let mut stories = Vec::new();
    // 개편안 2판 2-2 낮음 반복 승격: 사건별 축 키와 마지막 시각을 모아 두었다가 루프 뒤 한 번에 적용
    let mut recur_keys: Vec<crate::recur::Keys> = Vec::new();
    let mut recur_ts: Vec<i64> = Vec::new();
    // 앞 사건이 가진 노드(프로세스·파일). 전에는 선 id 를 넣고 뿌리 노드 id 로 찾았다 — 번호열이 달라
    // 뿌리 노드 번호가 우연히 앞 사건의 선 번호와 같으면 그 사건이 통째로 빠졌다(10판 구현 중 발견)
    let mut claimed: HashSet<i64> = HashSet::new();
    // L055: 사건마다 트랜잭션을 열고 커밋하면 사건 수만큼 디스크 커밋이 생긴다 → 모았다가 한 번에
    let mut chapter_updates: Vec<(i64, Option<i64>)> = Vec::new();
    for &(root, kind) in roots {
        if claimed.contains(&root) {
            continue;
        }
        let tc = std::time::Instant::now();
        let built;
        let chain: &rules::Chain = match cache.as_deref_mut() {
            Some(c) => c.get_or_build(view, root, kind, &mut prof.chains_built),
            None => {
                prof.chains_built += 1;
                built = rules::collect_chain(view, root, kind);
                &built
            }
        };
        prof.chain += tc.elapsed();
        if chain.edges.is_empty() {
            continue;
        }
        claimed.extend(chain.procs.iter().copied());
        claimed.extend(chain.files.iter().copied());
        // 뿌리가 여러 후보에 걸리면(예: Zone 3 이면서 서명 없음) 첫 번째 규칙이 이긴다.
        let ts = std::time::Instant::now();
        let scored = score::score(view, chain, kind, baseline, store, &pc_domains, &feedback)?;
        prof.score += ts.elapsed();
        // 사건에 속한 선에 장을 기록 (평범은 NULL 로 두지 않고 장을 남긴다: 보관 정책의 "의심" 기준은 level)
        chapter_updates.extend(
            chain
                .edges
                .iter()
                .map(|(eid, ch)| (*eid, ch.map(|c| c as i64))),
        );
        recur_keys.push(crate::recur::keys_of(view, root, &chain.procs, kind));
        recur_ts.push(
            chain
                .edges
                .iter()
                .filter_map(|(id, _)| view.by_id.get(id).map(|&i| view.edges[i].ts))
                .max()
                .unwrap_or(0),
        );
        stories.push(Story {
            root,
            root_label: view.node(root).label.clone(),
            root_kind: kind,
            chapter: chain.chapter,
            score: scored.score,
            level: scored.level,
            reasons: scored.reasons,
            edges: chain.edges.iter().map(|(id, _)| *id).collect(),
            ingress_unknown: chain.ingress_unknown,
        });
    }
    let now_ft = recur_ts.iter().copied().max().unwrap_or(0);
    crate::recur::apply(&mut stories, &recur_keys, &recur_ts, now_ft);
    stories.sort_by(|a, b| b.score.cmp(&a.score).then(a.root.cmp(&b.root)));
    prof.stories = stories.len();
    Ok((stories, chapter_updates))
}

/// 지금 판정의 장으로 덮어쓴다(없으면 NULL). 값이 같으면 쓰지 않는다(L050). 트랜잭션 한 번(L055).
/// `prune_upto`: 소비한 변경 기록(graph_changes)을 같은 트랜잭션에서 지운다(증분 판정)
pub(crate) fn write_chapters(
    store: &Store,
    updates: &[(i64, Option<i64>)],
    prune_upto: Option<i64>,
) -> Result<()> {
    if updates.is_empty() && prune_upto.is_none() {
        return Ok(());
    }
    let tx = store.begin_write()?;
    {
        let mut st =
            tx.prepare_cached("UPDATE edges SET chapter = ?1 WHERE id = ?2 AND chapter IS NOT ?1")?;
        for (eid, ch) in updates {
            st.execute(rusqlite::params![ch, eid])?;
        }
    }
    if let Some(upto) = prune_upto {
        graph::changes::prune(&tx, upto)?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod hub_tests {
    //! L064: 많이 접속한 원격지(들어온 선이 많은 노드)가 사슬 모으기를 제곱으로 만들지 않는다
    use super::*;

    fn node(id: i64, kind: &str, key: &str, attrs: &str) -> Node {
        Node {
            id,
            kind: kind.into(),
            key: key.into(),
            label: key.into(),
            first_ts: 0,
            last_ts: 0,
            attrs_json: Some(attrs.into()),
        }
    }

    #[test]
    fn hub_remote_does_not_make_chain_quadratic() {
        // 뿌리 프로세스 1 이 원격지 하나(id 3)에 N 번 접속, 다른 프로세스들도 같은 원격지에 M 번 접속
        const N: i64 = 20_000;
        const M: i64 = 40_000;
        let mut nodes = HashMap::new();
        nodes.insert(
            1,
            node(
                1,
                "process",
                "p1",
                r#"{"image":"C:\\Users\\u\\Downloads\\x.exe","pid":10}"#,
            ),
        );
        nodes.insert(
            2,
            node(2, "process", "p2", r#"{"image":"C:\\x\\y.exe","pid":11}"#),
        );
        nodes.insert(
            3,
            node(
                3,
                "remote",
                "93.184.216.34:443",
                r#"{"ip":"93.184.216.34","port":443}"#,
            ),
        );
        let mut v = View {
            nodes,
            edges: Vec::new(),
            out: HashMap::new(),
            inc: HashMap::new(),
            by_id: HashMap::new(),
            table_only: HashSet::new(),
            debug_ports: HashSet::from([9222]),
        };
        let mut id = 0;
        for (src, n) in [(2, M), (1, N)] {
            for _ in 0..n {
                id += 1;
                let i = v.edges.len();
                v.edges.push(Edge {
                    id,
                    src,
                    dst: 3,
                    rel: "connected".into(),
                    ts: id,
                    evidence_id: None,
                    chapter: None,
                    attrs_json: None,
                });
                v.by_id.insert(id, i);
                v.out.entry(src).or_default().push(i);
                v.inc.entry(3).or_default().push(i);
            }
        }
        // 원격지·파일 노드에는 실행 파일이 없다(전에는 들어온 선 M+N 개를 다 훑고 None)
        assert!(v.image_file(3).is_none());
        let t = std::time::Instant::now();
        let c = rules::collect_chain(&v, 1, RootKind::UnsignedProcess);
        let el = t.elapsed();
        assert_eq!(c.edges.len() as i64, N);
        assert_eq!(c.procs, vec![1]);
        // 고치기 전: N × (M+N) = 12억 번 비교(디버그 빌드 수십 초). 고친 뒤: 선형
        assert!(el < std::time::Duration::from_secs(5), "사슬 모으기 {el:?}");
    }
}
