//! 질의: 되감기(rewind)와 주인공 기준 투영(projection)
//!
//! - 되감기: 어떤 노드에서 "원인" 방향(선의 src 쪽)으로 거슬러 올라가 시작점까지 경로를 모은다.
//!   SQLite 재귀 CTE 로 한 번에 가져온다.
//! - 투영: 그래프(DAG)를 주인공 기준 너비 우선으로 펼쳐 나무로 만든다. 이미 나온 노드를
//!   다시 만나면 가지를 늘리지 않고 참조 표시(seen=true)만 남긴다. 마인드맵이 이 결과를 그린다.

use crate::store::row_to_edge;
use crate::{Edge, Node, Result, Store};
use rusqlite::params;
use std::collections::{HashSet, VecDeque};

/// 되감기 결과의 한 단계
#[derive(Debug, Clone, serde::Serialize)]
pub struct RewindStep {
    pub depth: i64,
    pub node: Node,
    /// 이 노드로 들어오게 만든 선 (시작 노드는 None)
    pub via: Option<Edge>,
}

/// `node_id` 에서 원인 방향으로 최대 `max_depth` 단계까지 거슬러 올라간다.
/// 결과는 깊이 오름차순(시작 노드 → 뿌리).
pub fn rewind(store: &Store, node_id: i64, max_depth: i64) -> Result<Vec<RewindStep>> {
    let mut st = store.conn.prepare(
        r#"
        WITH RECURSIVE up(node_id, depth, edge_id, path) AS (
            SELECT ?1, 0, NULL, ',' || ?1 || ','
            UNION ALL
            SELECT e.src, up.depth + 1, e.id, up.path || e.src || ','
            FROM edges e JOIN up ON e.dst = up.node_id
            WHERE up.depth < ?2
              AND instr(up.path, ',' || e.src || ',') = 0          -- 순환 방지
              -- 원인 방향으로 따라갈 관계. 'connected' 는 원격지 → 접속한 프로세스로 올라가기 위해 포함.
              -- 'resolved' 는 제외: 도메인 노드에서 그것을 조회한 모든 프로세스로 퍼져 나가면 사슬이 아니다.
              AND e.rel IN ('spawned','executed_as','wrote','downloaded','injected','connected','connected_via')
        )
        SELECT up.depth, up.node_id, up.edge_id
        FROM up
        ORDER BY up.depth, up.node_id
        "#,
    )?;
    let rows = st.query_map(params![node_id, max_depth], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<i64>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for row in rows {
        let (depth, nid, eid) = row?;
        if !seen.insert(nid) {
            continue; // 여러 경로로 같은 조상에 닿으면 첫 경로만
        }
        let node = store.node(nid)?;
        let via = match eid {
            Some(id) => Some(edge_by_id(store, id)?),
            None => None,
        };
        out.push(RewindStep { depth, node, via });
    }
    Ok(out)
}

/// 투영 결과의 한 가지
#[derive(Debug, Clone, serde::Serialize)]
pub struct Branch {
    pub depth: i64,
    pub node: Node,
    pub via: Option<Edge>,
    /// 주인공에서 볼 때 "어디서 왔나"(원인 쪽) 인지 "무엇을 했나"(결과 쪽) 인지
    pub side: Side,
    /// 이미 다른 가지에 나온 노드면 true (마인드맵은 참조 표시로 그림)
    pub seen: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Origin,
    Action,
}

/// 주인공 `center` 를 기준으로 양쪽으로 `max_depth` 까지 너비 우선 펼침.
pub fn project(store: &Store, center: i64, max_depth: i64) -> Result<Vec<Branch>> {
    Ok(project_capped(store, center, max_depth, usize::MAX)?.0)
}

/// 가지 수 상한이 있는 펼침 (A21: 마인드맵). 반환: (가지, 잘렸는가).
/// 상한이 없으면 허브 노드(explorer·자주 쓰는 도메인)에서 깊이 6 펼침이 수만 가지가 돼 엔진 스레드와 UI 를 붙잡는다.
/// 공격자가 한쪽(예: 실행 전에 파일 수백 개를 만들어 원인 쪽)을 부풀려 다른 쪽(외부 접속)을 밀어내지 못하게
/// **쪽별로 나눠** 준다(원인 40% / 행동 60%, 한쪽이 남기면 다른 쪽이 쓴다). 각 노드에서는 **4장 판정 선을 먼저** 펼친다(17차 Q4).
pub fn project_capped(
    store: &Store,
    center: i64,
    max_depth: i64,
    cap: usize,
) -> Result<(Vec<Branch>, bool)> {
    let cap = cap.max(2);
    let mut truncated = false;
    let mut out = vec![Branch {
        depth: 0,
        node: store.node(center)?,
        via: None,
        side: Side::Action,
        seen: false,
    }];
    let origin_cap = ((cap - 1) as u128 * 2 / 5) as usize;
    let (origin, o_cut) = expand_side(store, center, max_depth, Side::Origin, origin_cap)?;
    let action_cap = cap - 1 - origin.len();
    let (action, a_cut) = expand_side(store, center, max_depth, Side::Action, action_cap)?;
    truncated |= a_cut;
    // 행동 쪽이 다 쓰지 않았으면 원인 쪽을 더 펼친다
    let origin = if o_cut && action.len() < action_cap {
        let more = origin_cap + (action_cap - action.len());
        let (o2, c2) = expand_side(store, center, max_depth, Side::Origin, more)?;
        truncated |= c2;
        o2
    } else {
        truncated |= o_cut;
        origin
    };
    out.extend(origin);
    out.extend(action);
    // 양쪽에 같은 노드가 나오면 두 번째부터 seen
    let mut seen: HashSet<i64> = HashSet::new();
    for b in out.iter_mut() {
        if !seen.insert(b.node.id) {
            b.seen = true;
        }
    }
    Ok((out, truncated))
}

fn expand_side(
    store: &Store,
    center: i64,
    max_depth: i64,
    side: Side,
    cap: usize,
) -> Result<(Vec<Branch>, bool)> {
    let mut out = Vec::new();
    let mut seen: HashSet<i64> = HashSet::new();
    seen.insert(center);
    let mut q: VecDeque<(i64, i64)> = VecDeque::new();
    q.push_back((center, 0));
    while let Some((nid, d)) = q.pop_front() {
        if d >= max_depth {
            continue;
        }
        let mut edges = match side {
            Side::Origin => store.edges_to(nid)?,
            Side::Action => store.edges_from(nid)?,
        };
        // 판정 선 먼저, 그다음 시각 순
        edges.sort_by_key(|e| (e.chapter.is_none(), e.ts));
        for e in edges {
            if out.len() >= cap {
                return Ok((out, true));
            }
            let next = match side {
                Side::Origin => e.src,
                Side::Action => e.dst,
            };
            let already = !seen.insert(next);
            out.push(Branch {
                depth: d + 1,
                node: store.node(next)?,
                via: Some(e),
                side,
                seen: already,
            });
            if !already {
                q.push_back((next, d + 1));
            }
        }
    }
    Ok((out, false))
}

/// 선 하나를 id 로
pub fn edge_by_id(store: &Store, id: i64) -> Result<Edge> {
    Ok(store.conn.query_row(
        "SELECT id, src, dst, rel, ts, evidence_id, chapter, attrs_json FROM edges WHERE id = ?1",
        params![id],
        row_to_edge,
    )?)
}

/// 시각 범위 안의 모든 선 (시간 막대용)
pub fn edges_between(store: &Store, from_ts: i64, to_ts: i64) -> Result<Vec<Edge>> {
    let mut st = store.conn.prepare(
        "SELECT id, src, dst, rel, ts, evidence_id, chapter, attrs_json FROM edges
         WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts, id",
    )?;
    let rows = st.query_map(params![from_ts, to_ts], row_to_edge)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// 시간 막대용: 구간을 `buckets` 개로 나눠 각 칸의 선 수와 의심 선 수를 센다.
/// 마인드맵 아래 시간 막대가 "언제 무엇이 많았나"를 그리는 재료.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Bucket {
    pub from_ts: i64,
    pub to_ts: i64,
    pub edges: i64,
    pub suspicious: i64,
}

pub fn timeline(store: &Store, from_ts: i64, to_ts: i64, buckets: usize) -> Result<Vec<Bucket>> {
    let buckets = buckets.max(1) as i64;
    let span = (to_ts - from_ts).max(1);
    let width = (span + buckets - 1) / buckets;
    let mut st = store.conn.prepare(
        "SELECT (ts - ?1) / ?2 AS b, COUNT(*), SUM(CASE WHEN chapter IS NOT NULL THEN 1 ELSE 0 END)
         FROM edges WHERE ts BETWEEN ?1 AND ?3 GROUP BY b",
    )?;
    let mut out: Vec<Bucket> = (0..buckets)
        .map(|i| Bucket {
            from_ts: from_ts + i * width,
            to_ts: from_ts + (i + 1) * width - 1,
            edges: 0,
            suspicious: 0,
        })
        .collect();
    for row in st.query_map(params![from_ts, width, to_ts], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })? {
        let (b, n, s) = row?;
        if let Some(bk) = out.get_mut(b.clamp(0, buckets - 1) as usize) {
            bk.edges += n;
            bk.suspicious += s;
        }
    }
    Ok(out)
}

/// 주인공의 선들을 시각 순으로 (시간 막대를 움직이면 가지가 순서대로 돋아나는 연출용)
pub fn edges_of_actor_until(store: &Store, actor: i64, until_ts: i64) -> Result<Vec<Edge>> {
    let mut st = store.conn.prepare(
        "SELECT id, src, dst, rel, ts, evidence_id, chapter, attrs_json FROM edges
         WHERE (src = ?1 OR dst = ?1) AND ts <= ?2 ORDER BY ts",
    )?;
    let rows = st.query_map(params![actor, until_ts], row_to_edge)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

// ── L030: 큰 범위 이야기("오늘 한 일")용 묶음 조회 ──────────────────────────────
// 노트북 실측: 선 17만·문장 3만 8천에서 선마다 노드 2번·근거 1번·원시 이벤트 여러 번을 따로 물어 story::tell 24h 가 237초.
// 같은 것을 IN 묶음(500개씩)으로 한 번에 읽는다.

const CHUNK: usize = 500;

/// [from, to] 의 선 중 가장 늦은 `limit` 개(시각 오름차순으로 돌려준다). 잘렸는지도 함께
pub fn edges_recent(
    store: &Store,
    from_ts: i64,
    to_ts: i64,
    limit: usize,
) -> Result<(Vec<Edge>, bool)> {
    let mut st = store.conn.prepare(
        "SELECT id, src, dst, rel, ts, evidence_id, chapter, attrs_json FROM edges
         WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts DESC, id DESC LIMIT ?3",
    )?;
    let lim = limit.saturating_add(1) as i64;
    let mut v: Vec<Edge> = st
        .query_map(params![from_ts, to_ts, lim], row_to_edge)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let truncated = v.len() > limit;
    v.truncate(limit);
    v.reverse();
    Ok((v, truncated))
}

fn in_list(n: usize) -> String {
    let mut s = String::with_capacity(n * 2);
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        s.push('?');
    }
    s
}

/// 노드 여러 개를 한 번에
pub fn nodes_by_ids(store: &Store, ids: &[i64]) -> Result<std::collections::HashMap<i64, Node>> {
    let mut out = std::collections::HashMap::with_capacity(ids.len());
    let uniq: Vec<i64> = ids
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    for ch in uniq.chunks(CHUNK) {
        let sql = format!(
            "SELECT id, kind, key, COALESCE(label, key), COALESCE(first_ts,0), COALESCE(last_ts,0), attrs_json FROM nodes WHERE id IN ({})",
            in_list(ch.len())
        );
        let mut st = store.conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(ch.iter()), |r| {
            Ok(Node {
                id: r.get(0)?,
                kind: r.get(1)?,
                key: r.get(2)?,
                label: r.get(3)?,
                first_ts: r.get(4)?,
                last_ts: r.get(5)?,
                attrs_json: r.get(6)?,
            })
        })?;
        for n in rows {
            let n = n?;
            out.insert(n.id, n);
        }
    }
    Ok(out)
}

/// 선마다 근거 원시 이벤트 id (Store::evidence_of 와 같은 순서·중복 제거: evidence_id 먼저, 나머지는 raw_id 순)
pub fn evidence_for(
    store: &Store,
    edges: &[Edge],
) -> Result<std::collections::HashMap<i64, Vec<i64>>> {
    let mut out: std::collections::HashMap<i64, Vec<i64>> = edges
        .iter()
        .map(|e| (e.id, e.evidence_id.into_iter().collect()))
        .collect();
    let ids: Vec<i64> = edges.iter().map(|e| e.id).collect();
    for ch in ids.chunks(CHUNK) {
        let sql = format!("SELECT edge_id, raw_id FROM edge_evidence WHERE edge_id IN ({}) ORDER BY edge_id, raw_id", in_list(ch.len()));
        let mut st = store.conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(ch.iter()), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })?;
        for r in rows {
            let (e, raw) = r?;
            let v = out.entry(e).or_default();
            if !v.contains(&raw) {
                v.push(raw);
            }
        }
    }
    Ok(out)
}

/// 원시 이벤트 id → (시각, 출처)
pub fn raw_meta(
    store: &Store,
    ids: &[i64],
) -> Result<std::collections::HashMap<i64, (i64, String)>> {
    let mut out = std::collections::HashMap::with_capacity(ids.len());
    let uniq: Vec<i64> = ids
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    for ch in uniq.chunks(CHUNK) {
        let sql = format!(
            "SELECT id, ts, source FROM raw_events WHERE id IN ({})",
            in_list(ch.len())
        );
        let mut st = store.conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(ch.iter()), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for r in rows {
            let (id, ts, src) = r?;
            out.insert(id, (ts, src));
        }
    }
    Ok(out)
}

/// 원격지로 실제 connected 선을 만든 프로세스 중 시각이 가장 가까운 것 — 색인(edges(dst, ts))으로 앞뒤 1건씩만 읽는다
pub fn nearest_connector(store: &Store, remote: i64, near_ts: i64) -> Result<Option<i64>> {
    let before: Option<(i64, i64)> = store
        .conn
        .query_row(
            "SELECT ts, src FROM edges WHERE dst = ?1 AND rel = 'connected' AND ts <= ?2 ORDER BY ts DESC LIMIT 1",
            params![remote, near_ts],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let after: Option<(i64, i64)> = store
        .conn
        .query_row(
            "SELECT ts, src FROM edges WHERE dst = ?1 AND rel = 'connected' AND ts > ?2 ORDER BY ts ASC LIMIT 1",
            params![remote, near_ts],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    Ok(match (before, after) {
        (Some(b), Some(a)) => Some(if (near_ts - b.0) <= (a.0 - near_ts) {
            b.1
        } else {
            a.1
        }),
        (Some(b), None) => Some(b.1),
        (None, Some(a)) => Some(a.1),
        (None, None) => None,
    })
}
