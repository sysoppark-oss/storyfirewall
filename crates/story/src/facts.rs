//! 사실(Fact): 그래프의 선 하나를 사람이 읽을 수 있는 주어-동사-목적어로 옮긴 것.
//! 선 하나 = 사실 하나. 여기서 합치거나 해석하지 않는다.

use crate::Result;
use graph::{Node, Store};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    /// src 프로세스가 dst 프로세스를 실행함
    Spawned,
    /// src 파일이 dst 프로세스로 실행됨
    ExecutedAs,
    /// src 프로세스가 dst 파일을 만듦
    Wrote,
    /// src 출처(도메인)에서 dst 파일을 받음
    Downloaded,
    /// src 프로세스가 dst 원격지에 접속함 (또는 dst 원격지가 src 프로세스에 접속해 옴)
    Connected,
    /// src 프로세스가 dst 도메인을 조회함
    Resolved,
    /// src 프로세스가 dst 자동 실행 항목을 등록함
    Registered,
    /// src 프로세스가 dst 프로세스에 코드를 넣음
    Injected,
    /// src 프로세스를 대신해 시스템 서비스가 dst 원격지에 접속함 (해석 선)
    ConnectedVia,
    /// src 프로세스가 dst 명령줄로 실행됨 (10판 5-9, 복구 수단 도구만 수집)
    Ran,
    /// src 프로세스가 dst 파일(브라우저 금고·미끼)을 엶 (17판 23-2 ②). 무엇을 읽었는지는 모른다
    Opened,
}

impl Verb {
    pub fn parse(rel: &str) -> Option<Verb> {
        Some(match rel {
            "spawned" => Verb::Spawned,
            "executed_as" => Verb::ExecutedAs,
            "wrote" => Verb::Wrote,
            "downloaded" => Verb::Downloaded,
            "connected" => Verb::Connected,
            "resolved" => Verb::Resolved,
            "registered" => Verb::Registered,
            "injected" => Verb::Injected,
            "connected_via" => Verb::ConnectedVia,
            "ran" => Verb::Ran,
            "opened" => Verb::Opened,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Fact {
    pub edge_id: i64,
    pub ts: i64,
    pub verb: Verb,
    pub subject: Node,
    pub object: Node,
    /// 근거 원시 이벤트 id 들 (합쳐진 선은 여러 개). 화면에서 "왜?"를 누르면 이 기록을 보여 준다.
    pub evidence: Vec<i64>,
    /// 4장 판정 (없으면 평범)
    pub chapter: Option<i64>,
}

/// 시각 범위 안의 모든 선을 사실로 옮긴다. 시각 순.
pub fn collect(store: &Store, from_ts: i64, to_ts: i64) -> Result<Vec<Fact>> {
    let edges = graph::query::edges_between(store, from_ts, to_ts)?;
    build(store, edges)
}

/// L030: 범위 안의 가장 늦은 `limit` 개 선만(오늘 한 일). 잘렸으면 true
pub fn collect_recent(
    store: &Store,
    from_ts: i64,
    to_ts: i64,
    limit: usize,
) -> Result<(Vec<Fact>, bool)> {
    let (edges, truncated) = graph::query::edges_recent(store, from_ts, to_ts, limit)?;
    Ok((build(store, edges)?, truncated))
}

/// 노드·근거를 묶음 조회로(선마다 따로 묻지 않는다 — L030 노트북 237초의 한 원인)
fn build(store: &Store, edges: Vec<graph::Edge>) -> Result<Vec<Fact>> {
    let edges: Vec<graph::Edge> = edges
        .into_iter()
        .filter(|e| Verb::parse(&e.rel).is_some())
        .collect();
    let ids: Vec<i64> = edges.iter().flat_map(|e| [e.src, e.dst]).collect();
    let nodes = graph::query::nodes_by_ids(store, &ids)?;
    let mut ev = graph::query::evidence_for(store, &edges)?;
    let mut out = Vec::with_capacity(edges.len());
    for e in edges {
        let verb = Verb::parse(&e.rel).expect("걸렀음");
        let (Some(subject), Some(object)) = (nodes.get(&e.src), nodes.get(&e.dst)) else {
            continue;
        };
        out.push(Fact {
            edge_id: e.id,
            ts: e.ts,
            verb,
            subject: subject.clone(),
            object: object.clone(),
            evidence: ev.remove(&e.id).unwrap_or_default(),
            chapter: e.chapter,
        });
    }
    Ok(out)
}
