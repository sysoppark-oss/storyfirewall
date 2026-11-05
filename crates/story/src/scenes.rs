//! 장면(Scene): 한 프로세스(주인공)를 중심으로 사실을 묶은 것.
//!
//! 묶는 규칙 (사실을 바꾸지 않는다, 같은 것끼리 모을 뿐)
//! - 주인공 = 사실의 주어가 프로세스이면 그 프로세스. `executed_as` 는 목적어(실행된 프로세스)가 주인공.
//! - 서비스 경유 통신(`connected_via`)은 원인 프로세스의 장면에 들어간다. 서비스 프로세스 자신의
//!   `connected` 사실은 그 서비스의 장면에 남되, 같은 원격지가 이미 누군가에게 귀속됐으면 "대신 나간 통신"으로 표시.
//! - 같은 도메인·같은 원격지로의 반복은 횟수로 접는다 (압축). 첫 시각과 마지막 시각은 남긴다.

use crate::facts::{Fact, Verb};
use crate::Result;
use graph::{Node, Store};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
pub struct Scene {
    pub actor: Node,
    /// 주인공의 부모 프로세스 (spawned 로 알 수 있을 때)
    pub parent: Option<Node>,
    /// 부모 → 주인공 실행 선과 그 근거 (머리 문장 "X → 실행 Y" 의 근거, A30 에서 빠진 것 발견)
    pub parent_edge: Option<(i64, Vec<i64>)>,
    /// 주인공을 실행한 파일
    pub image: Option<Node>,
    pub first_ts: i64,
    pub last_ts: i64,
    /// 접힌 행위 목록 (같은 동사·같은 목적어는 하나로)
    pub actions: Vec<Action>,
    /// 이 프로세스가 시스템 서비스로서 남을 대신해 나간 통신인가 (연출용 표시)
    pub is_proxy_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Action {
    pub verb: Verb,
    pub object: Node,
    pub count: usize,
    pub first_ts: i64,
    pub last_ts: i64,
    /// 이 행위를 이루는 사실들의 근거 id (화면에서 "왜?")
    pub evidence: Vec<i64>,
    pub edge_ids: Vec<i64>,
    /// 서비스 경유로 귀속된 행위면 그 서비스 프로세스
    pub via: Option<Node>,
    /// D028-1: 경유 귀속의 근거 — 짝짓기 방식("capi2" | "window")과 두 이벤트 시각 차(ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_basis: Option<(String, Option<i64>)>,
    pub chapter: Option<i64>,
}

/// 사실 목록을 장면으로 묶는다. 결과는 첫 등장 시각 순.
pub fn group(store: &Store, facts: &[Fact]) -> Result<Vec<Scene>> {
    let mut scenes: BTreeMap<i64, Scene> = BTreeMap::new(); // key: actor node id
    let mut order: Vec<i64> = Vec::new();
    // 원격지 node id → 귀속된 원인 프로세스 (connected_via 로 알게 됨)
    let mut proxied_targets: HashMap<i64, i64> = HashMap::new();
    for f in facts {
        if f.verb == Verb::ConnectedVia {
            proxied_targets.insert(f.object.id, f.subject.id);
        }
    }

    let ensure =
        |scenes: &mut BTreeMap<i64, Scene>, order: &mut Vec<i64>, actor: &Node, ts: i64| {
            if !scenes.contains_key(&actor.id) {
                scenes.insert(
                    actor.id,
                    Scene {
                        actor: actor.clone(),
                        parent: None,
                        parent_edge: None,
                        image: None,
                        first_ts: ts,
                        last_ts: ts,
                        actions: Vec::new(),
                        is_proxy_only: false,
                    },
                );
                order.push(actor.id);
            }
            let s = scenes.get_mut(&actor.id).unwrap();
            s.first_ts = s.first_ts.min(ts);
            s.last_ts = s.last_ts.max(ts);
        };

    for f in facts {
        match f.verb {
            Verb::Spawned => {
                // 자식의 장면에 부모를 기록. 부모의 장면에도 "실행함" 행위를 남긴다.
                ensure(&mut scenes, &mut order, &f.object, f.ts);
                let child = scenes.get_mut(&f.object.id).unwrap();
                child.parent = Some(f.subject.clone());
                child.parent_edge = Some((f.edge_id, f.evidence.clone()));
                ensure(&mut scenes, &mut order, &f.subject, f.ts);
                push_action(scenes.get_mut(&f.subject.id).unwrap(), f, None);
            }
            Verb::ExecutedAs => {
                ensure(&mut scenes, &mut order, &f.object, f.ts);
                scenes.get_mut(&f.object.id).unwrap().image = Some(f.subject.clone());
            }
            Verb::ConnectedVia => {
                // 원인 프로세스의 장면에, 어느 서비스를 거쳤는지와 함께
                ensure(&mut scenes, &mut order, &f.subject, f.ts);
                let via = find_connector(store, f.object.id, f.ts)?;
                push_action(scenes.get_mut(&f.subject.id).unwrap(), f, via);
                let basis = via_basis(store, f.edge_id);
                if let Some(a) = scenes
                    .get_mut(&f.subject.id)
                    .unwrap()
                    .actions
                    .iter_mut()
                    .rev()
                    .find(|a| a.verb == Verb::ConnectedVia && a.object.id == f.object.id)
                {
                    if a.via_basis.is_none() {
                        a.via_basis = basis;
                    }
                }
            }
            Verb::Connected
                if proxied_targets.contains_key(&f.object.id) && f.subject.kind == "process" =>
            {
                // 서비스가 대신 나간 통신: 서비스 장면에는 넣되 표시만
                ensure(&mut scenes, &mut order, &f.subject, f.ts);
                let s = scenes.get_mut(&f.subject.id).unwrap();
                s.is_proxy_only = true;
                push_action(s, f, None);
            }
            _ => {
                if f.subject.kind == "process" {
                    ensure(&mut scenes, &mut order, &f.subject, f.ts);
                    push_action(scenes.get_mut(&f.subject.id).unwrap(), f, None);
                } else if f.object.kind == "process" {
                    // 인바운드 접속, 다운로드 등: 목적어가 프로세스면 그쪽이 주인공
                    ensure(&mut scenes, &mut order, &f.object, f.ts);
                    push_action(scenes.get_mut(&f.object.id).unwrap(), f, None);
                }
            }
        }
    }

    // 서비스 장면 중 "대신 나간 통신"만 있는 것은 is_proxy_only 유지, 자기 통신도 있으면 해제
    for s in scenes.values_mut() {
        if s.is_proxy_only {
            let own = s
                .actions
                .iter()
                .any(|a| a.verb == Verb::Connected && !proxied_targets.contains_key(&a.object.id));
            if own {
                s.is_proxy_only = false;
            }
        }
    }

    let mut out: Vec<Scene> = order
        .into_iter()
        .filter_map(|id| scenes.remove(&id))
        .collect();
    out.sort_by_key(|s| s.first_ts);
    Ok(out)
}

fn push_action(scene: &mut Scene, f: &Fact, via: Option<Node>) {
    if let Some(a) = scene
        .actions
        .iter_mut()
        .find(|a| a.verb == f.verb && a.object.id == f.object.id)
    {
        a.count += 1;
        a.last_ts = a.last_ts.max(f.ts);
        a.first_ts = a.first_ts.min(f.ts);
        a.evidence.extend(&f.evidence);
        a.edge_ids.push(f.edge_id);
        if a.chapter.is_none() {
            a.chapter = f.chapter;
        }
        return;
    }
    scene.actions.push(Action {
        verb: f.verb,
        object: f.object.clone(),
        count: 1,
        first_ts: f.ts,
        last_ts: f.ts,
        evidence: f.evidence.clone(),
        edge_ids: vec![f.edge_id],
        via,
        via_basis: None,
        chapter: f.chapter,
    });
}

/// 원격지 노드로 실제 `connected` 선을 만든 프로세스 (connected_via 의 "거친 서비스").
/// L030: 원격지의 들어오는 선 전부를 읽지 않고 색인으로 가장 가까운 앞뒤 1건만
/// connected_via 선의 attrs(method, lag_ms)
fn via_basis(store: &Store, edge_id: i64) -> Option<(String, Option<i64>)> {
    let e = store.edge(edge_id).ok()?;
    let v: serde_json::Value = serde_json::from_str(e.attrs_json.as_deref()?).ok()?;
    let m = v
        .get("method")
        .and_then(|x| x.as_str())
        .unwrap_or("window")
        .to_string();
    Some((m, v.get("lag_ms").and_then(|x| x.as_i64())))
}

fn find_connector(store: &Store, remote: i64, near_ts: i64) -> Result<Option<Node>> {
    Ok(
        match graph::query::nearest_connector(store, remote, near_ts)? {
            Some(src) => Some(store.node(src)?),
            None => None,
        },
    )
}

/// 장면에서 처음 보는 프로세스 집합 (신규 프로그램 알림용 보조)
pub fn actors(scenes: &[Scene]) -> HashSet<i64> {
    scenes.iter().map(|s| s.actor.id).collect()
}
