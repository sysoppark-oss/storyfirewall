//! 원격 제어 사기 경보 (기획서 14판 20-4) — 서비스 쪽 연결.
//!
//! 원격 도구 프로세스를 수집 배치(ProcessStart·ProcessStop)와 시작 때 그래프 조회로 알고,
//! SAMPLE_EVERY_SECS 마다 그 pid 들의 누적 송수신(conn_bytes)을 재서 `graph::remote::SessionTracker` 에 넣는다.
//! 세션 모양이 시작되면 바로 서비스 사건(알림)을 남긴다 — 조용함 원칙의 예외(실시간성이 이 기능의 가치, 20-4).
//! 판정 점수·차단은 하지 않는다. 끊기는 사용자가 사건에서 그 프로그램을 열어 기존 끊기로 한다.

use std::collections::BTreeMap;

use graph::remote::{self, SessionTracker, Transition};

use crate::runtime::{unix_to_filetime, World};

/// 재는 간격(초). 시작 판단 창(30초) 안에 세 번 이상 재게
pub const SAMPLE_EVERY_SECS: i64 = 10;
/// 그래프에서 원격 도구를 다시 찾는 간격(초)
pub const SEED_EVERY_SECS: i64 = 60;

#[derive(Debug, Default)]
pub struct RemoteWatch {
    pub tracker: SessionTracker,
    /// 살아 있는 원격 도구: pid → (도구 key, 프로세스 노드 id)
    pub alive: BTreeMap<u32, (&'static str, i64)>,
    /// pid → 프로세스 노드 id (끝난 뒤에도 끝 사건이 그 프로그램을 가리키게 남긴다 — 끝 사건을 남기면 지운다)
    pub nodes: BTreeMap<u32, i64>,
    pub last_sample_wall: i64,
    /// 마지막으로 그래프에서 원격 도구를 다시 찾은 시각(엔진 벽시각). 0 = 아직
    pub last_seed_wall: i64,
}

/// 수집 배치에서 원격 도구의 시작·끝을 받는다(배치는 이미 그래프에 들어간 뒤 온다)
pub fn on_batch(world: &mut World, events: &[graph::Event]) {
    for ev in events {
        match &ev.kind {
            graph::EventKind::ProcessStart { pid, image, .. } => {
                if let Some(t) = remote::tool_of(image) {
                    let node = world
                        .graph
                        .latest_process_by_pid(*pid, ev.ts.saturating_add(1))
                        .ok()
                        .flatten()
                        .unwrap_or(0);
                    world.remote.alive.insert(*pid, (t.key, node));
                    world.remote.nodes.insert(*pid, node);
                }
            }
            graph::EventKind::ProcessStop { pid } => {
                world.remote.alive.remove(pid);
            }
            _ => {}
        }
    }
}

/// 때가 됐으면 재고, 세션 시작·끝을 서비스 사건으로 남긴다. 사건을 남겼으면 true(호출 쪽이 flush)
pub fn sample(world: &mut World) -> bool {
    let now = world.engine_wall();
    if now - world.remote.last_sample_wall < SAMPLE_EVERY_SECS {
        return false;
    }
    world.remote.last_sample_wall = now;
    if now - world.remote.last_seed_wall >= SEED_EVERY_SECS {
        // 서비스 시작 전부터 돌던 것(스냅샷은 배치로 오지 않는다): 처음엔 최근 10분, 그 뒤엔 1분마다 최근 통신한 pid 에서
        let back = if world.remote.last_seed_wall == 0 {
            600
        } else {
            SEED_EVERY_SECS + SAMPLE_EVERY_SECS
        };
        world.remote.last_seed_wall = now;
        if let Ok(rows) = remote::running_tools(&world.graph, unix_to_filetime(now - back)) {
            for (pid, node, key) in rows {
                world.remote.alive.entry(pid).or_insert((key, node));
                world.remote.nodes.entry(pid).or_insert(node);
            }
        }
    }
    if world.remote.alive.is_empty() && world.remote.tracker.active().is_empty() {
        world.remote.nodes.clear();
        return false;
    }
    let alive: Vec<(u32, &'static str)> = world
        .remote
        .alive
        .iter()
        .map(|(p, (k, _))| (*p, *k))
        .collect();
    let pids: Vec<u32> = alive.iter().map(|a| a.0).collect();
    let samples = remote::sent_recv_by_pid(&world.graph, &pids).unwrap_or_default();
    let trs = world.remote.tracker.observe(now, &alive, &samples);
    let mut any = false;
    for tr in trs {
        match tr {
            Transition::Started {
                pid,
                tool,
                sent_window,
                ..
            } => {
                let target = target_of(world.remote.nodes.get(&pid).copied(), pid, tool, None);
                let _ = world.engine.record_event_ref(
                    "remote_session_start",
                    3,
                    remote::start_text(remote::display_of(tool), sent_window),
                    Some(target.to_string()),
                );
                any = true;
            }
            Transition::Ended {
                pid,
                tool,
                started_ts,
                ended_ts,
                sent_total,
                process_gone,
            } => {
                let target = target_of(
                    world.remote.nodes.get(&pid).copied(),
                    pid,
                    tool,
                    Some(started_ts),
                );
                if !world.remote.alive.contains_key(&pid) {
                    world.remote.nodes.remove(&pid);
                }
                let _ = world.engine.record_event_ref(
                    "remote_session_end",
                    2,
                    remote::end_text(
                        remote::display_of(tool),
                        started_ts,
                        ended_ts,
                        sent_total,
                        process_gone,
                    ),
                    Some(target.to_string()),
                );
                any = true;
            }
        }
    }
    any
}

/// 사건이 가리키는 대상. 노드를 모르면(0) node_id 를 넣지 않는다 — 화면이 없는 프로그램을 열지 않게
fn target_of(
    node: Option<i64>,
    pid: u32,
    tool: &str,
    started_ts: Option<i64>,
) -> serde_json::Value {
    let mut v = serde_json::json!({ "pid": pid, "tool": tool });
    if let Some(n) = node.filter(|n| *n > 0) {
        v["node_id"] = serde_json::json!(n);
    }
    if let Some(t) = started_ts {
        v["started_ts"] = serde_json::json!(t);
    }
    v
}
