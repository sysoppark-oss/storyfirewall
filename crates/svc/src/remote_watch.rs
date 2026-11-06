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
    /// 32차 Q1: 지난번 본 활성 RDP 세션 → (시작 엔진 벽시각, 접속한 쪽 이름)
    pub rdp: BTreeMap<u32, (i64, String)>,
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
    // 32차 Gemini Q1: 원격 데스크톱(RDP)은 프로세스 이름·송신량이 아니라 세션 종류로 본다(WTS, 드라이버 없음)
    let any_rdp = rdp_sample(world, now);
    if world.remote.alive.is_empty() && world.remote.tracker.active().is_empty() {
        if any_rdp {
            return true;
        }
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
                let mut target = target_of(world.remote.nodes.get(&pid).copied(), pid, tool, None);
                // 32차 Gemini Q2 → 33차 Q4: 사용자가 "내가 쓰는 원격 도구"로 표시한 도구만 작게(2), 나머지는 크게(3). 끄지는 않는다
                let first = !trusted(world, tool);
                target["first_time"] = serde_json::json!(first);
                target["trusted"] = serde_json::json!(!first);
                let mut text = remote::start_text(remote::display_of(tool), sent_window);
                if !first {
                    text.push_str(" (내가 쓰는 원격 도구로 표시한 프로그램입니다)");
                }
                let _ = world.engine.record_event_ref(
                    "remote_session_start",
                    if first { 3 } else { 2 },
                    text,
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
                let mut target = target_of(
                    world.remote.nodes.get(&pid).copied(),
                    pid,
                    tool,
                    Some(started_ts),
                );
                // 2단계: 세션 동안 이 PC 에서 일어난 일(사실만)
                let facts = remote::session_facts(
                    &world.graph,
                    unix_to_filetime(started_ts),
                    unix_to_filetime(ended_ts),
                )
                .unwrap_or_default();
                target["facts"] = serde_json::to_value(&facts).unwrap_or_default();
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
                    ) + &remote::facts_text(&facts),
                    Some(target.to_string()),
                );
                any = true;
            }
        }
    }
    any || any_rdp
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

/// 사용자가 "내가 쓰는 원격 도구"로 표시했나(설정 remote_trusted_tools, 관리자 승인으로만 바뀐다).
/// 33차 Gemini Q4: "최근 30일 기록이 있으면 낮춤"은 사기범이 짧게 한 번 접속해 기록을 만들면 뚫린다 — 사람의 확인만 쓴다
fn trusted(world: &World, tool: &str) -> bool {
    world
        .settings
        .get("remote_trusted_tools")
        .and_then(|v| v.as_array())
        .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(tool)))
}

/// RDP 세션 시작·끝을 서비스 사건으로. 사건을 남겼으면 true
fn rdp_sample(world: &mut World, now: i64) -> bool {
    let cur: BTreeMap<u32, String> = world.host.rdp_sessions().into_iter().collect();
    let mut any = false;
    let (rdp, events) = rdp_diff(&world.remote.rdp, &cur, now);
    world.remote.rdp = rdp;
    let mine = trusted(world, "rdp");
    for (kind, mut sev, mut text, mut target) in events {
        if kind == "remote_session_start" && mine {
            // 33차 Q4 와 같은 규칙: 사용자가 "내가 쓰는 원격 도구"로 표시했으면 작게(끄지는 않음)
            sev = 2;
            target["first_time"] = serde_json::json!(false);
            target["trusted"] = serde_json::json!(true);
            text.push_str(" (내가 쓰는 원격 도구로 표시한 방식입니다)");
        }
        if kind == "remote_session_end" {
            // 14판 20-4 2단계와 같게: 세션 동안 이 PC 에서 일어난 일
            if let Some(start) = target.get("started_ts").and_then(|v| v.as_i64()) {
                let facts = remote::session_facts(
                    &world.graph,
                    unix_to_filetime(start),
                    unix_to_filetime(now),
                )
                .unwrap_or_default();
                text.push_str(&remote::facts_text(&facts));
                target["facts"] = serde_json::to_value(&facts).unwrap_or_default();
            }
        }
        let _ = world
            .engine
            .record_event_ref(kind, sev, text, Some(target.to_string()));
        any = true;
    }
    any
}

/// 지난번과 지금의 RDP 세션을 비교한다(순수 함수 — 시험 대상). 접속한 쪽 이름은 접속한 쪽이 정하는 값이라 사실로만 붙인다
pub fn rdp_diff(
    prev: &BTreeMap<u32, (i64, String)>,
    cur: &BTreeMap<u32, String>,
    now: i64,
) -> (
    BTreeMap<u32, (i64, String)>,
    Vec<(&'static str, u8, String, serde_json::Value)>,
) {
    let mut next = BTreeMap::new();
    let mut ev = Vec::new();
    for (sid, name) in cur {
        match prev.get(sid) {
            Some(v) => {
                next.insert(*sid, v.clone());
            }
            None => {
                next.insert(*sid, (now, name.clone()));
                let who = if name.is_empty() {
                    String::new()
                } else {
                    format!(" (접속한 쪽 컴퓨터 이름: {name})")
                };
                ev.push((
                    "remote_session_start",
                    3u8,
                    format!("원격 데스크톱(RDP)으로 이 PC 에 접속한 세션이 열렸습니다{who}. 직접 연 원격 접속이 아니면 바로 끊으세요."),
                    serde_json::json!({ "tool": "rdp", "session": sid, "first_time": true }),
                ));
            }
        }
    }
    for (sid, (start, _)) in prev {
        if !cur.contains_key(sid) {
            let mins = ((now - start).max(0) + 59) / 60;
            ev.push((
                "remote_session_end",
                2u8,
                format!("원격 데스크톱(RDP) 세션이 끝났습니다. 약 {mins}분 동안 열려 있었습니다."),
                serde_json::json!({ "tool": "rdp", "session": sid, "started_ts": start }),
            ));
        }
    }
    (next, ev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdp_sessions_start_and_end() {
        let none = BTreeMap::new();
        let mut cur = BTreeMap::new();
        cur.insert(2u32, "ATTACKER-PC".to_string());
        let (s1, ev) = rdp_diff(&none, &cur, 100);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].0, "remote_session_start");
        assert!(ev[0].2.contains("ATTACKER-PC"), "{}", ev[0].2);
        // 그대로 이어지면 사건 없음
        let (s2, ev) = rdp_diff(&s1, &cur, 110);
        assert!(ev.is_empty());
        // 끝남: 시작 시각을 넘긴다
        let (s3, ev) = rdp_diff(&s2, &BTreeMap::new(), 400);
        assert!(s3.is_empty());
        assert_eq!(ev[0].0, "remote_session_end");
        assert_eq!(ev[0].3["started_ts"], serde_json::json!(100));
        assert!(ev[0].2.contains("약 5분"), "{}", ev[0].2);
    }
}
