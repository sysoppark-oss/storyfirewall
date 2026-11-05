//! L028(노트북: 새 판에서 모든 목록이 빈 화면): 원시 이벤트 표(7일, 수백만 행)를 매 호출 전체 훑는 질의가
//! 엔진 스레드를 붙잡아 다른 조회까지 시간 초과가 났던 것으로 추정. 화면이 2초마다 부르는 질의는 색인을 타야 한다.

fn plan(store: &graph::store::Store, sql: &str) -> String {
    let mut st = store
        .conn()
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap();
    let rows: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(3))
        .unwrap()
        .map(|x| x.unwrap())
        .collect();
    rows.join(" | ")
}

#[test]
fn hot_raw_event_queries_use_indexes() {
    let store = graph::store::Store::open_in_memory().unwrap();
    // 이야기 "이미 열려 있음"(story::mark_already_open)
    let p = plan(
        &store,
        "SELECT DISTINCT ts FROM raw_events WHERE source = 'snapshot'",
    );
    assert!(
        p.contains("ix_raw_snapshot"),
        "부분 색인만 훑어야 한다: {p}"
    );
    // 수집 상태 한 줄(collector.health)의 마지막 사건 시각
    let p = plan(
        &store,
        "SELECT ts FROM raw_events WHERE source <> 'snapshot' ORDER BY ts DESC LIMIT 1",
    );
    assert!(p.contains("ix_raw_ts"), "{p}");
}

/// 27차 perf(Windows 100만 건, 연결 목록 7일 2.2초): 연결 목록의 접기는 덮는 부분 색인 ix_edges_conn 만 읽어야 한다
#[test]
fn connections_list_uses_covering_partial_index() {
    let store = graph::store::Store::open_in_memory().unwrap();
    let p = plan(&store, "SELECT src, dst, COUNT(*), MIN(ts), MAX(ts) FROM edges WHERE rel = 'connected' AND ts >= 0 GROUP BY src, dst");
    assert!(p.contains("ix_edges_conn"), "{p}");
}

/// L047: 같은 PID 의 가장 최근 프로세스(수집 이벤트마다·듣는 포트 줄마다)는 (kind, key) 색인 범위로 찾아야 한다
#[test]
fn latest_process_by_pid_uses_key_index() {
    let store = graph::store::Store::open_in_memory().unwrap();
    let p = plan(&store, "SELECT id FROM nodes WHERE kind = 'process' AND key >= '42@' AND key < '42A' AND first_ts <= 9 ORDER BY first_ts DESC LIMIT 1");
    assert!(p.contains("key>? AND key<?"), "색인 범위를 타야 한다: {p}");
    // 결과: 4200@ 같은 다른 PID 를 잡지 않는다
    store
        .upsert_node(graph::NodeKind::Process, "42@100", "a.exe", 100, None)
        .unwrap();
    store
        .upsert_node(graph::NodeKind::Process, "420@200", "b.exe", 200, None)
        .unwrap();
    store
        .upsert_node(graph::NodeKind::Process, "42@150", "c.exe", 150, None)
        .unwrap();
    let id = store.latest_process_by_pid(42, 1000).unwrap().unwrap();
    assert_eq!(store.node(id).unwrap().label, "c.exe");
}
