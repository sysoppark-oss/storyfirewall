//! A2: 보관 정책·하루 압축·시간 막대 검증

use graph::ingest::Ingester;
use graph::query::{edges_of_actor_until, timeline};
use graph::retention::{apply, summaries_between, RetentionPolicy, DAY};
use graph::textlog::{parse_text, POC1B_RUN2};
use graph::{NodeKind, Store};

fn build() -> (Store, i64, i64) {
    let store = Store::open_in_memory().unwrap();
    let events = parse_text(POC1B_RUN2);
    Ingester::new(&store).ingest_all(&events).unwrap();
    (store, events.first().unwrap().ts, events.last().unwrap().ts)
}

#[test]
fn timeline_buckets_cover_all_edges() {
    let (store, t0, t1) = build();
    let total = store.count_edges().unwrap();
    let tl = timeline(&store, t0, t1, 10).unwrap();
    assert_eq!(tl.len(), 10);
    let sum: i64 = tl.iter().map(|b| b.edges).sum();
    assert_eq!(sum, total, "모든 선이 어느 한 칸에 들어가야 함");
    assert!(tl.iter().any(|b| b.edges > 0));
}

#[test]
fn actor_edges_grow_with_time() {
    let (store, _t0, t1) = build();
    let start = 134377664655883666i64; // curl.exe(7368) 생성 시각. 사슬 전체가 0.2초 안에 끝난다
    let curl = store
        .find_node(NodeKind::Process, &format!("7368@{start}"))
        .unwrap()
        .unwrap();
    let early = edges_of_actor_until(&store, curl, start + 500_000)
        .unwrap()
        .len(); // +50ms
    let late = edges_of_actor_until(&store, curl, t1).unwrap().len();
    assert!(
        late > early,
        "시각을 뒤로 옮기면 가지가 늘어야 함: {early} → {late}"
    );
}

#[test]
fn ordinary_edges_compact_into_daily_summary_and_raw_expire() {
    let (store, _t0, t1) = build();
    let before_edges = store.count_edges().unwrap();
    let raw_before: i64 = store
        .conn()
        .query_row("SELECT COUNT(*) FROM raw_events", [], |r| r.get(0))
        .unwrap();
    assert!(raw_before > 0);

    // 4일 뒤(27차: 압축은 3일 뒤부터): 평범한 선은 요약으로, 원시 이벤트는 아직 (7일 미만)
    let rep = apply(&store, t1 + 4 * DAY, RetentionPolicy::default()).unwrap();
    assert!(rep.edges_compacted > 0, "{rep:?}");
    assert!(rep.summaries_written > 0);
    assert_eq!(rep.raw_deleted, 0);
    let after_edges = store.count_edges().unwrap();
    assert!(after_edges < before_edges);
    // executed_as(출신 사슬)는 남는다
    let exec: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE rel='executed_as'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(exec > 0);
    // 27차: 하루 압축은 접속·주소 조회만. 평범한 출신 사슬 선(spawned 등)은 30일까지 남는다
    let left: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE chapter IS NULL AND rel IN ('connected','resolved')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(left, 0);
    let prov = |s: &Store| -> i64 {
        s.conn().query_row("SELECT COUNT(*) FROM edges WHERE chapter IS NULL AND rel NOT IN ('connected','resolved','executed_as')", [], |r| r.get(0)).unwrap()
    };
    let prov_before = prov(&store);
    assert!(
        prov_before > 0,
        "시험 데이터에 평범한 출신 사슬 선이 있어야 한다"
    );
    // 요약의 횟수 합 = 접힌 선 수
    let sum: i64 = summaries_between(&store, 0, i64::MAX)
        .unwrap()
        .iter()
        .map(|s| s.count)
        .sum();
    assert_eq!(sum as usize, rep.edges_compacted);

    // 8일 뒤: 원시 이벤트 삭제, 요약은 유지
    let rep2 = apply(&store, t1 + 8 * DAY, RetentionPolicy::default()).unwrap();
    assert_eq!(rep2.raw_deleted as i64, raw_before);
    let raw_after: i64 = store
        .conn()
        .query_row("SELECT COUNT(*) FROM raw_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(raw_after, 0);
    assert!(summaries_between(&store, 0, i64::MAX).unwrap().len() > 0);

    assert_eq!(
        prov(&store),
        prov_before,
        "8일 뒤에도 출신 사슬 선은 남는다"
    );

    // 31일 뒤: 요약도 삭제, 노드는 출신 사슬(파일→프로세스)만 남음
    let rep3 = apply(&store, t1 + 31 * DAY, RetentionPolicy::default()).unwrap();
    assert_eq!(rep3.provenance_deleted as i64, prov_before);
    assert!(rep3.summaries_deleted > 0);
    assert_eq!(summaries_between(&store, 0, i64::MAX).unwrap().len(), 0);
    assert!(rep3.nodes_deleted > 0);

    // 멱등: 한 번 더 돌려도 변화 없음
    let rep4 = apply(&store, t1 + 31 * DAY, RetentionPolicy::default()).unwrap();
    assert_eq!(
        rep4.edges_compacted
            + rep4.provenance_deleted
            + rep4.summaries_deleted
            + rep4.raw_deleted
            + rep4.nodes_deleted,
        0
    );
}

#[test]
fn suspicious_edges_survive_daily_compaction() {
    let (store, _t0, t1) = build();
    // 선 하나를 의심(3장)으로 표시
    store.conn().execute("UPDATE edges SET chapter = 3 WHERE id = (SELECT MIN(id) FROM edges WHERE rel='connected')", []).unwrap();
    apply(&store, t1 + 2 * DAY, RetentionPolicy::default()).unwrap();
    let kept: i64 = store
        .conn()
        .query_row("SELECT COUNT(*) FROM edges WHERE chapter = 3", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(kept, 1, "의심 선은 하루 압축에서 살아남아야 함");
    apply(&store, t1 + 31 * DAY, RetentionPolicy::default()).unwrap();
    let kept: i64 = store
        .conn()
        .query_row("SELECT COUNT(*) FROM edges WHERE chapter = 3", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(kept, 0, "30일 뒤에는 삭제");
}

#[test]
fn size_cap_evicts_oldest_ordinary_raw_but_keeps_suspicious() {
    let (store, _t0, t1) = build();
    let total: i64 = store
        .conn()
        .query_row(
            "SELECT SUM(LENGTH(payload_json)) FROM raw_events",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // 가장 최근 connected 선을 의심으로 표시 → 그 근거는 용량 순환에서 제외돼야 한다
    store.conn().execute(
        "UPDATE edges SET chapter = 4 WHERE id = (SELECT MAX(id) FROM edges WHERE rel='connected' AND evidence_id IS NOT NULL)", []).unwrap();
    let susp_raw: i64 = store
        .conn()
        .query_row("SELECT evidence_id FROM edges WHERE chapter = 4", [], |r| {
            r.get(0)
        })
        .unwrap();

    let policy = RetentionPolicy {
        raw_max_bytes: total / 2,
        ..RetentionPolicy::default()
    };
    let rep = apply(&store, t1, policy).unwrap(); // 날짜로는 아무것도 안 지워지는 시점
    assert_eq!(rep.raw_deleted, 0);
    assert!(rep.raw_deleted_by_size > 0, "{rep:?}");
    assert!(rep.raw_bytes_after <= total / 2, "{rep:?}");
    let still: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM raw_events WHERE id = ?1",
            [susp_raw],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(still, 1, "의심 사건의 근거는 용량 순환에서 살아남아야 함");
    // 멱등
    let rep2 = apply(&store, t1, policy).unwrap();
    assert_eq!(rep2.raw_deleted_by_size, 0);
}

#[test]
fn suspicious_raw_kept_longer_than_ordinary_raw() {
    let (store, _t0, t1) = build();
    store.conn().execute(
        "UPDATE edges SET chapter = 2 WHERE id = (SELECT MIN(id) FROM edges WHERE rel='connected' AND evidence_id IS NOT NULL)", []).unwrap();
    let susp_raw: i64 = store
        .conn()
        .query_row("SELECT evidence_id FROM edges WHERE chapter = 2", [], |r| {
            r.get(0)
        })
        .unwrap();
    apply(&store, t1 + 8 * DAY, RetentionPolicy::default()).unwrap(); // 평범 원시는 7일 지나 삭제
    let n: i64 = store
        .conn()
        .query_row("SELECT COUNT(*) FROM raw_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "의심 사건 근거 하나만 남아야 함");
    let still: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM raw_events WHERE id = ?1",
            [susp_raw],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(still, 1);
    apply(&store, t1 + 31 * DAY, RetentionPolicy::default()).unwrap(); // 30일 지나면 그것도 삭제
    let n: i64 = store
        .conn()
        .query_row("SELECT COUNT(*) FROM raw_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn policy_round_trips_through_json_and_sanitizes() {
    let json = r#"{"raw_days": 3, "raw_max_bytes": 1048576}"#; // 나머지는 기본값
    let p: RetentionPolicy = serde_json::from_str(json).unwrap();
    assert_eq!(p.raw_days, 3);
    assert_eq!(p.raw_max_bytes, 1048576);
    assert_eq!(p.summary_days, 30);
    let bad = RetentionPolicy {
        raw_days: 0,
        suspicious_raw_days: 1,
        ..p
    };
    let s = bad.sanitized();
    assert_eq!(s.raw_days, 7, "0 은 기본값으로");
    assert!(
        s.suspicious_raw_days >= s.raw_days,
        "의심은 평범보다 짧을 수 없음"
    );
}

/// 28차 Gemini 아이디어 1: 새 파일 DB 는 auto_vacuum=INCREMENTAL(2)
#[test]
fn new_file_db_uses_incremental_auto_vacuum() {
    let dir = std::env::temp_dir().join(format!("sf-av-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let s = graph::store::Store::open(dir.join("g.db")).unwrap();
    let av: i64 = s
        .conn()
        .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .unwrap();
    assert_eq!(av, 2);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 27차 Gemini Q9: 하루씩 나눈 정리는 한 번에 한 정리와 결과가 같다
#[test]
fn chunked_apply_matches_single_apply() {
    use graph::retention::apply_chunked;
    let (a, _t0, t1) = build();
    let (b, _, _) = build();
    let now = t1 + 40 * DAY;
    apply(&a, now, RetentionPolicy::default()).unwrap();
    apply_chunked(&b, now, RetentionPolicy::default()).unwrap();
    let count = |s: &Store, q: &str| -> i64 { s.conn().query_row(q, [], |r| r.get(0)).unwrap() };
    for q in [
        "SELECT COUNT(*) FROM edges",
        "SELECT COUNT(*) FROM raw_events",
        "SELECT COUNT(*) FROM nodes",
        "SELECT COALESCE(SUM(count),0) FROM daily_summary",
    ] {
        assert_eq!(count(&a, q), count(&b, q), "{q}");
    }
    // 중간 시점(3일 뒤)도 같다
    let (c, _, _) = build();
    let (d, _, _) = build();
    apply(&c, t1 + 4 * DAY, RetentionPolicy::default()).unwrap();
    apply_chunked(&d, t1 + 4 * DAY, RetentionPolicy::default()).unwrap();
    for q in [
        "SELECT COUNT(*) FROM edges",
        "SELECT COALESCE(SUM(count),0) FROM daily_summary",
    ] {
        assert_eq!(count(&c, q), count(&d, q), "{q}");
    }
}

/// install-128 실측(용량 계산 434초): 원시 기록 바이트 합은 트리거로 유지되고 실제 합과 같다. 옛 큰 DB(합 행 없음)는 용량 순환을 건너뛴다
#[test]
fn raw_size_tracks_inserts_and_deletes() {
    let store = graph::Store::open_in_memory().unwrap();
    let sum = |s: &graph::Store| -> i64 {
        s.conn()
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(payload_json)),0) FROM raw_events",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(store.raw_bytes().unwrap(), Some(0));
    for i in 0..50 {
        store
            .insert_raw(
                i,
                "t",
                &format!("{{\"n\":\"{}\"}}", "가".repeat(i as usize)),
            )
            .unwrap();
    }
    assert_eq!(store.raw_bytes().unwrap(), Some(sum(&store)));
    store
        .conn()
        .execute("DELETE FROM raw_events WHERE ts < 20", [])
        .unwrap();
    assert_eq!(store.raw_bytes().unwrap(), Some(sum(&store)));
    // 합 행이 없는 옛 DB: 용량 순환을 하지 않는다(-1)
    store.conn().execute("DELETE FROM raw_size", []).unwrap();
    let policy = RetentionPolicy {
        raw_max_bytes: 1,
        ..RetentionPolicy::default()
    };
    let rep = apply(&store, 100, policy).unwrap();
    assert_eq!((rep.raw_deleted_by_size, rep.raw_bytes_after), (0, -1));
}

/// install-130 실측(용량 단계 434초): 용량 순환의 후보 질의는 시각 색인 순으로 읽고 정렬하지 않는다(필요한 만큼만 읽고 멈춤)
#[test]
fn size_victim_query_uses_ts_index_without_sort() {
    let store = graph::Store::open_in_memory().unwrap();
    let mut q = store
        .conn()
        .prepare("EXPLAIN QUERY PLAN SELECT id, LENGTH(payload_json) FROM raw_events INDEXED BY ix_raw_ts ORDER BY ts, id")
        .unwrap();
    let plan: Vec<String> = q
        .query_map([], |r| r.get::<_, String>(3))
        .unwrap()
        .map(|x| x.unwrap())
        .collect();
    let text = plan.join(" | ");
    assert!(
        text.contains("ix_raw_ts") && !text.contains("TEMP B-TREE"),
        "{text}"
    );
}

/// 상한을 조금 넘긴 큰 원시 기록에서 용량 순환이 빨리 끝난다(앞에서 필요한 만큼만)
#[test]
fn size_rotation_on_large_raw_is_fast() {
    let store = graph::Store::open_in_memory().unwrap();
    {
        let tx = store.begin_write().unwrap();
        let mut st = tx
            .prepare("INSERT INTO raw_events(ts, source, payload_json) VALUES (?1, 't', ?2)")
            .unwrap();
        let body = "x".repeat(180);
        for i in 0..300_000i64 {
            st.execute(rusqlite::params![i, body]).unwrap();
        }
        drop(st);
        tx.commit().unwrap();
    }
    let total = store.raw_bytes().unwrap().unwrap();
    let policy = RetentionPolicy {
        raw_max_bytes: total - 180 * 1000,
        ..RetentionPolicy::default()
    };
    let t = std::time::Instant::now();
    let rep = apply(&store, 400_000, policy).unwrap();
    let ms = t.elapsed().as_millis();
    assert_eq!(rep.raw_deleted_by_size, 1000);
    assert!(ms < 3000, "용량 순환 {ms}ms");
}
