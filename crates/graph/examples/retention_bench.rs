//! 개발 도구: 노트북 규모(diag-222·239: 그래프 1 GB, 원시 기록 500 MiB 상한, 시간마다 선 1.6만·원시 2.3만 정리)와 비슷한 DB 를 만들어
//! 보관 정리 한 번(1시간 뒤)의 단계별 시간과 질의 계획을 본다.
//! 사용: cargo run --release -p graph --example retention_bench -- <만들 DB 경로> [배율(기본 1.0)]
use graph::retention::{apply, RetentionPolicy};
use graph::store::Store;

const SEC: i64 = 10_000_000;
const HOUR: i64 = 3600 * SEC;
const DAY: i64 = 24 * HOUR;
const T: i64 = 133_800_000_000_000_000 + 40 * DAY;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let path = a.get(1).expect("DB 경로");
    let k: f64 = a.get(2).and_then(|x| x.parse().ok()).unwrap_or(1.0);
    let _ = std::fs::remove_file(path);
    let store = Store::open(path).unwrap();
    let c = store.conn();
    let n = |x: f64| (x * k) as i64;
    let t = std::time::Instant::now();
    c.execute_batch("BEGIN").unwrap();
    // 노드: 프로세스 2천, 원격지 2만, 파일 5천
    c.execute_batch(
        "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 27000)
         INSERT INTO nodes(id, kind, key, label, first_ts, last_ts, attrs_json)
         SELECT i, CASE WHEN i <= 2000 THEN 'process' WHEN i <= 22000 THEN 'remote' ELSE 'file' END, 'k' || i, 'n' || i, 0, 0, '{}' FROM s;",
    )
    .unwrap();
    // 원시 기록: 최근 74시간(용량 상한이 7일보다 먼저 걸린 상태) + 의심 사건 근거(30일까지)
    let raw_n = n(1_700_000.0);
    c.execute(
        &format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < {raw_n})
             INSERT INTO raw_events(id, ts, source, payload_json)
             SELECT i, {T} - 74 * {HOUR} + (i * (74 * {HOUR} / {raw_n})), 'etw:network', printf('%0300d', i) FROM s"
        ),
        [],
    )
    .unwrap();
    let susp_raw_n = n(220_000.0);
    c.execute(
        &format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < {susp_raw_n})
             INSERT INTO raw_events(id, ts, source, payload_json)
             SELECT 10000000 + i, {T} - 30 * {DAY} + (i * (30 * {DAY} / {susp_raw_n})), 'etw:process', printf('%0300d', i) FROM s"
        ),
        [],
    )
    .unwrap();
    // 평범한 접속·조회 선: 최근 73시간, 시간당 1.6만
    let ord_n = n(16_000.0 * 73.0);
    c.execute(
        &format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < {ord_n})
             INSERT INTO edges(id, src, dst, rel, ts, evidence_id, chapter, attrs_json)
             SELECT i, 1 + i % 2000, 2001 + (i * 7) % 20000, CASE WHEN i % 5 = 0 THEN 'resolved' ELSE 'connected' END,
                    {T} - 73 * {HOUR} + (i * (73 * {HOUR} / {ord_n})), 1 + ((i - 1) * {raw_n} / {ord_n}), NULL, NULL FROM s"
        ),
        [],
    )
    .unwrap();
    // 출신 사슬 선(평범): 30일, 시간당 2천
    let prov_n = n(2_000.0 * 720.0);
    c.execute(
        &format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < {prov_n})
             INSERT INTO edges(id, src, dst, rel, ts, evidence_id, chapter, attrs_json)
             SELECT 20000000 + i, 1 + i % 2000, 22001 + (i * 3) % 5000,
                    CASE i % 4 WHEN 0 THEN 'spawned' WHEN 1 THEN 'executed_as' WHEN 2 THEN 'opened' ELSE 'wrote' END,
                    {T} - 30 * {DAY} + (i * (30 * {DAY} / {prov_n})), NULL, NULL, NULL FROM s"
        ),
        [],
    )
    .unwrap();
    // 의심 사건 선: 30일에 22만, 근거 있음
    c.execute(
        &format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < {susp_raw_n})
             INSERT INTO edges(id, src, dst, rel, ts, evidence_id, chapter, attrs_json)
             SELECT 40000000 + i, 1 + i % 2000, 2001 + (i * 11) % 20000, CASE WHEN i % 3 = 0 THEN 'connected' ELSE 'spawned' END,
                    {T} - 30 * {DAY} + (i * (30 * {DAY} / {susp_raw_n})), 10000000 + i, 1 + i % 4, NULL FROM s"
        ),
        [],
    )
    .unwrap();
    c.execute_batch(
        "INSERT INTO edge_evidence(edge_id, raw_id) SELECT id, evidence_id FROM edges WHERE evidence_id IS NOT NULL;
         INSERT OR REPLACE INTO raw_size(k, bytes) SELECT 1, SUM(LENGTH(payload_json)) FROM raw_events;
         COMMIT; ANALYZE;",
    )
    .unwrap();
    let total: i64 = c
        .query_row("SELECT bytes FROM raw_size", [], |r| r.get(0))
        .unwrap();
    eprintln!(
        "fill {:?} edges={} raw={} raw_bytes={}",
        t.elapsed(),
        ord_n + prov_n + susp_raw_n,
        raw_n + susp_raw_n,
        total
    );
    // 지금 상태에서 한 번(밀린 것 정리) → 1시간 뒤(평소 모습)
    let mut policy = RetentionPolicy::default();
    policy.raw_max_bytes = total - total / 74; // 한 시간치쯤 넘친 상태
    for (name, now) in [("first", T), ("hour+1", T + HOUR)] {
        // 그 한 시간 동안 새로 들어온 것은 넣지 않는다 — 정리 대상은 "3일 넘은 한 시간치"로 같다
        let t = std::time::Instant::now();
        let r = apply(&store, now, policy).unwrap();
        eprintln!(
            "{name}: total {:?} fold={} raw={} size={} nodes={} | compacted={} prov={} susp={} raw_del={} by_size={}",
            t.elapsed(), r.ms_fold, r.ms_raw, r.ms_size, r.ms_nodes, r.edges_compacted, r.provenance_deleted, r.suspicious_deleted, r.raw_deleted, r.raw_deleted_by_size
        );
        policy.raw_max_bytes -= total / 74;
    }
}
