//! 차단 기록 DB 7일 보관(2026-11-10 — 메모리에만 두니 재시작 때 증거가 사라졌다)
use graph::store::{BlockedFilter, BlockedRow};
use graph::Store;

fn row(ts: i64, f: u64, app: &str) -> BlockedRow {
    BlockedRow {
        ts,
        filter_id: f,
        app: app.into(),
        remote: "127.0.0.1".into(),
        rport: 8815,
        lport: 50000,
        proto: 6,
        dir: "out".into(),
        loopback: true,
        ours_at: false,
    }
}

#[test]
fn insert_load_prune() {
    let st = Store::open_in_memory().unwrap();
    st.blocked_log_insert(&[
        row(100, 7, "msedge.exe"),
        row(200, 7, "msedge.exe"),
        row(300, 9, "a.exe"),
    ])
    .unwrap();
    let f = BlockedFilter {
        name: "Block Edge".into(),
        provider_key: "decc16ca-3f33-4346-be1e-8fb4ae0f3d62".into(),
        ..Default::default()
    };
    st.blocked_filter_put(7, &f, 100).unwrap();
    // 처음 본 이름이 증거 — 나중 이름으로 덮지 않는다
    st.blocked_filter_put(
        7,
        &BlockedFilter {
            name: "renamed".into(),
            ..Default::default()
        },
        200,
    )
    .unwrap();
    let (rows, fs) = st.blocked_log_load(150).unwrap();
    assert_eq!(rows.iter().map(|r| r.ts).collect::<Vec<_>>(), [200, 300]);
    assert_eq!(fs, vec![(7, f)]);
    // 7일 지난 것 정리 + 줄 상한
    assert_eq!(st.blocked_log_prune(150, 100).unwrap(), 1);
    st.blocked_log_insert(
        &(0..10)
            .map(|i| row(400 + i, 9, "b.exe"))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(st.blocked_log_prune(0, 5).unwrap(), 7);
    let (rows, fs) = st.blocked_log_load(0).unwrap();
    assert_eq!(rows.len(), 5);
    assert_eq!(rows.last().unwrap().ts, 409);
    assert!(fs.is_empty(), "남은 줄이 가리키지 않는 필터 정보도 지운다");
}
