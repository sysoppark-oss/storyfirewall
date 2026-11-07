//! 시간대별 트래픽 요약(개편안 2판 1-4): 쓰기 경로에서 한 행씩 쌓이고, 조회는 그 표만 읽는다
use graph::Store;

const FT_2026_11_07_00: i64 = (1_794_009_600 + 11_644_473_600) * 10_000_000; // 2026-11-07 00:00 UTC
const H: i64 = 3_600 * 10_000_000;

#[test]
fn bytes_and_conns_accumulate_per_hour() {
    let st = Store::open_in_memory().unwrap();
    st.add_traffic_hour(FT_2026_11_07_00 + 5 * 10_000_000, 100, 10, 0).unwrap();
    st.add_traffic_hour(FT_2026_11_07_00 + 30 * 60 * 10_000_000, 50, 5, 0).unwrap();
    st.add_traffic_hour(FT_2026_11_07_00 + 10, 0, 0, 1).unwrap();
    st.add_traffic_hour(FT_2026_11_07_00 + H + 1, 7, 7, 1).unwrap();
    let rows = st.traffic_hourly(1_794_009_600).unwrap();
    assert_eq!(rows, vec![(1_794_009_600, 150, 15, 1, 0, 0), (1_794_009_600 + 3600, 7, 7, 1, 0, 0)]);
    st.add_blocked_hour(1_794_009_600 + 100, 3, 1).unwrap();
    st.add_blocked_hour(1_794_009_600 + 200, 2, 0).unwrap();
    assert_eq!(st.traffic_hourly(1_794_009_600).unwrap()[0], (1_794_009_600, 150, 15, 1, 5, 1));
    // since 가 시 중간이면 그 시간대부터
    let rows = st.traffic_hourly(1_794_009_600 + 3600 + 100).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(st.prune_traffic_hourly(1_794_009_600 + 3600).unwrap(), 1);
}

#[test]
fn hour_bucket_floors_to_hour() {
    assert_eq!(Store::hour_bucket(FT_2026_11_07_00 + H - 1), 1_794_009_600);
    assert_eq!(Store::hour_bucket(FT_2026_11_07_00 + H), 1_794_009_600 + 3600);
}
