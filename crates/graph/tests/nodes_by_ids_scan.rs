//! diag-159: 많이 찾을 때(표 차례 읽기)와 적게 찾을 때(IN 묶음)가 같은 결과를 내는지
use graph::store::Store;

#[test]
fn full_scan_path_matches_chunk_path() {
    let store = Store::open_in_memory().unwrap();
    {
        let c = store.conn();
        let tx = c.unchecked_transaction().unwrap();
        {
            let mut st = tx
                .prepare("INSERT INTO nodes(id, kind, key, label, first_ts, last_ts, attrs_json) VALUES (?1, 'remote', ?2, NULL, ?1, ?1, '{}')")
                .unwrap();
            for i in 1..=25_000i64 {
                st.execute(rusqlite::params![i, format!("10.0.0.{i}:443")])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }
    // 큰 요청: 20,001개(+ 없는 id 2개, 중복) → 표 차례 읽기
    let mut big: Vec<i64> = (2..=20_002).collect();
    big.extend([99_999, 100_000, 5, 5]);
    let a = graph::query::nodes_by_ids(&store, &big).unwrap();
    assert_eq!(a.len(), 20_001);
    assert!(!a.contains_key(&99_999) && !a.contains_key(&1));
    // 작은 요청으로 같은 노드를 읽어 내용 비교
    let small: Vec<i64> = vec![2, 5, 777, 20_002];
    let b = graph::query::nodes_by_ids(&store, &small).unwrap();
    for id in small {
        let (x, y) = (&a[&id], &b[&id]);
        assert_eq!(
            (
                x.kind.as_str(),
                x.key.as_str(),
                x.label.as_str(),
                x.first_ts
            ),
            (
                y.kind.as_str(),
                y.key.as_str(),
                y.label.as_str(),
                y.first_ts
            )
        );
    }
    // label 이 NULL 이면 key 를 쓴다(두 경로 같게)
    assert_eq!(a[&777].label, "10.0.0.777:443");
}

/// diag-265: 같은 id 가 거듭 든 목록(판정 뷰는 선마다 두 끝점을 넘긴다)에 표를 목록 길이만큼 잡아
/// 노드 22만에 426만 칸(900 MiB)을 쥐고 있었다. 표 크기는 서로 다른 id 수를 따라야 한다.
#[test]
fn table_is_sized_by_distinct_ids_not_by_list_length() {
    let store = Store::open_in_memory().unwrap();
    for i in 1..=50i64 {
        store
            .conn()
            .execute(
                "INSERT INTO nodes(id, kind, key, label, first_ts, last_ts, attrs_json) VALUES (?1, 'remote', ?2, NULL, 1, 1, '{}')",
                rusqlite::params![i, format!("10.0.0.{i}:443")],
            )
            .unwrap();
    }
    // 50개 노드를 20만 번 가리키는 목록(큰 요청 경로)과 1만 번 가리키는 목록(묶음 경로)
    for len in [200_000usize, 10_000] {
        let ids: Vec<i64> = (0..len).map(|i| (i % 50) as i64 + 1).collect();
        let got = graph::query::nodes_by_ids(&store, &ids).unwrap();
        assert_eq!(got.len(), 50);
        assert!(
            got.capacity() < 200,
            "목록 길이 {len} 에 표 {} 칸",
            got.capacity()
        );
    }
}
