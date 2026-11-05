//! L023: 부팅 직후 RTC 가 틀렸다가 동기화된 PC — 스냅샷 프로세스의 CreateTime 이 부팅보다 이르면
//! 선·노드 시각을 부팅 시각으로 올리고, 키(PID@CreateTime)와 원래 값은 그대로 둔다.

use graph::event::{Event, EventKind};
use graph::ingest::{proc_key, Ingester};
use graph::{NodeKind, Store};

#[test]
fn snapshot_create_time_before_boot_is_clamped_but_key_kept() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let day = 864_000_000_000i64; // 하루(100ns)
    let boot = 134_000_000_000_000_000i64;
    let now = boot + day / 4;
    let wrong = boot - 108 * day; // 부팅 때 RTC 가 석 달 반 뒤처져 있었다
    ing.set_boot_time(boot);
    let snap = |pid: u32, ppid: u32, img: &str, ct: i64| {
        Event::new(
            now,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid,
                ppid,
                image: img.into(),
                create_time: ct,
                services: vec![],
            },
        )
    };
    // 부모(services.exe)와 자식(BrYNSvc) 모두 틀린 시각 + 정상 시각 프로세스 하나
    ing.ingest(&snap(700, 4, r"C:\Windows\System32\services.exe", wrong))
        .unwrap();
    ing.ingest(&snap(
        4100,
        700,
        r"C:\Program Files\X\BrYNSvc.exe",
        wrong + 50_000_000,
    ))
    .unwrap();
    ing.ingest(&snap(5000, 700, r"C:\u\app.exe", boot + day / 8))
        .unwrap();

    // 키는 원래 CreateTime (종료 시 GetProcessTimes 대조용)
    let child = store
        .find_node(NodeKind::Process, &proc_key(4100, wrong + 50_000_000))
        .unwrap()
        .expect("키 유지");
    let (first_ts, attrs): (i64, String) = store
        .conn()
        .query_row(
            "SELECT first_ts, COALESCE(attrs_json,'') FROM nodes WHERE id=?1",
            [child],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(first_ts, boot, "보이는 시각은 부팅 시각");
    assert!(attrs.contains("\"create_time_uncertain\":true"), "{attrs}");
    assert!(
        attrs.contains(&format!("\"create_time_raw\":{}", wrong + 50_000_000)),
        "{attrs}"
    );

    // 선 시각도 부팅 시각, 부모 선은 이어진다
    let edge_ts: Vec<(String, i64)> = {
        let mut st = store
            .conn()
            .prepare("SELECT rel, ts FROM edges WHERE dst=?1")
            .unwrap();
        st.query_map([child], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|x| x.unwrap())
            .collect()
    };
    assert!(
        edge_ts.iter().any(|(r, _)| r == "spawned"),
        "부모 선 있음: {edge_ts:?}"
    );
    assert!(edge_ts.iter().all(|(_, t)| *t == boot), "{edge_ts:?}");

    // 정상 시각 프로세스는 그대로
    let ok = store
        .find_node(NodeKind::Process, &proc_key(5000, boot + day / 8))
        .unwrap()
        .unwrap();
    let (ts2, a2): (i64, String) = store
        .conn()
        .query_row(
            "SELECT first_ts, COALESCE(attrs_json,'') FROM nodes WHERE id=?1",
            [ok],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(ts2, boot + day / 8);
    assert!(!a2.contains("uncertain"));
}

#[test]
fn node_stored_before_the_fix_is_corrected_on_next_snapshot() {
    // 보정 전 빌드가 저장한 그래프(같은 키)에 새 서비스 실행이 스냅샷을 다시 넣으면 시각이 올라가야 한다
    let store = Store::open_in_memory().unwrap();
    let day = 864_000_000_000i64;
    let boot = 134_000_000_000_000_000i64;
    let wrong = boot - 108 * day;
    let ev = Event::new(
        boot + day / 4,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid: 4100,
            ppid: 4,
            image: r"C:\Program Files\X\BrYNSvc.exe".into(),
            create_time: wrong,
            services: vec![],
        },
    );
    Ingester::new(&store).ingest(&ev).unwrap(); // 부팅 시각 모름 = 옛 빌드
    let mut ing = Ingester::new(&store);
    ing.set_boot_time(boot);
    ing.ingest(&ev).unwrap();
    let id = store
        .find_node(NodeKind::Process, &proc_key(4100, wrong))
        .unwrap()
        .unwrap();
    let (ts, attrs): (i64, String) = store
        .conn()
        .query_row(
            "SELECT first_ts, attrs_json FROM nodes WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(ts, boot);
    assert!(attrs.contains("create_time_uncertain"), "{attrs}");
    let bad: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE dst=?1 AND ts<>?2",
            rusqlite::params![id, boot],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bad, 0);
}
