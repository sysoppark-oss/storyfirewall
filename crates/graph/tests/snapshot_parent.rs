//! 검수 122-1(2026-11-09 노트북): 출처 사슬에 "story-firewall-ui.exe → 실행 → wininit.exe" 가 나왔다.
//! 스냅샷에서 wininit 의 생성 시각을 못 읽으면 수집기가 스냅샷 시각을 넣는다 → 그 사이 smss 의 PID 를 다시 받은 UI 가 "부모"로 잡혔다.
//! 생성 시각을 모르는 스냅샷 프로세스는 부모 선을 잇지 않는다.

use graph::event::{Event, EventKind};
use graph::ingest::Ingester;
use graph::Store;

const S: i64 = 10_000_000;
const BOOT: i64 = 134_000_000_000_000_000;

fn snap(snap_ts: i64, pid: u32, ppid: u32, image: &str, create_time: i64) -> Event {
    Event::new(
        snap_ts,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid,
            ppid,
            image: image.into(),
            create_time,
            services: vec![],
        },
    )
}

fn spawned_into(st: &Store, image_suffix: &str) -> usize {
    st.conn()
        .query_row(
            "SELECT COUNT(*) FROM edges e JOIN nodes n ON n.id = e.dst
             WHERE e.rel = 'spawned' AND json_extract(n.attrs_json, '$.image') LIKE ?1",
            [format!("%{image_suffix}")],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as usize
}

#[test]
fn unknown_create_time_does_not_link_reused_pid_parent() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.set_boot_time(BOOT);
    let snap_ts = BOOT + 3600 * S;
    // UI 가 smss 의 옛 PID 500 을 받아 나중에 시작
    ing.ingest(&snap(
        snap_ts,
        500,
        9000,
        r"C:\Program Files\Story Firewall\story-firewall-ui.exe",
        BOOT + 3000 * S,
    ))
    .unwrap();
    // wininit: 생성 시각을 못 읽어 스냅샷 시각이 들어옴, 부모 PID = 500(끝난 smss)
    ing.ingest(&snap(
        snap_ts,
        600,
        500,
        r"C:\Windows\System32\wininit.exe",
        snap_ts,
    ))
    .unwrap();
    assert_eq!(
        spawned_into(&st, "wininit.exe"),
        0,
        "생성 시각을 모르면 부모를 잇지 않는다"
    );
    let unknown: bool = st
        .conn()
        .query_row(
            "SELECT json_extract(attrs_json, '$.create_time_unknown') FROM nodes WHERE json_extract(attrs_json, '$.image') LIKE '%wininit.exe'",
            [],
            |r| r.get::<_, Option<bool>>(0),
        )
        .unwrap()
        .unwrap_or(false);
    assert!(unknown, "모른다는 표시를 남긴다");
}

#[test]
fn known_create_time_still_links_real_parent() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.set_boot_time(BOOT);
    let snap_ts = BOOT + 3600 * S;
    ing.ingest(&snap(
        snap_ts,
        700,
        600,
        r"C:\Windows\System32\wininit.exe",
        BOOT + 5 * S,
    ))
    .unwrap();
    ing.ingest(&snap(
        snap_ts,
        800,
        700,
        r"C:\Windows\System32\services.exe",
        BOOT + 6 * S,
    ))
    .unwrap();
    assert_eq!(spawned_into(&st, "services.exe"), 1);
}

/// 이미 DB 에 들어간 잘못된 선은 다음에 열 때 한 번 지운다(정상 스냅샷 선은 남긴다)
#[test]
fn reopen_removes_old_bad_snapshot_parent_edges_once() {
    use graph::{NodeKind, Rel};
    let dir = std::env::temp_dir().join(format!("sf-fix122-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("g.db");
    let _ = std::fs::remove_file(&path);
    let snap_ts = BOOT + 3600 * S;
    {
        let st = Store::open(&path).unwrap();
        // 지난 판이 만든 상태를 손으로: wininit(노드 시각 = 스냅샷 시각) ← UI, services(진짜 생성 시각) ← wininit
        st.conn()
            .execute("DELETE FROM meta WHERE key = 'fix_122_unknown_ct'", [])
            .unwrap();
        let ui = st
            .upsert_node(
                NodeKind::Process,
                "500@1",
                "story-firewall-ui.exe",
                BOOT + 3000 * S,
                Some(r#"{"preexisting":true}"#),
            )
            .unwrap();
        let wi = st
            .upsert_node(
                NodeKind::Process,
                "600@2",
                "wininit.exe",
                snap_ts,
                Some(r#"{"preexisting":true}"#),
            )
            .unwrap();
        let sv = st
            .upsert_node(
                NodeKind::Process,
                "800@3",
                "services.exe",
                BOOT + 6 * S,
                Some(r#"{"preexisting":true}"#),
            )
            .unwrap();
        let r1 = st.insert_raw(snap_ts, "snapshot", "{}").unwrap();
        let r2 = st.insert_raw(snap_ts, "snapshot", "{}").unwrap();
        st.insert_edge(ui, wi, Rel::Spawned, snap_ts, Some(r1))
            .unwrap();
        st.insert_edge(wi, sv, Rel::Spawned, BOOT + 6 * S, Some(r2))
            .unwrap();
    }
    let st = Store::open(&path).unwrap();
    let n: i64 = st
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE rel = 'spawned'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1, "wininit 로 들어가는 잘못된 선만 지운다");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn find_processes_dedups_by_image_latest_first() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.set_boot_time(BOOT);
    let t = BOOT + 100 * S;
    ing.ingest(&snap(t, 10, 4, r"C:\a\WhaleSetup.exe", BOOT + 10 * S))
        .unwrap();
    ing.ingest(&snap(t, 11, 4, r"C:\a\WhaleSetup.exe", BOOT + 20 * S))
        .unwrap();
    ing.ingest(&snap(t, 12, 4, r"C:\b\whale.exe", BOOT + 15 * S))
        .unwrap();
    ing.ingest(&snap(t, 13, 4, r"C:\b\chrome.exe", BOOT + 16 * S))
        .unwrap();
    let f = graph::views::find_processes(&st, "WHALE", 10).unwrap();
    assert_eq!(
        f.iter().map(|x| x.label.as_str()).collect::<Vec<_>>(),
        ["WhaleSetup.exe", "whale.exe"]
    );
    assert_eq!(f[0].first_ts, BOOT + 20 * S, "같은 실행 파일은 최근 것");
    assert!(graph::views::find_processes(&st, "  ", 10)
        .unwrap()
        .is_empty());
}
