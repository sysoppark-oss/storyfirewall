//! 2026-11-08 노트북 실측: TeamViewer_Service.exe 의 출처가 "… claude.exe → story-firewall-ui.exe → wininit.exe → services.exe"
//! 로 나왔다. 재부팅 전의 story-firewall-ui.exe 노드(종료 기록 없음)가 남아 있고, 재부팅 뒤 wininit.exe 의 부모 PID
//! (이미 끝난 smss 인스턴스)가 그 옛 PID 와 같아 "그 PID 의 가장 최근 프로세스"로 옛 노드가 이어졌다.
//! 규칙: 이번 부팅에서 생긴 프로세스의 부모는 이번 부팅의 프로세스여야 한다(부팅 시각 2분 여유).

use graph::event::{Event, EventKind};
use graph::ingest::{proc_key, Ingester};
use graph::{NodeKind, Store};

fn snap(now: i64, pid: u32, ppid: u32, img: &str, ct: i64) -> Event {
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
}

fn parents_of(store: &Store, id: i64) -> Vec<i64> {
    let mut st = store
        .conn()
        .prepare("SELECT src FROM edges WHERE dst = ?1 AND rel = 'spawned'")
        .unwrap();
    st.query_map([id], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn parent_from_previous_boot_is_not_linked_after_reboot() {
    let store = Store::open_in_memory().unwrap();
    let day = 864_000_000_000i64;
    let min = 600_000_000i64;
    let boot0 = 134_000_000_000_000_000i64;
    let boot1 = boot0 + day;
    // 재부팅 전: 서비스 실행 중 UI(PID 900) 를 봤다 — 종료 기록 없이 재부팅
    {
        let mut ing = Ingester::new(&store);
        ing.set_boot_time(boot0);
        ing.ingest(&snap(
            boot0 + 60 * min,
            900,
            800,
            r"C:\Program Files\Story Firewall\story-firewall-ui.exe",
            boot0 + 30 * min,
        ))
        .unwrap();
    }
    // 재부팅 뒤: wininit(부모 PID 900 = 끝난 smss 인스턴스) → services → TeamViewer_Service
    let mut ing = Ingester::new(&store);
    ing.set_boot_time(boot1);
    let now = boot1 + 10 * min;
    ing.ingest(&snap(
        now,
        600,
        900,
        r"C:\Windows\System32\wininit.exe",
        boot1 + 20_000_000,
    ))
    .unwrap();
    ing.ingest(&snap(
        now,
        700,
        600,
        r"C:\Windows\System32\services.exe",
        boot1 + 25_000_000,
    ))
    .unwrap();
    ing.ingest(&snap(
        now,
        5720,
        700,
        r"C:\Program Files\TeamViewer\TeamViewer_Service.exe",
        boot1 + 60_000_000,
    ))
    .unwrap();

    let wininit = store
        .find_node(NodeKind::Process, &proc_key(600, boot1 + 20_000_000))
        .unwrap()
        .unwrap();
    let old_ui = store
        .find_node(NodeKind::Process, &proc_key(900, boot0 + 30 * min))
        .unwrap()
        .unwrap();
    assert!(
        !parents_of(&store, wininit).contains(&old_ui),
        "재부팅 전 UI 가 wininit 의 부모로 이어짐"
    );
    // 이번 부팅 안의 부모는 그대로 잇는다
    let services = store
        .find_node(NodeKind::Process, &proc_key(700, boot1 + 25_000_000))
        .unwrap()
        .unwrap();
    assert_eq!(parents_of(&store, services), vec![wininit]);
    let tv = store
        .find_node(NodeKind::Process, &proc_key(5720, boot1 + 60_000_000))
        .unwrap()
        .unwrap();
    assert_eq!(parents_of(&store, tv), vec![services]);
}

/// 실시간 시작(ProcessStart)도 같다: 부모 PID 가 재부팅 전 노드에만 있으면 잇지 않는다
#[test]
fn live_start_does_not_adopt_previous_boot_parent() {
    let store = Store::open_in_memory().unwrap();
    let day = 864_000_000_000i64;
    let min = 600_000_000i64;
    let boot0 = 134_000_000_000_000_000i64;
    let boot1 = boot0 + day;
    {
        let mut ing = Ingester::new(&store);
        ing.set_boot_time(boot0);
        ing.ingest(&snap(
            boot0 + 60 * min,
            4444,
            800,
            r"C:\Users\u\old.exe",
            boot0 + 30 * min,
        ))
        .unwrap();
    }
    let mut ing = Ingester::new(&store);
    ing.set_boot_time(boot1);
    let t = boot1 + 30 * min;
    ing.ingest(&Event::new(
        t,
        "etw:process",
        EventKind::ProcessStart {
            pid: 5000,
            ppid: 4444,
            image: r"C:\Users\u\new.exe".into(),
            create_time: Some(t),
        },
    ))
    .unwrap();
    let child = store
        .find_node(NodeKind::Process, &proc_key(5000, t))
        .unwrap()
        .unwrap();
    let old = store
        .find_node(NodeKind::Process, &proc_key(4444, boot0 + 30 * min))
        .unwrap()
        .unwrap();
    assert!(
        !parents_of(&store, child).contains(&old),
        "재부팅 전 old.exe 가 부모로 이어짐"
    );
}
