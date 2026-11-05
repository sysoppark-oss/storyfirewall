//! A20: 끊기 뿌리 파일 해시 대조 (출신 기록의 첫 해시 vs 지금)

use graph::event::{Event, EventKind};
use graph::ingest::Ingester;
use graph::Store;

#[test]
fn root_hash_match_changed_missing_unrecorded() {
    let dir = std::env::temp_dir().join(format!("sf-cut-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("payload.exe");
    std::fs::write(&exe, b"MZ first").unwrap();
    let path = exe.to_str().unwrap().to_string();
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let t = 133_800_000_000_000_000i64;
    let sha = match graph::hash::sha256_file(&path) {
        graph::hash::HashOutcome::Ok { sha256, .. } => sha256,
        o => panic!("{o:?}"),
    };
    ing.ingest_all(&[
        Event {
            ts: t,
            source: "snapshot".into(),
            kind: EventKind::ProcessSnapshot {
                pid: 10,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: t,
                services: vec![],
            },
        },
        Event {
            ts: t + 1,
            source: "etw:process".into(),
            kind: EventKind::ProcessStart {
                pid: 20,
                ppid: 10,
                image: path.clone(),
                create_time: Some(t + 1),
            },
        },
        Event {
            ts: t + 2,
            source: "hash".into(),
            kind: EventKind::FileHash {
                path: path.clone(),
                sha256: Some(sha.clone()),
                size: 8,
                note: None,
            },
        },
    ])
    .unwrap();
    let root = st.find_node(graph::NodeKind::File, &path).unwrap().unwrap();
    let p = svc::cut::plan(&st, root, &["terminate".into()]).unwrap();
    assert_eq!(p.root_hash.status, "match");
    assert_eq!(p.root_hash.recorded.as_deref(), Some(sha.as_str()));
    // 같은 경로에 다른 파일
    std::fs::write(&exe, b"MZ replaced").unwrap();
    let p = svc::cut::plan(&st, root, &[]).unwrap();
    assert_eq!(p.root_hash.status, "changed");
    assert!(p.warnings.iter().any(|w| w.contains("내용이 사건 당시")));
    assert!(!p.block_images.is_empty(), "차단은 경로 기준이라 그대로");
    // 삭제됨
    std::fs::remove_file(&exe).unwrap();
    assert_eq!(
        svc::cut::plan(&st, root, &[]).unwrap().root_hash.status,
        "missing"
    );
    // 해시 기록이 없는 파일
    std::fs::write(dir.join("other.exe"), b"x").unwrap();
    let other = dir.join("other.exe").to_str().unwrap().to_string();
    ing.ingest(&Event {
        ts: t + 3,
        source: "etw:process".into(),
        kind: EventKind::ProcessStart {
            pid: 30,
            ppid: 10,
            image: other.clone(),
            create_time: Some(t + 3),
        },
    })
    .unwrap();
    let r2 = st
        .find_node(graph::NodeKind::File, &other)
        .unwrap()
        .unwrap();
    assert_eq!(
        svc::cut::plan(&st, r2, &[]).unwrap().root_hash.status,
        "unrecorded"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 외부 문자열 → YAML 은 직렬화기로: 따옴표·개행·YAML 특수 문자가 든 경로도 정책 문서를 깨지 못한다
#[test]
fn cut_yaml_survives_hostile_paths() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let t = 133_800_000_000_000_000i64;
    let hostile = r"C:\Users\x\a' : {action: allow} #.exe";
    ing.ingest_all(&[
        Event {
            ts: t,
            source: "snapshot".into(),
            kind: EventKind::ProcessSnapshot {
                pid: 10,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: t,
                services: vec![],
            },
        },
        Event {
            ts: t + 1,
            source: "etw:process".into(),
            kind: EventKind::ProcessStart {
                pid: 20,
                ppid: 10,
                image: hostile.into(),
                create_time: Some(t + 1),
            },
        },
        Event {
            ts: t + 2,
            source: "etw:process".into(),
            kind: EventKind::ProcessStart {
                pid: 21,
                ppid: 20,
                image: "C:\\Users\\x\\b\nc.exe".into(),
                create_time: Some(t + 2),
            },
        },
    ])
    .unwrap();
    let root = st
        .find_node(graph::NodeKind::File, hostile)
        .unwrap()
        .unwrap();
    let p = svc::cut::plan(&st, root, &[]).unwrap();
    let doc = dsl::parse(&p.yaml).expect("YAML 이 깨지지 않음");
    assert_eq!(doc.policies.len(), 1);
    assert_eq!(
        doc.policies[0].action,
        dsl::model::Action::Block,
        "allow 로 바뀌지 않음"
    );
    assert_eq!(
        doc.policies[0].matcher.process,
        vec![hostile.to_string()],
        "제어 문자 경로는 빠지고 원래 경로는 그대로"
    );
    assert!(p.warnings.iter().any(|w| w.contains("제어 문자")));
    assert!(p
        .policy_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)));
}

/// 16차 Q1-c: 대상이 코드를 주입한 정상 프로그램(브라우저)은 경로째 막지 않고, 그 정상 자식도 따라가지 않으며,
/// 접속지만 막는다. 끝내기는 terminate_injected 일 때만.
#[test]
fn injected_host_is_not_path_blocked_and_its_children_are_not_targets() {
    use graph::event::{Direction, ProcRef, Proto};
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let t = 133_800_000_000_000_000i64;
    let chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    let payload = r"C:\Users\x\AppData\Local\Temp\payload.exe";
    let ev = |ts: i64, kind: EventKind| Event {
        ts,
        source: "t".into(),
        kind,
    };
    ing.ingest_all(&[
        ev(
            t,
            EventKind::ProcessSnapshot {
                pid: 10,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: t,
                services: vec![],
            },
        ),
        ev(
            t,
            EventKind::ProcessSnapshot {
                pid: 15,
                ppid: 10,
                image: chrome.into(),
                create_time: t,
                services: vec![],
            },
        ),
        ev(
            t + 1,
            EventKind::ProcessStart {
                pid: 20,
                ppid: 10,
                image: payload.into(),
                create_time: Some(t + 1),
            },
        ),
        // 주입 전 브라우저의 정상 접속 → 차단 후보 아님
        ev(
            t + 1,
            EventKind::Connect {
                proc: ProcRef::new(15, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50999,
                raddr: "142.250.1.1".into(),
                rport: 443,
            },
        ),
        ev(
            t + 2,
            EventKind::Injected {
                from: ProcRef::new(20, None),
                into: ProcRef::new(15, None),
                method: "CreateRemoteThread".into(),
            },
        ),
        ev(
            t + 3,
            EventKind::ProcessStart {
                pid: 16,
                ppid: 15,
                image: chrome.into(),
                create_time: Some(t + 3),
            },
        ), // 렌더러
        ev(
            t + 4,
            EventKind::Connect {
                proc: ProcRef::new(15, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 51000,
                raddr: "203.0.113.50".into(),
                rport: 443,
            },
        ),
        ev(
            t + 5,
            EventKind::Connect {
                proc: ProcRef::new(20, None),
                proto: Proto::Udp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 51001,
                raddr: "203.0.113.51".into(),
                rport: 5353,
            },
        ),
    ])
    .unwrap();
    let root = st
        .find_node(graph::NodeKind::File, payload)
        .unwrap()
        .unwrap();
    let p = svc::cut::plan(&st, root, &["terminate".into()]).unwrap();
    assert_eq!(
        p.block_images,
        vec![payload.to_string()],
        "chrome 경로는 막지 않음"
    );
    assert_eq!(p.injected_hosts.len(), 1);
    assert_eq!(p.injected_hosts[0].pid, 15);
    assert!(
        p.terminate.iter().all(|x| x.pid == 20),
        "chrome·렌더러는 기본 종료 대상 아님: {:?}",
        p.terminate
    );
    assert!(
        !p.injected_hosts
            .iter()
            .chain(p.terminate.iter())
            .any(|x| x.pid == 16),
        "주입당한 프로그램의 자식은 따라가지 않음"
    );
    let a: Vec<(String, u16, u8, String)> = p
        .addresses
        .iter()
        .map(|a| (a.ip.clone(), a.port, a.proto, a.why.clone()))
        .collect();
    assert!(
        a.contains(&("203.0.113.50".into(), 443, 6, "injected".into())),
        "{a:?}"
    );
    assert!(
        !a.iter().any(|x| x.0 == "142.250.1.1"),
        "주입 전 접속은 빼야 한다: {a:?}"
    );
    assert!(
        a.contains(&("203.0.113.51".into(), 5353, 17, "target".into())),
        "UDP 는 17: {a:?}"
    );
    assert!(p
        .warnings
        .iter()
        .any(|w| w.contains("주입한 정상 프로그램")));
    // 명시하면 주입당한 프로그램도 끝낸다
    let p = svc::cut::plan(
        &st,
        root,
        &["terminate".into(), "terminate_injected".into()],
    )
    .unwrap();
    assert!(p.terminate.iter().any(|x| x.pid == 15));
}
