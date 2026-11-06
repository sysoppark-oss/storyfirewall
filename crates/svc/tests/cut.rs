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

/// 2026-11-06 노트북 제보: 수집 전부터 실행 중이라 경로를 모르는 프로세스를 끊으려 하면 "제어 문자" 경고로 대상이 빠지고,
/// 접속지 맨 앞의 DNS 주소(…:53/udp)로 만든 정책이 규칙 8 자동 제외로 비어 적용이 안 됐다.
/// → 살아 있으면 (PID, 생성 시각)으로 지금 경로를 읽어 채우고, DNS·NTP·DHCP 주소는 막을 목록에서 뺀다
#[test]
fn unknown_image_is_filled_from_live_process_and_dns_is_kept_open() {
    use graph::event::{Direction, ProcRef, Proto};
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let t = 133_800_000_000_000_000i64;
    let ev = |ts: i64, kind: EventKind| Event {
        ts,
        source: "t".into(),
        kind,
    };
    let conn = |ts: i64, raddr: &str, rport: u16, proto: Proto| {
        ev(
            ts,
            EventKind::Connect {
                proc: ProcRef::new(30, None),
                proto,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 40000u16.wrapping_add(rport),
                raddr: raddr.into(),
                rport,
            },
        )
    };
    ing.ingest_all(&[
        ev(
            t,
            EventKind::ProcessSnapshot {
                pid: 30,
                ppid: 4,
                image: String::new(),
                create_time: t,
                services: vec![],
            },
        ),
        conn(t + 1, "1.214.68.2", 53, Proto::Udp),
        conn(t + 2, "203.0.113.9", 443, Proto::Tcp),
        conn(t + 3, "127.0.0.1", 57256, Proto::Tcp),
        conn(t + 4, "192.168.0.1", 80, Proto::Tcp),
    ])
    .unwrap();
    let root = st
        .find_node(graph::NodeKind::Process, &format!("30@{t}"))
        .unwrap()
        .unwrap();
    // 살아 있는 프로세스 경로를 모르면: 경로 없이 접속지만, "제어 문자" 경고는 없다
    let p0 = svc::cut::plan(&st, root, &[]).unwrap();
    assert!(p0.block_images.is_empty());
    assert!(
        !p0.warnings.iter().any(|w| w.contains("제어 문자")),
        "{:?}",
        p0.warnings
    );
    assert!(
        p0.warnings
            .iter()
            .any(|w| w.contains("경로를 확인하지 못한")),
        "{:?}",
        p0.warnings
    );
    assert!(
        p0.addresses.iter().all(|a| a.port != 53),
        "DNS 는 막지 않는다"
    );
    assert!(p0.addresses.iter().any(|a| a.ip == "203.0.113.9"));
    assert!(
        p0.yaml.contains("203.0.113.9"),
        "첫 주소 정책이 DNS 가 아니어야 한다: {}",
        p0.yaml
    );
    // 호스트 흉내: PID 30 은 생성 시각 `real` 로 살아 있다. Host::live_image 와 같은 규칙(같은 생성 시각 또는 처음 본 시각 전에 생김)
    let host = |real: i64| {
        move |pid: u32, ft: i64, seen: i64| {
            (pid == 30 && (real == ft || (seen > 0 && real <= seen)))
                .then(|| (r"C:\Users\x\AppData\Local\Temp\agent.exe".to_string(), real))
        }
    };
    let p1 = svc::cut::plan_with(&st, root, &[], &host(t)).unwrap();
    assert_eq!(
        p1.block_images,
        vec![r"C:\Users\x\AppData\Local\Temp\agent.exe".to_string()]
    );
    assert!(
        p1.addresses.iter().all(|a| a.who == "agent.exe"),
        "프로그램을 모르던 접속지에 이름"
    );
    // 기록의 생성 시각이 어긋나도(수집 전부터 실행) 처음 본 시각보다 먼저 생긴 살아 있는 프로세스면 같은 프로세스 — 실제 생성 시각으로 끝낸다
    let p2 = svc::cut::plan_with(
        &st,
        root,
        &["terminate".to_string()],
        &host(t - 5_000_000_000),
    )
    .unwrap();
    assert_eq!(p2.block_images.len(), 1);
    assert!(
        p2.terminate
            .iter()
            .any(|x| x.pid == 30 && x.create_ts == t - 5_000_000_000),
        "{:?}",
        p2.terminate
    );
    // 처음 본 뒤에 생긴 같은 PID(재사용)는 채우지 않는다
    assert!(svc::cut::plan_with(&st, root, &[], &host(t + 99))
        .unwrap()
        .block_images
        .is_empty());
}
