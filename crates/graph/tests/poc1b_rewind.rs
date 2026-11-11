//! P3 통과 기준: PoC 1-b run-2 의 실측 로그를 그래프에 넣고,
//! curl.exe 의 접속에서 되감기하면 "접속 ← curl.exe ← (부모 pwsh) " 사슬이 복원돼야 한다.
//! 또 CryptSvc(svchost, pid 880)의 CRL 조회가 curl 에 귀속(connected_via)돼야 한다.

use graph::event::{Event, EventKind};
use graph::ingest::Ingester;
use graph::query::{project, rewind, Side};
use graph::{NodeKind, Store};

fn load_fixture() -> Vec<Event> {
    graph::textlog::parse_text(graph::textlog::POC1B_RUN2)
}

#[test]
fn ingests_run2_and_rewinds_curl_chain() {
    let store = Store::open_in_memory().unwrap();
    let events = load_fixture();
    assert!(events.len() > 40, "fixture 파싱 수: {}", events.len());

    let mut ing = Ingester::new(&store);
    let edges = ing.ingest_all(&events).unwrap();
    assert!(edges > 25, "선 수: {edges}"); // DNS 1초 합치기 후 34
    assert!(store.count_nodes().unwrap() > 20);

    // curl.exe (pid 7368) 가 www.rust-lang.org 의 IP 로 접속한 remote 노드를 찾는다
    let remote = store
        .find_node(NodeKind::Remote, "185.199.108.153:443")
        .unwrap()
        .expect("remote 노드");
    let steps = rewind(&store, remote, 6).unwrap();
    let labels: Vec<String> = steps
        .iter()
        .map(|s| format!("{}:{}", s.node.kind, s.node.label))
        .collect();
    eprintln!("되감기: {labels:?}");

    // 접속 ← curl.exe(프로세스) ← curl.exe(파일) 와 ← 부모 프로세스(pid 6732, 수집 전부터 존재)
    assert_eq!(steps[0].node.kind, "remote");
    assert!(
        labels.iter().any(|l| l == "process:curl.exe"),
        "curl 프로세스가 사슬에 있어야 함"
    );
    assert!(
        labels.iter().any(|l| l == "file:curl.exe"),
        "실행 파일 노드가 사슬에 있어야 함"
    );
    assert!(
        labels
            .iter()
            .any(|l| l.starts_with("process:알 수 없는 프로그램(PID 6732)")),
        "부모(pid 6732)까지 올라가야 함"
    );

    // remote 노드에 DNS 로 얻은 도메인 이름이 붙어야 한다 (IP 만 남는 연결에 도메인 부여)
    let r = store.node(remote).unwrap();
    assert_eq!(r.label, "www.rust-lang.org:443");
}

#[test]
fn attributes_cryptsvc_crl_lookup_to_curl() {
    let store = Store::open_in_memory().unwrap();
    let events = load_fixture();
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&events).unwrap();

    // pid 880 은 수집 전부터 있던 svchost(CryptSvc). 스냅샷 없이 넣으면 이름을 모른다.
    let unknown = store.latest_process_by_pid(880, i64::MAX).unwrap().unwrap();
    assert!(store
        .node(unknown)
        .unwrap()
        .label
        .starts_with("알 수 없는 프로그램(PID 880)"));

    // 제품 경로: 수집 시작 시 프로세스 스냅샷(SCM 매핑 포함)이 먼저 들어온다 (명세 4판 2-2)
    let store2 = Store::open_in_memory().unwrap();
    let mut ing2 = Ingester::new(&store2);
    let snap = Event::new(
        events[0].ts - 10_000_000,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid: 880,
            ppid: 4,
            image: r"C:\Windows\System32\svchost.exe".into(),
            create_time: events[0].ts - 600_000_000, // 1분 전에 생성
            services: vec!["CryptSvc".into()],
        },
    );
    ing2.ingest(&snap).unwrap();
    ing2.ingest_all(&events).unwrap();

    // CRL 서버(x1.c.lencr.org → 184.29.31.119:80)로의 접속이 curl 프로세스에 connected_via 로 귀속돼야 한다
    let crl = store2
        .find_node(NodeKind::Remote, "184.29.31.119:80")
        .unwrap()
        .expect("CRL remote");
    let incoming = store2.edges_to(crl).unwrap();
    let rels: Vec<&str> = incoming.iter().map(|e| e.rel.as_str()).collect();
    eprintln!("CRL 노드로 들어오는 선: {rels:?}");
    assert!(
        rels.contains(&"connected"),
        "svchost 의 실제 접속(사실)이 남아야 함"
    );
    assert!(
        rels.contains(&"connected_via"),
        "curl 에 귀속된 선(해석)이 있어야 함"
    );

    let via = incoming.iter().find(|e| e.rel == "connected_via").unwrap();
    let origin = store2.node(via.src).unwrap();
    assert_eq!(origin.label, "curl.exe", "귀속 대상은 curl.exe 여야 함");

    // 투영: curl 을 주인공으로 하면 CRL 접속이 '무엇을 했나' 쪽 가지에 나와야 한다
    let curl = via.src;
    let branches = project(&store2, curl, 2).unwrap();
    let action_labels: Vec<&str> = branches
        .iter()
        .filter(|b| b.side == Side::Action && b.depth == 1)
        .map(|b| b.node.label.as_str())
        .collect();
    eprintln!("curl 의 행동 가지: {action_labels:?}");
    assert!(action_labels.contains(&"x1.c.lencr.org:80"));
    assert!(action_labels.contains(&"www.rust-lang.org:443"));
}

#[test]
fn projection_marks_repeated_nodes_as_seen() {
    let store = Store::open_in_memory().unwrap();
    let events = load_fixture();
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&events).unwrap();
    // DNS 서비스(1896)를 주인공으로: DNS 서버(168.63.129.16:53)로 UDP 송신이 여러 번 → 두 번째부터 seen=true
    let svc = store
        .latest_process_by_pid(1896, i64::MAX)
        .unwrap()
        .unwrap();
    let branches = project(&store, svc, 2).unwrap();
    let seen_count = branches.iter().filter(|b| b.seen).count();
    assert!(
        seen_count >= 1,
        "같은 노드로의 반복 선은 참조 표시가 돼야 함"
    );
}

#[test]
fn snapshot_and_process_start_dedupe_on_create_time() {
    // 명세 4판 2-2 ③: ETW 를 먼저 켜고 스냅샷을 뜨므로, 같은 프로세스가 스냅샷과 ProcessStart 양쪽에
    // 올 수 있다. CreateTime 이 같으면 하나의 노드여야 한다.
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let ct = 133_000_000_000_000_000i64;
    let start = Event::new(
        ct + 30_000, // 이벤트 기록 시각은 생성보다 3ms 늦다
        "etw:process",
        EventKind::ProcessStart {
            pid: 4242,
            ppid: 1,
            image: r"C:\\x\\a.exe".into(),
            create_time: Some(ct),
        },
    );
    let snap = Event::new(
        ct + 5_000_000,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid: 4242,
            ppid: 1,
            image: r"C:\\x\\a.exe".into(),
            create_time: ct,
            services: vec![],
        },
    );
    ing.ingest(&start).unwrap();
    ing.ingest(&snap).unwrap();
    let n: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM nodes WHERE kind='process' AND key LIKE '4242@%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1, "같은 PID@CreateTime 은 노드 하나");
    assert!(store
        .find_node(NodeKind::Process, &graph::ingest::proc_key(4242, ct))
        .unwrap()
        .is_some());
}

#[test]
fn scm_map_overrides_image_name_heuristic() {
    // SCM 매핑을 받은 뒤에는 이미지 이름이 svchost 여도 서비스 목록이 없으면 서비스로 보지 않는다
    // (이름만 흉내 낸 프로세스 대비, 명세 4판 2-1)
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let t0 = 133_000_000_000_000_000i64;
    let ev = |ts: i64, kind: EventKind| Event::new(ts, "t", kind);
    use graph::event::{Direction, ProcRef, Proto};
    ing.ingest(&ev(
        t0,
        EventKind::ServiceMap {
            pid: 900,
            services: vec!["CryptSvc".into()],
            system_token: Some(true),
            create_time: None,
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::ProcessStart {
            pid: 100,
            ppid: 1,
            image: r"C:\\u\\app.exe".into(),
            create_time: Some(t0),
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::ProcessStart {
            pid: 900,
            ppid: 1,
            image: r"C:\\Windows\\System32\\svchost.exe".into(),
            create_time: Some(t0),
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::ProcessStart {
            pid: 901,
            ppid: 1,
            image: r"C:\\tmp\\svchost.exe".into(),
            create_time: Some(t0),
        },
    ))
    .unwrap();
    let conn = |ts: i64, pid: u32, raddr: &str| {
        ev(
            ts,
            EventKind::Connect {
                proc: ProcRef::new(pid, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000,
                raddr: raddr.into(),
                rport: 443,
            },
        )
    };
    ing.ingest(&conn(t0 + 10, 100, "1.1.1.1")).unwrap();
    ing.ingest(&conn(t0 + 20, 900, "2.2.2.2")).unwrap(); // 진짜 서비스 → 귀속
    ing.ingest(&conn(t0 + 30, 901, "3.3.3.3")).unwrap(); // 이름만 svchost → 귀속 안 함
    let via: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE rel='connected_via'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(via, 1);
    let r3 = store
        .find_node(NodeKind::Remote, "3.3.3.3:443")
        .unwrap()
        .unwrap();
    assert!(store
        .edges_to(r3)
        .unwrap()
        .iter()
        .all(|e| e.rel == "connected"));
}

#[test]
fn capi2_attributes_crl_fetch_deterministically_and_replaces_window_rule() {
    // 명세 5판 2-3 (run-9 정정): 41(url, cert fileRef) ← 11(subject, 체인 fileRef 목록) ← subject 도메인을 만진 사용자 프로세스 P
    // ⇒ host(url) 로의 서비스 접속에 connected_via(method=capi2, confidence=high)
    use graph::event::{Direction, ProcRef, Proto};
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let t0 = 133_000_000_000_000_000i64;
    let s = 10_000_000i64; // 1초
    let ev = |ts: i64, kind: EventKind| Event::new(ts, "t", kind);
    ing.ingest(&ev(
        t0,
        EventKind::ServiceMap {
            pid: 700,
            services: vec!["KeyIso".into()],
            system_token: Some(true),
            create_time: None,
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::ProcessStart {
            pid: 700,
            ppid: 4,
            image: r"C:\Windows\System32\lsass.exe".into(),
            create_time: Some(t0),
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::ProcessStart {
            pid: 100,
            ppid: 1,
            image: r"C:\u\curl.exe".into(),
            create_time: Some(t0),
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::ProcessStart {
            pid: 101,
            ppid: 1,
            image: r"C:\u\other.exe".into(),
            create_time: Some(t0),
        },
    ))
    .unwrap();
    // curl 이 rust-lang.org 조회·접속, other 는 무관한 도메인
    ing.ingest(&ev(
        t0 + s,
        EventKind::DnsQuery {
            proc: ProcRef::new(100, None),
            name: "www.rust-lang.org".into(),
            results: vec!["1.2.3.4".into()],
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0 + s,
        EventKind::DnsQuery {
            proc: ProcRef::new(101, None),
            name: "example.org".into(),
            results: vec!["9.9.9.9".into()],
        },
    ))
    .unwrap();
    let conn = |ts: i64, pid: u32, raddr: &str, rport: u16| {
        ev(
            ts,
            EventKind::Connect {
                proc: ProcRef::new(pid, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000,
                raddr: raddr.into(),
                rport,
            },
        )
    };
    ing.ingest(&conn(t0 + s + 1, 100, "1.2.3.4", 443)).unwrap();
    ing.ingest(&conn(t0 + s + 2, 101, "9.9.9.9", 443)).unwrap(); // 2초 창 안에 후보가 둘 → window 귀속은 보류
                                                                 // lsass 가 CRL 서버에 접속 (DNS 로 도메인 부여)
    ing.ingest(&ev(
        t0 + 2 * s,
        EventKind::DnsQuery {
            proc: ProcRef::new(700, None),
            name: "x1.c.lencr.org".into(),
            results: vec!["5.5.5.5".into()],
        },
    ))
    .unwrap();
    ing.ingest(&conn(t0 + 2 * s + 1, 700, "5.5.5.5", 80))
        .unwrap();
    let crl = store
        .find_node(NodeKind::Remote, "5.5.5.5:80")
        .unwrap()
        .unwrap();
    assert!(
        store
            .edges_to(crl)
            .unwrap()
            .iter()
            .all(|e| e.rel != "connected_via"),
        "후보 둘이면 window 귀속 보류"
    );
    // CAPI2: 체인(subject rust-lang.org) → 폐기 확인(url x1.c.lencr.org)
    ing.ingest(&ev(
        t0 + 2 * s + 2,
        EventKind::CertChain {
            pid: 700,
            subject: "rust-lang.org".into(),
            task_id: "T1".into(),
            chain_refs: vec!["LEAF1".into(), "INTER1".into(), "ROOT1".into()],
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0 + 2 * s + 3,
        EventKind::RevocationFetch {
            pid: 700,
            task_id: "T9".into(),
            url: "http://x1.c.lencr.org/".into(),
            cert_ref: Some("INTER1".into()),
        },
    ))
    .unwrap();
    let via: Vec<_> = store
        .edges_to(crl)
        .unwrap()
        .into_iter()
        .filter(|e| e.rel == "connected_via")
        .collect();
    assert_eq!(via.len(), 1, "CAPI2 귀속 선 하나");
    let curl = store.latest_process_by_pid(100, i64::MAX).unwrap().unwrap();
    assert_eq!(
        via[0].src, curl,
        "원인은 curl (subject 접미 일치: www.rust-lang.org)"
    );
    let a = via[0].attrs_json.clone().unwrap();
    assert!(
        a.contains("\"method\":\"capi2\"") && a.contains("\"confidence\":\"high\""),
        "{a}"
    );

    // 41 이 접속보다 먼저 온 경우: 보류분으로 다음 서비스 접속에 바로 귀속
    ing.ingest(&ev(
        t0 + 3 * s,
        EventKind::CertChain {
            pid: 700,
            subject: "*.github.com".into(),
            task_id: "T2".into(),
            chain_refs: vec!["INTER2".into()],
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0 + 3 * s,
        EventKind::DnsQuery {
            proc: ProcRef::new(100, None),
            name: "api.github.com".into(),
            results: vec!["2.2.2.2".into()],
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0 + 3 * s + 1,
        EventKind::RevocationFetch {
            pid: 700,
            task_id: "T8".into(),
            url: "http://ocsp.digicert.com/".into(),
            cert_ref: Some("INTER2".into()),
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0 + 3 * s + 2,
        EventKind::DnsQuery {
            proc: ProcRef::new(700, None),
            name: "ocsp.digicert.com".into(),
            results: vec!["6.6.6.6".into()],
        },
    ))
    .unwrap();
    ing.ingest(&conn(t0 + 3 * s + 3, 700, "6.6.6.6", 80))
        .unwrap();
    let ocsp = store
        .find_node(NodeKind::Remote, "6.6.6.6:80")
        .unwrap()
        .unwrap();
    let via2: Vec<_> = store
        .edges_to(ocsp)
        .unwrap()
        .into_iter()
        .filter(|e| e.rel == "connected_via")
        .collect();
    assert_eq!(via2.len(), 1);
    assert!(via2[0].attrs_json.clone().unwrap().contains("capi2"));
}

#[test]
fn signature_updates_file_node_and_service_judgement() {
    use graph::event::{Direction, ProcRef, Proto};
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let t0 = 133_000_000_000_000_000i64;
    let ev = |ts: i64, kind: EventKind| Event::new(ts, "t", kind);
    // 서비스로 등록됐지만 서명이 Microsoft 가 아닌 svchost 흉내 → 서비스로 보지 않는다
    ing.ingest(&ev(
        t0,
        EventKind::ServiceMap {
            pid: 900,
            services: vec!["EvilSvc".into()],
            system_token: Some(true),
            create_time: None,
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::ProcessStart {
            pid: 900,
            ppid: 1,
            image: r"C:\tmp\svchost.exe".into(),
            create_time: Some(t0),
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::Signature {
            path: r"C:\tmp\svchost.exe".into(),
            signer: Some("Evil Corp".into()),
            issuer: None,
            status: "valid".into(),
            catalog: false,
        },
    ))
    .unwrap();
    ing.ingest(&ev(
        t0,
        EventKind::ProcessStart {
            pid: 100,
            ppid: 1,
            image: r"C:\u\app.exe".into(),
            create_time: Some(t0),
        },
    ))
    .unwrap();
    let conn = |ts: i64, pid: u32, raddr: &str| {
        ev(
            ts,
            EventKind::Connect {
                proc: ProcRef::new(pid, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000,
                raddr: raddr.into(),
                rport: 443,
            },
        )
    };
    ing.ingest(&conn(t0 + 10, 100, "1.1.1.1")).unwrap();
    ing.ingest(&conn(t0 + 20, 900, "2.2.2.2")).unwrap();
    let via: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE rel='connected_via'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        via, 0,
        "비 Microsoft 서명 서비스는 '대신 나간 통신'으로 보지 않는다"
    );
    let f = store
        .find_node(NodeKind::File, r"C:\tmp\svchost.exe")
        .unwrap()
        .unwrap();
    let attrs = store.node(f).unwrap().attrs_json.unwrap();
    assert!(attrs.contains("Evil Corp") && attrs.contains("\"sig_status\":\"valid\""));
}

/// diag-177: 문장 만들기가 선마다 묻던 근거·선 조회를 묶음으로 바꿈 — 묶음 결과가 선마다 물은 것과 같아야 한다
#[test]
fn batched_evidence_and_edges_match_single_lookups() {
    let store = Store::open_in_memory().unwrap();
    Ingester::new(&store).ingest_all(&load_fixture()).unwrap();
    let ids: Vec<i64> = store
        .conn()
        .prepare("SELECT id FROM edges ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(ids.len() > 25);
    let mut with_missing = ids.clone();
    with_missing.push(9_999_999);
    let many = store.evidence_of_many(&with_missing).unwrap();
    let edges = graph::query::edges_by_ids(&store, &with_missing).unwrap();
    for id in &ids {
        assert_eq!(
            many.get(id).cloned().unwrap_or_default(),
            store.evidence_of(*id).unwrap(),
            "선 {id}"
        );
        assert_eq!(edges[id], graph::query::edge_by_id(&store, *id).unwrap());
    }
    assert!(!edges.contains_key(&9_999_999));
    assert!(many.get(&9_999_999).is_none_or(|v| v.is_empty()));
}
