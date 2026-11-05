//! A19 화면용 조회: 연결 목록, 프로세스 상세, 자손, 끊기 대상.

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::views;
use graph::Store;

const T: i64 = 133_800_000_000_000_000;
const S: i64 = 10_000_000;
const PAYLOAD: &str = r"C:\Users\pjg\AppData\Local\Temp\payload.exe";

fn ev(ts: i64, source: &str, kind: EventKind) -> Event {
    Event {
        ts,
        source: source.into(),
        kind,
    }
}

fn scenario() -> Store {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let events = vec![
        ev(
            T,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 1000,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: T,
                services: vec![],
            },
        ),
        ev(
            T + S,
            "etw:file",
            EventKind::FileWrite {
                proc: ProcRef::new(1000, None),
                path: PAYLOAD.into(),
            },
        ),
        ev(
            T + S,
            "motw",
            EventKind::Downloaded {
                path: PAYLOAD.into(),
                host_url: Some("https://evil.example/p".into()),
                referrer_url: None,
                zone_id: Some(3),
            },
        ),
        ev(
            T + 2 * S,
            "signature",
            EventKind::Signature {
                path: PAYLOAD.into(),
                signer: None,
                issuer: None,
                status: "nosignature".into(),
                catalog: false,
            },
        ),
        ev(
            T + 3 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 2200,
                ppid: 1000,
                image: PAYLOAD.into(),
                create_time: Some(T + 3 * S),
            },
        ),
        // 자손: payload → cmd → powershell, 그리고 payload 가 띄운 svchost(위장 아님, 시스템 이미지)
        ev(
            T + 4 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 2300,
                ppid: 2200,
                image: r"C:\Windows\System32\cmd.exe".into(),
                create_time: Some(T + 4 * S),
            },
        ),
        ev(
            T + 5 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 2400,
                ppid: 2300,
                image: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
                create_time: Some(T + 5 * S),
            },
        ),
        ev(
            T + 5 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 2500,
                ppid: 2200,
                image: r"C:\Windows\System32\svchost.exe".into(),
                create_time: Some(T + 5 * S),
            },
        ),
        ev(
            T + 6 * S,
            "autorun",
            EventKind::AutorunRegistered {
                proc: ProcRef::new(2200, None),
                location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater".into(),
                target: PAYLOAD.into(),
            },
        ),
        ev(
            T + 6 * S,
            "etw:file",
            EventKind::FileWrite {
                proc: ProcRef::new(2400, None),
                path: r"C:\Users\pjg\AppData\Roaming\x.ps1".into(),
            },
        ),
        ev(
            T + 7 * S,
            "etw:dns",
            EventKind::DnsQuery {
                proc: ProcRef::new(2200, None),
                name: "c2.evil.example".into(),
                results: vec!["203.0.113.9".into()],
            },
        ),
        ev(
            T + 8 * S,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(2200, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000,
                raddr: "203.0.113.9".into(),
                rport: 8443,
            },
        ),
        ev(
            T + 9 * S,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(2200, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50001,
                raddr: "203.0.113.9".into(),
                rport: 8443,
            },
        ),
        ev(
            T + 9 * S,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(2500, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50002,
                raddr: "198.51.100.7".into(),
                rport: 443,
            },
        ),
        ev(
            T + 10 * S,
            "etw:process",
            EventKind::ProcessStop { pid: 2300 },
        ),
    ];
    ing.ingest_all(&events).unwrap();
    st.add_conn_bytes(2200, "tcp", "203.0.113.9", 8443, 1200, 34000, T + 9 * S)
        .unwrap();
    st
}

fn proc_id(st: &Store, pid: u32, ct: i64) -> i64 {
    st.find_node(graph::NodeKind::Process, &format!("{pid}@{ct}"))
        .unwrap()
        .unwrap()
}

#[test]
fn connections_are_aggregated_per_process_remote_with_bytes() {
    let st = scenario();
    let rows = views::connections(&st, T, 100).unwrap();
    let p = rows.iter().find(|r| r.pid == 2200).expect("payload 접속");
    assert_eq!(p.count, 2, "같은 (프로세스, 원격지) 두 번 접속은 한 줄");
    assert_eq!(p.raddr, "203.0.113.9");
    assert_eq!(p.rport, 8443);
    assert_eq!(p.domain.as_deref(), Some("c2.evil.example"));
    assert_eq!(p.direction, "out");
    assert_eq!((p.sent, p.recv), (1200, 34000));
    assert!(p.image.ends_with("payload.exe"));
    // 최신 순
    assert!(rows.windows(2).all(|w| w[0].last_ts >= w[1].last_ts));
    // since 이후만
    assert!(views::connections(&st, T + 100 * S, 100)
        .unwrap()
        .is_empty());
}

#[test]
fn process_detail_has_signature_origin_children_and_autoruns() {
    let st = scenario();
    let id = proc_id(&st, 2200, T + 3 * S);
    let d = views::process_detail(&st, id, 50).unwrap();
    assert_eq!(d.pid, 2200);
    assert_eq!(d.create_ts, T + 3 * S);
    assert_eq!(
        d.signature.as_ref().unwrap()["sig_status"],
        serde_json::json!("nosignature")
    );
    assert_eq!(
        d.origin.as_ref().unwrap()["host_url"],
        serde_json::json!("https://evil.example/p")
    );
    assert_eq!(d.children.len(), 2);
    assert_eq!(d.autoruns.len(), 1);
    assert!(!d.connections.is_empty());
    assert!(d.parents.iter().any(|r| r.rel == "spawned"));
    assert!(!d.ended);
    let cmd = views::process_detail(&st, proc_id(&st, 2300, T + 4 * S), 50).unwrap();
    assert!(cmd.ended, "ProcessStop 뒤 ended");
}

#[test]
fn cut_targets_from_file_root_include_descendants_and_mark_system() {
    let st = scenario();
    let f = st
        .find_node(graph::NodeKind::File, PAYLOAD)
        .unwrap()
        .unwrap();
    let t = views::cut_targets(&st, f, 1000).unwrap();
    assert_eq!(t.root_kind, "file");
    assert_eq!(t.root_image.as_deref(), Some(PAYLOAD));
    let pids: Vec<u32> = t.procs.iter().map(|p| p.pid).collect();
    for want in [2200, 2300, 2400, 2500] {
        assert!(pids.contains(&want), "{want} in {pids:?}");
    }
    assert!(!pids.contains(&1000), "부모(explorer)는 대상 아님");
    let svc = t.procs.iter().find(|p| p.pid == 2500).unwrap();
    assert!(svc.system, "svchost 는 시스템으로 표시");
    assert_eq!(t.system_addresses, vec![("198.51.100.7".to_string(), 443)]);
    assert_eq!(t.autoruns.len(), 1);
    assert_eq!(
        t.written_executables,
        vec![r"C:\Users\pjg\AppData\Roaming\x.ps1".to_string()]
    );
    // 프로세스 뿌리도 같은 집합
    let t2 = views::cut_targets(&st, proc_id(&st, 2200, T + 3 * S), 1000).unwrap();
    assert_eq!(t2.procs.len(), t.procs.len());
    // 상한
    assert!(views::cut_targets(&st, f, 2).unwrap().procs.len() <= 3);
}

#[test]
fn descendant_images_and_addresses_by_image() {
    let st = scenario();
    let imgs = views::descendant_images_of_file(&st, &PAYLOAD.to_ascii_uppercase(), 1000).unwrap();
    assert!(imgs.iter().any(|i| i.ends_with("powershell.exe")));
    assert!(imgs.iter().any(|i| i == PAYLOAD));
    assert!(views::descendant_images_of_file(&st, r"C:\nope.exe", 10)
        .unwrap()
        .is_empty());
    let a = views::addresses_of_image(&st, r"c:\windows\system32\svchost.exe", 0).unwrap();
    assert_eq!(
        a,
        vec![("198.51.100.7".to_string(), 443, "tcp".to_string())]
    );
}

/// 접점(A19 러너 실측): 두 연결이 같은 파일을 동시에 열어도 "database is locked" 없이 열려야 한다
#[test]
fn two_connections_open_same_file_concurrently() {
    let dir = std::env::temp_dir().join(format!("graph-lock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("g.db");
    for round in 0..100 {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let ps: Vec<_> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || {
                    Store::open(&p)
                        .map(|s| s.set_meta("k", "v").is_ok())
                        .map_err(|e| e.to_string())
                })
            })
            .collect();
        for h in ps {
            assert_eq!(h.join().unwrap(), Ok(true), "round {round}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A20: 첫 해시는 출신 기록에, 바뀌면 교체 사실을 남긴다. 서명 없는 실행 파일은 MOTW 없이도 출신 기록(장기 보관)을 만든다.
#[test]
fn file_hash_is_recorded_once_and_change_is_detected() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let p = r"C:\Tools\unsigned.exe";
    let h = |sha: &str, ts: i64| {
        ev(
            ts,
            "hash",
            EventKind::FileHash {
                path: p.into(),
                sha256: Some(sha.into()),
                size: 10,
                note: None,
            },
        )
    };
    ing.ingest(&h(&"a".repeat(64), T)).unwrap();
    ing.ingest(&h(&"a".repeat(64), T + S)).unwrap();
    let f = st.find_node(graph::NodeKind::File, p).unwrap().unwrap();
    let (sha, ts): (String, i64) = st
        .conn()
        .query_row(
            "SELECT sha256, sha256_ts FROM origins WHERE file_node = ?1",
            [f],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((sha.as_str(), ts), ("a".repeat(64).as_str(), T));
    assert!(st.node(f).unwrap().attr("content_changed_ts").is_none());
    ing.ingest(&h(&"b".repeat(64), T + 2 * S)).unwrap();
    let n = st.node(f).unwrap();
    assert_eq!(n.attr("sha256").unwrap(), serde_json::json!("b".repeat(64)));
    assert_eq!(
        n.attr("sha256_first").unwrap(),
        serde_json::json!("a".repeat(64))
    );
    assert_eq!(
        n.attr("content_changed_ts").unwrap(),
        serde_json::json!(T + 2 * S)
    );
    // 출신 기록의 첫 해시는 그대로
    let sha: String = st
        .conn()
        .query_row(
            "SELECT sha256 FROM origins WHERE file_node = ?1",
            [f],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sha, "a".repeat(64));
    // 해시를 못 구한 경우: 사유만
    ing.ingest(&ev(
        T,
        "hash",
        EventKind::FileHash {
            path: r"C:\big.exe".into(),
            sha256: None,
            size: 1 << 30,
            note: Some("too_large".into()),
        },
    ))
    .unwrap();
    let b = st
        .find_node(graph::NodeKind::File, r"C:\big.exe")
        .unwrap()
        .unwrap();
    assert_eq!(
        st.node(b).unwrap().attr("hash_note").unwrap(),
        serde_json::json!("too_large")
    );
}

/// 16차 Q4-2 재현: 읽고 나서 쓰기로 올라가는 DEFERRED 트랜잭션은 그 사이 다른 연결이 커밋하면 busy 처리기 없이 실패한다.
/// begin_write(IMMEDIATE) 는 기다렸다가 성공해야 한다. (수집 저장 스레드가 이 오류로 끝나면 수집 세션 전체가 멈춘다)
#[test]
fn deferred_upgrade_fails_but_begin_write_waits() {
    let dir = std::env::temp_dir().join(format!("graph-upg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("g.db");
    let _ = std::fs::remove_file(&path);
    let a = Store::open(&path).unwrap();
    let b = Store::open(&path).unwrap();
    // DEFERRED: A 가 읽기 스냅샷을 잡은 뒤 B 가 커밋 → A 의 쓰기는 즉시 실패
    a.conn().execute_batch("BEGIN").unwrap();
    let _: i64 = a
        .conn()
        .query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))
        .unwrap();
    b.set_meta("x", "1").unwrap();
    let t0 = std::time::Instant::now();
    let r = a
        .conn()
        .execute("INSERT INTO meta(key, value) VALUES ('y', '2')", []);
    assert!(r.is_err(), "DEFERRED 승격은 실패해야 재현이 된다");
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(1),
        "busy 처리기 없이 바로 실패"
    );
    a.conn().execute_batch("ROLLBACK").unwrap();
    // IMMEDIATE: 다른 연결이 쓰기를 쥐고 있어도 기다렸다 성공
    let (tx_ready, rx_ready) = std::sync::mpsc::channel();
    let p2 = path.clone();
    let h = std::thread::spawn(move || {
        let c = Store::open(&p2).unwrap();
        let t = c.begin_write().unwrap();
        t.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('x', '2')",
            [],
        )
        .unwrap();
        tx_ready.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        t.commit().unwrap();
    });
    rx_ready.recv().unwrap();
    let t0 = std::time::Instant::now();
    let tx = a.begin_write().expect("기다렸다가 잠금");
    assert!(
        t0.elapsed() >= std::time::Duration::from_millis(200),
        "실제로 기다렸다"
    );
    let _: i64 = tx
        .query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))
        .unwrap();
    tx.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('y', '3')",
        [],
    )
    .unwrap();
    tx.commit().unwrap();
    h.join().unwrap();
    assert_eq!(b.get_meta("y").unwrap().as_deref(), Some("3"));
    assert_eq!(b.get_meta("x").unwrap().as_deref(), Some("2"));
    // 놓으면 되돌림
    {
        let tx = a.begin_write().unwrap();
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('z', '9')",
            [],
        )
        .unwrap();
    }
    assert_eq!(a.get_meta("z").unwrap(), None);
    drop((a, b));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A21: 마인드맵 펼침 상한 — 허브 노드에서도 상한을 넘지 않고 잘렸다고 알린다
#[test]
fn project_is_capped_at_hub_nodes() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let mut evs = vec![ev(
        T,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid: 1000,
            ppid: 4,
            image: r"C:\Windows\explorer.exe".into(),
            create_time: T,
            services: vec![],
        },
    )];
    for i in 0..300u32 {
        evs.push(ev(
            T + i as i64 + 1,
            "etw:process",
            EventKind::ProcessStart {
                pid: 5000 + i,
                ppid: 1000,
                image: format!(r"C:\Apps\a{i}.exe"),
                create_time: Some(T + i as i64 + 1),
            },
        ));
    }
    ing.ingest_all(&evs).unwrap();
    let ex = st
        .find_node(graph::NodeKind::Process, &format!("1000@{T}"))
        .unwrap()
        .unwrap();
    let (b, cut) = graph::query::project_capped(&st, ex, 6, 100).unwrap();
    assert_eq!(b.len(), 100);
    assert!(cut);
    let (b, cut) = graph::query::project_capped(&st, ex, 1, 10_000).unwrap();
    assert!(!cut && b.len() > 300);
}

/// 17차 Q4: 원인 쪽을 부풀려도 행동 쪽(외부 접속)이 밀려나지 않는다 + 판정 선은 먼저 펼친다
#[test]
fn inflated_origin_side_cannot_push_out_actions() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let mut evs = vec![ev(
        T,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid: 1000,
            ppid: 4,
            image: r"C:\Windows\explorer.exe".into(),
            create_time: T,
            services: vec![],
        },
    )];
    // 드로퍼가 실행 전에 payload.exe 를 300번 덮어쓴다 → payload 의 원인 쪽(실행 파일 ← 만든 선) 깊이 2 가 부푼다
    evs.push(ev(
        T + 1,
        "etw:process",
        EventKind::ProcessStart {
            pid: 1100,
            ppid: 1000,
            image: r"C:\Temp\dropper.exe".into(),
            create_time: Some(T + 1),
        },
    ));
    for i in 0..300 {
        evs.push(ev(
            T + 2 + i,
            "etw:file",
            EventKind::FileWrite {
                proc: ProcRef::new(1100, None),
                path: r"C:\Temp\payload.exe".into(),
            },
        ));
    }
    evs.push(ev(
        T + 400,
        "etw:process",
        EventKind::ProcessStart {
            pid: 2200,
            ppid: 1100,
            image: r"C:\Temp\payload.exe".into(),
            create_time: Some(T + 400),
        },
    ));
    for i in 0..5u16 {
        evs.push(ev(
            T + 500 + i as i64,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(2200, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000 + i,
                raddr: format!("203.0.113.{i}"),
                rport: 443,
            },
        ));
    }
    ing.ingest_all(&evs).unwrap();
    let p = st
        .find_node(graph::NodeKind::Process, &format!("2200@{}", T + 400))
        .unwrap()
        .unwrap();
    let (b, cut) = graph::query::project_capped(&st, p, 3, 60).unwrap();
    assert!(cut);
    assert!(b.len() <= 60);
    let remotes = b.iter().filter(|x| x.node.kind == "remote").count();
    assert_eq!(remotes, 5, "외부 접속 5건은 모두 남는다");
    // 판정 선 우선: 원인 쪽 선 하나에 장을 붙이면 그 선이 같은 노드의 다른 선보다 먼저
    let dropper = st
        .find_node(graph::NodeKind::Process, &format!("1100@{}", T + 1))
        .unwrap()
        .unwrap();
    let last_junk_edge: i64 = st
        .conn()
        .query_row(
            "SELECT id FROM edges WHERE src = ?1 AND rel = 'wrote' ORDER BY ts DESC LIMIT 1",
            [dropper],
            |r| r.get(0),
        )
        .unwrap();
    st.conn()
        .execute(
            "UPDATE edges SET chapter = 1 WHERE id = ?1",
            [last_junk_edge],
        )
        .unwrap();
    // 드로퍼를 주인공으로: 행동 쪽 첫 가지는 판정 선
    let (b, _) = graph::query::project_capped(&st, dropper, 1, 10).unwrap();
    let first_action = b
        .iter()
        .find(|x| x.depth == 1 && matches!(x.side, graph::query::Side::Action))
        .unwrap();
    assert_eq!(first_action.via.as_ref().unwrap().id, last_junk_edge);
}

/// 공격 시나리오(14~17차 답변 #4): 이벤트 폭주로 수집기가 쉴 새 없이 쓰기 트랜잭션을 잡으면, 드물게 쓰는 엔진이
/// busy_timeout(5초) 안에 잠금을 못 얻는가(기아). 수집 배치 한 건의 길이는 100건/200ms 로 묶여 있으므로
/// 트랜잭션 사이 틈에 엔진이 들어가야 한다.
#[test]
fn rare_writer_is_not_starved_by_busy_writer() {
    let dir = std::env::temp_dir().join(format!("graph-starve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("g.db");
    let _ = std::fs::remove_file(&path);
    let _ = Store::open(&path).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (p2, st2) = (path.clone(), stop.clone());
    let busy = std::thread::spawn(move || {
        let s = Store::open(&p2).unwrap();
        let mut n = 0u64;
        while !st2.load(std::sync::atomic::Ordering::Relaxed) {
            let tx = s.begin_write().unwrap();
            for i in 0..100 {
                tx.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES (?1, 'x')",
                    [format!("k{}", i)],
                )
                .unwrap();
            }
            tx.commit().unwrap();
            n += 1;
        }
        n
    });
    std::thread::sleep(std::time::Duration::from_millis(200));
    let s = Store::open(&path).unwrap();
    let mut worst = std::time::Duration::ZERO;
    for _ in 0..20 {
        let t0 = std::time::Instant::now();
        let tx = s.begin_write().expect("기아 없이 잠금");
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('engine', 'y')",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        worst = worst.max(t0.elapsed());
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let batches = busy.join().unwrap();
    eprintln!("busy batches={batches} worst engine wait={worst:?}");
    assert!(worst < std::time::Duration::from_secs(2), "{worst:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 17차 Q3 답변: 버린 구간을 기록하고 겹치는 구간으로 꺼낸다
#[test]
fn ingest_gaps_are_recorded_and_queried() {
    let st = Store::open_in_memory().unwrap();
    let g = views::Gap {
        from_ts: T,
        to_ts: T + 5 * S,
        events: 100,
        reason: "store_failed".into(),
    };
    {
        let tx = st.begin_write().unwrap();
        views::record_gap(&tx, &g).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        views::gaps_between(&st, T + S, T + 2 * S).unwrap(),
        vec![g.clone()]
    );
    assert!(views::gaps_between(&st, T + 6 * S, T + 9 * S)
        .unwrap()
        .is_empty());
    assert_eq!(views::gaps_between(&st, 0, i64::MAX).unwrap().len(), 1);
}

/// 과제 23: diag 일관성 점검 — 서비스 없는 svchost, 실행 파일 선 없는 프로세스, 이름 모르는 프로세스
#[test]
fn consistency_counts() {
    use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
    let store = graph::store::Store::open_in_memory().unwrap();
    let t = 133_800_000_000_000_000i64;
    let e = |ts: i64, kind: EventKind| Event {
        ts,
        source: "test".into(),
        kind,
    };
    let svc = r"C:\Windows\System32\svchost.exe".to_string();
    let evs = vec![
        e(
            t,
            EventKind::ProcessSnapshot {
                pid: 10,
                ppid: 4,
                image: svc.clone(),
                create_time: t - 100,
                services: vec!["Dnscache".into()],
            },
        ),
        e(
            t,
            EventKind::ProcessSnapshot {
                pid: 11,
                ppid: 4,
                image: svc.clone(),
                create_time: t - 100,
                services: vec![],
            },
        ),
        e(
            t + 1,
            EventKind::ProcessStart {
                pid: 20,
                ppid: 10,
                image: r"C:\Tools\a.exe".into(),
                create_time: Some(t + 1),
            },
        ),
        // 스냅샷·시작 모두 없는 PID 의 연결 → 이름 모르는 프로세스
        e(
            t + 2,
            EventKind::Connect {
                proc: ProcRef::new(999, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 5000,
                raddr: "203.0.113.1".into(),
                rport: 443,
            },
        ),
    ];
    graph::ingest::Ingester::new(&store)
        .ingest_all(&evs)
        .unwrap();
    let c = graph::views::consistency(&store, 0).unwrap();
    let get = |n: &str| {
        c.iter()
            .find(|x| x.name == n)
            .map(|x| (x.bad, x.total))
            .unwrap()
    };
    assert_eq!(get("svchost_no_services"), (1, 2), "{c:?}");
    assert_eq!(get("process_unresolved").0, 1, "{c:?}");
    let (b, total) = get("process_no_image_file");
    assert!(total == 4 && b >= 1, "{c:?}");
}
