//! 원격 제어 사기 경보 (기획서 14판 20-4): 그래프 조회 부분 — 이미 돌던 원격 도구 찾기, pid 별 외부 송수신

use graph::event::{Event, EventKind};
use graph::ingest::Ingester;
use graph::remote::{facts_text, running_tools, sent_recv_by_pid, session_facts, Sample};
use graph::Store;

const T: i64 = 133_800_000_000_000_000;
const S: i64 = 10_000_000;

fn ev(ts: i64, kind: EventKind) -> Event {
    Event {
        ts,
        source: "snapshot".into(),
        kind,
    }
}

fn snap(pid: u32, image: &str) -> Event {
    ev(
        T,
        EventKind::ProcessSnapshot {
            pid,
            ppid: 4,
            image: image.into(),
            create_time: T - 100 * S,
            services: vec![],
        },
    )
}

#[test]
fn running_tools_finds_live_remote_tools_only() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.ingest(&snap(500, r"C:\Program Files\TeamViewer\TeamViewer.exe"))
        .unwrap();
    ing.ingest(&snap(600, r"C:\Windows\explorer.exe")).unwrap();
    ing.ingest(&snap(700, r"C:\Users\u\Downloads\AnyDesk.exe"))
        .unwrap();
    // AnyDesk 는 끝남
    ing.ingest(&ev(T + S, EventKind::ProcessStop { pid: 700 }))
        .unwrap();
    // 시작 때 고르는 기준은 최근 통신량: explorer 와 끝난 AnyDesk 도 통신했지만 빠진다
    for pid in [500, 600, 700] {
        st.add_conn_bytes(pid, "tcp", "203.0.113.5", 443, 10, 10, T + 2 * S)
            .unwrap();
    }
    let got = running_tools(&st, T).unwrap();
    let keys: Vec<(u32, &str)> = got.iter().map(|g| (g.0, g.2)).collect();
    assert_eq!(keys, vec![(500, "teamviewer")]);
    assert!(got[0].1 > 0, "노드 id");
    // 최근 통신이 없으면 고르지 않는다
    assert!(running_tools(&st, T + 1000 * S).unwrap().is_empty());
}

#[test]
fn sent_recv_excludes_loopback() {
    let st = Store::open_in_memory().unwrap();
    st.add_conn_bytes(500, "tcp", "203.0.113.5", 5938, 1000, 200, T)
        .unwrap();
    st.add_conn_bytes(500, "tcp", "203.0.113.5", 5938, 500, 0, T + S)
        .unwrap();
    st.add_conn_bytes(500, "tcp", "127.0.0.1", 5939, 9_000_000, 9_000_000, T)
        .unwrap();
    st.add_conn_bytes(500, "tcp", "::1", 5939, 9_000_000, 9_000_000, T)
        .unwrap();
    let got = sent_recv_by_pid(&st, &[500, 501]).unwrap();
    assert_eq!(
        got,
        vec![
            Sample {
                pid: 500,
                sent: 1500,
                recv: 200
            },
            Sample {
                pid: 501,
                sent: 0,
                recv: 0
            },
        ]
    );
}

#[test]
fn session_facts_collects_whole_pc_in_window() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.ingest(&snap(1000, r"C:\Windows\explorer.exe")).unwrap();
    let start = |ts: i64, pid: u32, image: &str| Event {
        ts,
        source: "etw:process".into(),
        kind: EventKind::ProcessStart {
            pid,
            ppid: 1000,
            image: image.into(),
            create_time: Some(ts),
        },
    };
    // 세션 전(빠짐), 세션 중 셸·설치 프로그램·평범한 프로그램, 세션 뒤(빠짐)
    ing.ingest(&start(T + 5 * S, 1100, r"C:\Windows\System32\notepad.exe"))
        .unwrap();
    ing.ingest(&start(
        T + 20 * S,
        1200,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ))
    .unwrap();
    ing.ingest(&start(
        T + 30 * S,
        1300,
        r"C:\Users\u\Downloads\BankSetup.exe",
    ))
    .unwrap();
    ing.ingest(&start(T + 40 * S, 1400, r"C:\Windows\System32\calc.exe"))
        .unwrap();
    ing.ingest(&start(T + 90 * S, 1500, r"C:\Windows\System32\cmd.exe"))
        .unwrap();
    let f = session_facts(&st, T + 10 * S, T + 60 * S).unwrap();
    assert_eq!(f.processes, 3);
    assert_eq!(f.shells, vec!["powershell.exe".to_string()]);
    assert_eq!(f.installers.len(), 1);
    let t = facts_text(&f);
    assert!(
        t.contains("새 프로그램 실행 3번")
            && t.contains("powershell.exe")
            && t.contains("banksetup.exe"),
        "{t}"
    );
    // 아무 일 없으면 빈 문장
    assert_eq!(
        facts_text(&session_facts(&st, T + 100 * S, T + 200 * S).unwrap()),
        ""
    );
}

#[test]
fn renamed_tool_found_by_valid_signer() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let exe = r"C:\Users\u\Downloads\tv.exe";
    ing.ingest(&ev(
        T,
        EventKind::ProcessStart {
            pid: 800,
            ppid: 4,
            image: exe.into(),
            create_time: Some(T),
        },
    ))
    .unwrap();
    st.add_conn_bytes(800, "tcp", "203.0.113.5", 5938, 10, 10, T + S)
        .unwrap();
    assert!(
        running_tools(&st, T).unwrap().is_empty(),
        "서명 오기 전에는 모름"
    );
    ing.ingest(&ev(
        T + S,
        EventKind::Signature {
            path: exe.into(),
            signer: Some("TeamViewer Germany GmbH".into()),
            issuer: None,
            status: "valid".into(),
            catalog: false,
        },
    ))
    .unwrap();
    let got = running_tools(&st, T).unwrap();
    assert_eq!(
        got.iter().map(|g| g.2).collect::<Vec<_>>(),
        vec!["teamviewer"]
    );
}

#[test]
fn session_facts_skip_service_session() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.ingest(&snap(1000, r"C:\Windows\explorer.exe")).unwrap();
    for (pid, img) in [
        (1100u32, r"C:\Windows\System32\cmd.exe"),
        (1200, r"C:\Windows\System32\MpCmdRun.exe"),
    ] {
        let ts = T + 20 * S;
        ing.ingest(&Event {
            ts,
            source: "etw:process".into(),
            kind: EventKind::ProcessStart {
                pid,
                ppid: 1000,
                image: img.into(),
                create_time: Some(ts),
            },
        })
        .unwrap();
        ing.ingest(&Event {
            ts,
            source: "etw:process".into(),
            kind: EventKind::ProcessSession {
                pid,
                create_time: ts,
                session: if pid == 1200 { 0 } else { 1 },
            },
        })
        .unwrap();
    }
    let f = session_facts(&st, T + 10 * S, T + 60 * S).unwrap();
    assert_eq!(f.processes, 1, "Session 0 의 백신 검사는 뺀다");
    assert_eq!(f.shells, vec!["cmd.exe".to_string()]);
}
