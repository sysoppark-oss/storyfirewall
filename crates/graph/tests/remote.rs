//! 원격 제어 사기 경보 (기획서 14판 20-4): 그래프 조회 부분 — 이미 돌던 원격 도구 찾기, pid 별 외부 송수신

use graph::event::{Event, EventKind};
use graph::ingest::Ingester;
use graph::remote::{running_tools, sent_recv_by_pid, Sample};
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
