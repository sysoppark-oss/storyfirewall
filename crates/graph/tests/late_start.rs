//! 시작 이벤트가 접속 이벤트보다 늦게 와도 이름을 잃지 않는다(2026-11-06 노트북 실측: chrome 네트워크 서비스 PID 16720 이
//! "알 수 없는 프로그램(PID 16720)"으로 사건 카드에 나옴 — 생성 21:59:21, 첫 접속 21:59:25)

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::{NodeKind, Store};

const S: i64 = 10_000_000;
const T0: i64 = 134_000_000_000_000_000;
const CHROME: &str = r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";

fn connect(ts: i64, pid: u32, raddr: &str) -> Event {
    Event::new(
        ts,
        "etw",
        EventKind::Connect {
            proc: ProcRef::new(pid, None),
            proto: Proto::Tcp,
            direction: Direction::Out,
            laddr: "192.168.0.10".into(),
            lport: 50000,
            raddr: raddr.into(),
            rport: 443,
        },
    )
}

fn start(ts: i64, pid: u32, create: i64) -> Event {
    Event::new(
        ts,
        "etw",
        EventKind::ProcessStart {
            pid,
            ppid: 19264,
            image: CHROME.into(),
            create_time: Some(create),
        },
    )
}

fn procs_of(store: &Store, pid: u32) -> Vec<(String, String)> {
    let mut st = store
        .conn()
        .prepare("SELECT key, label FROM nodes WHERE kind = 'process' AND key LIKE ?1")
        .unwrap();
    st.query_map([format!("{pid}@%")], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|x| x.unwrap())
        .collect()
}

#[test]
fn late_process_start_adopts_unresolved_node() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest(&connect(T0 + 4 * S, 16720, "142.251.153.119"))
        .unwrap();
    ing.ingest(&start(T0 + 5 * S, 16720, T0)).unwrap();
    let ps = procs_of(&store, 16720);
    assert_eq!(
        ps,
        vec![(format!("16720@{T0}"), "chrome.exe".to_string())],
        "노드 하나, 이름 chrome.exe"
    );
    // 먼저 붙은 접속 선이 이 프로세스에 그대로 남는다
    let id = store
        .find_node(NodeKind::Process, &format!("16720@{T0}"))
        .unwrap()
        .unwrap();
    let n: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE src = ?1 AND rel = 'connected'",
            [id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let any: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE src = ?1 OR dst = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        any >= 2,
        "접속 선 + 실행 파일 선이 있어야 함 (connected={n}, 전체={any})"
    );
    let img: Option<String> = store
        .conn()
        .query_row(
            "SELECT json_extract(attrs_json, '$.image') FROM nodes WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(img.as_deref(), Some(CHROME));
}

#[test]
fn old_unresolved_node_of_reused_pid_is_not_adopted() {
    // 같은 PID 를 쓰던 예전 프로세스(새 프로세스 생성보다 먼저 본 것)는 넘겨받지 않는다
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest(&connect(T0 - 60 * S, 16720, "203.0.113.9"))
        .unwrap();
    ing.ingest(&start(T0 + 1 * S, 16720, T0)).unwrap();
    let ps = procs_of(&store, 16720);
    assert_eq!(ps.len(), 2, "{ps:?}");
    assert!(ps
        .iter()
        .any(|(_, l)| l.starts_with("알 수 없는 프로그램(PID 16720)")));
    assert!(ps.iter().any(|(_, l)| l == "chrome.exe"));
}

#[test]
fn unresolved_node_long_after_start_is_not_adopted() {
    // 생성 뒤 30초가 넘어 처음 본 이름 모름 노드는 다른 프로세스일 수 있어 넘겨받지 않는다(보수적)
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest(&connect(T0 + 40 * S, 16720, "203.0.113.9"))
        .unwrap();
    ing.ingest(&start(T0 + 41 * S, 16720, T0)).unwrap();
    assert_eq!(procs_of(&store, 16720).len(), 2);
}
