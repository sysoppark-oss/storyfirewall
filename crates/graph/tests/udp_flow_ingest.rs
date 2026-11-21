//! UDP 흐름(udp_flow.rs)이 Ingester 안에서 지키는 것 — 수집기에서 걸렀던 첫 구현을 별도 검수가 깨뜨린 경우들.

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::Store;

const T: i64 = 133_800_000_000_000_000;
const S: i64 = 10_000_000;

fn ev(ts: i64, source: &str, kind: EventKind) -> Event {
    Event {
        ts,
        source: source.into(),
        kind,
    }
}
fn start(ts: i64, pid: u32, image: &str) -> Event {
    ev(
        ts,
        "etw:process",
        EventKind::ProcessStart {
            pid,
            ppid: 4,
            image: image.into(),
            create_time: Some(ts),
        },
    )
}
fn send(ts: i64, pid: u32, proto: Proto, raddr: &str, rport: u16) -> Event {
    ev(
        ts,
        "etw:network",
        EventKind::Connect {
            proc: ProcRef::new(pid, None),
            proto,
            direction: Direction::Out,
            laddr: "10.0.0.2".into(),
            lport: 50000,
            raddr: raddr.into(),
            rport,
        },
    )
}
fn dns(ts: i64, pid: u32, name: &str, ip: &str) -> Event {
    ev(
        ts,
        "etw:dns",
        EventKind::DnsQuery {
            proc: ProcRef::new(pid, None),
            name: name.into(),
            results: vec![ip.into()],
        },
    )
}
fn count(st: &Store, sql: &str) -> i64 {
    st.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}
fn connected(st: &Store) -> i64 {
    count(st, "SELECT COUNT(*) FROM edges WHERE rel = 'connected'")
}

const APP: &str = r"C:\Program Files\App\app.exe";

#[test]
fn a_udp_flow_sent_every_second_makes_one_edge_and_one_raw_event() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.ingest(&start(T, 100, APP)).unwrap();
    let raw0 = count(&st, "SELECT COUNT(*) FROM raw_events");
    // 10분 동안 초당 한 번(수집기가 1초 안 반복만 거르고 보내는 모양 그대로)
    let mut made = 0;
    for s in 1..=600 {
        made += ing
            .ingest(&send(T + s * S, 100, Proto::Udp, "203.0.113.7", 41641))
            .unwrap();
    }
    assert_eq!(made, 1);
    assert_eq!(connected(&st), 1);
    // 이어지는 송신은 원시 이벤트도 남기지 않는다
    assert_eq!(count(&st, "SELECT COUNT(*) FROM raw_events") - raw0, 1);
    // TCP 는 전과 같다: 연결마다 선 하나
    for s in 601..=605 {
        ing.ingest(&send(T + s * S, 100, Proto::Tcp, "203.0.113.7", 443))
            .unwrap();
    }
    assert_eq!(connected(&st), 6);
    // 70초 쉬었다 다시 보내면 새 접속
    ing.ingest(&send(T + 700 * S, 100, Proto::Udp, "203.0.113.7", 41641))
        .unwrap();
    assert_eq!(connected(&st), 7);
}

#[test]
fn a_reused_pid_gets_its_own_first_connection() {
    // 프로세스 100 이 보내던 곳으로, 같은 번호를 물려받은 새 프로세스가 10초 뒤 보낸다 — 새 프로세스의 접속이 남아야 한다.
    // (흐름의 열쇠가 번호가 아니라 프로세스 노드라서, 시작 이벤트 순서와 무관하게 갈린다)
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.ingest(&start(T, 100, APP)).unwrap();
    ing.ingest(&send(T + S, 100, Proto::Udp, "203.0.113.7", 443))
        .unwrap();
    ing.ingest(&ev(
        T + 2 * S,
        "etw:process",
        EventKind::ProcessStop { pid: 100 },
    ))
    .unwrap();
    ing.ingest(&start(
        T + 5 * S,
        100,
        r"C:\Users\u\AppData\Local\Temp\x.exe",
    ))
    .unwrap();
    assert_eq!(
        ing.ingest(&send(T + 11 * S, 100, Proto::Udp, "203.0.113.7", 443))
            .unwrap(),
        1
    );
    assert_eq!(connected(&st), 2);
    let srcs = count(
        &st,
        "SELECT COUNT(DISTINCT src) FROM edges WHERE rel = 'connected'",
    );
    assert_eq!(srcs, 2, "두 프로세스 노드가 각각 접속 선을 가진다");
}

#[test]
fn a_second_domain_behind_the_same_address_is_a_new_connection() {
    // 공유 주소(CDN):443 로 흐름이 이어지는 동안, 같은 프로세스가 같은 주소의 **다른 이름**을 조회해 보낸다.
    // 접속 선이 다시 남아 원격지 노드의 도메인이 새 이름으로 바뀌어야 한다(수집기에서 거르면 첫 이름에 머문다)
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    ing.ingest(&start(T, 100, APP)).unwrap();
    ing.ingest(&dns(T + S, 100, "cdn.legit.example", "203.0.113.7"))
        .unwrap();
    for s in 2..=20 {
        ing.ingest(&send(T + s * S, 100, Proto::Udp, "203.0.113.7", 443))
            .unwrap();
    }
    assert_eq!(connected(&st), 1);
    ing.ingest(&dns(T + 21 * S, 100, "c2.evil.example", "203.0.113.7"))
        .unwrap();
    assert_eq!(
        ing.ingest(&send(T + 22 * S, 100, Proto::Udp, "203.0.113.7", 443))
            .unwrap(),
        1
    );
    assert_eq!(connected(&st), 2);
    let attrs: String = st
        .conn()
        .query_row(
            "SELECT attrs_json FROM nodes WHERE kind = 'remote' AND key = '203.0.113.7:443'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(attrs.contains("c2.evil.example"), "{attrs}");
    // 그 뒤 같은 이름으로 이어지는 것은 다시 한 흐름
    for s in 23..=40 {
        ing.ingest(&send(T + s * S, 100, Proto::Udp, "203.0.113.7", 443))
            .unwrap();
    }
    assert_eq!(connected(&st), 2);
}

#[test]
fn a_fresh_ingester_forgets_flows_so_nothing_is_hidden_after_a_failed_batch() {
    // 저장이 실패하면 수집 쪽은 Ingester 를 새로 만든다(되돌린 트랜잭션의 기억을 버리려고).
    // 새 Ingester 는 흐름을 모르므로 다음 송신이 다시 접속으로 남는다 — 되돌려진 선 때문에 접속이 묻히지 않는다
    let st = Store::open_in_memory().unwrap();
    {
        let mut ing = Ingester::new(&st);
        ing.ingest(&start(T, 100, APP)).unwrap();
        ing.ingest(&send(T + S, 100, Proto::Udp, "203.0.113.7", 443))
            .unwrap();
        assert_eq!(
            ing.ingest(&send(T + 2 * S, 100, Proto::Udp, "203.0.113.7", 443))
                .unwrap(),
            0
        );
    }
    let mut ing = Ingester::new(&st);
    assert_eq!(
        ing.ingest(&send(T + 3 * S, 100, Proto::Udp, "203.0.113.7", 443))
            .unwrap(),
        1
    );
}

/// 서비스(svchost)의 접속을 "직전 2초 안에 접속한 사용자 프로세스가 하나뿐이면 그 프로세스 몫"으로 본다(시간 창 귀속).
/// 이어지는 UDP 흐름의 송신은 선을 만들지 않지만 **후보로는 여전히 센다** — 귀속 결과가 흐름 묶기 전과 같아야 한다
/// (수집기에서 거르면 후보에서 빠져, 보류되던 접속이 다른 프로세스 하나에 귀속된다 — 별도 검수 지적 4)
#[test]
fn continuing_udp_sends_still_count_as_recent_user_connects() {
    let svc_map = |ts: i64| {
        ev(
            ts,
            "scm",
            EventKind::ServiceMap {
                pid: 900,
                services: vec!["CryptSvc".into()],
                system_token: Some(true),
                create_time: Some(T),
            },
        )
    };
    let via = |st: &Store| count(st, "SELECT COUNT(*) FROM edges WHERE rel = 'connected_via'");
    // (가) 사용자 프로세스 B 만 접속 → 서비스 접속이 B 에 귀속된다
    {
        let st = Store::open_in_memory().unwrap();
        let mut ing = Ingester::new(&st);
        ing.ingest(&start(T, 900, r"C:\Windows\System32\svchost.exe"))
            .unwrap();
        ing.ingest(&svc_map(T)).unwrap();
        ing.ingest(&start(T, 200, APP)).unwrap();
        ing.ingest(&send(T + 100 * S, 200, Proto::Tcp, "198.51.100.5", 443))
            .unwrap();
        ing.ingest(&send(T + 101 * S, 900, Proto::Tcp, "192.0.2.80", 80))
            .unwrap();
        assert_eq!(via(&st), 1, "후보가 하나면 귀속");
    }
    // (나) 사용자 프로세스 A 가 UDP 흐름을 이어 가는 중 → 후보가 둘이라 보류(귀속 선 없음). 흐름 묶기 전과 같은 결과
    {
        let st = Store::open_in_memory().unwrap();
        let mut ing = Ingester::new(&st);
        ing.ingest(&start(T, 900, r"C:\Windows\System32\svchost.exe"))
            .unwrap();
        ing.ingest(&svc_map(T)).unwrap();
        ing.ingest(&start(T, 100, r"C:\Program Files\Other\other.exe"))
            .unwrap();
        ing.ingest(&start(T, 200, APP)).unwrap();
        // A: 90초째부터 초당 한 번 — 첫 송신만 선이 되고 나머지는 이어짐
        for s in 90..=101 {
            ing.ingest(&send(T + s * S, 100, Proto::Udp, "203.0.113.7", 41641))
                .unwrap();
        }
        assert_eq!(connected(&st), 1);
        ing.ingest(&send(T + 100 * S, 200, Proto::Tcp, "198.51.100.5", 443))
            .unwrap();
        ing.ingest(&send(T + 101 * S + 1, 900, Proto::Tcp, "192.0.2.80", 80))
            .unwrap();
        assert_eq!(
            via(&st),
            0,
            "후보가 둘이면 보류 — 이어지는 UDP 송신도 후보다"
        );
        let attrs: String = st
            .conn()
            .query_row(
                "SELECT attrs_json FROM nodes WHERE kind = 'remote' AND key = '192.0.2.80:80'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(attrs.contains("via_ambiguous"), "{attrs}");
    }
}
