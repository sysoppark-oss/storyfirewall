//! L015(노트북 실사용): 우리 UI·서비스가 시험 인증서(신뢰 체인 없음)로 서명돼 "의심 100점"이 되던 자기 자신 오탐.
//! 설치 폴더의 우리 파일은 서명 내용이 온전하면 뿌리로 삼지 않는다. 내용이 바뀐(bad_digest) 우리 파일은 그대로 잡는다.
//! (별도 시험 바이너리: set_self_dirs 는 프로세스 전역)

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::store::Store;
use judge::Baseline;

const T0: i64 = 133_800_000_000_000_000;
const SEC: i64 = 10_000_000;
const UI: &str = r"C:\Program Files\Story Firewall\story-firewall-ui.exe";
const OTHER: &str = r"C:\Users\u\AppData\Local\Temp\selfsigned.exe";

fn ev(ts: i64, source: &str, kind: EventKind) -> Event {
    Event {
        ts,
        source: source.into(),
        kind,
    }
}

fn run(ui_status: &str) -> Vec<judge::Story> {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let evs = vec![
        ev(
            T0,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3000,
                ppid: 1000,
                image: UI.into(),
                create_time: Some(T0),
            },
        ),
        ev(
            T0,
            "signature",
            EventKind::Signature {
                path: UI.into(),
                signer: Some("StoryFirewall Dev".into()),
                issuer: None,
                status: ui_status.into(),
                catalog: false,
            },
        ),
        ev(
            T0 + SEC,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(3000, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.1.0.4".into(),
                lport: 50001,
                raddr: "13.107.42.14".into(),
                rport: 443,
            },
        ),
        // 같은 성질(자체 서명, 외부 접속)이지만 우리 설치 폴더 밖 → 그대로 판정
        ev(
            T0,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3100,
                ppid: 1000,
                image: OTHER.into(),
                create_time: Some(T0),
            },
        ),
        ev(
            T0,
            "signature",
            EventKind::Signature {
                path: OTHER.into(),
                signer: Some("StoryFirewall Dev".into()),
                issuer: None,
                status: "untrusted:root".into(),
                catalog: false,
            },
        ),
        ev(
            T0 + SEC,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(3100, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.1.0.4".into(),
                lport: 50002,
                raddr: "13.107.42.15".into(),
                rport: 443,
            },
        ),
    ];
    ing.ingest_all(&evs).unwrap();
    let bl = Baseline::open(&store, T0 + SEC).unwrap();
    judge::run(&store, 0, i64::MAX, &bl).unwrap()
}

#[test]
fn own_components_are_not_roots_unless_their_content_changed() {
    judge::set_self_dirs(vec![r"C:\Program Files\Story Firewall".into()]);
    let s = run("untrusted:root");
    assert!(
        !s.iter().any(|x| x.root_label == "story-firewall-ui.exe"),
        "우리 UI 는 사건이 아님: {s:#?}"
    );
    let other = s
        .iter()
        .find(|x| x.root_label == "selfsigned.exe")
        .expect("설치 폴더 밖 자체 서명 파일은 사건");
    let whats: Vec<&str> = other.reasons.iter().map(|r| r.what).collect();
    assert!(whats.contains(&"신뢰 체인 없는 서명"), "{whats:?}");
    assert!(
        !whats.contains(&"서명 깨짐·신뢰할 수 없음"),
        "신뢰 체인 없음을 깨짐으로 말하지 않는다: {whats:?}"
    );
    // 내용이 바뀐 우리 파일(서명 뒤 수정)은 잡는다
    let t = run("untrusted:bad_digest");
    let ui = t
        .iter()
        .find(|x| x.root_label == "story-firewall-ui.exe")
        .expect("변조된 우리 파일은 사건");
    assert!(ui
        .reasons
        .iter()
        .any(|r| r.what == "서명 깨짐·신뢰할 수 없음"));
}
