//! 17판 23-2 ② 브라우저 금고 경비 — 문장: 어느 브라우저의 어떤 파일을 열었는지(사실)만, 근거 선, 금지어 없음

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::store::Store;
use judge::{Baseline, Level};
use story::render::FORBIDDEN;
use story::Voice;

const T0: i64 = 133_800_000_000_000_000;
const SEC: i64 = 10_000_000;

fn ev(ts: i64, source: &str, kind: EventKind) -> Event {
    Event {
        ts,
        source: source.into(),
        kind,
    }
}
fn start(ts: i64, pid: u32, ppid: u32, image: &str) -> Event {
    ev(
        ts,
        "etw:process",
        EventKind::ProcessStart {
            pid,
            ppid,
            image: image.into(),
            create_time: Some(ts),
        },
    )
}
fn sig(ts: i64, path: &str, signer: Option<&str>, status: &str, catalog: bool) -> Event {
    ev(
        ts,
        "signature",
        EventKind::Signature {
            path: path.into(),
            signer: signer.map(|s| s.into()),
            issuer: None,
            status: status.into(),
            catalog,
        },
    )
}

fn all_text(n: &story::Narrative) -> String {
    format!(
        "{} {} {}",
        n.title,
        n.sentences
            .iter()
            .map(|s| s.text.clone())
            .collect::<Vec<_>>()
            .join(" "),
        n.items
            .iter()
            .map(|i| i.value.clone())
            .collect::<Vec<_>>()
            .join(" ")
    )
}

#[test]
fn vault_open_and_debug_launch_are_told_as_facts() {
    let store = Store::open_in_memory().unwrap();
    let explorer = r"C:\Windows\explorer.exe";
    let chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    let stealer = r"C:\Users\pjg\AppData\Local\Temp\x.exe";
    let login = r"C:\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        ev(
            T0,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 1000,
                ppid: 4,
                image: explorer.into(),
                create_time: T0,
                services: vec![],
            },
        ),
        sig(T0, explorer, Some("Microsoft Windows"), "valid", true),
        sig(T0, chrome, Some("Google LLC"), "valid", false),
        start(T0 + SEC, 8000, 1000, stealer),
        sig(T0 + SEC, stealer, None, "nosignature", false),
        ev(
            T0 + 2 * SEC,
            "etw:file:open",
            EventKind::FileOpen {
                proc: ProcRef::new(8000, None),
                path: login.into(),
            },
        ),
        start(T0 + 3 * SEC, 8100, 8000, chrome),
        ev(
            T0 + 3 * SEC,
            "etw:process",
            EventKind::ProcessCommand {
                proc: ProcRef::new(8100, Some(T0 + 3 * SEC)),
                cmdline: "chrome.exe --remote-debugging-port=9222 --headless=new".into(),
                tool: None,
            },
        ),
        ev(
            T0 + 4 * SEC,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(8000, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "127.0.0.1".into(),
                lport: 50000,
                raddr: "127.0.0.1".into(),
                rport: 9222,
            },
        ),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + 24 * 3600 * SEC).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(stories.len(), 1, "{stories:#?}");
    assert_eq!(stories[0].level, Level::Suspicious);
    for voice in [Voice::Plain, Voice::Expert] {
        let n = story::narrate(&store, &stories, voice).unwrap();
        let n = &n[0];
        let vault = n
            .sentences
            .iter()
            .find(|s| s.text.contains("Login Data"))
            .expect("금고 문장");
        assert!(
            vault.text.contains(
                "x.exe: 브라우저가 아닌 프로그램이 Chrome 의 저장된 로그인 정보 파일(Login Data)을 열었습니다."
            ),
            "{}",
            vault.text
        );
        assert_eq!(vault.edge_ids.len(), 1);
        assert!(!vault.evidence.is_empty(), "근거 원시 이벤트");
        let item = n
            .items
            .iter()
            .find(|i| i.label == "브라우저 저장소")
            .expect("항목");
        assert!(
            item.value.starts_with("Chrome · 저장된 로그인 정보"),
            "{}",
            item.value
        );
        let dbg = n
            .items
            .iter()
            .filter(|i| i.label == "브라우저 디버깅")
            .map(|i| i.value.clone())
            .collect::<Vec<_>>();
        assert!(
            dbg.iter()
                .any(|v| v == "x.exe → 실행 chrome.exe · chrome.exe --remote-debugging-port=9222 --headless=new"),
            "{dbg:?}"
        );
        assert!(
            dbg.iter().any(|v| v == "x.exe → 이 PC 안 포트 9222"),
            "{dbg:?}"
        );
        let all = all_text(n);
        for w in FORBIDDEN {
            assert!(!all.contains(w), "{w}: {all}");
        }
        // 쿠키·암호를 가져갔다는 말은 없다
        assert!(!all.contains("가져갔") && !all.contains("보냈"), "{all}");
    }
    // 오늘 한 일: 파일 열기 문장
    let t = story::tell(&store, 0, i64::MAX, Voice::Plain).unwrap();
    assert!(
        t.iter()
            .any(|s| s.text.contains("Login Data 파일을 열었습니다")
                || s.parts
                    .as_ref()
                    .is_some_and(|p| p.text().contains("Login Data"))),
        "{:#?}",
        t.iter().map(|s| &s.text).collect::<Vec<_>>()
    );
}
