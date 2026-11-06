//! 변경 장부 (17판 23-2 ③) 33차 Q1: 대리 창으로 추정해 적은 파일을 뿌리 꼬리표로 찾는다

use graph::event::{Event, EventKind, ProcRef};
use graph::ingest::Ingester;
use graph::ledger::{inferred_files, inferred_source};
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

#[test]
fn inferred_files_by_root_tag() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let start = |pid: u32, ts: i64, image: &str| {
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
    };
    let write = |pid: u32, ts: i64, path: &str, source: String| {
        ev(
            ts,
            &source,
            EventKind::FileWrite {
                proc: ProcRef::new(pid, None),
                path: path.into(),
            },
        )
    };
    ing.ingest(&start(700, T, r"C:\Windows\System32\cmd.exe"))
        .unwrap();
    ing.ingest(&write(
        700,
        T + S,
        r"C:\p\payload.exe",
        inferred_source((600, 7)),
    ))
    .unwrap();
    ing.ingest(&write(
        700,
        T + 2 * S,
        r"C:\p\junk\*",
        format!("{}:bulk:21", inferred_source((600, 7))),
    ))
    .unwrap();
    // 다른 뿌리(앞자리만 같은 6000@7)·평범한 장부 기록은 빠진다
    ing.ingest(&write(
        700,
        T + 3 * S,
        r"C:\q\other.exe",
        inferred_source((6000, 7)),
    ))
    .unwrap();
    ing.ingest(&write(
        700,
        T + 4 * S,
        r"C:\q\plain.exe",
        "etw:file:ledger".into(),
    ))
    .unwrap();
    let got = inferred_files(&st, (600, 7), T, T + 10 * S, 50).unwrap();
    let paths: Vec<&str> = got.iter().map(|g| g.0.as_str()).collect();
    assert_eq!(paths, vec![r"C:\p\payload.exe", r"C:\p\junk\*"], "{got:?}");
    // 관찰 기간 밖이면 없다
    assert!(inferred_files(&st, (600, 7), T + 20 * S, T + 30 * S, 50)
        .unwrap()
        .is_empty());
}
