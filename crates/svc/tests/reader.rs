//! 구조 개선 C: 읽기 작업자(읽기 전용 연결)가 엔진 쪽 직접 처리와 같은 답을 내고, DB 에 쓰지 못하는지
use std::sync::atomic::AtomicU64;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use graph::ingest::Ingester;
use graph::store::Store;
use svc::dispatch::Caller;
use svc::reads::{self, ReadJob, ReadState};

const NOW: i64 = 1_793_000_000; // unix 초(2026-10 무렵)

fn caller() -> Caller {
    Caller {
        pid: 1,
        image: "ui.exe".into(),
        is_admin: true,
        session: None,
    }
}

#[test]
fn reader_matches_inline_and_cannot_write() {
    let dir = std::env::temp_dir().join(format!("sf-reader-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("graph.db");
    let w = Store::open(&path).unwrap();
    let now_ft = svc::runtime::unix_to_filetime(NOW);
    Ingester::new(&w)
        .ingest_all(&svc::demo::demo_events(now_ft))
        .unwrap();

    // 엔진 쪽 직접 처리(기록자 연결)
    let mut rs = ReadState::default();
    let p = serde_json::json!({ "since_secs": 7 * 86_400 });
    let inline = reads::connections_list(&w, &mut rs, NOW, p.clone(), &caller()).unwrap();
    let today_inline =
        reads::story_today(&w, &mut rs, NOW, serde_json::json!({}), &caller()).unwrap();
    assert!(
        !inline["items"].as_array().unwrap().is_empty(),
        "시연 연결이 있어야 한다"
    );

    // 작업자
    let gen = Arc::new(AtomicU64::new(0));
    let tx = reads::spawn(&w.path(), gen).expect("파일 DB 면 작업자가 뜬다");
    let ask = |method: api::Method, params: serde_json::Value| {
        let (rtx, rrx) = mpsc::channel();
        tx.send(ReadJob {
            id: api::rpc::Id::Num(1),
            method,
            params,
            caller: caller(),
            now: NOW,
            reply: rtx,
            enqueued: std::time::Instant::now(),
        })
        .unwrap();
        let r = rrx
            .recv_timeout(Duration::from_secs(10))
            .expect("작업자 응답");
        serde_json::to_value(&r).unwrap()["result"].clone()
    };
    assert_eq!(ask(api::Method::ConnectionsList, p), inline);
    assert_eq!(
        ask(api::Method::StoryToday, serde_json::json!({})),
        today_inline
    );

    // 27차 Gemini Q4: 대기열에서 너무 오래 기다린 요청은 처리하지 않고 busy(-32004)
    let (rtx, rrx) = mpsc::channel();
    let old = std::time::Instant::now()
        .checked_sub(Duration::from_secs(30))
        .unwrap();
    tx.send(ReadJob {
        id: api::rpc::Id::Num(2),
        method: api::Method::StoryToday,
        params: serde_json::json!({}),
        caller: caller(),
        now: NOW,
        reply: rtx,
        enqueued: old,
    })
    .unwrap();
    let r = serde_json::to_value(rrx.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
    assert_eq!(r["error"]["code"], serde_json::json!(-32004), "{r}");

    // 읽기 전용: 쓰기 시도는 실패해야 한다
    let ro = Store::open_read_only(&path).unwrap();
    assert!(
        ro.conn().execute("DELETE FROM edges", []).is_err(),
        "읽기 전용 연결이 썼다"
    );

    // 메모리 DB 는 작업자를 띄우지 않는다(엔진이 직접)
    let mem = Store::open_in_memory().unwrap();
    assert!(reads::spawn(&mem.path(), Arc::new(AtomicU64::new(0))).is_none());
    drop(tx);
    let _ = std::fs::remove_dir_all(&dir);
}
