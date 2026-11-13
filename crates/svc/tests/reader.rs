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

/// 50차 1단계: 문(Gate)으로 직접 넘긴 조회는 작업자가 답하고, 줄이 가득 차면 넘기지 않으며, 닫힌 문은 엔진으로 돌려보낸다
#[test]
fn gate_submits_directly_and_bounds_queue() {
    use svc::reads::{Direct, Gate, MAX_PENDING_READS};
    let job = |reply: mpsc::Sender<api::Response>| ReadJob {
        id: api::rpc::Id::Num(7),
        method: api::Method::ConnectionsList,
        params: serde_json::json!({ "since_secs": 300 }),
        caller: caller(),
        now: NOW,
        reply,
        enqueued: std::time::Instant::now(),
    };
    // 닫힌 문(작업자 없음) → 엔진으로
    let gate = Gate::default();
    let (rtx, _rrx) = mpsc::channel();
    assert!(matches!(gate.submit(job(rtx)), Direct::Closed(_)));

    // 작업자 없이 채널만 연 문: 아무도 꺼내지 않으므로 상한까지만 받는다
    let (tx, rx) = mpsc::channel::<ReadJob>();
    gate.open(tx, NOW);
    assert_eq!(gate.now(), NOW);
    let (rtx, _rrx) = mpsc::channel();
    for _ in 0..MAX_PENDING_READS {
        assert!(matches!(gate.submit(job(rtx.clone())), Direct::Sent));
    }
    assert!(matches!(gate.submit(job(rtx.clone())), Direct::Full(_)));
    // 강제 모드면 줄이 비어도 엔진으로
    gate.set_forced();
    assert!(matches!(gate.submit(job(rtx.clone())), Direct::Closed(_)));
    // 작업자가 죽으면(수신 쪽 닫힘) 문이 닫힌다
    let gate2 = Gate::default();
    let (tx2, rx2) = mpsc::channel::<ReadJob>();
    gate2.open(tx2, NOW);
    drop(rx2);
    assert!(matches!(gate2.submit(job(rtx.clone())), Direct::Closed(_)));
    assert!(matches!(gate2.submit(job(rtx)), Direct::Closed(_)));
    drop(rx);
}

/// 50차 1단계: 엔진 채널을 아무도 읽지 않아도(엔진이 판정에 묶인 상황) handler 가 작업자에게 직접 넘겨 답한다
#[test]
fn handler_answers_heavy_reads_while_engine_is_stuck() {
    use svc::handler::{Authn, Read, Transport};
    struct T(mpsc::Receiver<String>, mpsc::Sender<String>);
    impl Transport for T {
        fn read_line(&mut self, timeout: Duration) -> Read {
            match self.0.recv_timeout(timeout) {
                Ok(l) => Read::Line(l),
                Err(mpsc::RecvTimeoutError::Timeout) => Read::Timeout,
                Err(_) => Read::Closed,
            }
        }
        fn write_line(&mut self, line: &str) -> bool {
            self.1.send(line.to_string()).is_ok()
        }
        fn client_pid(&self) -> u32 {
            1
        }
    }
    struct A;
    impl Authn for A {
        fn client_image(&self, _: u32) -> Option<String> {
            Some("ui.exe".into())
        }
        fn signature_ok(&self, _: u32) -> bool {
            true
        }
        fn is_admin(&self, _: u32) -> bool {
            false
        }
    }
    let dir = std::env::temp_dir().join(format!("sf-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let w = Store::open(dir.join("graph.db")).unwrap();
    Ingester::new(&w)
        .ingest_all(&svc::demo::demo_events(svc::runtime::unix_to_filetime(NOW)))
        .unwrap();
    let gate = reads::Gate::default();
    let rd = reads::spawn_counted(&w.path(), Arc::new(AtomicU64::new(0)), &gate).expect("작업자");
    gate.open(rd, NOW);
    // 엔진: 채널만 있고 아무도 읽지 않는다
    let (etx, _erx) = mpsc::channel::<svc::runtime::Command>();
    let (c2s, c2s_rx) = mpsc::channel::<String>();
    let (s2c, s2c_rx) = mpsc::channel::<String>();
    let g2 = gate.clone();
    std::thread::spawn(move || {
        let mut t = T(c2s_rx, s2c);
        svc::handler::serve_direct(1, &mut t, &A, &etx, &g2);
    });
    let mut call = |id: i64, m: &str, p: serde_json::Value| {
        c2s.send(serde_json::to_string(&api::Request::new(id, m, p)).unwrap())
            .unwrap();
        let l = s2c_rx.recv_timeout(Duration::from_secs(4)).expect("응답");
        serde_json::from_str::<serde_json::Value>(l.trim_end()).unwrap()
    };
    let h = call(
        1,
        "rpc.hello",
        serde_json::json!({ "api": api::API_VERSION, "client_version": "test" }),
    );
    assert!(h.get("error").is_none(), "{h}");
    let c = call(
        2,
        "connections.list",
        serde_json::json!({ "since_secs": 604800 }),
    );
    assert!(
        !c["result"]["items"].as_array().unwrap().is_empty(),
        "엔진 없이도 연결 목록이 와야 한다: {c}"
    );
    let s = call(3, "story.today", serde_json::json!({}));
    assert!(s["result"]["sentences"].is_array(), "{s}");
    // 작업자 길의 처리 시간이 문에 남는다(진단 표에 합쳐 나간다)
    let names: Vec<&str> = gate.stats().iter().map(|(k, _)| *k).collect();
    for want in [
        "작업자: story.today",
        "작업자: connections.list",
        "작업자: (대기열)",
    ] {
        assert!(names.contains(&want), "{want} 없음: {names:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dec_saturating_stops_at_zero() {
    let n = std::sync::atomic::AtomicUsize::new(1);
    svc::runtime::dec_saturating(&n);
    svc::runtime::dec_saturating(&n);
    assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// 시연 프로세스에 세션을 붙이면 그 세션의 일반 사용자에게 보이고, 붙이지 않으면 보이지 않는다(A27 실제 화면 시험의 전제)
#[test]
fn demo_with_session_is_visible_to_that_session() {
    use svc::dispatch::Scope;
    let now_ft = svc::runtime::unix_to_filetime(NOW);
    let count = |evs: Vec<graph::event::Event>, me: u32| {
        let g = Store::open_in_memory().unwrap();
        Ingester::new(&g).ingest_all(&evs).unwrap();
        let ids: Vec<i64> = g
            .conn()
            .prepare("SELECT id FROM nodes WHERE kind = 'process'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();
        assert!(!ids.is_empty());
        (
            ids.iter()
                .filter(|id| Scope::Session(me).process_visible(&g, **id))
                .count(),
            ids.len(),
        )
    };
    let (seen, _) = count(svc::demo::demo_events(now_ft), 2);
    assert_eq!(
        seen, 0,
        "세션 없는 시연 프로세스는 일반 사용자에게 안 보인다"
    );
    let (seen, started) = count(
        svc::demo::with_session(svc::demo::demo_events(now_ft), 2),
        2,
    );
    assert!(
        seen > 0 && seen * 2 >= started,
        "세션을 붙인 시연 프로세스가 보여야 한다: {seen}/{started}"
    );
    let (other, _) = count(
        svc::demo::with_session(svc::demo::demo_events(now_ft), 2),
        3,
    );
    assert_eq!(other, 0, "다른 세션에는 안 보인다");
}

/// 50차 2단계 시험 준비: 파일 DB 에 시연 기록을 넣고 증분 판정으로 사건과 판정 그래프를 얻는다
fn judged_db(
    tag: &str,
    events: Vec<graph::event::Event>,
) -> (
    std::path::PathBuf,
    Store,
    judge::Incremental,
    Arc<Vec<judge::Story>>,
) {
    let dir = std::env::temp_dir().join(format!("sf-snap-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let w = Store::open(dir.join("graph.db")).unwrap();
    Ingester::new(&w).ingest_all(&events).unwrap();
    let now_ft = svc::runtime::unix_to_filetime(NOW);
    let base = judge::Baseline::open(&w, now_ft).unwrap();
    let mut inc = judge::Incremental::new();
    let (stories, _) = inc.run(&w, 0, i64::MAX, &base).unwrap();
    assert!(!stories.is_empty(), "시연 기록에서 사건이 나와야 한다");
    (dir, w, inc, Arc::new(stories))
}

fn user(session: u32) -> Caller {
    Caller {
        pid: 1,
        image: "ui.exe".into(),
        is_admin: false,
        session: Some(session),
    }
}

fn events_via_reader(
    gate: &reads::Gate,
    tx: &mpsc::Sender<ReadJob>,
    caller: Caller,
    params: serde_json::Value,
) -> serde_json::Value {
    let _ = gate;
    let (rtx, rrx) = mpsc::channel();
    tx.send(ReadJob {
        id: api::rpc::Id::Num(9),
        method: api::Method::StoryEvents,
        params,
        caller,
        now: NOW,
        reply: rtx,
        enqueued: std::time::Instant::now(),
    })
    .unwrap();
    serde_json::to_value(
        rrx.recv_timeout(Duration::from_secs(10))
            .expect("작업자 응답"),
    )
    .unwrap()
}

/// 50차 2단계: 작업자의 story.events 가 같은 스냅숏으로 기록자 연결에서 직접 부른 것과 같고,
/// 스냅숏이 없으면(첫 판정 전) busy, 구간 지정(since_ts ≠ 0)은 작업자 몫이 아니다
#[test]
fn reader_story_events_matches_direct_and_needs_snapshot() {
    let now_ft = svc::runtime::unix_to_filetime(NOW);
    let (dir, w, inc, stories) = judged_db(
        "same",
        svc::demo::with_session(svc::demo::demo_events(now_ft), 2),
    );
    let gate = reads::Gate::default();
    let tx = reads::spawn_counted(&w.path(), Arc::new(AtomicU64::new(0)), &gate).expect("작업자");
    let p =
        serde_json::json!({ "level_min": "normal", "triage": "all", "cursor": { "limit": 50 } });

    // 첫 판정 전: busy(-32004)
    let r = events_via_reader(&gate, &tx, caller(), p.clone());
    assert_eq!(r["error"]["code"], serde_json::json!(-32004), "{r}");

    let snap = svc::events::StorySnap::build(1, NOW, stories.clone(), inc.view(), None);
    gate.publish(Arc::new(snap));
    for c in [caller(), user(2), user(3)] {
        let via = events_via_reader(&gate, &tx, c.clone(), p.clone());
        let snap = gate.snapshot().unwrap();
        let mut tl = Vec::new();
        let (direct, _) = svc::events::story_events(
            &w,
            Some(&snap),
            &gate.narr_cache(),
            NOW,
            p.clone(),
            &c,
            &mut tl,
        )
        .unwrap();
        assert_eq!(
            via["result"], direct,
            "작업자와 직접 호출이 달라짐({:?})",
            c.session
        );
    }
    // 관리자는 다 보고, 세션 2 사용자도 자기 시연 사건을 보며, 세션 3 사용자에게는 세션 2 프로세스 사건이 안 보인다
    let n = |c: Caller| {
        events_via_reader(&gate, &tx, c, p.clone())["result"]["items"]
            .as_array()
            .map_or(0, |a| a.len())
    };
    let (all, mine, other) = (n(caller()), n(user(2)), n(user(3)));
    assert!(all > 0 && mine > 0, "all={all} mine={mine}");
    assert!(
        other < mine,
        "다른 세션 사건이 보임: other={other} mine={mine}"
    );

    // 구간 지정은 엔진 몫 — 작업자가 받으면 오류(handler 는 애초에 넘기지 않는다)
    assert!(!reads::is_heavy_read(
        api::Method::StoryEvents,
        &serde_json::json!({ "since_ts": 5 })
    ));
    assert!(reads::is_heavy_read(
        api::Method::StoryEvents,
        &serde_json::json!({})
    ));
    assert!(reads::is_heavy_read(
        api::Method::StoryEvents,
        &serde_json::json!({ "since_ts": 0 })
    ));
    // 처리 시간이 작업자 이름으로 남는다
    let names: Vec<&str> = gate.stats().iter().map(|(k, _)| *k).collect();
    assert!(names.contains(&"작업자: story.events"), "{names:?}");
    assert!(
        names.contains(&"작업자: 이야기 목록: 보임 가리기"),
        "{names:?}"
    );
    drop(tx);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 49차 덧붙임·50차 Q1(보안 경계): 판정 때 세션을 몰랐던 프로세스는 스냅숏에 "보임"으로 굳지 않는다.
/// 판정 뒤 세션 기록이 다른 사용자로 들어오면, 새 판정을 기다리지 않고 그 사용자 사건은 바로 숨는다.
/// 거꾸로 자기 세션으로 들어오면 그때부터 보인다(스냅숏을 다시 만들지 않아도)
#[test]
fn stale_snapshot_with_unknown_session_never_shows_other_users_story() {
    let now_ft = svc::runtime::unix_to_filetime(NOW);
    let plain = svc::demo::demo_events(now_ft);
    let sess_only = |s: u32| -> Vec<graph::event::Event> {
        svc::demo::with_session(plain.clone(), s)
            .into_iter()
            .filter(|e| matches!(e.kind, graph::event::EventKind::ProcessSession { .. }))
            .collect()
    };
    let p =
        serde_json::json!({ "level_min": "normal", "triage": "all", "cursor": { "limit": 50 } });
    let count = |gate: &reads::Gate, tx: &mpsc::Sender<ReadJob>, c: Caller| {
        let v = events_via_reader(gate, tx, c, p.clone());
        assert!(v.get("error").is_none(), "{v}");
        v["result"]["items"].as_array().map_or(0, |a| a.len())
    };

    for (tag, late) in [("other", 3u32), ("mine", 2u32)] {
        let (dir, w, inc, stories) = judged_db(tag, plain.clone());
        let gate = reads::Gate::default();
        let tx =
            reads::spawn_counted(&w.path(), Arc::new(AtomicU64::new(0)), &gate).expect("작업자");
        // 판정 때는 세션을 모른다 → 일반 사용자에게 프로세스 사건은 안 보인다(모르면 숨김)
        gate.publish(Arc::new(svc::events::StorySnap::build(
            1,
            NOW,
            stories,
            inc.view(),
            None,
        )));
        let before = count(&gate, &tx, user(2));
        let admin = count(&gate, &tx, caller());
        assert!(
            admin > before,
            "관리자는 다 본다: admin={admin} before={before}"
        );
        // 판정 뒤에 세션 기록이 들어온다(스냅숏은 그대로)
        Ingester::new(&w).ingest_all(&sess_only(late)).unwrap();
        let after = count(&gate, &tx, user(2));
        if late == 2 {
            assert!(
                after > before,
                "자기 세션 기록이 들어오면 보여야 한다: {before} → {after}"
            );
        } else {
            assert_eq!(after, before, "다른 사용자 세션 사건이 보였다");
        }
        drop(tx);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
