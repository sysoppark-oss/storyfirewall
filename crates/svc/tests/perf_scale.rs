//! 실데이터 규모 성능 시험(CLAUDE.md: 화면 조회는 원시 사건 수십만~수백만에서 2초 이내).
//! 파일 DB(WAL) + 읽기 전용 연결로 실제 서비스와 같은 경로를 잰다.
//! 기본(작은 규모, 디버그)은 회귀 막이만. 실측: `SF_PERF_N=300000 cargo test --release -p svc --test perf_scale -- --nocapture`
//! Azure win-tests 의 perf job 이 주 1회 30만·100만으로 돌린다.
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::store::Store;
use svc::dispatch::Caller;
use svc::reads::{self, ReadState};

const T0: i64 = 133_800_000_000_000_000; // FILETIME
const SEC: i64 = 10_000_000;

fn ev(ts: i64, source: &str, kind: EventKind) -> Event {
    Event {
        ts,
        source: source.into(),
        kind,
    }
}

/// 원시 사건 n 건(초당 4건): 브라우저·svchost·셸 + 임시 폴더의 서명 없는 프로그램 20개(판정 사건)
fn fill(store: &Store, n: usize) {
    // L055: 노트북은 주기 판정이 평균 5.3초(테스트 자료 0.6초) — 의심 후보(뿌리) 수가 다르다. SF_PERF_ROOTS 로 늘려 잰다
    let roots: u32 = std::env::var("SF_PERF_ROOTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let mut v = Vec::with_capacity(50_000);
    for (pid, img) in [
        (100u32, r"C:\Program Files\Google\Chrome\chrome.exe"),
        (200, r"C:\Windows\System32\svchost.exe"),
        (300, r"C:\Program Files\Git\usr\bin\sh.exe"),
    ] {
        v.push(ev(
            T0,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid,
                ppid: 4,
                image: img.into(),
                create_time: T0 - 3600 * SEC,
                services: vec![],
            },
        ));
    }
    for k in 0..roots {
        let img = format!(r"C:\Users\u\AppData\Local\Temp\tool{k}.exe");
        v.push(ev(
            T0,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 1000 + k,
                ppid: 4,
                image: img.clone(),
                create_time: T0 - 600 * SEC,
                services: vec![],
            },
        ));
        v.push(ev(
            T0,
            "signature",
            EventKind::Signature {
                path: img,
                signer: None,
                issuer: None,
                status: "nosignature".into(),
                catalog: false,
            },
        ));
    }
    // L052(노트북 install-23: 이야기 목록 평균 3.4초·최대 5.9초): Git for Windows 의 서명 없는 sh.exe 가 8천 번 넘게 실행된 PC.
    // 파일 뿌리 이야기 하나가 executed_as 선 8천 개를 가진다 — 이야기 목록(story.events)의 문장 만들기 비용을 잰다
    let gsh = r"C:\Users\u\AppData\Local\Programs\Git\usr\bin\sh.exe".to_string();
    v.push(ev(
        T0,
        "signature",
        EventKind::Signature {
            path: gsh.clone(),
            signer: None,
            issuer: None,
            status: "nosignature".into(),
            catalog: false,
        },
    ));
    for k in 0..8_000u32 {
        v.push(ev(
            T0 + k as i64 * SEC,
            "etw:process",
            EventKind::ProcessStart {
                pid: 60_000 + k,
                ppid: 300,
                image: gsh.clone(),
                create_time: Some(T0 + k as i64 * SEC),
            },
        ));
    }
    let mut ing = Ingester::new(store);
    for i in 0..n {
        let ts = T0 + (i as i64) * SEC / 4;
        let pid = if i % 10 == 9 {
            1000 + (i as u32 / 10) % roots
        } else {
            [100u32, 100, 100, 200, 300][i % 5]
        };
        let host = i % 3000;
        let ip = format!("10.{}.{}.{}", host / 65536, (host / 256) % 256, host % 256);
        if i % 4 == 0 {
            v.push(ev(
                ts,
                "etw:dns",
                EventKind::DnsQuery {
                    proc: ProcRef::new(pid, None),
                    name: format!("h{host}.example.com"),
                    results: vec![ip],
                },
            ));
        } else {
            v.push(ev(
                ts,
                "etw:network",
                EventKind::Connect {
                    proc: ProcRef::new(pid, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "192.168.0.2".into(),
                    lport: (40000 + i % 20000) as u16,
                    raddr: ip,
                    rport: 443,
                },
            ));
        }
        if v.len() >= 50_000 {
            ing.ingest_all(&v).unwrap();
            v.clear();
        }
    }
    ing.ingest_all(&v).unwrap();
}

fn admin() -> Caller {
    Caller {
        pid: 1,
        image: "ui.exe".into(),
        is_admin: true,
        session: None,
    }
}

fn time<T>(name: &str, f: impl FnOnce() -> T) -> (T, u128) {
    let t = Instant::now();
    let r = f();
    let ms = t.elapsed().as_millis();
    eprintln!("PERF {name} ms={ms}");
    (r, ms)
}

#[test]
fn screen_queries_within_two_seconds() {
    let scale = std::env::var("SF_PERF_N")
        .ok()
        .and_then(|x| x.parse::<usize>().ok());
    let n = scale.unwrap_or(20_000);
    let dir = std::env::temp_dir().join(format!("sf-perf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("graph.db");
    let w = Store::open(&path).unwrap();
    time("ingest", || fill(&w, n));
    let raw: i64 = w
        .conn()
        .query_row("SELECT COUNT(*) FROM raw_events", [], |r| r.get(0))
        .unwrap();
    let edges: i64 = w
        .conn()
        .query_row("SELECT COUNT(*) FROM edges", [], |r| r.get(0))
        .unwrap();
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) / (1 << 20);
    eprintln!("PERF scale n={n} raw={raw} edges={edges} db_mb={size}");
    let now_ft = T0 + (n as i64) * SEC / 4 + 60 * SEC;
    let now = now_ft / SEC - 11_644_473_600;

    // L047(노트북: 듣는 포트 목록 5.3초): 짧게 사는 프로세스가 많은 PC(git 인증 도우미 시간당 240개 등) — 프로세스 노드 2만 개에서
    // PID 로 가장 최근 프로세스 찾기(수집 이벤트마다·듣는 포트 줄마다) 200번
    for k in 0..20_000u32 {
        w.upsert_node(
            graph::NodeKind::Process,
            &format!("{}@{}", 50_000 + k, T0 + k as i64),
            "sh.exe",
            T0 + k as i64,
            None,
        )
        .unwrap();
    }
    let (_, pid_ms) = time("latest_process_by_pid x200 (process nodes 20k)", || {
        for k in 0..200u32 {
            let _ = w.latest_process_by_pid(50_000 + k * 97, i64::MAX).unwrap();
        }
    });
    assert!(pid_ms < 100, "PID 찾기가 색인을 타지 않는다: {pid_ms}ms");

    // 주기 작업(화면 2초 대상 아님 — 기록만): 판정
    let bl = judge::Baseline::open(&w, now_ft).unwrap();
    let (stories, judge_ms) = time("judge.run(periodic)", || {
        judge::run(&w, 0, i64::MAX, &bl).unwrap()
    });
    assert!(!stories.is_empty());

    // 갈래 C: 증분 주기 판정. 첫 번은 전체, 그 뒤 1분치(초당 4건 = 240건: 접속·주소 조회 + 새 프로세스 2개)를 덧붙이고 증분.
    // 마지막 결과는 전체 판정과 같아야 한다
    let roots_n: u32 = std::env::var("SF_PERF_ROOTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let mut inc = judge::Incremental::new();
    let (_, inc_full_ms) = time("judge.incremental(first = full)", || {
        inc.run(&w, 0, i64::MAX, &bl).unwrap()
    });
    let mut inc_ms: Vec<u128> = Vec::new();
    let mut last = Vec::new();
    {
        let mut ing = Ingester::new(&w);
        for minute in 0..5i64 {
            let base = now_ft + minute * 60 * SEC;
            let mut evs: Vec<Event> = Vec::with_capacity(242);
            for k in 0..2u32 {
                let pid = 90_000 + minute as u32 * 10 + k;
                evs.push(ev(
                    base,
                    "etw:process",
                    EventKind::ProcessStart {
                        pid,
                        ppid: 100,
                        image: format!(r"C:\Users\u\AppData\Local\Temp\tool{}.exe", k),
                        create_time: Some(base),
                    },
                ));
            }
            for i in 0..240usize {
                let ts = base + (i as i64) * SEC / 4;
                let pid = if i % 10 == 9 {
                    1000 + (i as u32 / 10) % roots_n
                } else {
                    [100u32, 100, 100, 200, 300][i % 5]
                };
                let host = (i * 7 + minute as usize * 13) % 3000;
                let ip = format!("10.{}.{}.{}", host / 65536, (host / 256) % 256, host % 256);
                evs.push(if i % 4 == 0 {
                    ev(
                        ts,
                        "etw:dns",
                        EventKind::DnsQuery {
                            proc: ProcRef::new(pid, None),
                            name: format!("h{host}.example.com"),
                            results: vec![ip],
                        },
                    )
                } else {
                    ev(
                        ts,
                        "etw:network",
                        EventKind::Connect {
                            proc: ProcRef::new(pid, None),
                            proto: Proto::Tcp,
                            direction: Direction::Out,
                            laddr: "192.168.0.2".into(),
                            lport: (40000 + i % 20000) as u16,
                            raddr: ip,
                            rport: 443,
                        },
                    )
                });
            }
            ing.ingest_all(&evs).unwrap();
            let ((s, p), ms) = time("judge.incremental(+1 minute)", || {
                inc.run(&w, 0, i64::MAX, &bl).unwrap()
            });
            assert_eq!(p.mode, "incremental");
            inc_ms.push(ms);
            last = s;
        }
    }
    let full_now = judge::assess(&w, 0, i64::MAX, &bl).unwrap();
    assert_eq!(
        serde_json::to_value(&last).unwrap(),
        serde_json::to_value(&full_now).unwrap(),
        "증분 결과 ≠ 전체 판정"
    );
    let inc_avg = inc_ms.iter().sum::<u128>() / inc_ms.len() as u128;
    let inc_max = inc_ms.iter().copied().max().unwrap_or(0);
    eprintln!(
        "PERF judge periodic: full_ms={judge_ms} incremental_first_full_ms={inc_full_ms} incremental_steady_avg_ms={inc_avg} max_ms={inc_max}"
    );

    // 화면 조회: 읽기 작업자와 같은 읽기 전용 연결
    let r = Store::open_read_only(&path).unwrap();
    let mut rs = ReadState::default();
    let mut screen: Vec<(&str, u128)> = Vec::new();
    let (_, ms) = time("story.today(24h, cold)", || {
        reads::story_today(&r, &mut rs, now, serde_json::json!({}), &admin()).unwrap()
    });
    screen.push(("story.today", ms));
    for secs in [300, 86_400, 7 * 86_400] {
        let (v, ms) = time(&format!("connections.list({secs}s)"), || {
            reads::connections_list(
                &r,
                &mut rs,
                now,
                serde_json::json!({ "since_secs": secs, "cursor": { "limit": 500 } }),
                &admin(),
            )
            .unwrap()
        });
        assert!(v["items"].is_array());
        screen.push(("connections.list", ms));
    }
    // 프로그램 상세: 가장 바쁜 프로세스(chrome)
    let busy: i64 = r
        .conn()
        .query_row(
            "SELECT src FROM edges GROUP BY src ORDER BY COUNT(*) DESC LIMIT 1",
            [],
            |x| x.get(0),
        )
        .unwrap();
    let (_, ms) = time("process.detail(busiest)", || {
        graph::views::process_detail(&r, busy, 200).unwrap();
        graph::query::rewind(&r, busy, 8).unwrap()
    });
    screen.push(("process.detail", ms));
    let (_, ms) = time("collector.health gaps(24h)", || {
        graph::views::gaps_between(&r, now_ft - 86_400 * SEC, i64::MAX).unwrap()
    });
    screen.push(("gaps", ms));
    // 이야기 목록(story.events) 한 쪽: 의심 이상 사건의 문장을 캐시 없이 만든다(판정이 바뀐 직후와 같은 경우)
    eprintln!(
        "PERF stories={} scores={:?}",
        stories.len(),
        stories
            .iter()
            .map(|s| (s.score, s.root_label.clone()))
            .take(30)
            .collect::<Vec<_>>()
    );
    let sus: Vec<judge::Story> = stories
        .iter()
        .filter(|s| s.score >= 40)
        .take(21)
        .cloned()
        .collect();
    let (_, ms) = time(
        &format!("story.events narrate(cold, {} stories)", sus.len()),
        || story::narrate(&r, &sus, story::render::Voice::Plain).unwrap(),
    );
    screen.push(("story.events", ms));
    // 설치 엑스레이(installs.list 와 같은 호출): 프로세스 노드 전체를 훑는다
    let (_, ms) = time("installs.list", || {
        let roots = graph::install::installer_roots(&r, 0, 120).unwrap();
        roots
            .iter()
            .take(30)
            .map(|x| graph::install::install_xray(&r, *x, 300).unwrap())
            .count()
    });
    screen.push(("installs.list", ms));
    // 파일 뿌리의 실행 횟수 줄(dispatch 의 root_exec 질의와 같은 SQL)
    let fid: Option<i64> = r
        .conn()
        .query_row(
            "SELECT id FROM nodes WHERE kind = 'file' AND key LIKE '%Git%sh.exe'",
            [],
            |x| x.get(0),
        )
        .ok();
    if let Some(fid) = fid {
        let (_, ms) = time("story.events root_exec(file root 8k executions)", || {
            r.conn()
                .query_row(
                    "SELECT COUNT(*), MIN(ts), MAX(ts), (SELECT dst FROM edges WHERE src = ?1 AND rel = 'executed_as' ORDER BY ts DESC LIMIT 1) FROM edges WHERE src = ?1 AND rel = 'executed_as'",
                    [fid],
                    |x| Ok((x.get::<_, i64>(0)?, x.get::<_, i64>(1)?)),
                )
                .unwrap()
        });
        screen.push(("root_exec", ms));
    }
    // 조회 경로 판정(시작 직후 한 번만 — 주기 판정 결과가 생기기 전)
    let (_, assess_ms) = time("judge.assess(read path, startup only)", || {
        judge::assess(&r, 0, i64::MAX, &bl).unwrap()
    });

    // 읽기 작업자 경로 그대로(스레드·채널 포함)
    let tx = reads::spawn(&path.to_string_lossy(), Arc::new(AtomicU64::new(0))).unwrap();
    let (rtx, rrx) = std::sync::mpsc::channel();
    let (_, ms) = time("reader thread story.today(cold)", || {
        tx.send(reads::ReadJob {
            id: api::rpc::Id::Num(1),
            method: api::Method::StoryToday,
            params: serde_json::json!({}),
            caller: admin(),
            now,
            reply: rtx.clone(),
            enqueued: std::time::Instant::now(),
        })
        .unwrap();
        rrx.recv().unwrap()
    });
    screen.push(("reader story.today", ms));

    // 27차: 보관 정리(주기 작업). 이틀 뒤로 돌려 평범한 접속 선을 모두 하루 요약으로 접는다 — 첫 정리의 쓰기 잠금 시간(수집기 대기 5초와 비교)
    let (rep, ret_ms) = time("retention.apply(+4d, first run)", || {
        graph::retention::apply(
            &w,
            now_ft + 4 * 86_400 * SEC,
            graph::retention::RetentionPolicy::default(),
        )
        .unwrap()
    });
    eprintln!(
        "PERF retention compacted={} summaries={} raw_deleted={}",
        rep.edges_compacted, rep.summaries_written, rep.raw_deleted
    );
    let (_, ret2_ms) = time("retention.apply(again, steady)", || {
        graph::retention::apply(
            &w,
            now_ft + 4 * 86_400 * SEC + 3600 * SEC,
            graph::retention::RetentionPolicy::default(),
        )
        .unwrap()
    });

    let limit = if scale.is_some() { 2_000 } else { 10_000 };
    for (name, ms) in &screen {
        assert!(*ms < limit, "{name} {ms}ms >= {limit}ms (n={n})");
    }
    eprintln!("PERF summary n={n} judge_ms={judge_ms} assess_ms={assess_ms} retention_first_ms={ret_ms} retention_steady_ms={ret2_ms} screen_max_ms={}", screen.iter().map(|x| x.1).max().unwrap_or(0));
    drop(tx);
    let _ = std::fs::remove_dir_all(&dir);
}
