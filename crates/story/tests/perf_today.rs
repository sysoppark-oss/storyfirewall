//! L030(노트북 diag): story::tell 24시간이 237초(원시 31만·선 17만·문장 3만 8천). 같은 규모 합성 데이터로 단계별 시간을 잰다.
//! 기본은 작은 규모로 상한만 확인하고, `SF_PERF_N=300000 cargo test -p story --release --test perf_today -- --nocapture` 로 실측.
use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::store::Store;
use std::time::Instant;

const T0: i64 = 133_800_000_000_000_000;
const SEC: i64 = 10_000_000;

fn ev(ts: i64, source: &str, kind: EventKind) -> Event {
    Event {
        ts,
        source: source.into(),
        kind,
    }
}

fn build(n: usize) -> Store {
    let store = Store::open_in_memory().unwrap();
    let mut v = Vec::with_capacity(n + 100);
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
    // 판정 사건이 생기게: 사용자 임시 폴더의 서명 없는 프로그램 20개(노트북 diag: 사건 18건)
    for k in 0..20u32 {
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
    for i in 0..n {
        let ts = T0 + (i as i64) * SEC / 4;
        let pid = if i % 10 == 9 {
            1000 + (i as u32 / 10) % 20
        } else {
            [100u32, 100, 100, 200, 300][i % 5]
        };
        let host = i % 3000;
        if i % 4 == 0 {
            v.push(ev(
                ts,
                "etw:dns",
                EventKind::DnsQuery {
                    proc: ProcRef::new(pid, None),
                    name: format!("h{host}.example.com"),
                    results: vec![format!(
                        "10.{}.{}.{}",
                        host / 65536,
                        (host / 256) % 256,
                        host % 256
                    )],
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
                    raddr: format!("10.{}.{}.{}", host / 65536, (host / 256) % 256, host % 256),
                    rport: 443,
                },
            ));
        }
    }
    Ingester::new(&store).ingest_all(&v).unwrap();
    store
}

#[test]
fn today_story_scales() {
    let n: usize = std::env::var("SF_PERF_N")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(20_000);
    let t = Instant::now();
    let store = build(n);
    eprintln!("build n={n} ms={}", t.elapsed().as_millis());
    let edges: i64 = store
        .conn()
        .query_row("SELECT COUNT(*) FROM edges", [], |r| r.get(0))
        .unwrap();
    let t = Instant::now();
    let f = story::facts::collect(&store, 0, i64::MAX).unwrap();
    eprintln!(
        "facts ms={} n={} edges={edges}",
        t.elapsed().as_millis(),
        f.len()
    );
    let t = Instant::now();
    let sc = story::scenes::group(&store, &f).unwrap();
    eprintln!("scenes ms={} n={}", t.elapsed().as_millis(), sc.len());
    let t = Instant::now();
    let r = story::render::render(&sc, story::Voice::Plain);
    eprintln!(
        "render ms={} sentences={}",
        t.elapsed().as_millis(),
        r.len()
    );
    let t = Instant::now();
    let all = story::tell(&store, 0, i64::MAX, story::Voice::Plain).unwrap();
    let ms = t.elapsed().as_millis();
    eprintln!("tell total ms={ms} sentences={}", all.len());
    // 회귀 막이: 기본 2만 건(디버그 빌드)은 넉넉히 10초 안. 전에는 선마다 따로 묻는 조회로 규모에 비해 크게 느려졌다
    if n <= 20_000 {
        assert!(ms < 10_000, "tell {ms}ms");
    }
}

#[test]
fn judge_scales() {
    let n: usize = std::env::var("SF_PERF_N")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(20_000);
    let store = build(n);
    let bl = judge::Baseline::open(&store, T0).unwrap();
    let t = Instant::now();
    let v = judge::View::load(&store, 0, i64::MAX).unwrap();
    eprintln!("view load ms={}", t.elapsed().as_millis());
    drop(v);
    let t = Instant::now();
    let s = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let ms = t.elapsed().as_millis();
    eprintln!("judge run ms={ms} stories={}", s.len());
    assert!(!s.is_empty(), "합성 데이터에 사건이 있어야 시험이 된다");
    // 회귀 막이: 사건마다 선 전체를 훑던 이중 반복(score.rs)이 돌아오면 여기서 걸린다
    if n <= 20_000 {
        assert!(ms < 10_000, "judge {ms}ms");
    }
}
