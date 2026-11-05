//! D004 시연 데이터: 수집 전부터 실행 중 사건 2건 — 오늘 새 활동 없음 1, 있음 1

#[test]
fn demo_has_one_stale_and_one_fresh_preexisting_story() {
    let store = graph::store::Store::open_in_memory().unwrap();
    let now = 134_000_000_000_000_000i64;
    graph::ingest::Ingester::new(&store)
        .ingest_all(&svc::demo::demo_events(now))
        .unwrap();
    let bl = judge::Baseline::open(&store, now).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let n = story::narrate(&store, &stories, story::Voice::Plain).unwrap();
    let find = |name: &str| {
        n.iter()
            .find(|x| x.title.contains(name))
            .unwrap_or_else(|| {
                panic!(
                    "{name}: {:#?}",
                    n.iter().map(|x| &x.title).collect::<Vec<_>>()
                )
            })
    };
    let up = find("updater.exe");
    let hp = find("helper.exe");
    assert!(up.running_since.is_some() && hp.running_since.is_some());
    assert!(!up.fresh, "updater: 오늘 새 활동 없음");
    assert!(hp.fresh, "helper: 오늘 새 활동 있음");
    assert!(
        up.score >= 40 && hp.score >= 40,
        "주의 이상으로 보여야 시연된다: {} {}",
        up.score,
        hp.score
    );
    // 기존 시연 사건은 그대로 '오늘'
    assert!(find("payload.exe").fresh);
}

#[test]
fn first_poll_connections_are_marked_already_open() {
    // D006-1: updater 의 수집 시작 직후(연결 테이블 첫 폴링) 접속 줄은 "이미 열려 있음", helper 의 5분 뒤 접속은 아님
    let store = graph::store::Store::open_in_memory().unwrap();
    let now = 134_000_000_000_000_000i64;
    graph::ingest::Ingester::new(&store)
        .ingest_all(&svc::demo::demo_events(now))
        .unwrap();
    let s = story::tell(&store, 0, i64::MAX, story::Voice::Plain).unwrap();
    let up: Vec<_> = s
        .iter()
        .filter(|x| x.text.starts_with("updater.exe → 접속"))
        .collect();
    assert!(
        !up.is_empty() && up.iter().all(|x| x.already_open),
        "{:?}",
        up.iter()
            .map(|x| (&x.text, x.already_open))
            .collect::<Vec<_>>()
    );
    let hp: Vec<_> = s
        .iter()
        .filter(|x| x.text.starts_with("helper.exe → 접속"))
        .collect();
    assert!(hp.iter().any(|x| !x.already_open), "helper 의 새 접속");
    assert!(s
        .iter()
        .filter(|x| x.text.starts_with("chrome.exe → 접속"))
        .all(|x| !x.already_open));
}

#[test]
fn every_filled_step_has_an_item() {
    // D023-2: 4칸 중 채운 칸(실행·자리잡기·외부 접속)마다 본문에 근거 항목이 하나는 있어야 한다
    let store = graph::store::Store::open_in_memory().unwrap();
    let now = 134_000_000_000_000_000i64;
    graph::ingest::Ingester::new(&store)
        .ingest_all(&svc::demo::demo_events(now))
        .unwrap();
    let bl = judge::Baseline::open(&store, now).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let n = story::narrate(&store, &stories, story::Voice::Plain).unwrap();
    assert!(!n.is_empty());
    for x in &n {
        let labels: Vec<&str> = x.items.iter().map(|i| i.label).collect();
        let need: &[(u8, &[&str])] = &[
            (2, &["위치", "실행", "실행한 프로그램", "시작", "시작 경위"]),
            (3, &["자동 실행"]),
            (4, &["접속"]),
        ];
        for (ch, ls) in need {
            if x.reached.contains(ch) {
                assert!(
                    labels.iter().any(|l| ls.contains(l)),
                    "{}: {}장 칸에 항목 없음 {labels:?}",
                    x.title,
                    ch
                );
            }
        }
        if x.reached.contains(&4) {
            assert!(x.egress.is_some(), "{}: 접속지", x.title);
        }
    }
}
