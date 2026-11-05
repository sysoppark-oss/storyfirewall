//! (바) judge 결과 → 문장. 금지어 없음, 모든 근거 문장에 선 id, 세 화법.

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

#[test]
fn payload_story_in_three_voices() {
    let store = Store::open_in_memory().unwrap();
    let payload = r"C:\Users\pjg\AppData\Local\Temp\payload.exe";
    let word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
    let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    {
        let mut ing = Ingester::new(&store);
        ing.ingest_all(&[
            ev(
                T0,
                "snapshot",
                EventKind::ProcessSnapshot {
                    pid: 1000,
                    ppid: 4,
                    image: r"C:\Windows\explorer.exe".into(),
                    create_time: T0,
                    services: vec![],
                },
            ),
            ev(
                T0 + SEC,
                "etw:file",
                EventKind::FileWrite {
                    proc: ProcRef::new(1000, None),
                    path: payload.into(),
                },
            ),
            ev(
                T0 + SEC,
                "motw",
                EventKind::Downloaded {
                    path: payload.into(),
                    host_url: Some("https://evil.example/p".into()),
                    referrer_url: None,
                    zone_id: Some(3),
                },
            ),
            ev(
                T0 + 2 * SEC,
                "signature",
                EventKind::Signature {
                    path: payload.into(),
                    signer: None,
                    issuer: None,
                    status: "untrusted:bad_digest".into(),
                    catalog: false,
                },
            ),
            ev(
                T0 + 3 * SEC,
                "etw:process",
                EventKind::ProcessStart {
                    pid: 2200,
                    ppid: 1000,
                    image: payload.into(),
                    create_time: Some(T0 + 3 * SEC),
                },
            ),
            ev(
                T0 + 4 * SEC,
                "autorun",
                EventKind::AutorunRegistered {
                    proc: ProcRef::new(2200, None),
                    location: "HKCU\\...\\Run\\x".into(),
                    target: payload.into(),
                },
            ),
            ev(
                T0 + 5 * SEC,
                "etw:dns",
                EventKind::DnsQuery {
                    proc: ProcRef::new(2200, None),
                    name: "c2.evil.example".into(),
                    results: vec!["203.0.113.9".into()],
                },
            ),
            ev(
                T0 + 6 * SEC,
                "etw:network",
                EventKind::Connect {
                    proc: ProcRef::new(2200, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "10.0.0.2".into(),
                    lport: 50000,
                    raddr: "203.0.113.9".into(),
                    rport: 8443,
                },
            ),
            // (라) WINWORD → powershell → 외부
            ev(
                T0 + 7 * SEC,
                "etw:process",
                EventKind::ProcessStart {
                    pid: 5000,
                    ppid: 1000,
                    image: word.into(),
                    create_time: Some(T0 + 7 * SEC),
                },
            ),
            ev(
                T0 + 7 * SEC,
                "signature",
                EventKind::Signature {
                    path: word.into(),
                    signer: Some("Microsoft Corporation".into()),
                    issuer: None,
                    status: "valid".into(),
                    catalog: false,
                },
            ),
            ev(
                T0 + 8 * SEC,
                "etw:process",
                EventKind::ProcessStart {
                    pid: 5100,
                    ppid: 5000,
                    image: ps.into(),
                    create_time: Some(T0 + 8 * SEC),
                },
            ),
            ev(
                T0 + 8 * SEC,
                "signature",
                EventKind::Signature {
                    path: ps.into(),
                    signer: Some("Microsoft Windows".into()),
                    issuer: None,
                    status: "valid".into(),
                    catalog: true,
                },
            ),
            ev(
                T0 + 9 * SEC,
                "etw:network",
                EventKind::Connect {
                    proc: ProcRef::new(5100, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "10.0.0.2".into(),
                    lport: 50001,
                    raddr: "203.0.113.50".into(),
                    rport: 443,
                },
            ),
        ])
        .unwrap();
    }
    let bl = Baseline::open(&store, T0).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(stories.len(), 2, "{stories:#?}");

    for voice in [Voice::Plain, Voice::Expert, Voice::OneLine] {
        let n = story::narrate(&store, &stories, voice).unwrap();
        assert_eq!(n.len(), 2);
        for nar in &n {
            for w in FORBIDDEN {
                assert!(!nar.title.contains(w), "금지어 {w}: {}", nar.title);
                for s in &nar.sentences {
                    assert!(!s.text.contains(w), "금지어 {w}: {}", s.text);
                }
            }
            if voice == Voice::OneLine {
                assert!(nar.sentences.is_empty());
            }
        }
    }

    let plain = story::narrate(&store, &stories, Voice::Plain).unwrap();
    let p = plain
        .iter()
        .find(|n| n.title.contains("payload.exe"))
        .unwrap();
    assert_eq!(p.level, Level::Suspicious);
    assert!(
        p.title
            .starts_with("[의심] payload.exe — 4장 외부 접속까지 진행"),
        "{}",
        p.title
    );
    let texts: Vec<&str> = p.sentences.iter().map(|s| s.text.as_str()).collect();
    assert!(
        texts[0].contains("1장 유입 → 2장 실행 → 3장 자리잡기 → 4장 외부 접속"),
        "{}",
        texts[0]
    );
    assert!(
        !p.sentences[0].evidence.is_empty(),
        "진행 경로 문장은 근거 이벤트를 가진다"
    );
    assert!(texts
        .iter()
        .any(|t| t.contains("서명이 파일 내용과 맞지 않거나")));
    assert!(texts.iter().any(|t| t.contains("인터넷에서 받은 파일")));
    // 카드 시각(L021): 마지막 활동 시각은 첫 장 시각보다 이르지 않다
    assert!(
        p.last_ts > 0 && p.sentences.iter().all(|s| s.ts <= p.last_ts),
        "last_ts {}",
        p.last_ts
    );
    // 접점(geo): 접속지 이름 뒤에 주소 종류·등록 국가 꼬리. 시험 주소 203.0.113.x 는 문서용 대역, DB 없이도 종류는 나온다
    let scene_lines: Vec<String> = story::tell(&store, 0, i64::MAX, story::Voice::Plain)
        .unwrap()
        .into_iter()
        .map(|s| s.text)
        .collect();
    assert!(
        scene_lines
            .iter()
            .any(|t| t.contains("→ 접속 c2.evil.example (문서용 주소)")),
        "{scene_lines:#?}"
    );
    assert!(texts
        .iter()
        .any(|t| t.contains("자동 실행에 등록된 파일에 서명이 없습니다")));
    // 자리잡기 근거 문장은 registered 선을 가리킨다
    let persist = p
        .sentences
        .iter()
        .find(|s| s.text.contains("자동 실행"))
        .unwrap();
    assert_eq!(persist.edge_ids.len(), 1);
    assert!(!persist.evidence.is_empty());
    assert!(
        !texts.iter().any(|t| t.contains("어떻게 들어왔는지")),
        "유입이 확인된 사건"
    );

    let w = plain
        .iter()
        .find(|n| n.title.contains("powershell.exe"))
        .unwrap();
    let wt: Vec<&str> = w.sentences.iter().map(|s| s.text.as_str()).collect();
    assert!(
        wt.iter()
            .any(|t| t.contains("어떻게 들어왔는지 확인되지 않음")),
        "{wt:?}"
    );
    assert!(
        wt.iter().any(|t| t.contains("문서를 다루는 프로그램")),
        "{wt:?}"
    );
    assert!(wt[0].contains("2장 실행 → 4장 외부 접속"), "{}", wt[0]);
    let doc = w
        .sentences
        .iter()
        .find(|s| s.text.contains("문서를 다루는"))
        .unwrap();
    assert_eq!(
        doc.edge_ids.len(),
        1,
        "WINWORD→powershell spawned 선이 근거"
    );

    let expert = story::narrate(&store, &stories, Voice::Expert).unwrap();
    let pe = expert
        .iter()
        .find(|n| n.title.contains("payload.exe"))
        .unwrap();
    assert!(pe.title.contains("점수 100"), "{}", pe.title);
    assert!(
        pe.sentences.iter().any(|s| s.text.ends_with("(+25)")),
        "{:?}",
        pe.sentences.iter().map(|s| &s.text).collect::<Vec<_>>()
    );
}

#[test]
fn preexisting_process_card_uses_observation_time() {
    // L024: 수개월 절전·재개만 한 PC — 4월에 시작해 계속 살아 있는 프로세스. 카드 시각은 관측(수집 시작) 뒤여야 하고,
    // 시작 시각은 running_since 로 따로 준다
    let store = Store::open_in_memory().unwrap();
    let day = 864_000_000_000i64;
    let old = T0 - 200 * day;
    let payload = r"C:\Users\pjg\AppData\Local\Temp\payload.exe";
    {
        let mut ing = Ingester::new(&store);
        ing.ingest_all(&[
            ev(
                T0,
                "snapshot",
                EventKind::ProcessSnapshot {
                    pid: 2200,
                    ppid: 4,
                    image: payload.into(),
                    create_time: old,
                    services: vec![],
                },
            ),
            ev(
                T0,
                "signature",
                EventKind::Signature {
                    path: payload.into(),
                    signer: None,
                    issuer: None,
                    status: "untrusted:bad_digest".into(),
                    catalog: false,
                },
            ),
            ev(
                T0 + 10 * SEC,
                "etw:net",
                EventKind::Connect {
                    proc: ProcRef::new(2200, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "10.0.0.2".into(),
                    lport: 50001,
                    raddr: "93.184.216.34".into(),
                    rport: 443,
                },
            ),
        ])
        .unwrap();
    }
    let bl = Baseline::open(&store, T0).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let n = story::narrate(&store, &stories, Voice::Plain).unwrap();
    let p = n
        .iter()
        .find(|n| n.title.contains("payload.exe"))
        .unwrap_or_else(|| panic!("{stories:#?}"));
    assert!(
        p.last_ts >= T0,
        "카드 시각이 관측 뒤: {} < {}",
        p.last_ts,
        T0
    );
    assert_eq!(p.running_since, Some(old));
    // D004: 관측 1분 안의 접속뿐이면 "오늘 새 활동 없음", 시작 경위·확인 방법 항목
    assert!(!p.fresh, "관측 직후 접속은 새 활동이 아님");
    let labels: Vec<&str> = p.items.iter().map(|i| i.label).collect();
    assert!(
        labels.contains(&"시작 경위") && !labels.contains(&"출신"),
        "{labels:?}"
    );
    assert_eq!(
        labels.contains(&"확인 방법"),
        p.score >= 40,
        "점수 {} {labels:?}",
        p.score
    );
    for it in &p.items {
        assert!(
            !it.value.contains("출처 불명") && !it.value.contains("침입"),
            "{}",
            it.value
        );
    }
    // 2분 뒤 새 접속이 생기면 오늘 새 활동
    Ingester::new(&store)
        .ingest(&ev(
            T0 + 120 * SEC,
            "etw:net",
            EventKind::Connect {
                proc: ProcRef::new(2200, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50002,
                raddr: "93.184.216.35".into(),
                rport: 443,
            },
        ))
        .unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let n = story::narrate(&store, &stories, Voice::Plain).unwrap();
    let p = n.iter().find(|n| n.title.contains("payload.exe")).unwrap();
    assert!(p.fresh);
}

#[test]
fn process_started_just_before_snapshot_is_not_marked_preexisting() {
    // L025: 수집 시작과 같은 초에 시작된 짧은 프로세스는 "수집 시작 전부터 실행 중"으로 표시하지 않는다
    let store = Store::open_in_memory().unwrap();
    let payload = r"C:\Users\pjg\AppData\Local\Temp\payload.exe";
    {
        let mut ing = Ingester::new(&store);
        ing.ingest_all(&[
            ev(
                T0,
                "motw",
                EventKind::Downloaded {
                    path: payload.into(),
                    host_url: Some("https://evil.example/p".into()),
                    referrer_url: None,
                    zone_id: Some(3),
                },
            ),
            ev(
                T0,
                "signature",
                EventKind::Signature {
                    path: payload.into(),
                    signer: None,
                    issuer: None,
                    status: "untrusted:bad_digest".into(),
                    catalog: false,
                },
            ),
            ev(
                T0,
                "snapshot",
                EventKind::ProcessSnapshot {
                    pid: 2200,
                    ppid: 4,
                    image: payload.into(),
                    create_time: T0 - SEC / 2,
                    services: vec![],
                },
            ),
            ev(
                T0 + 10 * SEC,
                "etw:net",
                EventKind::Connect {
                    proc: ProcRef::new(2200, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "10.0.0.2".into(),
                    lport: 50001,
                    raddr: "203.0.113.50".into(),
                    rport: 443,
                },
            ),
        ])
        .unwrap();
    }
    let bl = Baseline::open(&store, T0).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let n = story::narrate(&store, &stories, Voice::Plain).unwrap();
    let p = n
        .iter()
        .find(|n| n.title.contains("payload.exe"))
        .expect("payload 사건");
    assert_eq!(p.running_since, None);
}

#[test]
fn process_started_in_no_record_gap_is_flagged_and_not_folded() {
    // 25차 Q1(가): 서비스를 멈추고(마지막 살아 있음 표시) 악성 프로세스를 띄운 뒤 다시 켜면 그 프로세스는 스냅샷 출신이 된다.
    // 시작 시각이 "기록 없는 구간" 안이면 그 구간을 알리고, 관측 직후 새 활동이 없어도 접힌 묶음으로 내리지 않는다
    let store = Store::open_in_memory().unwrap();
    let stop = T0 - 600 * SEC;
    assert_eq!(
        graph::views::heartbeat(&store, stop).unwrap(),
        None,
        "처음 표시는 구간 없음"
    );
    let g = graph::views::heartbeat(&store, T0)
        .unwrap()
        .expect("10분 벌어짐 → 기록 없는 구간");
    assert_eq!(
        (g.from_ts, g.to_ts, g.reason.as_str()),
        (stop, T0, "no_record")
    );
    assert_eq!(
        graph::views::heartbeat(&store, T0 + 30 * SEC).unwrap(),
        None,
        "30초 간격은 구간 아님"
    );
    let payload = r"C:\Users\pjg\AppData\Local\Temp\payload.exe";
    {
        let mut ing = Ingester::new(&store);
        ing.ingest_all(&[
            ev(
                T0,
                "snapshot",
                EventKind::ProcessSnapshot {
                    pid: 2200,
                    ppid: 4,
                    image: payload.into(),
                    create_time: T0 - 300 * SEC,
                    services: vec![],
                },
            ),
            ev(
                T0,
                "signature",
                EventKind::Signature {
                    path: payload.into(),
                    signer: None,
                    issuer: None,
                    status: "untrusted:bad_digest".into(),
                    catalog: false,
                },
            ),
            ev(
                T0 + 10 * SEC,
                "etw:net",
                EventKind::Connect {
                    proc: ProcRef::new(2200, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "10.0.0.2".into(),
                    lport: 50001,
                    raddr: "93.184.216.34".into(),
                    rport: 443,
                },
            ),
        ])
        .unwrap();
    }
    let bl = Baseline::open(&store, T0).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let n = story::narrate(&store, &stories, Voice::Plain).unwrap();
    let p = n
        .iter()
        .find(|n| n.title.contains("payload.exe"))
        .unwrap_or_else(|| panic!("{stories:#?}"));
    assert_eq!(p.started_in_gap, Some((stop, T0)));
    assert!(p.fresh, "기록 없는 구간에 시작한 것은 접지 않는다");
    let v: Vec<&str> = p
        .items
        .iter()
        .filter(|i| i.label == "시작 경위")
        .map(|i| i.value.as_str())
        .collect();
    assert!(
        v.len() == 1 && v[0].starts_with("기록 없는 구간에 시작"),
        "{v:?}"
    );

    // 구간 밖(서비스가 기록하던 중)에 시작한 프로세스는 표시하지 않는다
    let store2 = Store::open_in_memory().unwrap();
    graph::views::heartbeat(&store2, T0 - 20 * SEC).unwrap();
    graph::views::heartbeat(&store2, T0).unwrap();
    assert!(graph::views::no_record_gap_at(&store2, T0 - 300 * SEC)
        .unwrap()
        .is_none());
}

#[test]
fn no_registration_or_guess_words_in_rendered_strings() {
    // D026: 나라 꼬리에 "등록" 없음, 화면 문장 어디에도 "추정" 없음(주석 제외 — 문자열만 본다)
    for src in [
        include_str!("../src/render.rs"),
        include_str!("../src/events.rs"),
    ] {
        for l in src.lines().filter(|l| !l.trim_start().starts_with("//")) {
            let code = l.split(" //").next().unwrap_or(l);
            assert!(!code.contains("추정"), "{l}");
            // D028-1: 확신 정도("~로 보임")가 아니라 근거를 쓴다
            assert!(!code.contains("보임") && !code.contains("보입니다"), "{l}");
            // D032-1: 포트 번호만으로 용도 이름("웹 서버"·"DNS 서버")을 붙이지 않는다
            assert!(
                !code.contains("웹 서버")
                    && !code.contains("DNS 서버")
                    && !code.contains("암호화 안 된"),
                "{l}"
            );
            assert!(
                !code.contains(" 등록 ·") && !code.contains("등록 국가"),
                "{l}"
            );
        }
    }
}

/// 10판 5-9 (1): 복구 수단 삭제 명령 — 5장 이름, "복구 수단" 항목(종류 + 실제 명령, 근거 선), 오늘 한 일의 명령줄 문장, 금지어 없음
#[test]
fn recovery_inhibit_story_states_command_as_fact() {
    let store = Store::open_in_memory().unwrap();
    let explorer = r"C:\Windows\explorer.exe";
    let vss = r"C:\Windows\System32\vssadmin.exe";
    let line = "vssadmin.exe delete shadows /all /quiet";
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
        ev(
            T0 + SEC,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3100,
                ppid: 1000,
                image: vss.into(),
                create_time: Some(T0 + SEC),
            },
        ),
        ev(
            T0 + SEC,
            "signature",
            EventKind::Signature {
                path: vss.into(),
                signer: Some("Microsoft Windows".into()),
                issuer: None,
                status: "valid".into(),
                catalog: true,
            },
        ),
        ev(
            T0 + SEC,
            "etw:process",
            EventKind::ProcessCommand {
                proc: ProcRef::new(3100, Some(T0 + SEC)),
                cmdline: line.into(),
                tool: None,
            },
        ),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + 24 * 3600 * SEC).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(stories.len(), 1);
    assert_eq!(stories[0].level, Level::Suspicious);
    for voice in [Voice::Plain, Voice::Expert] {
        let n = story::narrate(&store, &stories, voice).unwrap();
        let n = &n[0];
        assert!(n.title.contains("5장 파괴 징후"), "{}", n.title);
        assert_eq!(n.reached, vec![2, 5]);
        let ex = n
            .items
            .iter()
            .find(|i| i.label == "실행한 프로그램")
            .expect("실행한 프로그램");
        assert_eq!(ex.value, "explorer.exe → 실행 vssadmin.exe");
        let it = n
            .items
            .iter()
            .find(|i| i.label == "복구 수단")
            .expect("복구 수단 항목");
        assert_eq!(it.value, "그림자 복사본 삭제");
        let d = n.destroy.as_ref().expect("destroy");
        assert_eq!(d.cmdline, line);
        assert_eq!(d.edge_id, it.edge_ids[0]);
        assert!(d.sentence.contains("그림자 복사본") && d.ts > 0);
        assert_eq!(it.edge_ids.len(), 1);
        assert!(!store.evidence_of(it.edge_ids[0]).unwrap().is_empty());
        let all = format!(
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
        );
        for w in FORBIDDEN {
            assert!(!all.contains(w), "{w}: {all}");
        }
    }
    // 오늘 한 일: 명령줄 문장
    let t = story::tell(&store, 0, i64::MAX, Voice::Plain).unwrap();
    assert!(
        t.iter().any(|s| s.text.contains(&format!("명령줄: {line}"))
            || s.parts.as_ref().is_some_and(|p| p.text().contains(line))),
        "{:#?}",
        t.iter().map(|s| &s.text).collect::<Vec<_>>()
    );
}
