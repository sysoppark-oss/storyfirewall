//! A1 통과 기준: run-2 로그로 "20초의 이야기"가 세 화법으로 나오고,
//! 모든 문장이 근거를 가지며, 의도 단정 금지어가 없고, CRL 조회가 curl 장면에 귀속된다.

use graph::event::{Event, EventKind};
use graph::ingest::Ingester;
use graph::textlog::{parse_text, POC1B_RUN2};
use graph::Store;
use story::render::FORBIDDEN;
use story::{tell, Voice};

fn build() -> Store {
    let store = Store::open_in_memory().unwrap();
    let events = parse_text(POC1B_RUN2);
    // 수집 시작 전부터 있던 프로세스: 시작 시 스냅샷이 채운다 (명세 4판 2-2). SCM 매핑 포함.
    let mut ing = Ingester::new(&store);
    for (pid, img, svcs) in [
        (
            880u32,
            r"C:\Windows\System32\svchost.exe",
            vec!["CryptSvc".to_string()],
        ),
        (
            1896u32,
            r"C:\Windows\System32\svchost.exe",
            vec!["Dnscache".to_string()],
        ),
        (6732u32, r"C:\Program Files\PowerShell\7\pwsh.exe", vec![]),
    ] {
        let snap = Event::new(
            events[0].ts - 10_000_000,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid,
                ppid: 4,
                image: img.into(),
                create_time: events[0].ts - 600_000_000,
                services: svcs,
            },
        );
        ing.ingest(&snap).unwrap();
    }
    ing.ingest_all(&events).unwrap();
    store
}

#[test]
fn tells_run2_in_three_voices() {
    let store = build();
    for voice in [Voice::OneLine, Voice::Plain, Voice::Expert] {
        let sents = tell(&store, 0, i64::MAX, voice).unwrap();
        assert!(!sents.is_empty(), "{voice:?}: 문장이 없음");
        eprintln!("===== {voice:?} ({}문장) =====", sents.len());
        for s in &sents {
            eprintln!("{}", s.text);
        }
        // 금지어 검사
        for s in &sents {
            for w in FORBIDDEN {
                assert!(!s.text.contains(w), "금지어 '{w}' 포함: {}", s.text);
            }
        }
    }
}

#[test]
fn every_action_sentence_has_evidence() {
    let store = build();
    let sents = tell(&store, 0, i64::MAX, Voice::Plain).unwrap();
    // 머리 문장("…을 실행했습니다")은 spawned 선의 근거를 갖지 않을 수 있으므로 행위 문장만 검사
    let action_sents: Vec<_> = sents
        .iter()
        .filter(|s| !s.text.contains("→ 실행 "))
        .collect();
    assert!(action_sents.len() > 5);
    for s in action_sents {
        assert!(!s.evidence.is_empty(), "근거 없는 문장: {}", s.text);
        assert!(!s.edge_ids.is_empty());
    }
}

#[test]
fn crl_lookup_belongs_to_curl_scene() {
    let store = build();
    let sents = tell(&store, 0, i64::MAX, Voice::Plain).unwrap();
    let curl_lines: Vec<&str> = sents
        .iter()
        .filter(|s| s.text.starts_with("curl.exe"))
        .map(|s| s.text.as_str())
        .collect();
    eprintln!("curl 문장: {curl_lines:#?}");
    assert!(curl_lines
        .iter()
        .any(|l| l.contains("→ 접속 www.rust-lang.org")));
    assert!(
        curl_lines.iter().any(|l| l.contains("x1.c.lencr.org")
            && l.contains("svchost.exe")
            && l.contains("경유")),
        "CRL 조회가 curl 장면에 서비스 경유로 나와야 함"
    );
    // D028-1: 경유 문장은 근거 이름(무엇을 대조했나)을 쓰고, 짝지은 두 이벤트의 시각 차(ms)를 함께 낸다
    let via: Vec<_> = sents.iter().filter(|s| s.text.contains("경유")).collect();
    assert!(
        via.iter()
            .all(|s| s.text.contains("대조") && !s.text.contains("보임")),
        "{:?}",
        via.iter().map(|s| &s.text).collect::<Vec<_>>()
    );
    assert!(
        via.iter().any(|s| s.via_lag_ms.is_some_and(|ms| ms >= 0)),
        "시각 차가 있어야 함"
    );
    // svchost 자신의 장면은 "대신 나간 통신만" 으로 접혀야 함
    let one = tell(&store, 0, i64::MAX, Voice::OneLine).unwrap();
    assert!(one
        .iter()
        .any(|s| s.text.starts_with("svchost.exe") && s.text.contains("대신한 통신만")));
}

#[test]
fn one_line_voice_names_parent_and_target() {
    let store = build();
    let one = tell(&store, 0, i64::MAX, Voice::OneLine).unwrap();
    let curl: Vec<&str> = one
        .iter()
        .filter(|s| s.text.contains("curl.exe"))
        .map(|s| s.text.as_str())
        .collect();
    eprintln!("{curl:#?}");
    assert!(curl
        .iter()
        .any(|l| l.starts_with("pwsh.exe → 실행 curl.exe") && l.contains("www.rust-lang.org")));
}
