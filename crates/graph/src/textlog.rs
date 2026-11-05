//! PoC 1-b 텍스트 로그 → Event 변환
//!
//! 제품에서는 ETW 콜백이 Event 를 직접 만든다. 이 모듈은 개발·테스트 단계에서
//! 러너가 남긴 run.out 을 그래프에 넣기 위한 어댑터다.

use crate::event::{Direction, Event, EventKind, ProcRef, Proto};

/// 한 줄을 Event 로. 알 수 없는 줄은 None.
pub fn parse_line(line: &str) -> Option<Event> {
    // "results=" 값에는 공백이 있을 수 있어(예: "type: 5 host;1.2.3.4;") 마지막 필드로 따로 떼어 낸다
    let (head, results_tail) = match line.split_once(" results=") {
        Some((h, t)) => (h, Some(t)),
        None => (line, None),
    };
    let mut it = head.split_whitespace();
    let kind = it.next()?;
    let mut kv: std::collections::HashMap<&str, &str> =
        it.filter_map(|t| t.split_once('=')).collect();
    if let Some(t) = results_tail {
        kv.insert("results", t);
    }
    let ts: i64 = kv.get("ts")?.parse().ok()?;
    let pid = |k: &str| kv.get(k).and_then(|v| v.parse::<u32>().ok());
    match kind {
        "PROC_START" => Some(Event::new(
            ts,
            "etw:process",
            EventKind::ProcessStart {
                pid: pid("pid")?,
                ppid: pid("ppid")?,
                image: kv.get("image")?.to_string(),
                create_time: None,
            },
        )),
        "PROC_STOP" => Some(Event::new(
            ts,
            "etw:process",
            EventKind::ProcessStop { pid: pid("pid")? },
        )),
        "DNS" => {
            let results = kv
                .get("results")
                .map(|r| {
                    r.split(';')
                        .filter(|s| !s.is_empty() && !s.starts_with("type:") && *s != "-")
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();
            Some(Event::new(
                ts,
                "etw:dns",
                EventKind::DnsQuery {
                    proc: ProcRef::new(pid("pid")?, None),
                    name: kv.get("name")?.to_string(),
                    results,
                },
            ))
        }
        "TCP_CONNECT" | "UDP_SEND" | "TCP_ACCEPT" => Some(Event::new(
            ts,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(pid("pid")?, None),
                proto: if kind == "UDP_SEND" {
                    Proto::Udp
                } else {
                    Proto::Tcp
                },
                direction: if kind == "TCP_ACCEPT" {
                    Direction::In
                } else {
                    Direction::Out
                },
                laddr: kv.get("saddr")?.to_string(),
                lport: kv.get("sport")?.parse().ok()?,
                raddr: kv.get("daddr")?.to_string(),
                rport: kv.get("dport")?.parse().ok()?,
            },
        )),
        _ => None,
    }
}

/// 여러 줄을 시각 순으로 정렬된 Event 목록으로
pub fn parse_text(text: &str) -> Vec<Event> {
    let mut evs: Vec<Event> = text.lines().filter_map(parse_line).collect();
    evs.sort_by_key(|e| e.ts);
    evs
}

/// PoC 1-b run-2 고정 데이터 (테스트·예제용)
pub const POC1B_RUN2: &str = include_str!("../tests/fixtures/poc1b-run2.out");
