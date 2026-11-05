//! PoC 1-b: ETW 수집기 검증
//!
//! 목적: Sysmon 없이 사용자 모드 ETW만으로
//!   1) 프로세스 생성·종료 (Microsoft-Windows-Kernel-Process)
//!   2) TCP/UDP 연결 시도·수락 (Microsoft-Windows-Kernel-Network)
//!   3) DNS 조회 (Microsoft-Windows-DNS-Client)
//! 를 받아, 짧은 연결도 PID에 귀속되는지 확인한다. (PoC 1에서 TIME_WAIT는 PID 0이었음)
//!
//! 통과 기준 (제품A 개발 명세 2판 5장 P1-b):
//!   러너에서 일으킨 웹 요청이 "프로세스 생성 → DNS 조회 → 연결 시도" 순서로 같은 PID에 잡힘.
//!
//! 출력 설계:
//!   - 각 (provider, event_id) 조합의 첫 이벤트는 전체 JSON을 stderr에 덤프한다.
//!     → Kernel-Network 필드명(daddr/dport 등)을 문서 대신 실측으로 확정하기 위함.
//!   - 그 뒤로는 한 줄 요약만 stdout에 찍는다.
//!
//! 실행: 관리자 권한 필요 (ETW 세션 생성). cargo run --release -- <초>

#![cfg(windows)]

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::ser::{EventSerializer, EventSerializerOptions};
use ferrisetw::trace::{TraceTrait, UserTrace};
use ferrisetw::EventRecord;

// 공급자 GUID (Velociraptor 아티팩트 문서로 확인)
const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

/// (provider 이름, event_id) 별로 첫 이벤트만 전체 덤프하기 위한 집합
static DUMPED: Mutex<Option<HashSet<(String, u16)>>> = Mutex::new(None);

fn first_time(provider: &str, id: u16) -> bool {
    let mut g = DUMPED.lock().unwrap();
    let set = g.get_or_insert_with(HashSet::new);
    set.insert((provider.to_string(), id))
}

/// 이벤트 전체를 JSON으로 stderr에 덤프 (필드명 확인용)
fn dump_full(tag: &str, record: &EventRecord, schema: &ferrisetw::schema::Schema) {
    let opts = EventSerializerOptions {
        include_schema: true,
        include_header: false,
        include_extended_data: false,
        fail_unimplemented: false,
    };
    let ser = EventSerializer::new(record, schema, opts);
    match serde_json::to_string(&ser) {
        Ok(js) => eprintln!("[schema] {tag} id={} {js}", record.event_id()),
        Err(e) => eprintln!("[schema] {tag} id={} serialize error: {e}", record.event_id()),
    }
}

/// 문자열 필드를 느슨하게 읽는다 (없으면 "-")
fn s(parser: &Parser, name: &str) -> String {
    parser.try_parse::<String>(name).unwrap_or_else(|_| "-".into())
}
fn u32f(parser: &Parser, name: &str) -> String {
    parser
        .try_parse::<u32>(name)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "-".into())
}
/// IP 필드: IpAddr 로 먼저 시도, 실패하면 u32(IPv4 네트워크 순서)로 재시도
fn ipf(parser: &Parser, name: &str) -> String {
    if let Ok(ip) = parser.try_parse::<std::net::IpAddr>(name) {
        return ip.to_string();
    }
    if let Ok(raw) = parser.try_parse::<u32>(name) {
        return std::net::Ipv4Addr::from(raw.to_ne_bytes()).to_string();
    }
    "-".into()
}

fn on_process(record: &EventRecord, locator: &SchemaLocator) {
    let id = record.event_id();
    if id != 1 && id != 2 {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else { return };
    if first_time("process", id) {
        dump_full("process", record, &schema);
    }
    let p = Parser::create(record, &schema);
    let kind = if id == 1 { "PROC_START" } else { "PROC_STOP" };
    println!(
        "{:<11} ts={} pid={} ppid={} image={}",
        kind,
        record.raw_timestamp(),
        u32f(&p, "ProcessID"),
        u32f(&p, "ParentProcessID"),
        s(&p, "ImageName")
    );
}

fn on_network(record: &EventRecord, locator: &SchemaLocator) {
    let id = record.event_id();
    // 12/28: TCP 연결 시도 (v4/v6), 15/31: 연결 수락, 42/58: UDP 송신 (v4/v6)
    let kind = match id {
        12 | 28 => "TCP_CONNECT",
        15 | 31 => "TCP_ACCEPT",
        42 | 58 => "UDP_SEND",
        _ => return,
    };
    let Ok(schema) = locator.event_schema(record) else { return };
    if first_time("network", id) {
        dump_full("network", record, &schema);
    }
    let p = Parser::create(record, &schema);
    // run-1 실측 확정: 필드명 PID/saddr/sport/daddr/dport/size. 헤더 PID 는 0 이므로 PID 필드를 쓴다.
    // 포트는 네트워크 바이트 순서로 들어온다 (예: 47873 → 443).
    let port = |name: &str| -> String {
        p.try_parse::<u16>(name)
            .map(|v| u16::from_be(v).to_string())
            .unwrap_or_else(|_| "-".into())
    };
    println!(
        "{:<11} ts={} id={} pid={} saddr={} sport={} daddr={} dport={} size={}",
        kind,
        record.raw_timestamp(),
        id,
        u32f(&p, "PID"),
        ipf(&p, "saddr"),
        port("sport"),
        ipf(&p, "daddr"),
        port("dport"),
        u32f(&p, "size")
    );
}

fn on_dns(record: &EventRecord, locator: &SchemaLocator) {
    let id = record.event_id();
    // 3006: 질의 시작, 3008: 질의 완료(결과 포함), 3020: 캐시 응답
    if id != 3006 && id != 3008 && id != 3020 {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else { return };
    if first_time("dns", id) {
        dump_full("dns", record, &schema);
    }
    let p = Parser::create(record, &schema);
    // run-1 실측: 3006/3008 은 헤더 PID 가 요청 프로세스, 3020(캐시 응답)은 헤더 PID 가
    // DNS 캐시 서비스(svchost)이고 실제 요청자는 ClientPID 필드에 있다.
    let pid = if id == 3020 { u32f(&p, "ClientPID") } else { record.process_id().to_string() };
    println!(
        "{:<11} ts={} id={} pid={} name={} type={} results={}",
        "DNS",
        record.raw_timestamp(),
        id,
        pid,
        s(&p, "QueryName"),
        u32f(&p, "QueryType"),
        s(&p, "QueryResults")
    );
}

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(15);
    println!("PoC 1-b — ETW 수집기 ({secs}초 수집)");

    let process = Provider::by_guid(KERNEL_PROCESS)
        // 0x10 = WINEVENT_KEYWORD_PROCESS. 0x50 은 Velociraptor 가 쓰는 값(프로세스+이미지)
        .any(0x50)
        .add_callback(on_process)
        .build();
    let network = Provider::by_guid(KERNEL_NETWORK)
        .add_callback(on_network)
        .build();
    let dns = Provider::by_guid(DNS_CLIENT)
        .add_callback(on_dns)
        .build();

    // 같은 이름의 세션이 남아 있으면 시작이 실패하므로 먼저 정리한다
    let _ = ferrisetw::trace::stop_trace_by_name("StoryFirewall-PoC1b");

    let trace = match UserTrace::new()
        .named("StoryFirewall-PoC1b".to_string())
        .enable(process)
        .enable(network)
        .enable(dns)
        .start_and_process()
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[error] ETW 세션 시작 실패: {e:?} (관리자 권한인지 확인)");
            std::process::exit(2);
        }
    };

    std::thread::sleep(Duration::from_secs(secs));
    eprintln!("[stat] events_processed={}", trace.events_handled());
    let _ = trace.stop();
    println!("END");
}
