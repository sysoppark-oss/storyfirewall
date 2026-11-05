//! 개발·시험 도구(제품에 들어가지 않음): 10판 5-9 (3) Defender CFA 기록 읽기를 러너에서 확인한다.
//!   defender-probe write <파일>   — 서명 없는 이 실행 파일로 파일을 쓴다(CFA 감사 모드면 1124 가 남는다)
//!   defender-probe read           — 서비스와 같은 함수(query_events·to_service_event)로 읽어 한 줄씩 찍는다
//! 이벤트 필드 이름은 공식 문서에 없어 추측 — read 가 원본 이름·값을 함께 찍어 poc3 기록으로 확인한다.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("write") => {
            let Some(p) = args.get(2) else {
                eprintln!("usage: defender-probe write <file>");
                std::process::exit(2);
            };
            match std::fs::write(p, b"story-firewall cfa probe\r\n") {
                Ok(()) => println!("PROBE write ok {p}"),
                // 차단 모드면 여기서 거부된다 — 그것도 결과다
                Err(e) => println!("PROBE write failed {p}: {e}"),
            }
        }
        Some("read") => match svc::defender::query_events() {
            Ok(evs) => {
                println!("PROBE events={}", evs.len());
                for e in evs.iter().take(10) {
                    let names: Vec<String> =
                        e.data.iter().map(|(k, v)| format!("{k}={v}")).collect();
                    println!(
                        "PROBE id={} record={} ts={} data=[{}]",
                        e.event_id,
                        e.record_id,
                        e.ts,
                        names.join(" | ")
                    );
                    if let Some((kind, _, detail, _)) = svc::defender::to_service_event(e) {
                        println!("PROBE service_event kind={kind} detail={detail}");
                    }
                }
            }
            Err(e) => println!("PROBE read error {e}"),
        },
        _ => {
            eprintln!("usage: defender-probe write <file> | read");
            std::process::exit(2);
        }
    }
}
