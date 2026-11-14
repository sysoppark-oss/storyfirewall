//! 개발 도구: 화면이 만든 보고서 모형(JSON)을 실제 코드로 HTML 로 바꾼다 — 캡처·검수용(화면 캡처 스크립트의 가짜 저장과 짝).
//! 사용: cargo run -p report --example render -- <모형.json> <나올.html> [PC이름] [사용자이름]
fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("사용: render <모형.json> <나올.html> [PC이름] [사용자이름]");
        std::process::exit(2);
    }
    let model: report::Report =
        serde_json::from_str(&std::fs::read_to_string(&a[1]).expect("모형 읽기"))
            .expect("모형 형식");
    let who = report::out::who_from(a.get(3).cloned(), a.get(4).cloned(), vec![], vec![]);
    let html = report::render_html(&report::masked_copy(&model, &who));
    let p = report::out::write_whole(std::path::Path::new(&a[2]), html.as_bytes()).expect("쓰기");
    println!("{} ({} bytes)", p.display(), html.len());
}
