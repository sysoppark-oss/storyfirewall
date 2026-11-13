//! 접점 시험: 화면(ui/src/report.ts)이 만드는 모형 JSON 을 이 크레이트가 그대로 읽는가.
//! `ui-model.json` 은 화면 쪽 시험(ui/src/report.test.ts "접점")이 같은 내용인지 확인하는 고정 자료다 — 한쪽만 바꾸면 한쪽 시험이 깨진다.
use report::{masked_copy, render_html, render_json, Report, Who};

#[test]
fn ui_model_deserializes_and_renders() {
    let r: Report = serde_json::from_str(include_str!("ui-model.json")).expect("화면이 만든 모형을 읽지 못함");
    assert_eq!(r.program, "storyfirewall");
    assert!(r.masked);
    assert_eq!(r.sections.len(), 3);
    assert_eq!(r.sections[0].shown, Some(1));
    let who = Who { pc_name: "DESKTOP-TEST".into(), users: vec!["pjg".into()], public_ips: vec![] };
    let m = masked_copy(&r, &who);
    let html = render_html(&m);
    // 가리기: 내부 주소·사용자 이름은 사라지고 바깥 목적지는 남는다
    assert!(!html.contains("192.168.0.7"), "내부 주소가 남음");
    assert!(!html.contains("pjg"), "사용자 이름이 남음");
    assert!(html.contains("203.0.113.7"));
    // 적대 글자는 태그가 되지 않는다
    assert!(!html.contains("<img"));
    assert!(html.contains("&lt;img"));
    let j = render_json(&m);
    assert_eq!(j["report"], "antioch.report/1");
    assert_eq!(j["sections"][1]["id"], "blocked");
    assert_eq!(j["sections"][1]["count"], 2);
}
