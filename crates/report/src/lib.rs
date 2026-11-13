//! 상세 보고서(통합프로젝트 「상세 보고서 기능 — 공통 규칙과 개발 의뢰 (1판)」 2장).
//!
//! 화면이 조회 결과로 **보고서 모형**(구역 → 문단·표·항목)을 만들어 넘기면, 여기서 가리기(2.4)를 하고
//! HTML 한 파일(2.1)과 원자료 JSON(2.6)을 만든다. 순수 함수만 — 파일 쓰기는 부른 쪽이 한다.
//!
//! 보안(2.2): 모형의 글자는 모두 바깥에서 온 자료(도메인·파일 이름·명령줄·프로세스 이름)로 보고 **전부 바꿔 쓴다**.
//! 모형에는 HTML 을 넣을 수 없다(글자만). 스크립트·이벤트 속성·링크·바깥 자원을 만들지 않는다.
use serde::{Deserialize, Serialize};

mod mask;
pub mod out;
pub use mask::{Masker, Who};

/// 구역 하나의 표 행 상한(2.7)
pub const MAX_ROWS: usize = 2000;
/// 머리 문구(2.6, 고정)
pub const HEAD_NOTE: &str =
    "이 보고서는 만든 시각까지 이 PC가 기록한 사실을 모은 것이며, 판정이 아닙니다.";

/// 보고서 모형. 시각은 RFC 3339 글자(부른 쪽이 이 PC 시각대로 만든다)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Report {
    /// "storyfirewall"
    pub program: String,
    /// 화면에 보이는 프로그램 이름("Story Firewall")
    pub program_title: String,
    pub version: String,
    pub generated_at: String,
    pub period_from: String,
    pub period_to: String,
    /// 가리기(2.4). 기본 켬
    #[serde(default = "yes")]
    pub masked: bool,
    /// 소스 주소(바닥글, 글자로만)
    #[serde(default)]
    pub source_url: String,
    pub sections: Vec<Section>,
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Section {
    /// 3.1 의 구역 id("incidents" …)
    pub id: String,
    pub title: String,
    /// 기간 안 전체 건수
    pub count: u64,
    /// 보고서에 실은 건수. 없으면 가장 큰 표의 행 수로 센다(사건마다 표가 따로인 구역은 부른 쪽이 적는다)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<u64>,
    /// 구역 설명 한두 줄(기준 등). 없어도 된다
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub blocks: Vec<Block>,
    /// 원자료(2.6 의 items) — 모양은 프로그램이 정한다. 가리기는 글자 값 전부에 한다
    #[serde(default)]
    pub items: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Block {
    /// 작은 제목
    Heading {
        text: String,
    },
    Para {
        text: String,
    },
    /// 이름 — 값 줄
    Facts {
        rows: Vec<(String, String)>,
    },
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

/// 2.2 의 1번: `& < > " '` 를 바꿔 쓰고 제어 문자를 뺀다(줄바꿈·탭은 빈칸으로)
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            '\n' | '\t' | '\r' => o.push(' '),
            // 제어 문자, 방향 바꾸기 문자(글자 순서를 속인다), BOM
            c if c.is_control()
                || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}') => {}
            c => o.push(c),
        }
    }
    o
}

/// 파일 이름(2.1): `<프로그램>-report-<YYYYMMDD-HHMMSS>.html`. `stamp` 는 부른 쪽이 만든 "YYYYMMDD-HHMMSS"
pub fn file_name(program: &str, stamp: &str) -> String {
    let p: String = program
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let s: String = stamp
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    format!("{p}-report-{s}.html")
}

/// 가리기를 모형 전체에 적용한 사본. `who` = 이 PC 의 이름·사용자·공인 주소(가릴 대상)
pub fn masked_copy(r: &Report, who: &Who) -> Report {
    if !r.masked {
        return r.clone();
    }
    let mut m = Masker::new(who.clone());
    let mut out = r.clone();
    for s in &mut out.sections {
        for n in &mut s.notes {
            *n = m.text(n);
        }
        for b in &mut s.blocks {
            match b {
                Block::Heading { text } | Block::Para { text } => *text = m.text(text),
                Block::Facts { rows } => {
                    for (_, v) in rows {
                        *v = m.text(v);
                    }
                }
                Block::Table { rows, .. } => {
                    for row in rows {
                        for c in row {
                            *c = m.text(c);
                        }
                    }
                }
            }
        }
        for it in &mut s.items {
            m.json(it);
        }
    }
    out
}

/// 구역에 실은 건수(가장 큰 표의 행 수, 표가 없으면 count)
fn shown_of(s: &Section) -> u64 {
    if let Some(n) = s.shown {
        return n.min(s.count);
    }
    s.blocks
        .iter()
        .filter_map(|b| match b {
            Block::Table { rows, .. } => Some(rows.len().min(MAX_ROWS) as u64),
            _ => None,
        })
        .max()
        .unwrap_or(s.count)
        .min(s.count.max(1))
}

const CSS: &str = "body{font-family:'Malgun Gothic','Segoe UI',sans-serif;color:#111;margin:24px;line-height:1.5}\
h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;border-bottom:2px solid #1f6f5c;padding-bottom:4px;margin-top:28px}\
h3{font-size:15px;margin:16px 0 6px}table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}\
th,td{border:1px solid #bbb;padding:3px 6px;text-align:left;vertical-align:top;word-break:break-all}th{background:#eee}\
.meta td:first-child,.facts td:first-child{width:11em;background:#f5f5f5}.note{color:#444;font-size:12px}\
.headnote{border-left:4px solid #1f6f5c;padding:6px 10px;background:#f5f5f5;margin:10px 0}footer{margin-top:32px;font-size:11px;color:#444;border-top:1px solid #bbb;padding-top:6px}\
@media print{section{break-before:page}section:first-of-type{break-before:auto}body{margin:0}}";

/// HTML 한 파일. `r` 은 가리기를 마친 모형(`masked_copy`)이어야 한다
pub fn render_html(r: &Report) -> String {
    let mut h = String::with_capacity(16 * 1024);
    h.push_str("<!DOCTYPE html>\n<html lang=\"ko\"><head><meta charset=\"utf-8\">\n");
    // 2.2 의 2·3번: 스크립트·바깥 자원 없음
    h.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">\n");
    h.push_str(&format!(
        "<title>{} 보고서 {}</title>\n<style>{CSS}</style></head><body>\n",
        esc(&r.program_title),
        esc(&r.generated_at)
    ));
    h.push_str(&format!("<h1>{} 보고서</h1>\n", esc(&r.program_title)));
    h.push_str(&format!("<p class=\"headnote\">{}</p>\n", esc(HEAD_NOTE)));
    h.push_str("<table class=\"meta\">");
    let meta = [
        ("프로그램", format!("{} {}", r.program_title, r.version)),
        ("만든 시각", r.generated_at.clone()),
        ("기간", format!("{} ~ {}", r.period_from, r.period_to)),
        (
            "가리기",
            if r.masked {
                "켬 — 내부 주소, MAC 주소 뒤쪽, PC 이름·사용자 이름, 이 PC 의 공인 주소를 가렸습니다. 바깥 목적지는 가리지 않습니다.".to_string()
            } else {
                "끔 — 내부 주소와 PC 이름이 그대로 들어 있습니다.".to_string()
            },
        ),
        (
            "구역",
            r.sections
                .iter()
                .map(|s| s.title.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    ];
    for (k, v) in meta {
        h.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", esc(k), esc(&v)));
    }
    h.push_str("</table>\n");
    for s in &r.sections {
        h.push_str(&format!("<section><h2>{}</h2>\n", esc(&s.title)));
        let shown = shown_of(s);
        if shown < s.count {
            h.push_str(&format!(
                "<p class=\"note\">전체 {}건 중 상위 {}건</p>\n",
                s.count, shown
            ));
        } else {
            h.push_str(&format!("<p class=\"note\">{}건</p>\n", s.count));
        }
        for n in &s.notes {
            h.push_str(&format!("<p class=\"note\">{}</p>\n", esc(n)));
        }
        for b in &s.blocks {
            match b {
                Block::Heading { text } => h.push_str(&format!("<h3>{}</h3>\n", esc(text))),
                Block::Para { text } => h.push_str(&format!("<p>{}</p>\n", esc(text))),
                Block::Facts { rows } => {
                    h.push_str("<table class=\"facts\">");
                    for (k, v) in rows {
                        h.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", esc(k), esc(v)));
                    }
                    h.push_str("</table>\n");
                }
                Block::Table { headers, rows } => {
                    h.push_str("<table><thead><tr>");
                    for x in headers {
                        h.push_str(&format!("<th>{}</th>", esc(x)));
                    }
                    h.push_str("</tr></thead><tbody>");
                    for row in rows.iter().take(MAX_ROWS) {
                        h.push_str("<tr>");
                        for c in row {
                            h.push_str(&format!("<td>{}</td>", esc(c)));
                        }
                        h.push_str("</tr>");
                    }
                    h.push_str("</tbody></table>\n");
                    if rows.len() > MAX_ROWS {
                        h.push_str(&format!(
                            "<p class=\"note\">표는 상위 {MAX_ROWS}행까지 실었습니다(받은 {}행).</p>\n",
                            rows.len()
                        ));
                    }
                }
            }
        }
        h.push_str("</section>\n");
    }
    // 2.5: 말씀·헌정 문구 없음. 바닥글 한 줄과 소스 주소(글자로만)
    h.push_str(&format!(
        "<footer>{} {} — 맑은물속교회가 무료로 나눕니다{}</footer>\n</body></html>\n",
        esc(&r.program_title),
        esc(&r.version),
        if r.source_url.is_empty() {
            String::new()
        } else {
            format!(" · 소스: {}", esc(&r.source_url))
        }
    ));
    h
}

/// 원자료 JSON(2.6, "antioch.report/1"). `r` 은 가리기를 마친 모형
pub fn render_json(r: &Report) -> serde_json::Value {
    serde_json::json!({
        "report": "antioch.report/1",
        "program": r.program,
        "version": r.version,
        "generated_at": r.generated_at,
        "period": { "from": r.period_from, "to": r.period_to },
        "masked": r.masked,
        "sections": r.sections.iter().map(|s| serde_json::json!({
            "id": s.id, "title": s.title, "count": s.count, "shown": shown_of(s), "items": s.items,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(evil: &str) -> Report {
        Report {
            program: "storyfirewall".into(),
            program_title: format!("Story Firewall{evil}"),
            version: format!("0.1.7{evil}"),
            generated_at: format!("2026-11-14T05:12:00+09:00{evil}"),
            period_from: evil.into(),
            period_to: evil.into(),
            masked: false,
            source_url: format!("https://example.invalid/{evil}"),
            sections: vec![Section {
                id: "incidents".into(),
                title: format!("인시던트{evil}"),
                count: 3,
                shown: None,
                notes: vec![evil.into()],
                blocks: vec![
                    Block::Heading { text: evil.into() },
                    Block::Para { text: evil.into() },
                    Block::Facts {
                        rows: vec![(evil.into(), evil.into())],
                    },
                    Block::Table {
                        headers: vec![evil.into()],
                        rows: vec![vec![evil.into()], vec![evil.into()]],
                    },
                ],
                items: vec![serde_json::json!({ "x": evil })],
            }],
        }
    }

    /// 만든 HTML 에서 우리가 쓰는 태그 말고는 `<` 가 없어야 하고, 속성은 우리가 쓰는 것뿐이어야 한다
    fn assert_inert(html: &str) {
        let allowed = [
            "!DOCTYPE", "html", "head", "meta", "title", "style", "body", "h1", "h2", "h3", "p",
            "table", "thead", "tbody", "tr", "td", "th", "section", "footer",
        ];
        let mut rest = html;
        while let Some(i) = rest.find('<') {
            let tail = &rest[i + 1..];
            let end = tail.find('>').expect("닫는 꺾쇠");
            let inner = tail[..end].trim_start_matches('/');
            let name: String = inner
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '!')
                .collect();
            assert!(
                allowed.contains(&name.as_str()),
                "허용하지 않는 태그: <{inner}>"
            );
            let attrs = inner[name.len()..].to_ascii_lowercase();
            for bad in [" on", "href", "src=", "javascript:", "url("] {
                assert!(!attrs.contains(bad), "허용하지 않는 속성: <{inner}>");
            }
            rest = &tail[end + 1..];
        }
        let low = html.to_ascii_lowercase();
        assert_eq!(low.matches("<script").count(), 0);
        assert!(low.contains("content-security-policy"));
        assert!(low.contains("default-src 'none'"));
    }

    #[test]
    fn hostile_text_never_becomes_markup() {
        for evil in [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "'</style><script>x</script>",
            "</td></tr></table><a href=\"javascript:alert(1)\">x</a>",
            "<svg/onload=alert(1)>",
            "&lt;script&gt;",
            "\u{202E}txt.exe\u{0000}\u{0007}",
            "</title><meta http-equiv=refresh content=0;url=http://x>",
        ] {
            let html = render_html(&sample(evil));
            assert_inert(&html);
            assert!(!html.contains('\u{202E}') && !html.contains('\u{0000}'));
        }
    }

    /// 2.2 의 5번: 무작위 입력(고정 씨앗) — 어떤 글자 조합도 태그·속성이 되지 않는다
    #[test]
    fn random_text_never_becomes_markup() {
        let alphabet: Vec<char> =
            "<>\"'&/=; \n\tscriptonerrorhrefjavascript:imgsvgstyle()\u{202E}\u{0}가나"
                .chars()
                .collect();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..400 {
            let mut s = String::new();
            for _ in 0..40 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                s.push(alphabet[(x % alphabet.len() as u64) as usize]);
            }
            assert_inert(&render_html(&sample(&s)));
        }
    }

    #[test]
    fn head_footer_and_counts() {
        let mut r = sample("");
        r.masked = true;
        r.sections[0].count = 5000;
        r.sections[0].blocks = vec![Block::Table {
            headers: vec!["a".into()],
            rows: (0..2500).map(|i| vec![i.to_string()]).collect(),
        }];
        let html = render_html(&r);
        assert!(html.contains(HEAD_NOTE));
        assert!(html.contains("전체 5000건 중 상위 2000건"));
        assert!(html.contains("맑은물속교회가 무료로 나눕니다"));
        assert!(html.contains("가리기") && html.contains("켬"));
        assert_eq!(html.matches("<tr><td>").count(), 5 + 2000);
        let j = render_json(&r);
        assert_eq!(j["report"], "antioch.report/1");
        assert_eq!(j["sections"][0]["count"], 5000);
        assert_eq!(j["sections"][0]["shown"], 2000);
        assert_eq!(j["masked"], true);
        assert_eq!(
            file_name("storyfirewall", "20261114-051200"),
            "storyfirewall-report-20261114-051200.html"
        );
        assert_eq!(file_name("a/../b", "2026..\\x"), "ab-report-2026.html");
    }
}

#[cfg(test)]
mod shown_tests {
    use super::*;

    /// 사건마다 표가 따로인 구역: 부른 쪽이 적은 "실은 건수"가 HTML·JSON 에 그대로 나온다
    #[test]
    fn explicit_shown_wins_over_table_rows() {
        let r = Report {
            program: "storyfirewall".into(),
            program_title: "Story Firewall".into(),
            version: "0.1.6".into(),
            generated_at: "2026-11-14T08:00:00+09:00".into(),
            period_from: "a".into(),
            period_to: "b".into(),
            masked: false,
            source_url: String::new(),
            sections: vec![Section {
                id: "incidents".into(),
                title: "인시던트".into(),
                count: 300,
                shown: Some(200),
                notes: vec![],
                blocks: vec![Block::Table {
                    headers: vec!["시각".into()],
                    rows: vec![vec!["x".into()]],
                }],
                items: vec![],
            }],
        };
        assert!(render_html(&r).contains("전체 300건 중 상위 200건"));
        assert_eq!(render_json(&r)["sections"][0]["shown"], 200);
    }
}
