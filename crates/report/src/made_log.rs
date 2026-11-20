//! 보고서 만든 기록(「상세 보고서 기능 (2판)」 2.3).
//!
//! 보고서를 만들 때마다 **화면(일반 권한)이 사용자 폴더의 기록 파일에 한 줄** 남긴다. 서비스는 거치지 않는다(3.2).
//! 편의 기록이지 변조를 막는 기록이 아니다 — 같은 사용자 권한으로 지우거나 고칠 수 있다.
//! 한 줄 = JSON 하나(JSON Lines). 크기 상한을 넘으면 오래된 줄부터 지운다. PC 밖으로 보내지 않는다.

use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Report;

/// 기록 파일 크기 상한. 한 줄이 300~500바이트라 500~800건쯤이다
pub const MAX_BYTES: usize = 256 * 1024;
/// 한 칸에 담는 글자 수 상한(저장 경로·실패 이유). 기록 한 줄이 끝없이 길어지지 않게
const MAX_FIELD_CHARS: usize = 400;
/// 구역 id 개수 상한(정상은 8개 이하)
const MAX_SECTIONS: usize = 32;

/// 기록 한 줄
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    /// 만든 시각(보고서 머리의 generated_at 그대로)
    pub at: String,
    /// 실은 구역 id
    pub sections: Vec<String>,
    pub period_from: String,
    pub period_to: String,
    /// 가리기 여부
    pub masked: bool,
    /// 원자료(JSON)를 함께 냈는지
    pub raw_json: bool,
    /// 저장한 경로(실패했으면 비어 있을 수 있다)
    pub path: String,
    pub ok: bool,
    /// 실패 이유 한 줄(성공이면 빈 글자)
    #[serde(default)]
    pub reason: String,
}

/// 제어 문자(줄바꿈 포함)를 빼고 길이를 자른다 — 한 건이 한 줄을 넘지 않게, 화면에 그대로 보여도 되게
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_FIELD_CHARS)
        .collect()
}

impl Entry {
    /// 보고서 모형과 결과에서 기록 한 줄을 만든다. `path` = 실제로 쓴 경로(없으면 빈 글자), `reason` = 실패 이유(성공이면 None)
    pub fn of(model: &Report, raw_json: bool, path: &str, reason: Option<&str>) -> Self {
        Self {
            at: clean(&model.generated_at),
            sections: model
                .sections
                .iter()
                .take(MAX_SECTIONS)
                .map(|s| clean(&s.id))
                .collect(),
            period_from: clean(&model.period_from),
            period_to: clean(&model.period_to),
            masked: model.masked,
            raw_json,
            path: clean(path),
            ok: reason.is_none(),
            reason: reason.map(clean).unwrap_or_default(),
        }
    }
}

/// 지금 내용 뒤에 한 줄을 붙이고, 상한을 넘으면 오래된 줄부터 버린 새 내용을 돌려준다.
/// 새 줄 하나가 상한보다 크면(있을 수 없지만) 그 줄만 남긴다.
pub fn appended(old: &str, line: &str, max_bytes: usize) -> String {
    let mut lines: Vec<&str> = old.lines().filter(|l| !l.trim().is_empty()).collect();
    lines.push(line);
    let mut total: usize = lines.iter().map(|l| l.len() + 1).sum();
    let mut from = 0;
    while total > max_bytes && from + 1 < lines.len() {
        total -= lines[from].len() + 1;
        from += 1;
    }
    let mut out = String::with_capacity(total);
    for l in &lines[from..] {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// 기록 파일에 한 줄을 더한다. 폴더가 없으면 만든다. 같은 폴더의 임시 이름에 다 쓴 뒤 이름을 바꾼다(반쪽 파일을 남기지 않는다).
/// 실패하면 오류를 돌려줄 뿐이다 — **부르는 쪽은 이 실패로 보고서 저장을 막지 않는다**(2.3).
pub fn append(file: &Path, entry: &Entry) -> std::io::Result<()> {
    let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // 읽지 못하면(없음·깨짐) 빈 것으로 보고 새로 시작한다. 상한의 몇 배가 넘는 파일은 읽지 않는다(누가 키워 놓은 경우)
    let old = match std::fs::metadata(file) {
        Ok(m) if m.len() as usize <= MAX_BYTES * 4 => {
            std::fs::read_to_string(file).unwrap_or_default()
        }
        _ => String::new(),
    };
    let body = appended(&old, &line, MAX_BYTES);
    let mut tmp = file.as_os_str().to_os_string();
    tmp.push(format!(".{}.part", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let r = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, file)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// 최근 것부터 `limit` 건. 읽지 못하는 줄(손으로 고쳤거나 깨진 줄)은 건너뛴다. 파일이 없으면 빈 목록
pub fn recent(file: &Path, limit: usize) -> Vec<Entry> {
    let Ok(m) = std::fs::metadata(file) else {
        return Vec::new();
    };
    if m.len() as usize > MAX_BYTES * 4 {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(file) else {
        return Vec::new();
    };
    text.lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .map(|e| Entry {
            // 파일은 사용자 권한으로 고칠 수 있다 — 읽을 때도 같은 규칙으로 다시 깎는다
            at: clean(&e.at),
            sections: e
                .sections
                .iter()
                .take(MAX_SECTIONS)
                .map(|s| clean(s))
                .collect(),
            period_from: clean(&e.period_from),
            period_to: clean(&e.period_to),
            path: clean(&e.path),
            reason: clean(&e.reason),
            ..e
        })
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Section;

    fn model() -> Report {
        Report {
            program: "storyfirewall".into(),
            program_title: "Story Firewall".into(),
            version: "0.1.6".into(),
            generated_at: "2026-11-20T13:40:00+09:00".into(),
            period_from: "2026-11-13T00:00:00+09:00".into(),
            period_to: "2026-11-20T13:40:00+09:00".into(),
            masked: true,
            source_url: String::new(),
            sections: ["incidents", "blocked", "policy"]
                .iter()
                .map(|id| {
                    serde_json::from_value::<Section>(
                        serde_json::json!({ "id": id, "title": id, "count": 0 }),
                    )
                    .unwrap()
                })
                .collect(),
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sf-made-log-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn entry_carries_the_seven_fields_of_2_3() {
        let e = Entry::of(&model(), false, r"C:\Users\pjg\Documents\r.html", None);
        assert_eq!(e.at, "2026-11-20T13:40:00+09:00");
        assert_eq!(e.sections, ["incidents", "blocked", "policy"]);
        assert_eq!(e.period_from, "2026-11-13T00:00:00+09:00");
        assert!(e.masked && !e.raw_json && e.ok);
        assert_eq!(e.path, r"C:\Users\pjg\Documents\r.html");
        assert_eq!(e.reason, "");
        let f = Entry::of(
            &model(),
            false,
            "",
            Some("파일을 쓰지 못했습니다: 접근 거부"),
        );
        assert!(!f.ok);
        assert_eq!(f.reason, "파일을 쓰지 못했습니다: 접근 거부");
    }

    #[test]
    fn one_entry_is_always_one_line() {
        // 경로·이유에 줄바꿈이나 제어 문자가 있어도 한 줄(기록을 여러 줄로 쪼개 거짓 줄을 끼워 넣지 못한다)
        let e = Entry::of(
            &model(),
            false,
            "C:\\a\nb\r\n{\"ok\":true}",
            Some("x\ny\u{0}z"),
        );
        let line = serde_json::to_string(&e).unwrap();
        assert!(!line.contains('\n') && !line.contains('\r'));
        assert_eq!(e.reason, "xyz");
        // 긴 값은 잘린다
        let long = "가".repeat(5000);
        let e = Entry::of(&model(), false, &long, None);
        assert_eq!(e.path.chars().count(), MAX_FIELD_CHARS);
    }

    #[test]
    fn appended_drops_oldest_lines_over_the_cap() {
        let old = "a1\na2\na3\n";
        assert_eq!(appended(old, "a4", 1024), "a1\na2\na3\na4\n");
        // 상한 9바이트 = 세 줄("xx\n" × 3)
        assert_eq!(appended(old, "a4", 9), "a2\na3\na4\n");
        assert_eq!(appended(old, "a4", 3), "a4\n");
        // 새 줄 하나가 상한보다 커도 그 줄은 남긴다
        assert_eq!(appended(old, "아주 긴 줄", 2), "아주 긴 줄\n");
        // 빈 줄은 버린다
        assert_eq!(appended("\n\na1\n\n", "a2", 1024), "a1\na2\n");
    }

    #[test]
    fn append_and_recent_roundtrip_newest_first() {
        let dir = tmp("roundtrip");
        let file = dir.join("sub").join("report-log.jsonl");
        let mut m = model();
        for i in 0..5 {
            m.generated_at = format!("2026-11-20T13:4{i}:00+09:00");
            append(
                &file,
                &Entry::of(&m, false, &format!("C:\\r{i}.html"), None),
            )
            .unwrap();
        }
        let got = recent(&file, 3);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].path, "C:\\r4.html");
        assert_eq!(got[2].path, "C:\\r2.html");
        // 임시 파일이 남지 않는다
        let left: Vec<_> = std::fs::read_dir(file.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert_eq!(left, ["report-log.jsonl"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_stays_under_the_cap() {
        let dir = tmp("cap");
        let file = dir.join("report-log.jsonl");
        let m = model();
        let path = "C:\\".to_string() + &"d".repeat(390);
        for _ in 0..800 {
            append(&file, &Entry::of(&m, false, &path, None)).unwrap();
        }
        let len = std::fs::metadata(&file).unwrap().len() as usize;
        assert!(len <= MAX_BYTES, "{len}");
        assert!(len > MAX_BYTES / 2, "오래된 줄만 버린다: {len}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recent_skips_broken_lines_and_missing_file() {
        let dir = tmp("broken");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("report-log.jsonl");
        assert!(recent(&file, 10).is_empty());
        let good = serde_json::to_string(&Entry::of(&model(), false, "C:\\ok.html", None)).unwrap();
        std::fs::write(&file, format!("깨진 줄\n{{\"at\":1}}\n{good}\n\n")).unwrap();
        let got = recent(&file, 10);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, "C:\\ok.html");
        // 손으로 고쳐 넣은 제어 문자는 읽을 때 빠진다
        let mut e = Entry::of(&model(), false, "x", None);
        e.path = "C:\\a\u{7}b".into();
        std::fs::write(&file, serde_json::to_string(&e).unwrap() + "\n").unwrap();
        assert_eq!(recent(&file, 1)[0].path, "C:\\ab");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
