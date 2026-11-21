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
/// 구역 id 한 개의 글자 수 상한(정상은 "incidents" 같은 짧은 영문). 한 줄이 수십 KB 로 불어 기록 몇 건에 상한이 차지 않게(57차 Q8)
const MAX_SECTION_CHARS: usize = 40;
/// 바꿔 쓰기가 "다른 프로그램이 파일을 열고 있음"으로 막혔을 때 다시 해 보는 횟수와 간격.
/// Windows 에서는 대상 파일을 백신 실시간 검사·미리 보기 등이 잠깐 잡고 있으면 이름 바꾸기가 거부된다(57차 Q1)
const RENAME_TRIES: u32 = 4;
const RENAME_WAIT: std::time::Duration = std::time::Duration::from_millis(40);

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
                .map(|s| clean(&s.id).chars().take(MAX_SECTION_CHARS).collect())
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

/// 기록 파일을 읽는다. 없거나 열지 못하면 빈 글자.
/// - 상한의 4배까지만 읽는다(크기를 먼저 재고 읽으면 그 사이에 파일을 키울 수 있다 — 읽는 양 자체를 막는다)
/// - UTF-8 이 아닌 바이트가 섞여도 버리지 않는다: 깨진 줄만 못 읽게 되고 나머지 줄은 산다
///   (예전에는 한 바이트만 깨져도 전체를 빈 것으로 보고, 다음 기록 때 앞의 줄을 모두 지웠다 — 별도 검수 지적 4·5)
fn read_capped(file: &Path) -> Option<String> {
    use std::io::Read as _;
    let f = std::fs::File::open(file).ok()?;
    let cap = (MAX_BYTES * 4) as u64;
    let mut buf = Vec::new();
    f.take(cap + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > cap {
        // 누가 키워 놓은 파일 — 읽지 않는다(기록은 새로 시작)
        return None;
    }
    // 메모장 등이 맨 앞에 붙인 BOM 은 벗긴다 — 두면 첫 줄을 못 읽고, 다시 쓸 때마다 그대로 따라간다(57차 Q7-2)
    let text = String::from_utf8_lossy(&buf);
    Some(text.trim_start_matches('\u{FEFF}').to_string())
}

/// 기록 파일을 둘 수 있는 평범한 로컬 경로인가: `C:\…` 처럼 드라이브 글자로 시작하는 절대 경로만.
/// `\\서버\공유`(네트워크), `\\.\…`·`\\?\…`(장치·특수 경로)는 받지 않는다 — 폴더 자리는 환경 변수에서 오고,
/// 환경 변수는 화면 프로그램을 띄운 쪽이 정한다(57차 Q2). 순수 함수라 Linux 에서 시험한다
pub fn is_plain_local_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/')
        && !p.chars().any(|c| c.is_control())
}

/// "다른 프로그램이 파일을 잡고 있다"는 오류인가. Windows 는 이것을 두 가지로 낸다:
/// 접근 거부(5 — 표준 라이브러리가 PermissionDenied 로 옮긴다)와 공유 위반(32 — 옮기는지 확실하지 않아 번호로도 본다).
/// 방금 쓴 임시 파일을 백신이 검사하는 흔한 경우가 32 다(별도 검수 지적)
fn busy(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
        || (cfg!(windows) && e.raw_os_error() == Some(32))
}

/// 예전 실행이 치우지 못하고 남긴 임시 파일을 지운다(이름에 프로세스 번호가 들어 있어 다음 실행은 같은 이름을 쓰지 않는다).
/// 10분 넘게 묵은 `<기록 파일 이름>.….part` 만 — 지금 쓰는 중인 것은 건드리지 않는다. 실패는 무시한다
fn sweep_stale_parts(file: &Path) {
    const STALE: std::time::Duration = std::time::Duration::from_secs(600);
    let (Some(dir), Some(name)) = (file.parent(), file.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let prefix = format!("{name}.");
    // 폴더에 파일이 아주 많아도 오래 붙잡지 않게 훑는 수를 막는다
    for ent in rd.flatten().take(2000) {
        let fname = ent.file_name();
        let Some(f) = fname.to_str() else { continue };
        if !(f.starts_with(&prefix) && f.ends_with(".part")) {
            continue;
        }
        // symlink_metadata: 연결이면 가리키는 곳이 아니라 연결 자체의 나이를 보고, 지워도 연결만 지워진다
        let old = std::fs::symlink_metadata(ent.path())
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE);
        if old {
            let _ = std::fs::remove_file(ent.path());
        }
    }
}

/// 한 프로세스 안에서 기록 쓰기는 한 번에 하나씩(읽고 → 고쳐 → 바꿔 쓰기라 겹치면 서로의 줄을 지운다 — 별도 검수 지적 3)
static APPEND_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 기록 파일에 한 줄을 더한다. 폴더가 없으면 만든다. 같은 폴더의 임시 이름에 다 쓴 뒤 이름을 바꾼다(반쪽 파일을 남기지 않는다).
/// 임시 파일은 **새로 만들 때만** 연다(`create_new`): 누가 그 이름에 미리 놓아 둔 링크를 따라가 다른 파일을 덮어쓰지 않는다.
/// 실패하면 오류를 돌려줄 뿐이다 — **부르는 쪽은 이 실패로 보고서 저장을 막지 않는다**(2.3).
pub fn append(file: &Path, entry: &Entry) -> std::io::Result<()> {
    let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    let _one = APPEND_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    sweep_stale_parts(file);
    let old = read_capped(file).unwrap_or_default();
    let body = appended(&old, &line, MAX_BYTES);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp = file.as_os_str().to_os_string();
    tmp.push(format!(".{}.{seq}.part", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let r = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        drop(f);
        let mut tries = 1;
        loop {
            match std::fs::rename(&tmp, file) {
                Err(e) if busy(&e) && tries < RENAME_TRIES => {
                    tries += 1;
                    std::thread::sleep(RENAME_WAIT);
                }
                r => break r,
            }
        }
    })();
    if r.is_err() {
        // create_new 가 실패했다면(이미 있던 이름) 그 파일은 우리 것이 아니다 — 지우지 않는다
        if !matches!(&r, Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists) {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    r
}

/// 최근 것부터 `limit` 건. 읽지 못하는 줄(손으로 고쳤거나 깨진 줄)은 건너뛴다. 파일이 없으면 빈 목록
pub fn recent(file: &Path, limit: usize) -> Vec<Entry> {
    let Some(text) = read_capped(file) else {
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
                .map(|s| clean(s).chars().take(MAX_SECTION_CHARS).collect())
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

    /// 별도 검수 지적 3: 여러 스레드가 한꺼번에 적어도 줄이 사라지지 않는다
    #[test]
    fn concurrent_appends_keep_every_line() {
        let dir = tmp("concurrent");
        let file = dir.join("report-log.jsonl");
        let m = model();
        std::thread::scope(|sc| {
            for t in 0..4 {
                let (file, m) = (&file, &m);
                sc.spawn(move || {
                    for i in 0..50 {
                        append(
                            file,
                            &Entry::of(m, false, &format!("C:\\t{t}-{i}.html"), None),
                        )
                        .unwrap();
                    }
                });
            }
        });
        assert_eq!(recent(&file, 1000).len(), 200);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 별도 검수 지적 4: UTF-8 이 아닌 바이트가 섞여도 나머지 줄은 살고, 다음 기록이 앞의 줄을 지우지 않는다
    #[test]
    fn a_broken_byte_does_not_wipe_the_log() {
        let dir = tmp("badbyte");
        let file = dir.join("report-log.jsonl");
        let m = model();
        for i in 0..3 {
            append(
                &file,
                &Entry::of(&m, false, &format!("C:\\r{i}.html"), None),
            )
            .unwrap();
        }
        let mut raw = std::fs::read(&file).unwrap();
        raw.extend([0xFF, b'\n']);
        std::fs::write(&file, raw).unwrap();
        assert_eq!(recent(&file, 10).len(), 3);
        append(&file, &Entry::of(&m, false, "C:\\r3.html", None)).unwrap();
        assert_eq!(recent(&file, 10).len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 별도 검수 지적 5: 임시 이름에 미리 놓인 파일(링크일 수 있다)을 따라 덮어쓰지 않는다
    #[test]
    fn a_planted_temp_file_is_not_overwritten() {
        let dir = tmp("planted");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("report-log.jsonl");
        let seq = TMP_SEQ.load(std::sync::atomic::Ordering::Relaxed);
        // 다음에 쓸 임시 이름 몇 개를 미리 차지해 둔다(다른 시험이 번호를 올려도 걸리게 넉넉히)
        let planted: Vec<_> = (seq..seq + 400)
            .map(|n| dir.join(format!("report-log.jsonl.{}.{n}.part", std::process::id())))
            .collect();
        for p in &planted {
            std::fs::write(p, "남의 것").unwrap();
        }
        let r = append(&file, &Entry::of(&model(), false, "C:\\x.html", None));
        assert!(r.is_err(), "이미 있는 임시 이름이면 쓰지 않고 실패한다");
        assert!(planted
            .iter()
            .all(|p| std::fs::read_to_string(p).unwrap() == "남의 것"));
        assert!(!file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 57차 Q7-2: BOM 이 붙은 파일(메모장으로 고쳐 저장)도 첫 줄을 읽고, 다시 쓰면 BOM 이 사라진다
    #[test]
    fn a_bom_does_not_hide_the_first_line() {
        let dir = tmp("bom");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("report-log.jsonl");
        let line = serde_json::to_string(&Entry::of(&model(), false, "C:\\a.html", None)).unwrap();
        // BOM + CRLF 줄바꿈
        std::fs::write(&file, format!("\u{FEFF}{line}\r\n{line}\r\n")).unwrap();
        assert_eq!(recent(&file, 10).len(), 2);
        append(&file, &Entry::of(&model(), false, "C:\\b.html", None)).unwrap();
        assert_eq!(recent(&file, 10).len(), 3);
        assert!(!std::fs::read(&file)
            .unwrap()
            .starts_with(&[0xEF, 0xBB, 0xBF]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 57차 Q8: 구역 id 가 길어도 한 줄이 불어나지 않는다
    #[test]
    fn section_ids_are_capped() {
        let mut m = model();
        m.sections[0].id = "가".repeat(5000);
        let e = Entry::of(&m, false, "x", None);
        assert_eq!(e.sections[0].chars().count(), MAX_SECTION_CHARS);
    }

    /// 57차 Q2: 기록 파일은 드라이브 글자로 시작하는 로컬 경로에만 둔다
    #[test]
    fn only_plain_drive_paths_are_accepted() {
        for ok in ["C:\\Users\\a\\AppData\\Local", "d:/data", "Z:\\"] {
            assert!(is_plain_local_path(ok), "{ok}");
        }
        for bad in [
            "",
            "C:",
            "C:rel",
            "\\\\server\\share",
            "\\\\.\\NUL",
            "\\\\?\\C:\\Windows",
            "\\\\.\\pipe\\x",
            "NUL",
            "/tmp/x",
            "C:\\a\nb",
        ] {
            assert!(!is_plain_local_path(bad), "{bad}");
        }
    }

    /// 별도 검수 지적: 예전 실행이 남긴 묵은 임시 파일은 다음 기록 때 치운다(새것은 두고)
    #[test]
    fn stale_part_files_are_swept() {
        let dir = tmp("sweep");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("report-log.jsonl");
        let stale = dir.join("report-log.jsonl.4242.7.part");
        let fresh = dir.join("report-log.jsonl.4242.8.part");
        let other = dir.join("notes.part");
        for p in [&stale, &fresh, &other] {
            std::fs::write(p, "x").unwrap();
        }
        // 묵은 것으로 보이게 수정 시각을 한 시간 전으로
        let hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for p in [&stale, &other] {
            std::fs::File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(hour_ago)
                .unwrap();
        }
        append(&file, &Entry::of(&model(), false, "C:\\x.html", None)).unwrap();
        assert!(!stale.exists(), "묵은 임시 파일은 지운다");
        assert!(fresh.exists(), "방금 것은 둔다");
        assert!(other.exists(), "이름이 다른 파일은 건드리지 않는다");
        // 구역 id 상한은 읽을 때도 걸린다(손으로 고친 파일)
        let mut e = Entry::of(&model(), false, "x", None);
        e.sections = vec!["가".repeat(5000)];
        std::fs::write(&file, serde_json::to_string(&e).unwrap() + "\n").unwrap();
        assert_eq!(
            recent(&file, 1)[0].sections[0].chars().count(),
            MAX_SECTION_CHARS
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
