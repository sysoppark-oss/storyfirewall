//! 파일 생성·이름 변경 링 버퍼 (명세 4판 2-2)
//!
//! Kernel-File 의 CreateNewFile·Rename 이벤트를 전 확장자로 받되 DB 에는 넣지 않고 여기 둔다.
//! 그 경로가 나중에 실행되면(ProcessStart 이미지) 그때 사슬(.tmp → .exe 포함)을 꺼내 DB 에 기록한다.

use std::collections::VecDeque;

#[derive(Clone, Debug)]
pub struct FileEvent {
    pub ts: i64,
    pub pid: u32,
    /// "create" | "rename"
    pub kind: &'static str,
    /// 생성된 경로, 또는 이름 변경 후 경로 (Win32 경로, 소문자 비교용 원본 유지)
    pub path: String,
    /// 이름 변경 전 경로 (rename 만)
    pub from: Option<String>,
}

pub struct FileRing {
    window: i64,
    buf: VecDeque<FileEvent>,
}

impl FileRing {
    pub fn new(window_100ns: i64) -> Self {
        Self {
            window: window_100ns,
            buf: VecDeque::new(),
        }
    }

    pub fn push(&mut self, ev: FileEvent) {
        let cutoff = ev.ts - self.window;
        while self.buf.front().map_or(false, |f| f.ts < cutoff) {
            self.buf.pop_front();
        }
        if self.buf.len() >= 200_000 {
            self.buf.pop_front();
        }
        self.buf.push_back(ev);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// 이름 변경의 옛 경로 추정: 같은 PID 가 같은 폴더에 60초 안에 만든 파일 중 가장 최근 것으로,
    /// 지금 디스크에 없는 것(`gone` 이 true). ADS(":Zone.Identifier") 는 제외.
    pub fn guess_rename_source<F: Fn(&str) -> bool>(
        &self,
        new_path: &str,
        pid: u32,
        ts: i64,
        gone: F,
    ) -> Option<String> {
        let dir = parent_dir(new_path).to_ascii_lowercase();
        for ev in self.buf.iter().rev() {
            if ts - ev.ts > 60 * 10_000_000 {
                break;
            }
            if ev.pid != pid || ev.kind != "create" {
                continue;
            }
            if ev.path.to_ascii_lowercase() == new_path.to_ascii_lowercase() {
                continue;
            }
            if file_part(&ev.path).contains(':') {
                continue; // 대체 데이터 스트림
            }
            if parent_dir(&ev.path).to_ascii_lowercase() != dir {
                continue;
            }
            if gone(&ev.path) {
                return Some(ev.path.clone());
            }
        }
        None
    }

    /// 진단용: 최근 n 건
    pub fn tail(&self, n: usize) -> Vec<FileEvent> {
        self.buf.iter().rev().take(n).cloned().collect()
    }

    /// 어떤 경로가 실행됐을 때, 그 경로로 이어지는 사슬을 최근 것부터 거슬러 올라가 꺼낸다.
    /// 예: create a.tmp → rename a.tmp→b.exe → (실행 b.exe) ⇒ [create a.tmp, rename a.tmp→b.exe]
    pub fn chain_for(&self, path: &str) -> Vec<FileEvent> {
        let mut out = Vec::new();
        let mut target = path.to_ascii_lowercase();
        // 뒤에서 앞으로: target 을 만든 create 또는 target 으로 바꾼 rename 을 찾는다
        for ev in self.buf.iter().rev() {
            if ev.path.to_ascii_lowercase() != target {
                continue;
            }
            out.push(ev.clone());
            match (&ev.kind, &ev.from) {
                (&"rename", Some(from)) => target = from.to_ascii_lowercase(),
                _ => break, // create 에 닿으면 끝
            }
            if out.len() > 16 {
                break;
            }
        }
        out.reverse();
        out
    }
}

fn parent_dir(p: &str) -> &str {
    match p.rfind('\\') {
        Some(i) => &p[..i],
        None => "",
    }
}
fn file_part(p: &str) -> &str {
    match p.rfind('\\') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guesses_rename_source_from_recent_create_in_same_dir() {
        let mut r = FileRing::new(10_000_000 * 600);
        r.push(FileEvent {
            ts: 100,
            pid: 7,
            kind: "create",
            path: "C:\\d\\payload.tmp".into(),
            from: None,
        });
        r.push(FileEvent {
            ts: 110,
            pid: 7,
            kind: "create",
            path: "C:\\d\\payload.tmp:Zone.Identifier".into(),
            from: None,
        });
        r.push(FileEvent {
            ts: 120,
            pid: 9,
            kind: "create",
            path: "C:\\d\\other.tmp".into(),
            from: None,
        });
        let from =
            r.guess_rename_source("C:\\d\\payload.exe", 7, 200, |p| p.ends_with("payload.tmp"));
        assert_eq!(from.as_deref(), Some("C:\\d\\payload.tmp"));
        // 다른 PID 의 파일은 후보가 아니다
        assert!(r
            .guess_rename_source("C:\\d\\x.exe", 9, 200, |_| false)
            .is_none());
    }
    #[test]
    fn follows_rename_chain() {
        let mut r = FileRing::new(10_000_000 * 600);
        r.push(FileEvent {
            ts: 100,
            pid: 1,
            kind: "create",
            path: "C:\\d\\a.tmp".into(),
            from: None,
        });
        r.push(FileEvent {
            ts: 200,
            pid: 1,
            kind: "create",
            path: "C:\\d\\other.txt".into(),
            from: None,
        });
        r.push(FileEvent {
            ts: 300,
            pid: 1,
            kind: "rename",
            path: "C:\\d\\b.exe".into(),
            from: Some("C:\\d\\a.tmp".into()),
        });
        let c = r.chain_for("c:\\D\\B.EXE");
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].kind, "create");
        assert_eq!(c[1].kind, "rename");
        assert!(r.chain_for("C:\\nope.exe").is_empty());
    }
}
