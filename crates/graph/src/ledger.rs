//! 변경 장부 (기획서 17판 23-2 ③, 첫 출시는 장부만): 첫 실행 관찰실 대상과 그 자손에 한해
//! 파일 만들기·이름 바꾸기를 실행 여부와 상관없이 기록한다(평소에는 실행 파일·스크립트이고 실행된 것만 기록).
//!
//! 여기에는 "지금 장부에 적는 프로세스" 목록만 둔다. 서비스(관찰 시작)가 넣고, 수집기가 프로세스 시작 때 자손을 물려받게 하고,
//! 파일 이벤트 때 물어본다. 두 스레드가 같이 쓰므로 전역 잠금 하나. 플랫폼 전용 코드 없음.
//!
//! 33차 Gemini Q2: 프로세스는 pid + 생성 시각으로 구분한다. 끝 이벤트를 놓쳐도 같은 pid 로 다른 프로세스가 시작되면
//! (`on_start` 의 생성 시각이 다름) 옛 항목을 지운다 — 남의 파일이 장부에 적히지 않게.
//! 33차 Gemini Q3: 한 프로세스가 한 폴더에 만든 파일은 `PER_FOLDER_EACH` 개까지만 하나씩 적고, 그 뒤로는 개수가
//! 문턱(`SUMMARY_AT`)에 닿을 때마다 "폴더\*" 한 줄로 묶어 적는다.

use std::collections::HashMap;
use std::sync::Mutex;

/// 동시에 적는 프로세스 상한(자식 폭주로 표가 커지지 않게). 넘으면 새 자손은 물려받지 않는다
pub const MAX_PIDS: usize = 2048;
/// 한 프로세스·한 폴더에서 하나씩 적는 파일 수
pub const PER_FOLDER_EACH: u32 = 20;
/// 묶음 줄을 적는 개수 문턱
pub const SUMMARY_AT: &[u32] = &[21, 100, 1_000, 10_000, 100_000];
/// 프로세스마다 기억하는 폴더 수 상한(폴더를 잔뜩 만들어 메모리를 키우지 못하게). 넘으면 새 폴더는 바로 묶음으로
const MAX_FOLDERS: usize = 256;

#[derive(Debug, Clone)]
struct Entry {
    /// 생성 시각(FILETIME). 0 = 모름(관찰 시작 때 모르면) — 그때는 pid 만 본다
    create_ft: i64,
    until_ft: i64,
    folders: HashMap<String, u32>,
}

/// pid → 항목
static WATCH: Mutex<Option<HashMap<u32, Entry>>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut HashMap<u32, Entry>) -> R) -> R {
    let mut g = WATCH.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// 관찰 시작: 이 프로세스(pid + 생성 시각)를 기한까지 적는다(같은 프로세스면 기한을 늘린다)
pub fn watch(pid: u32, create_ft: i64, until_ft: i64) {
    with(|m| {
        if m.len() >= MAX_PIDS && !m.contains_key(&pid) {
            return;
        }
        match m.get_mut(&pid) {
            Some(e) if e.create_ft == create_ft || e.create_ft == 0 || create_ft == 0 => {
                e.until_ft = e.until_ft.max(until_ft);
                if e.create_ft == 0 {
                    e.create_ft = create_ft;
                }
            }
            _ => {
                m.insert(
                    pid,
                    Entry {
                        create_ft,
                        until_ft,
                        folders: HashMap::new(),
                    },
                );
            }
        }
    });
}

/// 어떤 프로세스든 시작될 때: 같은 pid 의 옛 항목이 다른 생성 시각이면 pid 가 다시 쓰인 것 — 지운다
pub fn on_start(pid: u32, create_ft: i64) {
    with(|m| {
        if let Some(e) = m.get(&pid) {
            if e.create_ft != 0 && create_ft != 0 && e.create_ft != create_ft {
                m.remove(&pid);
            }
        }
    });
}

/// 프로세스 시작: 부모가 장부에 있으면 같은 기한을 물려받는다. 물려받았으면 true. `on_start` 다음에 부른다
pub fn on_spawn(ppid: u32, pid: u32, create_ft: i64, now_ft: i64) -> bool {
    with(|m| {
        let Some(until) = m.get(&ppid).map(|e| e.until_ft) else {
            return false;
        };
        if until < now_ft {
            m.remove(&ppid);
            return false;
        }
        if m.len() >= MAX_PIDS {
            return false;
        }
        m.insert(
            pid,
            Entry {
                create_ft,
                until_ft: until,
                folders: HashMap::new(),
            },
        );
        true
    })
}

/// 프로세스 끝: 지운다(pid 재사용에 물려받지 않게)
pub fn on_exit(pid: u32) {
    with(|m| {
        m.remove(&pid);
    });
}

/// 지금 적는 프로세스인가(기한 지난 것은 지운다)
pub fn is_watched(pid: u32, now_ft: i64) -> bool {
    with(|m| match m.get(&pid) {
        Some(e) if e.until_ft >= now_ft => true,
        Some(_) => {
            m.remove(&pid);
            false
        }
        None => false,
    })
}

/// 파일 하나를 어떻게 적을지
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// 적지 않는다(장부 대상 아님, 또는 묶음 사이)
    Skip,
    /// 그 파일을 그대로
    Each,
    /// "폴더\*" 한 줄 — 이 폴더에 지금까지 n 개
    Summary { folder_glob: String, count: u32 },
}

/// 장부 대상 프로세스의 파일 이벤트 하나 → 적는 방법
pub fn record_file(pid: u32, path: &str, now_ft: i64) -> Write {
    with(|m| {
        let Some(e) = m.get_mut(&pid) else {
            return Write::Skip;
        };
        if e.until_ft < now_ft {
            m.remove(&pid);
            return Write::Skip;
        }
        let folder = match path.rfind(['\\', '/']) {
            Some(i) => path[..i].to_ascii_lowercase(),
            None => String::new(),
        };
        let glob = || match path.rfind(['\\', '/']) {
            Some(i) => format!("{}\\*", &path[..i]),
            None => "*".to_string(),
        };
        if !e.folders.contains_key(&folder) && e.folders.len() >= MAX_FOLDERS {
            // 폴더가 너무 많다: 새 폴더는 묶음 개수 없이 한 줄만(처음 한 번)
            return Write::Summary {
                folder_glob: glob(),
                count: 0,
            };
        }
        let n = e.folders.entry(folder).or_insert(0);
        *n = n.saturating_add(1);
        if *n <= PER_FOLDER_EACH {
            Write::Each
        } else if SUMMARY_AT.contains(n) {
            Write::Summary {
                folder_glob: glob(),
                count: *n,
            }
        } else {
            Write::Skip
        }
    })
}

/// 지금 적는 프로세스 수 (진단)
pub fn len() -> usize {
    with(|m| m.len())
}

/// 시험용: 비운다
pub fn clear() {
    with(|m| m.clear());
}

#[cfg(test)]
mod tests {
    use super::*;

    // 전역 목록을 쓰므로 한 시험 안에서 차례로 본다
    #[test]
    fn ledger_rules() {
        clear();
        // 물려받기·기한·끝
        watch(10, 5, 1000);
        assert!(is_watched(10, 500));
        on_start(11, 600);
        assert!(on_spawn(10, 11, 600, 600), "자식은 물려받는다");
        assert!(on_spawn(11, 12, 700, 700), "손자도");
        assert!(!on_spawn(99, 13, 700, 700), "모르는 부모");
        on_exit(11);
        assert!(!is_watched(11, 700));
        assert!(is_watched(12, 999));
        assert!(!is_watched(12, 1001), "기한 지남");
        assert!(!on_spawn(10, 14, 1001, 1001), "기한 지난 부모");

        // 33차 Q2: 끝 이벤트를 놓친 뒤 같은 pid 로 다른 프로세스 → 지운다
        clear();
        watch(20, 100, 10_000);
        on_start(20, 100);
        assert!(
            is_watched(20, 200),
            "같은 프로세스의 시작 이벤트는 지우지 않는다"
        );
        on_start(20, 300);
        assert!(!is_watched(20, 400), "pid 재사용");

        // 33차 Q3: 한 폴더 20개까지 하나씩, 그 뒤는 문턱마다 묶음
        clear();
        watch(30, 1, 10_000);
        let mut each = 0;
        let mut sums = Vec::new();
        for i in 0..1_500u32 {
            match record_file(30, &format!(r"C:\Temp\g\f{i}.txt"), 10) {
                Write::Each => each += 1,
                Write::Summary { folder_glob, count } => sums.push((folder_glob, count)),
                Write::Skip => {}
            }
        }
        assert_eq!(each, 20);
        assert_eq!(
            sums.iter().map(|s| s.1).collect::<Vec<_>>(),
            vec![21, 100, 1000]
        );
        assert_eq!(sums[0].0, r"C:\Temp\g\*");
        // 다른 폴더는 따로 센다
        assert_eq!(record_file(30, r"C:\Temp\h\a.txt", 10), Write::Each);
        assert_eq!(record_file(99, r"C:\x\a.txt", 10), Write::Skip, "대상 아님");
        clear();
    }
}
