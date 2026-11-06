//! 변경 장부 (기획서 17판 23-2 ③, 첫 출시는 장부만): 첫 실행 관찰실 대상과 그 자손에 한해
//! 파일 만들기·이름 바꾸기를 실행 여부와 상관없이 기록한다(평소에는 실행 파일·스크립트이고 실행된 것만 기록).
//!
//! 여기에는 "지금 장부에 적는 프로세스" 목록만 둔다. 서비스(관찰 시작)가 넣고, 수집기가 프로세스 시작 때 자손을 물려받게 하고,
//! 파일 이벤트 때 물어본다. 두 스레드가 같이 쓰므로 전역 잠금 하나. 플랫폼 전용 코드 없음.
//! 프로세스 키는 pid 만 쓴다 — 기한(관찰 시간)이 짧고 끝나면 지우므로 pid 재사용 위험은 기한 안으로 한정된다.

use std::collections::HashMap;
use std::sync::Mutex;

/// 동시에 적는 프로세스 상한(자식 폭주로 표가 커지지 않게). 넘으면 새 자손은 물려받지 않는다
pub const MAX_PIDS: usize = 2048;

/// pid → 기한(FILETIME)
static WATCH: Mutex<Option<HashMap<u32, i64>>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut HashMap<u32, i64>) -> R) -> R {
    let mut g = WATCH.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// 관찰 시작: 이 프로세스를 기한까지 적는다(기한이 더 길면 늘린다)
pub fn watch(pid: u32, until_ft: i64) {
    with(|m| {
        if m.len() >= MAX_PIDS && !m.contains_key(&pid) {
            return;
        }
        let e = m.entry(pid).or_insert(until_ft);
        *e = (*e).max(until_ft);
    });
}

/// 프로세스 시작: 부모가 장부에 있으면 같은 기한을 물려받는다. 물려받았으면 true
pub fn on_spawn(ppid: u32, pid: u32, now_ft: i64) -> bool {
    with(|m| {
        let Some(&until) = m.get(&ppid) else {
            return false;
        };
        if until < now_ft {
            m.remove(&ppid);
            return false;
        }
        if m.len() >= MAX_PIDS {
            return false;
        }
        m.insert(pid, until);
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
        Some(&until) if until >= now_ft => true,
        Some(_) => {
            m.remove(&pid);
            false
        }
        None => false,
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

    #[test]
    fn inherit_expire_exit() {
        clear();
        watch(10, 1000);
        assert!(is_watched(10, 500));
        assert!(on_spawn(10, 11, 600), "자식은 물려받는다");
        assert!(on_spawn(11, 12, 700), "손자도");
        assert!(!on_spawn(99, 13, 700), "모르는 부모");
        on_exit(11);
        assert!(!is_watched(11, 700));
        assert!(is_watched(12, 999));
        assert!(!is_watched(12, 1001), "기한 지남");
        assert!(!on_spawn(10, 14, 1001), "기한 지난 부모");
        clear();
    }
}
