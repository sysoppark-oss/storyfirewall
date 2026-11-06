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
//! 33차 Gemini Q1: 대상(또는 자손)이 대리 실행 도구(schtasks·at·wmic·sc)를 띄우면 그 종류의 "대리 창"을 연다.
//! 창이 열린 동안 그 도구가 일을 맡기는 시스템 프로세스(작업 스케줄러 svchost·taskhostw, WmiPrvSE, services)가 새로 띄운
//! 프로세스는 **추정**으로 물려받는다. 부모-자식 관계가 아니라 시간으로 잇는 것이라 표시를 따로 하고, 창마다 개수·시간을 제한한다.
//! 대상이 자식 없이 직접 COM·WMI 를 부르는 경우는 도구 실행이 보이지 않아 창이 열리지 않는다(한계 — 드라이버 없이 RPC 를 보지 못함).

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
/// 대리 창이 열려 있는 시간(FILETIME, 2분). 예약 작업을 나중 시각으로 걸어 두면 놓친다(한계)
pub const PROXY_WINDOW_FT: i64 = 120 * 10_000_000;
/// 대리 창 하나가 물려줄 수 있는 프로세스 수(창이 열린 사이 그 시스템 프로세스가 띄운 무관한 프로세스를 줄이게)
pub const PROXY_MAX: u32 = 3;

/// 대리 실행 종류
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proxy {
    /// 예약 작업(schtasks·at) → 작업 스케줄러
    Task,
    /// WMI(wmic) → WmiPrvSE
    Wmi,
    /// 서비스(sc) → services
    Service,
}

/// 대리 실행 도구(실행 파일 이름, 소문자) → 종류
pub fn proxy_tool(image_base: &str) -> Option<Proxy> {
    match image_base {
        "schtasks.exe" | "at.exe" => Some(Proxy::Task),
        "wmic.exe" => Some(Proxy::Wmi),
        "sc.exe" => Some(Proxy::Service),
        _ => None,
    }
}

/// 일을 맡는 시스템 프로세스(부모 이미지 이름) → 종류
pub fn proxy_host(image_base: &str) -> Option<Proxy> {
    match image_base {
        // 작업 스케줄러 서비스(Schedule)를 담은 svchost 는 이름이 아니라 서비스 대조표로 고른다(34차 Q2, `set_schedule_hosts`)
        "taskhostw.exe" | "taskeng.exe" => Some(Proxy::Task),
        "wmiprvse.exe" => Some(Proxy::Wmi),
        "services.exe" => Some(Proxy::Service),
        _ => None,
    }
}

/// 장부의 뿌리(관찰 대상): pid@생성 시각
pub type Root = (u32, i64);

#[derive(Debug, Clone)]
struct Entry {
    /// 생성 시각(FILETIME). 0 = 모름(관찰 시작 때 모르면) — 그때는 pid 만 본다
    create_ft: i64,
    until_ft: i64,
    root: Root,
    /// 부모-자식이 아니라 대리 창으로 물려받음(화면에 "추정")
    inferred: bool,
    folders: HashMap<String, u32>,
}

#[derive(Debug, Clone)]
struct Arm {
    root: Root,
    /// 창이 닫히는 시각
    close_ft: i64,
    /// 관찰 기한(물려받는 프로세스의 기한)
    until_ft: i64,
    left: u32,
}

#[derive(Default)]
struct State {
    watch: HashMap<u32, Entry>,
    /// 일을 맡는 시스템 프로세스: pid → 종류
    hosts: HashMap<u32, Proxy>,
    /// 열린 대리 창
    arms: Vec<(Proxy, Arm)>,
    /// 작업 스케줄러 서비스를 담은 svchost pid(서비스 대조표)
    sched: std::collections::HashSet<u32>,
    /// 34차 Q1: 관찰 중에 등록된 예약 작업 이름(소문자) → (뿌리, 기한). 작업 스케줄러 ETW 106·140 이 넣고 129 가 쓴다
    tasks: HashMap<String, (Root, i64)>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(State::default))
}

fn base_lower(image: &str) -> String {
    image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase()
}

/// 관찰 시작: 이 프로세스(pid + 생성 시각)를 기한까지 적는다. 뿌리는 자기 자신
pub fn watch(pid: u32, create_ft: i64, until_ft: i64) {
    watch_under(pid, create_ft, until_ft, (pid, create_ft));
}

/// 관찰 시작 때 이미 떠 있던 자손: 뿌리를 대상으로
pub fn watch_under(pid: u32, create_ft: i64, until_ft: i64, root: Root) {
    with(|s| {
        let m = &mut s.watch;
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
                        root,
                        inferred: false,
                        folders: HashMap::new(),
                    },
                );
            }
        }
    });
}

/// 어떤 프로세스든 시작될 때(먼저 부른다): 같은 pid 의 옛 항목이 다른 생성 시각이면 pid 가 다시 쓰인 것 — 지운다.
/// 일을 맡는 시스템 프로세스면 기억한다
pub fn on_start(pid: u32, create_ft: i64, image: &str) {
    with(|s| {
        if let Some(e) = s.watch.get(&pid) {
            if e.create_ft != 0 && create_ft != 0 && e.create_ft != create_ft {
                s.watch.remove(&pid);
            }
        }
        match proxy_host(&base_lower(image)) {
            Some(k) => {
                s.hosts.insert(pid, k);
            }
            None => {
                s.hosts.remove(&pid);
            }
        }
    });
}

/// 34차 Gemini Q2: 작업 스케줄러 서비스(Schedule)를 담은 svchost 들. 수집기가 서비스 대조표(SCM, 1초마다)로 알려 준다.
/// 다른 svchost(업데이트·백신 등)가 띄운 프로세스는 대리 창으로 물려받지 않는다
pub fn set_schedule_hosts(pids: &[u32]) {
    with(|s| {
        s.sched = pids.iter().copied().collect();
    });
}

/// 지금 관찰 중인 서로 다른 뿌리(기한 안). 대리 등록을 어느 대상에 이을지 정할 때만 쓴다
fn live_roots(s: &State, now_ft: i64) -> Vec<(Root, i64)> {
    let mut v: Vec<(Root, i64)> = Vec::new();
    for e in s
        .watch
        .values()
        .filter(|e| e.until_ft >= now_ft && !e.inferred)
    {
        match v.iter_mut().find(|x| x.0 == e.root) {
            Some(x) => x.1 = x.1.max(e.until_ft),
            None => v.push((e.root, e.until_ft)),
        }
    }
    v
}

/// 34차 Gemini Q1: 예약 작업이 등록·변경됨(작업 스케줄러 ETW 106·140). 이벤트에 등록한 프로세스 pid 가 없다(러너 실측 —
/// 헤더 pid 는 작업 스케줄러 svchost). 그래서 **지금 관찰 중인 대상이 하나뿐일 때만** 그 대상에 잇는다(여럿이면 어느 쪽인지 모름).
/// 이은 작업이 나중에 실행되면(129) 실행된 프로세스를 정확히 그 pid 로 물려받는다 — 시각 창이 아니라 작업 이름으로. 이었으면 true
pub fn task_registered(name: &str, now_ft: i64) -> bool {
    with(|s| {
        let roots = live_roots(s, now_ft);
        if roots.len() != 1 {
            return false;
        }
        let (root, until) = roots[0];
        if s.tasks.len() > 256 {
            s.tasks.retain(|_, (_, u)| *u >= now_ft);
        }
        s.tasks.insert(name.to_ascii_lowercase(), (root, until));
        true
    })
}

/// 예약 작업이 프로세스를 실행함(작업 스케줄러 ETW 129: TaskName·ProcessID). 이은 작업이면 그 pid 를 추정으로 물려받는다
pub fn task_launched(name: &str, pid: u32, now_ft: i64) -> bool {
    with(|s| {
        let Some(&(root, until)) = s.tasks.get(&name.to_ascii_lowercase()) else {
            return false;
        };
        if until < now_ft || s.watch.len() >= MAX_PIDS {
            return false;
        }
        s.watch.insert(
            pid,
            Entry {
                create_ft: 0,
                until_ft: until,
                root,
                inferred: true,
                folders: HashMap::new(),
            },
        );
        true
    })
}

/// 물려받은 방법
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inherit {
    No,
    /// 부모가 장부에 있음
    Child,
    /// 대리 창으로(추정)
    Proxy(Proxy),
}

/// 프로세스 시작(`on_start` 다음): 부모가 장부에 있으면 같은 기한·뿌리를 물려받는다. 아니면 부모가 일을 맡는
/// 시스템 프로세스이고 그 종류의 대리 창이 열려 있으면 추정으로 물려받는다.
/// 물려받은 프로세스가 대리 실행 도구면 그 종류의 창을 연다
pub fn on_spawn(ppid: u32, pid: u32, create_ft: i64, image: &str, now_ft: i64) -> Inherit {
    with(|s| {
        let base = base_lower(image);
        s.arms.retain(|(_, a)| a.close_ft >= now_ft && a.left > 0);
        let parent = s.watch.get(&ppid).map(|e| (e.until_ft, e.root, e.inferred));
        let (until, root, inferred, how) = match parent {
            Some((until, _, _)) if until < now_ft => {
                s.watch.remove(&ppid);
                return Inherit::No;
            }
            Some((until, root, inf)) => (until, root, inf, Inherit::Child),
            None => {
                let kind = match s.hosts.get(&ppid).copied() {
                    Some(k) => k,
                    None if s.sched.contains(&ppid) => Proxy::Task,
                    None => return Inherit::No,
                };
                let Some((_, arm)) = s.arms.iter_mut().find(|(k, _)| *k == kind) else {
                    return Inherit::No;
                };
                arm.left -= 1;
                (arm.until_ft, arm.root, true, Inherit::Proxy(kind))
            }
        };
        if s.watch.len() >= MAX_PIDS {
            return Inherit::No;
        }
        s.watch.insert(
            pid,
            Entry {
                create_ft,
                until_ft: until,
                root,
                inferred,
                folders: HashMap::new(),
            },
        );
        if let Some(k) = proxy_tool(&base) {
            s.arms.push((
                k,
                Arm {
                    root,
                    close_ft: now_ft + PROXY_WINDOW_FT,
                    until_ft: until,
                    left: PROXY_MAX,
                },
            ));
        }
        how
    })
}

/// 프로세스 끝: 지운다(pid 재사용에 물려받지 않게)
pub fn on_exit(pid: u32) {
    with(|s| {
        s.watch.remove(&pid);
        s.hosts.remove(&pid);
    });
}

/// 지금 적는 프로세스인가(기한 지난 것은 지운다)
pub fn is_watched(pid: u32, now_ft: i64) -> bool {
    with(|s| match s.watch.get(&pid) {
        Some(e) if e.until_ft >= now_ft => true,
        Some(_) => {
            s.watch.remove(&pid);
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
    /// 그 파일을 그대로. `inferred_root` 가 있으면 대리 창으로 물려받은 프로세스(추정) — 출처에 뿌리를 단다
    Each { inferred_root: Option<Root> },
    /// "폴더\*" 한 줄 — 이 폴더에 지금까지 n 개
    Summary {
        folder_glob: String,
        count: u32,
        inferred_root: Option<Root>,
    },
}

/// 장부 대상 프로세스의 파일 이벤트 하나 → 적는 방법
pub fn record_file(pid: u32, path: &str, now_ft: i64) -> Write {
    with(|s| {
        let m = &mut s.watch;
        let Some(e) = m.get_mut(&pid) else {
            return Write::Skip;
        };
        if e.until_ft < now_ft {
            m.remove(&pid);
            return Write::Skip;
        }
        let inferred_root = e.inferred.then_some(e.root);
        let folder = match path.rfind(['\\', '/']) {
            Some(i) => path[..i].to_ascii_lowercase(),
            None => String::new(),
        };
        let glob = || match path.rfind(['\\', '/']) {
            Some(i) => format!("{}\\*", &path[..i]),
            None => "*".to_string(),
        };
        if !e.folders.contains_key(&folder) && e.folders.len() >= MAX_FOLDERS {
            // 폴더가 너무 많다: 새 폴더는 묶음 개수 없이 한 줄만
            return Write::Summary {
                folder_glob: glob(),
                count: 0,
                inferred_root,
            };
        }
        let n = e.folders.entry(folder).or_insert(0);
        *n = n.saturating_add(1);
        if *n <= PER_FOLDER_EACH {
            Write::Each { inferred_root }
        } else if SUMMARY_AT.contains(n) {
            Write::Summary {
                folder_glob: glob(),
                count: *n,
                inferred_root,
            }
        } else {
            Write::Skip
        }
    })
}

/// 추정(대리 창) 기록의 출처 꼬리표 — ledger.get 이 뿌리로 찾는다
pub fn inferred_source(root: Root) -> String {
    format!("etw:file:ledger:inferred:{}@{}", root.0, root.1)
}

/// 추정(대리 창)으로 적힌 파일: 뿌리 꼬리표가 붙은 쓰기 선의 파일 경로와 출처. 관찰 시간 범위(FILETIME)로 원시 기록 색인을 탄다
pub fn inferred_files(
    store: &crate::store::Store,
    root: Root,
    from_ft: i64,
    to_ft: i64,
    limit: usize,
) -> crate::Result<Vec<(String, String)>> {
    // 꼬리표에는 %·_ 가 없다(숫자·영문·:·@). 같은 뿌리만: 정확히 같거나 뒤에 ":bulk:…"
    let exact = inferred_source(root);
    let prefix = format!("{exact}:%");
    let mut st = store.conn().prepare_cached(
        "SELECT n.key, r.source FROM raw_events r
           JOIN edges e ON e.evidence_id = r.id AND e.rel = 'wrote'
           JOIN nodes n ON n.id = e.dst
         WHERE r.ts >= ?1 AND r.ts <= ?2 AND (r.source = ?3 OR r.source LIKE ?4)
         ORDER BY r.ts LIMIT ?5",
    )?;
    let rows = st.query_map(
        rusqlite::params![from_ft, to_ft, exact, prefix, limit as i64],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// 지금 적는 프로세스 수 (진단)
pub fn len() -> usize {
    with(|s| s.watch.len())
}

/// 시험용: 비운다
pub fn clear() {
    with(|s| *s = State::default());
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
        on_start(11, 600, "a.exe");
        assert_eq!(
            on_spawn(10, 11, 600, "a.exe", 600),
            Inherit::Child,
            "자식은 물려받는다"
        );
        assert_eq!(
            on_spawn(11, 12, 700, "b.exe", 700),
            Inherit::Child,
            "손자도"
        );
        assert_eq!(
            on_spawn(99, 13, 700, "c.exe", 700),
            Inherit::No,
            "모르는 부모"
        );
        on_exit(11);
        assert!(!is_watched(11, 700));
        assert!(is_watched(12, 999));
        assert!(!is_watched(12, 1001), "기한 지남");
        assert_eq!(
            on_spawn(10, 14, 1001, "d.exe", 1001),
            Inherit::No,
            "기한 지난 부모"
        );

        // 33차 Q2: 끝 이벤트를 놓친 뒤 같은 pid 로 다른 프로세스 → 지운다
        clear();
        watch(20, 100, 10_000);
        on_start(20, 100, "x.exe");
        assert!(
            is_watched(20, 200),
            "같은 프로세스의 시작 이벤트는 지우지 않는다"
        );
        on_start(20, 300, "y.exe");
        assert!(!is_watched(20, 400), "pid 재사용");

        // 33차 Q3: 한 폴더 20개까지 하나씩, 그 뒤는 문턱마다 묶음
        clear();
        watch(30, 1, 10_000);
        let mut each = 0;
        let mut sums = Vec::new();
        for i in 0..1_500u32 {
            match record_file(30, &format!(r"C:\Temp\g\f{i}.txt"), 10) {
                Write::Each { .. } => each += 1,
                Write::Summary {
                    folder_glob, count, ..
                } => sums.push((folder_glob, count)),
                Write::Skip => {}
            }
        }
        assert_eq!(each, 20);
        assert_eq!(
            sums.iter().map(|s| s.1).collect::<Vec<_>>(),
            vec![21, 100, 1000]
        );
        assert_eq!(sums[0].0, r"C:\Temp\g\*");
        assert_eq!(
            record_file(30, r"C:\Temp\h\a.txt", 10),
            Write::Each {
                inferred_root: None
            }
        );
        assert_eq!(record_file(99, r"C:\x\a.txt", 10), Write::Skip, "대상 아님");
        clear();
        proxy_window_infers_scheduler_children();
        clear();
    }

    /// 33차 Q1: 대리 창(전역을 쓰므로 위 시험 안에서 차례로 부른다)
    fn proxy_window_infers_scheduler_children() {
        let t = 1_000_000_000i64;
        on_start(5000, 1, r"C:\Windows\System32\svchost.exe");
        on_start(5003, 1, r"C:\Windows\System32\svchost.exe");
        // 34차 Q2: 작업 스케줄러를 담은 svchost(5000)만 — 다른 svchost(5003, 업데이트 등)는 아님
        set_schedule_hosts(&[5000]);
        on_start(5001, 1, r"C:\Windows\System32\wbem\WmiPrvSE.exe");
        watch(6000, 7, t + PROXY_WINDOW_FT * 10);
        // 창이 열리기 전: 작업 스케줄러가 띄운 것은 물려받지 않는다
        on_start(6100, 2, r"C:\Windows\System32\cmd.exe");
        assert_eq!(
            on_spawn(5000, 6100, 2, r"C:\Windows\System32\cmd.exe", t),
            Inherit::No
        );
        // 대상이 schtasks 를 띄움 → 예약 작업 창
        on_start(6001, 3, r"C:\Windows\System32\schtasks.exe");
        assert_eq!(
            on_spawn(6000, 6001, 3, r"C:\Windows\System32\schtasks.exe", t),
            Inherit::Child
        );
        // 작업 스케줄러(svchost)가 띄운 프로세스는 추정으로, 뿌리는 대상
        on_start(6200, 4, r"C:\Windows\System32\cmd.exe");
        assert_eq!(
            on_spawn(5000, 6200, 4, r"C:\Windows\System32\cmd.exe", t + 10),
            Inherit::Proxy(Proxy::Task)
        );
        assert_eq!(
            record_file(6200, r"C:\p\payload.exe", t + 20),
            Write::Each {
                inferred_root: Some((6000, 7))
            }
        );
        assert_eq!(
            inferred_source((6000, 7)),
            "etw:file:ledger:inferred:6000@7"
        );
        // 다른 svchost 가 띄운 것은 물려받지 않는다
        on_start(6210, 4, "upd.exe");
        assert_eq!(on_spawn(5003, 6210, 4, "upd.exe", t + 15), Inherit::No);
        // 다른 종류(WMI)의 창은 열리지 않았다
        on_start(6300, 5, "x.exe");
        assert_eq!(on_spawn(5001, 6300, 5, "x.exe", t + 30), Inherit::No);
        // 창은 개수(3)까지만
        for (i, pid) in [6400u32, 6401].iter().enumerate() {
            on_start(*pid, 10 + i as i64, "y.exe");
            assert_eq!(
                on_spawn(5000, *pid, 10 + i as i64, "y.exe", t + 40),
                Inherit::Proxy(Proxy::Task)
            );
        }
        on_start(6402, 20, "y.exe");
        assert_eq!(
            on_spawn(5000, 6402, 20, "y.exe", t + 50),
            Inherit::No,
            "개수 다 씀"
        );
        // 시간이 지나면 닫힘(새 창으로 확인)
        on_start(6002, 30, "schtasks.exe");
        on_spawn(6000, 6002, 30, "schtasks.exe", t + 60);
        on_start(6500, 31, "z.exe");
        assert_eq!(
            on_spawn(5000, 6500, 31, "z.exe", t + 60 + PROXY_WINDOW_FT + 1),
            Inherit::No,
            "창 닫힘"
        );
        for p in [
            5000, 5001, 6000, 6001, 6002, 6100, 6200, 6300, 6400, 6401, 6402, 6500,
        ] {
            on_exit(p);
        }
    }
}
