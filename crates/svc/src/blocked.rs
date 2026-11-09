//! 차단 통신 집계(개편안 2판 1-2②, 42차 Q1): WFP CLASSIFY_DROP 구독 → 채널 → 집계 스레드 → traffic_hourly.blocked
//!
//! - 콜백(BFE 스레드)은 `try_send` 한 번만 한다. 채널이 차면 버리고 `lost` 를 센다 — 과소 집계를 숨기지 않는다(화면은 "최소 N건").
//! - 우리 필터가 막은 것만 센다(`our_filters`, 엔진 스레드가 정책이 바뀔 때·주기 판정마다 갱신). Windows 방화벽 등
//!   다른 Provider 의 차단은 세지 않는다.
//! - 집계 스레드는 자기 SQLite 연결(WAL)로 10초마다 시간대별 합계를 쓴다. 조회 경로는 건드리지 않는다.
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// 우리 WFP 필터 id 집합(엔진 스레드가 갱신)
pub type OurFilters = Arc<RwLock<HashSet<u64>>>;

/// 채널 상한(초당 수만 건 폭주 때 BFE 스레드를 막지 않게 작게)
pub const CHANNEL_CAP: usize = 4096;
/// 집계 → DB 쓰기 주기
pub const FLUSH_EVERY: Duration = Duration::from_secs(10);

/// 콜백이 채널에 미는 정보. 집계(우리 필터만 시간대별)와 차단 기록(모든 공급자, 최근 N건)이 함께 쓴다
#[derive(Debug, Clone, Default)]
pub struct Drop {
    pub ts_ft: i64,
    pub filter_id: u64,
    /// 차단 기록(사용자 요청 2026-11-09 — "인터넷 액세스가 차단되었습니다"의 이유 찾기)
    pub app: String,
    pub remote: String,
    pub rport: u16,
    pub lport: u16,
    pub proto: u8,
    /// 0 나가기, 1 들어오기, 그 밖 모름
    pub dir: u32,
    pub loopback: bool,
    /// 서비스 시작 때 BFE 기록에서 되읽은 것 — 기록에만 넣고 시간대 집계에는 넣지 않는다(이미 셌다)
    pub backfill: bool,
}

/// 차단 기록 한 줄(화면용). 외부 문자열(app·필터 이름)은 화면이 위생 처리한다
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockRec {
    /// unix 초
    pub ts: i64,
    pub filter_id: u64,
    pub app: String,
    pub remote: String,
    pub rport: u16,
    pub lport: u16,
    pub proto: u8,
    pub dir: &'static str,
    pub loopback: bool,
    /// 받은 때 이 필터가 우리 정책 필터 목록(엔진 DB)에 있었나 — 공급자 키만으로 "우리 것"이라 하지 않는다(46차 Q2·Q3)
    pub ours_at: bool,
}

/// 규칙·프로그램별 누적(46차 답변 Q2 수용): 최근 3,000건 고리가 다량 차단으로 밀려나도 "어느 규칙이 어느 프로그램을 몇 번" 은 남는다
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleAgg {
    pub filter_id: u64,
    pub app: String,
    pub n: u64,
    pub first: i64,
    pub last: i64,
    pub remote: String,
    pub rport: u16,
    pub dir: &'static str,
    pub loopback: bool,
    pub ours_at: bool,
}
/// 누적 칸 상한(넘으면 새 칸은 만들지 않고 overflow 로 센다)
pub const RULES_CAP: usize = 2000;

/// 최근 차단 기록(메모리, 서비스가 꺼지면 사라지지만 시작 때 BFE 기록 최근 것을 되읽는다) + 필터 정보 표
#[derive(Default)]
pub struct RecentInner {
    pub items: std::collections::VecDeque<BlockRec>,
    pub filters: HashMap<u64, Option<policy::FilterInfo>>,
    /// 같은 (필터, 프로그램, 원격, 포트)가 1초 안에 거듭 오면 하나로(폭주 때 기록이 한 프로그램으로 덮이지 않게)
    pub dup_skipped: u64,
    /// (필터, 프로그램) → 누적
    pub rules: HashMap<(u64, String), RuleAgg>,
    pub rules_overflow: u64,
    /// 고리에서 밀려난 줄 수
    pub evicted: u64,
}
pub type Recent = Arc<std::sync::Mutex<RecentInner>>;
/// 기록 상한
pub const RECENT_CAP: usize = 3000;

/// msFwpDirection: FWP_DIRECTION_IN 0x3900 · OUT 0x3901 · FORWARD 0x3902 (FWPM_NET_EVENT_CLASSIFY_DROP1/2 문서).
/// FWP_DIRECTION_OUTBOUND 0 · INBOUND 1 꼴도 받는다(CLASSIFY_ALLOW0 은 이쪽). install-136 실측: 0x3900 이 와서 빈칸이었다
pub fn dir_word(d: u32) -> &'static str {
    match d {
        0x3901 | 0 => "out",
        0x3900 | 1 => "in",
        0x3902 => "fwd",
        _ => "",
    }
}

impl RecentInner {
    /// 한 줄 넣기(최신이 뒤). 바로 앞 몇 줄과 같은 것이 1초 안이면 건너뛴다
    pub fn push(&mut self, d: &Drop, ours_at: bool) {
        let ts = crate::runtime::filetime_to_unix(d.ts_ft);
        // 누적은 묶기·밀려남과 상관없이 모든 사건을 센다
        let key = (d.filter_id, d.app.clone());
        if let Some(a) = self.rules.get_mut(&key) {
            a.n += 1;
            a.first = a.first.min(ts);
            if ts >= a.last {
                a.last = ts;
                a.remote = d.remote.clone();
                a.rport = d.rport;
            }
        } else if self.rules.len() < RULES_CAP {
            self.rules.insert(
                key,
                RuleAgg {
                    filter_id: d.filter_id,
                    app: d.app.clone(),
                    n: 1,
                    first: ts,
                    last: ts,
                    remote: d.remote.clone(),
                    rport: d.rport,
                    dir: dir_word(d.dir),
                    loopback: d.loopback,
                    ours_at,
                },
            );
        } else {
            self.rules_overflow += 1;
        }
        let dup = self.items.iter().rev().take(8).any(|r| {
            r.filter_id == d.filter_id
                && r.app == d.app
                && r.remote == d.remote
                && r.rport == d.rport
                && (ts - r.ts).abs() <= 1
        });
        if dup {
            self.dup_skipped += 1;
            return;
        }
        self.items.push_back(BlockRec {
            ts,
            filter_id: d.filter_id,
            app: d.app.clone(),
            remote: d.remote.clone(),
            rport: d.rport,
            lport: d.lport,
            proto: d.proto,
            dir: dir_word(d.dir),
            loopback: d.loopback,
            ours_at,
        });
        // 되읽은 옛 기록(backfill)은 시각이 앞설 수 있다 — 시각 순을 지킨다(3000건이라 정렬은 싸다)
        if self.items.len() >= 2 && self.items[self.items.len() - 2].ts > ts {
            self.items.make_contiguous().sort_by_key(|r| r.ts);
        }
        while self.items.len() > RECENT_CAP {
            self.items.pop_front();
            self.evicted += 1;
        }
    }
}

/// 콜백 쪽 싱크: try_send 만, 넘치면 lost
#[derive(Clone)]
pub struct Sink {
    tx: SyncSender<Drop>,
    pub lost: Arc<AtomicU64>,
}
impl Sink {
    pub fn push(&self, d: Drop) {
        match self.tx.try_send(d) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.lost.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

pub fn channel() -> (Sink, Receiver<Drop>, Arc<AtomicU64>) {
    let (tx, rx) = sync_channel(CHANNEL_CAP);
    let lost = Arc::new(AtomicU64::new(0));
    (
        Sink {
            tx,
            lost: lost.clone(),
        },
        rx,
        lost,
    )
}

/// 시간대별 (차단 수, 유실 수) 누적 — 순수 로직(시험용)
#[derive(Default)]
pub struct Agg {
    pub hours: HashMap<i64, u64>,
}
impl Agg {
    /// FILETIME → 시간대(unix 초, 시 단위). 우리 필터가 아니면 세지 않는다
    pub fn add(&mut self, d: &Drop, ours: &HashSet<u64>) -> bool {
        if d.backfill || !ours.contains(&d.filter_id) {
            return false;
        }
        let hour = graph::Store::hour_bucket(d.ts_ft);
        *self.hours.entry(hour).or_insert(0) += 1;
        true
    }
    pub fn take(&mut self) -> HashMap<i64, u64> {
        std::mem::take(&mut self.hours)
    }
}

/// 집계 스레드 본체: rx 에서 받아 모았다가 FLUSH_EVERY 마다 store 에 쓴다. rx 가 닫히면 끝
/// 필터 번호 → 정보 찾기(WFP 세션은 스레드 안에서 만든다 — HANDLE 은 Send 가 아니다)
pub type ResolverFactory =
    Box<dyn FnOnce() -> Box<dyn FnMut(u64) -> Option<policy::FilterInfo>> + Send>;

pub fn run(
    rx: Receiver<Drop>,
    lost: Arc<AtomicU64>,
    ours: OurFilters,
    recent: Recent,
    resolver: ResolverFactory,
    db_path: String,
    log: impl Fn(String),
) {
    let mut resolve = resolver();
    let store = match graph::Store::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            log(format!("blocked: graph db open failed: {e}"));
            return;
        }
    };
    let mut agg = Agg::default();
    let mut last = std::time::Instant::now();
    loop {
        match rx.recv_timeout(FLUSH_EVERY) {
            Ok(d) => {
                let set = ours.read().map(|g| g.clone()).unwrap_or_default();
                agg.add(&d, &set);
                // 차단 기록: 처음 보는 필터면 그때 이름·공급자를 읽어 둔다(나중에 필터가 지워져도 남게)
                if let Ok(mut g) = recent.lock() {
                    if !g.filters.contains_key(&d.filter_id) {
                        let info = resolve(d.filter_id);
                        g.filters.insert(d.filter_id, info);
                    }
                    let ours_at = set.contains(&d.filter_id);
                    g.push(&d, ours_at);
                }
                // 폭주 때 recv 만 계속 성공하면 flush 가 밀린다 → 시간으로도 끊는다
                if last.elapsed() < FLUSH_EVERY {
                    continue;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        last = std::time::Instant::now();
        let lost_n = lost.swap(0, Ordering::Relaxed);
        let hours = agg.take();
        if hours.is_empty() && lost_n == 0 {
            continue;
        }
        let now_hour = graph::Store::hour_bucket(crate::runtime::unix_to_filetime(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        ));
        for (h, n) in hours {
            if let Err(e) = store.add_blocked_hour(h, n, 0) {
                log(format!("blocked: write failed: {e}"));
            }
        }
        if lost_n > 0 {
            let _ = store.add_blocked_hour(now_hour, 0, lost_n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_our_filters_are_counted_per_hour() {
        let ours: HashSet<u64> = [10u64, 11].into_iter().collect();
        let mut a = Agg::default();
        let t0 = crate::runtime::unix_to_filetime(1_794_009_600);
        assert!(a.add(
            &Drop {
                ts_ft: t0,
                filter_id: 10,
                ..Default::default()
            },
            &ours
        ));
        assert!(a.add(
            &Drop {
                ts_ft: t0 + 5 * 10_000_000,
                filter_id: 11,
                ..Default::default()
            },
            &ours
        ));
        assert!(!a.add(
            &Drop {
                ts_ft: t0,
                filter_id: 99,
                ..Default::default()
            },
            &ours
        ));
        assert!(a.add(
            &Drop {
                ts_ft: t0 + 3600 * 10_000_000,
                filter_id: 10,
                ..Default::default()
            },
            &ours
        ));
        let h = a.take();
        assert_eq!(h.get(&1_794_009_600), Some(&2));
        assert_eq!(h.get(&(1_794_009_600 + 3600)), Some(&1));
        assert!(a.take().is_empty());
    }

    #[test]
    fn full_channel_counts_lost_instead_of_blocking() {
        let (sink, rx, lost) = channel();
        for i in 0..(CHANNEL_CAP + 5) as u64 {
            sink.push(Drop {
                ts_ft: 0,
                filter_id: i,
                ..Default::default()
            });
        }
        assert_eq!(lost.load(Ordering::Relaxed), 5);
        assert_eq!(rx.try_iter().count(), CHANNEL_CAP);
    }
}

#[cfg(test)]
mod recent_tests {
    use super::*;
    #[test]
    fn recent_keeps_all_providers_dedups_and_caps() {
        let mut r = RecentInner::default();
        let ft = crate::runtime::unix_to_filetime(1_794_009_600);
        let d = |f: u64, app: &str, s: i64| Drop {
            ts_ft: ft + s * 10_000_000,
            filter_id: f,
            app: app.into(),
            remote: "127.0.0.1".into(),
            rport: 8815,
            loopback: true,
            ..Default::default()
        };
        r.push(&d(5, "msedge.exe", 0), false);
        r.push(&d(5, "msedge.exe", 1), false); // 1초 안 같은 것 → 하나로
        r.push(&d(5, "msedge.exe", 3), false);
        r.push(&d(77, "chrome.exe", 3), false); // 다른 공급자 필터도 남는다
        assert_eq!(r.items.len(), 3);
        assert_eq!(r.dup_skipped, 1);
        assert_eq!(r.items[0].dir, "out");
        assert_eq!(
            (
                dir_word(0x3900),
                dir_word(0x3901),
                dir_word(0x3902),
                dir_word(7)
            ),
            ("in", "out", "fwd", "")
        );
        assert_eq!(
            r.rules[&(5, "msedge.exe".to_string())].n,
            3,
            "묶인 것도 누적에는 센다"
        );
        // 46차 Q2: 한 프로그램이 포트를 바꿔 가며 쏟아내 고리를 밀어내도, 앞의 규칙·프로그램 누적은 남는다
        for i in 0..(RECENT_CAP as i64 + 10) {
            let mut x = d(9, "flood.exe", 10 + i);
            x.rport = (i % 60000) as u16;
            r.push(&x, false);
        }
        assert_eq!(r.items.len(), RECENT_CAP);
        assert!(r.evicted >= 3);
        assert_eq!(r.rules[&(77, "chrome.exe".to_string())].n, 1);
        assert_eq!(
            r.rules[&(9, "flood.exe".to_string())].n,
            RECENT_CAP as u64 + 10
        );
    }
    #[test]
    fn backfill_is_recorded_but_not_counted() {
        let ours: HashSet<u64> = [5u64].into_iter().collect();
        let mut a = Agg::default();
        assert!(!a.add(
            &Drop {
                filter_id: 5,
                backfill: true,
                ..Default::default()
            },
            &ours
        ));
        assert!(a.add(
            &Drop {
                filter_id: 5,
                ..Default::default()
            },
            &ours
        ));
    }
}
