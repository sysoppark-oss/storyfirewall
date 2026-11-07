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

/// 콜백이 채널에 미는 최소 정보
#[derive(Debug, Clone, Copy)]
pub struct Drop {
    pub ts_ft: i64,
    pub filter_id: u64,
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
    (Sink { tx, lost: lost.clone() }, rx, lost)
}

/// 시간대별 (차단 수, 유실 수) 누적 — 순수 로직(시험용)
#[derive(Default)]
pub struct Agg {
    pub hours: HashMap<i64, u64>,
}
impl Agg {
    /// FILETIME → 시간대(unix 초, 시 단위). 우리 필터가 아니면 세지 않는다
    pub fn add(&mut self, d: Drop, ours: &HashSet<u64>) -> bool {
        if !ours.contains(&d.filter_id) {
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
pub fn run(rx: Receiver<Drop>, lost: Arc<AtomicU64>, ours: OurFilters, db_path: String, log: impl Fn(String)) {
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
                agg.add(d, &set);
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
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
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
        assert!(a.add(Drop { ts_ft: t0, filter_id: 10 }, &ours));
        assert!(a.add(Drop { ts_ft: t0 + 5 * 10_000_000, filter_id: 11 }, &ours));
        assert!(!a.add(Drop { ts_ft: t0, filter_id: 99 }, &ours));
        assert!(a.add(Drop { ts_ft: t0 + 3600 * 10_000_000, filter_id: 10 }, &ours));
        let h = a.take();
        assert_eq!(h.get(&1_794_009_600), Some(&2));
        assert_eq!(h.get(&(1_794_009_600 + 3600)), Some(&1));
        assert!(a.take().is_empty());
    }

    #[test]
    fn full_channel_counts_lost_instead_of_blocking() {
        let (sink, rx, lost) = channel();
        for i in 0..(CHANNEL_CAP + 5) as u64 {
            sink.push(Drop { ts_ft: 0, filter_id: i });
        }
        assert_eq!(lost.load(Ordering::Relaxed), 5);
        assert_eq!(rx.try_iter().count(), CHANNEL_CAP);
    }
}
