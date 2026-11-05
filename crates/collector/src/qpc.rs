//! ETW 시각: QPC 원시 값 → 벽시계 FILETIME 변환 (23차 답변 Q2 수용, clock.rs 대체).
//!
//! ETW 가 바꿔 주는 FILETIME 은 세션 시작 때 기준을 쓰므로 그 뒤 시스템 시각 변경을 따라가지 않는다(B2 3회차 실측:
//! W32Time 이 시계를 152,794ms 되돌린 뒤 Sysmon 의 ETW 계열 사건이 152.8초 어긋남). 그래서 실시간 소비를
//! `PROCESS_TRACE_MODE_RAW_TIMESTAMP` 로 열어 QPC 틱을 받고, 우리가 **(QPC, 벽시계) 쌍**을 1초마다 잡아 둔다.
//! 사건의 QPC 와 가장 가까운 "그 이전" 쌍으로 바꾼다 → 시각 변경 앞의 사건은 변경 앞 기준, 뒤의 사건은 뒤 기준으로 바뀐다.
//! 소비 지연(버퍼 밀림)은 변환에 영향이 없다(사건 QPC 는 사건이 일어난 순간 값). 앞서 쓰던 "칸 최소 지연" 방식은
//! 일반 사용자가 이벤트 홍수로 소비를 15초 넘게 밀면 지연을 시각 변경으로 오인했다(23차 시나리오 1) — 이 방식에는 그 판단이 없다.
//!
//! 쌍끼리 (벽시계 차 − QPC 차)가 2초를 넘으면 그 사이에 시스템 시각이 바뀐 것으로 세어 보고한다(진단용).

use std::collections::VecDeque;

/// 쌍을 새로 잡는 최소 간격 (QPC 를 초로 바꾼 값, 100ns)
pub const PAIR_EVERY: i64 = 10_000_000;
/// 보관하는 쌍 수 (1초 간격이면 약 10분 — 소비가 그보다 오래 밀린 사건은 가장 오래된 쌍으로 바꾼다)
pub const MAX_PAIRS: usize = 600;
/// 시각 변경으로 세는 문턱 (100ns)
pub const JUMP_THRESHOLD: i64 = 2 * 10_000_000;

#[derive(Debug)]
pub struct QpcClock {
    freq: i64,
    /// (qpc, filetime), qpc 오름차순
    pairs: VecDeque<(i64, i64)>,
    /// 감지한 시각 변경 수와 가장 큰 변경(100ns, 절댓값)
    pub jumps: u64,
    pub max_jump: i64,
}

impl QpcClock {
    pub fn new(freq: i64) -> Self {
        assert!(freq > 0);
        QpcClock {
            freq,
            pairs: VecDeque::new(),
            jumps: 0,
            max_jump: 0,
        }
    }

    /// QPC 틱 차이를 100ns 로 (넘침 없이)
    fn ticks_to_100ns(&self, d: i64) -> i64 {
        ((d as i128) * 10_000_000 / (self.freq as i128)) as i64
    }

    /// 마지막 쌍 뒤로 `PAIR_EVERY` 가 지났으면 새 쌍이 필요하다
    pub fn needs_pair(&self, qpc_now: i64) -> bool {
        self.pairs
            .back()
            .is_none_or(|(q, _)| self.ticks_to_100ns(qpc_now - q) >= PAIR_EVERY)
    }

    pub fn add_pair(&mut self, qpc: i64, ft: i64) {
        if let Some(&(q0, f0)) = self.pairs.back() {
            if qpc <= q0 {
                return;
            }
            let jump = (ft - f0) - self.ticks_to_100ns(qpc - q0);
            if jump.abs() > JUMP_THRESHOLD {
                self.jumps += 1;
                self.max_jump = self.max_jump.max(jump.abs());
            }
        }
        self.pairs.push_back((qpc, ft));
        while self.pairs.len() > MAX_PAIRS {
            self.pairs.pop_front();
        }
    }

    /// 사건 QPC → FILETIME. 쌍이 없으면 None (호출 쪽이 먼저 쌍을 넣는다)
    pub fn to_filetime(&self, qpc: i64) -> Option<i64> {
        if self.pairs.is_empty() {
            return None;
        }
        // qpc 이하인 마지막 쌍. 모두 qpc 보다 뒤면 첫 쌍(보관 범위보다 오래된 사건)
        let i = self.pairs.partition_point(|(q, _)| *q <= qpc);
        let (q, f) = self.pairs[i.saturating_sub(1)];
        Some(f + self.ticks_to_100ns(qpc - q))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const S: i64 = 10_000_000;
    const FREQ: i64 = 10_000_000; // 실제 Windows 10+ 의 흔한 값

    #[test]
    fn converts_and_follows_clock_change_by_event_time_not_delivery_time() {
        let mut c = QpcClock::new(FREQ);
        let ft0 = 134_380_000_000_000_000;
        // 0~20초: 벽시계 = ft0 + qpc
        for s in 0..=20 {
            c.add_pair(s * FREQ, ft0 + s * S);
        }
        // 20.5초에 W32Time 이 152.794초 되돌림
        let back = 1_527_940_000;
        for s in 21..=40 {
            c.add_pair(s * FREQ, ft0 + s * S - back);
        }
        assert_eq!(c.jumps, 1);
        assert_eq!(c.max_jump, back);
        // 변경 앞(15.3초)에 일어나 뒤에 늦게 받은 사건 → 변경 앞 기준
        assert_eq!(c.to_filetime(153 * FREQ / 10), Some(ft0 + 153 * S / 10));
        // 변경 뒤(30.7초)의 사건 → 뒤 기준
        assert_eq!(
            c.to_filetime(307 * FREQ / 10),
            Some(ft0 + 307 * S / 10 - back)
        );
    }

    #[test]
    fn needs_pair_spacing_and_bounds() {
        let mut c = QpcClock::new(3_579_545); // 다른 주파수에서도 단위 변환
        assert!(c.needs_pair(0));
        assert_eq!(c.to_filetime(5), None);
        c.add_pair(1_000, 500);
        assert!(!c.needs_pair(1_000 + 3_579_545 / 2));
        assert!(c.needs_pair(1_000 + 3_579_545));
        // 첫 쌍보다 이른 사건도 첫 쌍으로 바꾼다 (음수 차)
        assert_eq!(c.to_filetime(1_000 - 3_579_545), Some(500 - S));
        // 뒤로 가는 쌍은 무시
        c.add_pair(900, 1);
        assert_eq!(c.to_filetime(1_000), Some(500));
        for i in 0..(MAX_PAIRS as i64 + 50) {
            c.add_pair(2_000 + i * 3_579_545, 1_000 + i * S);
        }
        assert_eq!(c.pairs.len(), MAX_PAIRS);
        assert_eq!(c.jumps, 0);
    }
}
