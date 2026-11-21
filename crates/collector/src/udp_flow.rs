//! UDP 송신을 "흐름" 단위로 본다 — 접속 선을 언제 새로 만들지 정한다.
//!
//! TCP 는 연결이 있어 연결마다 접속 선 하나다. UDP 는 연결이 없어, 전에는 "같은 목적지 1초 안 반복"만 거르고
//! 나머지 송신을 모두 접속으로 보냈다. 이어지는 UDP 흐름(사설망 터널, QUIC, 원격 접속) 하나가 초당 선 하나를 만들어
//! 노트북에서 접속 선 162만 개 중 156만 개(96%)가 UDP 였고 한 짝에 8만 7천 개가 쌓였다(diag-273).
//!
//! 규칙: (프로세스, 원격 주소, 원격 포트)가 같은 송신은
//! - **`IDLE` 넘게 쉬었다가 다시 보낼 때** 새 접속으로 보고,
//! - 쉬지 않고 이어지더라도 **`REFRESH` 마다 한 번**은 접속으로 남긴다(며칠 이어지는 흐름이 첫날 선 하나로만 남아
//!   보관 정리 뒤 사라지지 않게, 그리고 "지금도 이어지고 있다"가 그래프에 보이게).
//!
//! 잃는 것: `IDLE` 보다 짧은 주기로 되풀이되는 UDP 송신은 선 하나로 보인다(주기 분석의 재료가 준다).
//! 보낸 양은 흐름과 무관하게 따로 쌓이므로(용량 카운터) 양은 잃지 않는다.
//! 시각은 Windows FILETIME(100ns 단위).

use std::collections::HashMap;

/// 100ns 단위의 1초
const SEC: i64 = 10_000_000;
/// 이만큼 쉬었다가 다시 보내면 새 흐름
pub const IDLE: i64 = 60 * SEC;
/// 이어지는 흐름도 이 간격으로는 접속 선을 남긴다
pub const REFRESH: i64 = 3600 * SEC;
/// 기억하는 흐름 수 상한. 넘으면 쉰 지 오래된 것부터 잊는다 — 잊힌 흐름은 다음 송신 때 새 접속으로 남으므로
/// 접속을 **놓치는** 쪽으로는 틀리지 않는다(선이 조금 더 생길 뿐)
pub const MAX_FLOWS: usize = 16_384;

/// (프로세스 번호, 원격 주소, 원격 포트)
pub type Key = (u32, String, u16);

#[derive(Debug, Clone, Copy)]
struct Flow {
    /// 마지막으로 본 송신
    last_seen: i64,
    /// 마지막으로 접속 선을 남긴 때
    last_emit: i64,
}

#[derive(Debug, Default)]
pub struct UdpFlows {
    flows: HashMap<Key, Flow>,
}

impl UdpFlows {
    pub fn new() -> Self {
        Self::default()
    }

    /// 송신 하나를 본다. 접속 선을 남겨야 하면 true.
    pub fn on_send(&mut self, key: Key, ts: i64) -> bool {
        if let Some(f) = self.flows.get_mut(&key) {
            // 시계가 뒤로 간 경우(ts < last)는 차이를 0 으로 본다 — 음수 차이로 영영 "이어짐"이 되지 않게 last 를 따라 내린다
            let idle = ts.saturating_sub(f.last_seen);
            let since_emit = ts.saturating_sub(f.last_emit);
            let back = ts < f.last_seen;
            f.last_seen = ts;
            if back {
                f.last_emit = f.last_emit.min(ts);
            }
            if idle >= IDLE || since_emit >= REFRESH {
                f.last_emit = ts;
                return true;
            }
            return false;
        }
        if self.flows.len() >= MAX_FLOWS {
            self.shrink(ts);
        }
        self.flows.insert(
            key,
            Flow {
                last_seen: ts,
                last_emit: ts,
            },
        );
        true
    }

    /// 프로세스가 새로 시작됐다 — 같은 번호를 쓰던 옛 프로세스의 흐름을 잊는다.
    /// (번호는 재사용된다. 잊지 않으면 새 프로세스의 첫 송신이 옛 프로세스의 흐름에 묻혀 접속 선이 안 남는다)
    pub fn forget_pid(&mut self, pid: u32) {
        self.flows.retain(|k, _| k.0 != pid);
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// 가득 찼을 때: 이미 끝난 흐름(IDLE 넘게 쉼)을 먼저 버리고, 그래도 많으면 쉰 지 오래된 절반을 버린다
    fn shrink(&mut self, now: i64) {
        self.flows
            .retain(|_, f| now.saturating_sub(f.last_seen) < IDLE);
        if self.flows.len() >= MAX_FLOWS {
            let mut seen: Vec<i64> = self.flows.values().map(|f| f.last_seen).collect();
            let mid = seen.len() / 2;
            seen.select_nth_unstable(mid);
            let cut = seen[mid];
            self.flows.retain(|_, f| f.last_seen >= cut);
            // 모두 같은 시각이면 위에서 하나도 안 빠진다 — 그때는 통째로 비운다(다음 송신들이 새 접속으로 남는다)
            if self.flows.len() >= MAX_FLOWS {
                self.flows.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(pid: u32, port: u16) -> Key {
        (pid, "203.0.113.7".to_string(), port)
    }

    #[test]
    fn a_continuous_flow_is_one_connection_until_refresh() {
        let mut f = UdpFlows::new();
        let t0 = 1_000_000 * SEC;
        assert!(f.on_send(k(1, 443), t0), "첫 송신은 접속");
        // 한 시간 동안 초당 한 번 — 전에는 3600개의 선이 생겼다
        let mut emitted = 0;
        for s in 1..3600 {
            if f.on_send(k(1, 443), t0 + s * SEC) {
                emitted += 1;
            }
        }
        assert_eq!(emitted, 0);
        // 한 시간째에 한 번 남긴다(지금도 이어진다는 표시)
        assert!(f.on_send(k(1, 443), t0 + 3600 * SEC));
        assert!(!f.on_send(k(1, 443), t0 + 3601 * SEC));
        // 하루 내내 이어지면 24~25개
        let mut day = 0;
        for s in 3602..86_400 {
            if f.on_send(k(1, 443), t0 + s * SEC) {
                day += 1;
            }
        }
        assert_eq!(day, 22);
    }

    #[test]
    fn a_pause_longer_than_idle_starts_a_new_connection() {
        let mut f = UdpFlows::new();
        let t0 = 5_000 * SEC;
        assert!(f.on_send(k(1, 53), t0));
        assert!(!f.on_send(k(1, 53), t0 + 59 * SEC), "59초 쉼은 같은 흐름");
        // 쉰 시간은 마지막 송신부터 잰다(처음 송신부터가 아니다)
        assert!(!f.on_send(k(1, 53), t0 + 118 * SEC));
        assert!(f.on_send(k(1, 53), t0 + 178 * SEC), "60초 쉬면 새 접속");
        // 5분마다 한 번 보내는 것은 매번 새 접속으로 남는다
        let mut n = 0;
        for i in 1..=10 {
            if f.on_send(k(1, 53), t0 + 178 * SEC + i * 300 * SEC) {
                n += 1;
            }
        }
        assert_eq!(n, 10);
    }

    #[test]
    fn different_process_port_or_address_are_different_flows() {
        let mut f = UdpFlows::new();
        let t = 9_000 * SEC;
        assert!(f.on_send(k(1, 443), t));
        assert!(f.on_send(k(2, 443), t), "다른 프로세스");
        assert!(f.on_send(k(1, 444), t), "다른 포트");
        assert!(f.on_send((1, "198.51.100.9".into(), 443), t), "다른 주소");
        assert!(!f.on_send(k(1, 443), t + SEC));
    }

    #[test]
    fn a_reused_pid_does_not_inherit_the_old_flow() {
        let mut f = UdpFlows::new();
        let t = 9_000 * SEC;
        assert!(f.on_send(k(77, 443), t));
        assert!(f.on_send(k(78, 443), t));
        // 77번이 끝나고 새 프로세스가 같은 번호로 시작해 10초 뒤 같은 곳에 보낸다 — 새 프로세스의 접속이 남아야 한다
        f.forget_pid(77);
        assert!(f.on_send(k(77, 443), t + 10 * SEC));
        // 다른 프로세스의 흐름은 그대로
        assert!(!f.on_send(k(78, 443), t + 10 * SEC));
    }

    #[test]
    fn many_destinations_never_hide_a_connection_and_memory_is_bounded() {
        // 목적지를 끝없이 바꿔 보내도(훑기) 목적지마다 접속이 남고, 기억은 상한을 넘지 않는다
        let mut f = UdpFlows::new();
        let t = 100_000 * SEC;
        for i in 0..(MAX_FLOWS as u32 * 3) {
            let key = (
                5,
                format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255),
                9,
            );
            assert!(f.on_send(key, t + i as i64), "새 목적지 {i}");
            assert!(f.len() <= MAX_FLOWS);
        }
        // 모두 같은 시각이어도(통째로 비우는 길) 상한을 지킨다
        let mut g = UdpFlows::new();
        for i in 0..(MAX_FLOWS as u32 + 10) {
            assert!(g.on_send((5, format!("10.9.{}.{}", i >> 8, i & 255), 9), t));
            assert!(g.len() <= MAX_FLOWS);
        }
    }

    #[test]
    fn a_clock_step_backwards_does_not_freeze_the_flow() {
        let mut f = UdpFlows::new();
        let t = 50_000 * SEC;
        assert!(f.on_send(k(1, 443), t));
        // 시계가 한 시간 뒤로 갔다
        let back = t - 3600 * SEC;
        assert!(!f.on_send(k(1, 443), back));
        // 그 뒤 60초 쉬면 새 접속(뒤로 간 시각 기준으로 잰다 — 옛 시각에 묶여 한 시간 동안 못 남기지 않는다)
        assert!(f.on_send(k(1, 443), back + 61 * SEC));
    }
}
