//! UDP 송신을 "흐름" 단위로 본다 — 접속 선을 언제 새로 만들지 정한다(Ingester 가 쓴다).
//!
//! TCP 는 연결이 있어 연결마다 접속 선 하나다. UDP 는 연결이 없어 수집기가 "같은 목적지 1초 안 반복"만 거르고
//! 나머지 송신을 모두 접속 이벤트로 보낸다. 그것을 그대로 선으로 만들면 이어지는 UDP 흐름(사설망 터널, QUIC, 원격 접속)
//! 하나가 초당 선 하나가 된다 — 노트북에서 접속 선 162만 개 중 156만 개(96%)가 UDP 였고 한 짝에 8만 7천 개가 쌓였다(diag-273).
//!
//! 규칙: (프로세스 노드, 원격 주소, 원격 포트)가 같고 **그 주소에 붙는 도메인도 같은** 송신은
//! - `IDLE` 넘게 쉬었다가 다시 보낼 때 새 접속으로 보고,
//! - 쉬지 않고 이어지더라도 `REFRESH` 마다 한 번은 접속으로 남긴다(며칠 이어지는 흐름이 첫날 선 하나로만 남아
//!   보관 정리 뒤 사라지지 않게, "지금도 이어지고 있다"가 그래프에 보이게).
//!
//! 왜 수집기가 아니라 여기인가(별도 검수 지적 — 수집기에서 걸렀던 첫 구현의 문제):
//! - 수집기는 프로세스를 번호(pid)로만 안다. 번호는 재사용되고 시작 이벤트는 접속보다 늦게 올 수 있다. 여기서는 프로세스 노드(번호 + 생성 시각)다.
//! - 수집기가 "남겼다"고 적은 뒤 이벤트가 버려지면(속도 제한·채널 가득) 한 시간 동안 다시 안 나온다. 여기서는 **선을 실제로 넣은 뒤에만** 적는다.
//! - 같은 주소:포트 뒤의 다른 도메인(공유 CDN)은 도메인을 아는 여기서만 가를 수 있다.
//! - 이어지는 송신도 이벤트는 계속 오므로, 서비스 경유 귀속("직전 사용자 접속")의 재료가 전과 같다.
//!
//! 묶지 않는 것: 시스템 서비스의 접속(DNS 전송 제외) — 선마다 귀속 판단을 받아야 한다(ingest.rs `udp_continuation`).
//! 줄지 않는 경우: 같은 주소에 두 이름이 번갈아 조회되면 송신마다 새 접속이 된다(전과 같다 — 나빠지지 않을 뿐).
//! 달라지는 값: 이어지는 동안 원격지 노드의 `last_ts`·접속 횟수는 다음 선(길어야 한 시간 뒤)에서야 오른다.
//! UDP 의 "접속 횟수"는 송신 수가 아니라 흐름 수다.
//! 잃는 것: `IDLE` 보다 짧은 주기로 되풀이되는 UDP 송신은 선 하나로 보인다(주기 분석의 재료가 준다).
//! 보낸 양은 흐름과 무관하게 따로 쌓인다(용량 카운터). 시각은 Windows FILETIME(100ns 단위).

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
/// 정리한 뒤 이만큼의 빈자리는 남긴다 — 가득 찬 채로 송신마다 전체를 훑지 않게
const HEADROOM: usize = 1024;

/// (프로세스 노드 id, 원격 주소, 원격 포트)
pub type Key = (i64, String, u16);

#[derive(Debug, Clone)]
struct Flow {
    /// 마지막으로 본 송신
    last_seen: i64,
    /// 마지막으로 접속 선을 남긴 때
    last_emit: i64,
    /// 선을 남길 때 그 주소에 붙어 있던 도메인(직전 DNS 응답 기준)
    domain: Option<String>,
}

#[derive(Debug, Default)]
pub struct UdpFlows {
    flows: HashMap<Key, Flow>,
}

impl UdpFlows {
    pub fn new() -> Self {
        Self::default()
    }

    /// 이 송신이 이미 선으로 남긴 흐름의 이어짐인가. 이어짐이면 "마지막으로 본 때"만 고치고 true —
    /// 부르는 쪽은 선을 만들지 않는다. false 면 아무것도 바꾸지 않는다(선을 넣은 뒤 `emitted` 를 불러야 기억된다).
    pub fn continues(&mut self, key: &Key, ts: i64, domain: Option<&str>) -> bool {
        let Some(f) = self.flows.get_mut(key) else {
            return false;
        };
        // 시계가 뒤로 갔으면(ts < 기억한 시각) 이어짐으로 보지 않는다 — 새로 남기고 그 시각부터 다시 잰다
        if ts < f.last_seen || ts < f.last_emit {
            return false;
        }
        if ts.saturating_sub(f.last_seen) >= IDLE
            || ts.saturating_sub(f.last_emit) >= REFRESH
            || f.domain.as_deref() != domain
        {
            return false;
        }
        f.last_seen = ts;
        true
    }

    /// 접속 선을 **넣은 뒤** 부른다
    pub fn emitted(&mut self, key: Key, ts: i64, domain: Option<&str>) {
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            self.shrink(ts);
        }
        self.flows.insert(
            key,
            Flow {
                last_seen: ts,
                last_emit: ts,
                domain: domain.map(str::to_string),
            },
        );
    }

    /// 프로세스가 끝났다 — 그 프로세스 노드의 흐름을 잊는다
    pub fn forget_proc(&mut self, proc_node: i64) {
        self.flows.retain(|k, _| k.0 != proc_node);
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// 가득 찼을 때: 이미 끝난 흐름(IDLE 넘게 쉼)을 버리고, 빈자리가 HEADROOM 에 못 미치면 쉰 지 오래된 절반을 버린다
    fn shrink(&mut self, now: i64) {
        self.flows
            .retain(|_, f| now.saturating_sub(f.last_seen) < IDLE);
        if self.flows.len() + HEADROOM > MAX_FLOWS {
            let mut seen: Vec<i64> = self.flows.values().map(|f| f.last_seen).collect();
            let mid = seen.len() / 2;
            seen.select_nth_unstable(mid);
            let cut = seen[mid];
            self.flows.retain(|_, f| f.last_seen > cut);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(p: i64, port: u16) -> Key {
        (p, "203.0.113.7".to_string(), port)
    }

    /// Ingester 가 하는 대로: 이어짐이 아니면 선을 넣고(true) 기억한다
    fn send(f: &mut UdpFlows, key: Key, ts: i64, domain: Option<&str>) -> bool {
        if f.continues(&key, ts, domain) {
            return false;
        }
        f.emitted(key, ts, domain);
        true
    }

    #[test]
    fn a_continuous_flow_is_one_connection_until_refresh() {
        let mut f = UdpFlows::new();
        let t0 = 1_000_000 * SEC;
        assert!(send(&mut f, k(1, 443), t0, None), "첫 송신은 접속");
        // 한 시간 동안 초당 한 번 — 전에는 3600개의 선이 생겼다
        let n = (1..3600)
            .filter(|s| send(&mut f, k(1, 443), t0 + s * SEC, None))
            .count();
        assert_eq!(n, 0);
        // 경계: 한 시간에서 한 틱 모자라면 아직, 정확히 한 시간이면 남긴다
        assert!(!send(&mut f, k(1, 443), t0 + REFRESH - 1, None));
        assert!(send(&mut f, k(1, 443), t0 + REFRESH, None));
        assert!(!send(&mut f, k(1, 443), t0 + REFRESH + SEC, None));
        // 하루 내내 이어지면 하루에 24개 안팎
        let day = (3602..86_400)
            .filter(|s| send(&mut f, k(1, 443), t0 + s * SEC, None))
            .count();
        assert_eq!(day, 22);
    }

    #[test]
    fn a_pause_of_idle_or_longer_starts_a_new_connection() {
        let mut f = UdpFlows::new();
        let t0 = 5_000 * SEC;
        assert!(send(&mut f, k(1, 53), t0, None));
        // 경계: 60초에서 한 틱 모자라면 같은 흐름, 정확히 60초면 새 접속
        assert!(!send(&mut f, k(1, 53), t0 + IDLE - 1, None));
        assert!(send(&mut f, k(1, 53), t0 + IDLE - 1 + IDLE, None));
        // 쉰 시간은 마지막 송신부터 잰다(처음 송신부터가 아니다)
        let t1 = t0 + 2 * IDLE;
        assert!(!send(&mut f, k(1, 53), t1 + 50 * SEC, None));
        assert!(!send(&mut f, k(1, 53), t1 + 100 * SEC, None));
        // 5분마다 한 번 보내는 것은 매번 새 접속으로 남는다
        let n = (1..=10)
            .filter(|i| send(&mut f, k(1, 53), t1 + 100 * SEC + i * 300 * SEC, None))
            .count();
        assert_eq!(n, 10);
    }

    #[test]
    fn different_process_port_address_or_domain_are_different_flows() {
        let mut f = UdpFlows::new();
        let t = 9_000 * SEC;
        assert!(send(&mut f, k(1, 443), t, Some("cdn.legit.example")));
        assert!(
            send(&mut f, k(2, 443), t, Some("cdn.legit.example")),
            "다른 프로세스"
        );
        assert!(
            send(&mut f, k(1, 444), t, Some("cdn.legit.example")),
            "다른 포트"
        );
        assert!(
            send(
                &mut f,
                (1, "198.51.100.9".into(), 443),
                t,
                Some("cdn.legit.example")
            ),
            "다른 주소"
        );
        assert!(!send(&mut f, k(1, 443), t + SEC, Some("cdn.legit.example")));
        // 같은 주소:포트라도 그 주소에 붙는 도메인이 바뀌었으면 새 접속(공유 CDN 뒤의 다른 이름 — 별도 검수 지적 2)
        assert!(send(
            &mut f,
            k(1, 443),
            t + 2 * SEC,
            Some("c2.evil.example")
        ));
        assert!(!send(
            &mut f,
            k(1, 443),
            t + 3 * SEC,
            Some("c2.evil.example")
        ));
        // 도메인이 없어진 것(None)도 다른 것으로 본다
        assert!(send(&mut f, k(1, 443), t + 4 * SEC, None));
    }

    #[test]
    fn nothing_is_remembered_until_the_edge_is_stored() {
        // 선을 넣지 못했으면(이벤트가 버려지거나 저장 실패) 기억하지 않는다 — 다음 송신이 다시 접속으로 남는다(별도 검수 지적 1)
        let mut f = UdpFlows::new();
        let t = 9_000 * SEC;
        assert!(!f.continues(&k(1, 443), t, None));
        // emitted 를 부르지 않았다
        assert!(!f.continues(&k(1, 443), t + SEC, None));
        assert!(f.is_empty());
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
            assert!(send(&mut f, key, t + i as i64, None), "새 목적지 {i}");
            assert!(f.len() <= MAX_FLOWS);
        }
        // 모두 같은 시각이어도 상한을 지킨다
        let mut g = UdpFlows::new();
        for i in 0..(MAX_FLOWS as u32 + 10) {
            assert!(send(
                &mut g,
                (5, format!("10.9.{}.{}", i >> 8, i & 255), 9),
                t,
                None
            ));
            assert!(g.len() <= MAX_FLOWS);
        }
    }

    #[test]
    fn shrinking_leaves_headroom() {
        // 가득 찬 채로 송신마다 전체를 훑지 않는다: 한 번 정리하면 빈자리가 HEADROOM 넘게 남는다(별도 검수 지적 6)
        let mut f = UdpFlows::new();
        let t = 100_000 * SEC;
        // 모두 아직 살아 있는 흐름(IDLE 안)으로 가득 채운다
        for i in 0..MAX_FLOWS as u32 {
            f.emitted(
                (
                    5,
                    format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255),
                    9,
                ),
                t + i as i64,
                None,
            );
        }
        assert_eq!(f.len(), MAX_FLOWS);
        f.emitted((6, "192.0.2.1".into(), 9), t + MAX_FLOWS as i64, None);
        assert!(f.len() + HEADROOM <= MAX_FLOWS, "{}", f.len());
    }

    #[test]
    fn a_clock_step_backwards_starts_over() {
        let mut f = UdpFlows::new();
        let t = 50_000 * SEC;
        assert!(send(&mut f, k(1, 443), t, None));
        // 시계가 한 시간 뒤로 갔다 — 이어짐으로 보지 않고 새로 남긴 뒤 그 시각부터 다시 잰다
        let back = t - 3600 * SEC;
        assert!(send(&mut f, k(1, 443), back, None));
        assert!(!send(&mut f, k(1, 443), back + 30 * SEC, None));
        assert!(send(&mut f, k(1, 443), back + 30 * SEC + IDLE, None));
        // 극단 시각에서도 넘치지 않는다
        assert!(send(&mut f, k(1, 443), i64::MAX, None));
        assert!(send(&mut f, k(1, 443), i64::MIN, None));
        assert!(send(&mut f, k(1, 443), 0, None));
    }
}
