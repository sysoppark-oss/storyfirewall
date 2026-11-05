//! 가드 (명세 4판 3장 규칙 8·9, 5차 검증 Q7): 엔진에 닿기 전에 거부한다. 순수 로직이라 Linux 에서 테스트.
//!
//! 거부 대상 (하드코딩, 사용자도 끌 수 없음)
//! - 루프백 127/8 (::1 은 V6 미지원이므로 V4 만), DHCP UDP 67/68, ICMP(1·58)
//! - svchost.exe + 53 (Dnscache), svchost.exe + 123 (w32time)
//! - 우리 자신(서비스 실행 파일)과 보호 목록의 실행 파일 (러너 에이전트 등 호출자가 넘긴다)
//! - 조건이 하나도 없는 전체 차단 (규칙 3: PoC 에서는 거부, 제품에서는 명시 확인)

use crate::spec::BlockSpec;
use crate::{PolicyError, Result};

pub struct Guard {
    /// 절대 막지 않을 실행 파일 이름(소문자 파일명). 우리 자신 + 호출자가 넘긴 목록
    pub protected_images: Vec<String>,
}

fn file_name_lower(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_ascii_lowercase()
}

impl Guard {
    pub fn new(protected: &[&str]) -> Self {
        Self { protected_images: protected.iter().map(|s| s.to_ascii_lowercase()).collect() }
    }

    pub fn check(&self, s: &BlockSpec) -> Result<()> {
        if s.action == crate::spec::Action::Permit {
            return Ok(()); // 우리 Sublayer 안의 예외는 가드 대상이 아니다 (아무것도 막지 않음)
        }
        if s.is_empty_match() {
            return Err(PolicyError::Guard("조건 없음: PC 전체 통신 차단".into()));
        }
        if s.protocols.iter().any(|p| *p == 1 || *p == 58) {
            return Err(PolicyError::Guard("ICMP 는 차단하지 않는다 (규칙 8)".into()));
        }
        if s.remote_v4.iter().any(|r| r.lo.is_loopback() || r.hi.is_loopback() || (r.lo <= std::net::Ipv4Addr::new(127, 0, 0, 1) && r.hi >= std::net::Ipv4Addr::new(127, 0, 0, 1))) {
            return Err(PolicyError::Guard("루프백 차단 금지 (규칙 8)".into()));
        }
        if s.remote_v6.iter().any(|p| p.addr.is_loopback()) {
            return Err(PolicyError::Guard("루프백(::1) 차단 금지 (규칙 8)".into()));
        }
        let udp_possible = s.protocols.is_empty() || s.protocols.contains(&17);
        let covers = |ranges: &[crate::spec::PortRange], port: u16| ranges.iter().any(|r| r.lo <= port && port <= r.hi);
        if udp_possible && (covers(&s.remote_ports, 67) || covers(&s.remote_ports, 68) || covers(&s.local_ports, 67) || covers(&s.local_ports, 68)) {
            return Err(PolicyError::Guard("DHCP 67/68 차단 금지 (규칙 8)".into()));
        }
        if let Some(app) = &s.app_path {
            let name = file_name_lower(app);
            if self.protected_images.iter().any(|p| *p == name) {
                return Err(PolicyError::Guard(format!("보호 대상 실행 파일: {name}")));
            }
            if name == "svchost.exe" {
                if covers(&s.remote_ports, 53) || covers(&s.remote_ports, 123) {
                    return Err(PolicyError::Guard("svchost 의 DNS/NTP 차단 금지 (규칙 8)".into()));
                }
                if s.remote_ports.is_empty() && s.remote_v4.is_empty() && s.remote_v6.is_empty() {
                    return Err(PolicyError::Guard("svchost 광역 차단은 명시 확인 필요 (규칙 9) — PoC 는 거부".into()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{Direction, PortRange, V4Range};
    fn port(p: u16) -> PortRange {
        PortRange { lo: p, hi: p }
    }

    fn g() -> Guard {
        Guard::new(&["story-firewall-svc.exe", "Runner.Listener.exe", "Runner.Worker.exe"])
    }

    #[test]
    fn allows_plain_app_block() {
        assert!(g().check(&BlockSpec::app("t", r"C:\Windows\System32\curl.exe", Direction::Out)).is_ok());
    }

    #[test]
    fn rejects_rule8_cases() {
        let mut s = BlockSpec::app("t", r"C:\x\a.exe", Direction::Out);
        s.protocols = vec![1];
        assert!(g().check(&s).is_err(), "ICMP");
        let mut s = BlockSpec::app("t", r"C:\x\a.exe", Direction::Out);
        s.remote_v4 = vec![V4Range { lo: "127.0.0.1".parse().unwrap(), hi: "127.0.0.1".parse().unwrap() }];
        assert!(g().check(&s).is_err(), "loopback");
        let mut s = BlockSpec::app("t", r"C:\x\a.exe", Direction::Out);
        s.remote_ports = vec![port(67)];
        s.protocols = vec![17];
        assert!(g().check(&s).is_err(), "DHCP");
        let mut s = BlockSpec::app("t", r"C:\Windows\System32\svchost.exe", Direction::Out);
        s.remote_ports = vec![port(53)];
        assert!(g().check(&s).is_err(), "svchost+53");
        assert!(g().check(&BlockSpec::app("t", r"C:\Windows\System32\svchost.exe", Direction::Out)).is_err(), "svchost 광역");
        assert!(g().check(&BlockSpec::app("t", r"C:\a\Runner.Listener.exe", Direction::Out)).is_err(), "러너 에이전트");
        let mut empty = BlockSpec::app("t", "", Direction::Out);
        empty.app_path = None;
        assert!(g().check(&empty).is_err(), "전체 차단");
        // svchost 라도 특정 포트(80)는 허용 (정책 가능)
        let mut s = BlockSpec::app("t", r"C:\Windows\System32\svchost.exe", Direction::Out);
        s.remote_ports = vec![port(80)];
        assert!(g().check(&s).is_ok());
        // TCP 67 은 DHCP 가 아니다
        let mut s = BlockSpec::app("t", r"C:\x\a.exe", Direction::Out);
        s.remote_ports = vec![port(67)];
        s.protocols = vec![6];
        assert!(g().check(&s).is_ok());
    }
}
