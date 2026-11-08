//! 긴급 차단 필터 명세 (대시보드 개편안 3판 1-1). 순수 로직이라 Linux 에서 테스트.
//!
//! 모양: 전용 Sublayer(wfp::EMERGENCY_SUBLAYER_KEY) 안에
//! - 전체 차단(나가는·들어오는, IPv4·IPv6) — 가장 낮은 weight
//! - 예외 허용 — 그보다 높은 weight(PERMIT_DEFAULT_WEIGHT)
//!
//! 전용 Sublayer 라서 이 안의 허용은 다른 Sublayer(우리 차단·ACL·Windows 방화벽)의 차단을 뚫지 못한다.
//! 필터는 영구(PERSISTENT)가 아니다 — 서비스가 기한을 처리하지 못해도 재부팅하면 풀린다(PC 가 갇히지 않는 안전판).
//!
//! 예외(모두 프로세스·경로 한정, 3판 1-1)
//! - 루프백 127.0.0.0/8 · ::1 (양방향, 프로그램 무관 — 이 PC 안의 통신)
//! - svchost.exe ↔ 53 (DNS 클라이언트), svchost.exe ↔ DHCP 67/68 · DHCPv6 546/547
//! - 이 앱(서비스·화면 실행 파일), 사용자가 고른 원격 도구 경로 (양방향)
//! - RDP: 지금 접속한 원격 세션의 상대 IP 에서 들어오는 svchost.exe(TermService) 로컬 3389(TCP·UDP)만
//!
//! 한계(설정·승인 창 문구에 적는다)
//! - svchost.exe 는 여러 서비스가 같이 쓴다. 서비스 SID 조건(Dnscache·Dhcp·TermService)은 아직 걸지 않아
//!   "svchost.exe 의 53번" 은 Dnscache 가 아닌 svchost 서비스에도 열린다(추측: 실제 영향은 작음 — 53 은 DNS 뿐).
//! - RDP 예외는 승인할 때의 상대 IP 만 연다. 접속 IP 가 바뀌면 만료(또는 해제) 때까지 다시 들어올 수 없다.

use crate::spec::{Action, BlockSpec, Direction, PortRange, V4Range, V6Prefix, PERMIT_DEFAULT_WEIGHT};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 전체 차단 weight — 같은 Sublayer 안에서 예외(PERMIT_DEFAULT_WEIGHT)보다 늘 아래
pub const BLOCK_ALL_WEIGHT: u64 = 1;
pub const POLICY_NAME: &str = "긴급 차단";
pub const SVCHOST: &str = r"C:\Windows\System32\svchost.exe";

#[derive(Debug, Clone, Default)]
pub struct Input {
    /// 이 앱의 실행 파일(서비스·화면) 경로
    pub own_images: Vec<String>,
    /// 사용자가 고른 원격 도구 실행 파일 경로
    pub remote_tools: Vec<String>,
    /// 지금 접속한 RDP 세션의 상대 IP
    pub rdp_clients: Vec<IpAddr>,
}

fn base(name: &str, action: Action, direction: Direction) -> BlockSpec {
    let mut s = BlockSpec::app(name, "", direction);
    s.app_path = None;
    s.action = action;
    s.emergency = true;
    s
}

fn port(p: u16) -> PortRange {
    PortRange { lo: p, hi: p }
}

/// 긴급 차단 필터 명세. 같은 입력이면 같은 순서(테스트·승인 창 요약용)
pub fn plan(inp: &Input) -> Vec<BlockSpec> {
    let mut v = Vec::new();
    for dir in [Direction::Out, Direction::In] {
        let mut b = base("긴급 차단: 전체", Action::Block, dir);
        b.weight = Some(BLOCK_ALL_WEIGHT);
        v.push(b);
    }
    for dir in [Direction::Out, Direction::In] {
        let mut l4 = base("긴급 차단 예외: 루프백", Action::Permit, dir);
        l4.remote_v4 = vec![V4Range { lo: Ipv4Addr::new(127, 0, 0, 0), hi: Ipv4Addr::new(127, 255, 255, 255) }];
        l4.weight = Some(PERMIT_DEFAULT_WEIGHT);
        v.push(l4);
        let mut l6 = base("긴급 차단 예외: 루프백", Action::Permit, dir);
        l6.remote_v6 = vec![V6Prefix { addr: Ipv6Addr::LOCALHOST, prefix: 128 }];
        l6.weight = Some(PERMIT_DEFAULT_WEIGHT);
        v.push(l6);
    }
    // DNS 클라이언트(svchost Dnscache) → 53
    let mut dns = base("긴급 차단 예외: DNS", Action::Permit, Direction::Out);
    dns.app_path = Some(SVCHOST.into());
    dns.remote_ports = vec![port(53)];
    dns.protocols = vec![6, 17];
    dns.weight = Some(PERMIT_DEFAULT_WEIGHT);
    v.push(dns);
    // DHCP(v4 67/68, v6 546/547) — 나가는 쪽은 서버 포트, 들어오는 쪽은 이 PC 클라이언트 포트
    let mut dho = base("긴급 차단 예외: DHCP", Action::Permit, Direction::Out);
    dho.app_path = Some(SVCHOST.into());
    dho.remote_ports = vec![port(67), port(547)];
    dho.protocols = vec![17];
    dho.weight = Some(PERMIT_DEFAULT_WEIGHT);
    v.push(dho);
    let mut dhi = base("긴급 차단 예외: DHCP", Action::Permit, Direction::In);
    dhi.app_path = Some(SVCHOST.into());
    dhi.local_ports = vec![port(68), port(546)];
    dhi.protocols = vec![17];
    dhi.weight = Some(PERMIT_DEFAULT_WEIGHT);
    v.push(dhi);
    let mut seen = std::collections::BTreeSet::new();
    for (label, paths) in [("이 앱", &inp.own_images), ("원격 도구", &inp.remote_tools)] {
        for p in paths {
            let key = p.to_ascii_lowercase();
            if p.trim().is_empty() || !seen.insert(key) {
                continue;
            }
            for dir in [Direction::Out, Direction::In] {
                let mut a = base(&format!("긴급 차단 예외: {label}"), Action::Permit, dir);
                a.app_path = Some(p.clone());
                a.weight = Some(PERMIT_DEFAULT_WEIGHT);
                v.push(a);
            }
        }
    }
    let mut ips: Vec<IpAddr> = inp.rdp_clients.clone();
    ips.sort();
    ips.dedup();
    for ip in ips {
        if ip.is_unspecified() {
            continue;
        }
        let mut r = base("긴급 차단 예외: 원격 데스크톱", Action::Permit, Direction::In);
        r.app_path = Some(SVCHOST.into());
        r.local_ports = vec![port(3389)];
        r.protocols = vec![6, 17];
        match ip {
            IpAddr::V4(a) => r.remote_v4 = vec![V4Range { lo: a, hi: a }],
            IpAddr::V6(a) => r.remote_v6 = vec![V6Prefix { addr: a, prefix: 128 }],
        }
        r.weight = Some(PERMIT_DEFAULT_WEIGHT);
        v.push(r);
    }
    v
}

/// 승인 창·서비스 사건에 쓸 한 줄 요약들
pub fn summary(inp: &Input) -> Vec<String> {
    let mut l = vec![
        "나가는·들어오는 통신을 모두 차단합니다(이미 열린 연결도 다음 패킷 판정에서 끊길 수 있음)".to_string(),
        "예외: 이 PC 안 통신(루프백) · DNS · DHCP · 이 앱".to_string(),
    ];
    for t in &inp.remote_tools {
        l.push(format!("예외: 원격 도구 {t}"));
    }
    if inp.rdp_clients.is_empty() {
        l.push("원격 데스크톱 접속 없음 — 긴급 차단 중에는 원격 데스크톱으로 들어올 수 없습니다".to_string());
    } else {
        for ip in &inp.rdp_clients {
            l.push(format!("예외: 원격 데스크톱 {ip} → 이 PC 3389 (접속 IP 가 바뀌면 만료 때까지 다시 들어올 수 없습니다)"));
        }
    }
    l.push("재부팅하면 풀립니다(안전판). 60초 안에 [유지]를 누르지 않으면 자동으로 되돌립니다".to_string());
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inp() -> Input {
        Input {
            own_images: vec![
                r"C:\Program Files\Story Firewall\story-firewall-svc.exe".into(),
                r"C:\Program Files\Story Firewall\story-firewall-ui.exe".into(),
            ],
            remote_tools: vec![r"C:\Program Files\TeamViewer\TeamViewer.exe".into()],
            rdp_clients: vec!["203.0.113.7".parse().unwrap(), "2001:db8::5".parse().unwrap()],
        }
    }

    #[test]
    fn every_spec_is_emergency_and_block_all_is_lowest() {
        let v = plan(&inp());
        assert!(v.iter().all(|s| s.emergency));
        let blocks: Vec<_> = v.iter().filter(|s| s.action == Action::Block).collect();
        assert_eq!(blocks.len(), 2, "나가는·들어오는 전체 차단 2건");
        assert!(blocks.iter().all(|s| s.is_empty_match() && s.weight == Some(BLOCK_ALL_WEIGHT)));
        assert!(v
            .iter()
            .filter(|s| s.action == Action::Permit)
            .all(|s| s.weight.unwrap() > BLOCK_ALL_WEIGHT && !s.is_empty_match()));
    }

    #[test]
    fn permits_are_scoped() {
        let v = plan(&inp());
        // 프로그램 무관 허용은 루프백뿐
        for s in v.iter().filter(|s| s.action == Action::Permit && s.app_path.is_none()) {
            let lo4 = s.remote_v4.iter().all(|r| r.lo.is_loopback() && r.hi.octets()[0] == 127);
            let lo6 = s.remote_v6.iter().all(|p| p.addr.is_loopback());
            assert!(s.local_ports.is_empty() && s.remote_ports.is_empty() && lo4 && lo6, "{s:?}");
        }
        // svchost 허용은 늘 포트가 붙는다(광역 svchost 허용 없음)
        for s in v.iter().filter(|s| s.app_path.as_deref() == Some(SVCHOST)) {
            assert!(!s.remote_ports.is_empty() || !s.local_ports.is_empty(), "{s:?}");
        }
        // RDP: 들어오는 쪽, 로컬 3389, 상대 IP 정확히
        let rdp: Vec<_> = v.iter().filter(|s| s.local_ports.iter().any(|p| p.lo == 3389)).collect();
        assert_eq!(rdp.len(), 2);
        assert!(rdp.iter().all(|s| s.direction == Direction::In));
        assert!(rdp.iter().any(|s| s.remote_v4 == vec![V4Range { lo: "203.0.113.7".parse().unwrap(), hi: "203.0.113.7".parse().unwrap() }]));
        assert!(rdp.iter().any(|s| s.remote_v6.first().map(|p| p.prefix) == Some(128)));
        // 원격 도구·이 앱: 양방향 2건씩
        let tv = v.iter().filter(|s| s.app_path.as_deref().is_some_and(|p| p.ends_with("TeamViewer.exe"))).count();
        assert_eq!(tv, 2);
    }

    #[test]
    fn no_rdp_session_means_no_3389_and_summary_says_so() {
        let mut i = inp();
        i.rdp_clients.clear();
        assert!(!plan(&i).iter().any(|s| s.local_ports.iter().any(|p| p.lo == 3389)));
        assert!(summary(&i).iter().any(|l| l.contains("원격 데스크톱으로 들어올 수 없습니다")));
    }

    #[test]
    fn duplicate_paths_and_unspecified_ips_are_dropped() {
        let i = Input {
            own_images: vec![r"C:\A\x.exe".into(), r"c:\a\X.EXE".into(), "".into()],
            remote_tools: vec![r"C:\A\x.exe".into()],
            rdp_clients: vec!["0.0.0.0".parse().unwrap(), "198.51.100.1".parse().unwrap(), "198.51.100.1".parse().unwrap()],
        };
        let v = plan(&i);
        assert_eq!(v.iter().filter(|s| s.app_path.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(r"C:\A\x.exe"))).count(), 2);
        assert_eq!(v.iter().filter(|s| s.local_ports.iter().any(|p| p.lo == 3389)).count(), 1);
    }
}
