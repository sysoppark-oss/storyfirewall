//! 주소 예약어 (`lan`, `internet`) 와 CIDR → 범위
//!
//! WFP 는 같은 필드의 조건을 OR 로 묶으므로 `internet` 은 "사설이 아님" 이 아니라
//! 공인 범위들의 OR 로 써야 한다 (6차 검증 Q1). IPv6 는 전역 유니캐스트 2000::/3.

use policy::spec::{V4Range, V6Prefix};
use std::net::{Ipv4Addr, Ipv6Addr};

fn r(lo: [u8; 4], hi: [u8; 4]) -> V4Range {
    V4Range { lo: Ipv4Addr::from(lo), hi: Ipv4Addr::from(hi) }
}

/// 사설·링크로컬·CGNAT (RFC 1918, 3927, 6598)
pub fn lan_v4() -> Vec<V4Range> {
    vec![
        r([10, 0, 0, 0], [10, 255, 255, 255]),
        r([100, 64, 0, 0], [100, 127, 255, 255]),
        r([169, 254, 0, 0], [169, 254, 255, 255]),
        r([172, 16, 0, 0], [172, 31, 255, 255]),
        r([192, 168, 0, 0], [192, 168, 255, 255]),
    ]
}

pub fn lan_v6() -> Vec<V6Prefix> {
    vec![
        V6Prefix { addr: "fc00::".parse().unwrap(), prefix: 7 },  // ULA
        V6Prefix { addr: "fe80::".parse().unwrap(), prefix: 10 }, // link-local
    ]
}

/// 공인 IPv4: 0/8·10/8·100.64/10·127/8·169.254/16·172.16/12·192.0.0/24·192.0.2/24·192.88.99/24·
/// 192.168/16·198.18/15·198.51.100/24·203.0.113/24·224/4·240/4 를 뺀 나머지의 OR
pub fn internet_v4() -> Vec<V4Range> {
    let excluded: Vec<V4Range> = vec![
        r([0, 0, 0, 0], [0, 255, 255, 255]),
        r([10, 0, 0, 0], [10, 255, 255, 255]),
        r([100, 64, 0, 0], [100, 127, 255, 255]),
        r([127, 0, 0, 0], [127, 255, 255, 255]),
        r([169, 254, 0, 0], [169, 254, 255, 255]),
        r([172, 16, 0, 0], [172, 31, 255, 255]),
        r([192, 0, 0, 0], [192, 0, 0, 255]),
        r([192, 0, 2, 0], [192, 0, 2, 255]),
        r([192, 88, 99, 0], [192, 88, 99, 255]),
        r([192, 168, 0, 0], [192, 168, 255, 255]),
        r([198, 18, 0, 0], [198, 19, 255, 255]),
        r([198, 51, 100, 0], [198, 51, 100, 255]),
        r([203, 0, 113, 0], [203, 0, 113, 255]),
        r([224, 0, 0, 0], [255, 255, 255, 255]), // 멀티캐스트 + 클래스 E + 브로드캐스트
    ];
    let mut out = Vec::new();
    let mut cursor: u64 = 0; // 다음 공인 시작 (u32 범위를 넘을 수 있어 u64)
    for e in &excluded {
        let lo = u32::from(e.lo) as u64;
        let hi = u32::from(e.hi) as u64;
        if lo > cursor {
            out.push(V4Range { lo: Ipv4Addr::from(cursor as u32), hi: Ipv4Addr::from((lo - 1) as u32) });
        }
        cursor = hi + 1;
    }
    if cursor <= u32::MAX as u64 {
        out.push(V4Range { lo: Ipv4Addr::from(cursor as u32), hi: Ipv4Addr::from(u32::MAX) });
    }
    out
}

pub fn internet_v6() -> Vec<V6Prefix> {
    vec![V6Prefix { addr: "2000::".parse().unwrap(), prefix: 3 }]
}

/// "1.2.3.4" | "1.2.3.0/24" | "2001:db8::/32" → 범위. 예약어는 호출자가 먼저 처리.
pub fn parse_addr(s: &str) -> Option<(Vec<V4Range>, Vec<V6Prefix>)> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (s, None),
    };
    if let Ok(v4) = addr.parse::<Ipv4Addr>() {
        let p = prefix.unwrap_or(32);
        if p > 32 {
            return None;
        }
        let base = u32::from(v4);
        let mask = if p == 0 { 0 } else { u32::MAX << (32 - p as u32) };
        let lo = base & mask;
        let hi = lo | !mask;
        return Some((vec![V4Range { lo: Ipv4Addr::from(lo), hi: Ipv4Addr::from(hi) }], vec![]));
    }
    if let Ok(v6) = addr.parse::<Ipv6Addr>() {
        let p = prefix.unwrap_or(128);
        if p > 128 {
            return None;
        }
        return Some((vec![], vec![V6Prefix { addr: v6, prefix: p }]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internet_v4_excludes_private_and_covers_rest() {
        let v = internet_v4();
        let contains = |ip: &str| {
            let x: Ipv4Addr = ip.parse().unwrap();
            v.iter().any(|r| r.lo <= x && x <= r.hi)
        };
        assert!(contains("8.8.8.8"));
        assert!(contains("185.199.108.153"));
        assert!(contains("1.0.0.1"));
        assert!(contains("223.255.255.255"));
        assert!(!contains("10.1.2.3"));
        assert!(!contains("192.168.0.1"));
        assert!(!contains("127.0.0.1"));
        assert!(!contains("169.254.1.1"));
        assert!(!contains("100.64.0.1"));
        assert!(!contains("224.0.0.1"));
        assert!(!contains("0.0.0.0"));
        // 범위가 겹치지 않고 오름차순
        for w in v.windows(2) {
            assert!(w[0].hi < w[1].lo);
        }
    }

    #[test]
    fn parses_cidr() {
        let (v4, _) = parse_addr("192.168.1.0/24").unwrap();
        assert_eq!(v4[0].lo, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(v4[0].hi, Ipv4Addr::new(192, 168, 1, 255));
        let (v4, _) = parse_addr("8.8.8.8").unwrap();
        assert_eq!(v4[0].lo, v4[0].hi);
        let (_, v6) = parse_addr("2001:db8::/32").unwrap();
        assert_eq!(v6[0].prefix, 32);
        assert!(parse_addr("nope").is_none());
        assert!(parse_addr("1.2.3.4/33").is_none());
    }
}
