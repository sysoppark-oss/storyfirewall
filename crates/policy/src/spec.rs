//! 필터 명세 (DSL 의 match 를 WFP 조건으로 펼친 단위)
//!
//! WFP 규칙 (6차 검증 Q1): 같은 필드의 조건 여러 개는 OR, 다른 필드끼리는 AND. 그래서 목록형 필드는
//! 한 필터 안에서 OR 로 묶이고, "~이 아님" 은 표현할 수 없다 (NOT_EQUAL 다중 OR 는 항상 참).
//! 그 예외(`process_not`·`allow`)는 우리 Sublayer 안의 permit 필터로 푼다 (6차 검증 Q2). permit 은
//! 같은 Sublayer 의 우리 block 만 이기고 다른 Sublayer(Defender)의 block 은 못 이긴다.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Out,
    In,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    /// 우리 Sublayer 안의 예외. 다른 Sublayer 에 영향 없음. CLEAR_ACTION_RIGHT 사용 안 함.
    Permit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4Range {
    pub lo: Ipv4Addr,
    pub hi: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct V6Prefix {
    pub addr: Ipv6Addr,
    pub prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

/// 필터 하나. 같은 필드 안의 목록은 OR. 조건이 모두 비면 "전체"이므로 가드가 거부한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSpec {
    pub name: String,
    #[serde(default = "default_action")]
    pub action: Action,
    pub direction: Direction,
    /// 실행 파일 Win32 경로 (ALE_APP_ID). 8.3·링크는 호출 전에 긴 경로로 정규화 (5차 검증 Q3)
    pub app_path: Option<String>,
    /// 원격 IPv4 범위들 (OR). 비면 조건 없음
    #[serde(default)]
    pub remote_v4: Vec<V4Range>,
    /// 원격 IPv6 프리픽스들 (OR). `internet` 은 2000::/3 (6차 검증 2-3)
    #[serde(default)]
    pub remote_v6: Vec<V6Prefix>,
    /// ACL: 이 PC 쪽 주소(FWPM_CONDITION_IP_LOCAL_ADDRESS). 비면 조건 없음
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_v4: Vec<V4Range>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_v6: Vec<V6Prefix>,
    /// ACL: 네트워크 인터페이스 별칭(예: "Wi-Fi"). 적용할 때 LUID 로 바꾼다(FWPM_CONDITION_IP_LOCAL_INTERFACE).
    /// 없는 이름이면 적용이 실패한다(조용히 넓은 필터가 되지 않게)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default)]
    pub remote_ports: Vec<PortRange>,
    #[serde(default)]
    pub local_ports: Vec<PortRange>,
    /// 6 TCP / 17 UDP (OR). ICMP(1·58)는 가드가 거부
    #[serde(default)]
    pub protocols: Vec<u8>,
    /// permit 은 block 보다 높은 weight 로 (같은 Sublayer 안에서만 의미)
    #[serde(default)]
    pub weight: Option<u64>,
    /// 이 명세가 만들 필터의 주소 체계. None = 조건에 따라 V4·V6 둘 다(필터 2개).
    /// A26 접점 결함: 정책 엔진은 "명세 1개 = 필터 1개"로 ID 를 저장하는데 실제 WFP 는 주소 조건 없는 명세를 V4·V6 두 필터로 만든다.
    /// 엔진은 백엔드에 넘기기 전에 `split_family` 로 나눠 1:1 을 지킨다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_family: Option<IpFamily>,
    /// 긴급 차단(대시보드 개편안 3판 1-1) 필터: 전용 Sublayer, 영구(PERSISTENT) 아님 — 재부팅하면 풀린다(안전판).
    /// 전용 Sublayer 라 이 안의 허용(예외)은 다른 Sublayer 의 차단(끊기 등)을 뚫지 못한다.
    #[serde(default, skip_serializing_if = "is_false")]
    pub emergency: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    V4,
    V6,
}

/// WFP weight 구간(같은 Sublayer 안에서 높은 weight 가 먼저 판정, 첫 종결 동작이 이긴다).
/// - 번호 없는 차단(끊기·첫 실행 관찰·주소 차단·직접 쓴 정책): FWP_UINT8 범위 식별자 14 → [14·2^60, 15·2^60).
///   전에는 FWP_EMPTY(자동, [0, 2^60))였는데 ACL 명시 weight(≈2^63)보다 낮아 ACL "허용" 한 줄이 끊기 차단을 이겼다
///   (37차 의뢰서 Q1 작성 중 발견, Microsoft Learn "Filter Weight Assignment" 로 범위 확인).
/// - 번호 없는 허용(process_not 예외): 0xF000_0000_0000_0000 — 같은 정책의 차단(구간 14)보다 위.
/// - ACL 번호 n: `ACL_WEIGHT_TOP − n<<40` — 늘 구간 14 아래(ACL 허용은 보안 차단을 뚫지 못한다).
///   37차 Q1① 뒤로 ACL 은 따로 ACL Sublayer 에 들어간다(wfp::ACL_SUBLAYER_KEY) — 구간 비교는 같은 Sublayer 안에서만 뜻이 있고,
///   Sublayer 사이에서는 차단이 이긴다. 그래도 구간은 그대로 둔다(옛 필터·가짜 백엔드와의 호환).
pub const BLOCK_RANGE_ID: u8 = 14;
pub const PERMIT_DEFAULT_WEIGHT: u64 = 0xF000_0000_0000_0000;
pub const ACL_WEIGHT_TOP: u64 = 0x8000_0000_0000_0000;

fn default_action() -> Action {
    Action::Block
}

impl BlockSpec {
    pub fn app(name: &str, path: &str, direction: Direction) -> Self {
        Self {
            name: name.into(),
            action: Action::Block,
            direction,
            app_path: Some(path.into()),
            remote_v4: Vec::new(),
            remote_v6: Vec::new(),
            local_v4: Vec::new(),
            local_v6: Vec::new(),
            interface: None,
            remote_ports: Vec::new(),
            local_ports: Vec::new(),
            protocols: Vec::new(),
            weight: None,
            ip_family: None,
            emergency: false,
        }
    }

    /// 앱·주소·포트 조건이 하나도 없으면 PC 전체 차단이다. 프로토콜만 있는 것("tcp 전부")도 전체 차단으로 본다
    /// (A11 테스트에서 발견: dsl 이 any → [6,17] 을 넣어 가드를 통과했음).
    pub fn is_empty_match(&self) -> bool {
        self.app_path.is_none()
            && self.remote_v4.is_empty()
            && self.remote_v6.is_empty()
            && self.local_v4.is_empty()
            && self.local_v6.is_empty()
            && self.interface.is_none()
            && self.remote_ports.is_empty()
            && self.local_ports.is_empty()
    }

    /// 주소 조건(상대·이 PC)에 IPv4·IPv6 가 있는가. 한쪽 체계 주소만 있으면 그 체계 필터만 만든다 —
    /// 다른 체계 필터는 주소 조건이 빠져 의도보다 넓게 막기 때문이다(ACL 이 PC IP 추가 때 발견)
    fn has_v4(&self) -> bool {
        !self.remote_v4.is_empty() || !self.local_v4.is_empty()
    }
    fn has_v6(&self) -> bool {
        !self.remote_v6.is_empty() || !self.local_v6.is_empty()
    }

    /// IPv4 조건만 있는 명세는 V6 계층에 만들지 않는다 (주소 체계가 다름). 둘 다 없으면 양쪽.
    pub fn wants_v4(&self) -> bool {
        match self.ip_family {
            Some(f) => f == IpFamily::V4,
            None => self.has_v4() || !self.has_v6(),
        }
    }
    pub fn wants_v6(&self) -> bool {
        match self.ip_family {
            Some(f) => f == IpFamily::V6,
            None => self.has_v6() || !self.has_v4(),
        }
    }

    /// 필터 1개씩으로 나눈다: 결과의 각 명세는 정확히 한 주소 체계(= WFP 필터 1개)
    pub fn split_family(&self) -> Vec<BlockSpec> {
        let mut out = Vec::new();
        for (want, fam) in [
            (self.wants_v4(), IpFamily::V4),
            (self.wants_v6(), IpFamily::V6),
        ] {
            if want {
                let mut s = self.clone();
                s.ip_family = Some(fam);
                out.push(s);
            }
        }
        out
    }

    /// 이 명세가 만들 WFP 필터 수 (0~2)
    pub fn filter_count(&self) -> usize {
        self.wants_v4() as usize + self.wants_v6() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A26 접점: 명세 하나가 WFP 필터 몇 개가 되는지와 split_family 가 1:1 로 나누는지
    #[test]
    fn split_family_makes_one_filter_per_spec() {
        let app = BlockSpec::app("x", r"C:\a\b.exe", Direction::Out);
        assert_eq!(app.filter_count(), 2, "주소 조건 없음 = V4·V6");
        let parts = app.split_family();
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|p| p.filter_count() == 1));
        assert_eq!((parts[0].wants_v4(), parts[0].wants_v6()), (true, false));
        assert_eq!((parts[1].wants_v4(), parts[1].wants_v6()), (false, true));
        // IPv4 주소만 있으면 V4 하나
        let mut v4 = app.clone();
        v4.remote_v4.push(V4Range {
            lo: Ipv4Addr::new(10, 0, 0, 1),
            hi: Ipv4Addr::new(10, 0, 0, 1),
        });
        assert_eq!(v4.filter_count(), 1);
        assert_eq!(v4.split_family().len(), 1);
        // 나눈 명세를 다시 나눠도 그대로 (저장된 행 재등록)
        assert_eq!(parts[0].split_family(), vec![parts[0].clone()]);
        // 예전 저장 형식(ip_family 없음)도 읽힌다
        let old = serde_json::to_string(&app).unwrap();
        assert!(!old.contains("ip_family"));
        let back: BlockSpec = serde_json::from_str(&old).unwrap();
        assert_eq!(back.filter_count(), 2);
        assert!(
            !old.contains("local_v4") && !old.contains("interface"),
            "새 필드는 비면 저장하지 않는다"
        );
        // ACL: 이 PC IPv4 만 있으면 V4 필터 하나(V6 필터는 주소 조건이 빠져 넓어지므로 만들지 않는다)
        let mut l4 = app.clone();
        l4.local_v4.push(V4Range {
            lo: Ipv4Addr::new(192, 168, 0, 10),
            hi: Ipv4Addr::new(192, 168, 0, 10),
        });
        assert_eq!((l4.wants_v4(), l4.wants_v6()), (true, false));
        // 인터페이스만 있으면 PC 전체가 아니다
        // weight 구간: ACL 최상위(번호 1)도 번호 없는 차단 구간의 바닥보다 낮다
        assert!(ACL_WEIGHT_TOP - (1u64 << 40) < (u64::from(BLOCK_RANGE_ID) << 60));
        assert!(PERMIT_DEFAULT_WEIGHT >= (u64::from(BLOCK_RANGE_ID) + 1) << 60);
        let mut ifc = BlockSpec::app("y", "", Direction::Out);
        ifc.app_path = None;
        assert!(ifc.is_empty_match());
        ifc.interface = Some("Wi-Fi".into());
        assert!(!ifc.is_empty_match());
    }
}
