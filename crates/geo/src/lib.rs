//! 원격 주소의 "어디" — 주소 종류(로컬망·멀티캐스트 등) + 나라(DB-IP 위치 정보) + ASN(통신사·클라우드). 전부 오프라인.
//!
//! - 국가·ASN 은 DB-IP Lite MMDB(CC BY 4.0, 월 1회 갱신)를 설치 폴더에서 읽는다. 앱이 직접 내려받지 않는다
//!   (조회 IP 가 밖으로 나가지 않음 — 외부 전송 금지 원칙). DB 는 빌드 때 함께 넣고 앱 업데이트로 바꾼다.
//! - 나라는 DB-IP Lite 의 **위치 정보**(geolocation)다 — RIR 등록 국가가 아니다(2026-11-03 정정). CDN·클라우드·VPN 은 실제 서버 위치와 다를 수 있다.
//!   화면에는 "등록"·"추정"을 쓰지 않는다(D026 사용자 결정). 정확도 한계는 "어디" 칸 안내문에서 한 번 알린다.
//! - 국가가 아닌 주소(사설망·루프백·링크로컬·멀티캐스트·브로드캐스트·CGNAT·문서용)는 DB 를 보지 않고 종류로만 답한다.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::OnceLock;

use serde::Serialize;

mod names_ko;

/// 주소 종류
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Public,
    Loopback,
    /// 사설망(RFC 1918, fc00::/7)
    Private,
    /// 169.254/16, fe80::/10
    LinkLocal,
    /// 224/4, ff00::/8
    Multicast,
    /// 255.255.255.255 (사설망의 x.x.x.255 는 Private 로 둔다 — 마스크를 모름)
    Broadcast,
    /// 100.64/10 (통신사 NAT)
    Cgnat,
    /// 0.0.0.0, ::
    Unspecified,
    /// 문서·시험용 대역(192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32)
    Documentation,
}

impl Scope {
    /// 화면에 쓰는 짧은 이름 (Public 은 국가로 대신)
    pub fn label_ko(self) -> &'static str {
        match self {
            Scope::Public => "인터넷",
            Scope::Loopback => "이 PC",
            Scope::Private => "로컬망",
            Scope::LinkLocal => "로컬망(링크로컬)",
            Scope::Multicast => "멀티캐스트",
            Scope::Broadcast => "브로드캐스트",
            Scope::Cgnat => "통신사 NAT",
            Scope::Unspecified => "지정 안 됨",
            Scope::Documentation => "문서용 주소",
        }
    }
}

pub fn classify(ip: IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v) => classify_v4(v),
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            classify_v6(v)
        }
    }
}

fn classify_v4(v: Ipv4Addr) -> Scope {
    let o = v.octets();
    if v.is_unspecified() {
        Scope::Unspecified
    } else if v.is_loopback() {
        Scope::Loopback
    } else if v.is_broadcast() {
        Scope::Broadcast
    } else if v.is_multicast() {
        Scope::Multicast
    } else if v.is_link_local() {
        Scope::LinkLocal
    } else if v.is_private() {
        Scope::Private
    } else if o[0] == 100 && (o[1] & 0xC0) == 64 {
        Scope::Cgnat
    } else if (o[0], o[1], o[2]) == (192, 0, 2)
        || (o[0], o[1], o[2]) == (198, 51, 100)
        || (o[0], o[1], o[2]) == (203, 0, 113)
    {
        Scope::Documentation
    } else {
        Scope::Public
    }
}

fn classify_v6(v: Ipv6Addr) -> Scope {
    let s = v.segments();
    if v.is_unspecified() {
        Scope::Unspecified
    } else if v.is_loopback() {
        Scope::Loopback
    } else if v.is_multicast() {
        Scope::Multicast
    } else if (s[0] & 0xffc0) == 0xfe80 {
        Scope::LinkLocal
    } else if (s[0] & 0xfe00) == 0xfc00 {
        Scope::Private
    } else if s[0] == 0x2001 && s[1] == 0x0db8 {
        Scope::Documentation
    } else {
        Scope::Public
    }
}

/// 한 주소의 "어디"
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Where {
    pub scope: Scope,
    /// ISO 3166-1 alpha-2 (대문자). Public 이고 DB 에 있을 때만
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<String>,
    /// 한국어 국가 이름 (표에 없으면 코드)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// ASN 조직 이름 (DB 의 영문 그대로 — 외부에서 온 문자열이므로 화면은 텍스트로만 넣는다)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

impl Where {
    /// 짧은 설명: "대한민국", "미국 · Cloudflare, Inc. (AS13335)", "로컬망"
    pub fn label_ko(&self) -> String {
        match (&self.country, &self.org) {
            (Some(c), Some(o)) => format!(
                "{c} · {o}{}",
                self.asn.map(|a| format!(" (AS{a})")).unwrap_or_default()
            ),
            (Some(c), None) => c.clone(),
            (None, Some(o)) => o.clone(),
            (None, None) => self.scope.label_ko().to_string(),
        }
    }
}

/// 생성 표(names_ko)보다 먼저 보는 표기(디자인 D005). 정치적 판단을 하지 않고 국내에서 흔히 쓰는 중립 표기.
/// 지역·미정 코드(DB-IP·RIR 이 섞어 주는 EU·AP·ZZ)는 나라가 아니므로 "지역"·"지정 안 됨"
const NAMES_KO_OVERRIDES: &[(&str, &str)] = &[
    ("TW", "대만"),
    ("EU", "유럽(나라 미상)"),
    ("AP", "아시아·태평양(나라 미상)"),
    ("ZZ", "지정 안 됨"),
];

/// 나라가 아닌 코드(국기를 쓰지 않는다)
pub fn is_region_code(cc: &str) -> bool {
    matches!(cc.to_ascii_uppercase().as_str(), "EU" | "AP" | "ZZ")
}

pub fn country_name_ko(cc: &str) -> Option<&'static str> {
    let up = cc.to_ascii_uppercase();
    if let Some((_, v)) = NAMES_KO_OVERRIDES.iter().find(|(k, _)| *k == up) {
        return Some(v);
    }
    names_ko::NAMES_KO
        .iter()
        .find(|(k, _)| *k == up)
        .map(|(_, v)| *v)
}

#[derive(serde::Deserialize)]
struct CountryRec<'a> {
    #[serde(borrow)]
    country: Option<CountryInner<'a>>,
}
#[derive(serde::Deserialize)]
struct CountryInner<'a> {
    iso_code: Option<&'a str>,
}
#[derive(serde::Deserialize)]
struct AsnRec<'a> {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<&'a str>,
}

/// 국가·ASN DB. 둘 다 없어도 동작한다(종류만 답함)
#[derive(Default)]
pub struct Geo {
    country: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    /// DB 빌드 시각(유닉스 초) — 화면의 "데이터 기준일"
    pub country_built: Option<u64>,
    /// 시연·시험 데이터 전용 고정 답(svc 의 --demo). 제품 경로에서는 비어 있다
    overrides: std::collections::HashMap<IpAddr, Where>,
}

/// 파일 이름 (설치 폴더의 geo\ 아래)
pub const COUNTRY_FILE: &str = "dbip-country-lite.mmdb";
pub const ASN_FILE: &str = "dbip-asn-lite.mmdb";

impl Geo {
    /// `dir` 의 두 파일을 읽는다. 없거나 깨진 파일은 건너뛴다(오류를 돌려 기록하게 함)
    pub fn open_dir(dir: &Path) -> (Geo, Vec<String>) {
        let mut g = Geo::default();
        let mut errs = vec![];
        match maxminddb::Reader::open_readfile(dir.join(COUNTRY_FILE)) {
            Ok(r) => {
                g.country_built = Some(r.metadata().build_epoch);
                g.country = Some(r);
            }
            Err(e) => errs.push(format!("{COUNTRY_FILE}: {e}")),
        }
        match maxminddb::Reader::open_readfile(dir.join(ASN_FILE)) {
            Ok(r) => g.asn = Some(r),
            Err(e) => errs.push(format!("{ASN_FILE}: {e}")),
        }
        (g, errs)
    }

    /// 시연·시험용: 정해진 주소에 정해진 답 (러너 화면 캡처에 국가·긴 조직 이름 행을 보이려고)
    pub fn with_overrides(mut self, v: Vec<(IpAddr, Where)>) -> Self {
        self.overrides.extend(v);
        self
    }

    pub fn has_country(&self) -> bool {
        self.country.is_some()
    }

    pub fn lookup(&self, ip: IpAddr) -> Where {
        if let Some(w) = self.overrides.get(&ip) {
            return w.clone();
        }
        let scope = classify(ip);
        let mut w = Where {
            scope,
            cc: None,
            country: None,
            asn: None,
            org: None,
        };
        if scope != Scope::Public {
            return w;
        }
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        if let Some(r) = &self.country {
            if let Ok(res) = r.lookup(ip) {
                if let Ok(Some(rec)) = res.decode::<CountryRec>() {
                    if let Some(cc) = rec
                        .country
                        .and_then(|c| c.iso_code)
                        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
                    {
                        let up = cc.to_ascii_uppercase();
                        w.country = Some(
                            country_name_ko(&up)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| up.clone()),
                        );
                        w.cc = Some(up);
                    }
                }
            }
        }
        if let Some(r) = &self.asn {
            if let Ok(res) = r.lookup(ip) {
                if let Ok(Some(rec)) = res.decode::<AsnRec>() {
                    w.asn = rec.autonomous_system_number;
                    // 외부 문자열: 길이 제한·제어 문자 제거
                    w.org = rec
                        .autonomous_system_organization
                        .map(|o| {
                            o.chars()
                                .filter(|c| !c.is_control())
                                .take(80)
                                .collect::<String>()
                        })
                        .filter(|o| !o.is_empty());
                }
            }
        }
        w
    }

    /// 문자열 주소. 못 읽으면 None
    pub fn lookup_str(&self, ip: &str) -> Option<Where> {
        ip.trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
            .ok()
            .map(|a| self.lookup(a))
    }
}

static GLOBAL: OnceLock<Geo> = OnceLock::new();

/// 서비스 시작 때 한 번. 두 번째부터는 무시
pub fn init_global(g: Geo) {
    let _ = GLOBAL.set(g);
}

/// 초기화 전에는 빈 Geo(종류만)
pub fn global() -> &'static Geo {
    static EMPTY: OnceLock<Geo> = OnceLock::new();
    GLOBAL
        .get()
        .unwrap_or_else(|| EMPTY.get_or_init(Geo::default))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(ip: &str) -> Scope {
        classify(ip.parse().unwrap())
    }

    #[test]
    fn classifies_non_country_addresses_seen_on_the_laptop() {
        // 노트북 화면(2026-11-03)에 실제로 보인 주소들
        assert_eq!(s("192.168.123.255"), Scope::Private); // NetBIOS 137 브로드캐스트 — 마스크를 모르니 로컬망
        assert_eq!(s("224.0.0.252"), Scope::Multicast); // LLMNR
        assert_eq!(s("ff02::1:3"), Scope::Multicast); // LLMNR v6
        assert_eq!(s("255.255.255.255"), Scope::Broadcast);
        assert_eq!(s("127.0.0.1"), Scope::Loopback);
        assert_eq!(s("::1"), Scope::Loopback);
        assert_eq!(s("169.254.10.1"), Scope::LinkLocal);
        assert_eq!(s("fe80::1"), Scope::LinkLocal);
        assert_eq!(s("fd00::5"), Scope::Private);
        assert_eq!(s("100.100.1.1"), Scope::Cgnat);
        assert_eq!(s("100.128.0.1"), Scope::Public);
        assert_eq!(s("203.0.113.9"), Scope::Documentation);
        assert_eq!(s("2001:db8::1"), Scope::Documentation);
        assert_eq!(s("0.0.0.0"), Scope::Unspecified);
        assert_eq!(s("::ffff:192.168.0.1"), Scope::Private); // v4 매핑은 v4 로 본다
        assert_eq!(s("160.79.104.10"), Scope::Public);
        assert_eq!(s("2606:4700::1"), Scope::Public);
    }

    #[test]
    fn without_db_public_has_no_country_and_label_falls_back() {
        let g = Geo::default();
        let w = g.lookup_str("160.79.104.10").unwrap();
        assert_eq!(w.scope, Scope::Public);
        assert_eq!(w.cc, None);
        assert_eq!(w.label_ko(), "인터넷");
        assert_eq!(g.lookup_str("192.168.0.1").unwrap().label_ko(), "로컬망");
        assert_eq!(g.lookup_str("[::1]").unwrap().scope, Scope::Loopback);
        assert!(g.lookup_str("not-an-ip").is_none());
    }

    #[test]
    fn korean_names_and_label_format() {
        assert_eq!(country_name_ko("kr"), Some("대한민국"));
        assert_eq!(country_name_ko("US"), Some("미국"));
        // D005
        assert_eq!(country_name_ko("TW"), Some("대만"));
        assert_eq!(country_name_ko("XK"), Some("코소보"));
        assert_eq!(country_name_ko("EU"), Some("유럽(나라 미상)"));
        assert_eq!(country_name_ko("AP"), Some("아시아·태평양(나라 미상)"));
        assert_eq!(country_name_ko("ZZ"), Some("지정 안 됨"));
        assert_eq!(country_name_ko("QZ"), None);
        assert!(is_region_code("zz") && is_region_code("EU") && !is_region_code("XK"));
        assert!(names_ko::NAMES_KO.len() >= 249);
        let w = Where {
            scope: Scope::Public,
            cc: Some("US".into()),
            country: Some("미국".into()),
            asn: Some(13335),
            org: Some("Cloudflare, Inc.".into()),
        };
        assert_eq!(w.label_ko(), "미국 · Cloudflare, Inc. (AS13335)");
    }

    /// 실제 DB-IP 파일로 접점 확인 (CI 가 geo-data 브랜치를 SF_GEO_DIR 로 넘길 때만; 없으면 건너뜀)
    #[test]
    fn real_dbip_files_decode_country_and_asn() {
        let Ok(dir) = std::env::var("SF_GEO_DIR") else {
            return;
        };
        let (g, errs) = Geo::open_dir(Path::new(&dir));
        assert!(errs.is_empty(), "{errs:?}");
        let kt = g.lookup_str("168.126.63.1").unwrap(); // KT DNS
        assert_eq!(kt.cc.as_deref(), Some("KR"), "{kt:?}");
        assert_eq!(kt.country.as_deref(), Some("대한민국"));
        let gg = g.lookup_str("8.8.8.8").unwrap();
        assert_eq!(gg.asn, Some(15169), "{gg:?}");
        assert!(gg.org.as_deref().unwrap_or("").contains("Google"), "{gg:?}");
        let v6 = g.lookup_str("2001:4860:4860::8888").unwrap();
        assert_eq!(v6.asn, Some(15169), "IPv6 도 {v6:?}");
        // 국가가 아닌 주소는 DB 를 보지 않는다
        assert_eq!(g.lookup_str("192.168.123.255").unwrap().cc, None);
        assert!(g.country_built.is_some());
        println!("{} / {}", kt.label_ko(), gg.label_ko());
    }

    #[test]
    fn missing_db_files_are_reported_not_fatal() {
        let (g, errs) = Geo::open_dir(Path::new("/nonexistent-geo-dir"));
        assert!(!g.has_country());
        assert_eq!(errs.len(), 2);
    }
}
