//! 검증 규칙 1~9 (명세 4판 3장, 6차 검증 반영)
//!
//! - 거부(errors): 규칙 1(형식), 규칙 2·3·9 에서 확인(acknowledge)이 없을 때.
//! - 경고(warnings): 규칙 4·5·6·8. 규칙 8 은 전개 단계에서 자동 제외하고 여기서는 알린다.
//! - 규칙 7(드라이런 의무)은 전개 결과의 `dryrun_required` 로 표시한다.

use std::collections::HashSet;

use crate::model::{Ack, Action, Direction, Document, Policy, Protocol};
use crate::ranges;
use crate::DslError;

/// 시스템 핵심 프로세스 (규칙 4): 종료·끊기 대상에서 제외
pub const SYSTEM_IMAGES: &[&str] = &[
    "svchost.exe",
    "explorer.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "wininit.exe",
];

#[derive(Debug, Default)]
pub struct Validation {
    pub errors: Vec<DslError>,
    pub warnings: Vec<String>,
    /// 사용자 확인이 필요한 항목 (정책 이름, 종류). 서비스가 UI 확인 뒤 `acknowledge` 를 붙여 다시 검증한다.
    pub needs_ack: Vec<(String, Ack)>,
}

impl Validation {
    pub fn ok(&self) -> bool {
        self.errors.is_empty() && self.needs_ack.is_empty()
    }
}

/// 시스템 핵심 프로세스인가: **이름이 목록에 있고 시스템 디렉터리에 있을 때만** (16차 1-(b) 결함 수정).
/// 이름만 보면 `C:\Users\x\svchost.exe` 같은 위장 파일이 차단·종료·틈 메우기를 피한다.
/// - System32·SysWOW64 (드라이브 무관, `\SystemRoot\` 표기 포함), explorer.exe 는 `\Windows\` 바로 아래
/// - 디렉터리 없는 이름만(사용자가 정책에 `svchost.exe` 라고 쓴 경우)은 보수적으로 시스템으로 본다
pub fn is_system_image(path: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    let p = p
        .strip_prefix("\\\\?\\")
        .or_else(|| p.strip_prefix("\\??\\"))
        .unwrap_or(&p)
        .to_string();
    let (dir, name) = match p.rfind('\\') {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => return SYSTEM_IMAGES.contains(&p.as_str()),
    };
    if !SYSTEM_IMAGES.contains(&name) {
        return false;
    }
    // 드라이브 접두 "c:" 또는 "\systemroot" 를 떼고 나머지 디렉터리를 본다
    let rest = if dir.len() >= 2 && dir.as_bytes()[1] == b':' {
        &dir[2..]
    } else if let Some(r) = dir.strip_prefix("\\systemroot") {
        return r == "\\system32" || r == "\\syswow64" || (name == "explorer.exe" && r.is_empty());
    } else {
        return false;
    };
    rest == "\\windows\\system32"
        || rest == "\\windows\\syswow64"
        || (name == "explorer.exe" && rest == "\\windows")
}

pub fn file_name_lower(p: &str) -> String {
    p.rsplit(['\\', '/'])
        .next()
        .unwrap_or(p)
        .to_ascii_lowercase()
}

/// "80" | "8000-8100"
pub fn parse_port(s: &str) -> Option<(u16, u16)> {
    let s = s.trim();
    if let Some((a, b)) = s.split_once('-') {
        let lo: u16 = a.trim().parse().ok()?;
        let hi: u16 = b.trim().parse().ok()?;
        if lo <= hi {
            return Some((lo, hi));
        }
        return None;
    }
    let p: u16 = s.parse().ok()?;
    Some((p, p))
}

/// "HH:MM-HH:MM" → (시작 분, 끝 분). 자정 넘김은 시작 > 끝.
pub fn parse_time(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.split_once('-')?;
    let hm = |x: &str| -> Option<u16> {
        let (h, m) = x.trim().split_once(':')?;
        let h: u16 = h.parse().ok()?;
        let m: u16 = m.parse().ok()?;
        if h > 23 || m > 59 {
            return None;
        }
        Some(h * 60 + m)
    };
    Some((hm(a)?, hm(b)?))
}

/// "30m" | "14d" | "2h" → 분. ISO 시각은 None 으로 두고 형식만 느슨히 본다.
pub fn parse_duration_minutes(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = num.parse().ok()?;
    match unit {
        "m" => Some(n),
        "h" => Some(n * 60),
        "d" => Some(n * 60 * 24),
        _ => None,
    }
}

fn is_iso_datetime(s: &str) -> bool {
    // 2026-11-01T09:00 또는 2026-11-01T09:00:00(+09:00|Z). 엄격한 달력 검증은 서비스가 한다.
    let b = s.as_bytes();
    b.len() >= 16
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

fn ports_cover(list: &[String], port: u16) -> bool {
    list.iter()
        .filter_map(|p| parse_port(p))
        .any(|(lo, hi)| lo <= port && port <= hi)
}

pub fn validate(doc: &Document) -> Validation {
    let mut v = Validation::default();
    let mut names: HashSet<&str> = HashSet::new();
    let rule = |n: u8, p: &str, m: &str| DslError::Rule {
        rule: n,
        policy: p.to_string(),
        msg: m.to_string(),
    };

    for p in &doc.policies {
        let name = p.name.as_str();
        // ---- 규칙 1: 형식 ----
        if name.is_empty() || name.chars().count() > 64 {
            v.errors.push(rule(1, name, "name 은 1~64자"));
        }
        if !names.insert(name) {
            v.errors.push(rule(1, name, "name 중복"));
        }
        let m = &p.matcher;
        if m.direction.is_none() {
            v.errors
                .push(rule(1, name, "match.direction 필수 (in|out|both)"));
        }
        for proc_ in m.process.iter().chain(m.process_not.iter()) {
            let norm = proc_.replace('/', "\\");
            if let Some(star) = norm.find('*') {
                // 와일드카드는 "디렉터리\*" 끝에만 (6차 검증 Q3)
                if star != norm.len() - 1 || !norm[..star].ends_with('\\') {
                    v.errors.push(rule(
                        1,
                        name,
                        &format!("와일드카드는 '디렉터리\\*' 끝에만: {proc_}"),
                    ));
                }
            }
            if norm.len() < 3 || !norm.as_bytes()[1..].starts_with(b":\\") {
                v.errors.push(rule(
                    1,
                    name,
                    &format!("process 는 절대 경로(X:\\…): {proc_}"),
                ));
            }
        }
        if let Some(d) = &m.descendants_of {
            let ok = d.starts_with("file:")
                && d.contains("#sha256:")
                && d.rsplit("#sha256:").next().map_or(false, |h| {
                    h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())
                });
            if !ok {
                v.errors.push(rule(
                    1,
                    name,
                    "descendants_of 는 'file:<경로>#sha256:<64자 hex>'",
                ));
            }
        }
        for ip in &m.remote_ip {
            if ip != "lan" && ip != "internet" && ranges::parse_addr(ip).is_none() {
                v.errors
                    .push(rule(1, name, &format!("remote_ip 형식 오류: {ip}")));
            }
        }
        for ip in &m.local_ip {
            if ip == "internet" || (ip != "lan" && ranges::parse_addr(ip).is_none()) {
                v.errors.push(rule(
                    1,
                    name,
                    &format!("local_ip 형식 오류(주소·CIDR·범위·lan): {ip}"),
                ));
            }
        }
        if let Some(ifc) = &m.interface {
            if ifc.trim().is_empty()
                || ifc.chars().count() > 64
                || ifc.chars().any(|c| c.is_control())
            {
                v.errors.push(rule(1, name, "interface 는 1~64자 이름"));
            }
        }
        if matches!(m.protocol, Some(Protocol::Icmp)) {
            if !m.remote_port.is_empty() || !m.local_port.is_empty() {
                v.errors.push(rule(1, name, "ICMP 에는 포트를 쓸 수 없다"));
            }
            let v6 = |list: &[String]| {
                list.iter().any(|ip| {
                    ranges::parse_addr(ip).map_or(false, |(v4, v6)| v4.is_empty() && !v6.is_empty())
                })
            };
            if v6(&m.remote_ip) || v6(&m.local_ip) {
                v.errors.push(rule(
                    1,
                    name,
                    "ICMP 규칙은 IPv4 주소만(ICMPv6 는 막지 않는다)",
                ));
            }
        }
        if let Some(n) = p.priority {
            if !(1..=9999).contains(&n) {
                v.errors.push(rule(1, name, "priority(ACL 번호)는 1~9999"));
            }
        }
        for port in m.remote_port.iter().chain(m.local_port.iter()) {
            if parse_port(port).is_none() {
                v.errors
                    .push(rule(1, name, &format!("포트 형식 오류: {port}")));
            }
        }
        if let Some(w) = &p.when {
            if let Some(t) = &w.time {
                if parse_time(t).is_none() {
                    v.errors.push(rule(
                        1,
                        name,
                        &format!("when.time 형식 오류(HH:MM-HH:MM): {t}"),
                    ));
                }
            }
            for d in &w.days {
                if !["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
                    .contains(&d.to_ascii_lowercase().as_str())
                {
                    v.errors
                        .push(rule(1, name, &format!("when.days 값 오류: {d}")));
                }
            }
        }
        if let Some(e) = &p.expires {
            if parse_duration_minutes(e).is_none() && !is_iso_datetime(e) {
                v.errors.push(rule(
                    1,
                    name,
                    &format!("expires 형식 오류(30m|2h|14d|ISO 시각): {e}"),
                ));
            }
        }
        if let Some(u) = &p.until {
            if u != "manual" {
                v.errors
                    .push(rule(1, name, &format!("until 은 1차에서 manual 만: {u}")));
            }
        }
        if p.action == Action::Allow && !p.also.is_empty() {
            v.errors
                .push(rule(1, name, "allow 에는 also 를 쓸 수 없다"));
        }
        if p.action == Action::Allow && m.descendants_of.is_some() {
            v.errors
                .push(rule(1, name, "allow 에는 descendants_of 를 쓸 수 없다"));
        }
        if !m.process_not.is_empty() && !m.process.is_empty() {
            v.errors
                .push(rule(1, name, "process 와 process_not 은 함께 쓸 수 없다"));
        }

        if p.action != Action::Block {
            continue; // 아래 규칙은 차단 정책만
        }
        let udp_possible = !matches!(m.protocol, Some(Protocol::Tcp));
        let no_target = m.process.is_empty() && m.descendants_of.is_none();
        // 인터페이스만 고른 차단은 그 인터페이스의 전부라 여전히 "전체"로 본다(유일한 인터페이스일 수 있다)
        let blocks_everything_addr = m.remote_ip.is_empty() && m.local_ip.is_empty();

        // ---- 규칙 2: 자기 차단 (DNS 53·DHCP 67/68·루프백) → 확인 필요 ----
        let touches_dns =
            udp_possible && (ports_cover(&m.remote_port, 53) || ports_cover(&m.local_port, 53));
        let touches_dhcp = udp_possible
            && [67u16, 68]
                .iter()
                .any(|p| ports_cover(&m.remote_port, *p) || ports_cover(&m.local_port, *p));
        let touches_loopback = m.remote_ip.iter().any(|ip| {
            ranges::parse_addr(ip).map_or(false, |(v4, v6)| {
                v4.iter().any(|r| r.lo.is_loopback() || r.hi.is_loopback())
                    || v6.iter().any(|p| p.addr.is_loopback())
            })
        });
        if (touches_dns || touches_dhcp || touches_loopback)
            && !p.acknowledge.contains(&Ack::SelfBlock)
        {
            v.warnings.push(format!("[2] {name}: DNS/DHCP/루프백을 막을 수 있어 확인 필요 (규칙 8 로 OS 필수 부분은 자동 제외됨)"));
            v.needs_ack.push((name.to_string(), Ack::SelfBlock));
        }
        // ---- 규칙 3: 전체 차단 ----
        if no_target && blocks_everything_addr && !p.acknowledge.contains(&Ack::Wide) {
            v.warnings.push(format!(
                "[3] {name}: 프로그램·주소 조건이 없어 PC 전체 통신 차단 — 확인 필요"
            ));
            v.needs_ack.push((name.to_string(), Ack::Wide));
        }
        // ---- 규칙 4: 시스템 프로세스 보호 ----
        for proc_ in &m.process {
            let fname = file_name_lower(proc_);
            if is_system_image(proc_) && fname != "svchost.exe" {
                v.warnings.push(format!("[4] {name}: 시스템 프로세스 {fname} 는 차단 대상에서 제외된다 (이야기형 4판 10-4장 절차)"));
            }
        }
        if p.also.contains(&crate::model::Also::Terminate) && m.descendants_of.is_some() {
            v.warnings.push(format!(
                "[4] {name}: also:terminate 는 자손 중 시스템 프로세스를 제외한다"
            ));
        }
        // ---- 규칙 9: svchost 광역 ----
        let svchost_wide = m
            .process
            .iter()
            .any(|x| file_name_lower(x) == "svchost.exe")
            && m.remote_port.is_empty()
            && m.remote_ip.is_empty();
        if svchost_wide && !p.acknowledge.contains(&Ack::Svchost) {
            v.warnings.push(format!("[9] {name}: svchost 광역 차단 — Windows Update·인증서 검증·인터넷 연결 표시(NCSI)·스토어가 멈출 수 있음. 확인 필요"));
            v.needs_ack.push((name.to_string(), Ack::Svchost));
        }
        // ---- 규칙 8: 자동 제외 예고 ----
        if touches_dns
            || touches_dhcp
            || touches_loopback
            || matches!(m.protocol, None | Some(Protocol::Any))
        {
            v.warnings.push(format!("[8] {name}: 루프백·DHCP·svchost DNS/NTP·ICMP 는 OS 보호를 위해 전개에서 자동 제외된다"));
        }
    }

    // ACL 번호 중복
    let mut prios: HashSet<u32> = HashSet::new();
    for p in &doc.policies {
        if let Some(n) = p.priority {
            if !prios.insert(n) {
                v.errors
                    .push(rule(1, &p.name, &format!("ACL 번호 중복: {n}")));
            }
        }
    }
    // ---- 규칙 5: block/allow 충돌 ----
    for (i, a) in doc.policies.iter().enumerate() {
        for b in doc.policies.iter().skip(i + 1) {
            if a.action != b.action && a.matcher == b.matcher {
                let msg = match (a.priority, b.priority) {
                    (Some(x), Some(y)) => format!(
                        "[5] {} 와 {} 는 같은 조건의 block/allow — 번호가 작은 {} 가 이긴다",
                        a.name,
                        b.name,
                        if x < y { &a.name } else { &b.name }
                    ),
                    _ => format!(
                        "[5] {} 와 {} 는 같은 조건의 block/allow — 차단이 이긴다",
                        a.name, b.name
                    ),
                };
                v.warnings.push(msg);
            }
        }
    }
    v
}

#[allow(dead_code)]
fn _direction_used(_: Direction) {}
#[allow(dead_code)]
fn _policy_used(_: &Policy) {}
