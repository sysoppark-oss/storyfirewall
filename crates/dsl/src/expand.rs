//! 전개: 정책 → `policy::BlockSpec` 목록 + 스케줄 + 부가 동작 (명세 4판 3장, 6차 검증 2-3)
//!
//! - 같은 필드의 조건은 OR, 다른 필드는 AND (WFP). 목록형은 한 명세에 담는다.
//! - `process_not`·`allow` 는 우리 Sublayer 안의 permit 명세로 (6차 검증 Q2).
//! - 규칙 8 자동 제외: 루프백, DHCP 67/68(UDP 가능 시), svchost 의 53·123, ICMP(프로토콜 미지정·any → tcp+udp).
//! - 규칙 4: 시스템 프로세스는 대상에서 제외하고 경고.
//! - 와일드카드 `디렉터리\*` 는 Resolver 가 열거. 이후 생기는 파일은 정책 엔진이 ProcessStart 로 보충(틈 있음, 문서화).

use policy::spec::{Action as SpecAction, BlockSpec, Direction as SpecDir, PortRange, V4Range, V6Prefix};
use std::net::Ipv4Addr;

use crate::model::{Action, Also, Direction, OnExpire, Policy, Protocol};
use crate::ranges;
use crate::validate::{file_name_lower, is_system_image, parse_duration_minutes, parse_port, parse_time};
use crate::{DslError, Result};

/// OS 를 만지는 조회는 호출자가 준다 (테스트에서는 가짜)
pub trait Resolver {
    /// `디렉터리\*` → 그 안의 실행 파일 전체 경로
    fn list_exes(&self, dir: &str) -> Vec<String>;
    /// descendants_of → 자손 프로세스 이미지 경로들. 파일 없음/해시 불일치는 Err(사유) (6차 검증 Q4)
    fn descendants(&self, file_path: &str, sha256: &str) -> std::result::Result<Vec<String>, String>;
    fn exists(&self, path: &str) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    /// 하루 안의 분 구간들 (자정 넘김은 둘로)
    pub minutes: Vec<(u16, u16)>,
    pub days: Vec<String>,
    /// 기간형 만료(분). ISO 시각은 raw 로 서비스가 해석
    pub expires_in_minutes: Option<u64>,
    pub expires_raw: Option<String>,
    pub until: Option<String>,
    pub on_expire: OnExpire,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expanded {
    pub name: String,
    pub specs: Vec<BlockSpec>,
    pub schedule: Option<Schedule>,
    pub also: Vec<Also>,
    pub log: bool,
    pub warnings: Vec<String>,
    /// 규칙 7: 활성화 전 드라이런 의무
    pub dryrun_required: bool,
    /// 규칙 4 로 차단·종료 대상에서 뺀 시스템 프로세스 이미지 경로 (7차 검증 (b)).
    /// dsl 은 정적 전개만 한다. 정책 엔진이 이 목록의 프로세스가 접속한 주소를 graph 에서 뽑아
    /// 앱 조건 없는 주소 차단 필터를 만들고, 자리잡기 제거·재부팅 권고로 잇는다.
    pub excluded_system: Vec<String>,
}

fn norm_path(p: &str) -> String {
    p.replace('/', "\\")
}

/// 포트 범위 목록에서 특정 포트를 빼서 쪼갠다 (규칙 8 자동 제외)
fn exclude_port(ranges: &mut Vec<PortRange>, port: u16) -> bool {
    let mut changed = false;
    let mut out = Vec::new();
    for r in ranges.iter() {
        if r.lo <= port && port <= r.hi {
            changed = true;
            if r.lo < port {
                out.push(PortRange { lo: r.lo, hi: port - 1 });
            }
            if port < r.hi {
                out.push(PortRange { lo: port + 1, hi: r.hi });
            }
        } else {
            out.push(*r);
        }
    }
    *ranges = out;
    changed
}

/// IPv4 범위 목록에서 한 범위를 뺀다
fn exclude_v4(ranges: &mut Vec<V4Range>, lo: Ipv4Addr, hi: Ipv4Addr) -> bool {
    let (xl, xh) = (u32::from(lo), u32::from(hi));
    let mut changed = false;
    let mut out = Vec::new();
    for r in ranges.iter() {
        let (rl, rh) = (u32::from(r.lo), u32::from(r.hi));
        if rh < xl || rl > xh {
            out.push(*r);
            continue;
        }
        changed = true;
        if rl < xl {
            out.push(V4Range { lo: r.lo, hi: Ipv4Addr::from(xl - 1) });
        }
        if rh > xh {
            out.push(V4Range { lo: Ipv4Addr::from(xh + 1), hi: r.hi });
        }
    }
    *ranges = out;
    changed
}

pub fn expand(p: &Policy, resolver: &dyn Resolver) -> Result<Expanded> {
    let m = &p.matcher;
    let name = p.name.clone();
    let mut warnings = Vec::new();
    let mut excluded_system: Vec<String> = Vec::new();
    let dirs: Vec<SpecDir> = match m.direction.unwrap_or(Direction::Out) {
        Direction::Out => vec![SpecDir::Out],
        Direction::In => vec![SpecDir::In],
        Direction::Both => vec![SpecDir::Out, SpecDir::In],
    };

    // ---- 주소 ----
    let mut remote_v4: Vec<V4Range> = Vec::new();
    let mut remote_v6: Vec<V6Prefix> = Vec::new();
    for ip in &m.remote_ip {
        match ip.as_str() {
            "lan" => {
                remote_v4.extend(ranges::lan_v4());
                remote_v6.extend(ranges::lan_v6());
            }
            "internet" => {
                remote_v4.extend(ranges::internet_v4());
                remote_v6.extend(ranges::internet_v6());
            }
            other => {
                let (v4, v6) = ranges::parse_addr(other).ok_or_else(|| DslError::Rule { rule: 1, policy: name.clone(), msg: format!("remote_ip: {other}") })?;
                remote_v4.extend(v4);
                remote_v6.extend(v6);
            }
        }
    }
    // ---- 포트·프로토콜 ----
    let to_ports = |list: &[String]| -> Vec<PortRange> { list.iter().filter_map(|s| parse_port(s)).map(|(lo, hi)| PortRange { lo, hi }).collect() };
    let mut remote_ports = to_ports(&m.remote_port);
    let mut local_ports = to_ports(&m.local_port);
    let protocols: Vec<u8> = match m.protocol {
        Some(Protocol::Tcp) => vec![6],
        Some(Protocol::Udp) => vec![17],
        // 미지정·any → tcp+udp 만. ICMP 는 절대 안 막는다 (규칙 8)
        None | Some(Protocol::Any) => vec![6, 17],
    };

    // ---- 규칙 8 자동 제외 (차단 정책만) ----
    if p.action == Action::Block {
        if exclude_v4(&mut remote_v4, Ipv4Addr::new(127, 0, 0, 0), Ipv4Addr::new(127, 255, 255, 255)) {
            warnings.push(format!("[8] {name}: 루프백 127/8 자동 제외"));
        }
        let before = remote_v6.len();
        remote_v6.retain(|p6| !p6.addr.is_loopback());
        if remote_v6.len() != before {
            warnings.push(format!("[8] {name}: 루프백 ::1 자동 제외"));
        }
        if protocols.contains(&17) {
            for port in [67u16, 68] {
                if exclude_port(&mut remote_ports, port) | exclude_port(&mut local_ports, port) {
                    warnings.push(format!("[8] {name}: DHCP {port} 자동 제외"));
                }
            }
        }
    }

    // ---- 대상 프로그램 ----
    let mut targets: Vec<String> = Vec::new();
    for proc_ in &m.process {
        let n = norm_path(proc_);
        if let Some(dir) = n.strip_suffix("\\*") {
            let listed = resolver.list_exes(dir);
            if listed.is_empty() {
                warnings.push(format!("[6] {name}: {dir}\\* 에 실행 파일이 없음"));
            }
            warnings.push(format!("[틈] {name}: {dir}\\* 는 지금 있는 실행 파일만 전개됨. 이후 생기는 파일은 정책 엔진이 ProcessStart 로 보충(그 사이 틈 있음)"));
            targets.extend(listed);
        } else {
            if !resolver.exists(&n) {
                warnings.push(format!("[6] {name}: 경로 없음 {n}"));
            }
            targets.push(n);
        }
    }
    // 규칙 4: 시스템 프로세스 제외. `process` 에 명시한 svchost 만 규칙 9 확인을 전제로 남긴다.
    // descendants_of 로 딸려 온 svchost·explorer 등은 감염돼도 광역 차단·종료 대상이 아니다
    // (이야기형 4판 10-4장: 원인 프로그램 종료·격리, 의심 주소만 WFP 차단, 자리잡기 제거, 재부팅 권고).
    let explicit_svchost = targets.iter().any(|t| file_name_lower(t) == "svchost.exe");
    if let Some(d) = &m.descendants_of {
        let body = d.strip_prefix("file:").unwrap_or(d);
        let (path, hash) = body.split_once("#sha256:").unwrap_or((body, ""));
        match resolver.descendants(&norm_path(path), hash) {
            Ok(list) => {
                warnings.push(format!("[틈] {name}: descendants_of 는 지금까지의 자손만. 새 자손은 정책 엔진이 보충"));
                for t in list {
                    let f = file_name_lower(&t);
                    if is_system_image(&t) {
                        warnings.push(format!("[4] {name}: 자손 중 시스템 프로세스 {f} 는 차단·종료 대상에서 제외 — 의심 주소 차단·자리잡기 제거·재부팅 권고로 처리"));
                        excluded_system.push(t);
                        continue;
                    }
                    targets.push(t);
                }
            }
            Err(why) => return Err(DslError::Rule { rule: 4, policy: name.clone(), msg: format!("descendants_of 적용 실패: {why}") }),
        }
    }
    let mut kept: Vec<String> = Vec::new();
    for t in targets {
        let f = file_name_lower(&t);
        let keep_svchost = f == "svchost.exe" && explicit_svchost;
        if is_system_image(&t) && !keep_svchost && p.action == Action::Block {
            warnings.push(format!("[4] {name}: {f} 제외"));
            excluded_system.push(t);
            continue;
        }
        kept.push(t);
    }
    let targets = kept;

    // ---- 명세 조립 ----
    let mut specs: Vec<BlockSpec> = Vec::new();
    let spec_action = if p.action == Action::Allow { SpecAction::Permit } else { SpecAction::Block };
    let make = |app: Option<String>, dir: SpecDir, action: SpecAction, rp: &Vec<PortRange>, lp: &Vec<PortRange>| BlockSpec {
        name: name.clone(),
        action,
        direction: dir,
        app_path: app,
        remote_v4: remote_v4.clone(),
        remote_v6: remote_v6.clone(),
        remote_ports: rp.clone(),
        local_ports: lp.clone(),
        protocols: protocols.clone(),
        weight: None,
        ip_family: None,
    };
    for dir in &dirs {
        if targets.is_empty() {
            // 프로그램 조건 없음: 주소·포트만으로 (규칙 3 확인은 validate 가 함)
            specs.push(make(None, *dir, spec_action, &remote_ports, &local_ports));
        } else {
            for t in &targets {
                let (mut rp, lp) = (remote_ports.clone(), local_ports.clone());
                if file_name_lower(t) == "svchost.exe" && p.action == Action::Block {
                    for port in [53u16, 123] {
                        if exclude_port(&mut rp, port) {
                            warnings.push(format!("[8] {name}: svchost {port} 자동 제외"));
                        }
                    }
                    if remote_ports.is_empty() {
                        warnings.push(format!("[8] {name}: svchost 광역 차단은 WFP 로 53·123 을 뺄 수 없어 전체가 막힘 — 규칙 9 확인 전제"));
                    }
                }
                specs.push(make(Some(t.clone()), *dir, spec_action, &rp, &lp));
            }
        }
        // process_not: 같은 조건의 permit 을 우리 Sublayer 안에 (6차 검증 Q2)
        for ex in &m.process_not {
            let n = norm_path(ex);
            let apps: Vec<String> = if let Some(dir) = n.strip_suffix("\\*") { resolver.list_exes(dir) } else { vec![n] };
            for a in apps {
                let mut s = make(Some(a), *dir, SpecAction::Permit, &remote_ports, &local_ports);
                s.name = format!("{name} (예외)");
                specs.push(s);
            }
        }
    }

    // ---- 스케줄 ----
    let schedule = if p.when.is_some() || p.expires.is_some() || p.until.is_some() {
        let mut minutes = Vec::new();
        let mut days = Vec::new();
        if let Some(w) = &p.when {
            if let Some(t) = &w.time {
                if let Some((a, b)) = parse_time(t) {
                    if a <= b {
                        minutes.push((a, b));
                    } else {
                        minutes.push((a, 24 * 60));
                        minutes.push((0, b));
                    }
                }
            }
            days = w.days.iter().map(|d| d.to_ascii_lowercase()).collect();
        }
        Some(Schedule {
            minutes,
            days,
            expires_in_minutes: p.expires.as_deref().and_then(parse_duration_minutes),
            expires_raw: p.expires.clone(),
            until: p.until.clone(),
            on_expire: p.on_expire.unwrap_or(OnExpire::Notify),
        })
    } else {
        None
    };

    Ok(Expanded { name, specs, schedule, also: p.also.clone(), log: p.log.unwrap_or(true), warnings, dryrun_required: true, excluded_system })
}
