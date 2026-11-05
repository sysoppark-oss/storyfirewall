//! B2: 자체 ETW 수집기 vs Sysmon 누락률 비교.
//!
//! 정답지 = 같은 시간에 같은 PC 에서 돈 Sysmon 의 기록(이벤트 로그를 JSON 줄로 내보낸 것).
//! 우리 기록 = collector-poc 가 만든 collector.db 의 raw_events (payload_json = graph::Event 직렬화).
//!
//! 비교 단위 (Sysmon 이벤트 ID → 우리 이벤트):
//! - 1 프로세스 생성 → ProcessStart: 같은 PID + 이미지 파일명(대소문자 무시) + 시각 차 ≤ 허용치
//! - 5 프로세스 종료 → ProcessStop: 같은 PID + 시각
//! - 3 네트워크 연결 → Connect: 같은 PID + 프로토콜 + 방향 + 원격 IP·포트(나가는 쪽) / 로컬 포트(들어오는 쪽) + 시각
//! - 22 DNS 조회 → DnsQuery: 같은 PID + 이름(소문자, 끝 점 제거) + 시각
//! - 11 파일 생성 → FileWrite: 경로 끝(드라이브·장치 접두 제거, 소문자) + 시각. **구간 안에서 나중에 실행된 파일만** 센다 —
//!   수집기는 파일 생성을 링 버퍼에 두었다가 그 파일이 실행될 때 사슬로 꺼내 기록한다(etw.rs process_provider, 명세 4판 2-2).
//!   실행되지 않은 파일 생성은 설계상 기록하지 않으므로 누락으로 세지 않는다.
//!
//! 판정은 "Sysmon 한 건에 대해 허용 시각 안에 같은 열쇠의 우리 기록이 하나라도 있으면 잡음". 같은 열쇠가 여러 번이면 각각 센다.
//! UDP 는 우리가 같은 목적지 1초 안 반복을 접으므로(etw.rs) 1초 안 반복 Sysmon 건도 같은 우리 기록 하나로 잡힌 것으로 본다.
//!
//! 시각 단위 접점: 둘 다 UTC. Sysmon `UtcTime`("YYYY-MM-DD hh:mm:ss.fff") → FILETIME(100ns, 1601) 로 바꿔 비교한다.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// FILETIME 1초
pub const SEC: i64 = 10_000_000;

/// "YYYY-MM-DD hh:mm:ss.fff" (UTC) → FILETIME. 형식이 다르면 None
pub fn utc_to_filetime(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, time) = s.split_once(' ')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, "0"),
    };
    let mut t = hms.split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next()?.parse().ok()?;
    let ss: i64 = t.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // 소수부: 앞 7자리(100ns)까지
    let mut f7 = String::from(frac);
    if !f7.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    f7.truncate(7);
    while f7.len() < 7 {
        f7.push('0');
    }
    let ticks: i64 = f7.parse().ok()?;
    let days = days_from_civil(y, m, day) - days_from_civil(1601, 1, 1);
    Some(((days * 86_400 + hh * 3600 + mm * 60 + ss) * SEC) + ticks)
}

/// 그레고리력 날짜 → 1970-01-01 기준 일수 (Howard Hinnant 알고리즘)
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 내보낸 Sysmon 이벤트 한 줄 (b2-run.ps1 이 만든다). 없는 필드는 빈 값.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SysmonRec {
    pub id: u32,
    #[serde(rename = "UtcTime")]
    pub utc_time: String,
    #[serde(rename = "ProcessId")]
    pub process_id: u32,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "Protocol")]
    pub protocol: String,
    #[serde(rename = "Initiated")]
    pub initiated: String,
    #[serde(rename = "SourceIp")]
    pub source_ip: String,
    #[serde(rename = "SourcePort")]
    pub source_port: String,
    #[serde(rename = "DestinationIp")]
    pub destination_ip: String,
    #[serde(rename = "DestinationPort")]
    pub destination_port: String,
    #[serde(rename = "QueryName")]
    pub query_name: String,
    #[serde(rename = "TargetFilename")]
    pub target_filename: String,
}

/// 비교 열쇠
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    ProcStart {
        pid: u32,
        name: String,
    },
    ProcStop {
        pid: u32,
    },
    /// dir: "out" | "in". out 이면 (raddr, rport), in 이면 lport 만(원격 쪽 표기는 Sysmon 판에 따라 다를 수 있어 쓰지 않는다 — 추측 회피)
    Net {
        pid: u32,
        proto: String,
        dir: &'static str,
        addr: String,
        port: u16,
    },
    Dns {
        pid: u32,
        name: String,
    },
    File {
        path: String,
    },
}

impl Key {
    /// Sysmon 쪽 원천이 ETW 계열인 열쇠(네트워크·DNS). 프로세스 생성·종료는 드라이버 콜백이라 보정 대상이 아니다
    pub fn is_etw_side(&self) -> bool {
        matches!(self, Key::Net { .. } | Key::Dns { .. })
    }
    pub fn category(&self) -> &'static str {
        match self {
            Key::ProcStart { .. } => "process_start(1)",
            Key::ProcStop { .. } => "process_stop(5)",
            Key::Net { dir: "out", .. } => "network_out(3)",
            Key::Net { .. } => "network_in(3)",
            Key::Dns { .. } => "dns(22)",
            Key::File { .. } => "file_create(11)",
        }
    }
}

/// 실행 파일 이름(경로 끝, 소문자)
pub fn base_name(p: &str) -> String {
    p.rsplit(['\\', '/'])
        .next()
        .unwrap_or(p)
        .trim()
        .to_ascii_lowercase()
}

/// 파일 경로 비교용: 소문자, `\\?\`·드라이브 문자·`\Device\HarddiskVolumeN` 을 떼고 나머지 경로만
pub fn path_tail(p: &str) -> String {
    let s = p.trim().replace('/', "\\").to_ascii_lowercase();
    let s = s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string();
    if let Some(rest) = s.strip_prefix("\\device\\") {
        // harddiskvolume3\users\... → \users\...
        return match rest.find('\\') {
            Some(i) => rest[i..].to_string(),
            None => String::new(),
        };
    }
    if s.len() >= 2 && s.as_bytes()[1] == b':' {
        return s[2..].to_string();
    }
    s
}

/// 비교할 파일 확장자 (실행 가능한 것). 실행됐는지는 compare 가 따로 본다
pub const FILE_EXTS: &[&str] = &[
    "exe", "dll", "scr", "com", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "hta", "msi", "lnk",
];

pub fn ext_in_scope(p: &str) -> bool {
    let b = base_name(p);
    match b.rsplit_once('.') {
        Some((_, e)) => FILE_EXTS.contains(&e),
        None => false,
    }
}

fn dns_name(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn ip(s: &str) -> String {
    graph::ingest::normalize_ip(s).to_ascii_lowercase()
}

/// Sysmon 기록 → (시각, 열쇠). 비교 대상이 아니면 None
pub fn sysmon_key(r: &SysmonRec) -> Option<(i64, Key)> {
    let ts = utc_to_filetime(&r.utc_time)?;
    let key = match r.id {
        1 => Key::ProcStart {
            pid: r.process_id,
            name: base_name(&r.image),
        },
        5 => Key::ProcStop { pid: r.process_id },
        3 => {
            let proto = r.protocol.trim().to_ascii_lowercase();
            if proto != "tcp" && proto != "udp" {
                return None;
            }
            let out = r.initiated.trim().eq_ignore_ascii_case("true");
            if out {
                Key::Net {
                    pid: r.process_id,
                    proto,
                    dir: "out",
                    addr: ip(&r.destination_ip),
                    port: r.destination_port.trim().parse().ok()?,
                }
            } else if proto == "udp" {
                // 받은 UDP(mDNS 5353·NetBIOS 137 등)는 수집기가 연결(Connect)로 기록하지 않는다 — 용량(conn_bytes)으로만 더한다.
                // 설계상 범위 밖이라 누락으로 세지 않는다 (B2 노트북 실측에서 inbound 134건 중 대부분)
                return None;
            } else {
                // 들어오는 연결: 우리 쪽(로컬) 포트. Sysmon 은 받은 쪽을 Destination 으로 적는다(B2 노트북 실측: TeamViewer 서비스 5939)
                Key::Net {
                    pid: r.process_id,
                    proto,
                    dir: "in",
                    addr: String::new(),
                    port: r.destination_port.trim().parse().ok()?,
                }
            }
        }
        22 => {
            let n = dns_name(&r.query_name);
            if n.is_empty() {
                return None;
            }
            Key::Dns {
                pid: r.process_id,
                name: n,
            }
        }
        11 => {
            if !ext_in_scope(&r.target_filename) {
                return None;
            }
            Key::File {
                path: path_tail(&r.target_filename),
            }
        }
        _ => return None,
    };
    Some((ts, key))
}

/// 우리 원시 이벤트(raw_events.payload_json) → (시각, 열쇠들)
pub fn ours_keys(payload_json: &str) -> Vec<(i64, Key)> {
    let Ok(ev) = serde_json::from_str::<graph::Event>(payload_json) else {
        return vec![];
    };
    use graph::EventKind as K;
    let ts = ev.ts;
    match ev.kind {
        K::ProcessStart { pid, image, .. } => vec![(
            ts,
            Key::ProcStart {
                pid,
                name: base_name(&image),
            },
        )],
        K::ProcessStop { pid } => vec![(ts, Key::ProcStop { pid })],
        K::Connect {
            proc,
            proto,
            direction,
            raddr,
            rport,
            lport,
            ..
        } => {
            let proto = match proto {
                graph::event::Proto::Tcp => "tcp",
                graph::event::Proto::Udp => "udp",
            }
            .to_string();
            match direction {
                graph::event::Direction::Out => vec![(
                    ts,
                    Key::Net {
                        pid: proc.pid,
                        proto,
                        dir: "out",
                        addr: ip(&raddr),
                        port: rport,
                    },
                )],
                graph::event::Direction::In => vec![(
                    ts,
                    Key::Net {
                        pid: proc.pid,
                        proto,
                        dir: "in",
                        addr: String::new(),
                        port: lport,
                    },
                )],
            }
        }
        K::DnsQuery { proc, name, .. } => vec![(
            ts,
            Key::Dns {
                pid: proc.pid,
                name: dns_name(&name),
            },
        )],
        K::FileWrite { path, .. } => vec![(
            ts,
            Key::File {
                path: path_tail(&path),
            },
        )],
        _ => vec![],
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CatStat {
    pub sysmon: usize,
    pub matched: usize,
    pub missed: usize,
    /// matched 중 Sysmon 시각 어긋남(`Report::sysmon_etw_offset`)을 보정해서야 맞은 수
    pub matched_by_offset: usize,
    /// 짝이 없고 보정 전·후 시각 중 하나만 구간 안이라 세지 않은 Sysmon 사건 수 (경계 판정 불가)
    pub boundary_skipped: usize,
    /// 0~100
    pub miss_rate_pct: f64,
    /// 우리에게만 있는 건(정보용: Sysmon 설정·필터 차이, Sysmon 자체 누락)
    pub ours_only: usize,
    pub missed_examples: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub window_from: i64,
    pub window_to: i64,
    pub tolerance_ms: i64,
    pub categories: std::collections::BTreeMap<String, CatStat>,
    /// 비교에서 뺀 프로세스 이미지(소문자 파일명)
    pub excluded_images: Vec<String>,
    /// Sysmon 의 ETW 계열 사건(3 네트워크·22 DNS) 시각 보정값(100ns). 0 이 아니면 보정 뒤 비교했다는 뜻 (`estimate_etw_offset`)
    pub sysmon_etw_offset: i64,
}

/// Sysmon 의 ETW 계열 사건(3 네트워크·22 DNS) 일부가 일정한 시각만큼 어긋나는지 추정한다.
/// B2 노트북 3회차 실측(2026-11-02): Sysmon 의 DNS 대부분과 네트워크 일부가 정확히 약 152.6초 이르게 찍혔다 — 같은 curl 의
/// DNS 가 그 curl 의 생성(드라이버 콜백, 우리와 일치)보다 2분 32초 먼저. 나머지 네트워크 사건은 0초 차이로 맞았다.
/// 측정 중 시스템 시각 변경 뒤 Sysmon 의 ETW 세션 시각 기준이 일부 경로에서 옛 값으로 남은 것으로 본다(원인은 추측).
/// 그래서 전부 옮기지 않고 "0 또는 이 값" 두 가지로 맞춰 본다. 값 = 2초 넘는 (우리 − Sysmon) 차이의 1초 칸 최빈값,
/// 같은 칸에 8개 이상일 때만. 없으면 0
pub fn estimate_etw_offset(sysmon: &[(i64, Key, String)], ours: &[(i64, Key)]) -> i64 {
    let mut idx: HashMap<&Key, Vec<i64>> = HashMap::new();
    for (t, k) in ours {
        if k.is_etw_side() {
            idx.entry(k).or_default().push(*t);
        }
    }
    let mut bins: HashMap<i64, Vec<i64>> = HashMap::new();
    for (t, k, _) in sysmon.iter().filter(|(_, k, _)| k.is_etw_side()) {
        let Some(d) = idx.get(k).and_then(|v| {
            v.iter()
                .map(|o| o - t)
                .filter(|x| x.abs() <= 300 * SEC)
                .min_by_key(|x| x.abs())
        }) else {
            continue;
        };
        if d.abs() >= 2 * SEC {
            bins.entry(d.div_euclid(SEC)).or_default().push(d);
        }
    }
    let Some((_, mut v)) = bins.into_iter().max_by_key(|(b, v)| (v.len(), -b.abs())) else {
        return 0;
    };
    if v.len() < 8 {
        return 0;
    }
    v.sort_unstable();
    v[v.len() / 2]
}

pub struct Options {
    /// 비교 구간 [from, to] (FILETIME). 수집 시작·끝에서 여유를 둔다
    pub from: i64,
    pub to: i64,
    /// 시각 허용치
    pub tolerance: i64,
    /// 비교에서 뺄 이미지 파일명(소문자) — Sysmon 자신, 수집기 자신, 내보내기 PowerShell 등
    pub exclude_images: Vec<String>,
    pub examples: usize,
}

/// 비교 본체. sysmon·ours 는 (시각, 열쇠). ours 는 구간 밖도 넣어도 된다(허용치 경계용).
pub fn compare(sysmon: &[(i64, Key, String)], ours: &[(i64, Key)], opt: &Options) -> Report {
    // Sysmon ETW 계열 시각 어긋남: 네트워크·DNS 는 t 와 t+off 둘 다 맞춰 본다 (보정으로 맞춘 수는 따로 센다)
    let off = estimate_etw_offset(sysmon, ours);
    // 제외할 PID: 제외 이미지의 프로세스 생성 기록에서(Sysmon 쪽 Image 로)
    let excluded_pids: std::collections::HashSet<u32> = sysmon
        .iter()
        .filter_map(|(_, k, img)| {
            let pid = match k {
                Key::ProcStart { pid, .. }
                | Key::ProcStop { pid }
                | Key::Net { pid, .. }
                | Key::Dns { pid, .. } => *pid,
                Key::File { .. } => return None,
            };
            opt.exclude_images.contains(&base_name(img)).then_some(pid)
        })
        .collect();
    let excluded = |k: &Key| match k {
        Key::ProcStart { pid, .. }
        | Key::ProcStop { pid }
        | Key::Net { pid, .. }
        | Key::Dns { pid, .. } => excluded_pids.contains(pid),
        Key::File { .. } => false,
    };

    // 구간 안에서 실행된 파일(Sysmon 1 의 Image) — 파일 생성은 이것만 비교 (수집기는 실행된 파일의 생성 사슬만 기록)
    let executed: std::collections::HashSet<String> = sysmon
        .iter()
        .filter(|(_, k, _)| matches!(k, Key::ProcStart { .. }))
        .map(|(_, _, img)| path_tail(img))
        .collect();
    let in_scope = |k: &Key| match k {
        Key::File { path } => executed.contains(path),
        _ => true,
    };

    let mut idx: HashMap<&Key, Vec<i64>> = HashMap::new();
    for (t, k) in ours {
        idx.entry(k).or_default().push(*t);
    }
    for v in idx.values_mut() {
        v.sort_unstable();
    }
    let near = |k: &Key, t: i64| -> bool {
        idx.get(k).is_some_and(|v| {
            let i = v.partition_point(|x| *x < t - opt.tolerance);
            i < v.len() && v[i] <= t + opt.tolerance
        })
    };

    let mut rep = Report {
        window_from: opt.from,
        window_to: opt.to,
        tolerance_ms: opt.tolerance / 10_000,
        excluded_images: opt.exclude_images.clone(),
        sysmon_etw_offset: off,
        ..Default::default()
    };
    // 구간 판정은 "보정 뒤 시각"으로 한다 (L004 지적: 보정 전 시각으로 거르면 구간 시작 직후의 어긋난 사건이 통째로 빠지고,
    // 구간 끝 밖의 사건이 들어온다). 어긋남은 사건마다 다르므로 짝이 맞은 쪽의 시각을 쓴다. 어느 쪽과도 짝이 없는 ETW 계열
    // 사건은 원래 시각과 보정 시각이 **둘 다** 구간 안일 때만 센다(경계 착시로 누락을 만들지 않게). 그래서 빠진 수는 따로 보고한다
    let in_win = |t: i64| t >= opt.from && t <= opt.to;
    let mut sys_idx: HashMap<&Key, Vec<i64>> = HashMap::new();
    for (t, k, img) in sysmon {
        if excluded(k) || !in_scope(k) {
            continue;
        }
        let skewable = off != 0 && k.is_etw_side();
        // 어긋남이 있으면 보정 시각을 먼저 본다. 3회차 분석: Sysmon 네트워크 사건 649건 중 "0초로만 맞는 것"은 0건,
        // 보정으로만 맞는 것 299건, 둘 다 맞는 것 348건(같은 열쇠의 반복 연결과 우연히 짝지은 것) — 어긋남은 ETW 계열
        // 전체에 고르게 걸려 있었다(23차 Q3). 0초를 먼저 보면 반복 연결이 누락을 가릴 수 있다
        let (eff, by_off) = if skewable && near(k, *t + off) {
            (Some(*t + off), true)
        } else if near(k, *t) {
            (Some(*t), false)
        } else {
            (None, false)
        };
        let counted = match eff {
            Some(e) => in_win(e),
            None => in_win(*t) && (!skewable || in_win(*t + off)),
        };
        if !counted {
            if eff.is_none() && skewable && (in_win(*t) || in_win(*t + off)) {
                rep.categories
                    .entry(k.category().to_string())
                    .or_default()
                    .boundary_skipped += 1;
            }
            continue;
        }
        sys_idx.entry(k).or_default().push(*t);
        let st = rep.categories.entry(k.category().to_string()).or_default();
        st.sysmon += 1;
        if eff.is_some() {
            st.matched += 1;
            if by_off {
                st.matched_by_offset += 1;
            }
        } else {
            st.missed += 1;
            if st.missed_examples.len() < opt.examples {
                st.missed_examples
                    .push(format!("{} {:?} img={}", filetime_to_utc(*t), k, img));
            }
        }
    }
    for v in sys_idx.values_mut() {
        v.sort_unstable();
    }
    // 우리에게만 있는 건 (정보용)
    for (t, k) in ours {
        if *t < opt.from || *t > opt.to || excluded(k) || !in_scope(k) {
            continue;
        }
        let hit = |t: i64| {
            sys_idx.get(k).is_some_and(|v| {
                let i = v.partition_point(|x| *x < t - opt.tolerance);
                i < v.len() && v[i] <= t + opt.tolerance
            })
        };
        let found = hit(*t) || (off != 0 && k.is_etw_side() && hit(*t - off));
        if !found {
            rep.categories
                .entry(k.category().to_string())
                .or_default()
                .ours_only += 1;
        }
    }
    for st in rep.categories.values_mut() {
        st.miss_rate_pct = if st.sysmon == 0 {
            0.0
        } else {
            (st.missed as f64) * 100.0 / (st.sysmon as f64)
        };
    }
    rep
}

/// FILETIME → "YYYY-MM-DD hh:mm:ss.fffZ" (보고서 표시용)
pub fn filetime_to_utc(ft: i64) -> String {
    let secs = ft.div_euclid(SEC);
    let ms = ft.rem_euclid(SEC) / 10_000;
    let days = secs.div_euclid(86_400) + days_from_civil(1601, 1, 1);
    let rem = secs.rem_euclid(86_400);
    // civil_from_days
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// collector.db 의 원시 이벤트 전부 → (시각, 열쇠)
pub fn load_ours(db: &str) -> Result<Vec<(i64, Key)>, String> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| e.to_string())?;
    let mut st = conn
        .prepare("SELECT payload_json FROM raw_events")
        .map_err(|e| e.to_string())?;
    let rows = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut out = vec![];
    for p in rows.flatten() {
        out.extend(ours_keys(&p));
    }
    Ok(out)
}

/// Sysmon JSON 줄 파일 → (시각, 열쇠, 이미지). 줄 수·버린 줄 수도
pub fn load_sysmon(text: &str) -> (Vec<(i64, Key, String)>, usize, usize) {
    let mut out = vec![];
    let (mut n, mut bad) = (0, 0);
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        n += 1;
        match serde_json::from_str::<SysmonRec>(line.trim_start_matches('\u{feff}')) {
            Ok(r) => match sysmon_key(&r) {
                Some((t, k)) => out.push((t, k, r.image.clone())),
                None => {}
            },
            Err(_) => bad += 1,
        }
    }
    (out, n, bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph::event::{Direction, ProcRef, Proto};
    use graph::{Event, EventKind};

    #[test]
    fn utc_parse_matches_filetime_epoch_contact() {
        // 접점: 1970-01-01 00:00:00 UTC = FILETIME 116444736000000000
        assert_eq!(
            utc_to_filetime("1970-01-01 00:00:00.000"),
            Some(116_444_736_000_000_000)
        );
        assert_eq!(utc_to_filetime("1601-01-01 00:00:00"), Some(0));
        let t = utc_to_filetime("2026-11-02 01:23:45.678").unwrap();
        assert_eq!(filetime_to_utc(t), "2026-11-02 01:23:45.678Z");
        // 윤년 2월 29일
        let a = utc_to_filetime("2028-02-29 23:59:59.999").unwrap();
        let b = utc_to_filetime("2028-03-01 00:00:00.000").unwrap();
        assert_eq!(b - a, 10_000);
        assert!(utc_to_filetime("2026-13-01 00:00:00").is_none());
        assert!(utc_to_filetime("garbage").is_none());
    }

    #[test]
    fn path_tail_unifies_device_and_drive_forms() {
        assert_eq!(
            path_tail(r"\Device\HarddiskVolume3\Users\a\Downloads\X.EXE"),
            r"\users\a\downloads\x.exe"
        );
        assert_eq!(
            path_tail(r"C:\Users\a\Downloads\x.exe"),
            r"\users\a\downloads\x.exe"
        );
        assert_eq!(path_tail(r"\\?\C:\Users\a\x.exe"), r"\users\a\x.exe");
        assert!(ext_in_scope("a.PS1") && !ext_in_scope("a.txt") && !ext_in_scope("noext"));
    }

    fn ev(ts: i64, kind: EventKind) -> String {
        serde_json::to_string(&Event::new(ts, "etw:x", kind)).unwrap()
    }

    #[test]
    fn our_payloads_map_to_keys_via_real_event_serialization() {
        // 접점: graph::Event 직렬화 형식 그대로 읽는다 (ingest 가 raw_events 에 넣는 것과 같은 to_string)
        let p = ev(
            5,
            EventKind::ProcessStart {
                pid: 7,
                ppid: 1,
                image: r"\Device\HarddiskVolume3\Windows\System32\curl.exe".into(),
                create_time: Some(5),
            },
        );
        assert_eq!(
            ours_keys(&p),
            vec![(
                5,
                Key::ProcStart {
                    pid: 7,
                    name: "curl.exe".into()
                }
            )]
        );
        let n = ev(
            6,
            EventKind::Connect {
                proc: ProcRef::new(7, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 5000,
                raddr: "::ffff:1.2.3.4".into(),
                rport: 443,
            },
        );
        assert_eq!(
            ours_keys(&n),
            vec![(
                6,
                Key::Net {
                    pid: 7,
                    proto: "tcp".into(),
                    dir: "out",
                    addr: "1.2.3.4".into(),
                    port: 443
                }
            )]
        );
        let d = ev(
            7,
            EventKind::DnsQuery {
                proc: ProcRef::new(7, None),
                name: "Example.COM.".into(),
                results: vec![],
            },
        );
        assert_eq!(
            ours_keys(&d),
            vec![(
                7,
                Key::Dns {
                    pid: 7,
                    name: "example.com".into()
                }
            )]
        );
    }

    #[test]
    fn sysmon_etw_clock_skew_is_estimated_and_corrected() {
        // 노트북 3회차 재현: Sysmon 의 DNS 시각만 152.6초 이르다
        let t0 = utc_to_filetime("2026-11-01 23:18:00.000").unwrap();
        let skew = 1526 * SEC / 10;
        let mut sys = vec![];
        let mut ours = vec![];
        for i in 0..20i64 {
            let k = Key::Dns {
                pid: 100 + i as u32,
                name: format!("h{i}.example"),
            };
            // 실측처럼 일부만 어긋난다 (짝수 번째만)
            sys.push((
                t0 + i * SEC - if i % 2 == 0 { skew } else { 0 },
                k.clone(),
                "x.exe".to_string(),
            ));
            ours.push((t0 + i * SEC + 3_000_000, k));
            let p = Key::ProcStart {
                pid: 100 + i as u32,
                name: "x.exe".into(),
            };
            sys.push((t0 + i * SEC, p.clone(), "x.exe".to_string()));
            ours.push((t0 + i * SEC, p));
        }
        let off = estimate_etw_offset(&sys, &ours);
        assert!((off - skew).abs() < SEC, "{off}");
        let rep = compare(
            &sys,
            &ours,
            &Options {
                from: t0 - 400 * SEC,
                to: t0 + 400 * SEC,
                tolerance: 2 * SEC,
                exclude_images: vec![],
                examples: 3,
            },
        );
        assert_eq!(rep.categories["dns(22)"].missed, 0);
        assert_eq!(rep.categories["dns(22)"].matched_by_offset, 10);
        assert_eq!(rep.categories["dns(22)"].ours_only, 0);
        // L004 회귀: 보정 전 시각은 구간 시작 전, 보정 뒤는 구간 안 → 세어야 한다
        let w = Options {
            from: t0 - SEC,
            to: t0 + 30 * SEC,
            tolerance: 2 * SEC,
            exclude_images: vec![],
            examples: 0,
        };
        let r2 = compare(&sys, &ours, &w);
        assert_eq!(
            r2.categories["dns(22)"].sysmon, 20,
            "어긋난 10건도 구간 안으로 세야"
        );
        assert_eq!(r2.categories["dns(22)"].missed, 0);
        assert_eq!(
            rep.categories["process_start(1)"].missed, 0,
            "드라이버 쪽은 보정하지 않는다"
        );
        // 어긋남이 없으면 0
        let rep0 = compare(
            &ours
                .iter()
                .map(|(t, k)| (*t, k.clone(), "x".to_string()))
                .collect::<Vec<_>>(),
            &ours,
            &Options {
                from: 0,
                to: i64::MAX,
                tolerance: 2 * SEC,
                exclude_images: vec![],
                examples: 0,
            },
        );
        assert_eq!(rep0.sysmon_etw_offset, 0);
    }

    #[test]
    fn compare_counts_matches_misses_tolerance_and_exclusions() {
        let t0 = utc_to_filetime("2026-11-02 00:00:10.000").unwrap();
        let sys_lines = [
            // 잡힘 (0.5초 차)
            r#"{"id":1,"UtcTime":"2026-11-02 00:00:10.500","ProcessId":7,"Image":"C:\\Windows\\System32\\curl.exe"}"#,
            // 놓침 (다른 PID)
            r#"{"id":1,"UtcTime":"2026-11-02 00:00:11.000","ProcessId":8,"Image":"C:\\x\\evil.exe"}"#,
            // 허용치(2초) 밖 → 놓침
            r#"{"id":3,"UtcTime":"2026-11-02 00:00:15.000","ProcessId":7,"Image":"C:\\Windows\\System32\\curl.exe","Protocol":"tcp","Initiated":"true","DestinationIp":"1.2.3.4","DestinationPort":"443"}"#,
            // 제외 이미지(Sysmon 자신)
            r#"{"id":1,"UtcTime":"2026-11-02 00:00:12.000","ProcessId":99,"Image":"C:\\Windows\\Sysmon64.exe"}"#,
            r#"{"id":3,"UtcTime":"2026-11-02 00:00:12.000","ProcessId":99,"Image":"C:\\Windows\\Sysmon64.exe","Protocol":"tcp","Initiated":"true","DestinationIp":"9.9.9.9","DestinationPort":"80"}"#,
            // 범위 밖 확장자 → 비교 안 함
            r#"{"id":11,"UtcTime":"2026-11-02 00:00:12.000","ProcessId":7,"Image":"x","TargetFilename":"C:\\a\\b.txt"}"#,
            // 실행된 파일의 생성 → 비교 (우리 기록 있음)
            r#"{"id":11,"UtcTime":"2026-11-02 00:00:10.200","ProcessId":5,"Image":"C:\\b\\dl.exe","TargetFilename":"C:\\x\\evil.exe"}"#,
            // 실행 안 된 파일 생성 → 비교 안 함
            r#"{"id":11,"UtcTime":"2026-11-02 00:00:10.200","ProcessId":5,"Image":"C:\\b\\dl.exe","TargetFilename":"C:\\x\\never.exe"}"#,
            // 구간 밖
            r#"{"id":1,"UtcTime":"2026-11-02 01:00:00.000","ProcessId":7,"Image":"C:\\a\\late.exe"}"#,
            "not json",
        ];
        let (sys, n, bad) = load_sysmon(&sys_lines.join("\n"));
        assert_eq!((n, bad), (10, 1));
        let ours = vec![
            (
                t0,
                Key::ProcStart {
                    pid: 7,
                    name: "curl.exe".into(),
                },
            ),
            (
                t0 + 2 * SEC,
                Key::Net {
                    pid: 7,
                    proto: "tcp".into(),
                    dir: "out",
                    addr: "1.2.3.4".into(),
                    port: 443,
                },
            ),
            (
                t0 + SEC,
                Key::Dns {
                    pid: 7,
                    name: "only.ours".into(),
                },
            ),
            (
                t0,
                Key::File {
                    path: r"\x\evil.exe".into(),
                },
            ),
        ];
        let rep = compare(
            &sys,
            &ours,
            &Options {
                from: t0 - SEC,
                to: t0 + 60 * SEC,
                tolerance: 2 * SEC,
                exclude_images: vec!["sysmon64.exe".into()],
                examples: 5,
            },
        );
        let ps = &rep.categories["process_start(1)"];
        assert_eq!((ps.sysmon, ps.matched, ps.missed), (2, 1, 1));
        assert!((ps.miss_rate_pct - 50.0).abs() < 1e-9);
        assert!(ps.missed_examples[0].contains("evil.exe"));
        let net = &rep.categories["network_out(3)"];
        assert_eq!(
            (net.sysmon, net.matched, net.missed),
            (1, 0, 1),
            "15초 기록 vs 12초 우리 기록 = 3초 차 > 2초"
        );
        assert_eq!(rep.categories["dns(22)"].ours_only, 1);
        let f = &rep.categories["file_create(11)"];
        assert_eq!(
            (f.sysmon, f.matched),
            (1, 1),
            "실행된 evil.exe 만 비교, never.exe·b.txt 는 제외"
        );
    }
}
