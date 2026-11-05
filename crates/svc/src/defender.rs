//! 이야기형 10판 5-9 (3): Windows 기본 보호와 잇기 — 진단에 "제어된 폴더 액세스(CFA)" 상태를 보인다.
//!
//! 근거(Microsoft Learn "Enable controlled folder access", 2026-11-05 확인): 상태 값 0 꺼짐(기본), 1 차단, 2 감사,
//! 3 디스크 수정만 차단, 4 디스크 수정만 감사. Get-MpPreference 속성 이름 EnableControlledFolderAccess.
//! 레지스트리 위치(Defender 설정 키)는 문서에 없어 poc3 로 확인했다: Get-MpPreference 0/AuditMode 2 와 레지스트리 값이
//! 같이 움직임(poc3 run-97, windows-2025, 2026-11-05 "CFA: before mp=0 reg=0 audit mp=2 reg=2 match=True").
//! 그룹 정책 키(Policies\...)는 아직 실측하지 않았다(추측).
//! CFA 는 Defender 실시간 보호가 켜져 있어야 동작한다(10판 5-9 (3)). 다른 백신이 주 백신이면 Defender 가 수동 모드일 수 있어
//! 레지스트리 값만으로 "동작 중"이라 말하지 않는다 — 화면은 "설정 값"으로 쓴다.

/// 29차 미결: 수집기 진단 카운터 읽기(서비스 바이너리가 수집 세션을 연 뒤 한 번 넣는다). 없으면 진단에 null
pub static COLLECTOR_COUNTS: std::sync::OnceLock<
    Box<dyn Fn() -> Vec<(String, u64)> + Send + Sync>,
> = std::sync::OnceLock::new();

/// 진단에 보일 명령줄 수집 카운터만 고른다(공급자별 콜백 수 전체는 너무 많다)
pub fn cmdline_counts(all: &[(String, u64)]) -> serde_json::Value {
    let keys = [
        "kernel_session_ok",
        "kernel_session_failed",
        "cmdline_kernel",
        "cmdline_ok",
        "cmdline_renamed_tool",
        "cmdline_unmatched",
    ];
    let mut m = serde_json::Map::new();
    for k in keys {
        m.insert(
            k.into(),
            serde_json::json!(all.iter().find(|x| x.0 == k).map(|x| x.1).unwrap_or(0)),
        );
    }
    // 직접 읽기 실패는 사유별 합(gone·denied·other)
    let open_failed: u64 = all
        .iter()
        .filter(|x| x.0.starts_with("cmdline_open_failed"))
        .map(|x| x.1)
        .sum();
    m.insert("cmdline_open_failed".into(), serde_json::json!(open_failed));
    serde_json::Value::Object(m)
}

/// 레지스트리 DWORD → 상태 이름
pub fn cfa_mode(v: Option<u32>) -> &'static str {
    match v {
        None => "unset",
        Some(0) => "off",
        Some(1) => "block",
        Some(2) => "audit",
        Some(3) => "block_disk",
        Some(4) => "audit_disk",
        Some(_) => "unknown",
    }
}

/// 정책 키가 있으면 정책이 이긴다(그룹 정책·MDM). 실시간 보호는 Disable 값(1 = 꺼짐)의 반대
pub fn status_json(
    local: Option<u32>,
    policy: Option<u32>,
    rt_disable_local: Option<u32>,
    rt_disable_policy: Option<u32>,
) -> serde_json::Value {
    let (v, source) = match (policy, local) {
        (Some(p), _) => (Some(p), "policy"),
        (None, Some(l)) => (Some(l), "local"),
        (None, None) => (None, "none"),
    };
    let rt = rt_disable_policy.or(rt_disable_local).map(|d| d == 0);
    serde_json::json!({
        "cfa": cfa_mode(v),
        "cfa_source": source,
        // None = 값 없음(기본은 켜짐이지만 다른 백신이면 Defender 가 꺼져 있을 수 있다 — 단정하지 않는다)
        "realtime": rt,
    })
}

#[cfg(any(windows, feature = "host-check"))]
pub fn read() -> serde_json::Value {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD,
    };
    fn dword(key: &str, value: &str) -> Option<u32> {
        let mut v = 0u32;
        let mut cb = 4u32;
        let r = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                crate::win::wide(key).as_ptr(),
                crate::win::wide(value).as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                &mut v as *mut u32 as *mut _,
                &mut cb,
            )
        };
        (r == 0).then_some(v)
    }
    const CFA: &str = r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
    const CFA_POL: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
    const RT: &str = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
    const RT_POL: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
    status_json(
        dword(CFA, "EnableControlledFolderAccess"),
        dword(CFA_POL, "EnableControlledFolderAccess"),
        dword(RT, "DisableRealtimeMonitoring"),
        dword(RT_POL, "DisableRealtimeMonitoring"),
    )
}

#[cfg(not(any(windows, feature = "host-check")))]
pub fn read() -> serde_json::Value {
    serde_json::Value::Null
}

/// 10판 5-9 (3): Defender 운영 로그(Microsoft-Windows-Windows Defender/Operational)에서 읽는 사건 번호.
/// 1123 CFA 차단, 1124 CFA 감사(Microsoft Learn "Controlled folder access" 이벤트 표). 1127/1128(디스크 섹터)은 경로가 아니라 장치라 아직 받지 않는다
pub const CHANNEL: &str = "Microsoft-Windows-Windows Defender/Operational";
pub const EVENT_IDS: [u32; 2] = [1123, 1124];

/// 렌더된 이벤트 XML 에서 꺼낸 것
#[derive(Debug, Clone, PartialEq)]
pub struct DefEvent {
    pub event_id: u32,
    pub record_id: u64,
    /// TimeCreated SystemTime → unix 초(못 읽으면 0)
    pub ts: i64,
    /// EventData 의 Data Name=... 쌍(이름은 문서에 없어 **추측** — poc3 가 실제 XML 을 남긴다)
    pub data: Vec<(String, String)>,
}

impl DefEvent {
    pub fn get(&self, names: &[&str]) -> Option<&str> {
        names
            .iter()
            .find_map(|n| {
                self.data
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(n))
                    .map(|(_, v)| v.as_str())
            })
            .filter(|v| !v.is_empty())
    }
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// `<tag ...>text</tag>` 의 text (처음 하나)
fn elem_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let mut from = 0;
    while let Some(i) = xml[from..].find(&open) {
        let i = from + i;
        let after = &xml[i + open.len()..];
        // <EventID> 와 <EventIDx> 를 가른다
        if after.starts_with('>') || after.starts_with(' ') || after.starts_with('/') {
            let gt = i + open.len() + after.find('>')?;
            if xml[..gt].ends_with('/') {
                return Some("");
            }
            let close = format!("</{tag}>");
            let end = gt + 1 + xml[gt + 1..].find(&close)?;
            return Some(&xml[gt + 1..end]);
        }
        from = i + open.len();
    }
    None
}

/// 속성 값(작은따옴표·큰따옴표 모두)
fn attr<'a>(tag_body: &'a str, name: &str) -> Option<&'a str> {
    let k = format!("{name}=");
    let i = tag_body.find(&k)? + k.len();
    let q = tag_body[i..].chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let rest = &tag_body[i + 1..];
    Some(&rest[..rest.find(q)?])
}

/// "2026-11-05T07:10:52.1234567Z" → unix 초
pub fn iso_to_unix(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |a: usize, l: usize| s.get(a..a + l)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (
        n(0, 4)?,
        n(5, 2)?,
        n(8, 2)?,
        n(11, 2)?,
        n(14, 2)?,
        n(17, 2)?,
    );
    // days_from_civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

/// EvtRender(EvtRenderEventXml) 결과 한 건을 읽는다. 사건 번호·레코드 번호가 없으면 None
pub fn parse_event_xml(xml: &str) -> Option<DefEvent> {
    let event_id = elem_text(xml, "EventID")?.trim().parse().ok()?;
    let record_id = elem_text(xml, "EventRecordID")?.trim().parse().ok()?;
    let ts = xml
        .find("<TimeCreated")
        .and_then(|i| {
            let body = &xml[i..i + xml[i..].find('>')?];
            attr(body, "SystemTime")
        })
        .and_then(iso_to_unix)
        .unwrap_or(0);
    let mut data = Vec::new();
    if let Some(ed) = elem_text(xml, "EventData") {
        let mut rest = ed;
        while let Some(i) = rest.find("<Data") {
            let r = &rest[i..];
            let Some(gt) = r.find('>') else { break };
            let head = &r[..gt];
            let name = attr(head, "Name").unwrap_or("").to_string();
            if head.ends_with('/') {
                data.push((name, String::new()));
                rest = &r[gt + 1..];
                continue;
            }
            let Some(end) = r.find("</Data>") else { break };
            data.push((name, unescape(&r[gt + 1..end])));
            rest = &r[end + 7..];
        }
    }
    Some(DefEvent {
        event_id,
        record_id,
        ts,
        data,
    })
}

/// 서비스 사건으로 남길 것: (kind, severity, 문장, 대상 JSON). 사실만 쓴다 — "랜섬웨어"·의도 단정 없음(원칙 22·FORBIDDEN)
pub fn to_service_event(e: &DefEvent) -> Option<(String, u8, String, serde_json::Value)> {
    let (kind, verb, sev) = match e.event_id {
        1123 => ("defender_cfa_blocked", "막았습니다", 3u8),
        1124 => (
            "defender_cfa_audited",
            "기록했습니다(감사 모드라 막지는 않음)",
            2u8,
        ),
        _ => return None,
    };
    let image = e
        .get(&["Process Name", "ProcessName", "Process"])
        .unwrap_or("")
        .to_string();
    let path = e.get(&["Path", "Target", "File"]).unwrap_or("").to_string();
    let prog = if image.is_empty() {
        "알 수 없는 프로그램".to_string()
    } else {
        image.clone()
    };
    let what = if path.is_empty() {
        "보호 폴더".to_string()
    } else {
        path.clone()
    };
    let detail = format!("Windows 기본 보호(제어된 폴더 액세스)가 {prog} 의 {what} 변경을 {verb}");
    let target = serde_json::json!({ "type": "defender", "event_id": e.event_id, "record_id": e.record_id, "defender_ts": e.ts, "image": image, "path": path });
    Some((kind.into(), sev, detail, target))
}

/// 첫 실행(책갈피 없음)에 얼마나 지난 기록까지 사건으로 남길지 — 오래된 감사 기록이 알림을 쏟지 않게
pub const FIRST_RUN_LOOKBACK_SECS: i64 = 86_400;

/// 새로 남길 사건만 고른다. last = 지난번까지 남긴 레코드 번호(None = 첫 실행). 돌려주는 두 번째 값 = 새 책갈피
/// 레코드 번호가 줄면(로그 지움·채널 재생성) 처음부터 다시 센다 — 그때도 첫 실행처럼 하루 치만
pub fn select_new(
    mut evs: Vec<DefEvent>,
    last: Option<u64>,
    now: i64,
) -> (Vec<DefEvent>, Option<u64>) {
    evs.sort_by_key(|e| e.record_id);
    let max = evs.last().map(|e| e.record_id);
    let reset = matches!((last, max), (Some(l), Some(m)) if m < l);
    let keep: Vec<DefEvent> = match last {
        Some(l) if !reset => evs.into_iter().filter(|e| e.record_id > l).collect(),
        _ => evs
            .into_iter()
            .filter(|e| e.ts == 0 || now - e.ts <= FIRST_RUN_LOOKBACK_SECS)
            .collect(),
    };
    let next = match (last, max) {
        (Some(l), Some(m)) if !reset => Some(l.max(m)),
        (_, Some(m)) => Some(m),
        (l, None) => l,
    };
    (keep, next)
}

#[cfg(any(windows, feature = "host-check"))]
pub fn query_events() -> Result<Vec<DefEvent>, String> {
    use windows_sys::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
        EvtRenderEventXml,
    };
    // 최근 것부터 최대 500건(하루에 그보다 많으면 오래된 쪽은 건너뛴다 — 다음 판에서 책갈피 XPath 로)
    let ids = EVENT_IDS
        .iter()
        .map(|i| format!("EventID={i}"))
        .collect::<Vec<_>>()
        .join(" or ");
    let q = format!("*[System[({ids})]]");
    let h = unsafe {
        EvtQuery(
            0,
            crate::win::wide(CHANNEL).as_ptr(),
            crate::win::wide(&q).as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    };
    if h == 0 {
        // 채널 없음(Defender 제거·다른 백신) 등 — 오류 번호만
        return Err(format!("EvtQuery {}", std::io::Error::last_os_error()));
    }
    let mut out = Vec::new();
    let mut handles = [0isize; 32];
    while out.len() < 500 {
        let mut got = 0u32;
        let ok = unsafe {
            EvtNext(
                h,
                handles.len() as u32,
                handles.as_mut_ptr(),
                1000,
                0,
                &mut got,
            )
        };
        if ok == 0 {
            break;
        }
        // 받은 핸들은 모두 렌더·닫기(한도는 묶음 사이에서만 본다 — 남은 핸들을 새게 두지 않는다)
        for &eh in &handles[..got as usize] {
            let mut used = 0u32;
            let mut props = 0u32;
            unsafe {
                EvtRender(
                    0,
                    eh,
                    EvtRenderEventXml,
                    0,
                    std::ptr::null_mut(),
                    &mut used,
                    &mut props,
                )
            };
            let mut buf = vec![0u16; (used as usize / 2) + 1];
            let r = unsafe {
                EvtRender(
                    0,
                    eh,
                    EvtRenderEventXml,
                    (buf.len() * 2) as u32,
                    buf.as_mut_ptr() as *mut _,
                    &mut used,
                    &mut props,
                )
            };
            unsafe { EvtClose(eh) };
            if r != 0 {
                let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                if let Some(e) = parse_event_xml(&String::from_utf16_lossy(&buf[..n])) {
                    out.push(e);
                }
            }
        }
    }
    unsafe { EvtClose(h) };
    Ok(out)
}

#[cfg(not(any(windows, feature = "host-check")))]
pub fn query_events() -> Result<Vec<DefEvent>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_counts_pick() {
        let all = vec![
            ("kernel_session_ok".to_string(), 1),
            ("cmdline_kernel".into(), 5),
            ("cmdline_open_failed_gone".into(), 2),
            ("cmdline_open_failed_denied".into(), 1),
            ("process".into(), 900),
        ];
        let v = cmdline_counts(&all);
        assert_eq!(v["cmdline_kernel"], 5);
        assert_eq!(v["cmdline_open_failed"], 3);
        assert_eq!(v["kernel_session_failed"], 0);
        assert!(v.get("process").is_none());
    }

    #[test]
    fn modes_and_policy_wins() {
        assert_eq!(cfa_mode(Some(1)), "block");
        assert_eq!(cfa_mode(Some(9)), "unknown");
        let v = status_json(Some(0), Some(1), Some(0), None);
        assert_eq!(v["cfa"], "block");
        assert_eq!(v["cfa_source"], "policy");
        assert_eq!(v["realtime"], true);
        let v = status_json(None, None, None, Some(1));
        assert_eq!(v["cfa"], "unset");
        assert_eq!(v["cfa_source"], "none");
        assert_eq!(v["realtime"], false);
        assert_eq!(
            status_json(Some(2), None, None, None)["realtime"],
            serde_json::Value::Null
        );
    }

    const XML1123: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>1123</EventID><Version>0</Version><TimeCreated SystemTime='2026-11-05T07:10:52.1234567Z'/><EventRecordID>4521</EventRecordID></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Detection Time'>2026-11-05T07:10:52.000Z</Data><Data Name='Path'>C:\Users\a\Documents\x &amp; y.docx</Data><Data Name='Process Name'>C:\Users\a\Downloads\tool.exe</Data><Data Name='Empty'/></EventData></Event>"#;

    #[test]
    fn parse_1123() {
        let e = parse_event_xml(XML1123).unwrap();
        assert_eq!(e.event_id, 1123);
        assert_eq!(e.record_id, 4521);
        assert_eq!(e.ts, 1_793_862_652);
        assert_eq!(e.get(&["Path"]), Some(r"C:\Users\a\Documents\x & y.docx"));
        assert_eq!(
            e.get(&["process name"]),
            Some(r"C:\Users\a\Downloads\tool.exe")
        );
        assert_eq!(e.get(&["Empty"]), None);
        let (kind, sev, detail, t) = to_service_event(&e).unwrap();
        assert_eq!(kind, "defender_cfa_blocked");
        assert_eq!(sev, 3);
        assert!(detail.contains("tool.exe") && detail.contains("막았습니다"));
        assert!(!detail.contains("랜섬"));
        assert_eq!(t["record_id"], 4521);
        // 큰따옴표 속성도
        let x = XML1123.replace(
            "SystemTime='2026-11-05T07:10:52.1234567Z'",
            "SystemTime=\"2026-11-05T07:10:52.1234567Z\"",
        );
        assert_eq!(parse_event_xml(&x).unwrap().ts, 1_793_862_652);
        // 다른 번호는 사건으로 남기지 않는다
        let x = XML1123.replace("<EventID>1123</EventID>", "<EventID>1116</EventID>");
        assert!(to_service_event(&parse_event_xml(&x).unwrap()).is_none());
        assert!(parse_event_xml("<Event/>").is_none());
    }

    #[test]
    fn iso() {
        assert_eq!(iso_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso_to_unix("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(iso_to_unix("bad"), None);
    }

    #[test]
    fn select_bookmark() {
        let ev = |r: u64, ts: i64| DefEvent {
            event_id: 1123,
            record_id: r,
            ts,
            data: vec![],
        };
        let now = 1_000_000;
        // 첫 실행: 하루 안 것만, 책갈피 = 최대
        let (k, b) = select_new(vec![ev(5, now - 10), ev(3, now - 200_000)], None, now);
        assert_eq!(k.iter().map(|e| e.record_id).collect::<Vec<_>>(), vec![5]);
        assert_eq!(b, Some(5));
        // 다음: 책갈피 뒤만
        let (k, b) = select_new(vec![ev(5, now), ev(6, now), ev(7, now)], Some(5), now);
        assert_eq!(k.len(), 2);
        assert_eq!(b, Some(7));
        // 새 것 없음: 책갈피 유지
        let (k, b) = select_new(vec![], Some(7), now);
        assert!(k.is_empty());
        assert_eq!(b, Some(7));
        // 로그를 지워 번호가 줄면 다시 첫 실행처럼
        let (k, b) = select_new(vec![ev(2, now)], Some(7), now);
        assert_eq!(k.len(), 1);
        assert_eq!(b, Some(2));
    }
}
