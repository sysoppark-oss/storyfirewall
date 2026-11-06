//! 원격 제어 사기 경보 (기획서 14판 20-4): 원격 제어 프로그램이 외부로 데이터를 계속 보내기 시작하면
//! "세션이 열린 모양"으로 보고 바로 알린다. 판정 점수가 아니라 사실(어느 프로그램이 언제부터 얼마나 보냈는가)이다.
//!
//! 플랫폼 전용 코드 없음(엔진 공유 원칙). 입력은 그래프의 `conn_bytes`(수집기가 1초마다 더하는 연결별 누적 바이트)다.
//!
//! 세션 모양: 조작당하는 PC 는 화면을 내보낸다 → 보낸 양이 받은 양보다 크고 일정 시간 이어진다.
//! 반대로 이 PC 에서 다른 PC 를 조작하면 받는 양이 크다 — 그 경우는 경보 대상이 아니다(문장도 다르게 쓸 수 있게 방향을 남긴다).
//!
//! 기준값(START_*, END_*)은 추측이다. 노트북의 실제 원격 도구(유휴·세션)로 재서 고친다(31차 이후 실측 항목).

use std::collections::{BTreeMap, VecDeque};

use rusqlite::params;
use serde::Serialize;

use crate::store::Store;
use crate::Result;

/// 원격 제어 프로그램 한 종류.
/// `images` 는 소문자 파일 이름. 이름만으로 맞추므로 이름을 바꾼 사본은 놓친다 —
/// 이 기능의 대상(사기범이 피해자에게 정품을 설치하게 하는 수법)에서는 정품 이름이 그대로 쓰인다.
/// 서명자(`signer`)는 화면 표시·추가 확인용이고 아직 일치 조건으로 쓰지 않는다.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RemoteTool {
    pub key: &'static str,
    pub display: &'static str,
    pub images: &'static [&'static str],
    pub signer: &'static str,
    /// 이름 확인에 쓴 출처(외부 데이터 원칙: 의미·정확도·출처를 문서로)
    pub source: &'static str,
}

/// 첫 목록. 출처는 제조사 문서·공개 탐지 규칙(MITRE T1219, CISA AA23-025A)과 실측으로 확인한다.
/// 국내 원격 지원 도구(은행·통신사 고객센터용)는 노트북·VM 실측 뒤 넣는다.
pub const TOOLS: &[RemoteTool] = &[
    RemoteTool {
        key: "teamviewer",
        display: "TeamViewer",
        images: &[
            "teamviewer.exe",
            "teamviewer_service.exe",
            "tv_w32.exe",
            "tv_x64.exe",
            "teamviewerqs.exe",
        ],
        signer: "TeamViewer Germany GmbH",
        source: "MITRE ATT&CK T1219.002; 노트북 설치본",
    },
    RemoteTool {
        key: "anydesk",
        display: "AnyDesk",
        images: &["anydesk.exe"],
        signer: "AnyDesk Software GmbH",
        source: "MITRE ATT&CK T1219.002; CISA AA23-025A",
    },
    RemoteTool {
        key: "rustdesk",
        display: "RustDesk",
        images: &["rustdesk.exe"],
        signer: "Purslane Ltd",
        source: "MITRE ATT&CK T1219.002",
    },
    RemoteTool {
        key: "chrome_remote_desktop",
        display: "Chrome 원격 데스크톱",
        images: &["remoting_host.exe", "remoting_desktop.exe"],
        signer: "Google LLC",
        source: "MITRE ATT&CK T1219.002",
    },
    RemoteTool {
        key: "quick_assist",
        display: "Windows 빠른 지원",
        images: &["quickassist.exe"],
        signer: "Microsoft Corporation",
        source: "MITRE ATT&CK S1209 (Quick Assist)",
    },
    RemoteTool {
        key: "screenconnect",
        display: "ScreenConnect",
        images: &[
            "screenconnect.clientservice.exe",
            "screenconnect.windowsclient.exe",
        ],
        signer: "ConnectWise, LLC",
        source: "CISA AA23-025A",
    },
];

fn base_lower(image: &str) -> String {
    image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase()
}

/// 프로세스 노드의 실행 파일(executed_as)이 원격 도구 제조사의 유효 서명인가
pub fn tool_of_signer(store: &Store, proc_node: i64) -> Option<&'static RemoteTool> {
    let attrs: Option<String> = store
        .conn()
        .query_row(
            "SELECT f.attrs_json FROM edges x JOIN nodes f ON f.id = x.src WHERE x.dst = ?1 AND x.rel = 'executed_as' LIMIT 1",
            params![proc_node],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    let v: serde_json::Value = serde_json::from_str(attrs.as_deref()?).ok()?;
    if v.get("sig_status").and_then(|x| x.as_str()) != Some("valid") {
        return None;
    }
    let signer = v.get("signer").and_then(|x| x.as_str())?;
    TOOLS.iter().find(|t| t.signer.eq_ignore_ascii_case(signer))
}

/// 실행 파일 경로가 원격 제어 프로그램인가
pub fn tool_of(image: &str) -> Option<&'static RemoteTool> {
    let b = base_lower(image);
    TOOLS.iter().find(|t| t.images.contains(&b.as_str()))
}

/// 세션 시작: 최근 WINDOW_SECS 동안 보낸 양이 START_SENT 이상이고, 받은 양보다 크다.
pub const WINDOW_SECS: i64 = 30;
pub const START_SENT: u64 = 600 * 1024;
/// 세션 끝: 최근 WINDOW_SECS 동안 보낸 양이 END_SENT 미만인 상태가 END_QUIET_SECS 이어진다(또는 프로세스가 사라짐).
pub const END_SENT: u64 = 150 * 1024;
pub const END_QUIET_SECS: i64 = 90;

/// 한 번 잰 값: 그 프로세스가 지금까지 외부(루프백 제외)로 보낸·받은 누적 바이트
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub pid: u32,
    pub sent: u64,
    pub recv: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Transition {
    /// 세션 모양이 시작됨. `ts` 는 창 안에서 처음 많이 보낸 시각(유닉스 초)
    Started {
        pid: u32,
        tool: &'static str,
        ts: i64,
        sent_window: u64,
    },
    /// 끝남. `sent_total` 은 세션 동안 보낸 양
    Ended {
        pid: u32,
        tool: &'static str,
        started_ts: i64,
        ended_ts: i64,
        sent_total: u64,
        process_gone: bool,
    },
}

#[derive(Debug, Default)]
struct PidState {
    tool: &'static str,
    last_sent: Option<u64>,
    last_recv: Option<u64>,
    /// (ts, 보낸 증분, 받은 증분)
    window: VecDeque<(i64, u64, u64)>,
    active_since: Option<i64>,
    quiet_since: Option<i64>,
    sent_in_session: u64,
}

/// 원격 도구 프로세스별 세션 상태. 서비스가 몇 초마다 `observe` 를 부른다.
#[derive(Debug, Default)]
pub struct SessionTracker {
    pids: BTreeMap<u32, PidState>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// 지금 세션 모양인 프로세스
    pub fn active(&self) -> Vec<(u32, &'static str, i64)> {
        self.pids
            .iter()
            .filter_map(|(p, s)| s.active_since.map(|t| (*p, s.tool, t)))
            .collect()
    }

    /// `alive`: 지금 살아 있는 원격 도구 프로세스(pid, 도구 key). `samples`: 그 pid 들의 누적 바이트.
    /// 첫 관찰은 기준점만 잡는다(서비스가 늦게 켜져도 지난 누적량을 한 번에 증분으로 세지 않는다).
    pub fn observe(
        &mut self,
        now: i64,
        alive: &[(u32, &'static str)],
        samples: &[Sample],
    ) -> Vec<Transition> {
        let mut out = Vec::new();
        // 사라진 프로세스: 세션이었으면 끝
        let gone: Vec<u32> = self
            .pids
            .keys()
            .filter(|p| !alive.iter().any(|(a, _)| a == *p))
            .copied()
            .collect();
        for p in gone {
            if let Some(s) = self.pids.remove(&p) {
                if let Some(st) = s.active_since {
                    out.push(Transition::Ended {
                        pid: p,
                        tool: s.tool,
                        started_ts: st,
                        ended_ts: now,
                        sent_total: s.sent_in_session,
                        process_gone: true,
                    });
                }
            }
        }
        for (pid, tool) in alive {
            let s = self.pids.entry(*pid).or_insert_with(|| PidState {
                tool,
                ..Default::default()
            });
            let smp = samples
                .iter()
                .find(|x| x.pid == *pid)
                .copied()
                .unwrap_or(Sample {
                    pid: *pid,
                    sent: 0,
                    recv: 0,
                });
            // 누적값이 줄면(연결 행이 보관 정리로 지워짐 등) 기준점만 다시 잡는다
            let ds = match s.last_sent {
                Some(l) if smp.sent >= l => smp.sent - l,
                _ => 0,
            };
            let dr = match s.last_recv {
                Some(l) if smp.recv >= l => smp.recv - l,
                _ => 0,
            };
            s.last_sent = Some(smp.sent);
            s.last_recv = Some(smp.recv);
            s.window.push_back((now, ds, dr));
            while s
                .window
                .front()
                .is_some_and(|(t, _, _)| *t <= now - WINDOW_SECS)
            {
                s.window.pop_front();
            }
            let ws: u64 = s.window.iter().map(|w| w.1).sum();
            let wr: u64 = s.window.iter().map(|w| w.2).sum();
            if s.active_since.is_some() {
                s.sent_in_session += ds;
            }
            match s.active_since {
                None => {
                    if ws >= START_SENT && ws > wr {
                        let first = s
                            .window
                            .iter()
                            .find(|w| w.1 > 0)
                            .map(|w| w.0)
                            .unwrap_or(now);
                        s.active_since = Some(first);
                        s.quiet_since = None;
                        s.sent_in_session = ws;
                        out.push(Transition::Started {
                            pid: *pid,
                            tool: s.tool,
                            ts: first,
                            sent_window: ws,
                        });
                    }
                }
                Some(st) => {
                    if ws < END_SENT {
                        let q = *s.quiet_since.get_or_insert(now);
                        if now - q >= END_QUIET_SECS {
                            out.push(Transition::Ended {
                                pid: *pid,
                                tool: s.tool,
                                started_ts: st,
                                ended_ts: now,
                                sent_total: s.sent_in_session,
                                process_gone: false,
                            });
                            s.active_since = None;
                            s.quiet_since = None;
                            s.sent_in_session = 0;
                        }
                    } else {
                        s.quiet_since = None;
                    }
                }
            }
        }
        out
    }
}

/// pid 들의 외부(루프백 제외) 누적 송수신. `conn_bytes` 의 기본 키가 pid 로 시작해 pid 별로 색인을 탄다.
/// 주의: conn_bytes 는 pid 만 키로 쓴다 — 같은 pid 가 재사용되면 앞 프로세스의 누적이 섞일 수 있다.
/// 추적기는 증분만 보므로 섞인 누적은 첫 관찰의 기준점에 흡수된다.
pub fn sent_recv_by_pid(store: &Store, pids: &[u32]) -> Result<Vec<Sample>> {
    let mut st = store.conn().prepare_cached(
        "SELECT COALESCE(SUM(sent),0), COALESCE(SUM(recv),0) FROM conn_bytes
         WHERE pid = ?1 AND raddr NOT IN ('127.0.0.1','::1') AND raddr NOT LIKE '127.%'",
    )?;
    let mut out = Vec::with_capacity(pids.len());
    for p in pids {
        let (s, r): (i64, i64) = st.query_row(params![p], |r| Ok((r.get(0)?, r.get(1)?)))?;
        out.push(Sample {
            pid: *p,
            sent: s.max(0) as u64,
            recv: r.max(0) as u64,
        });
    }
    Ok(out)
}

/// 사람이 읽는 양 (KB/MB)
pub fn human_bytes(b: u64) -> String {
    if b >= 1024 * 1024 {
        format!("{:.1}MB", b as f64 / (1024.0 * 1024.0))
    } else {
        format!("{}KB", b.div_ceil(1024))
    }
}

/// 세션 시작 문장 — 사실만(의도·상대를 단정하지 않는다)
pub fn start_text(display: &str, sent_window: u64) -> String {
    format!(
        "{display} 가 외부로 데이터를 계속 보내기 시작했습니다(최근 {WINDOW_SECS}초에 {}). 다른 곳에서 이 PC 화면을 보거나 조작할 때의 모양입니다. 직접 연 원격 접속이 아니면 바로 끊으세요.",
        human_bytes(sent_window)
    )
}

/// 세션 끝 문장
pub fn end_text(
    display: &str,
    started_ts: i64,
    ended_ts: i64,
    sent_total: u64,
    process_gone: bool,
) -> String {
    let mins = ((ended_ts - started_ts).max(0) + 59) / 60;
    let why = if process_gone {
        "프로그램이 종료됨"
    } else {
        "보내는 양이 줄어듦"
    };
    format!(
        "{display} 의 원격 세션 모양이 끝났습니다({why}). 약 {mins}분 동안 {} 를 보냈습니다.",
        human_bytes(sent_total)
    )
}

/// 서비스가 켜질 때 이미 돌고 있는 원격 도구 프로세스(수집기 스냅샷은 그래프에 바로 들어가 배치로 오지 않는다).
/// 스냅샷 노드의 시각은 프로세스 생성 시각이라(며칠 전일 수 있음) 노드 시각으로 고르지 않는다 —
/// 최근 `since_ts`(FILETIME) 이후 통신량이 기록된 pid 중, 끝 표시 없는 최신 프로세스 노드의 이름이 목록에 있는 것.
/// 통신하지 않는 원격 도구는 세션 모양을 만들 수 없다 — 서비스가 1분마다 다시 불러, 조용하다 통신을 시작한 것도 잡는다.
/// (pid, 노드 id, 도구 key)
pub fn running_tools(store: &Store, since_ts: i64) -> Result<Vec<(u32, i64, &'static str)>> {
    let pids: Vec<u32> = {
        let mut st = store
            .conn()
            .prepare("SELECT DISTINCT pid FROM conn_bytes WHERE last_ts >= ?1")?;
        let rows = st.query_map(params![since_ts], |r| r.get::<_, i64>(0))?;
        rows.filter_map(|r| r.ok())
            .filter_map(|p| u32::try_from(p).ok())
            .collect()
    };
    let mut out = Vec::new();
    for pid in pids {
        let Some(id) = store.latest_process_by_pid(pid, i64::MAX)? else {
            continue;
        };
        let n = store.node(id)?;
        if n.attr("ended").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }
        let by_name = n
            .attr("image")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .as_deref()
            .and_then(tool_of);
        // 32차 Gemini Q1: 이름을 바꾼 원격 도구는 실행 파일의 유효 서명자로 알아본다(서명은 실행 뒤에 오므로 다시 찾을 때만)
        let Some(t) = by_name.or_else(|| tool_of_signer(store, id)) else {
            continue;
        };
        out.push((pid, id, t.key));
    }
    Ok(out)
}

/// 세션 동안 PC 에서 일어난 일(사실만). 세션 끝 문장과 화면이 쓴다.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct SessionFacts {
    /// 새로 시작된 프로세스 수
    pub processes: usize,
    /// 그중 명령 프롬프트·PowerShell·Windows 터미널
    pub shells: Vec<String>,
    /// 그중 설치 프로그램(설치 엑스레이 기준)
    pub installers: Vec<String>,
    /// 내려받은 파일(MOTW)
    pub downloads: Vec<String>,
    /// 자동 실행 등록 수
    pub autoruns: usize,
}

const SHELLS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "windowsterminal.exe",
    "wt.exe",
];
const FACTS_CAP: usize = 20;

/// `from_ts`~`to_ts`(FILETIME) 동안의 사실을 모은다. 원격 도구의 자손만이 아니라 PC 전체 —
/// 단 서비스 세션(Session 0)에서 뜬 것은 뺀다(32차 Gemini Q3: 업데이트·백신 같은 배경 작업). 세션을 모르면 넣는다.
/// 원격 조작은 이 PC 의 탐색기·브라우저로 일을 시키므로 자손으로 좁히면 놓친다.
pub fn session_facts(store: &Store, from_ts: i64, to_ts: i64) -> Result<SessionFacts> {
    let mut f = SessionFacts::default();
    let conn = store.conn();
    {
        let mut st = conn.prepare_cached(
            "SELECT json_extract(n.attrs_json, '$.image') FROM edges e JOIN nodes n ON n.id = e.dst
             WHERE e.rel = 'spawned' AND e.ts >= ?1 AND e.ts <= ?2
               AND COALESCE(json_extract(n.attrs_json, '$.session'), -1) != 0",
        )?;
        let rows = st.query_map(params![from_ts, to_ts], |r| r.get::<_, Option<String>>(0))?;
        for img in rows.filter_map(|r| r.ok()).flatten() {
            f.processes += 1;
            let b = base_lower(&img);
            if SHELLS.contains(&b.as_str()) && f.shells.len() < FACTS_CAP && !f.shells.contains(&b)
            {
                f.shells.push(b);
            } else if crate::install::is_installer_image(&img)
                && f.installers.len() < FACTS_CAP
                && !f.installers.contains(&img)
            {
                f.installers.push(img);
            }
        }
    }
    {
        let mut st = conn.prepare_cached(
            "SELECT DISTINCT n.key FROM edges e JOIN nodes n ON n.id = e.dst
             WHERE e.rel = 'downloaded' AND e.ts >= ?1 AND e.ts <= ?2 LIMIT ?3",
        )?;
        f.downloads = st
            .query_map(params![from_ts, to_ts, FACTS_CAP as i64], |r| {
                r.get::<_, String>(0)
            })?
            .filter_map(|r| r.ok())
            .collect();
    }
    f.autoruns = conn.query_row(
        "SELECT COUNT(*) FROM edges WHERE rel = 'registered' AND ts >= ?1 AND ts <= ?2",
        params![from_ts, to_ts],
        |r| r.get::<_, i64>(0),
    )? as usize;
    Ok(f)
}

/// 세션 사실 한 줄(없으면 빈 문자열)
pub fn facts_text(f: &SessionFacts) -> String {
    let mut parts = Vec::new();
    if f.processes > 0 {
        parts.push(format!("새 프로그램 실행 {}번", f.processes));
    }
    if !f.shells.is_empty() {
        parts.push(format!("명령 창 실행({})", f.shells.join(", ")));
    }
    if !f.installers.is_empty() {
        let names: Vec<String> = f.installers.iter().map(|i| base_lower(i)).collect();
        parts.push(format!("설치 프로그램 실행({})", names.join(", ")));
    }
    if !f.downloads.is_empty() {
        parts.push(format!("파일 내려받기 {}개", f.downloads.len()));
    }
    if f.autoruns > 0 {
        parts.push(format!("자동 실행 등록 {}건", f.autoruns));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" 그동안 이 PC 에서: {}.", parts.join(", "))
    }
}

/// key → 표시 이름
pub fn display_of(key: &str) -> &'static str {
    TOOLS
        .iter()
        .find(|t| t.key == key)
        .map(|t| t.display)
        .unwrap_or("원격 제어 프로그램")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names() {
        assert_eq!(
            tool_of(r"C:\Program Files\TeamViewer\TeamViewer.exe").map(|t| t.key),
            Some("teamviewer")
        );
        assert_eq!(
            tool_of(r"C:\Users\a\Downloads\AnyDesk.exe").map(|t| t.key),
            Some("anydesk")
        );
        assert!(tool_of(r"C:\Windows\System32\svchost.exe").is_none());
        // 이름 일부만 같은 것은 아니다
        assert!(tool_of(r"C:\x\anydesk_helper.exe").is_none());
    }

    fn feed(t: &mut SessionTracker, now: i64, sent: u64, recv: u64) -> Vec<Transition> {
        t.observe(
            now,
            &[(10, "teamviewer")],
            &[Sample {
                pid: 10,
                sent,
                recv,
            }],
        )
    }

    #[test]
    fn idle_relay_is_not_a_session() {
        let mut t = SessionTracker::new();
        let mut sent = 5_000_000; // 서비스가 켜지기 전 누적(기준점으로 흡수)
        for i in 0..60 {
            // 10초마다 2KB 유지 신호
            assert!(feed(&mut t, i * 10, sent, sent / 2).is_empty());
            sent += 2048;
        }
        assert!(t.active().is_empty());
    }

    #[test]
    fn screen_streaming_starts_and_ends() {
        let mut t = SessionTracker::new();
        let mut sent = 0u64;
        let mut recv = 0u64;
        assert!(feed(&mut t, 0, sent, recv).is_empty());
        let mut started = None;
        for i in 1..=6 {
            sent += 300 * 1024; // 10초에 300KB 내보냄
            recv += 20 * 1024;
            let tr = feed(&mut t, i * 10, sent, recv);
            if let Some(Transition::Started { ts, .. }) = tr.first() {
                started = Some(*ts);
            }
        }
        assert_eq!(started, Some(10), "창 안에서 처음 보낸 시각부터");
        // 조용해짐: 90초 지나야 끝
        let mut ended = None;
        for i in 7..=20 {
            sent += 1024;
            let tr = feed(&mut t, i * 10, sent, recv);
            if let Some(Transition::Ended {
                ended_ts,
                process_gone,
                ..
            }) = tr.first()
            {
                ended = Some((*ended_ts, *process_gone));
            }
        }
        let (e, gone) = ended.expect("끝나야 함");
        assert!(!gone);
        // 60초에 마지막 큰 증분 → 창(30초)에서 빠지는 90초부터 조용 → 90초 뒤 180초에 끝
        assert_eq!(e, 180);
    }

    #[test]
    fn viewer_side_is_not_alarm() {
        // 이 PC 가 다른 PC 를 조작: 받는 양이 크다
        let mut t = SessionTracker::new();
        let (mut sent, mut recv) = (0u64, 0u64);
        feed(&mut t, 0, sent, recv);
        for i in 1..=6 {
            sent += 300 * 1024;
            recv += 900 * 1024;
            assert!(feed(&mut t, i * 10, sent, recv).is_empty());
        }
    }

    #[test]
    fn process_exit_ends_session() {
        let mut t = SessionTracker::new();
        let mut sent = 0;
        feed(&mut t, 0, sent, 0);
        for i in 1..=4 {
            sent += 400 * 1024;
            feed(&mut t, i * 10, sent, 0);
        }
        assert_eq!(t.active().len(), 1);
        let tr = t.observe(50, &[], &[]);
        assert!(matches!(
            tr.as_slice(),
            [Transition::Ended {
                process_gone: true,
                ..
            }]
        ));
        assert!(t.active().is_empty());
    }

    #[test]
    fn counter_reset_does_not_fake_burst() {
        let mut t = SessionTracker::new();
        feed(&mut t, 0, 9_000_000, 0);
        // 누적이 줄었다(행 삭제) → 기준점만 다시
        assert!(feed(&mut t, 10, 1_000, 0).is_empty());
        assert!(feed(&mut t, 20, 3_000, 0).is_empty());
        assert!(t.active().is_empty());
    }
}
