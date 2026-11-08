//! 설치 엑스레이 (기획서 14판 20-3): 설치 프로그램 실행 한 번이 PC 에 한 일을 모은다.
//!
//! 판정하지 않는다 — 사실 목록만. 플랫폼 전용 코드 없음(엔진 공유 원칙).

use std::collections::BTreeMap;

use rusqlite::params;
use serde::Serialize;

use crate::store::Store;
use crate::views::descendants;
use crate::Result;

/// 경로에서 파일 이름(소문자)
fn base_lower(image: &str) -> String {
    image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase()
}

/// 설치 프로그램으로 보는 실행 파일 이름인가.
/// msiexec, 이름에 setup·install 이 든 실행 파일. 제거 프로그램(unins*, uninstall*)은 뺀다.
/// L067(31차 검수): Windows 폴더 아래 구성 요소(TrustedInstaller.exe = Windows 모듈 설치 관리자 서비스, servicing·WinSxS 의
/// 업데이트 도구)는 사용자가 실행한 설치가 아니다 — msiexec 만 남긴다. Windows 업데이트는 설치 엑스레이 대상이 아니다
pub fn is_installer_image(image: &str) -> bool {
    let b = base_lower(image);
    if !b.ends_with(".exe") {
        return false;
    }
    if b.starts_with("unins") || b.contains("uninstall") {
        return false;
    }
    if b == "msiexec.exe" {
        return true;
    }
    let p = image.replace('/', "\\").to_ascii_lowercase();
    let in_windows = p.len() > 3 && p.as_bytes()[1] == b':' && p[2..].starts_with("\\windows\\");
    if in_windows || b == "trustedinstaller.exe" {
        return false;
    }
    b.contains("setup") || b.contains("install")
}

/// 설치 한 번의 요약
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InstallRun {
    /// 설치 프로그램 프로세스 노드
    pub root: i64,
    pub image: String,
    pub pid: Option<u32>,
    pub start_ts: i64,
    /// 설치 묶음 안에서 마지막으로 기록된 시각
    pub last_ts: i64,
    /// 설치 파일이 어디서 왔는지(내려받은 곳 URL·호스트), 알 때만
    pub origin: Option<String>,
    /// 설치 묶음의 프로세스 (뿌리 포함): 이미지 경로
    pub procs: Vec<String>,
    /// 만든 파일(수집 범위: 실행 파일·스크립트, 사용자 쓰기 가능 경로)
    pub files: Vec<String>,
    /// 자동 실행 등록 (위치, 대상)
    pub autoruns: Vec<(String, String)>,
    /// 접속한 곳 (이름, 횟수) — 많은 순
    pub remotes: Vec<(String, u32)>,
    /// 실행한 명령
    pub commands: Vec<String>,
    /// 자손이 상한에 걸려 잘렸는가
    pub truncated: bool,
    /// L060: 자리잡기 명령(예약 작업 만들기·서비스 등록 등). 명령줄을 못 받았으면 "도구 실행"만 남긴다
    #[serde(default)]
    pub persistence: Vec<String>,
    /// L060: 부모 연결은 없지만 같은 시간대에 이어 시작해 이 설치로 함께 묶은 설치 과정(실행 파일 경로)
    #[serde(default)]
    pub grouped: Vec<String>,
    /// L062(30차 Q1): 설치 파일의 유효 서명 회사(서명이 유효할 때만). 시간 묶기는 같은 서명 회사끼리만
    #[serde(default)]
    pub signer: Option<String>,
    /// 자손이 잘렸어도(`truncated`) 접속·자동 실행·파일 쓰기를 한 자손은 모두 담았나(화면 검수 N1: 그 개수에는 "이상"을 붙이지 않는다)
    #[serde(default)]
    pub facts_complete: bool,
    /// UI 명세 4판 3-6: 설치 프로그램을 띄운 부모 프로세스의 이미지 경로(기록이 있을 때만)
    #[serde(default)]
    pub parent: Option<String>,
    /// UI 명세 4판 3-6: 설치 프로그램 자신의 명령줄(기록이 있을 때만)
    #[serde(default)]
    pub cmdline: Option<String>,
    /// UI 명세 4판 3-7: 접속한 곳 이름 → 처음 본 IP (화면이 나라·망을 붙이는 데 쓴다). remotes 와 같은 이름
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_ips: Vec<(String, String)>,
}

/// 앞 설치의 마지막 기록 뒤 이 안(100ns, 2분)에 시작했고 **둘 다 같은 회사의 유효 서명**이면 같은 설치로 묶는다(L062, 30차 Q1:
/// 시간만으로 묶으면 정상 설치에 악성 설치 과정이 끼어들어 "정상 설치의 일부"처럼 보인다).
/// 설치 파일이 업데이트 서비스·권한 상승을 거쳐 진짜 설치 과정을 띄우면 부모 연결이 끊긴다(install-28 Whale 실측).
pub const JOIN_WINDOW: i64 = 120 * 10_000_000;

/// 명령줄에서 자리잡기 사실을 고른다(사실 문장 재료). 소문자 비교
pub fn persistence_of(commands: &[String], procs: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen_tool = std::collections::HashSet::new();
    for c in commands {
        let l = c.to_ascii_lowercase();
        let toks: Vec<&str> = l.split_whitespace().collect();
        let first = toks
            .first()
            .map(|t| base_lower(t.trim_matches('"')))
            .unwrap_or_default();
        let has = |w: &str| toks.iter().any(|t| t.trim_matches('"') == w);
        if first.starts_with("schtasks") {
            seen_tool.insert("schtasks.exe");
            if has("/create") {
                out.push(format!("예약 작업 만들기: {c}"));
            } else if has("/change") {
                out.push(format!("예약 작업 바꾸기: {c}"));
            }
        } else if first == "sc" || first == "sc.exe" {
            seen_tool.insert("sc.exe");
            if has("create") {
                out.push(format!("서비스 등록: {c}"));
            } else if has("config") {
                out.push(format!("서비스 설정 바꾸기: {c}"));
            }
        } else if (first == "reg" || first == "reg.exe")
            && has("add")
            && l.contains("\\currentversion\\run")
        {
            out.push(format!("자동 실행 레지스트리 추가: {c}"));
        }
    }
    // 도구는 실행됐는데 명령줄을 못 받은 경우: 무엇을 했는지 모른다는 사실만
    for p in procs {
        let b = base_lower(p);
        for tool in ["schtasks.exe", "sc.exe"] {
            if b == tool && seen_tool.insert(tool) {
                out.push(format!(
                    "{tool} 실행 (명령줄을 받지 못해 무엇을 바꿨는지 모름)"
                ));
            }
        }
    }
    out.dedup();
    out
}

/// 최근 설치 목록(최신 먼저). 부모 연결 없이 이어 시작한 설치 과정은 시간으로 묶는다(`JOIN_WINDOW`).
/// `visible` 은 보이는 범위(사용자 권한) 검사 — 안 보이는 뿌리는 뺀다
pub fn installs(
    store: &Store,
    since_ts: i64,
    limit: usize,
    max_procs: usize,
    visible: impl Fn(i64) -> bool,
) -> Result<Vec<InstallRun>> {
    let mut runs = Vec::new();
    for r in installer_roots(store, since_ts, limit.saturating_mul(4).max(limit))? {
        if visible(r) {
            runs.push(install_xray(store, r, max_procs)?);
        }
    }
    Ok(group_runs(runs, limit))
}

/// 설치 한 번씩(뿌리마다)의 엑스레이를 시간 묶음으로 합친다. 최신 먼저, `limit` 개
pub fn group_runs(mut runs: Vec<InstallRun>, limit: usize) -> Vec<InstallRun> {
    runs.sort_by_key(|x| (x.start_ts, x.root));
    let mut groups: Vec<InstallRun> = Vec::new();
    for x in runs {
        match groups.last_mut() {
            Some(g)
                if x.start_ts <= g.last_ts + JOIN_WINDOW
                    && g.signer.is_some()
                    && g.signer.as_deref().map(str::to_lowercase)
                        == x.signer.as_deref().map(str::to_lowercase) =>
            {
                g.grouped.push(x.image.clone());
                g.last_ts = g.last_ts.max(x.last_ts);
                g.origin = g.origin.take().or(x.origin);
                g.procs.extend(x.procs);
                g.files.extend(x.files);
                g.files.sort();
                g.files.dedup();
                g.autoruns.extend(x.autoruns);
                g.autoruns.sort();
                g.autoruns.dedup();
                for (n, c) in x.remotes {
                    match g.remotes.iter_mut().find(|r| r.0 == n) {
                        Some(r) => r.1 += c,
                        None => g.remotes.push((n, c)),
                    }
                }
                g.remotes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                for (n, ip) in x.remote_ips {
                    if !g.remote_ips.iter().any(|r| r.0 == n) {
                        g.remote_ips.push((n, ip));
                    }
                }
                g.commands.extend(x.commands);
                g.truncated |= x.truncated;
                g.persistence = persistence_of(&g.commands, &g.procs);
            }
            _ => groups.push(x),
        }
    }
    groups.reverse();
    groups.truncate(limit);
    groups
}

/// L069(32차 검수 4): 설치 목록 미리 계산. 조회(installs.list)는 이것을 읽기만 한다(2초 원칙: 무거운 계산은 주기 작업으로).
/// 뿌리마다 엑스레이를 들고 있고, 주기마다 최근 `FRESH` 안에 시작한 뿌리만 다시 본다(설치가 아직 진행 중일 수 있어서).
/// 그보다 오래된 설치는 끝난 것으로 보고 다시 계산하지 않는다
#[derive(Debug, Default, Clone)]
pub struct InstallCache {
    /// 뿌리 프로세스 노드 → 그 설치 한 번
    pub runs: BTreeMap<i64, InstallRun>,
    /// 처음 전체 훑기를 했는가
    pub primed: bool,
}

impl InstallCache {
    /// 다시 계산하는 최근 구간(FILETIME, 2시간)
    pub const FRESH: i64 = 2 * 3600 * 10_000_000;
    /// 들고 있는 기간(FILETIME, 30일 — installs.list days 상한)
    pub const KEEP: i64 = 30 * 86_400 * 10_000_000;
    /// 들고 있는 뿌리 상한(오래된 것부터 버린다)
    pub const MAX_ROOTS: usize = 400;

    /// `now_ts`(FILETIME) 기준으로 맞춘다. 처음에는 30일 전체, 그 뒤에는 최근 `FRESH` 만 훑는다
    pub fn refresh(&mut self, store: &Store, now_ts: i64, max_procs: usize) -> Result<()> {
        let since = if self.primed {
            now_ts - Self::FRESH
        } else {
            now_ts - Self::KEEP
        };
        for r in installer_roots(store, since, Self::MAX_ROOTS)? {
            let x = install_xray(store, r, max_procs)?;
            self.runs.insert(r, x);
        }
        self.primed = true;
        // 오래된 것·상한 넘친 것 버리기
        self.runs.retain(|_, x| x.start_ts >= now_ts - Self::KEEP);
        while self.runs.len() > Self::MAX_ROOTS {
            let oldest = self
                .runs
                .iter()
                .min_by_key(|(_, x)| x.start_ts)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    self.runs.remove(&k);
                }
                None => break,
            }
        }
        Ok(())
    }

    /// 조회: `since_ts` 이후 시작한, 보이는 뿌리만 묶어서 최신 `limit` 개
    pub fn list(
        &self,
        since_ts: i64,
        limit: usize,
        visible: impl Fn(i64) -> bool,
    ) -> Vec<InstallRun> {
        let runs: Vec<InstallRun> = self
            .runs
            .iter()
            .filter(|(r, x)| x.start_ts >= since_ts && visible(**r))
            .map(|(_, x)| x.clone())
            .collect();
        group_runs(runs, limit)
    }
}

/// 이 시각 이후 시작한 설치 프로그램 프로세스(바깥쪽만 — 설치 프로그램이 띄운 설치 프로그램은 같은 묶음). 최신 먼저
pub fn installer_roots(store: &Store, since_ts: i64, limit: usize) -> Result<Vec<i64>> {
    let mut st = store.conn().prepare(
        "SELECT id, attrs_json FROM nodes WHERE kind = 'process' AND first_ts >= ?1 ORDER BY first_ts DESC",
    )?;
    let rows = st.query_map(params![since_ts], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
    })?;
    let mut parent_st = store.conn().prepare(
        "SELECT n.attrs_json FROM edges e JOIN nodes n ON n.id = e.src WHERE e.dst = ?1 AND e.rel = 'spawned' AND n.kind = 'process' LIMIT 1",
    )?;
    let mut out = Vec::new();
    for row in rows {
        let (id, attrs) = row?;
        if !image_of(attrs.as_deref())
            .map(|i| is_installer_image(&i))
            .unwrap_or(false)
        {
            continue;
        }
        let parent: Option<Option<String>> = parent_st.query_row(params![id], |r| r.get(0)).ok();
        let parent_is_installer = parent
            .flatten()
            .and_then(|a| image_of(Some(&a)))
            .map(|i| is_installer_image(&i))
            .unwrap_or(false);
        if parent_is_installer {
            continue;
        }
        out.push(id);
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

fn image_of(attrs: Option<&str>) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(attrs?).ok()?;
    v.get("image")?.as_str().map(|s| s.to_string())
}

/// 설치 프로그램 프로세스 하나의 엑스레이. 자손은 max_procs 까지
pub fn install_xray(store: &Store, root: i64, max_procs: usize) -> Result<InstallRun> {
    let node = store.node(root)?;
    let image = node
        .attr("image")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| node.label.clone());
    let pid = node.attr("pid").and_then(|v| v.as_u64()).map(|p| p as u32);
    let mut ids = vec![root];
    // 32차 Gemini Q5: 자손을 상한까지 앞에서부터만 담으면, 의미 없는 자식 수백 개를 먼저 띄워 진짜 행동을 밀어낼 수 있다.
    // 상한을 넘으면 더 넓게(10배) 읽고, 접속·자동 실행 등록·파일 쓰기를 했거나 판정 장이 붙은 자손을 먼저 담는다
    let wide = max_procs.saturating_mul(10);
    let desc = descendants(store, root, wide + 1)?;
    let desc_len_within = desc.len() <= wide;
    let truncated = desc.len() > max_procs;
    let mut facts_complete = !truncated;
    if truncated {
        let mut act = store.conn().prepare_cached(
            "SELECT 1 FROM edges WHERE src = ?1 AND (rel IN ('connected','registered','wrote') OR chapter IS NOT NULL) LIMIT 1",
        )?;
        let (mut busy, mut quiet): (Vec<i64>, Vec<i64>) = (Vec::new(), Vec::new());
        for d in desc {
            if act.exists(params![d])? {
                busy.push(d);
            } else {
                quiet.push(d);
            }
        }
        // 넓게 읽은 범위(10배)도 넘쳤으면 그 밖의 자손은 모른다
        facts_complete = busy.len() <= max_procs && desc_len_within;
        ids.extend(busy.into_iter().chain(quiet).take(max_procs));
    } else {
        ids.extend(desc);
    }

    let conn = store.conn();
    let mut procs = Vec::new();
    let mut files = Vec::new();
    let mut autoruns = Vec::new();
    let mut remotes: BTreeMap<String, u32> = BTreeMap::new();
    let mut remote_ip: BTreeMap<String, String> = BTreeMap::new();
    let mut commands = Vec::new();
    let mut last_ts = node.first_ts;
    let mut out_st = conn.prepare_cached(
        "SELECT e.rel, e.ts, n.kind, n.key, n.label, n.attrs_json FROM edges e JOIN nodes n ON n.id = e.dst WHERE e.src = ?1 AND e.rel IN ('wrote','registered','connected','ran')",
    )?;
    for id in &ids {
        let p = store.node(*id)?;
        procs.push(
            p.attr("image")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or(p.label.clone()),
        );
        last_ts = last_ts.max(p.first_ts);
        let rows = out_st.query_map(params![id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?;
        for row in rows {
            let (rel, ts, kind, key, label, attrs) = row?;
            last_ts = last_ts.max(ts);
            match (rel.as_str(), kind.as_str()) {
                ("wrote", "file") => files.push(key),
                ("registered", "autorun") => autoruns.push((key, label)),
                ("connected", "remote") => {
                    // 도메인을 알면 도메인, 모르면 주소
                    let av = attrs
                        .as_deref()
                        .and_then(|a| serde_json::from_str::<serde_json::Value>(a).ok());
                    let name = av
                        .as_ref()
                        .and_then(|v| {
                            v.get("domain")
                                .and_then(|d| d.as_str().map(|s| s.to_string()))
                        })
                        .unwrap_or(label);
                    if let Some(ip) = av
                        .as_ref()
                        .and_then(|v| v.get("ip").and_then(|x| x.as_str()))
                    {
                        remote_ip
                            .entry(name.clone())
                            .or_insert_with(|| ip.to_string());
                    }
                    *remotes.entry(name).or_default() += 1;
                }
                ("ran", "command") => commands.push(label),
                _ => {}
            }
        }
    }
    files.sort();
    files.dedup();
    autoruns.sort();
    autoruns.dedup();
    commands.dedup();
    let mut remotes: Vec<(String, u32)> = remotes.into_iter().collect();
    remotes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    // 출신: 설치 파일(executed_as 의 파일)을 내려받은 곳
    let origin: Option<String> = conn
        .query_row(
            "SELECT o.label FROM edges x JOIN edges d ON d.dst = x.src AND d.rel = 'downloaded' JOIN nodes o ON o.id = d.src
             WHERE x.dst = ?1 AND x.rel = 'executed_as' LIMIT 1",
            params![root],
            |r| r.get(0),
        )
        .ok();

    let persistence = persistence_of(&commands, &procs);
    // 설치 파일(executed_as 의 파일)의 유효 서명 회사
    let signer: Option<String> = conn
        .query_row(
            "SELECT f.attrs_json FROM edges x JOIN nodes f ON f.id = x.src WHERE x.dst = ?1 AND x.rel = 'executed_as' LIMIT 1",
            params![root],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
        .and_then(|a| serde_json::from_str::<serde_json::Value>(&a).ok())
        .filter(|v| v.get("sig_status").and_then(|s| s.as_str()) == Some("valid"))
        .and_then(|v| v.get("signer").and_then(|s| s.as_str()).map(|s| s.to_string()));
    // 부모(spawned 의 src) 이미지
    let parent: Option<String> = conn
        .query_row(
            "SELECT n.attrs_json FROM edges e JOIN nodes n ON n.id = e.src WHERE e.dst = ?1 AND e.rel = 'spawned' AND n.kind = 'process' LIMIT 1",
            params![root],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
        .and_then(|a| image_of(Some(&a)));
    // 뿌리 자신의 명령줄(ran 선)
    let cmdline: Option<String> = conn
        .query_row(
            "SELECT n.label FROM edges e JOIN nodes n ON n.id = e.dst WHERE e.src = ?1 AND e.rel = 'ran' AND n.kind = 'command' ORDER BY e.ts LIMIT 1",
            params![root],
            |r| r.get(0),
        )
        .ok();
    Ok(InstallRun {
        root,
        image,
        parent,
        cmdline,
        remote_ips: remote_ip.into_iter().collect(),
        pid,
        start_ts: node.first_ts,
        last_ts,
        origin,
        procs,
        files,
        autoruns,
        remotes,
        commands,
        truncated,
        persistence,
        grouped: Vec::new(),
        signer,
        facts_complete,
    })
}

#[cfg(test)]
mod tests {
    use super::{is_installer_image, persistence_of};

    #[test]
    fn persistence_from_commands_and_tools() {
        let c = vec![
            r#"schtasks /create /tn "WhaleUpdate" /tr C:\x.exe"#.to_string(),
            "sc.exe create WhaleSvc binPath= C:\\y.exe".to_string(),
            "schtasks /query".to_string(),
        ];
        let p = persistence_of(&c, &[r"C:\Windows\System32\sc.exe".into()]);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p[0].starts_with("예약 작업 만들기"));
        assert!(p[1].starts_with("서비스 등록"));
        // 명령줄 없이 도구만 돈 경우
        let p = persistence_of(
            &[],
            &[
                r"C:\Windows\SysWOW64\schtasks.exe".into(),
                r"C:\Windows\SysWOW64\schtasks.exe".into(),
            ],
        );
        assert_eq!(
            p,
            vec!["schtasks.exe 실행 (명령줄을 받지 못해 무엇을 바꿨는지 모름)".to_string()]
        );
    }

    #[test]
    fn installer_names() {
        assert!(is_installer_image(r"C:\Users\u\Downloads\WhaleSetup.exe"));
        assert!(is_installer_image(r"C:\Windows\System32\msiexec.exe"));
        assert!(is_installer_image(
            r"C:\Temp\Git-2.47.0-64-bit-installer.exe"
        ));
        assert!(!is_installer_image(r"C:\Program Files\App\unins000.exe"));
        // L067: Windows 구성 요소는 설치가 아니다(msiexec 만 예외)
        assert!(!is_installer_image(
            r"C:\Windows\servicing\TrustedInstaller.exe"
        ));
        assert!(!is_installer_image(
            r"C:\Windows\WinSxS\amd64_x\TrustedInstaller.exe"
        ));
        assert!(!is_installer_image(r"C:\Windows\System32\oobe\Setup.exe"));
        assert!(!is_installer_image(r"D:\TrustedInstaller.exe"));
        assert!(is_installer_image(
            r"C:\Users\u\Downloads\windows-setup.exe"
        ));
        assert!(!is_installer_image(r"C:\Program Files\App\Uninstall.exe"));
        assert!(!is_installer_image(
            r"C:\Program Files\Google\Chrome\chrome.exe"
        ));
        assert!(!is_installer_image(r"C:\Temp\setup.msi"));
    }
}
