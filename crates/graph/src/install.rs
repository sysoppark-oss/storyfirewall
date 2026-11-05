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
pub fn is_installer_image(image: &str) -> bool {
    let b = base_lower(image);
    if !b.ends_with(".exe") {
        return false;
    }
    if b.starts_with("unins") || b.contains("uninstall") {
        return false;
    }
    b == "msiexec.exe" || b.contains("setup") || b.contains("install")
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
    runs.sort_by_key(|x| x.start_ts);
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
                g.commands.extend(x.commands);
                g.truncated |= x.truncated;
                g.persistence = persistence_of(&g.commands, &g.procs);
            }
            _ => groups.push(x),
        }
    }
    groups.reverse();
    groups.truncate(limit);
    Ok(groups)
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
    let desc = descendants(store, root, max_procs + 1)?;
    let truncated = desc.len() > max_procs;
    ids.extend(desc.into_iter().take(max_procs));

    let conn = store.conn();
    let mut procs = Vec::new();
    let mut files = Vec::new();
    let mut autoruns = Vec::new();
    let mut remotes: BTreeMap<String, u32> = BTreeMap::new();
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
                    let name = attrs
                        .as_deref()
                        .and_then(|a| serde_json::from_str::<serde_json::Value>(a).ok())
                        .and_then(|v| {
                            v.get("domain")
                                .and_then(|d| d.as_str().map(|s| s.to_string()))
                        })
                        .unwrap_or(label);
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
    Ok(InstallRun {
        root,
        image,
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
        assert!(!is_installer_image(r"C:\Program Files\App\Uninstall.exe"));
        assert!(!is_installer_image(
            r"C:\Program Files\Google\Chrome\chrome.exe"
        ));
        assert!(!is_installer_image(r"C:\Temp\setup.msi"));
    }
}
