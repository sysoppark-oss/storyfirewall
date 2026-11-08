//! 화면용 조회 (A19): 연결 목록, 프로세스 상세, 자손, 끊기 대상.
//! 모두 읽기 전용이다. 시각은 FILETIME(100ns, 1601 기준) — 경계 변환은 svc 가 한다.

use std::collections::{BTreeSet, HashMap, HashSet};

use rusqlite::params;
use serde::Serialize;

use crate::store::Store;
use crate::{Node, Result};

/// 프로세스 노드 키 "PID@생성시각" → (pid, 생성 시각)
pub fn parse_proc_key(key: &str) -> Option<(u32, i64)> {
    let (p, t) = key.split_once('@')?;
    Some((p.parse().ok()?, t.parse().ok()?))
}

fn attr_str(n: &Node, k: &str) -> Option<String> {
    n.attr(k).and_then(|v| v.as_str().map(|s| s.to_string()))
}

/// 시스템 핵심 프로세스 이름. **dsl::validate::SYSTEM_IMAGES 와 같아야 한다** — graph 는 dsl 에 의존하지 않으므로
/// 사본을 두고 svc 접점 테스트가 목록과 `is_system_image` 판정을 대조한다.
pub const SYSTEM_IMAGES: &[&str] = &[
    "svchost.exe",
    "explorer.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "wininit.exe",
];

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

// ---------------------------------------------------------------- 연결 목록

/// (프로세스, 원격지) 쌍 하나. 같은 쌍의 여러 접속은 합친다.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConnRow {
    pub process_id: i64,
    pub pid: u32,
    pub image: String,
    pub remote_id: i64,
    pub raddr: String,
    pub rport: u16,
    pub proto: String,
    pub domain: Option<String>,
    /// "out" | "in"
    pub direction: String,
    pub count: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub sent: i64,
    pub recv: i64,
    /// 서비스 경유 귀속이 있으면 원래 요청한 프로세스 노드
    pub proxied_for: Option<i64>,
}

/// `since_ts` 이후 접속, 마지막 접속이 늦은 순. `limit` 상한.
pub fn connections(store: &Store, since_ts: i64, limit: usize) -> Result<Vec<ConnRow>> {
    let mut st = store.conn().prepare(
        r#"
        WITH agg AS (
            -- 27차 perf(100만 건 7일 2.2초): 선을 먼저 (src, dst) 쌍으로 접고(부분 색인 ix_edges_conn 만 읽음) 그 뒤 노드와 잇는다
            SELECT src, dst, COUNT(*) AS n, MIN(ts) AS f, MAX(ts) AS l
            FROM edges
            WHERE rel = 'connected' AND ts >= ?1
            GROUP BY src, dst
        )
        SELECT p.id, p.key, p.attrs_json, r.id, r.attrs_json,
               CASE WHEN a.src = p.id THEN 'out' ELSE 'in' END AS dir,
               SUM(a.n), MIN(a.f), MAX(a.l)
        FROM agg a
        JOIN nodes p ON p.id IN (a.src, a.dst) AND p.kind = 'process'
        JOIN nodes r ON r.id IN (a.src, a.dst) AND r.kind = 'remote'
        GROUP BY p.id, r.id, dir
        ORDER BY MAX(a.l) DESC
        LIMIT ?2
        "#,
    )?;
    let rows = st.query_map(params![since_ts, limit as i64], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, i64>(7)?,
            r.get::<_, i64>(8)?,
        ))
    })?;
    let mut bytes = store.conn().prepare("SELECT COALESCE(SUM(sent),0), COALESCE(SUM(recv),0) FROM conn_bytes WHERE pid = ?1 AND raddr = ?2 AND rport = ?3")?;
    let mut out = Vec::new();
    for row in rows {
        let (pid_node, pkey, pattrs, rid, rattrs, dir, count, first, last) = row?;
        let pa: serde_json::Value = pattrs
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        let ra: serde_json::Value = rattrs
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        let pid = parse_proc_key(&pkey).map(|(p, _)| p).unwrap_or(0);
        let raddr = ra["ip"].as_str().unwrap_or("").to_string();
        let rport = ra["port"].as_u64().unwrap_or(0) as u16;
        let (sent, recv): (i64, i64) =
            bytes.query_row(params![pid, raddr, rport], |r| Ok((r.get(0)?, r.get(1)?)))?;
        out.push(ConnRow {
            process_id: pid_node,
            pid,
            image: pa["image"].as_str().unwrap_or("").to_string(),
            remote_id: rid,
            raddr,
            rport,
            proto: match &ra["proto"] {
                serde_json::Value::String(s) => s.to_ascii_lowercase(),
                v => v.to_string(),
            },
            domain: ra["domain"].as_str().map(|s| s.to_string()),
            direction: dir,
            count,
            first_ts: first,
            last_ts: last,
            sent,
            recv,
            proxied_for: ra["proxied_for"].as_i64(),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------- 프로세스 상세

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Related {
    pub node_id: i64,
    pub kind: String,
    pub label: String,
    pub key: String,
    pub rel: String,
    pub edge_id: i64,
    pub ts: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessDetail {
    pub node: Node,
    pub pid: u32,
    pub create_ts: i64,
    pub image: String,
    pub ended: bool,
    /// 실행 파일 노드의 서명 정보 (signer, issuer, sig_status, catalog)
    pub signature: Option<serde_json::Value>,
    /// 출신 기록 (MOTW HostUrl·ReferrerUrl)
    pub origin: Option<serde_json::Value>,
    /// 부모 (spawned 의 src)
    pub parents: Vec<Related>,
    pub children: Vec<Related>,
    pub connections: Vec<Related>,
    pub files_written: Vec<Related>,
    pub autoruns: Vec<Related>,
    pub injected: Vec<Related>,
    /// D025: 들어온 연결(원격 → 이 프로세스, connected)
    pub inbound: Vec<Related>,
}

fn related(store: &Store, sql: &str, id: i64, limit: usize) -> Result<Vec<Related>> {
    let mut st = store.conn().prepare(sql)?;
    let rows = st.query_map(params![id, limit as i64], |r| {
        Ok(Related {
            node_id: r.get(0)?,
            kind: r.get(1)?,
            label: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            key: r.get(3)?,
            rel: r.get(4)?,
            edge_id: r.get(5)?,
            ts: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn process_detail(store: &Store, node_id: i64, limit: usize) -> Result<ProcessDetail> {
    let node = store.node(node_id)?;
    let (pid, create_ts) = parse_proc_key(&node.key).unwrap_or((0, node.first_ts));
    let image = attr_str(&node, "image").unwrap_or_default();
    let ended = node
        .attr("ended")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // 실행 파일 노드 (executed_as 의 src)
    let file_node: Option<i64> = store
        .conn()
        .query_row("SELECT e.src FROM edges e JOIN nodes f ON f.id = e.src WHERE e.dst = ?1 AND e.rel = 'executed_as' AND f.kind = 'file' LIMIT 1", params![node_id], |r| r.get(0))
        .ok();
    let (signature, origin) = match file_node {
        Some(f) => {
            let fnode = store.node(f)?;
            let sig = fnode.attr("sig_status").map(|_| {
                serde_json::json!({
                    "signer": fnode.attr("signer"), "issuer": fnode.attr("issuer"),
                    "sig_status": fnode.attr("sig_status"), "catalog": fnode.attr("catalog"),
                })
            });
            let org = store
                .conn()
                .query_row("SELECT host_url, referrer_url, via_process, first_seen FROM origins WHERE file_node = ?1", params![f], |r| {
                    Ok(serde_json::json!({"host_url": r.get::<_, Option<String>>(0)?, "referrer_url": r.get::<_, Option<String>>(1)?, "via_process": r.get::<_, Option<String>>(2)?, "first_seen": r.get::<_, Option<i64>>(3)?}))
                })
                .ok()
                .or_else(|| fnode.attr("host_url").map(|h| serde_json::json!({"host_url": h, "zone_id": fnode.attr("zone_id")})));
            (sig, org)
        }
        None => (None, None),
    };
    let out_q = |rel: &str| {
        format!("SELECT n.id, n.kind, n.label, n.key, e.rel, e.id, e.ts FROM edges e JOIN nodes n ON n.id = e.dst WHERE e.src = ?1 AND e.rel = '{rel}' ORDER BY e.ts LIMIT ?2")
    };
    let parents = related(store, "SELECT n.id, n.kind, n.label, n.key, e.rel, e.id, e.ts FROM edges e JOIN nodes n ON n.id = e.src WHERE e.dst = ?1 AND e.rel IN ('spawned','executed_as','injected') ORDER BY e.ts LIMIT ?2", node_id, limit)?;
    Ok(ProcessDetail {
        children: related(store, &out_q("spawned"), node_id, limit)?,
        connections: related(store, &out_q("connected"), node_id, limit)?,
        files_written: related(store, &out_q("wrote"), node_id, limit)?,
        autoruns: related(store, &out_q("registered"), node_id, limit)?,
        injected: related(store, &out_q("injected"), node_id, limit)?,
        inbound: related(store, "SELECT n.id, n.kind, n.label, n.key, e.rel, e.id, e.ts FROM edges e JOIN nodes n ON n.id = e.src WHERE e.dst = ?1 AND e.rel = 'connected' AND n.kind = 'remote' ORDER BY e.ts LIMIT ?2", node_id, limit)?,
        parents,
        node,
        pid,
        create_ts,
        image,
        ended,
        signature,
        origin,
    })
}

// ---------------------------------------------------------------- 자손·끊기 대상

/// 프로세스 노드에서 spawned·injected 로 닿는 모든 프로세스 (자신 제외). 순환 안전.
pub fn descendants(store: &Store, process_id: i64, max: usize) -> Result<Vec<i64>> {
    let mut st = store.conn().prepare(
        r#"
        WITH RECURSIVE down(id, path) AS (
            SELECT ?1, ',' || ?1 || ','
            UNION ALL
            SELECT e.dst, down.path || e.dst || ','
            FROM edges e JOIN down ON e.src = down.id
            JOIN nodes n ON n.id = e.dst AND n.kind = 'process'
            WHERE e.rel IN ('spawned','injected') AND instr(down.path, ',' || e.dst || ',') = 0
        )
        SELECT DISTINCT id FROM down WHERE id != ?1 LIMIT ?2
        "#,
    )?;
    let rows = st.query_map(params![process_id, max as i64], |r| r.get::<_, i64>(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// 끊기 대상 한 프로세스
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CutProc {
    pub node_id: i64,
    pub pid: u32,
    pub create_ts: i64,
    /// 이 프로세스를 처음 본 시각(FILETIME). 생성 시각을 정확히 모를 때 "그때 이미 살아 있던 같은 프로세스인가"를 가리는 데 쓴다
    pub first_ts: i64,
    pub image: String,
    pub system: bool,
    pub ended: bool,
    /// 대상이 코드를 주입한 다른 프로세스(예: 브라우저). 그 프로그램 경로를 통째로 막지 않고 자손도 따라가지 않는다 (16차 Q1-c)
    pub injected_host: bool,
}

/// 주소 차단 후보 (누가, IP, 포트, 프로토콜 번호 6/17)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CutAddress {
    pub who: String,
    pub ip: String,
    pub port: u16,
    pub proto: u8,
    /// system | injected | target
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CutTargets {
    pub root: i64,
    pub root_kind: String,
    pub root_label: String,
    /// 뿌리 실행 파일 경로 (파일 뿌리면 그 경로, 프로세스 뿌리면 그 이미지)
    pub root_image: Option<String>,
    pub procs: Vec<CutProc>,
    /// 대상 프로세스들이 등록한 자동 실행 (location, target)
    pub autoruns: Vec<(String, String)>,
    /// 대상 프로세스들이 쓴 파일 중 실행 파일·스크립트 (격리 후보)
    pub written_executables: Vec<String>,
    /// 대상 중 시스템 프로세스가 접속한 주소 (ip, port) — 주소 차단 후보
    pub system_addresses: Vec<(String, u16)>,
    /// 주소 차단 후보 전부: 시스템·주입당한 프로그램·대상 프로세스의 접속지 (IP·포트·프로토콜)
    pub addresses: Vec<CutAddress>,
}

const EXEC_EXT: &[&str] = &[
    ".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi", ".lnk",
];

/// 사건 뿌리(파일 또는 프로세스)에서 끊기 대상을 뽑는다.
/// 파일 뿌리: 그 파일로 실행된 모든 프로세스 + 자손. 프로세스 뿌리: 자신 + 자손.
pub fn cut_targets(store: &Store, root: i64, max: usize) -> Result<CutTargets> {
    let rn = store.node(root)?;
    let mut starts: Vec<i64> = Vec::new();
    let root_image = match rn.kind.as_str() {
        "file" => {
            let mut st = store
                .conn()
                .prepare("SELECT dst FROM edges WHERE src = ?1 AND rel = 'executed_as'")?;
            for r in st.query_map(params![root], |r| r.get::<_, i64>(0))? {
                starts.push(r?);
            }
            Some(rn.key.clone())
        }
        "process" => {
            starts.push(root);
            attr_str(&rn, "image")
        }
        _ => None,
    };
    // 너비 우선: spawned 는 대상으로 따라가고, injected 는 "주입당한 프로그램"으로 표시만 하고 더 내려가지 않는다
    // (브라우저에 주입했다고 브라우저의 정상 자식들까지 끊으면 안 된다).
    let mut all: std::collections::BTreeMap<i64, bool> = std::collections::BTreeMap::new();
    // 주입당한 프로그램: 처음 주입된 시각. 그 전의 접속은 그 프로그램의 정상 활동이므로 주소 차단 후보에서 뺀다
    // (A22 스크린샷 검토: 주입 전 브라우저의 구글·네이버 접속까지 24시간 막으려 했다)
    let mut injected_at: HashMap<i64, i64> = HashMap::new();
    let mut q: std::collections::VecDeque<i64> = starts.iter().copied().collect();
    for s in &starts {
        all.insert(*s, false);
    }
    while let Some(id) = q.pop_front() {
        if all.len() >= max {
            break;
        }
        if all.get(&id) == Some(&true) {
            continue;
        }
        for e in store.edges_from(id)? {
            if all.len() >= max {
                break;
            }
            let injected = match e.rel.as_str() {
                "spawned" => false,
                "injected" => true,
                _ => continue,
            };
            if store.node(e.dst)?.kind != "process" {
                continue;
            }
            match all.get(&e.dst) {
                Some(false) => continue,            // 이미 대상
                Some(true) if injected => continue, // 이미 주입 표시
                _ => {}
            }
            all.insert(e.dst, injected);
            if injected {
                let t = injected_at.entry(e.dst).or_insert(e.ts);
                *t = (*t).min(e.ts);
            } else {
                q.push_back(e.dst);
            }
        }
    }
    let mut procs = Vec::new();
    let mut autoruns = Vec::new();
    let mut written: BTreeSet<String> = BTreeSet::new();
    let mut sys_addr: BTreeSet<(String, u16)> = BTreeSet::new();
    let mut addrs: BTreeSet<CutAddress> = BTreeSet::new();
    let mut seen_ar: HashSet<(String, String)> = HashSet::new();
    for (id, injected_host) in &all {
        let n = store.node(*id)?;
        let (pid, create_ts) = parse_proc_key(&n.key).unwrap_or((0, n.first_ts));
        let image = attr_str(&n, "image").unwrap_or_default();
        let system = is_system_image(&image);
        let who = image
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&image)
            .to_string();
        procs.push(CutProc {
            node_id: *id,
            pid,
            create_ts,
            first_ts: n.first_ts,
            image: image.clone(),
            system,
            ended: n.attr("ended").and_then(|v| v.as_bool()).unwrap_or(false),
            injected_host: *injected_host,
        });
        for e in store.edges_from(*id)? {
            let dst = store.node(e.dst)?;
            match e.rel.as_str() {
                // 주입당한 프로그램의 자동 실행 등록·파일은 그 프로그램의 정상 활동일 수 있어 끊기 목록에 넣지 않는다
                "registered" if dst.kind == "autorun" && !injected_host => {
                    let k = (dst.key.clone(), dst.label.clone());
                    if seen_ar.insert(k.clone()) {
                        autoruns.push(k);
                    }
                }
                "wrote" if dst.kind == "file" && !injected_host => {
                    let lower = dst.key.to_ascii_lowercase();
                    if EXEC_EXT.iter().any(|x| lower.ends_with(x)) {
                        written.insert(dst.key.clone());
                    }
                }
                "connected" if dst.kind == "remote" => {
                    let ip = dst
                        .attr("ip")
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                    let port = dst.attr("port").and_then(|v| v.as_u64());
                    let proto = match dst
                        .attr("proto")
                        .and_then(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                        .as_deref()
                    {
                        Some("udp") => 17u8,
                        _ => 6u8,
                    };
                    if *injected_host && injected_at.get(id).map_or(false, |t| e.ts < *t) {
                        continue;
                    }
                    if let (Some(ip), Some(port)) = (ip, port) {
                        if system {
                            sys_addr.insert((ip.clone(), port as u16));
                        }
                        let why = if system {
                            "system"
                        } else if *injected_host {
                            "injected"
                        } else {
                            "target"
                        };
                        addrs.insert(CutAddress {
                            who: who.clone(),
                            ip,
                            port: port as u16,
                            proto,
                            why: why.into(),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    Ok(CutTargets {
        root,
        root_kind: rn.kind.clone(),
        root_label: rn.label.clone(),
        root_image,
        procs,
        autoruns,
        written_executables: written.into_iter().collect(),
        system_addresses: sys_addr.into_iter().collect(),
        addresses: addrs.into_iter().collect(),
    })
}

/// 이미지 경로의 프로세스들이 접속한 외부 (ip, port, proto) — engine::GraphQuery 구현 재료
pub fn addresses_of_image(
    store: &Store,
    image: &str,
    since_ts: i64,
) -> Result<Vec<(String, u16, String)>> {
    let mut st = store.conn().prepare(
        r#"
        SELECT DISTINCT r.attrs_json FROM edges e
        JOIN nodes p ON p.id = e.src AND p.kind = 'process'
        JOIN nodes r ON r.id = e.dst AND r.kind = 'remote'
        WHERE e.rel = 'connected' AND e.ts >= ?2 AND lower(json_extract(p.attrs_json, '$.image')) = lower(?1)
        "#,
    )?;
    let rows = st.query_map(params![image, since_ts], |r| r.get::<_, Option<String>>(0))?;
    let mut out = Vec::new();
    for r in rows {
        let v: serde_json::Value = r?
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        if let (Some(ip), Some(port)) = (v["ip"].as_str(), v["port"].as_u64()) {
            out.push((
                ip.to_string(),
                port as u16,
                v["proto"].as_str().unwrap_or("tcp").to_ascii_lowercase(),
            ));
        }
    }
    Ok(out)
}

/// 파일 경로로 실행된 프로세스들의 자손 이미지 경로 (dsl::Resolver::descendants 재료). 뿌리 이미지 포함.
pub fn descendant_images_of_file(store: &Store, path: &str, max: usize) -> Result<Vec<String>> {
    let Some(f) = store
        .conn()
        .query_row(
            "SELECT id FROM nodes WHERE kind = 'file' AND lower(key) = lower(?1)",
            params![path],
            |r| r.get::<_, i64>(0),
        )
        .ok()
    else {
        return Ok(vec![]);
    };
    let t = cut_targets(store, f, max)?;
    let mut imgs: BTreeSet<String> = BTreeSet::new();
    imgs.insert(path.to_string());
    for p in t.procs {
        if !p.image.is_empty() {
            imgs.insert(p.image);
        }
    }
    Ok(imgs.into_iter().collect())
}

/// 출신 기록의 첫 해시 (경로 대소문자 무시). (sha256, 기록 시각 FILETIME)
pub fn recorded_sha256(store: &Store, path: &str) -> Result<Option<(String, i64)>> {
    Ok(store
        .conn()
        .query_row(
            "SELECT o.sha256, o.sha256_ts FROM origins o JOIN nodes f ON f.id = o.file_node WHERE f.kind = 'file' AND lower(f.key) = lower(?1) AND o.sha256 IS NOT NULL",
            params![path],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0))),
        )
        .ok())
}

/// 저장 실패로 버린 구간 (17차 Q3 답변). 이야기·화면에 "이 구간 기록 일부 누락"으로 표시한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub from_ts: i64,
    pub to_ts: i64,
    pub events: i64,
    /// store_failed | channel_full | no_record(서비스가 멈췄거나 PC 가 절전이라 아무것도 기록하지 못한 구간)
    pub reason: String,
}

pub const GAP_DDL: &str = "CREATE TABLE IF NOT EXISTS ingest_gaps (from_ts INTEGER NOT NULL, to_ts INTEGER NOT NULL, events INTEGER NOT NULL, reason TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_gaps_to ON ingest_gaps(to_ts);";

pub fn record_gap(conn: &rusqlite::Connection, g: &Gap) -> Result<()> {
    conn.execute(
        "INSERT INTO ingest_gaps(from_ts, to_ts, events, reason) VALUES (?1, ?2, ?3, ?4)",
        params![g.from_ts, g.to_ts, g.events, g.reason],
    )?;
    Ok(())
}

/// [from, to] 구간과 겹치는 구멍
pub fn gaps_between(store: &Store, from_ts: i64, to_ts: i64) -> Result<Vec<Gap>> {
    let mut st = store.conn().prepare("SELECT from_ts, to_ts, events, reason FROM ingest_gaps WHERE to_ts >= ?1 AND from_ts <= ?2 ORDER BY from_ts LIMIT 200")?;
    let rows = st.query_map(params![from_ts, to_ts], |r| {
        Ok(Gap {
            from_ts: r.get(0)?,
            to_ts: r.get(1)?,
            events: r.get(2)?,
            reason: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// 살아 있음 표시 간격(초). 수집기가 30초마다 남긴다
pub const HEARTBEAT_EVERY_SECS: i64 = 30;
/// 직전 표시와 이만큼(초) 넘게 벌어지면 그 사이를 "기록 없는 구간"(no_record)으로 남긴다
pub const NO_RECORD_AFTER_SECS: i64 = 90;
const FT_SEC: i64 = 10_000_000;

/// 25차 Q1: 수집기가 살아 있음을 남기고, 직전 표시와 90초 넘게 벌어졌으면 그 사이를 no_record 구멍으로 기록해 돌려준다.
/// 서비스 중지·재시작과 절전·재개를 가리지 않는다(둘 다 "기록 없음"이 사실). 처음 설치(직전 표시 없음)·시계가 뒤로 간 경우는 기록하지 않는다.
/// 한계: 시스템 시각을 앞으로 옮기면 가짜 구간이 생긴다(시계 변경은 collector.health 에 따로 보인다).
pub fn heartbeat(store: &Store, now_ft: i64) -> Result<Option<Gap>> {
    let last = store
        .get_meta("heartbeat_ft")?
        .and_then(|v| v.parse::<i64>().ok());
    store.set_meta("heartbeat_ft", &now_ft.to_string())?;
    let Some(last) = last else { return Ok(None) };
    if now_ft - last <= NO_RECORD_AFTER_SECS * FT_SEC {
        return Ok(None);
    }
    let g = Gap {
        from_ts: last,
        to_ts: now_ft,
        events: 0,
        reason: "no_record".into(),
    };
    record_gap(store.conn(), &g)?;
    Ok(Some(g))
}

/// 시각 ts 가 "기록 없는 구간" 안이면 그 구간
pub fn no_record_gap_at(store: &Store, ts: i64) -> Result<Option<Gap>> {
    Ok(store
        .conn()
        .query_row(
            "SELECT from_ts, to_ts, events, reason FROM ingest_gaps WHERE reason = 'no_record' AND from_ts <= ?1 AND to_ts >= ?1 ORDER BY to_ts - from_ts LIMIT 1",
            params![ts],
            |r| Ok(Gap { from_ts: r.get(0)?, to_ts: r.get(1)?, events: r.get(2)?, reason: r.get(3)? }),
        )
        .ok())
}

/// diag 일관성 점검 한 줄: (이름, 문제 수, 전체 수)
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct Consistency {
    pub name: &'static str,
    pub bad: i64,
    pub total: i64,
}

/// 수집·그래프 일관성(과제 23, 26차 2장 같은 결함을 다시 찾기 위한 숫자). since_ts 이후에 보인 프로세스만 센다.
/// - svchost_no_services: 서비스 목록이 없는 svchost(ServiceMap 병합 누락이면 오탐 원인 — 26차 2장)
/// - process_no_image_file: 실행 파일 선(executed_as)이 없는 프로세스(출신·서명을 이을 수 없음)
/// - process_unresolved: 이름을 모르는 프로세스("알 수 없는 프로그램(PID n)", ETW·스냅샷 모두 놓침)
pub fn consistency(store: &Store, since_ts: i64) -> Result<Vec<Consistency>> {
    let c = store.conn();
    let one = |sql: &str| -> Result<(i64, i64)> {
        Ok(c.query_row(sql, rusqlite::params![since_ts], |r| {
            Ok((r.get::<_, Option<i64>>(0)?.unwrap_or(0), r.get(1)?))
        })?)
    };
    let (a, at) = one(
        "SELECT SUM(CASE WHEN json_array_length(COALESCE(json_extract(attrs_json, '$.services'), '[]')) = 0 THEN 1 ELSE 0 END), COUNT(*)
         FROM nodes WHERE kind = 'process' AND last_ts >= ?1 AND LOWER(COALESCE(json_extract(attrs_json, '$.image'), '')) LIKE '%\\svchost.exe'",
    )?;
    let (b, bt) = one(
        "SELECT SUM(CASE WHEN NOT EXISTS (SELECT 1 FROM edges e WHERE e.dst = n.id AND e.rel = 'executed_as') THEN 1 ELSE 0 END), COUNT(*)
         FROM nodes n WHERE n.kind = 'process' AND n.last_ts >= ?1",
    )?;
    let (u, ut) = one(
        "SELECT SUM(CASE WHEN json_extract(attrs_json, '$.unresolved') = 1 THEN 1 ELSE 0 END), COUNT(*)
         FROM nodes WHERE kind = 'process' AND last_ts >= ?1",
    )?;
    Ok(vec![
        Consistency {
            name: "svchost_no_services",
            bad: a,
            total: at,
        },
        Consistency {
            name: "process_no_image_file",
            bad: b,
            total: bt,
        },
        Consistency {
            name: "process_unresolved",
            bad: u,
            total: ut,
        },
    ])
}

/// 프로세스의 실행 파일 노드(executed_as 의 출발). 없으면 None (L063: 금고 경비 정상 처리)
pub fn image_file_of(store: &Store, process_id: i64) -> Option<Node> {
    let id: i64 = store
        .conn()
        .query_row(
            "SELECT src FROM edges WHERE dst = ?1 AND rel = 'executed_as' ORDER BY ts LIMIT 1",
            params![process_id],
            |r| r.get(0),
        )
        .ok()?;
    store.node(id).ok()
}

/// 명령 팔레트(UI 명세 4판 3-9): 실행 파일 이름에 글자가 든 프로세스. 같은 실행 파일은 가장 최근 것 하나만. 최신 먼저. 읽기만
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FoundProcess {
    pub node_id: i64,
    pub label: String,
    pub image: Option<String>,
    pub first_ts: i64,
}

pub fn find_processes(store: &Store, q: &str, limit: usize) -> Result<Vec<FoundProcess>> {
    let q = q.trim().to_lowercase();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let mut st = store.conn().prepare_cached(
        "SELECT id, label, json_extract(attrs_json, '$.image'), first_ts FROM nodes
         WHERE kind = 'process' AND instr(lower(label), ?1) > 0
         ORDER BY first_ts DESC LIMIT 2000",
    )?;
    let rows = st.query_map(rusqlite::params![q], |r| {
        Ok(FoundProcess {
            node_id: r.get(0)?,
            label: r.get(1)?,
            image: r.get(2)?,
            first_ts: r.get(3)?,
        })
    })?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for r in rows {
        let f = r?;
        let k = f
            .image
            .clone()
            .unwrap_or_else(|| f.label.clone())
            .to_lowercase();
        if seen.insert(k) {
            out.push(f);
            if out.len() >= limit {
                break;
            }
        }
    }
    Ok(out)
}
