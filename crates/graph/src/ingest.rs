//! 이벤트 → 그래프 변환
//!
//! 규칙
//! - 프로세스 키 = "PID@CreateTime" (명세 4판 2-1). ProcessStart 페이로드의 CreateTime 또는 스냅샷의
//!   GetProcessTimes 값. 둘은 같은 FILETIME 기준이라 중복 제거가 된다. CreateTime 이 없는 오프라인
//!   로그는 이벤트 시각으로 대신한다. 이후 이벤트는 PID 로 가장 최근 프로세스를 찾는다.
//!   스냅샷에도 없고 ProcessStart 도 못 본 프로세스는 첫 등장 시각으로 키를 만들고 preexisting 표시.
//! - 시스템 서비스 판별: SCM 매핑(ServiceMap/ProcessSnapshot 의 services)이 1차 기준. 그것이 없는
//!   오프라인 로그에서만 이미지 이름(svchost 등)으로 추정한다. A4 에서 서명자 기준이 추가된다.
//! - 모든 선은 raw_events 의 근거 id 를 가진다.
//! - DNS 조회는 프로세스→도메인(resolved) 선을 만들고, 응답 IP 를 도메인에 기록해 둔다.
//!   이후 같은 IP 로의 Connect 는 remote 노드에 도메인 이름을 붙인다 (IP 만 남는 연결에 도메인 부여).
//! - 서비스 경유 통신(P1-b 실측: TLS 중 CryptSvc 가 CRL 조회): 시스템 서비스 프로세스가 사용자
//!   프로세스의 접속 직후 짧은 시간 창 안에 새 도메인에 접속하면, 그 접속을 원인 프로세스에
//!   `proxied_by` 속성으로 귀속한다. 선은 서비스 프로세스에 그대로 남기고(사실), 귀속은 속성(해석)이다.

use crate::event::{Direction, Event, EventKind, ProcRef};
use crate::{NodeKind, Rel, Result, Store};
use rusqlite::OptionalExtension;
use std::collections::HashMap;

/// 서비스 경유 귀속 시간 창 (FILETIME 100ns 단위). 2초.
const PROXY_WINDOW: i64 = 2 * 10_000_000;

/// SCM 정보가 없는 오프라인 로그에서만 쓰는 추정 기준 (소문자 파일명). 제품 경로에서는 SCM 매핑이 우선.
const SERVICE_IMAGES_FALLBACK: &[&str] =
    &["svchost.exe", "lsass.exe", "services.exe", "wininit.exe"];

/// 부팅 시각 비교 여유(100ns 단위, 2분)
const BOOT_SLACK: i64 = 2 * 60 * 10_000_000;

/// SCM 매핑이 ProcessStart 보다 먼저 왔을 때 같은 프로세스로 보는 여유(100ns, 2초 — 생성 시각보다 이만큼 이른 매핑까지)
const SCM_EARLY_SLACK: i64 = 2 * 10_000_000;

/// 시작 이벤트보다 먼저 온 접속·파일 이벤트로 만든 "알 수 없는 프로그램" 노드를 늦게 온 ProcessStart 가 넘겨받는 여유(100ns, 30초).
/// 실측(2026-11-06 노트북): chrome 네트워크 서비스(생성 21:59:21)의 접속(21:59:25)이 시작 이벤트보다 먼저 그래프에 들어와 이름을 잃었다
const ADOPT_WINDOW: i64 = 30 * 10_000_000;

/// 명령 노드 키 최대 길이(문자)
pub const CMDLINE_MAX: usize = 1024;

pub struct Ingester<'a> {
    store: &'a Store,
    /// 이번 부팅 시각(FILETIME). 있으면 스냅샷 프로세스의 생성 시각이 이보다 이를 때 선 시각을 부팅 시각으로 올린다(L023)
    boot_time: Option<i64>,
    /// 최근 DNS 응답: ip → (domain, ts)
    dns_cache: HashMap<String, (String, i64)>,
    /// 최근 사용자 프로세스 아웃바운드 접속: (ts, process node id). 서비스 경유 귀속용
    recent_user_connects: Vec<(i64, i64)>,
    /// PID → 이미지 파일명 (서비스 판별용)
    image_by_pid: HashMap<u32, String>,
    /// 최근 DNS 조회 선: (process node, domain node, ts, edge id). 1초 창 합치기용
    recent_resolves: Vec<(i64, i64, i64, i64)>,
    /// SCM 매핑: PID → 서비스 이름 목록. 비어 있지 않으면 시스템 서비스.
    services_by_pid: HashMap<u32, Vec<String>>,
    /// 그 PID 의 SCM 매핑을 마지막으로 받은 시각 — ProcessStart 보다 먼저 온 매핑이 이 프로세스의 것인지 가르는 데 쓴다
    scm_ts_by_pid: HashMap<u32, (i64, Option<i64>)>,
    /// SCM 매핑을 한 번이라도 받았는가. 받았으면 이미지 이름 추정을 쓰지 않는다.
    scm_seen: bool,
    /// PID → 토큰이 시스템 계정인가 (None = 모름)
    system_token_by_pid: HashMap<u32, Option<bool>>,
    /// 실행 파일 경로(소문자) → 서명자 (None = 서명 없음/무효). 서비스 판별 3조건 중 하나.
    signer_by_path: HashMap<String, Option<String>>,
    /// CAPI2 체인 인증서 fileRef(또는 TaskId) → (ts, 리프 subject 소문자)
    cert_chains: HashMap<String, (i64, String)>,
    /// 사용자 프로세스가 도메인을 조회·접속한 기록: (ts, process node, 도메인 소문자)
    recent_domain_touch: Vec<(i64, i64, String)>,
    /// 서비스 프로세스의 아웃바운드: (ts, remote node, 도메인 또는 ip 소문자, connected edge id)
    recent_service_connects: Vec<(i64, i64, String, i64)>,
    /// 41 이 접속보다 먼저 온 경우를 위해: (ts, host, 원인 process node, confidence)
    pending_capi2: Vec<(i64, String, i64, &'static str)>,
    /// 최근 열기 선: (process node, file node) → (edge id, 첫 ts). 같은 프로세스가 같은 파일을 OPEN_MERGE_WINDOW 안에 다시 열면 근거만 더한다
    recent_opens: HashMap<(i64, i64), (i64, i64)>,
}

/// 같은 (프로세스, 파일) 열기를 선 하나로 합치는 시간 창 (60초)
const OPEN_MERGE_WINDOW: i64 = 60 * 10_000_000;

/// CAPI2 귀속 시간 창 (60초)
const CAPI2_WINDOW: i64 = 60 * 10_000_000;

/// DNS 조회 합치기 시간 창 (FILETIME 100ns). 1초.
const RESOLVE_WINDOW: i64 = 10_000_000;

impl<'a> Ingester<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self {
            store,
            boot_time: None,
            dns_cache: HashMap::new(),
            recent_user_connects: Vec::new(),
            image_by_pid: HashMap::new(),
            recent_resolves: Vec::new(),
            services_by_pid: HashMap::new(),
            scm_ts_by_pid: HashMap::new(),
            scm_seen: false,
            system_token_by_pid: HashMap::new(),
            signer_by_path: HashMap::new(),
            cert_chains: HashMap::new(),
            recent_domain_touch: Vec::new(),
            recent_service_connects: Vec::new(),
            pending_capi2: Vec::new(),
            recent_opens: HashMap::new(),
        }
    }

    fn touch_domain(&mut self, ts: i64, p: i64, domain: &str) {
        self.recent_domain_touch
            .push((ts, p, domain.to_ascii_lowercase()));
        if self.recent_domain_touch.len() > 4096 {
            self.recent_domain_touch.drain(..2048);
        }
    }

    /// CAPI2 리프 subject(CN) 와 접속 도메인의 일치. 와일드카드·하위 도메인은 접미 일치.
    fn subject_matches(subject: &str, domain: &str) -> bool {
        let s = subject.trim_start_matches("*.");
        domain == subject || domain == s || domain.ends_with(&format!(".{s}"))
    }

    /// CAPI2 결정적 귀속 (명세 5판 2-3): host(U) 로의 서비스 접속을 원인 프로세스 P 에 묶는다.
    /// 기존 window 귀속 선이 있으면 교체한다.
    fn apply_capi2(
        &mut self,
        ts: i64,
        host: &str,
        origin: i64,
        confidence: &'static str,
        raw_id: i64,
        task_id: &str,
        url: &str,
    ) -> Result<usize> {
        let mut n = 0;
        let targets: Vec<(i64, i64)> = self
            .recent_service_connects
            .iter()
            .filter(|(t, _, h, _)| ts - *t <= CAPI2_WINDOW && *t - ts <= CAPI2_WINDOW && h == host)
            .map(|(_, r, _, e)| (*r, *e))
            .collect();
        for (remote, _edge) in targets {
            // window 귀속 선 제거 (같은 원격지, 60초 안)
            self.store.conn.execute(
                r#"DELETE FROM edges WHERE rel='connected_via' AND dst = ?1 AND ABS(ts - ?2) <= ?3
                 AND COALESCE(attrs_json, '') LIKE '%"method":"window"%'"#,
                rusqlite::params![remote, ts, CAPI2_WINDOW],
            )?;
            let already: i64 = self.store.conn.query_row(
                "SELECT COUNT(*) FROM edges WHERE rel='connected_via' AND dst = ?1 AND src = ?2 AND ABS(ts - ?3) <= ?4",
                rusqlite::params![remote, origin, ts, CAPI2_WINDOW],
                |r| r.get(0),
            )?;
            if already > 0 {
                continue;
            }
            let attrs = serde_json::json!({ "method": "capi2", "confidence": confidence, "task_id": task_id, "url": url }).to_string();
            self.store.insert_edge_with_attrs(
                origin,
                remote,
                Rel::ConnectedVia,
                ts,
                Some(raw_id),
                &attrs,
            )?;
            n += 1;
        }
        Ok(n)
    }

    /// 이번 부팅 시각을 알려 준다(수집기 스냅샷 단계). 프로세스 키(PID@CreateTime)는 그대로 두고 — 종료 시
    /// GetProcessTimes 와 맞춰 보는 값이라 바꾸면 안 된다 — 선·노드 시각만 보정한다
    pub fn set_boot_time(&mut self, ft: i64) {
        self.boot_time = Some(ft);
    }

    /// 프로세스 노드 생성 (ProcessStart·스냅샷 공용). 부모 선과 실행 파일 선을 만든다.
    fn add_process(
        &mut self,
        pid: u32,
        ppid: u32,
        image: &str,
        key_ts: i64,
        ev_ts: i64,
        raw_id: i64,
        preexisting: bool,
        services: &[String],
    ) -> Result<usize> {
        self.image_by_pid.insert(pid, file_name(image));
        if !services.is_empty() {
            self.services_by_pid.insert(pid, services.to_vec());
            self.scm_seen = true;
        }
        let child_key = proc_key(pid, key_ts);
        // 부팅보다 이른 생성 시각 = 부팅 직후 시계가 틀렸던 것(L023). 2분 여유. 원래 값은 키·속성에 남는다
        let uncertain = preexisting && self.boot_time.is_some_and(|b| key_ts < b - BOOT_SLACK);
        let shown_ts = if uncertain {
            self.boot_time.unwrap_or(key_ts)
        } else {
            key_ts
        };
        // 중복 제거: 스냅샷으로 이미 들어온 프로세스의 ProcessStart (또는 그 반대)
        if let Some(existing) = self.store.find_node(NodeKind::Process, &child_key)? {
            // 보정 전에 저장된 노드(이전 서비스 실행)가 있으면 그 노드·들어오는 선의 시각도 올린다
            if uncertain {
                self.store.conn.execute(
                    "UPDATE nodes SET first_ts = ?1,
                       attrs_json = json_set(COALESCE(attrs_json, '{}'), '$.create_time_uncertain', json('true'), '$.create_time_raw', ?2)
                     WHERE id = ?3 AND first_ts = ?2",
                    rusqlite::params![shown_ts, key_ts, existing],
                )?;
                self.store.conn.execute(
                    "UPDATE edges SET ts = ?1 WHERE dst = ?3 AND ts = ?2 AND rel IN ('spawned', 'executed_as')",
                    rusqlite::params![shown_ts, key_ts, existing],
                )?;
            }
            return Ok(0);
        }
        let mut attrs = serde_json::json!({
            "image": image, "pid": pid, "ppid": ppid,
            "preexisting": preexisting, "services": services,
        });
        if uncertain {
            attrs["create_time_uncertain"] = serde_json::json!(true);
            attrs["create_time_raw"] = serde_json::json!(key_ts);
        }
        let attrs = attrs.to_string();
        // 이하 노드·선·부모 찾기는 보정된 시각으로(부모도 같은 규칙으로 보정돼 first_ts 비교가 맞는다)
        let key_ts = shown_ts;
        // 순서 뒤바뀜 보정: 이 프로세스가 생긴 뒤(여유 안) 같은 PID 로 먼저 만들어진 이름 모름 노드가 있으면
        // 새 노드를 만들지 않고 그 노드를 넘겨받는다(키·이름·속성을 이 프로세스 것으로). 이미 붙은 접속·파일 선은 그대로 이 프로세스 것이 된다
        let adopt: Option<i64> = self
            .store
            .conn
            .query_row(
                "SELECT id FROM nodes
                 WHERE kind = 'process' AND key >= ?1 AND key < ?2
                   AND json_extract(attrs_json, '$.unresolved') = 1
                   AND first_ts >= ?3 AND first_ts <= ?4
                 ORDER BY first_ts LIMIT 1",
                rusqlite::params![
                    format!("{pid}@"),
                    format!("{pid}A"),
                    key_ts,
                    key_ts + ADOPT_WINDOW
                ],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = adopt {
            self.store.conn.execute(
                "UPDATE nodes SET key = ?1, label = ?2, first_ts = ?3, attrs_json = ?4 WHERE id = ?5",
                rusqlite::params![child_key, file_name(image), key_ts, attrs, id],
            )?;
        }
        let child = match adopt {
            Some(id) => id,
            None => self.store.upsert_node(
                NodeKind::Process,
                &child_key,
                &file_name(image),
                key_ts,
                Some(&attrs),
            )?,
        };
        let mut n = 0;
        // 부모: 스냅샷 프로세스는 부모가 이미 종료됐을 수 있다. 있을 때만 잇는다.
        // 2026-11-08 노트북: 재부팅 전 노드(종료 기록 없음)가 같은 PID 로 잡혀 wininit 의 부모가 됐다 → 이번 부팅 것만
        let parent = if preexisting {
            match self.store.latest_process_by_pid(ppid, key_ts)? {
                Some(id) if self.same_boot(id, shown_ts)? => Some(id),
                _ => None,
            }
        } else {
            Some(self.resolve_proc(&ProcRef::new(ppid, None), ev_ts)?)
        };
        if let Some(parent) = parent {
            if parent != child {
                self.store
                    .insert_edge(parent, child, Rel::Spawned, key_ts, Some(raw_id))?;
                n += 1;
            }
        }
        // 파일 → 프로세스 (실행됨). 파일 노드는 경로로 식별
        if !image.is_empty() {
            let file =
                self.store
                    .upsert_node(NodeKind::File, image, &file_name(image), key_ts, None)?;
            self.store
                .insert_edge(file, child, Rel::ExecutedAs, key_ts, Some(raw_id))?;
            n += 1;
        }
        Ok(n)
    }

    fn recent_resolve(&self, p: i64, d: i64, ts: i64) -> Option<i64> {
        self.recent_resolves
            .iter()
            .rev()
            .find(|(pp, dd, t, _)| *pp == p && *dd == d && ts - *t <= RESOLVE_WINDOW && ts >= *t)
            .map(|(_, _, _, eid)| *eid)
    }

    /// 이벤트 하나를 그래프에 반영한다. 만들어진 선의 수를 돌려준다.
    pub fn ingest(&mut self, ev: &Event) -> Result<usize> {
        let payload = serde_json::to_string(ev)?;
        let raw_id = self.store.insert_raw(ev.ts, &ev.source, &payload)?;
        match &ev.kind {
            EventKind::ProcessStart {
                pid,
                ppid,
                image,
                create_time,
            } => {
                let key_ts = create_time.unwrap_or(ev.ts);
                // L048: SCM 폴링(1초)이 ETW 시작 이벤트(전달 지연 최대 ~1초)보다 먼저 새 서비스 호스트를 볼 수 있다. 그 매핑은
                // 변화분이라 다시 오지 않으므로, 이 프로세스가 생긴 뒤(여유 2초) 받은 매핑이면 이 노드에 붙인다.
                // 그보다 오래된 매핑은 같은 PID 를 쓰던 예전 프로세스 것이다 — 붙이지 않는다(물려받기로 고립 svchost 판정 피하기 방지)
                // 매핑에 생성 시각이 있으면 정확히 같을 때만, 없으면(예전 형식) 시각 여유로
                let early: Vec<String> =
                    match (self.services_by_pid.get(pid), self.scm_ts_by_pid.get(pid)) {
                        (Some(v), Some((_, Some(ct)))) if *ct == key_ts => v.clone(),
                        (Some(v), Some((t, None))) if *t >= key_ts - SCM_EARLY_SLACK => v.clone(),
                        _ => Vec::new(),
                    };
                self.add_process(*pid, *ppid, image, key_ts, ev.ts, raw_id, false, &early)
            }
            EventKind::ProcessSnapshot {
                pid,
                ppid,
                image,
                create_time,
                services,
            } => self.add_process(
                *pid,
                *ppid,
                image,
                *create_time,
                ev.ts,
                raw_id,
                true,
                services,
            ),
            EventKind::ProcessSession {
                pid,
                create_time,
                session,
            } => {
                if let Some(id) = self
                    .store
                    .find_node(NodeKind::Process, &format!("{pid}@{create_time}"))?
                {
                    self.store
                        .merge_node_attrs(id, &serde_json::json!({ "session": session }))?;
                }
                Ok(0)
            }
            EventKind::ServiceMap {
                pid,
                services,
                system_token,
                create_time,
            } => {
                self.scm_seen = true;
                self.scm_ts_by_pid.insert(*pid, (ev.ts, *create_time));
                if services.is_empty() {
                    self.services_by_pid.remove(pid);
                } else {
                    self.services_by_pid.insert(*pid, services.clone());
                    // L038: 수집 시작 뒤 켜진 서비스 호스트(예: 필요할 때 켜지는 W32Time 의 svchost)는 ProcessStart 때 서비스 목록이 비어 있다.
                    // 전에는 이 매핑을 메모리에만 두어 노드의 services 가 끝까지 비었고, 판정이 "알려진 서비스 없는 고립 svchost"로 오탐했다
                    // 끝난 노드(같은 PID 를 쓰던 예전 프로세스)에는 붙이지 않는다 — 새 프로세스의 시작 이벤트가 아직 안 온 경우다.
                    // 그때는 위 기억(services_by_pid·scm_ts_by_pid)을 ProcessStart 가 쓴다
                    // 생성 시각을 알면 그 노드에만(없으면 시작 이벤트가 아직 — 위 기억을 ProcessStart 가 쓴다).
                    // 모르면(예전 형식) 끝나지 않은 가장 최근 같은 PID 노드
                    let target = match create_time {
                        Some(ct) => self
                            .store
                            .find_node(NodeKind::Process, &proc_key(*pid, *ct))?,
                        None => self.store.latest_process_by_pid(*pid, ev.ts)?.filter(|id| {
                            !self
                                .store
                                .node(*id)
                                .ok()
                                .and_then(|n| n.attr("ended"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                        }),
                    };
                    if let Some(id) = target {
                        self.store
                            .merge_node_attrs(id, &serde_json::json!({ "services": services }))?;
                    }
                }
                self.system_token_by_pid.insert(*pid, *system_token);
                Ok(0)
            }
            EventKind::CertChain {
                subject,
                task_id,
                chain_refs,
                ..
            } => {
                let leaf = subject.to_ascii_lowercase();
                self.cert_chains
                    .insert(task_id.clone(), (ev.ts, leaf.clone()));
                for r in chain_refs {
                    self.cert_chains
                        .insert(r.to_ascii_lowercase(), (ev.ts, leaf.clone()));
                }
                if self.cert_chains.len() > 2048 {
                    let cutoff = ev.ts - CAPI2_WINDOW;
                    self.cert_chains.retain(|_, (t, _)| *t >= cutoff);
                }
                Ok(0)
            }
            EventKind::RevocationFetch {
                task_id,
                url,
                cert_ref,
                ..
            } => {
                let host = host_of(url).to_ascii_lowercase();
                // 검사 대상 인증서(중간·루트)의 fileRef 가 어느 체인에 속했는지 → 그 체인의 리프 도메인
                let found = cert_ref
                    .as_ref()
                    .and_then(|r| self.cert_chains.get(&r.to_ascii_lowercase()).cloned())
                    .or_else(|| self.cert_chains.get(task_id).cloned());
                let Some((_, subject)) = found else {
                    // 11 없이 41 만 온 경우: 시간 창 폴백에 맡긴다 (4차 검증 A4-4)
                    return Ok(0);
                };
                // 60초 안에 subject 도메인을 만진 사용자 프로세스 후보
                let mut cands: Vec<(i64, i64)> = self
                    .recent_domain_touch
                    .iter()
                    .filter(|(t, _, d)| {
                        ev.ts - *t <= CAPI2_WINDOW && Self::subject_matches(&subject, d)
                    })
                    .map(|(t, p, _)| (*t, *p))
                    .collect();
                if cands.is_empty() {
                    return Ok(0);
                }
                cands.sort();
                let distinct: std::collections::HashSet<i64> =
                    cands.iter().map(|(_, p)| *p).collect();
                let origin = cands.last().unwrap().1;
                let confidence: &'static str = if distinct.len() == 1 { "high" } else { "low" };
                let n = self.apply_capi2(ev.ts, &host, origin, confidence, raw_id, task_id, url)?;
                // 접속이 아직 안 왔을 수 있으므로 보류 목록에도 둔다
                self.pending_capi2.push((ev.ts, host, origin, confidence));
                if self.pending_capi2.len() > 512 {
                    self.pending_capi2.drain(..256);
                }
                Ok(n)
            }
            EventKind::Signature {
                path,
                signer,
                issuer,
                status,
                catalog,
            } => {
                self.signer_by_path
                    .insert(path.to_ascii_lowercase(), signer.clone());
                if let Some(f) = self.store.find_node(NodeKind::File, path)? {
                    self.store.merge_node_attrs(f, &serde_json::json!({
                        "signer": signer, "issuer": issuer, "sig_status": status, "catalog": catalog,
                    }))?;
                    self.store.conn.execute(
                        "UPDATE origins SET signer = ?1 WHERE file_node = ?2",
                        rusqlite::params![signer, f],
                    )?;
                }
                Ok(0)
            }
            EventKind::ProcessStop { pid } => {
                if let Some(id) = self.store.latest_process_by_pid(*pid, ev.ts)? {
                    self.store.conn.execute(
                        "UPDATE nodes SET last_ts = ?1 WHERE id = ?2",
                        rusqlite::params![ev.ts, id],
                    )?;
                    // 종료 표시 (A19: 프로세스 상세·끊기에서 "이미 끝남")
                    self.store
                        .merge_node_attrs(id, &serde_json::json!({ "ended": true }))?;
                }
                Ok(0)
            }
            EventKind::DnsQuery {
                proc,
                name,
                results,
            } => {
                let p = self.resolve_proc(proc, ev.ts)?;
                let d = self
                    .store
                    .upsert_node(NodeKind::Domain, name, name, ev.ts, None)?;
                if !self.is_service(proc.pid) {
                    self.touch_domain(ev.ts, p, name);
                }
                for ip in results {
                    let ip = normalize_ip(ip);
                    if ip.is_empty() {
                        continue;
                    }
                    self.dns_cache.insert(ip, (name.clone(), ev.ts));
                }
                // 한 번의 조회가 A/AAAA × 시작/완료/캐시 이벤트로 6~8건이 된다.
                // 같은 프로세스·같은 도메인의 조회가 1초 창 안이면 선 하나로 합치고, 근거만 추가한다.
                if let Some(eid) = self.recent_resolve(p, d, ev.ts) {
                    self.store.add_evidence(eid, raw_id)?;
                    return Ok(0);
                }
                let eid = self
                    .store
                    .insert_edge(p, d, Rel::Resolved, ev.ts, Some(raw_id))?;
                self.recent_resolves.push((p, d, ev.ts, eid));
                if self.recent_resolves.len() > 512 {
                    self.recent_resolves.drain(..256);
                }
                Ok(1)
            }
            EventKind::Connect {
                proc,
                proto,
                direction,
                raddr,
                rport,
                ..
            } => {
                let p = self.resolve_proc(proc, ev.ts)?;
                let ip = normalize_ip(raddr);
                let key = format!("{ip}:{rport}");
                // 직전 DNS 조회로 도메인을 붙인다. 조회가 이 수집기 수명 안에 없으면(서비스 재시작·배치 경계) 같은 원격지 노드에
                // 전에 붙은 도메인을 이어받는다 — 없으면 upsert 가 attrs 를 통째로 바꿔 도메인이 지워지고, 사건 추적이 "새 접속지"로 잘못 본다(39차 반영 중 발견)
                let domain = self.dns_cache.get(&ip).map(|(d, _)| d.clone()).or_else(|| {
                    self.store
                        .find_node(NodeKind::Remote, &key)
                        .ok()
                        .flatten()
                        .and_then(|id| self.store.node(id).ok())
                        .and_then(|n| n.attr("domain"))
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                });
                let label = match &domain {
                    Some(d) => format!("{d}:{rport}"),
                    None => key.clone(),
                };
                let mut attrs = serde_json::json!({
                    "ip": ip, "port": rport, "proto": proto, "domain": domain,
                });
                let is_svc = self.is_service(proc.pid);
                let host_key = domain
                    .clone()
                    .unwrap_or_else(|| ip.clone())
                    .to_ascii_lowercase();
                // 서비스 경유 귀속 (2순위, 시간 창 폴백): 서비스 프로세스의 아웃바운드가 직전 사용자 접속의
                // 시간 창 안이면. DNS 전송(UDP 53)은 이미 `resolved` 사실로 기록되므로 귀속 대상도 아니다.
                if *direction == Direction::Out && is_svc && !is_dns_transport(*proto, *rport) {
                    // 1순위: 이미 도착한 CAPI2(41) 보류분이 이 host 를 가리키면 그것으로
                    if let Some((t, _, origin, conf)) = self
                        .pending_capi2
                        .iter()
                        .rev()
                        .find(|(t, h, _, _)| ev.ts - *t <= CAPI2_WINDOW && *h == host_key)
                    {
                        attrs["proxied_for"] = serde_json::json!(origin);
                        attrs["via_lag_ms"] = serde_json::json!((ev.ts - *t) / 10_000);
                        attrs["via_method"] = serde_json::json!("capi2");
                        attrs["via_confidence"] = serde_json::json!(conf);
                    } else if let Some((t0, origin)) = self
                        .recent_user_connects
                        .iter()
                        .rev()
                        .find(|(t, _)| ev.ts - *t <= PROXY_WINDOW && ev.ts >= *t)
                    {
                        // 후보가 둘 이상이면 보류 (4판 3-2 보완)
                        let distinct: std::collections::HashSet<i64> = self
                            .recent_user_connects
                            .iter()
                            .filter(|(t, _)| ev.ts - *t <= PROXY_WINDOW && ev.ts >= *t)
                            .map(|(_, p)| *p)
                            .collect();
                        if distinct.len() == 1 {
                            attrs["proxied_for"] = serde_json::json!(origin);
                            attrs["via_method"] = serde_json::json!("window");
                            attrs["via_lag_ms"] = serde_json::json!((ev.ts - *t0) / 10_000);
                            attrs["via_confidence"] = serde_json::json!("low");
                        } else {
                            attrs["via_ambiguous"] = serde_json::json!(distinct.len());
                        }
                    }
                } else if *direction == Direction::Out && !is_dns_transport(*proto, *rport) {
                    // DNS 전송(UDP 53)은 다른 통신의 부속이라 "원인 후보"에서 뺀다.
                    // (P1-b 실측: DNS 클라이언트 서비스의 UDP 송신이 CRL 조회의 원인으로 잘못 잡혔음)
                    self.recent_user_connects.push((ev.ts, p));
                    if self.recent_user_connects.len() > 256 {
                        self.recent_user_connects.drain(..128);
                    }
                }
                let r = self.store.upsert_node(
                    NodeKind::Remote,
                    &key,
                    &label,
                    ev.ts,
                    Some(&attrs.to_string()),
                )?;
                let (src, dst) = match direction {
                    Direction::Out => (p, r),
                    Direction::In => (r, p),
                };
                let eid = self
                    .store
                    .insert_edge(src, dst, Rel::Connected, ev.ts, Some(raw_id))?;
                self.store.add_traffic_hour(ev.ts, 0, 0, 1)?;
                if *direction == Direction::Out && !is_svc {
                    if let Some(d) = &domain {
                        self.touch_domain(ev.ts, p, d);
                    }
                } else if *direction == Direction::Out && is_svc {
                    self.recent_service_connects
                        .push((ev.ts, r, host_key.clone(), eid));
                    if self.recent_service_connects.len() > 1024 {
                        self.recent_service_connects.drain(..512);
                    }
                }
                // 귀속 정보는 선에도 남긴다 (질의에서 바로 쓰기 위해). method/confidence 는 attrs_json 에.
                if let Some(origin) = attrs.get("proxied_for").and_then(|v| v.as_i64()) {
                    let via_attrs = serde_json::json!({
                        "method": attrs.get("via_method").cloned().unwrap_or(serde_json::json!("window")),
                        "confidence": attrs.get("via_confidence").cloned().unwrap_or(serde_json::json!("low")),
                        // D028-1: 짝지은 두 이벤트(사용자 접속·인증서 확인 ↔ 서비스 접속)의 시각 차 — 화면 근거 툴팁
                        "lag_ms": attrs.get("via_lag_ms").cloned().unwrap_or(serde_json::Value::Null),
                    })
                    .to_string();
                    self.store.insert_edge_with_attrs(
                        origin,
                        r,
                        Rel::ConnectedVia,
                        ev.ts,
                        Some(raw_id),
                        &via_attrs,
                    )?;
                    return Ok(2);
                }
                Ok(1)
            }
            EventKind::FileWrite { proc, path } => {
                let p = self.resolve_proc(proc, ev.ts)?;
                let f =
                    self.store
                        .upsert_node(NodeKind::File, path, &file_name(path), ev.ts, None)?;
                self.store
                    .insert_edge(p, f, Rel::Wrote, ev.ts, Some(raw_id))?;
                Ok(1)
            }
            EventKind::FileOpen { proc, path } => {
                // 17판 23-2 ②: 프로세스 → 파일(opened). 무엇을 읽었는지는 모른다 — 열었다는 사실만
                let p = self.resolve_proc(proc, ev.ts)?;
                let f =
                    self.store
                        .upsert_node(NodeKind::File, path, &file_name(path), ev.ts, None)?;
                if let Some((eid, t0)) = self.recent_opens.get(&(p, f)).copied() {
                    if ev.ts >= t0 && ev.ts - t0 <= OPEN_MERGE_WINDOW {
                        self.store.add_evidence(eid, raw_id)?;
                        return Ok(0);
                    }
                }
                let eid = self
                    .store
                    .insert_edge(p, f, Rel::Opened, ev.ts, Some(raw_id))?;
                if self.recent_opens.len() > 1024 {
                    self.recent_opens
                        .retain(|_, (_, t)| ev.ts - *t <= OPEN_MERGE_WINDOW);
                }
                self.recent_opens.insert((p, f), (eid, ev.ts));
                Ok(1)
            }
            EventKind::Downloaded {
                path,
                host_url,
                referrer_url,
                zone_id,
            } => {
                let f =
                    self.store
                        .upsert_node(NodeKind::File, path, &file_name(path), ev.ts, None)?;
                self.store.merge_node_attrs(
                    f,
                    &serde_json::json!({ "zone_id": zone_id, "host_url": host_url }),
                )?;
                let origin_label = host_url.clone().unwrap_or_else(|| "(unknown)".into());
                let o = self.store.upsert_node(
                    NodeKind::Domain,
                    &host_of(&origin_label),
                    &host_of(&origin_label),
                    ev.ts,
                    None,
                )?;
                self.store
                    .insert_edge(o, f, Rel::Downloaded, ev.ts, Some(raw_id))?;
                self.store.conn.execute(
                    "INSERT OR REPLACE INTO origins(file_node, host_url, referrer_url, first_seen)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![f, host_url, referrer_url, ev.ts],
                )?;
                Ok(1)
            }
            EventKind::AutorunRegistered {
                proc,
                location,
                target,
            } => {
                let p = self.resolve_proc(proc, ev.ts)?;
                let a = self
                    .store
                    .upsert_node(NodeKind::Autorun, location, target, ev.ts, None)?;
                self.store
                    .insert_edge(p, a, Rel::Registered, ev.ts, Some(raw_id))?;
                Ok(1)
            }
            EventKind::FileHash {
                path,
                sha256,
                size,
                note,
            } => {
                // 출신 기록(장기 보관)에 첫 해시를 남기고, 파일 노드에는 현재 해시. 바뀌면 "교체됨" 사실로 남긴다.
                // 서명 없는 실행 파일은 MOTW 가 없어도 출신 기록을 만든다 (지침: 서명 없거나 인터넷에서 받은 실행 파일은 장기 보관).
                let f =
                    self.store
                        .upsert_node(NodeKind::File, path, &file_name(path), ev.ts, None)?;
                self.store.conn.execute(
                    "INSERT OR IGNORE INTO origins(file_node, first_seen) VALUES (?1, ?2)",
                    rusqlite::params![f, ev.ts],
                )?;
                let Some(h) = sha256 else {
                    self.store.merge_node_attrs(
                        f,
                        &serde_json::json!({ "hash_note": note, "size": size }),
                    )?;
                    return Ok(0);
                };
                let first: Option<String> = self.store.conn.query_row(
                    "SELECT sha256 FROM origins WHERE file_node = ?1",
                    rusqlite::params![f],
                    |r| r.get(0),
                )?;
                match first {
                    None => {
                        self.store.conn.execute(
                            "UPDATE origins SET sha256 = ?1, sha256_ts = ?2 WHERE file_node = ?3",
                            rusqlite::params![h, ev.ts, f],
                        )?;
                        self.store.merge_node_attrs(
                            f,
                            &serde_json::json!({ "sha256": h, "size": size }),
                        )?;
                    }
                    Some(old) if &old != h => {
                        self.store.merge_node_attrs(f, &serde_json::json!({ "sha256": h, "size": size, "sha256_first": old, "content_changed_ts": ev.ts }))?;
                    }
                    Some(_) => {}
                }
                // 31차 Gemini Q1: 해시를 확인한 시각은 바뀌지 않았어도 남긴다 — 이번 실행 뒤의 해시가 왔는지 첫 실행 판단이 알 수 있게
                self.store
                    .merge_node_attrs(f, &serde_json::json!({ "sha256_seen_ts": ev.ts }))?;
                Ok(0)
            }
            EventKind::ProcessCommand {
                proc,
                cmdline,
                tool,
            } => {
                // 명령 노드: 키 = 명령줄 원문(최대 CMDLINE_MAX 자), 이름 = 앞부분. 같은 명령은 한 노드, 실행마다 선 하나
                let key: String = cmdline.trim().chars().take(CMDLINE_MAX).collect();
                if key.is_empty() {
                    return Ok(0);
                }
                let p = self.resolve_proc(proc, ev.ts)?;
                let label: String = if key.chars().count() > 80 {
                    key.chars().take(79).chain(std::iter::once('…')).collect()
                } else {
                    key.clone()
                };
                let c = self
                    .store
                    .upsert_node(NodeKind::Command, &key, &label, ev.ts, None)?;
                let eid = self
                    .store
                    .insert_edge(p, c, Rel::Ran, ev.ts, Some(raw_id))?;
                if let Some(t) = tool {
                    // 판정이 명령줄 첫 토큰(바뀐 이름) 대신 원래 도구 이름으로 판별하게
                    self.store.conn.execute(
                        "UPDATE edges SET attrs_json = json_object('tool', ?1) WHERE id = ?2",
                        rusqlite::params![t, eid],
                    )?;
                }
                Ok(1)
            }
            EventKind::Injected { from, into, method } => {
                let a = self.resolve_proc(from, ev.ts)?;
                let b = self.resolve_proc(into, ev.ts)?;
                let eid = self
                    .store
                    .insert_edge(a, b, Rel::Injected, ev.ts, Some(raw_id))?;
                let _ = (eid, method);
                Ok(1)
            }
        }
    }

    /// 여러 이벤트를 시각 순으로 넣는다
    pub fn ingest_all<'e, I: IntoIterator<Item = &'e Event>>(
        &mut self,
        events: I,
    ) -> Result<usize> {
        let mut n = 0;
        for ev in events {
            n += self.ingest(ev)?;
        }
        Ok(n)
    }

    /// ProcRef → 프로세스 노드 id. 생성 시각을 알면 정확히, 모르면 같은 PID 의 가장 최근 프로세스.
    /// 둘 다 없으면 "기존 프로세스"로 새로 만든다 (수집 시작 전부터 살아 있던 프로세스).
    /// 노드가 `ts` 와 같은 부팅의 것인가. 부팅 시각을 모르거나 `ts` 가 이번 부팅 이전이면 따지지 않는다.
    /// 노드 시각이 이번 부팅보다 2분(BOOT_SLACK) 넘게 이르면 이전 부팅의 프로세스 — 같은 PID 라도 다른 프로세스다.
    /// (L023: 부팅 직후 시계가 틀린 프로세스는 노드 시각을 부팅 시각으로 올려 두므로 여기서 걸리지 않는다)
    fn same_boot(&self, id: i64, ts: i64) -> Result<bool> {
        let Some(b) = self.boot_time else {
            return Ok(true);
        };
        if ts < b - BOOT_SLACK {
            return Ok(true);
        }
        let first: i64 =
            self.store
                .conn
                .query_row("SELECT first_ts FROM nodes WHERE id = ?1", [id], |r| {
                    r.get(0)
                })?;
        Ok(first >= b - BOOT_SLACK)
    }

    fn resolve_proc(&mut self, p: &ProcRef, ts: i64) -> Result<i64> {
        if let Some(st) = p.start_ts {
            let key = proc_key(p.pid, st);
            if let Some(id) = self.store.find_node(NodeKind::Process, &key)? {
                return Ok(id);
            }
        }
        if let Some(id) = self.store.latest_process_by_pid(p.pid, ts)? {
            // 재부팅 전 노드를 이번 부팅의 이벤트 주인으로 쓰지 않는다(PID 는 부팅마다 다시 쓰인다)
            if self.same_boot(id, ts)? {
                return Ok(id);
            }
        }
        // 스냅샷에도 ProcessStart 에도 없던 프로세스: 첫 등장 시각으로 키를 만든다 (경로 미확인)
        let key = proc_key(p.pid, ts);
        let label = self
            .image_by_pid
            .get(&p.pid)
            .cloned()
            // D014-3: 이름을 모르면 "pid 4" 가 아니라 화면에 그대로 쓸 수 있는 말로
            .unwrap_or_else(|| format!("알 수 없는 프로그램(PID {})", p.pid));
        let attrs = serde_json::json!({ "pid": p.pid, "preexisting": true, "unresolved": true })
            .to_string();
        self.store
            .upsert_node(NodeKind::Process, &key, &label, ts, Some(&attrs))
    }

    /// 시스템 서비스인가 (명세 5판 2-3): SCM 매핑 ∧ 서명자 Microsoft(알면) ∧ 시스템 토큰(알면).
    /// SCM 정보가 없는 오프라인 로그에서만 이미지 이름으로 추정.
    fn is_service(&self, pid: u32) -> bool {
        if self.scm_seen {
            let scm = self
                .services_by_pid
                .get(&pid)
                .map_or(false, |v| !v.is_empty());
            if !scm {
                return false;
            }
            if let Some(Some(false)) = self.system_token_by_pid.get(&pid) {
                return false;
            }
            if let Some(img) = self.image_path_by_pid(pid) {
                if let Some(signer) = self.signer_by_path.get(&img.to_ascii_lowercase()) {
                    return signer
                        .as_deref()
                        .map_or(false, |s| s.starts_with("Microsoft"));
                }
            }
            return true;
        }
        let label = match self.image_by_pid.get(&pid) {
            Some(img) => img.clone(),
            None => self
                .store
                .conn
                .query_row(
                    // L047: LIKE 는 색인을 못 쓴다 — 'pid@' ≤ key < 'pidA' 범위로
                    "SELECT COALESCE(label,'') FROM nodes WHERE kind='process' AND key >= ?1 AND key < ?2
                     ORDER BY first_ts DESC LIMIT 1",
                    rusqlite::params![format!("{pid}@"), format!("{pid}A")],
                    |r| r.get::<_, String>(0),
                )
                .unwrap_or_default(),
        };
        SERVICE_IMAGES_FALLBACK.contains(&label.to_ascii_lowercase().as_str())
    }
}

impl<'a> Ingester<'a> {
    /// PID 의 실행 파일 전체 경로 (노드 attrs 의 image)
    fn image_path_by_pid(&self, pid: u32) -> Option<String> {
        self.store
            .conn
            .query_row(
                "SELECT COALESCE(attrs_json,'') FROM nodes WHERE kind='process' AND key >= ?1 AND key < ?2 ORDER BY first_ts DESC LIMIT 1",
                rusqlite::params![format!("{pid}@"), format!("{pid}A")],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|a| serde_json::from_str::<serde_json::Value>(&a).ok())
            .and_then(|v| v.get("image").and_then(|i| i.as_str().map(|s| s.to_string())))
    }
}

fn is_dns_transport(proto: crate::event::Proto, rport: u16) -> bool {
    proto == crate::event::Proto::Udp && rport == 53
}

pub fn proc_key(pid: u32, start_ts: i64) -> String {
    format!("{pid}@{start_ts}")
}

pub fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// "::ffff:1.2.3.4" 같은 IPv4-mapped 표기를 "1.2.3.4" 로 정리
/// IP 표기 하나로: IPv4 매핑 IPv6(`::ffff:a.b.c.d`) → IPv4, IPv6 → 표준 축약형(RFC 5952, 소문자).
/// B2 실측: ETW 는 `ff02::1:3`, Sysmon·다른 원천은 `ff02:0:0:0:0:0:1:3` 처럼 펼쳐 써서 같은 주소가 둘로 갈렸다.
pub fn normalize_ip(s: &str) -> String {
    let s = s.trim();
    match s.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        Ok(ip) => ip.to_string(),
        Err(_) => s.strip_prefix("::ffff:").unwrap_or(s).to_string(),
    }
}

pub fn host_of(url: &str) -> String {
    let s = url.split("://").nth(1).unwrap_or(url);
    s.split('/').next().unwrap_or(s).to_string()
}

#[cfg(test)]
mod normalize_tests {
    #[test]
    fn ip_forms_converge() {
        use super::normalize_ip as n;
        assert_eq!(n("ff02:0:0:0:0:0:1:3"), "ff02::1:3");
        assert_eq!(n("FF02::1:3"), "ff02::1:3");
        assert_eq!(n("::ffff:1.2.3.4"), "1.2.3.4");
        assert_eq!(n(" 10.0.0.1 "), "10.0.0.1");
        assert_eq!(n("not-an-ip"), "not-an-ip");
    }
}
