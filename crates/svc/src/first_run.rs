//! 첫 실행 관찰실 (기획서 17판 23-2 ①)
//!
//! 대상: 인터넷에서 받은 표시(MOTW Zone 3·4)가 있고 서명이 없거나(None_)·신뢰되지 않거나(Untrusted)·깨진(Broken)
//! 실행 파일이 **이 PC 에서 처음** 실행된 때. "처음" = 같은 파일 노드에서 더 이른 실행 선(executed_as)이 없음.
//! (기준선 program_key 는 Zone 3·4·서명 없는 파일을 학습하지 않아 None 이 되므로 쓸 수 없다 — 그래프 실행 이력으로 본다.)
//!
//! 예외: 서명이 유효한 파일(Microsoft·Valid·스토어 패키지), 사용자가 "정상"으로 표시한 파일(feedback_normal),
//! 우리 제품 구성요소. 설치 프로그램 이름(setup·install)이라는 이유로 막기를 면제하지 않는다(L062, 30차 Q2).
//!
//! 판단 시점: 서명·출신(Zone)은 실행 뒤 따로 도착한다(WinVerifyTrust·Zone.Identifier 읽기). 그래서 ProcessStart 를
//! 대기 목록에 넣고, 수집 배치·틱마다 다시 본다. `PENDING_SECS` 안에 서명·출신이 오지 않으면 대상 아님으로 버린다.
//!
//! 기록: 관찰 한 건은 그래프 DB 의 `first_run_watch` 표(파일 경로 소문자 키, 같은 파일은 한 번만)와 서비스 사건
//! (`first_run_watch`, 대상 = 프로세스 {pid, create_ft, image}) 으로 남는다. 관찰 창 안에서 그 프로그램이 한 일은
//! 따로 모으지 않는다 — 이미 출처 그래프(이야기 사슬)에 있다.
//!
//! 문장은 사실만: "인터넷에서 받은 서명 없는 프로그램이 처음 실행됐습니다 · 10분 동안 관찰". 의도를 단정하지 않는다.

use std::collections::{HashMap, HashSet};

use graph::store::Store;
use graph::Node;
use judge::rules::{is_self_file, sig_of, zone_is_internet, Sig};
use serde::Serialize;

/// 서비스 사건·알림 종류
pub const KIND: &str = "first_run_watch";
/// 정책 기록(policy_history.actor)에 남는 행위자 — 자동 차단이 켜지면 이 이름으로 남는다
pub const ACTOR: &str = "system:first_run_watch";
/// 관찰실 정책 이름 접두(우산 `UMBRELLA_NAME`). 정책 화면이 "첫 실행 관찰실 정책"으로 알아본다
pub const POLICY_PREFIX: &str = "first-run-";
pub const DEFAULT_MINUTES: u32 = 10;
pub const MINUTES_CHOICES: [u32; 3] = [5, 10, 30];
/// 서명·출신 확인을 기다리는 최대 시간(초, 엔진 벽시각)
pub const PENDING_SECS: i64 = 120;
/// 대기 목록 상한 (프로세스 폭주 때 메모리 보호 — 넘치면 오래된 것부터 버린다)
pub const PENDING_CAP: usize = 512;
/// L065(30차 Q7-a): 우산 아래 동시에 걸린 기한부 필터 상한. 실행 파일 하나 = IPv4·IPv6 필터 2개라 프로그램 50개.
/// 서명 없는 파일을 수백 개 풀어 WFP 필터·엔진 장부를 채우는 공격을 막는다. 넘으면 알림만 하고 그 사실을 문장에 밝힌다
pub const UMBRELLA_FILTER_CAP: usize = 100;

/// 관찰실 우산 정책 이름 (방식 나, 사용자 결정 2026-11-06).
///
/// 불변식을 지키는 구조:
/// ① 새 정책은 관리자 요청에서만 — 관리자가 settings.set(또는 승인 도우미 경유 change.stage)으로 first_run_watch = "block" 을
///    고를 때, 그 요청의 request_id·행위자로 필터 없는 우산 정책 1건을 만든다(`engine::apply_umbrella`).
/// ② F19 — 우산은 일반 정책과 같이 Applied 로 시작해 60초 안에 사람이 확인해야 Confirmed 가 된다. 확인이 없으면 자동 롤백.
/// 엔진은 **Confirmed 우산 아래에서만** 대상 실행 파일마다 기한부(first_run_minutes) 경로 차단 필터를 더한다
/// (`engine::add_child_blocks`, 새 정책 아님). 우산이 없거나 확인 대기·되돌림·일시 중지·삭제 상태면 알림만 하고 그 사실을 문장에 밝힌다.
/// block → notify/off 로 바꾸면 같은 관리자 요청으로 우산을 지운다(그 아래 필터도 함께).
pub const UMBRELLA_NAME: &str = "first-run-watch";
/// 우산 정책의 원문 자리(필터 없음 — 정책 화면은 이 정책을 따로 요약한다)
pub const UMBRELLA_NOTE: &str = "# 첫 실행 관찰실 우산 정책: 인터넷에서 받은 서명 없는 프로그램이 처음 실행되면 관찰 시간 동안 그 실행 파일의 나가는 연결을 막는다\n";

pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS first_run_watch (
  file_key   TEXT PRIMARY KEY,   -- 실행 파일 경로 소문자 (같은 파일은 한 번만 관찰)
  file_node  INTEGER NOT NULL,
  proc_node  INTEGER NOT NULL,
  start_ts   INTEGER NOT NULL,   -- 첫 실행 시각 (unix 초)
  until_ts   INTEGER NOT NULL,   -- 관찰 끝 (unix 초)
  minutes    INTEGER NOT NULL,
  mode       TEXT NOT NULL,      -- notify | block (그때 설정)
  blocked    INTEGER NOT NULL,   -- 실제로 인터넷을 막았는가
  installer  INTEGER NOT NULL,
  sig        TEXT NOT NULL,      -- none | untrusted | broken
  host       TEXT                -- 받은 곳 (알 때만)
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Notify,
    Block,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "off" => Some(Mode::Off),
            "notify" => Some(Mode::Notify),
            "block" => Some(Mode::Block),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Notify => "notify",
            Mode::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub mode: Mode,
    pub minutes: u32,
}

/// 서비스 설정(world.settings)에서 읽는다. 모르는 값은 기본(notify, 10분) — api 검증이 먼저 막지만 옛 DB 값도 안전하게
pub fn settings_of(map: &HashMap<String, serde_json::Value>) -> Settings {
    let mode = map
        .get("first_run_watch")
        .and_then(|v| v.as_str())
        .and_then(Mode::parse)
        .unwrap_or(Mode::Notify);
    let minutes = map
        .get("first_run_minutes")
        .and_then(|v| v.as_u64())
        .map(|m| m as u32)
        .filter(|m| MINUTES_CHOICES.contains(m))
        .unwrap_or(DEFAULT_MINUTES);
    Settings { mode, minutes }
}

/// 서명 상태의 사실 말
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SigFact {
    None,
    Untrusted,
    Broken,
    /// L062(30차 Q5): 보류 시간 안에 서명 확인 결과가 오지 않음(실행 직후 파일 삭제 등) — 모르는 것을 안전으로 보지 않는다
    Unknown,
}

impl SigFact {
    pub fn as_str(self) -> &'static str {
        match self {
            SigFact::None => "none",
            SigFact::Untrusted => "untrusted",
            SigFact::Broken => "broken",
            SigFact::Unknown => "unknown",
        }
    }
    fn of_str(s: &str) -> SigFact {
        match s {
            "untrusted" => SigFact::Untrusted,
            "broken" => SigFact::Broken,
            "unknown" => SigFact::Unknown,
            _ => SigFact::None,
        }
    }
    /// "서명 없는" 등 — 문장 앞부분
    fn phrase(self) -> &'static str {
        match self {
            SigFact::None => "서명 없는",
            SigFact::Untrusted => "신뢰할 수 없는 서명의",
            SigFact::Broken => "서명과 내용이 맞지 않는",
            SigFact::Unknown => "서명을 확인하지 못한",
        }
    }
}

/// 관찰 대상 한 건
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Target {
    pub proc_node: i64,
    pub file_node: i64,
    pub path: String,
    pub pid: u32,
    /// 프로세스 생성 시각(FILETIME) — 서비스 사건 대상 {pid, create_ft} 가 그래프 프로세스 키와 같은 형식이 되게
    pub create_ft: i64,
    /// 첫 실행 시각(unix 초)
    pub start_ts: i64,
    pub host: Option<String>,
    pub installer: bool,
    pub sig: SigFact,
    /// 프로세스 로그온 세션 (A30: 다른 사용자 세션이면 일반 사용자에게 경로를 감춘다)
    pub session: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Assess {
    /// 서명·출신·프로세스 노드를 아직 모른다 — 다시 본다
    Pending,
    /// 대상 아님 (이유)
    Skip(&'static str),
    Target(Box<Target>),
}

fn filetime_to_unix(ft: i64) -> i64 {
    ft / 10_000_000 - 11_644_473_600
}

/// 프로세스 노드 하나를 판단한다. `feedback` = 기준선의 정상 표시 키(judge::baseline::root_key)
pub fn assess(g: &Store, feedback: &HashSet<String>, proc_node: i64) -> Assess {
    assess_with(g, feedback, proc_node, false)
}

/// 보류 시간이 지난 마지막 판단(L062, 30차 Q5): 인터넷에서 받은 파일인데 서명 확인 결과가 끝내 없으면 "서명을 확인하지 못한" 대상으로 본다
pub fn assess_at_expiry(g: &Store, feedback: &HashSet<String>, proc_node: i64) -> Assess {
    assess_with(g, feedback, proc_node, true)
}

fn assess_with(g: &Store, feedback: &HashSet<String>, proc_node: i64, expired: bool) -> Assess {
    let Ok(p) = g.node(proc_node) else {
        return Assess::Pending;
    };
    if p.kind != "process" {
        return Assess::Skip("프로세스 아님");
    }
    // 수집 시작 때 이미 실행 중이던 프로세스(스냅샷)는 "처음 실행"인지 알 수 없다
    if p.attr("preexisting").and_then(|v| v.as_bool()) == Some(true) {
        return Assess::Skip("수집 전부터 실행 중");
    }
    let Ok(ins) = g.edges_to(proc_node) else {
        return Assess::Pending;
    };
    let Some(exec) = ins.iter().find(|e| e.rel == "executed_as") else {
        return Assess::Skip("실행 파일 모름");
    };
    let Ok(file) = g.node(exec.src) else {
        return Assess::Pending;
    };
    assess_file(g, feedback, &p, &file, exec.ts, expired)
}

fn assess_file(
    g: &Store,
    feedback: &HashSet<String>,
    p: &Node,
    file: &Node,
    exec_ts: i64,
    expired: bool,
) -> Assess {
    if is_self_file(file) {
        return Assess::Skip("제품 구성요소");
    }
    let sig = match sig_of(file) {
        // 출신 표시가 인터넷이면 마지막 판단에서는 대상으로(모르는 것 ≠ 안전)
        None if expired && zone_is_internet(file) => SigFact::Unknown,
        None => return Assess::Pending,
        Some(Sig::Microsoft | Sig::Valid | Sig::Package) => return Assess::Skip("서명 유효"),
        Some(Sig::None_) => SigFact::None,
        Some(Sig::Untrusted) => SigFact::Untrusted,
        Some(Sig::Broken) => SigFact::Broken,
    };
    if !zone_is_internet(file) {
        // 출신 표시는 서명보다 늦게 올 수 있다 — 표시가 아직 없으면 기다린다(시간이 지나면 대기 목록에서 버린다)
        if file.attr("zone_id").is_none() {
            return Assess::Pending;
        }
        return Assess::Skip("인터넷에서 받은 표시 없음");
    }
    if feedback.contains(&judge::baseline::root_key(file)) {
        return Assess::Skip("사용자가 정상으로 표시");
    }
    // 처음 실행인가: 같은 파일에서 더 이른 실행 선이 있으면 아니다
    let earlier: i64 = g
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE src = ?1 AND rel = 'executed_as' AND dst != ?2
               AND (ts < ?3 OR (ts = ?3 AND dst < ?2))",
            rusqlite::params![file.id, p.id, exec_ts],
            |r| r.get(0),
        )
        .unwrap_or(1);
    if earlier > 0 {
        return Assess::Skip("전에 실행된 적 있음");
    }
    let host = file
        .attr("host_url")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .map(|u| graph::ingest::host_of(&u))
        .filter(|h| !h.is_empty());
    let pid = p.attr("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let create_ft = p
        .key
        .rsplit_once('@')
        .and_then(|(_, t)| t.parse().ok())
        .unwrap_or(exec_ts);
    Assess::Target(Box::new(Target {
        proc_node: p.id,
        file_node: file.id,
        path: file.key.clone(),
        pid,
        create_ft,
        start_ts: filetime_to_unix(exec_ts),
        host,
        installer: graph::install::is_installer_image(&file.key),
        sig,
        session: p.attr("session").and_then(|v| v.as_u64()),
    }))
}

/// 이야기 카드·사건 문장 (사실만). `blocked` = 실제로 나가는 연결을 막았을 때만 "(나가는 연결 차단)"
pub fn story_line(sig: SigFact, installer: bool, minutes: u32, blocked: bool) -> String {
    let what = if installer {
        "설치 프로그램"
    } else {
        "프로그램"
    };
    format!(
        "인터넷에서 받은 {} {what}이 처음 실행됐습니다 · {minutes}분 동안 관찰{}",
        sig.phrase(),
        if blocked {
            "(나가는 연결 차단)"
        } else {
            ""
        }
    )
}

/// 표가 없으면 만든다 (엔진 시작 때 한 번)
pub fn ensure_table(g: &Store) {
    let _ = g.conn().execute_batch(DDL);
}

/// 이 파일을 이미 관찰했는가
pub fn already_watched(g: &Store, path: &str) -> bool {
    g.conn()
        .query_row(
            "SELECT 1 FROM first_run_watch WHERE file_key = ?1",
            [path.to_ascii_lowercase()],
            |_| Ok(()),
        )
        .is_ok()
}

/// 관찰 기록 (이야기 카드용)
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Watch {
    pub start_ts: i64,
    pub until_ts: i64,
    pub minutes: u32,
    pub mode: String,
    pub blocked: bool,
    pub installer: bool,
    pub host: Option<String>,
    pub text: String,
}

/// 파일 경로로 관찰 기록 찾기 (표가 없거나 없으면 None)
pub fn watch_of(g: &Store, path: &str) -> Option<Watch> {
    g.conn()
        .query_row(
            "SELECT start_ts, until_ts, minutes, mode, blocked, installer, sig, host FROM first_run_watch WHERE file_key = ?1",
            [path.to_ascii_lowercase()],
            |r| {
                let minutes: i64 = r.get(2)?;
                let blocked: i64 = r.get(4)?;
                let installer: i64 = r.get(5)?;
                let sig: String = r.get(6)?;
                Ok(Watch {
                    start_ts: r.get(0)?,
                    until_ts: r.get(1)?,
                    minutes: minutes as u32,
                    mode: r.get(3)?,
                    blocked: blocked != 0,
                    installer: installer != 0,
                    host: r.get(7)?,
                    text: story_line(SigFact::of_str(&sig), installer != 0, minutes as u32, blocked != 0),
                })
            },
        )
        .ok()
}

fn record_watch(g: &Store, t: &Target, s: Settings, blocked: bool) -> bool {
    g.conn()
        .execute(
            "INSERT OR IGNORE INTO first_run_watch(file_key, file_node, proc_node, start_ts, until_ts, minutes, mode, blocked, installer, sig, host)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                t.path.to_ascii_lowercase(),
                t.file_node,
                t.proc_node,
                t.start_ts,
                t.start_ts + s.minutes as i64 * 60,
                s.minutes,
                s.mode.as_str(),
                blocked as i64,
                t.installer as i64,
                t.sig.as_str(),
                t.host
            ],
        )
        .map(|n| n == 1)
        .unwrap_or(false)
}

/// 우산 정책 행 (지운 것 제외, 가장 최근 상태). 없으면 None
pub fn umbrella(store: &engine::EngineStore) -> Option<engine::PolicyRow> {
    for st in [
        engine::State::Confirmed,
        engine::State::Applied,
        engine::State::Paused,
        engine::State::RolledBack,
        engine::State::Expired,
    ] {
        if let Some(r) = store
            .policies_in(st)
            .ok()?
            .into_iter()
            .find(|r| r.name == UMBRELLA_NAME)
        {
            return Some(r);
        }
    }
    None
}

/// 설정 저장(관리자 요청) 때 우산을 맞춘다. `new_mode` = 이 요청이 정하는 모드(요청에 first_run_watch 가 있을 때만 부른다).
/// block: 확인 대기·확인된 우산이 없으면 새로(또는 새 판으로) 적용해 그 결과를 돌려준다 — 60초 확인은 부르는 쪽(UI·승인 도우미)이 한다.
/// 그 밖: 남아 있는 우산(확인 대기·확인·일시 중지)을 지운다. 그 아래 기한부 필터도 함께 내려간다.
pub fn sync_umbrella(
    engine: &mut engine::Engine,
    new_mode: Mode,
    request_id: &str,
    actor: &str,
) -> engine::Result<Option<engine::ApplyResult>> {
    let cur = umbrella(&engine.store);
    let live = |r: &engine::PolicyRow| {
        matches!(
            r.state,
            engine::State::Applied | engine::State::Confirmed | engine::State::Paused
        )
    };
    if new_mode == Mode::Block {
        if cur
            .as_ref()
            .is_some_and(|r| matches!(r.state, engine::State::Applied | engine::State::Confirmed))
        {
            return Ok(None);
        }
        return engine
            .apply_umbrella(UMBRELLA_NAME, UMBRELLA_NOTE, request_id, actor)
            .map(Some);
    }
    if let Some(r) = cur.filter(live) {
        engine.remove(r.id, actor)?;
    }
    Ok(None)
}

/// 대상 실행 파일을 확인된 우산 아래에서 `until`(unix 초)까지 막는다. 막지 않으면 그 까닭(사실 문장)을 돌려준다.
/// 설치 프로그램·시스템 핵심 프로세스는 여기서, 우리 자신·보호 목록·RDP 등은 엔진 가드가 거부한다.
pub fn try_block(
    engine: &mut engine::Engine,
    t: &Target,
    until: i64,
) -> Result<(i64, Vec<u64>), String> {
    // L062(30차 Q2): 이름(setup·install)만으로 막기를 면제하지 않는다. 대상은 이미 서명 없음·깨짐·신뢰 체인 없음이므로
    // 서명된 설치 프로그램은 애초에 대상이 아니다. 서명 없는 "설치 프로그램"도 같이 막는다
    if graph::views::is_system_image(&t.path) || dsl::validate::is_system_image(&t.path) {
        return Err("시스템 핵심 프로세스는 막지 않고 알림만 했습니다".into());
    }
    let Some(u) = umbrella(&engine.store).filter(|r| r.state == engine::State::Confirmed) else {
        return Err("관찰실 차단 정책이 확인된 상태가 아니어서 막지 않고 알림만 했습니다".into());
    };
    let live = engine
        .store
        .filters_of(u.id)
        .map_err(|e| format!("막지 못해 알림만 했습니다 ({e})"))?;
    if live.len() + 2 > UMBRELLA_FILTER_CAP {
        return Err(format!(
            "관찰실이 동시에 막을 수 있는 수(프로그램 {}개)에 닿아 막지 않고 알림만 했습니다",
            UMBRELLA_FILTER_CAP / 2
        ));
    }
    let base = t.path.rsplit(['\\', '/']).next().unwrap_or(&t.path);
    let spec = policy::spec::BlockSpec::app(
        &format!("{UMBRELLA_NAME}: {base}"),
        &t.path,
        policy::spec::Direction::Out,
    );
    match engine.add_child_blocks(
        u.id,
        &[spec],
        until,
        ACTOR,
        &format!("path {} (process node {})", t.path, t.proc_node),
    ) {
        Ok(ids) => Ok((u.id, ids)),
        Err(engine::EngineError::Guard(m)) => {
            Err(format!("보호 규칙에 걸려 막지 않고 알림만 했습니다 ({m})"))
        }
        Err(e) => Err(format!("막지 못해 알림만 했습니다 ({e})")),
    }
}

/// 수집 배치의 ProcessStart 를 대기 목록에 넣고 한 번 훑는다
pub fn on_batch(world: &mut crate::runtime::World, events: &[graph::Event]) {
    let s = settings_of(&world.settings);
    if s.mode == Mode::Off {
        world.first_run_pending.clear();
        return;
    }
    let now = world.engine_wall();
    let mut added = false;
    for ev in events {
        if let graph::event::EventKind::ProcessStart {
            pid, create_time, ..
        } = &ev.kind
        {
            let key = graph::ingest::proc_key(*pid, create_time.unwrap_or(ev.ts));
            world.first_run_pending.push((key, now));
            added = true;
        }
    }
    let n = world.first_run_pending.len();
    if n > PENDING_CAP {
        world.first_run_pending.drain(..n - PENDING_CAP);
    }
    // 서명·출신 이벤트만 온 배치도 대기 중인 것을 다시 본다
    if added || !world.first_run_pending.is_empty() {
        sweep(world);
    }
}

/// 대기 목록을 다시 본다 (배치·틱). 정해진 것은 빼고, 오래 기다린 것은 버린다
pub fn sweep(world: &mut crate::runtime::World) {
    if world.first_run_pending.is_empty() {
        return;
    }
    let s = settings_of(&world.settings);
    if s.mode == Mode::Off {
        world.first_run_pending.clear();
        return;
    }
    let now = world.engine_wall();
    let feedback = world
        .baseline
        .feedback_keys(&world.graph)
        .unwrap_or_default();
    let pending = std::mem::take(&mut world.first_run_pending);
    let mut keep = Vec::new();
    let mut found = Vec::new();
    for (key, seen) in pending {
        let node = world
            .graph
            .find_node(graph::NodeKind::Process, &key)
            .ok()
            .flatten();
        let expired = now - seen >= PENDING_SECS;
        let a = match node {
            Some(id) if expired => assess_at_expiry(&world.graph, &feedback, id),
            Some(id) => assess(&world.graph, &feedback, id),
            None => Assess::Pending,
        };
        match a {
            Assess::Pending if !expired => keep.push((key, seen)),
            Assess::Target(t) => found.push(*t),
            _ => {}
        }
    }
    world.first_run_pending = keep;
    for t in found {
        start_watch(world, &t, s);
    }
}

/// 관찰 시작: 기록(같은 파일은 한 번만) + 서비스 사건(알림 대기열 경유)
fn start_watch(world: &mut crate::runtime::World, t: &Target, s: Settings) {
    if already_watched(&world.graph, &t.path) {
        return;
    }
    let until = t.start_ts + s.minutes as i64 * 60;
    // block 모드: 확인된 우산 아래에서만 막는다. 실제로 막지 않았으면 "(나가는 연결 차단)"이라고 쓰지 않는다
    let (blocked, umbrella_id, why_not) = if s.mode == Mode::Block {
        match try_block(&mut world.engine, t, until) {
            Ok((uid, _)) => (true, Some(uid), None),
            Err(why) => (false, None, Some(why)),
        }
    } else {
        (false, None, None)
    };
    if !record_watch(&world.graph, t, s, blocked) {
        return;
    }
    let mut detail = format!(
        "{}: {}",
        story_line(t.sig, t.installer, s.minutes, blocked),
        t.path
    );
    if let Some(h) = &t.host {
        detail.push_str(&format!(" (받은 곳 {h})"));
    }
    if let Some(w) = why_not {
        detail.push_str(&format!(" — {w}"));
    }
    let target = serde_json::json!({
        "type": "process", "pid": t.pid, "create_ft": t.create_ft, "image": t.path, "session": t.session,
        "origin_host": t.host, "start_ts": t.start_ts, "until_ts": until, "minutes": s.minutes,
        "mode": s.mode.as_str(), "blocked": blocked, "installer": t.installer,
        "umbrella_policy_id": umbrella_id,
    });
    let _ = world
        .engine
        .record_event_ref(KIND, 1, detail, Some(target.to_string()));
    // 이야기 카드에 관찰 줄이 바로 보이게
    world.judged = None;
    world.judge_cache = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_defaults_and_bad_values() {
        let mut m = HashMap::new();
        assert_eq!(
            settings_of(&m),
            Settings {
                mode: Mode::Notify,
                minutes: 10
            }
        );
        m.insert("first_run_watch".into(), serde_json::json!("block"));
        m.insert("first_run_minutes".into(), serde_json::json!(30));
        assert_eq!(
            settings_of(&m),
            Settings {
                mode: Mode::Block,
                minutes: 30
            }
        );
        m.insert("first_run_watch".into(), serde_json::json!("weird"));
        m.insert("first_run_minutes".into(), serde_json::json!(7));
        assert_eq!(
            settings_of(&m),
            Settings {
                mode: Mode::Notify,
                minutes: 10
            }
        );
    }

    #[test]
    fn story_line_is_facts_only() {
        let s = story_line(SigFact::None, false, 10, false);
        assert_eq!(
            s,
            "인터넷에서 받은 서명 없는 프로그램이 처음 실행됐습니다 · 10분 동안 관찰"
        );
        assert!(story_line(SigFact::None, false, 10, true)
            .ends_with("10분 동안 관찰(나가는 연결 차단)"));
        assert!(story_line(SigFact::Broken, true, 5, false)
            .contains("서명과 내용이 맞지 않는 설치 프로그램"));
        for f in story::render::FORBIDDEN {
            assert!(!s.contains(f), "{f}");
        }
    }
}
