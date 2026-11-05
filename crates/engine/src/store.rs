//! 정책 엔진 저장 (명세 2판 정책 표 + 10차 2-1): policies, policy_versions, wfp_filters, policy_history, events, idempotency

use policy::spec::BlockSpec;
use rusqlite::{params, Connection, OptionalExtension};

use crate::{ApplyResult, Result, Schedule};

/// 저장된 서비스 사건 (A29)
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredEvent {
    pub id: i64,
    /// UTC unix 초
    pub ts: i64,
    pub kind: String,
    pub severity: u8,
    pub detail: String,
    pub ref_json: Option<String>,
}

pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, yaml TEXT NOT NULL, state TEXT NOT NULL,
  version INTEGER NOT NULL, schedule_json TEXT, confirm_deadline INTEGER, created INTEGER NOT NULL, actor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_versions (
  policy_id INTEGER NOT NULL, version INTEGER NOT NULL, yaml TEXT NOT NULL, specs_json TEXT NOT NULL,
  schedule_json TEXT, ts INTEGER NOT NULL, PRIMARY KEY(policy_id, version)
);
CREATE TABLE IF NOT EXISTS wfp_filters (
  filter_id INTEGER PRIMARY KEY, policy_id INTEGER NOT NULL, version INTEGER NOT NULL,
  spec_json TEXT NOT NULL, expires_at INTEGER
);
CREATE TABLE IF NOT EXISTS policy_history (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, policy_id INTEGER NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, result TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, severity INTEGER NOT NULL, detail TEXT
);
-- 사건이 가리키는 대상 (A29): 프로세스 {pid, create_ft, image} 등. 사건 표를 바꾸지 않으려고 따로 둔다
CREATE TABLE IF NOT EXISTS event_refs (
  event_id INTEGER PRIMARY KEY, ref_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
  request_id TEXT PRIMARY KEY, result_json TEXT NOT NULL, ts INTEGER NOT NULL
);
-- 열린 조건(틈 메우기 인덱스)을 판별로 저장한다 (A19). 재시작·판 되돌리기 때 다시 전개하지 않고 여기서 복원한다:
-- descendants_of 의 뿌리 파일이 격리·삭제되면 재전개가 실패해 틈 메우기가 조용히 사라지기 때문.
CREATE TABLE IF NOT EXISTS open_conds (
  policy_id INTEGER NOT NULL, version INTEGER NOT NULL, cond_json TEXT NOT NULL, PRIMARY KEY(policy_id, version)
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum State {
    Applied,
    Confirmed,
    RolledBack,
    Expired,
    Paused,
    Removed,
}
impl State {
    fn as_str(self) -> &'static str {
        match self {
            State::Applied => "applied",
            State::Confirmed => "confirmed",
            State::RolledBack => "rolled_back",
            State::Expired => "expired",
            State::Paused => "paused",
            State::Removed => "removed",
        }
    }
    fn parse(s: &str) -> State {
        match s {
            "applied" => State::Applied,
            "confirmed" => State::Confirmed,
            "rolled_back" => State::RolledBack,
            "expired" => State::Expired,
            "paused" => State::Paused,
            _ => State::Removed,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub id: i64,
    pub name: String,
    pub yaml: String,
    pub state: State,
    pub version: i64,
    pub schedule: Option<Schedule>,
    pub confirm_deadline: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct FilterRow {
    pub filter_id: u64,
    pub policy_id: i64,
    pub version: i64,
    pub spec: BlockSpec,
    pub expires_at: Option<i64>,
}

pub struct EngineStore {
    pub conn: Connection,
}

impl EngineStore {
    pub fn new(conn: Connection) -> Result<Self> {
        conn.execute_batch(DDL)?;
        // 28차 Q2 후속: WFP filterId 는 "runtime identifier"(문서)라 BFE 재시작·재부팅 뒤 바뀔 수 있다(추측).
        // 우리가 대조할 수 있는 고정 값은 filterKey(GUID) — 예전 DB 에는 열이 없으므로 더한다
        let has_key: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('wfp_filters') WHERE name = 'filter_key'")?
            .exists([])?;
        if !has_key {
            conn.execute_batch("ALTER TABLE wfp_filters ADD COLUMN filter_key TEXT")?;
        }
        Ok(Self { conn })
    }

    /// 같은 이름의 정책이 있으면 버전을 올리고, 없으면 새로 만든다. (정책 행 + 버전 행)
    pub fn new_version(&self, name: &str, yaml: &str, specs: &[BlockSpec], schedule: Option<&Schedule>, ts: i64, actor: &str) -> Result<(i64, i64)> {
        let sj = schedule.map(|s| serde_json::to_string(s).unwrap());
        let existing: Option<(i64, i64)> = self.conn.query_row("SELECT id, version FROM policies WHERE name = ?1 AND state NOT IN ('removed')", [name], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let (id, version) = match existing {
            Some((id, v)) => {
                self.conn.execute("UPDATE policies SET yaml = ?1, version = ?2, schedule_json = ?3 WHERE id = ?4", params![yaml, v + 1, sj, id])?;
                (id, v + 1)
            }
            None => {
                self.conn.execute(
                    "INSERT INTO policies(name, yaml, state, version, schedule_json, created, actor) VALUES (?1, ?2, 'applied', 1, ?3, ?4, ?5)",
                    params![name, yaml, sj, ts, actor],
                )?;
                (self.conn.last_insert_rowid(), 1)
            }
        };
        self.conn.execute(
            "INSERT INTO policy_versions(policy_id, version, yaml, specs_json, schedule_json, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, version, yaml, serde_json::to_string(specs).unwrap(), sj, ts],
        )?;
        Ok((id, version))
    }

    pub fn set_state(&self, id: i64, state: State, confirm_deadline: Option<i64>) -> Result<()> {
        self.conn.execute("UPDATE policies SET state = ?1, confirm_deadline = ?2 WHERE id = ?3", params![state.as_str(), confirm_deadline, id])?;
        Ok(())
    }
    pub fn set_version(&self, id: i64, version: i64) -> Result<()> {
        let (yaml, sj): (String, Option<String>) = self.conn.query_row("SELECT yaml, schedule_json FROM policy_versions WHERE policy_id = ?1 AND version = ?2", params![id, version], |r| Ok((r.get(0)?, r.get(1)?)))?;
        self.conn.execute("UPDATE policies SET version = ?1, yaml = ?2, schedule_json = ?3 WHERE id = ?4", params![version, yaml, sj, id])?;
        Ok(())
    }

    fn row_to_policy(r: &rusqlite::Row) -> rusqlite::Result<PolicyRow> {
        let sj: Option<String> = r.get(5)?;
        Ok(PolicyRow {
            id: r.get(0)?,
            name: r.get(1)?,
            yaml: r.get(2)?,
            state: State::parse(&r.get::<_, String>(3)?),
            version: r.get(4)?,
            schedule: sj.and_then(|s| serde_json::from_str(&s).ok()),
            confirm_deadline: r.get(6)?,
        })
    }
    const POLICY_COLS: &'static str = "id, name, yaml, state, version, schedule_json, confirm_deadline";

    pub fn policy(&self, id: i64) -> Result<Option<PolicyRow>> {
        Ok(self.conn.query_row(&format!("SELECT {} FROM policies WHERE id = ?1", Self::POLICY_COLS), [id], Self::row_to_policy).optional()?)
    }
    pub fn policies_in(&self, state: State) -> Result<Vec<PolicyRow>> {
        let mut st = self.conn.prepare(&format!("SELECT {} FROM policies WHERE state = ?1 ORDER BY id", Self::POLICY_COLS))?;
        let rows = st.query_map([state.as_str()], Self::row_to_policy)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
    pub fn version_specs(&self, id: i64, version: i64) -> Result<Option<Vec<BlockSpec>>> {
        let s: Option<String> = self.conn.query_row("SELECT specs_json FROM policy_versions WHERE policy_id = ?1 AND version = ?2", params![id, version], |r| r.get(0)).optional()?;
        Ok(s.and_then(|j| serde_json::from_str(&j).ok()))
    }

    pub fn version_ts(&self, id: i64, version: i64) -> Result<Option<i64>> {
        Ok(self.conn.query_row("SELECT ts FROM policy_versions WHERE policy_id = ?1 AND version = ?2", params![id, version], |r| r.get(0)).optional()?)
    }
    pub fn insert_filter_tx(tx: &rusqlite::Transaction, filter_id: u64, policy_id: i64, version: i64, spec: &BlockSpec, expires_at: Option<i64>) -> Result<()> {
        tx.execute(
            "INSERT OR REPLACE INTO wfp_filters(filter_id, policy_id, version, spec_json, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![filter_id as i64, policy_id, version, serde_json::to_string(spec).unwrap(), expires_at],
        )?;
        Ok(())
    }
    fn row_to_filter(r: &rusqlite::Row) -> rusqlite::Result<FilterRow> {
        let sj: String = r.get(3)?;
        Ok(FilterRow { filter_id: r.get::<_, i64>(0)? as u64, policy_id: r.get(1)?, version: r.get(2)?, spec: serde_json::from_str(&sj).unwrap(), expires_at: r.get(4)? })
    }
    pub fn filters_of(&self, policy_id: i64) -> Result<Vec<FilterRow>> {
        let mut st = self.conn.prepare("SELECT filter_id, policy_id, version, spec_json, expires_at FROM wfp_filters WHERE policy_id = ?1 ORDER BY filter_id")?;
        let rows = st.query_map([policy_id], Self::row_to_filter)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
    pub fn all_filters(&self) -> Result<Vec<FilterRow>> {
        let mut st = self.conn.prepare("SELECT filter_id, policy_id, version, spec_json, expires_at FROM wfp_filters ORDER BY filter_id")?;
        let rows = st.query_map([], Self::row_to_filter)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
    pub fn filter(&self, filter_id: u64) -> Result<Option<FilterRow>> {
        Ok(self.conn.query_row("SELECT filter_id, policy_id, version, spec_json, expires_at FROM wfp_filters WHERE filter_id = ?1", [filter_id as i64], Self::row_to_filter).optional()?)
    }
    pub fn filter_count(&self, policy_id: i64) -> Result<usize> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM wfp_filters WHERE policy_id = ?1", [policy_id], |r| r.get(0))?;
        Ok(n as usize)
    }
    /// 이 정책에 같은 앱 경로의 필터가 이미 있는가 (spec_json 의 app_path 비교, 대소문자 무시)
    pub fn has_app(&self, policy_id: i64, image: &str) -> Result<bool> {
        let needle = serde_json::to_string(image).unwrap().to_ascii_lowercase();
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM wfp_filters WHERE policy_id = ?1 AND instr(lower(spec_json), ?2) > 0",
            params![policy_id, needle],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }
    pub fn filters_expired(&self, now: i64) -> Result<Vec<FilterRow>> {
        let mut st = self.conn.prepare("SELECT filter_id, policy_id, version, spec_json, expires_at FROM wfp_filters WHERE expires_at IS NOT NULL AND expires_at <= ?1")?;
        let rows = st.query_map([now], Self::row_to_filter)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
    /// 필터 키(filterKey GUID) 기록 — 없을 때만(이미 있으면 그대로)
    pub fn set_filter_key(&self, id: u64, key: &str) -> Result<()> {
        self.conn.execute("UPDATE wfp_filters SET filter_key = ?2 WHERE filter_id = ?1 AND filter_key IS NULL", params![id as i64, key])?;
        Ok(())
    }
    /// 키 → DB 의 필터 번호
    pub fn filter_ids_by_key(&self) -> Result<std::collections::HashMap<String, u64>> {
        let mut st = self.conn.prepare("SELECT filter_key, filter_id FROM wfp_filters WHERE filter_key IS NOT NULL")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
    /// 같은 필터(같은 키)의 번호가 바뀌었을 때 DB 번호만 고친다
    pub fn renumber_filter(&self, old: u64, new: u64) -> Result<()> {
        self.conn.execute("UPDATE wfp_filters SET filter_id = ?2 WHERE filter_id = ?1", params![old as i64, new as i64])?;
        Ok(())
    }

    pub fn delete_filters(&self, ids: &[u64]) -> Result<()> {
        for id in ids {
            self.conn.execute("DELETE FROM wfp_filters WHERE filter_id = ?1", [*id as i64])?;
        }
        Ok(())
    }

    pub fn history(&self, ts: i64, policy_id: i64, action: &str, actor: &str, result: &str) -> Result<()> {
        self.conn.execute("INSERT INTO policy_history(ts, policy_id, action, actor, result) VALUES (?1, ?2, ?3, ?4, ?5)", params![ts, policy_id, action, actor, result])?;
        Ok(())
    }
    /// (시각, 동작, 결과, 누가) — 누가 = 호출자 PID·이미지 (승인 도우미 경유면 승인한 쪽 + 맡긴 쪽)
    pub fn history_of(&self, policy_id: i64) -> Result<Vec<(i64, String, String, String)>> {
        let mut st = self.conn.prepare("SELECT ts, action, result, actor FROM policy_history WHERE policy_id = ?1 ORDER BY id")?;
        let rows = st.query_map([policy_id], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<String>>(2)?.unwrap_or_default(), r.get(3)?)))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
    /// 12차 Q6: 감사 기록은 개념상 영구지만 물리 상한을 둔다. 정책 변경 API 를 수만 번 호출해 디스크를 채우는 것을 막는다.
    /// - events: 90일 지난 행 삭제 + 최대 200,000행
    /// - policy_history: 최대 100,000행 (오래된 것부터)
    /// - policy_versions: 정책당 최근 50판 (현재 판·필터가 가리키는 판은 남김)
    /// - idempotency: 7일
    pub fn enforce_caps(&self, now: i64) -> Result<usize> {
        let mut n = 0;
        n += self.conn.execute("DELETE FROM events WHERE ts < ?1", [now - 90 * 86_400])?;
        n += self.conn.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 200000)", [])?;
        n += self.conn.execute("DELETE FROM policy_history WHERE id NOT IN (SELECT id FROM policy_history ORDER BY id DESC LIMIT 100000)", [])?;
        n += self.conn.execute(
            "DELETE FROM policy_versions WHERE rowid IN (
               SELECT v.rowid FROM policy_versions v
               WHERE v.version NOT IN (SELECT version FROM policy_versions w WHERE w.policy_id = v.policy_id ORDER BY version DESC LIMIT 50)
                 AND v.version <> (SELECT version FROM policies p WHERE p.id = v.policy_id)
                 AND NOT EXISTS (SELECT 1 FROM wfp_filters f WHERE f.policy_id = v.policy_id AND f.version = v.version))",
            [],
        )?;
        n += self.conn.execute("DELETE FROM idempotency WHERE ts > 0 AND ts < ?1", [now - 7 * 86_400])?;
        Ok(n)
    }
    /// 반환: 사건 id
    pub fn insert_event(&self, ts: i64, kind: &str, severity: u8, detail: &str) -> Result<i64> {
        self.conn.execute("INSERT INTO events(ts, kind, severity, detail) VALUES (?1, ?2, ?3, ?4)", params![ts, kind, severity as i64, detail])?;
        Ok(self.conn.last_insert_rowid())
    }
    pub fn set_event_ref(&self, event_id: i64, ref_json: &str) -> Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO event_refs(event_id, ref_json) VALUES (?1, ?2)", params![event_id, ref_json])?;
        Ok(())
    }
    /// 서비스 사건 목록 (A29): `since` 이후, 새것부터 `limit` 건
    pub fn list_events(&self, since: i64, limit: usize) -> Result<Vec<StoredEvent>> {
        let mut st = self.conn.prepare(
            "SELECT e.id, e.ts, e.kind, e.severity, e.detail, r.ref_json FROM events e LEFT JOIN event_refs r ON r.event_id = e.id
             WHERE e.ts >= ?1 ORDER BY e.id DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![since, limit as i64], |r| {
            Ok(StoredEvent { id: r.get(0)?, ts: r.get(1)?, kind: r.get(2)?, severity: r.get::<_, i64>(3)? as u8, detail: r.get::<_, Option<String>>(4)?.unwrap_or_default(), ref_json: r.get(5)? })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn save_open_cond(&self, policy_id: i64, version: i64, cond_json: &str) -> Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO open_conds(policy_id, version, cond_json) VALUES (?1, ?2, ?3)", rusqlite::params![policy_id, version, cond_json])?;
        Ok(())
    }
    pub fn open_cond(&self, policy_id: i64, version: i64) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        Ok(self.conn.query_row("SELECT cond_json FROM open_conds WHERE policy_id = ?1 AND version = ?2", rusqlite::params![policy_id, version], |r| r.get(0)).optional()?)
    }
    pub fn delete_open_conds(&self, policy_id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM open_conds WHERE policy_id = ?1", rusqlite::params![policy_id])?;
        Ok(())
    }

    pub fn idempotent_lookup(&self, request_id: &str) -> Result<Option<ApplyResult>> {
        let s: Option<String> = self.conn.query_row("SELECT result_json FROM idempotency WHERE request_id = ?1", [request_id], |r| r.get(0)).optional()?;
        Ok(s.and_then(|j| serde_json::from_str(&j).ok()))
    }
    pub fn idempotent_save(&self, request_id: &str, result: &ApplyResult) -> Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO idempotency(request_id, result_json, ts) VALUES (?1, ?2, ?3)", params![request_id, serde_json::to_string(result).unwrap(), result.confirm_deadline])?;
        Ok(())
    }
}
