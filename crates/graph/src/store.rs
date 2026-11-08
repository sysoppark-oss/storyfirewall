//! SQLite 저장소: 연결, 스키마 적용, 노드·선 upsert

use crate::schema::{DDL, SCHEMA_VERSION};
use crate::{Edge, GraphError, Node, NodeKind, Rel, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub struct Store {
    pub(crate) conn: Connection,
}

impl Store {
    /// 파일 DB 를 연다. 없으면 만들고 스키마를 적용한다.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        // 수집 세션(기록자)과 서비스 엔진(판정·기준선 기록)이 같은 파일을 연다: WAL + 대기 5초.
        // A19 러너(windows-2022) 실측: 두 연결이 동시에 처음 열면 "database is locked". 대기 시간을 먼저 걸어도
        // journal_mode 전환·스키마 적용 중에는 SQLite 가 busy 처리기를 부르지 않고 바로 BUSY 를 돌려주는 경우가 있어
        // (교착 회피), 여는 과정 전체를 짧게 다시 시도한다 (최대 약 5초).
        let path = path.as_ref();
        let mut last = None;
        for _ in 0..50 {
            match Self::open_once(path) {
                Ok(s) => return Ok(s),
                Err(GraphError::Sqlite(e))
                    if matches!(
                        e.sqlite_error_code(),
                        Some(
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        )
                    ) =>
                {
                    last = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
        Err(GraphError::Sqlite(last.expect("재시도")))
    }

    fn open_once(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // 28차 Gemini 아이디어 1: 새 DB 는 auto_vacuum=INCREMENTAL(표를 만들기 전에만 효과 — 기존 DB 는 VACUUM 해야 바뀐다, SQLite pragma 문서).
        // 보관 정리 뒤 incremental_vacuum 으로 빈 쪽을 파일에서 돌려준다
        conn.execute_batch(
            "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
        )?;
        let s = Self::init(conn)?;
        // 오래 여는 연결: 문서 권고대로 열 때 optimize=0x10002, 그 뒤 주기적으로 optimize(보관 정리 뒤)
        let _ = s.conn.execute_batch("PRAGMA optimize=0x10002;");
        Ok(s)
    }

    /// 읽기 전용 연결(구조 개선 C 읽기 작업자). 스키마를 적용하지 않고, query_only 로 실수 쓰기도 막는다.
    /// WAL 이라 기록자(수집 세션·엔진)와 동시에 읽는다
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            path.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA query_only=ON;")?;
        Ok(Self { conn })
    }

    /// 파일 DB 경로(메모리 DB 면 빈 문자열)
    pub fn path(&self) -> String {
        self.conn.path().unwrap_or_default().to_string()
    }

    /// 메모리 DB (테스트용)
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(DDL)?;
        // 갈래 C: 증분 판정용 변경 기록 표·트리거 (meta 표가 먼저 있어야 한다)
        conn.execute_batch(crate::changes::DDL)?;
        // 스키마 2 → 3 이행: 기존 DB 에 edges.attrs_json 이 없으면 추가 (있으면 오류를 무시)
        let _ = conn.execute("ALTER TABLE edges ADD COLUMN attrs_json TEXT", []);
        conn.execute_batch(crate::views::GAP_DDL)?;
        // A20 이행: origins.sha256 / sha256_ts
        let _ = conn.execute("ALTER TABLE origins ADD COLUMN sha256 TEXT", []);
        // 개편안 2판 1-2②: 시간대별 차단 통신 수(우리 필터가 막은 것)와 집계 채널이 넘쳐 못 센 수
        let _ = conn.execute(
            "ALTER TABLE traffic_hourly ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE traffic_hourly ADD COLUMN blocked_lost INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute("ALTER TABLE origins ADD COLUMN sha256_ts INTEGER", []);
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// 쓰기 트랜잭션은 **항상 이것으로** 연다 (`BEGIN IMMEDIATE`). 같은 파일에 쓰는 연결이 둘이다(수집 세션·엔진).
    /// `BEGIN`(DEFERRED) 으로 열고 읽은 뒤 쓰기로 올라가면, 그 사이 다른 연결이 커밋한 경우 SQLite 는 busy 처리기 없이
    /// 바로 SQLITE_BUSY(_SNAPSHOT) 를 준다 — 수집 저장 스레드가 이 오류로 끝나면 수집 세션 전체가 멈춘다(16차 Q4-2, A20 재현).
    /// IMMEDIATE 는 시작할 때 쓰기 잠금을 잡으므로 busy_timeout 으로 기다린다. 놓으면(drop) 되돌린다.
    pub fn begin_write(&self) -> Result<WriteTx<'_>> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(WriteTx {
            conn: &self.conn,
            done: false,
        })
    }

    /// 원시 이벤트를 저장하고 id 를 돌려준다. 모든 선은 이 id 를 근거로 가리킨다.
    pub fn insert_raw(&self, ts: i64, source: &str, payload_json: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO raw_events(ts, source, payload_json) VALUES (?1, ?2, ?3)",
            params![ts, source, payload_json],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// 노드를 만들거나(없으면) 시각 범위를 갱신한다(있으면). id 를 돌려준다.
    pub fn upsert_node(
        &self,
        kind: NodeKind,
        key: &str,
        label: &str,
        ts: i64,
        attrs_json: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO nodes(kind, key, label, first_ts, last_ts, attrs_json)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5)
             ON CONFLICT(kind, key) DO UPDATE SET
               last_ts  = MAX(last_ts, excluded.last_ts),
               first_ts = MIN(first_ts, excluded.first_ts),
               label    = COALESCE(excluded.label, label),
               attrs_json = COALESCE(excluded.attrs_json, attrs_json)",
            params![kind.as_str(), key, label, ts, attrs_json],
        )?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM nodes WHERE kind = ?1 AND key = ?2",
            params![kind.as_str(), key],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    pub fn find_node(&self, kind: NodeKind, key: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM nodes WHERE kind = ?1 AND key = ?2",
                params![kind.as_str(), key],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 같은 PID 로 가장 최근에 시작된 프로세스 노드 (생성 시각을 모르는 이벤트의 귀속용)
    pub fn latest_process_by_pid(&self, pid: u32, before_ts: i64) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                // 28차 이후(L047 듣는 포트 5.3초): LIKE 'pid@%' 는 SQLite 기본(대소문자 무시) LIKE 라 (kind, key) 색인을 못 써
                // 프로세스 노드 전체를 훑었다. 수집 이벤트마다 불리는 함수다. 'pid@' ≤ key < 'pidA'('A' = '@' 다음 글자) 범위로 색인을 탄다
                "SELECT id FROM nodes
                 WHERE kind = 'process' AND key >= ?1 AND key < ?3 AND first_ts <= ?2
                 ORDER BY first_ts DESC LIMIT 1",
                params![format!("{pid}@"), before_ts, format!("{pid}A")],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn insert_edge(
        &self,
        src: i64,
        dst: i64,
        rel: Rel,
        ts: i64,
        evidence_id: Option<i64>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO edges(src, dst, rel, ts, evidence_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![src, dst, rel.as_str(), ts, evidence_id],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// 선에 근거를 하나 더 붙인다 (합쳐진 이벤트)
    pub fn add_evidence(&self, edge_id: i64, raw_id: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO edge_evidence(edge_id, raw_id) VALUES (?1, ?2)",
            params![edge_id, raw_id],
        )?;
        Ok(())
    }

    /// 선의 모든 근거 id (첫 근거 + 추가 근거)
    pub fn evidence_of(&self, edge_id: i64) -> Result<Vec<i64>> {
        let mut out: Vec<i64> = Vec::new();
        if let Some(first) = self
            .conn
            .query_row(
                "SELECT evidence_id FROM edges WHERE id = ?1",
                params![edge_id],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
        {
            out.push(first);
        }
        let mut st = self
            .conn
            .prepare("SELECT raw_id FROM edge_evidence WHERE edge_id = ?1 ORDER BY raw_id")?;
        for r in st.query_map(params![edge_id], |r| r.get::<_, i64>(0))? {
            let v = r?;
            if !out.contains(&v) {
                out.push(v);
            }
        }
        Ok(out)
    }

    pub fn node(&self, id: i64) -> Result<Node> {
        self.conn
            .query_row(
                "SELECT id, kind, key, COALESCE(label, key), COALESCE(first_ts,0), COALESCE(last_ts,0), attrs_json
                 FROM nodes WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Node {
                        id: r.get(0)?,
                        kind: r.get(1)?,
                        key: r.get(2)?,
                        label: r.get(3)?,
                        first_ts: r.get(4)?,
                        last_ts: r.get(5)?,
                        attrs_json: r.get(6)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| GraphError::NodeNotFound(id.to_string()))
    }

    pub fn edges_from(&self, src: i64) -> Result<Vec<Edge>> {
        let mut st = self.conn.prepare(
            "SELECT id, src, dst, rel, ts, evidence_id, chapter, attrs_json FROM edges WHERE src = ?1 ORDER BY ts",
        )?;
        let rows = st.query_map(params![src], row_to_edge)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// 선 하나 (A30: 범위 검사)
    pub fn edge(&self, id: i64) -> Result<Edge> {
        self.conn
            .query_row("SELECT id, src, dst, rel, ts, evidence_id, chapter, attrs_json FROM edges WHERE id = ?1", params![id], row_to_edge)
            .optional()?
            .ok_or_else(|| GraphError::NodeNotFound(format!("edge {id}")))
    }

    pub fn edges_to(&self, dst: i64) -> Result<Vec<Edge>> {
        let mut st = self.conn.prepare(
            "SELECT id, src, dst, rel, ts, evidence_id, chapter, attrs_json FROM edges WHERE dst = ?1 ORDER BY ts",
        )?;
        let rows = st.query_map(params![dst], row_to_edge)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// 속성이 있는 선 (귀속 선의 method/confidence 등)
    pub fn insert_edge_with_attrs(
        &self,
        src: i64,
        dst: i64,
        rel: Rel,
        ts: i64,
        evidence_id: Option<i64>,
        attrs_json: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO edges(src, dst, rel, ts, evidence_id, attrs_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![src, dst, rel.as_str(), ts, evidence_id, attrs_json],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// 노드 attrs_json 에 키들을 병합 (없는 키는 추가, 있는 키는 덮어씀)
    pub fn merge_node_attrs(&self, id: i64, patch: &serde_json::Value) -> Result<()> {
        let cur: Option<String> = self
            .conn
            .query_row(
                "SELECT attrs_json FROM nodes WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let mut v: serde_json::Value = cur
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        if let (Some(obj), Some(p)) = (v.as_object_mut(), patch.as_object()) {
            for (k, val) in p {
                obj.insert(k.clone(), val.clone());
            }
        }
        self.conn.execute(
            "UPDATE nodes SET attrs_json = ?1 WHERE id = ?2",
            params![v.to_string(), id],
        )?;
        Ok(())
    }

    /// meta 키 저장 (수집기 통계·스키마 기록용)
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// 연결별 송수신 바이트 증분 (F2)
    pub fn add_conn_bytes(
        &self,
        pid: u32,
        proto: &str,
        raddr: &str,
        rport: u16,
        sent: u64,
        recv: u64,
        ts: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO conn_bytes(pid, proto, raddr, rport, sent, recv, first_ts, last_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT(pid, proto, raddr, rport) DO UPDATE SET
               sent = sent + excluded.sent, recv = recv + excluded.recv, last_ts = excluded.last_ts",
            params![pid, proto, raddr, rport, sent as i64, recv as i64, ts],
        )?;
        Ok(())
    }

    /// FILETIME → 시간대 버킷(unix 초, 시 단위 내림)
    pub fn hour_bucket(ts_ft: i64) -> i64 {
        let unix = ts_ft / 10_000_000 - 11_644_473_600;
        unix - unix.rem_euclid(3600)
    }
    /// 시간대별 트래픽 요약에 바이트 더하기(쓰기 경로, 한 시간에 한 행)
    pub fn add_traffic_hour(&self, ts_ft: i64, sent: u64, recv: u64, conns: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO traffic_hourly(hour, sent, recv, conns) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(hour) DO UPDATE SET sent = sent + excluded.sent, recv = recv + excluded.recv, conns = conns + excluded.conns",
            params![Self::hour_bucket(ts_ft), sent as i64, recv as i64, conns as i64],
        )?;
        Ok(())
    }
    /// 차단 통신 수 더하기(hour 는 unix 초 시 단위, 집계 스레드가 10초마다 부른다)
    pub fn add_blocked_hour(&self, hour_unix: i64, blocked: u64, lost: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO traffic_hourly(hour, blocked, blocked_lost) VALUES (?1, ?2, ?3)
             ON CONFLICT(hour) DO UPDATE SET blocked = blocked + excluded.blocked, blocked_lost = blocked_lost + excluded.blocked_lost",
            params![hour_unix - hour_unix.rem_euclid(3600), blocked as i64, lost as i64],
        )?;
        Ok(())
    }
    /// `since_unix` 이후 시간대별 요약(hour 오름차순): (hour, sent, recv, conns, blocked, blocked_lost). 조회 경로는 이 작은 표만 읽는다
    pub fn traffic_hourly(&self, since_unix: i64) -> Result<Vec<(i64, i64, i64, i64, i64, i64)>> {
        let mut st = self.conn.prepare("SELECT hour, sent, recv, conns, blocked, blocked_lost FROM traffic_hourly WHERE hour >= ?1 ORDER BY hour")?;
        let rows = st.query_map(params![since_unix - since_unix.rem_euclid(3600)], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
    /// 보관 정리: 오래된 시간대 요약 삭제
    pub fn prune_traffic_hourly(&self, before_unix: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM traffic_hourly WHERE hour < ?1",
            params![before_unix],
        )?)
    }

    pub fn count_nodes(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))?)
    }
    pub fn count_edges(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM edges", [], |r| r.get(0))?)
    }
}

pub(crate) fn row_to_edge(r: &rusqlite::Row) -> rusqlite::Result<Edge> {
    Ok(Edge {
        id: r.get(0)?,
        src: r.get(1)?,
        dst: r.get(2)?,
        rel: r.get(3)?,
        ts: r.get(4)?,
        evidence_id: r.get(5)?,
        chapter: r.get(6)?,
        attrs_json: r.get(7)?,
    })
}

/// `Store::begin_write` 의 안내자. `commit()` 하지 않고 놓으면 ROLLBACK.
pub struct WriteTx<'a> {
    conn: &'a Connection,
    done: bool,
}
impl<'a> WriteTx<'a> {
    pub fn commit(mut self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        self.done = true;
        Ok(())
    }
}
impl std::ops::Deref for WriteTx<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn
    }
}
impl Drop for WriteTx<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}
