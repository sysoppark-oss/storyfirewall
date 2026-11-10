//! SQLite 저장소: 연결, 스키마 적용, 노드·선 upsert

use crate::schema::{DDL, SCHEMA_VERSION};
use crate::{Edge, GraphError, Node, NodeKind, Rel, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

/// 차단 기록 한 줄(DB 보관용). svc 의 BlockRec 과 같은 뜻
#[derive(Debug, Clone, PartialEq)]
pub struct BlockedRow {
    pub ts: i64,
    pub filter_id: u64,
    pub app: String,
    pub remote: String,
    pub rport: u16,
    pub lport: u16,
    pub proto: u8,
    pub dir: String,
    pub loopback: bool,
    pub ours_at: bool,
}
/// 차단한 필터의 이름·공급자(처음 본 때)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BlockedFilter {
    pub name: String,
    pub description: String,
    pub provider_name: String,
    pub provider_key: String,
    pub ours: bool,
}

/// 원시 기록 바이트 합(용량 상한 순환용). 합 행이 있을 때만 트리거가 더하고 뺀다
const RAW_SIZE_DDL: &str = "
CREATE TABLE IF NOT EXISTS raw_size (k INTEGER PRIMARY KEY CHECK (k = 1), bytes INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS tr_raw_size_ins AFTER INSERT ON raw_events BEGIN
  UPDATE raw_size SET bytes = bytes + LENGTH(NEW.payload_json) WHERE k = 1;
END;
CREATE TRIGGER IF NOT EXISTS tr_raw_size_del AFTER DELETE ON raw_events BEGIN
  UPDATE raw_size SET bytes = bytes - LENGTH(OLD.payload_json) WHERE k = 1;
END;
";

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
        // install-128 실측(시작 때 보관 정리 6분 중 434초가 원시 기록 용량 계산 SUM(LENGTH) — 250만 행 전부 읽기):
        // 원시 기록 바이트 합을 표 하나에 들고 트리거로 더하고 뺀다. 합 행이 없으면(옛 DB) 작은 DB 는 바로 세고,
        // 큰 DB 는 서비스가 따로 읽기 연결로 한 번 센다(init_raw_size) — 그 전까지 보관 정리는 용량 순환을 건너뛴다
        conn.execute_batch(RAW_SIZE_DDL)?;
        let have: bool = conn
            .query_row("SELECT 1 FROM raw_size WHERE k = 1", [], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !have {
            let small: i64 = conn.query_row(
                "SELECT COUNT(*) FROM (SELECT 1 FROM raw_events LIMIT 200001)",
                [],
                |r| r.get(0),
            )?;
            if small <= 200_000 {
                conn.execute(
                    "INSERT OR IGNORE INTO raw_size(k, bytes) SELECT 1, COALESCE(SUM(LENGTH(payload_json)), 0) FROM raw_events",
                    [],
                )?;
            }
        }
        // 검수 122-1 한 번 정리: 생성 시각을 못 읽은 스냅샷 프로세스(노드 시각 = 스냅샷 시각)에 이어 둔 부모 선은
        // PID 재사용으로 엉뚱한 프로세스가 부모로 잡혔을 수 있다(wininit ← UI 실측). 근거 원시 이벤트가 남은 것만 가린다
        let done: bool = conn
            .query_row(
                "SELECT 1 FROM meta WHERE key = 'fix_122_unknown_ct'",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !done {
            // install-124 실측: 처음 쓴 질의(edges 전체를 훑고 원시 이벤트·노드 JSON 과 맞춤)가 830MB DB 에서 수 분 걸려
            // 서비스 시작 동안 엔진이 묶였다. 스냅샷 시각(부분 색인 ix_raw_snapshot, 몇 개뿐) → 그 시각에 생긴 프로세스 노드
            // → 그 노드로 들어오는 선(ix_edges_dst) 순서로 좁힌다
            conn.execute(
                "DELETE FROM edges WHERE id IN (
                   SELECT e.id FROM nodes n
                   JOIN edges e ON e.dst = n.id AND e.ts = n.first_ts
                   WHERE n.kind = 'process'
                     AND n.first_ts IN (SELECT DISTINCT ts FROM raw_events WHERE source = 'snapshot')
                     AND e.rel = 'spawned')",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('fix_122_unknown_ct', '1')",
                [],
            )?;
        }
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
        Ok(Self { conn })
    }

    /// 원시 기록 바이트 합(트리거로 유지). 아직 세지 않은 옛 DB 면 None
    pub fn raw_bytes(&self) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row("SELECT bytes FROM raw_size WHERE k = 1", [], |r| r.get(0))
            .optional()?)
    }

    /// 큰 옛 DB 의 원시 기록 바이트 합을 한 번 센다. 읽기 연결(WAL — 기록자를 막지 않음)로 세고, 짧은 쓰기 한 번으로 넣는다.
    /// 세는 동안 들어온 기록은 빠질 수 있다(용량 상한은 대략값이라 괜찮다). 이미 있으면 아무것도 안 한다
    pub fn init_raw_size<P: AsRef<Path>>(path: P) -> Result<Option<i64>> {
        let w = Self::open(path.as_ref())?;
        if let Some(b) = w.raw_bytes()? {
            return Ok(Some(b));
        }
        let r = Self::open_read_only(path.as_ref())?;
        let total: i64 = r.conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload_json)), 0) FROM raw_events",
            [],
            |x| x.get(0),
        )?;
        w.conn.execute(
            "INSERT OR IGNORE INTO raw_size(k, bytes) VALUES (1, ?1)",
            params![total],
        )?;
        Ok(Some(total))
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
    /// 차단 기록 줄 넣기(집계 스레드가 10초마다 묶어서). 트랜잭션 하나
    pub fn blocked_log_insert(&self, rows: &[BlockedRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let tx = self.begin_write()?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO blocked_log(ts, filter_id, app, remote, rport, lport, proto, dir, loopback, ours_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for r in rows {
                st.execute(params![
                    r.ts,
                    r.filter_id as i64,
                    r.app,
                    r.remote,
                    r.rport,
                    r.lport,
                    r.proto,
                    r.dir,
                    r.loopback,
                    r.ours_at
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    /// 필터 이름·공급자(처음 볼 때 한 번). 이미 있으면 그대로 둔다 — 처음 본 때의 이름이 증거다
    pub fn blocked_filter_put(
        &self,
        filter_id: u64,
        f: &BlockedFilter,
        seen_ts: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO blocked_filters(filter_id, name, description, provider_name, provider_key, ours, seen_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![filter_id as i64, f.name, f.description, f.provider_name, f.provider_key, f.ours, seen_ts],
        )?;
        Ok(())
    }
    /// 보관 정리: min_ts 보다 오래된 것, 그리고 max_rows 를 넘는 오래된 것. 남은 줄이 가리키지 않는 필터 정보도 지운다. 지운 줄 수
    pub fn blocked_log_prune(&self, min_ts: i64, max_rows: i64) -> Result<usize> {
        let mut n = self
            .conn
            .execute("DELETE FROM blocked_log WHERE ts < ?1", params![min_ts])?;
        n += self.conn.execute(
            "DELETE FROM blocked_log WHERE id <= (SELECT id FROM blocked_log ORDER BY id DESC LIMIT 1 OFFSET ?1)",
            params![max_rows],
        )?;
        if n > 0 {
            self.conn.execute(
                "DELETE FROM blocked_filters WHERE filter_id NOT IN (SELECT DISTINCT filter_id FROM blocked_log)",
                [],
            )?;
        }
        Ok(n)
    }
    /// 시작 때 되읽기: since_ts 이후 줄(시각 순)과 필터 정보 전부
    pub fn blocked_log_load(
        &self,
        since_ts: i64,
    ) -> Result<(Vec<BlockedRow>, Vec<(u64, BlockedFilter)>)> {
        let mut st = self.conn.prepare(
            "SELECT ts, filter_id, app, remote, rport, lport, proto, dir, loopback, ours_at FROM blocked_log WHERE ts >= ?1 ORDER BY ts, id",
        )?;
        let rows = st
            .query_map(params![since_ts], |r| {
                Ok(BlockedRow {
                    ts: r.get(0)?,
                    filter_id: r.get::<_, i64>(1)? as u64,
                    app: r.get(2)?,
                    remote: r.get(3)?,
                    rport: r.get(4)?,
                    lport: r.get(5)?,
                    proto: r.get(6)?,
                    dir: r.get(7)?,
                    loopback: r.get(8)?,
                    ours_at: r.get(9)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut st = self.conn.prepare(
            "SELECT filter_id, name, description, provider_name, provider_key, ours FROM blocked_filters",
        )?;
        let fs = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    BlockedFilter {
                        name: r.get(1)?,
                        description: r.get(2)?,
                        provider_name: r.get(3)?,
                        provider_key: r.get(4)?,
                        ours: r.get(5)?,
                    },
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((rows, fs))
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
