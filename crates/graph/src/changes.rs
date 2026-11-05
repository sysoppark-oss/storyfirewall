//! 그래프 변경 기록 (증분 판정용, 갈래 C)
//!
//! 주기 판정은 1분마다 보관 기간 전체를 다시 읽었다(노트북 install-27: 불러오기 평균 1.8초).
//! 증분 판정은 메모리에 둔 뷰에 "지난 판정 뒤 바뀐 것"만 더한다. 바뀐 것은 두 갈래로 안다.
//!
//! 1. **새 선**: `edges.id > 지난 스냅숏의 MAX(id)`. 노드는 선의 끝점으로 따라 들어온다.
//!    edges.id 는 AUTOINCREMENT 가 아니라 다시 쓰일 수 있다(가장 큰 id 들이 지워지면 MAX+1 이 옛 빈자리를 다시 쓴다).
//!    그래서 지운 선 id 의 최댓값(높은 물 표시, meta `graph_edges_hw`)을 두고, 그 이하 id 로 들어온 INSERT 는
//!    변경 기록에 남긴다. 근거: 다시 쓰인 id g 는 예전에 지워진 id 다 → 지울 때 hw ≥ g (트리거 또는 `begin_bulk`).
//!    hw 보다 큰 새 id 는 지난 스냅숏 MAX 보다도 크다(그 사이 MAX 가 내려가려면 MAX 행이 지워져 hw ≥ MAX).
//!    (시험에서 발견: 보관 정리로 빈 129 가 130·131 삭제 뒤 다시 쓰여 증분 뷰에서 빠졌다)
//! 2. **제자리 변경·삭제**: 아래 트리거가 `graph_changes` 에 (표, 행 id) 를 남긴다.
//!    - nodes: kind·key·label·attrs_json 이 실제로 바뀐 UPDATE, DELETE
//!      (first_ts·last_ts 만 바뀐 것은 대개 남기지 않는다 — 뿌리·사슬은 노드 시각을 쓰지 않는다. 예외: (사) 점수의 보조 근거
//!      "브라우저 종료 직후 권한 상승 서비스"가 프로세스의 first_ts 와 끝난(ended) 프로세스의 last_ts 를 읽는다 →
//!      프로세스 노드의 first_ts 변경, 끝난 프로세스의 last_ts 변경은 남긴다. 끝나기 전의 last_ts 는 그 판단에 쓰이지 않고,
//!      ended 를 붙이는 갱신은 속성 변경으로 남아 그때 노드를 새로 읽는다)
//!    - edges: src·dst·rel·ts·evidence_id·attrs_json 이 바뀐 UPDATE, DELETE
//!      (chapter 만 바꾸는 판정 자신의 기록은 남기지 않는다 — `UPDATE OF` 열 목록에 chapter 가 없다)
//!    - edge_evidence: 접속 선(connected)에 근거가 붙은 INSERT (근거가 연결 표뿐인지 = table_only 가 바뀔 수 있다)
//!
//! 트리거는 DB 파일에 있으므로 어느 연결(수집 세션·엔진·옛 판 수집기)이 쓰든 남는다.
//!
//! **대량 변경(보관 정리)**: 행마다 기록하면 수십만 행이 생긴다. 보관 정리는 같은 트랜잭션 안에서
//! `begin_bulk` 로 meta 에 표시를 세워 트리거를 끄고, 끝에 `end_bulk` 로 표시를 지우며 "전체 다시"
//! 표시(`tbl = '*'`)를 하나 남긴다. 트랜잭션이 되돌려지면 표시도 함께 되돌려진다(원자적).
//!
//! 기록은 판정이 소비한 뒤 `prune` 으로 지운다. seq 는 AUTOINCREMENT 라 지운 뒤에도 다시 쓰이지 않는다(단조 증가).

use rusqlite::{params, Connection};

use crate::Result;

/// 트리거가 꺼진 상태 표시(meta 키). 이 키가 있으면 트리거가 기록하지 않는다
pub const BULK_KEY: &str = "graph_bulk";
/// 지운 선 id 의 최댓값(높은 물 표시). 이 이하 id 로 들어온 선은 다시 쓰인 id 라 변경 기록에 남긴다
pub const EDGES_HW_KEY: &str = "graph_edges_hw";

pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS graph_changes (
  seq    INTEGER PRIMARY KEY AUTOINCREMENT,
  tbl    TEXT    NOT NULL,     -- 'n' 노드 / 'e' 선 / '*' 전체 다시(보관 정리 등 대량 변경)
  row_id INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS tg_gc_nodes_upd AFTER UPDATE OF kind, key, label, attrs_json ON nodes
  WHEN (OLD.kind IS NOT NEW.kind OR OLD.key IS NOT NEW.key OR OLD.label IS NOT NEW.label
        OR OLD.attrs_json IS NOT NEW.attrs_json)
   AND NOT EXISTS (SELECT 1 FROM meta WHERE key = 'graph_bulk')
BEGIN
  INSERT INTO graph_changes(tbl, row_id) VALUES ('n', NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS tg_gc_nodes_ts AFTER UPDATE OF first_ts, last_ts ON nodes
  WHEN NEW.kind = 'process'
   AND (OLD.first_ts IS NOT NEW.first_ts
        OR (OLD.last_ts IS NOT NEW.last_ts AND json_extract(NEW.attrs_json, '$.ended') = 1))
   AND NOT EXISTS (SELECT 1 FROM meta WHERE key = 'graph_bulk')
BEGIN
  INSERT INTO graph_changes(tbl, row_id) VALUES ('n', NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS tg_gc_nodes_del AFTER DELETE ON nodes
  WHEN NOT EXISTS (SELECT 1 FROM meta WHERE key = 'graph_bulk')
BEGIN
  INSERT INTO graph_changes(tbl, row_id) VALUES ('n', OLD.id);
END;
CREATE TRIGGER IF NOT EXISTS tg_gc_edges_upd AFTER UPDATE OF src, dst, rel, ts, evidence_id, attrs_json ON edges
  WHEN (OLD.src IS NOT NEW.src OR OLD.dst IS NOT NEW.dst OR OLD.rel IS NOT NEW.rel OR OLD.ts IS NOT NEW.ts
        OR OLD.evidence_id IS NOT NEW.evidence_id OR OLD.attrs_json IS NOT NEW.attrs_json)
   AND NOT EXISTS (SELECT 1 FROM meta WHERE key = 'graph_bulk')
BEGIN
  INSERT INTO graph_changes(tbl, row_id) VALUES ('e', NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS tg_gc_edges_del AFTER DELETE ON edges
  WHEN NOT EXISTS (SELECT 1 FROM meta WHERE key = 'graph_bulk')
BEGIN
  INSERT INTO graph_changes(tbl, row_id) VALUES ('e', OLD.id);
  INSERT INTO meta(key, value) VALUES ('graph_edges_hw', OLD.id)
    ON CONFLICT(key) DO UPDATE SET value = MAX(CAST(value AS INTEGER), CAST(excluded.value AS INTEGER));
END;
CREATE TRIGGER IF NOT EXISTS tg_gc_edges_ins AFTER INSERT ON edges
  WHEN NEW.id <= COALESCE((SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'graph_edges_hw'), 0)
BEGIN
  INSERT INTO graph_changes(tbl, row_id) VALUES ('e', NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS tg_gc_evidence_ins AFTER INSERT ON edge_evidence
  WHEN (SELECT rel FROM edges WHERE id = NEW.edge_id) = 'connected'
   AND NOT EXISTS (SELECT 1 FROM meta WHERE key = 'graph_bulk')
BEGIN
  INSERT INTO graph_changes(tbl, row_id) VALUES ('e', NEW.edge_id);
END;
"#;

/// 대량 변경 시작: 같은 트랜잭션 안에서 부른다(트리거 끄기)
pub fn begin_bulk(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?1, '1')",
        params![BULK_KEY],
    )?;
    // 이번에 지울 수 있는 선 id 는 모두 지금 MAX(id) 이하 → 높은 물 표시를 한 번에 올린다(행마다 트리거 대신)
    let max: Option<i64> = conn.query_row("SELECT MAX(id) FROM edges", [], |r| r.get(0))?;
    if let Some(m) = max {
        conn.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = MAX(CAST(value AS INTEGER), CAST(excluded.value AS INTEGER))",
            params![EDGES_HW_KEY, m],
        )?;
    }
    Ok(())
}

/// 대량 변경 끝: 트리거를 다시 켜고, 무엇이든 바뀌었으면(`changed`) "전체 다시" 표시를 남긴다
/// 판정이 돌지 않아(진단 도구만 쓰는 DB 등) 변경 기록이 쌓이기만 할 때의 상한. 넘으면 보관 정리가 비우고 "전체 다시"를 남긴다
pub const MAX_PENDING: i64 = 500_000;

pub fn end_bulk(conn: &Connection, changed: bool) -> Result<()> {
    conn.execute("DELETE FROM meta WHERE key = ?1", params![BULK_KEY])?;
    let pending: i64 = conn.query_row("SELECT COUNT(*) FROM graph_changes", [], |r| r.get(0))?;
    if changed || pending > MAX_PENDING {
        // 어차피 전체 다시 — 쌓인 기록은 필요 없다(seq 는 AUTOINCREMENT 라 비워도 줄지 않는다)
        conn.execute("DELETE FROM graph_changes", [])?;
        mark_reset(conn)?;
    }
    Ok(())
}

/// 증분 판정이 다음에 전체를 다시 읽게 한다
pub fn mark_reset(conn: &Connection) -> Result<()> {
    conn.execute("INSERT INTO graph_changes(tbl, row_id) VALUES ('*', 0)", [])?;
    Ok(())
}

/// 지금까지 매긴 마지막 seq (기록을 지웠어도 줄지 않는다). 기록이 한 번도 없으면 0
pub fn last_seq(conn: &Connection) -> Result<i64> {
    // sqlite_sequence 는 AUTOINCREMENT 표에 처음 넣을 때 생긴다 — 없으면 0
    let v: Option<i64> = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = 'graph_changes'",
            [],
            |r| r.get(0),
        )
        .ok();
    Ok(v.unwrap_or(0))
}

/// (seq, 표, 행 id) — `after` 다음 것부터 seq 순서로, 최대 `limit` 개
pub fn since(conn: &Connection, after: i64, limit: usize) -> Result<Vec<(i64, String, i64)>> {
    let mut st = conn.prepare_cached(
        "SELECT seq, tbl, row_id FROM graph_changes WHERE seq > ?1 ORDER BY seq LIMIT ?2",
    )?;
    let rows = st.query_map(params![after, limit as i64], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// 소비한 기록 지우기 (seq ≤ upto)
pub fn prune(conn: &Connection, upto: i64) -> Result<usize> {
    Ok(conn.execute("DELETE FROM graph_changes WHERE seq <= ?1", params![upto])?)
}
