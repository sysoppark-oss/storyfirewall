//! 보관 정책과 하루 단위 압축 (이야기형 3판 11장)
//!
//! - 원시 이벤트(raw_events): 7일 **또는** 용량 상한(기본 500MB) 중 먼저 닿는 쪽. 오래된 것부터 삭제(순환).
//!   의심 사건(chapter 가 있는 선)이 가리키는 원시 이벤트는 순환에서 빼고 30일 보존.
//!   삭제되면 선의 evidence_id 는 NULL 이 되고, 선 자체는 남는다.
//! - 모든 수치는 `RetentionPolicy` 로 사용자가 바꿀 수 있다. 기본값은 개인 PC 기준.
//! - 평범한 활동(chapter 가 NULL 인 선) 중 대량인 접속·주소 조회(connected·resolved): 하루가 지나면 `daily_summary` 로 접고 선을 지운다.
//!   출신 사슬 선(spawned·wrote·downloaded·registered·injected·connected_via)은 양이 적고 이야기의 뼈대라
//!   하루 압축에서 빼고 요약과 같은 기간(30일) 뒤 지운다(2026-11-03, 27차 — 며칠 전 시작한 프로세스의 "어디서 왔나"가 끊기지 않게).
//!   executed_as(파일→프로세스)는 지우지 않는다.
//!   접는 단위 = (날짜, src 노드, rel, dst 노드) → 횟수·첫 시각·마지막 시각.
//!   요약도 30일이 지나면 삭제.
//! - 의심 사건(chapter 가 있는 선)과 그 선이 닿는 노드: 30일. 그 뒤 삭제.
//! - 출신 기록(origins)과 그것이 가리키는 파일 노드: 삭제하지 않는다 (장기 보관).
//! - 노드: 어떤 선·요약·출신 기록도 가리키지 않게 되면 삭제.
//!
//! 압축은 사실을 줄이는 것이지 바꾸는 것이 아니다. 요약 행은 "같은 선이 N번" 이라는 사실을 보존한다.

use crate::{Result, Store};
use rusqlite::params;
use rusqlite::OptionalExtension;

/// FILETIME 100ns 단위의 하루
pub const DAY: i64 = 24 * 60 * 60 * 10_000_000;

/// 보관 정책. 설정 파일(JSON/YAML)에서 읽어 사용자가 조절한다. 빠진 항목은 기본값.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RetentionPolicy {
    /// 평범한 원시 이벤트 보관 일수
    pub raw_days: i64,
    /// 원시 이벤트 전체 용량 상한(바이트). 초과하면 오래된 평범한 이벤트부터 삭제. 0 = 무제한
    pub raw_max_bytes: i64,
    /// 의심 사건이 가리키는 원시 이벤트 보관 일수 (용량 순환에서 제외)
    pub suspicious_raw_days: i64,
    /// 평범한 선을 하루 요약으로 접기까지의 일수
    pub ordinary_days: i64,
    /// 하루 요약 보관 일수
    pub summary_days: i64,
    /// 의심 사건 선 보관 일수
    pub suspicious_days: i64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            raw_days: 7,
            raw_max_bytes: 500 * 1024 * 1024,
            suspicious_raw_days: 30,
            // 27차 Gemini Q8: 하루는 사후 분석에 너무 짧다(며칠 뒤 다른 경로로 악성임이 밝혀지면 시각별 기록이 없다) — 3일
            ordinary_days: 3,
            summary_days: 30,
            suspicious_days: 30,
        }
    }
}

impl RetentionPolicy {
    /// 설정값을 안전한 범위로 맞춘다 (0 이하 일수는 기본값, 의심은 평범보다 짧을 수 없음)
    pub fn sanitized(self) -> Self {
        let d = Self::default();
        let pick = |v: i64, dv: i64| if v <= 0 { dv } else { v };
        let raw_days = pick(self.raw_days, d.raw_days);
        Self {
            raw_days,
            raw_max_bytes: self.raw_max_bytes.max(0),
            suspicious_raw_days: pick(self.suspicious_raw_days, d.suspicious_raw_days)
                .max(raw_days),
            ordinary_days: pick(self.ordinary_days, d.ordinary_days),
            summary_days: pick(self.summary_days, d.summary_days),
            suspicious_days: pick(self.suspicious_days, d.suspicious_days),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionReport {
    pub raw_deleted: usize,
    /// 용량 상한 때문에 추가로 지운 원시 이벤트 수
    pub raw_deleted_by_size: usize,
    /// 적용 후 원시 이벤트 총 바이트 (payload_json 길이 합)
    pub raw_bytes_after: i64,
    pub edges_compacted: usize,
    /// 기간이 지나 지운 평범한 출신 사슬 선(spawned 등)
    pub provenance_deleted: usize,
    pub summaries_written: usize,
    pub summaries_deleted: usize,
    pub suspicious_deleted: usize,
    pub nodes_deleted: usize,
    /// L050(노트북 84초, 지운 것 0건): 단계별 걸린 시간(ms) — 접기·출신·의심 / 원시 / 용량 / 고아 노드
    pub ms_fold: u64,
    pub ms_raw: u64,
    pub ms_size: u64,
    pub ms_nodes: u64,
}

pub const SUMMARY_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS daily_summary (
  day        INTEGER NOT NULL,   -- FILETIME 을 하루 단위로 내림한 값
  src        INTEGER NOT NULL REFERENCES nodes(id),
  dst        INTEGER NOT NULL REFERENCES nodes(id),
  rel        TEXT NOT NULL,
  count      INTEGER NOT NULL,
  first_ts   INTEGER NOT NULL,
  last_ts    INTEGER NOT NULL,
  PRIMARY KEY(day, src, dst, rel)
);
CREATE INDEX IF NOT EXISTS ix_summary_day ON daily_summary(day);
"#;

/// 27차 Gemini Q9: 오래 밀린 정리를 하루씩 나눠 짧은 트랜잭션 여러 번으로(수집기 쓰기가 오래 막히지 않게).
/// 기준 시각을 가장 오래된 기록부터 하루씩 앞으로 옮기며 `apply` 를 부른다 — 결과는 `apply(now)` 한 번과 같다(시험).
/// 시계가 크게 뒤로 갔던 기록 등으로 너무 오래되면 최근 60일부터만 나눈다
pub fn apply_chunked(store: &Store, now: i64, policy: RetentionPolicy) -> Result<RetentionReport> {
    let oldest: Option<i64> = store.conn.query_row(
        "SELECT MIN(t) FROM (SELECT MIN(ts) AS t FROM edges UNION ALL SELECT MIN(ts) FROM raw_events)",
        [],
        |r| r.get(0),
    )?;
    let mut total = RetentionReport::default();
    if let Some(o) = oldest {
        let p = policy.sanitized();
        let shortest = p
            .ordinary_days
            .min(p.raw_days)
            .min(p.suspicious_days)
            .min(p.summary_days);
        let mut t = (o + (shortest + 1) * DAY).max(now - 60 * DAY);
        while t < now {
            // 하루 단위 중간 정리는 용량 계산(원시 기록 전체 읽기)을 하지 않는다 — 마지막 한 번만
            add_report(&mut total, apply_inner(store, t, policy, false)?);
            t += DAY;
        }
    }
    let last = apply_inner(store, now, policy, true)?;
    add_report(&mut total, last);
    total.raw_bytes_after = last.raw_bytes_after;
    Ok(total)
}

fn add_report(a: &mut RetentionReport, b: RetentionReport) {
    a.raw_deleted += b.raw_deleted;
    a.raw_deleted_by_size += b.raw_deleted_by_size;
    a.edges_compacted += b.edges_compacted;
    a.provenance_deleted += b.provenance_deleted;
    a.summaries_written += b.summaries_written;
    a.summaries_deleted += b.summaries_deleted;
    a.suspicious_deleted += b.suspicious_deleted;
    a.nodes_deleted += b.nodes_deleted;
    a.ms_fold += b.ms_fold;
    a.ms_raw += b.ms_raw;
    a.ms_size += b.ms_size;
    a.ms_nodes += b.ms_nodes;
}

/// `now` 기준으로 보관 정책을 적용한다. 멱등: 두 번 돌려도 결과는 같다.
pub fn apply(store: &Store, now: i64, policy: RetentionPolicy) -> Result<RetentionReport> {
    apply_inner(store, now, policy, true)
}

/// `measure_size`: 용량 상한 검사·적용 후 크기 계산(원시 기록 내용 전체를 읽는다)을 할지
fn apply_inner(
    store: &Store,
    now: i64,
    policy: RetentionPolicy,
    measure_size: bool,
) -> Result<RetentionReport> {
    let ms = |t: std::time::Instant| t.elapsed().as_millis() as u64;
    let t0 = std::time::Instant::now();
    let policy = policy.sanitized();
    store.conn.execute_batch(SUMMARY_DDL)?;
    let tx = store.begin_write()?;
    // 갈래 C: 대량 삭제·근거 끊기를 행마다 변경 기록에 남기지 않는다(트리거 끄기). 끝에 "전체 다시" 표시 하나로 대신한다
    crate::changes::begin_bulk(&tx)?;
    let mut rep = RetentionReport::default();

    // 1) 평범한 선 → 하루 요약으로 접기
    let ordinary_before = now - policy.ordinary_days * DAY;
    {
        let mut st = tx.prepare(
            "SELECT (ts / ?1) * ?1 AS day, src, dst, rel, COUNT(*), MIN(ts), MAX(ts)
             FROM edges WHERE chapter IS NULL AND ts < ?2 AND rel IN ('connected', 'resolved')
             GROUP BY day, src, dst, rel",
        )?;
        let rows: Vec<(i64, i64, i64, String, i64, i64, i64)> = st
            .query_map(params![DAY, ordinary_before], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        for (day, src, dst, rel, n, f, l) in rows {
            tx.execute(
                "INSERT INTO daily_summary(day, src, dst, rel, count, first_ts, last_ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(day, src, dst, rel) DO UPDATE SET
                   count = count + excluded.count,
                   first_ts = MIN(first_ts, excluded.first_ts),
                   last_ts = MAX(last_ts, excluded.last_ts)",
                params![day, src, dst, rel, n, f, l],
            )?;
            rep.summaries_written += 1;
        }
        // 접힌 선 삭제(접속·주소 조회만)
        rep.edges_compacted = tx.execute(
            "DELETE FROM edges WHERE chapter IS NULL AND ts < ?1 AND rel IN ('connected', 'resolved')",
            params![ordinary_before],
        )?;
    }
    // 1-b) 평범한 출신 사슬 선: 요약과 같은 기간 뒤 삭제. executed_as 는 남긴다
    rep.provenance_deleted = tx.execute(
        "DELETE FROM edges WHERE chapter IS NULL AND ts < ?1 AND rel NOT IN ('connected', 'resolved', 'executed_as')",
        params![now - policy.summary_days * DAY],
    )?;

    // 2) 의심 사건 삭제 (30일)
    let suspicious_before = now - policy.suspicious_days * DAY;
    rep.suspicious_deleted = tx.execute(
        "DELETE FROM edges WHERE chapter IS NOT NULL AND ts < ?1",
        params![suspicious_before],
    )?;

    // 3) 요약 삭제 (30일)
    let summary_before = now - policy.summary_days * DAY;
    rep.summaries_deleted = tx.execute(
        "DELETE FROM daily_summary WHERE day < ?1",
        params![summary_before],
    )?;

    rep.ms_fold = ms(t0);
    let t1 = std::time::Instant::now();
    // 4) 원시 이벤트 삭제. 의심 사건이 가리키는 것은 suspicious_raw_days, 나머지는 raw_days.
    //    "의심 사건이 가리킨다" = chapter 가 있는 선의 evidence_id 또는 edge_evidence 에 있음.
    let raw_before = now - policy.raw_days * DAY;
    let susp_raw_before = now - policy.suspicious_raw_days * DAY;
    // 기한이 지난 원시 기록이 하나라도 있을 때만(시각 색인으로 한 줄) — 없으면 선 전체를 훑는 근거 표 만들기를 건너뛴다
    let any_old: bool = tx
        .query_row(
            "SELECT 1 FROM raw_events WHERE ts < ?1 LIMIT 1",
            params![raw_before.max(susp_raw_before)],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let need_susp = any_old || (measure_size && policy.raw_max_bytes > 0);
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS susp_raw(id INTEGER PRIMARY KEY);
         DELETE FROM susp_raw;",
    )?;
    if need_susp {
        tx.execute(
            "INSERT OR IGNORE INTO susp_raw(id)
             SELECT evidence_id FROM edges WHERE chapter IS NOT NULL AND evidence_id IS NOT NULL
             UNION SELECT ee.raw_id FROM edge_evidence ee JOIN edges e ON e.id = ee.edge_id WHERE e.chapter IS NOT NULL",
            [],
        )?;
    }
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS raw_del(id INTEGER PRIMARY KEY);
         DELETE FROM raw_del;",
    )?;
    if any_old {
        tx.execute(
            "INSERT INTO raw_del(id)
             SELECT id FROM raw_events
             WHERE (ts < ?1 AND id NOT IN (SELECT id FROM susp_raw))
                OR (ts < ?2 AND id IN (SELECT id FROM susp_raw))",
            params![raw_before, susp_raw_before],
        )?;
        rep.raw_deleted = count_raw_del(&tx)?;
        if rep.raw_deleted > 0 {
            delete_raw_del(&tx)?;
        }
    }
    rep.ms_raw = ms(t1);
    let t2 = std::time::Instant::now();

    // 4-b) 용량 상한 순환: 평범한 원시 이벤트를 오래된 순으로, 상한 아래로 내려올 때까지.
    //      원시 기록 내용 전체를 읽으므로 마지막 정리에서만(measure_size). 적용 후 크기는 다시 읽지 않고 뺀다
    let mut total_after: i64 = -1;
    // 합은 트리거로 유지되는 값(raw_size). 아직 세지 않은 옛 DB 면 이번엔 용량 순환을 건너뛴다(-1)
    let known: Option<i64> = if measure_size {
        tx.query_row("SELECT bytes FROM raw_size WHERE k = 1", [], |r| r.get(0))
            .optional()?
    } else {
        None
    };
    if let Some(mut total) = known {
        total_after = total;
        if policy.raw_max_bytes > 0 && total > policy.raw_max_bytes {
            // 한 번에 지울 양을 오래된 순 누적 합으로 계산 (의심 사건 근거는 제외)
            // install-130 실측(이 단계 434초): "NOT IN susp_raw ... ORDER BY ts, id" 를 플래너가 전체 훑기 + 정렬로 풀어
            // 첫 줄을 내기 전에 250만 행의 길이를 모두 읽었다. 시각 색인 순으로 앞에서부터 읽고(필요한 만큼만),
            // 의심 사건 근거는 메모리 집합으로 건너뛴다
            let susp: std::collections::HashSet<i64> = {
                let mut q = tx.prepare("SELECT id FROM susp_raw")?;
                let v = q
                    .query_map([], |r| r.get::<_, i64>(0))?
                    .collect::<std::result::Result<_, _>>()?;
                v
            };
            let mut st = tx.prepare(
                // diag-157: 이 단계가 10.5초. LENGTH(text) 는 글자 수를 세려고 내용을 다 읽는다 → octet_length 는
                // 기록 머리의 바이트 길이만 본다(SQLite 3.43+). 합(raw_size, 글자 수)과 조금 다르지만(한글은 바이트가 더 큼)
                // 고르는 양이 약간 적어질 뿐이고 실제 합은 트리거가 맞춘다 — 다음 정리에서 나머지를 지운다
                "SELECT id, octet_length(payload_json) FROM raw_events INDEXED BY ix_raw_ts ORDER BY ts, id",
            )?;
            let mut victims: Vec<i64> = Vec::new();
            let mut rows = st.query([])?;
            while let Some(r) = rows.next()? {
                if total <= policy.raw_max_bytes {
                    break;
                }
                let id: i64 = r.get(0)?;
                if susp.contains(&id) {
                    continue;
                }
                victims.push(id);
                total -= r.get::<_, i64>(1)?;
            }
            drop(rows);
            drop(st);
            if !victims.is_empty() {
                tx.execute("DELETE FROM raw_del", [])?;
                {
                    // 문장 준비를 한 번만(지울 행이 수만 개)
                    let mut ins = tx.prepare_cached("INSERT INTO raw_del(id) VALUES (?1)")?;
                    for id in &victims {
                        ins.execute(params![id])?;
                    }
                }
                rep.raw_deleted_by_size = victims.len();
                delete_raw_del(&tx)?;
            }
            total_after = total;
        }
    }
    rep.raw_bytes_after = total_after;
    rep.ms_size = ms(t2);
    let t3 = std::time::Instant::now();

    // 5) 고아 노드 삭제. 출신 기록이 가리키는 파일 노드와, 그 파일의 executed_as 선은 보존.
    //    이번 정리에서 선·요약을 지운 것이 없으면 새 고아도 없다 — 표 넷을 훑는 질의를 건너뛴다
    let removed = rep.edges_compacted
        + rep.provenance_deleted
        + rep.suspicious_deleted
        + rep.summaries_deleted;
    if removed > 0 {
        rep.nodes_deleted = tx.execute(
            "DELETE FROM nodes WHERE id NOT IN (SELECT src FROM edges)
            AND id NOT IN (SELECT dst FROM edges)
            AND id NOT IN (SELECT src FROM daily_summary)
            AND id NOT IN (SELECT dst FROM daily_summary)
            AND id NOT IN (SELECT file_node FROM origins)",
            [],
        )?;
    }
    rep.ms_nodes = ms(t3);
    // 선·노드·근거(원시 기록) 중 하나라도 지웠으면 증분 판정이 메모리 뷰를 버리고 전체를 다시 읽는다
    let changed = rep.edges_compacted
        + rep.provenance_deleted
        + rep.suspicious_deleted
        + rep.nodes_deleted
        + rep.raw_deleted
        + rep.raw_deleted_by_size
        > 0;
    crate::changes::end_bulk(&tx, changed)?;
    // 시간대별 트래픽 요약은 연결 요약과 같은 기간(summary_days) 보관
    let hourly_before_unix = (now - policy.summary_days * DAY) / 10_000_000 - 11_644_473_600;
    tx.execute(
        "DELETE FROM traffic_hourly WHERE hour < ?1",
        params![hourly_before_unix],
    )?;
    tx.commit()?;
    Ok(rep)
}

fn count_raw_del(tx: &rusqlite::Connection) -> Result<usize> {
    Ok(tx.query_row("SELECT COUNT(*) FROM raw_del", [], |r| r.get::<_, i64>(0))? as usize)
}

/// raw_del 에 모인 id 를 지우고 선의 근거 참조를 끊는다
fn delete_raw_del(tx: &rusqlite::Connection) -> Result<()> {
    tx.execute(
        "UPDATE edges SET evidence_id = NULL WHERE evidence_id IN (SELECT id FROM raw_del)",
        [],
    )?;
    tx.execute(
        "DELETE FROM edge_evidence WHERE raw_id IN (SELECT id FROM raw_del)",
        [],
    )?;
    tx.execute(
        "DELETE FROM raw_events WHERE id IN (SELECT id FROM raw_del)",
        [],
    )?;
    Ok(())
}

/// 요약 한 줄 (시간 막대·"오늘의 일기" 축약용)
#[derive(Debug, Clone, serde::Serialize)]
pub struct DailySummary {
    pub day: i64,
    pub src: i64,
    pub dst: i64,
    pub rel: String,
    pub count: i64,
    pub first_ts: i64,
    pub last_ts: i64,
}

pub fn summaries_between(store: &Store, from_day: i64, to_day: i64) -> Result<Vec<DailySummary>> {
    store.conn.execute_batch(SUMMARY_DDL)?;
    let mut st = store.conn.prepare(
        "SELECT day, src, dst, rel, count, first_ts, last_ts FROM daily_summary
         WHERE day BETWEEN ?1 AND ?2 ORDER BY day, first_ts",
    )?;
    let rows = st.query_map(params![from_day, to_day], |r| {
        Ok(DailySummary {
            day: r.get(0)?,
            src: r.get(1)?,
            dst: r.get(2)?,
            rel: r.get(3)?,
            count: r.get(4)?,
            first_ts: r.get(5)?,
            last_ts: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}
