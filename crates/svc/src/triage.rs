//! 사건 추적 — 처리 상태와 처리 기록 (사용자 "분류된 사건에 대한 추적이 반듯이 필요함" 2026-11-07)
//!
//! - 상태: 새 사건(행 없음) → 조사됨 → 조치함[정상·끊음·지켜보기] → 닫힘. 어느 상태에서든 조치·닫기는 된다.
//! - DB 쓰기는 조치(상태 바꿈)할 때만. 조회(story.events)는 읽기만 한다.
//! - 처리 기록(incident_log)은 1년 보관(보관 정리 때 지움). 상태 행은 뿌리 노드가 지워지면 함께 지운다.
//! - 재발: 조치함·닫힘인 사건이 조치 시점보다 높은 장까지 이어지면 "새 사건"으로 되돌리고 기록에 남긴다(주기 판정에서).
//!   같은 장에서의 반복(같은 접속 N번)은 재발로 보지 않는다 — 장이 올라간 것만.
//! - 알림은 처리 안 한 사건(새 사건·조사됨)만. 조치함·닫힘은 재발로 되돌아올 때 다시 알린다.

use std::collections::HashMap;

use graph::store::Store;

pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS incident_state (
  root        INTEGER PRIMARY KEY,
  state       TEXT NOT NULL,           -- investigated | acted | closed (새 사건 = 행 없음 또는 'new')
  action      TEXT,                    -- acted 일 때: normal | cut | watch
  chapter     INTEGER NOT NULL,        -- 상태를 바꾼 시점의 장 (재발 판단)
  score       INTEGER NOT NULL DEFAULT 0,
  updated_ts  INTEGER NOT NULL,        -- unix 초
  note        TEXT
);
CREATE TABLE IF NOT EXISTS incident_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  root    INTEGER NOT NULL,
  ts      INTEGER NOT NULL,            -- unix 초
  state   TEXT NOT NULL,
  action  TEXT,
  actor   TEXT NOT NULL,
  note    TEXT
);
CREATE INDEX IF NOT EXISTS incident_log_root ON incident_log(root, ts);
"#;

/// 처리 기록 보관 일수
pub const LOG_KEEP_DAYS: i64 = 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    New,
    Investigated,
    Acted,
    Closed,
}
impl State {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "new" => State::New,
            "investigated" => State::Investigated,
            "acted" => State::Acted,
            "closed" => State::Closed,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            State::New => "new",
            State::Investigated => "investigated",
            State::Acted => "acted",
            State::Closed => "closed",
        }
    }
    /// 처리 안 한 사건인가 (알림·기본 필터 기준)
    pub fn is_open(self) -> bool {
        matches!(self, State::New | State::Investigated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Normal,
    Cut,
    Watch,
}
impl Action {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "normal" => Action::Normal,
            "cut" => Action::Cut,
            "watch" => Action::Watch,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Normal => "normal",
            Action::Cut => "cut",
            Action::Watch => "watch",
        }
    }
}

/// 사건 하나의 처리 상태 (화면용)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Rec {
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    pub chapter: i64,
    pub updated_ts: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
impl Rec {
    pub fn new_default() -> Self {
        Rec {
            state: State::New,
            action: None,
            chapter: 0,
            updated_ts: 0,
            note: None,
        }
    }
}

/// 처리 기록 한 줄
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LogRow {
    pub id: i64,
    pub ts: i64,
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// 상태별 개수 (화면 위 요약)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Counts {
    pub new: usize,
    pub investigated: usize,
    pub acted: usize,
    pub closed: usize,
}
impl Counts {
    pub fn add(&mut self, s: State) {
        match s {
            State::New => self.new += 1,
            State::Investigated => self.investigated += 1,
            State::Acted => self.acted += 1,
            State::Closed => self.closed += 1,
        }
    }
    pub fn open(&self) -> usize {
        self.new + self.investigated
    }
}

/// 필터 (story.events `triage`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// 처리 안 한 사건 (새 사건·조사됨) — 기본
    Open,
    /// 처리한 사건 (조치함·닫힘)
    Done,
    All,
}
impl Filter {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "open" => Filter::Open,
            "done" => Filter::Done,
            "all" => Filter::All,
            _ => return None,
        })
    }
    pub fn keeps(self, s: State) -> bool {
        match self {
            Filter::Open => s.is_open(),
            Filter::Done => !s.is_open(),
            Filter::All => true,
        }
    }
}

fn graph_err(e: graph::GraphError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

pub fn ensure_table(store: &Store) {
    let _ = store.conn().execute_batch(DDL);
}

fn row_to_rec(r: &rusqlite::Row) -> rusqlite::Result<Rec> {
    let st: String = r.get(0)?;
    let ac: Option<String> = r.get(1)?;
    Ok(Rec {
        state: State::parse(&st).unwrap_or(State::New),
        action: ac.as_deref().and_then(Action::parse),
        chapter: r.get(2)?,
        updated_ts: r.get(3)?,
        note: r.get(4)?,
    })
}

/// 뿌리 하나의 상태 (행이 없으면 새 사건)
pub fn get(store: &Store, root: i64) -> Rec {
    store
        .conn()
        .query_row(
            "SELECT state, action, chapter, updated_ts, note FROM incident_state WHERE root = ?1",
            [root],
            |r| row_to_rec(r),
        )
        .unwrap_or_else(|_| Rec::new_default())
}

/// 상태가 있는 사건 전부 (조회 한 번으로 — story.events 가 사건마다 묻지 않게)
pub fn all(store: &Store) -> HashMap<i64, Rec> {
    let mut out = HashMap::new();
    let Ok(mut st) = store
        .conn()
        .prepare("SELECT root, state, action, chapter, updated_ts, note FROM incident_state")
    else {
        return out;
    };
    let rows = st.query_map([], |r| {
        let root: i64 = r.get(0)?;
        let st: String = r.get(1)?;
        let ac: Option<String> = r.get(2)?;
        Ok((
            root,
            Rec {
                state: State::parse(&st).unwrap_or(State::New),
                action: ac.as_deref().and_then(Action::parse),
                chapter: r.get(3)?,
                updated_ts: r.get(4)?,
                note: r.get(5)?,
            },
        ))
    });
    if let Ok(rows) = rows {
        for (root, rec) in rows.flatten() {
            out.insert(root, rec);
        }
    }
    out
}

/// 상태 바꾸기 + 기록 한 줄. 같은 상태·같은 조치로 다시 부르면 기록만 남기지 않고 시각만 갱신한다(두 번 눌러도 기록이 불지 않게)
#[allow(clippy::too_many_arguments)]
pub fn set(
    store: &Store,
    root: i64,
    state: State,
    action: Option<Action>,
    chapter: i64,
    score: u8,
    actor: &str,
    note: Option<&str>,
    now: i64,
) -> rusqlite::Result<Rec> {
    let cur = get(store, root);
    let same = cur.state == state && cur.action == action && cur.state != State::New;
    let tx = store.begin_write().map_err(graph_err)?;
    tx.execute(
        "INSERT INTO incident_state(root, state, action, chapter, score, updated_ts, note) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(root) DO UPDATE SET state = excluded.state, action = excluded.action, chapter = excluded.chapter,
           score = excluded.score, updated_ts = excluded.updated_ts, note = excluded.note",
        rusqlite::params![root, state.as_str(), action.map(|a| a.as_str()), chapter, score as i64, now, note],
    )?;
    if !same {
        tx.execute(
            "INSERT INTO incident_log(root, ts, state, action, actor, note) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![root, now, state.as_str(), action.map(|a| a.as_str()), actor, note],
        )?;
    }
    tx.commit().map_err(graph_err)?;
    Ok(Rec {
        state,
        action,
        chapter,
        updated_ts: now,
        note: note.map(|s| s.to_string()),
    })
}

/// 재발: 조치함·닫힘인 사건이 조치 때보다 높은 장까지 이어졌다 → 새 사건으로 되돌리고 기록. 되돌렸으면 true
pub fn recur_if_escalated(
    store: &Store,
    root: i64,
    rec: &Rec,
    chapter: i64,
    score: u8,
    now: i64,
) -> bool {
    if rec.state.is_open() || chapter <= rec.chapter {
        return false;
    }
    let note = format!(
        "재발: {}장에서 조치했는데 {}장까지 이어짐",
        rec.chapter, chapter
    );
    set(
        store,
        root,
        State::New,
        None,
        chapter,
        score,
        "system",
        Some(&note),
        now,
    )
    .is_ok()
}

/// 처리 기록 (최신 먼저)
pub fn log(store: &Store, root: i64, limit: usize) -> Vec<LogRow> {
    let Ok(mut st) = store.conn().prepare(
        "SELECT id, ts, state, action, actor, note FROM incident_log WHERE root = ?1 ORDER BY ts DESC, id DESC LIMIT ?2",
    ) else {
        return Vec::new();
    };
    let rows = st.query_map(rusqlite::params![root, limit as i64], |r| {
        let st: String = r.get(2)?;
        let ac: Option<String> = r.get(3)?;
        Ok(LogRow {
            id: r.get(0)?,
            ts: r.get(1)?,
            state: State::parse(&st).unwrap_or(State::New),
            action: ac.as_deref().and_then(Action::parse),
            actor: r.get(4)?,
            note: r.get(5)?,
        })
    });
    rows.map(|it| it.flatten().collect()).unwrap_or_default()
}

/// 보관 정리: 1년 넘은 기록, 뿌리 노드가 사라진 상태 행
pub fn prune(store: &Store, now: i64) -> rusqlite::Result<(usize, usize)> {
    let cutoff = now - LOG_KEEP_DAYS * 86_400;
    let a = store
        .conn()
        .execute("DELETE FROM incident_log WHERE ts < ?1", [cutoff])?;
    let b = store.conn().execute(
        "DELETE FROM incident_state WHERE root NOT IN (SELECT id FROM nodes)",
        [],
    )?;
    Ok((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Store {
        let s = Store::open_in_memory().expect("mem");
        ensure_table(&s);
        s
    }

    #[test]
    fn new_then_act_then_close_logs_each_step() {
        let s = mem();
        assert_eq!(get(&s, 7).state, State::New);
        set(&s, 7, State::Investigated, None, 2, 50, "ui", None, 100).unwrap();
        set(&s, 7, State::Acted, Some(Action::Watch), 3, 72, "user", Some("지켜봄"), 200).unwrap();
        // 같은 상태를 두 번: 기록은 한 줄만
        set(&s, 7, State::Acted, Some(Action::Watch), 3, 72, "user", Some("지켜봄"), 210).unwrap();
        set(&s, 7, State::Closed, None, 3, 72, "user", None, 300).unwrap();
        let r = get(&s, 7);
        assert_eq!(r.state, State::Closed);
        assert_eq!(r.updated_ts, 300);
        let l = log(&s, 7, 10);
        assert_eq!(l.len(), 3);
        assert_eq!(l[0].state, State::Closed);
        assert_eq!(l[2].state, State::Investigated);
        assert_eq!(all(&s).len(), 1);
    }

    #[test]
    fn recur_only_when_chapter_rises() {
        let s = mem();
        set(&s, 1, State::Acted, Some(Action::Normal), 3, 70, "user", None, 10).unwrap();
        let r = get(&s, 1);
        assert!(!recur_if_escalated(&s, 1, &r, 3, 75, 20), "같은 장은 재발 아님");
        assert!(recur_if_escalated(&s, 1, &r, 4, 80, 30));
        let r2 = get(&s, 1);
        assert_eq!(r2.state, State::New);
        assert_eq!(r2.chapter, 4);
        assert!(log(&s, 1, 10)[0].note.as_deref().unwrap().starts_with("재발"));
        // 열린 사건은 재발 판단 대상이 아니다
        assert!(!recur_if_escalated(&s, 1, &r2, 4, 80, 40));
    }

    #[test]
    fn filter_and_counts() {
        let mut c = Counts::default();
        for st in [State::New, State::Investigated, State::Acted, State::Closed, State::New] {
            c.add(st);
        }
        assert_eq!(c.open(), 3);
        assert!(Filter::Open.keeps(State::Investigated));
        assert!(!Filter::Open.keeps(State::Acted));
        assert!(Filter::Done.keeps(State::Closed));
        assert!(Filter::All.keeps(State::New));
    }

    #[test]
    fn prune_old_log_and_orphan_state() {
        let s = mem();
        set(&s, 99, State::Closed, None, 2, 10, "u", None, 1_000).unwrap();
        let (a, b) = prune(&s, 1_000 + LOG_KEEP_DAYS * 86_400 + 1).unwrap();
        assert_eq!(a, 1, "1년 넘은 기록");
        assert_eq!(b, 1, "노드 없는 뿌리의 상태 행");
        assert_eq!(get(&s, 99).state, State::New);
    }
}
