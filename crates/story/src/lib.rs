//! 이야기 생성기
//!
//! 출처 그래프 → 사실(Fact) 목록 → 장면(Scene) → 문장.
//!
//! 원칙 (이야기형 3판 7장)
//! - 사실은 그래프가 정한다. 이 크레이트는 그래프의 선을 그대로 사실로 옮길 뿐, 새 사실을 만들지 않는다.
//! - 모든 문장은 근거 이벤트 id 를 가진다. 화면은 문장을 누르면 원본 기록을 보여 줄 수 있다.
//! - 의도를 단정하지 않는다. "몰래", "훔치려" 같은 말은 어떤 화법에도 없다.
//! - 평범한 활동은 묶어 짧게, 평소와 다른 장면만 펼친다. (압축은 사실을 줄이는 것이지 바꾸는 것이 아니다)
//!
//! 단계
//! 1. `facts::collect`  그래프 선 → Fact (주어·동사·목적어·시각·근거)
//! 2. `scenes::group`   Fact 를 주인공 프로세스별 장면으로 묶고, 서비스 경유 통신은 원인 프로세스 장면에 합친다
//! 3. `render`          장면 → 문장. 화법 3종(Expert / Plain / OneLine)

pub mod events;
pub mod facts;
pub mod ports;
pub mod render;
pub mod scenes;

pub use events::{narrate, Narrative};
pub use facts::{Fact, Verb};
pub use render::{render, Sentence, Voice};
pub use scenes::{group, Scene};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoryError {
    #[error("graph: {0}")]
    Graph(#[from] graph::GraphError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, StoryError>;

/// 그래프에서 시각 범위의 이야기를 한 번에 만든다.
pub fn tell(store: &graph::Store, from_ts: i64, to_ts: i64, voice: Voice) -> Result<Vec<Sentence>> {
    let facts = facts::collect(store, from_ts, to_ts)?;
    finish(store, &facts, voice)
}

/// L030 "오늘 한 일": 범위 안의 가장 늦은 `max_edges` 개 선만으로 만든다. 잘렸으면 true(화면이 "이전 기록 생략"을 밝힌다)
pub fn tell_recent(
    store: &graph::Store,
    from_ts: i64,
    to_ts: i64,
    voice: Voice,
    max_edges: usize,
) -> Result<(Vec<Sentence>, bool)> {
    let (facts, truncated) = facts::collect_recent(store, from_ts, to_ts, max_edges)?;
    Ok((finish(store, &facts, voice)?, truncated))
}

fn finish(store: &graph::Store, facts: &[facts::Fact], voice: Voice) -> Result<Vec<Sentence>> {
    let scenes = scenes::group(store, facts)?;
    let mut out = render::render(&scenes, voice);
    // 근거 원시 이벤트의 시각·출처를 한 번에 읽어(문장마다 따로 묻지 않는다) 두 표시에 함께 쓴다
    let ids: Vec<i64> = out
        .iter()
        .flat_map(|s| s.evidence.iter().copied())
        .collect();
    let meta = graph::query::raw_meta(store, &ids)?;
    mark_already_open(store, &mut out, &meta);
    for s in out.iter_mut() {
        s.sources = count_sources(
            s.evidence
                .iter()
                .filter_map(|id| meta.get(id).map(|m| m.1.as_str())),
        );
    }
    Ok(out)
}

fn count_sources<'a>(srcs: impl Iterator<Item = &'a str>) -> Vec<(String, u32)> {
    let mut m: std::collections::BTreeMap<String, u32> = Default::default();
    for src in srcs {
        let k = src.split(':').next().unwrap_or(src).to_string();
        *m.entry(k).or_default() += 1;
    }
    let mut v: Vec<(String, u32)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

/// 원시 이벤트 id 들 → 출처별 수. 출처는 앞부분만("etw:process" → "etw", "sysmon:8" → "sysmon")
pub fn sources_of(store: &graph::Store, raw_ids: &[i64]) -> Vec<(String, u32)> {
    match graph::query::raw_meta(store, raw_ids) {
        Ok(meta) => count_sources(
            raw_ids
                .iter()
                .filter_map(|id| meta.get(id).map(|m| m.1.as_str())),
        ),
        Err(_) => Vec::new(),
    }
}

/// 수집 시작(스냅샷) 1분 안의 연결 테이블 폴링만 근거인 문장 = 수집 시작 때 이미 열려 있던 연결(D006-1).
/// 사실은 남기고 표시만 바꾼다(판정·점수와 무관)
fn mark_already_open(
    store: &graph::Store,
    out: &mut [Sentence],
    meta: &std::collections::HashMap<i64, (i64, String)>,
) {
    const WINDOW: i64 = 60 * 10_000_000;
    // 스냅샷 시각(서비스 시작마다 하나)을 한 번만 읽는다(부분 색인 ix_raw_snapshot)
    let snaps: Vec<i64> = store
        .conn()
        .prepare("SELECT DISTINCT ts FROM raw_events WHERE source = 'snapshot'")
        .and_then(|mut st| st.query_map([], |r| r.get(0))?.collect())
        .unwrap_or_default();
    if snaps.is_empty() {
        return;
    }
    let first_poll = |raw: &i64| -> bool {
        matches!(meta.get(raw), Some((ts, src)) if src == "conntable" && snaps.iter().any(|sn| *sn <= *ts && *ts - sn <= WINDOW))
    };
    for s in out.iter_mut() {
        s.already_open = !s.evidence.is_empty() && s.evidence.iter().all(first_poll);
    }
}
