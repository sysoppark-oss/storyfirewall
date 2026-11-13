//! 50차 2단계: 이야기 목록(story.events, 전체 구간)을 엔진 스레드 밖 조회 작업자에서 답한다.
//!
//! - 엔진은 주기 판정 결과가 바뀔 때 **조회용 스냅숏**(바뀌지 않는 값)을 만들어 문(Gate)에 내놓는다.
//!   스냅숏: 사건 목록(Arc)·판정 세대·시각, 세션 가리기용 조각(선의 양 끝, 노드 종류·세션), 정상 처리 단위 문구, 살아 있음 확인 함수.
//! - 조회 작업자는 스냅숏 + 읽기 전용 연결 + 함께 쓰는 문장 캐시로 답한다(DB 에 쓰지 않는다).
//! - 엔진이 직접 답하는 경우(메모리 DB 시험·구간 지정 since_ts ≠ 0·작업자 없음)도 같은 본체(`page`)를 쓴다.
//!
//! 세션 가리기는 보안 경계다: 스냅숏에서 세션을 모르는 프로세스·스냅숏에 없는 노드는 DB 의 지금 값으로 다시 본다
//! (`StoryVisibility::compute_with`). 스냅숏이 "세션 모름 = 보임"으로 굳는 순서가 없게 한다.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use api::methods::StoryEventsParams;
use api::{ErrorCode, Page, RpcError};
use graph::store::Store;

use crate::dispatch::{Caller, StoryVisibility};

/// 문장 캐시 열쇠: (뿌리, 화법, 사건 내용 해시)
pub type NarrKey = (i64, String, u64);
/// 문장 캐시: 열쇠 → (만든 시각 엔진 wall, 문장). 엔진·문장 스레드·조회 작업자가 함께 쓴다.
/// 넣고 꺼낼 때만 잠그고, 문장을 만드는 동안은 쥐지 않는다(50차 Q4)
pub type NarrCache = Arc<Mutex<HashMap<NarrKey, (i64, story::events::Narrative)>>>;

/// 문장 캐시: 10분 지나면 다시 만든다(실행 횟수 등 사건 밖 숫자), 최대 칸 수
pub const NARR_TTL_SECS: i64 = 600;
pub const NARR_CAP: usize = 4096;

/// 캐시에 있고 살아 있으면 그 문장(만들지 않는다)
pub fn cache_peek(c: &NarrCache, key: &NarrKey, now: i64) -> Option<story::events::Narrative> {
    let g = c.lock().ok()?;
    g.get(key)
        .filter(|(t, _)| now - *t < NARR_TTL_SECS && now >= *t)
        .map(|(_, n)| n.clone())
}

/// 만든 문장을 넣는다. 오래된 칸은 버리고, 그래도 많으면(사건이 아주 많은 PC) 통째로 비운다 — 메모리 상한
pub fn cache_put(c: &NarrCache, now: i64, items: Vec<(NarrKey, story::events::Narrative)>) {
    let Ok(mut g) = c.lock() else {
        return;
    };
    for (k, n) in items {
        if g.len() >= NARR_CAP {
            g.retain(|_, (t, _)| now - *t < NARR_TTL_SECS && now >= *t);
            if g.len() >= NARR_CAP {
                g.clear();
            }
        }
        g.insert(k, (now, n));
    }
}

/// 세션 가리기에 필요한 노드 사실
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeSeen {
    /// 프로세스가 아닌 노드(파일·원격지 등) — 늘 보임
    Other,
    /// 프로세스: 세션(모르면 None → 가리기는 DB 의 지금 값으로 다시 본다)
    Process(Option<u64>),
}

impl NodeSeen {
    pub fn of(n: &graph::Node) -> Self {
        if n.kind != graph::NodeKind::Process.as_str() {
            return Self::Other;
        }
        Self::Process(n.attr("session").and_then(|v| v.as_u64()))
    }
}

/// 조회용 스냅숏(바뀌지 않는다). 엔진이 판정 결과가 바뀔 때 새로 만들어 바꿔 끼운다
pub struct StorySnap {
    /// 판정 결과 세대(world.judged_gen)
    pub gen: u64,
    /// 판정 결과를 넣은 엔진 벽시각(unix 초)
    pub at: i64,
    pub stories: Arc<Vec<judge::Story>>,
    /// 사건에 든 선 → (src, dst). 판정 그래프에 없던 선은 빠진다(조회 때 DB)
    ends: HashMap<i64, (i64, i64)>,
    /// 사건에 든 노드 → 종류·세션. 세션을 모르는 프로세스는 넣지 않는다(조회 때 DB)
    nodes: HashMap<i64, NodeSeen>,
    /// 프로세스 뿌리 (다)·(라)·(바) → (부모를 아는가, 정상 처리 단위 문구)
    chain_units: HashMap<i64, (bool, String)>,
    /// 지금 실행 중인지 확인(Windows). None = 실행 중 아님으로 본다
    live: Option<crate::host::LiveProbe>,
}

impl StorySnap {
    /// 판정 결과와 그 판정이 본 그래프(view, 없으면 None — 가리기는 모두 DB)로 만든다
    pub fn build(
        gen: u64,
        at: i64,
        stories: Arc<Vec<judge::Story>>,
        view: Option<&judge::View>,
        live: Option<crate::host::LiveProbe>,
    ) -> Self {
        let mut ends = HashMap::new();
        let mut nodes = HashMap::new();
        let mut chain_units = HashMap::new();
        if let Some(v) = view {
            let put_node = |id: i64, nodes: &mut HashMap<i64, NodeSeen>| {
                if nodes.contains_key(&id) {
                    return;
                }
                if let Some(n) = v.nodes.get(&id) {
                    let seen = NodeSeen::of(n);
                    // 세션 모르는 프로세스는 굳히지 않는다(49차 덧붙임: 낡은 그래프 + 세션 없음)
                    if seen != NodeSeen::Process(None) {
                        nodes.insert(id, seen);
                    }
                }
            };
            for s in stories.iter() {
                put_node(s.root, &mut nodes);
                for e in &s.edges {
                    if ends.contains_key(e) {
                        continue;
                    }
                    if let Some(ed) = v.edge(*e) {
                        ends.insert(*e, (ed.src, ed.dst));
                        put_node(ed.src, &mut nodes);
                        put_node(ed.dst, &mut nodes);
                    }
                }
                if matches!(
                    s.root_kind,
                    judge::RootKind::IsolatedSvchost
                        | judge::RootKind::LolbinFromDocApp
                        | judge::RootKind::RecoveryInhibit
                ) {
                    if let Some(u) = v.chain_unit(s.root) {
                        chain_units.insert(s.root, (u.parent.is_some(), u.label()));
                    }
                }
            }
        }
        Self {
            gen,
            at,
            stories,
            ends,
            nodes,
            chain_units,
            live,
        }
    }
}

/// 이야기 목록 본체가 엔진·작업자에 따라 다르게 하는 일
pub(crate) trait Source {
    fn store(&self) -> &Store;
    /// 세션 범위 가리기
    fn visibility(
        &self,
        scope: crate::dispatch::Scope,
        stories: &[judge::Story],
        min: u8,
    ) -> StoryVisibility;
    /// 캐시에 있으면 그 문장
    fn peek(&self, voice: &str, s: &judge::Story) -> Option<story::events::Narrative>;
    /// 메모리 DB(시험)만: 조회 안에서 문장을 만든다. None = 이 길에서는 만들지 않는다(파일 DB)
    fn make_now(
        &mut self,
        voice: &str,
        s: &judge::Story,
    ) -> Option<Result<story::events::Narrative, RpcError>>;
    /// 프로세스 뿌리의 정상 처리 단위 (부모를 아는가, 문구)
    fn chain_unit(&self, s: &judge::Story) -> Option<(bool, String)>;
    /// 지금 실행 중인가
    fn live(&self, d: &graph::views::ProcessDetail) -> serde_json::Value;
    /// 처리 시간 기록(단계 이름)
    fn record(&mut self, stage: &'static str, d: std::time::Duration);
}

/// 살아 있음 표시: 끝남 기록이 있으면 끝남, 없으면 지금 그 PID 가 같은 프로세스로 살아 있는가
pub(crate) fn live_json(
    d: &graph::views::ProcessDetail,
    probe: &dyn Fn(u32, i64, i64) -> Option<(String, i64)>,
) -> serde_json::Value {
    let running = !d.ended && probe(d.pid, d.create_ts, d.node.first_ts).is_some();
    serde_json::json!({ "running": running, "pid": d.pid, "ended": d.ended })
}

/// 조회 안에서 새 문장을 만드는 데 쓰는 최대 시간(메모리 DB 시험만)
const NARR_QUERY_BUDGET: std::time::Duration = std::time::Duration::from_millis(1000);
/// 큰 사건(선 수) — 조회 안에서 만들지 않는다
pub(crate) const BIG_STORY_EDGES: usize = 1000;

/// story.events 본체. 반환: (응답, 문장을 아직 못 만든 사건 수 — 0 보다 크면 부른 쪽이 미리 만들기를 부탁한다)
pub(crate) fn page(
    src: &mut dyn Source,
    stories: &[judge::Story],
    v: &StoryEventsParams,
    caller: &Caller,
) -> Result<(serde_json::Value, usize), RpcError> {
    let t_filter = std::time::Instant::now();
    // 등급으로 거른다(점수가 아니라): 5장 심각은 점수 70~89 라도 심각이다
    let min = judge::Level::parse(&v.level_min)
        .unwrap_or(judge::Level::Suspicious)
        .rank();
    let scope = caller.scope();
    // 사건 추적: 처리 상태는 한 번에 읽고(사건마다 묻지 않는다), 수준·범위를 거른 뒤 상태별 개수를 센 다음 필터를 건다
    let triage_all = crate::triage::all(src.store());
    let triage_filter =
        crate::triage::Filter::parse(&v.triage).unwrap_or(crate::triage::Filter::Open);
    let mut counts = crate::triage::Counts::default();
    // diag-191: 판정 그래프(또는 스냅숏)에서 한 번에 가린다(없는 것만 DB 묶음 조회)
    let t_vis = std::time::Instant::now();
    let vis = src.visibility(scope, stories, min);
    src.record("보임 가리기", t_vis.elapsed());
    // 개편안 2판 2-2(낮음 요약 칩): 등급 필터에 걸려 숨긴 미조치 사건 수 — 숨겨도 존재는 알린다
    let state_of = |root: i64| {
        triage_all
            .get(&root)
            .map_or(crate::triage::State::New, |r| r.state)
    };
    let hidden_low = stories
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            s.level.rank() < min && vis.root_ok(*i) && triage_filter.keeps(state_of(s.root))
        })
        .count();
    // A30: 다른 사용자 세션의 프로세스가 든 이야기는 통째로 숨긴다
    let kept: Vec<&judge::Story> = stories
        .iter()
        .enumerate()
        .filter(|(i, s)| s.level.rank() >= min && vis.all_ok(*i))
        .map(|(_, s)| s)
        .filter(|s| {
            let st = state_of(s.root);
            counts.add(st);
            triage_filter.keeps(st)
        })
        .collect();
    let cur = v.cursor.clone().normalized();
    let start = cur
        .after
        .as_deref()
        .and_then(|a| a.parse::<usize>().ok())
        .unwrap_or(0);
    // L043·L044: 이 쪽에 보일 것만 문장으로
    let page_stories: Vec<&judge::Story> = kept
        .iter()
        .skip(start)
        .take(cur.limit + 1)
        .copied()
        .collect();
    src.record("거르기", t_filter.elapsed());

    let t_narr = std::time::Instant::now();
    let mut nar: Vec<story::events::Narrative> = Vec::with_capacity(page_stories.len());
    // diag-170·184·186: 조회 안에서는 ① 캐시 ② (메모리 DB 시험만) 예산 안의 작은 사건 ③ 아니면 선을 훑지 않는 한 줄(OneLine)
    // 로 대신 담고 partial — 목록의 사건 수는 늘 완전하고 설명만 미리 만들기가 이어서 채운다
    let mut pending = 0usize;
    let mut partial_roots: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for s in &page_stories {
        if let Some(n) = src.peek(&v.voice, s) {
            nar.push(n);
            continue;
        }
        if t_narr.elapsed() < NARR_QUERY_BUDGET && s.edges.len() < BIG_STORY_EDGES {
            if let Some(r) = src.make_now(&v.voice, s) {
                nar.push(r?);
                continue;
            }
        }
        pending += 1;
        partial_roots.insert(s.root);
        let n = story::narrate(src.store(), std::slice::from_ref(*s), story::Voice::OneLine)
            .map_err(|e| RpcError::with(ErrorCode::Internal, e.to_string()))?
            .pop()
            .ok_or_else(|| RpcError::with(ErrorCode::Internal, "narrate"))?;
        nar.push(n);
    }
    src.record("문장", t_narr.elapsed());

    let t_extra = std::time::Instant::now();
    let g = src.store();
    let mut slice: Vec<serde_json::Value> = Vec::with_capacity(nar.len());
    for n in &nar {
        let mut v = serde_json::to_value(n).unwrap_or_default();
        if partial_roots.contains(&n.root) {
            // 설명을 아직 만드는 중(한 줄 요약만) — 화면은 "설명 준비 중"으로
            v["partial"] = serde_json::json!(true);
        }
        // D020-1: 뿌리가 Windows 핵심 프로세스면 화면이 "끊기" 대신 "이 접속지만 차단"을 보이고 서명·위치를 밝힌다
        let root_kind = g.node(n.root).map(|x| x.kind).unwrap_or_default();
        let story_of = page_stories.iter().find(|s| s.root == n.root);
        // 정상 처리(judge.feedback_normal)는 파일 뿌리만 된다 — 화면이 단추를 숨긴다
        // L063: 금고 경비 사건(프로세스 뿌리)도 정상 처리 가능(그 판정에 한정)
        let vault = story_of.is_some_and(|s| s.root_kind == judge::RootKind::VaultAccess);
        // 프로세스 뿌리 (다)·(라)·(바): 정상 처리 단위 = 부모 → 도구 → 띄운 프로그램
        let chain_unit = story_of.and_then(|s| src.chain_unit(s));
        // 39차 Q1②: 부모를 모르면 단추를 숨기고 이유를 보인다
        let chain_ok = chain_unit
            .as_ref()
            .is_some_and(|(has_parent, _)| *has_parent);
        v["feedback_ok"] = serde_json::json!(root_kind == "file" || vault || chain_ok);
        match chain_unit {
            Some((true, u)) => v["feedback_unit"] = serde_json::json!(u),
            Some((false, _)) => {
                v["feedback_note"] = serde_json::json!(
                    "이 도구를 실행한 프로그램을 알 수 없어(수집 전부터 실행 중) '정상'으로 표시할 수 없습니다."
                )
            }
            None => {}
        }
        // 사건 추적: 처리 상태(없으면 새 사건)
        v["triage"] = serde_json::to_value(
            triage_all
                .get(&n.root)
                .cloned()
                .unwrap_or_else(crate::triage::Rec::new_default),
        )
        .unwrap_or_default();
        // 프로세스 뿌리만 process_detail(파일 노드에도 Ok 를 돌려주지만 경로가 빈다 — L046 "위치 줄 없음")
        let pd = if root_kind == "process" {
            graph::views::process_detail(g, n.root, 0).ok()
        } else {
            None
        };
        if let Some(d) = pd {
            v["root_chain"] = crate::dispatch::chain_line(g, n.root);
            v["root_live"] = src.live(&d);
            v["root_core"] = serde_json::json!(graph::views::is_system_image(&d.image));
            v["root_image"] = serde_json::json!(d.image);
            v["root_signature"] = d.signature.clone().unwrap_or(serde_json::Value::Null);
        } else if let Ok(f) = g.node(n.root) {
            // D039-2: 뿌리가 파일이면 경로·서명은 파일 노드에, 이름 단추는 그 파일로 실행된 가장 최근 프로세스로
            if f.kind == "file" {
                v["root_image"] = serde_json::json!(f.key);
                v["root_signature"] = serde_json::json!({ "signer": f.attr("signer"), "sig_status": f.attr("sig_status"), "issuer": f.attr("issuer") });
                let ex: Option<(i64, i64, i64, i64)> = g
                    .conn()
                    .query_row(
                        "SELECT COUNT(*), MIN(ts), MAX(ts), (SELECT dst FROM edges WHERE src = ?1 AND rel = 'executed_as' ORDER BY ts DESC LIMIT 1) FROM edges WHERE src = ?1 AND rel = 'executed_as'",
                        [f.id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .ok();
                if let Some((c, first, last, latest)) = ex {
                    if let Some(d) = graph::views::process_detail(g, latest, 0)
                        .ok()
                        .filter(|_| latest > 0)
                    {
                        v["root_live"] = src.live(&d);
                        v["root_chain"] = crate::dispatch::chain_line(g, latest);
                    }
                    v["root_exec"] = serde_json::json!({ "count": c, "first_ts": first, "last_ts": last, "latest_proc": latest });
                }
            }
        }
        // 첫 실행 관찰실(17판 23-2 ①): 뿌리 실행 파일을 관찰한 기록이 있으면 카드에 사실 한 줄
        if let Some(w) = v["root_image"]
            .as_str()
            .and_then(|path| crate::first_run::watch_of(g, path))
        {
            v["first_run_watch"] = serde_json::to_value(w).unwrap_or_default();
        }
        // D022-4: 접속지의 등록 국가(발생 시각 목록 줄)
        let egress_ip = n.egress_node.and_then(|id| g.node(id).ok()).and_then(|nd| {
            nd.attr("ip")
                .and_then(|ip| ip.as_str().map(|s| s.to_string()))
        });
        if let Some(w) = egress_ip
            .as_deref()
            .and_then(|ip| geo::global().lookup_str(ip))
        {
            v["egress_where"] = serde_json::to_value(w).unwrap_or_default();
        }
        // 안디옥 인계(변경 제안 2판): 접속지 이름에 짝지어진 숫자 주소 — 주소로 해석되는 값만
        if let Some(ip) = egress_ip.filter(|ip| ip.parse::<std::net::IpAddr>().is_ok()) {
            v["egress_ip"] = serde_json::json!(ip);
        }
        slice.push(v);
    }
    let page = Page::from_overfetch(
        slice.into_iter().enumerate().collect::<Vec<_>>(),
        cur.limit,
        |(i, _)| (start + i + 1).to_string(),
    );
    src.record("부가 정보", t_extra.elapsed());
    // 저장 실패로 버린 구간 (17차 Q3): 이야기 위에 "기록 일부 누락" 표시
    let t_gaps = std::time::Instant::now();
    let gaps = graph::views::gaps_between(src.store(), v.since_ts, i64::MAX).unwrap_or_default();
    src.record("기록 없는 구간", t_gaps.elapsed());
    Ok((
        serde_json::json!({ "items": page.items.into_iter().map(|(_, v)| v).collect::<Vec<_>>(), "next": page.next, "gaps": gaps, "counts": counts, "hidden_low": hidden_low, "pending": pending }),
        pending,
    ))
}

/// 조회 작업자 쪽 출처: 스냅숏 + 읽기 전용 연결 + 함께 쓰는 문장 캐시
pub(crate) struct SnapSource<'a> {
    pub snap: &'a StorySnap,
    pub store: &'a Store,
    pub cache: &'a NarrCache,
    /// 엔진 시계의 벽시각(문장 캐시 수명 판정)
    pub now: i64,
    pub timings: &'a mut Vec<(&'static str, std::time::Duration)>,
}

impl Source for SnapSource<'_> {
    fn store(&self) -> &Store {
        self.store
    }
    fn visibility(
        &self,
        scope: crate::dispatch::Scope,
        stories: &[judge::Story],
        min: u8,
    ) -> StoryVisibility {
        StoryVisibility::compute_with(
            self.store,
            scope,
            stories,
            min,
            &|e| self.snap.ends.get(&e).copied(),
            &|id| self.snap.nodes.get(&id).copied(),
        )
    }
    fn peek(&self, voice: &str, s: &judge::Story) -> Option<story::events::Narrative> {
        cache_peek(self.cache, &crate::dispatch::narr_key(s, voice), self.now)
    }
    fn make_now(
        &mut self,
        _voice: &str,
        _s: &judge::Story,
    ) -> Option<Result<story::events::Narrative, RpcError>> {
        // 파일 DB: 조회 안에서 만들지 않는다(diag-186) — 미리 만들기가 별도 스레드에서 채운다
        None
    }
    fn chain_unit(&self, s: &judge::Story) -> Option<(bool, String)> {
        self.snap.chain_units.get(&s.root).cloned()
    }
    fn live(&self, d: &graph::views::ProcessDetail) -> serde_json::Value {
        let probe = self.snap.live;
        live_json(d, &|p, c, f| probe.and_then(|f2| f2(p, c, f)))
    }
    fn record(&mut self, stage: &'static str, d: std::time::Duration) {
        self.timings.push((stage, d));
    }
}

/// 작업자 길의 단계 이름(진단 처리 시간 표 — 엔진 쪽 "이야기 목록: …"과 구별)
pub(crate) fn reader_stage_name(stage: &'static str) -> &'static str {
    match stage {
        "보임 가리기" => "작업자: 이야기 목록: 보임 가리기",
        "거르기" => "작업자: 이야기 목록: 거르기",
        "문장" => "작업자: 이야기 목록: 문장",
        "부가 정보" => "작업자: 이야기 목록: 부가 정보",
        "기록 없는 구간" => "작업자: 이야기 목록: 기록 없는 구간",
        _ => "작업자: 이야기 목록: 기타",
    }
}

/// 엔진 쪽 단계 이름(전과 같은 이름 — 진단 기록을 이어 볼 수 있게)
pub(crate) fn engine_stage_name(stage: &'static str) -> &'static str {
    match stage {
        "보임 가리기" => "이야기 목록: 보임 가리기",
        "거르기" => "이야기 목록: 거르기",
        "문장" => "이야기 목록: 문장",
        "부가 정보" => "이야기 목록: 부가 정보",
        "기록 없는 구간" => "이야기 목록: 기록 없는 구간",
        _ => "이야기 목록: 기타",
    }
}

/// 조회 작업자: story.events(since_ts == 0). 스냅숏이 아직 없으면 busy "첫 판정을 하는 중"
pub fn story_events(
    store: &Store,
    snap: Option<&StorySnap>,
    cache: &NarrCache,
    now: i64,
    p: serde_json::Value,
    caller: &Caller,
    timings: &mut Vec<(&'static str, std::time::Duration)>,
) -> Result<(serde_json::Value, usize), RpcError> {
    let v: StoryEventsParams = serde_json::from_value(p)
        .map_err(|e| RpcError::with(ErrorCode::InvalidParams, e.to_string()))?;
    if v.since_ts != 0 {
        return Err(RpcError::with(
            ErrorCode::Internal,
            "구간을 지정한 판정은 엔진이 한다",
        ));
    }
    let Some(snap) = snap else {
        return Err(RpcError::with(ErrorCode::Busy, "첫 판정을 하는 중"));
    };
    let stories = snap.stories.clone();
    let mut src = SnapSource {
        snap,
        store,
        cache,
        now,
        timings,
    };
    page(&mut src, &stories, &v, caller)
}
