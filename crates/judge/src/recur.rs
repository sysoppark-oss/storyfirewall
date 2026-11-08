//! 낮음 반복 승격(개편안 2판 2-2, 42차 Q4): 낮음(Normal) 사건이라도 세 축 중 하나에서 7일 안에 서로 다른 사건 3건이
//! 모이면 중간(Watch)으로 올린다. 경로·이름을 바꿔 가며 다시 뜨는 드로퍼(출처 축 회피)는 접속지·통신 양식 축에 걸린다.
//!
//! 축
//! - 출처: 뿌리 실행 파일의 root_key(경로+서명)
//! - 접속지: 뿌리 사슬이 접속한 원격지(도메인이 있으면 도메인, 없으면 ip:port)
//! - 통신 양식: (유입 경로 종류, 목적 포트) — 주기 버킷은 접속 시각 묶음(10분 단위 간격)으로 대신한다
//!
//! 판정은 메모리 뷰에서만 한다(DB 쓰기 없음). 승격 사유에는 어느 축이 묶였는지 적는다.
use std::collections::{HashMap, HashSet};

use crate::rules::{attr_str, RootKind};
use crate::score::{Level, Reason, LEVEL_BOUNDS};
use crate::{Story, View};

/// 7일(FILETIME 단위)
pub const WINDOW_FT: i64 = 7 * 86_400 * 10_000_000;
/// 승격 문턱: 서로 다른 사건 수
pub const THRESHOLD: usize = 3;

/// 한 사건의 축 키들(출처 1개, 접속지 0~n개, 통신 양식 0~n개)
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Keys {
    pub origin: Option<String>,
    pub remotes: Vec<String>,
    pub shapes: Vec<String>,
}

/// 사건의 축 키 뽑기(뷰에서). `procs` 는 사슬에 든 프로세스 노드들
pub fn keys_of(view: &View, root: i64, procs: &[i64], kind: RootKind) -> Keys {
    let mut k = Keys::default();
    if let Some(f) = view.image_file(root) {
        k.origin = Some(crate::baseline::root_key(f));
    }
    let mut remotes = HashSet::new();
    let mut shapes = HashSet::new();
    let mut last_ts: Option<i64> = None;
    for &p in procs {
        for e in view.outs(p) {
            if e.rel != "connected" {
                continue;
            }
            let dst = view.node(e.dst);
            if dst.kind != "remote" {
                continue;
            }
            let dom = attr_str(dst, "domain").filter(|d| !d.is_empty());
            remotes.insert(match dom {
                Some(d) => format!("d:{}", d.to_ascii_lowercase()),
                None => format!("r:{}", dst.key),
            });
            // 통신 양식: 유입 종류 + 목적 포트 + 직전 접속과의 간격(10분 단위) — 같은 모양이면 같은 키
            let port = dst.key.rsplit(':').next().unwrap_or("").to_string();
            let gap_bucket = last_ts
                .map(|t| ((e.ts - t) / (600 * 10_000_000)).max(0))
                .unwrap_or(-1);
            last_ts = Some(e.ts);
            shapes.insert(format!("s:{:?}:{}:{}", kind, port, gap_bucket));
        }
    }
    k.remotes = remotes.into_iter().collect();
    k.shapes = shapes.into_iter().collect();
    k
}

/// 낮음 사건들에 반복 승격을 적용한다. `ts_of[i]` 는 사건의 마지막 시각(FILETIME), `now` 기준 7일 안만 센다.
/// 돌려주는 값: 올린 사건 수
pub fn apply(stories: &mut [Story], keys: &[Keys], ts_of: &[i64], now: i64) -> usize {
    debug_assert_eq!(stories.len(), keys.len());
    // 축 키 → 서로 다른 뿌리 집합 (낮음이면서 7일 안인 사건만)
    let mut by_key: HashMap<&str, HashSet<i64>> = HashMap::new();
    for (i, s) in stories.iter().enumerate() {
        if s.level != Level::Normal || now - ts_of[i] > WINDOW_FT {
            continue;
        }
        let k = &keys[i];
        for key in k
            .origin
            .iter()
            .chain(k.remotes.iter())
            .chain(k.shapes.iter())
        {
            by_key.entry(key.as_str()).or_default().insert(s.root);
        }
    }
    let mut raised = 0;
    for (i, s) in stories.iter_mut().enumerate() {
        if s.level != Level::Normal || now - ts_of[i] > WINDOW_FT {
            continue;
        }
        let k = &keys[i];
        let hit = |keys: &[String]| {
            keys.iter()
                .filter_map(|x| by_key.get(x.as_str()))
                .map(|set| set.len())
                .max()
                .unwrap_or(0)
        };
        let origin_n = k
            .origin
            .as_ref()
            .map(|o| by_key.get(o.as_str()).map_or(0, |s| s.len()))
            .unwrap_or(0);
        let remote_n = hit(&k.remotes);
        let shape_n = hit(&k.shapes);
        let (axis, n): (&'static str, usize) = if origin_n >= THRESHOLD {
            ("반복 징후(같은 출처, 7일)", origin_n)
        } else if remote_n >= THRESHOLD {
            ("반복 징후(같은 접속지, 7일)", remote_n)
        } else if shape_n >= THRESHOLD {
            ("반복 징후(같은 통신 양식, 7일)", shape_n)
        } else {
            continue;
        };
        let target = LEVEL_BOUNDS.0;
        let delta = target as i32 - s.score as i32;
        if delta > 0 {
            s.score = target;
        }
        s.level = Level::Watch;
        s.reasons.push(Reason {
            points: delta.max(0),
            what: axis,
            edge_id: None,
            node_id: Some(s.root),
        });
        let _ = n;
        raised += 1;
    }
    raised
}
