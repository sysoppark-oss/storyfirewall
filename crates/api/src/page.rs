//! 페이지: 한 쪽 최대 1,000건, `cursor` 는 불투명 문자열(서비스가 만든다). 10차 3장.

use serde::{Deserialize, Serialize};

pub const PAGE_MAX: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// 마지막으로 돌려준 항목의 키 (예: edge id, ts). 없으면 처음부터
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default = "Cursor::default_limit")]
    pub limit: usize,
}
/// `#[derive(Default)]` 를 쓰면 limit 이 0 → normalized 에서 1 이 된다. cursor 를 생략한 요청이 1건만 받던 결함(A19 발견).
/// 기본은 serde 기본값과 같은 PAGE_MAX.
impl Default for Cursor {
    fn default() -> Self {
        Cursor {
            after: None,
            limit: PAGE_MAX,
        }
    }
}
impl Cursor {
    fn default_limit() -> usize {
        PAGE_MAX
    }
    /// limit 을 1~PAGE_MAX 로 자른다
    pub fn normalized(mut self) -> Self {
        self.limit = self.limit.clamp(1, PAGE_MAX);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// 다음 쪽이 있으면 그 cursor.after 값
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}
impl<T> Page<T> {
    /// items 가 limit+1 개 오면 마지막을 잘라 next 로 쓴다
    pub fn from_overfetch(mut items: Vec<T>, limit: usize, key_of: impl Fn(&T) -> String) -> Self {
        let limit = limit.clamp(1, PAGE_MAX);
        if items.len() > limit {
            items.truncate(limit);
            let next = items.last().map(&key_of);
            Page { items, next }
        } else {
            Page { items, next: None }
        }
    }
}
