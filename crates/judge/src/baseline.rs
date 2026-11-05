//! 프로그램별 평소 행동 기준선 (F11, 8차 의뢰서 5장) 과 "정상" 피드백
//!
//! - 키 = (이미지 경로, 서명자). 경로만 쓰면 바꿔치기에 속고 서명자만 쓰면 다른 프로그램이 섞인다.
//! - 학습 14일. 학습 전에는 기준선 가중치를 쓰지 않는다. 학습 후에도 매일 갱신.
//! - **학습 제외**: 서명 없거나 깨졌거나 Zone 3·4 로 들어온 실행 파일은 기준선을 만들지 않는다
//!   (설치 전부터 있던 악성코드가 "평소"로 굳는 기준선 오염 방지). 이들의 "처음 보는 곳"은
//!   PC 전체 도메인 집합(학습된 프로그램들이 접속한 곳)과 비교한다.
//! - 피드백: 뿌리 키로 저장. 서명 유효 ∧ 서명자 동일 ∧ 경로 동일이면 해시가 바뀌어도 상속(8차 Q4).
//!   서명 없는 프로그램은 상속 없음 — 현재 그래프에 파일 해시가 없어 (경로, 크기·수정시각) 대신
//!   `file_id` 문자열(수집기가 채움, 없으면 경로)로 묶는다. 해시 도입은 수집기 과제.
//! - 1차에서 학습 항목은 도메인(eTLD+1)·포트·자손 이미지. 시간대·바이트 분포는 2차.
//! - eTLD+1 은 Public Suffix List 채택 전까지 단순 규칙(2단계 TLD 목록)으로 근사한다.

use std::collections::HashSet;

use graph::store::Store;
use graph::Node;

use crate::rules::{attr_str, file_name_lower, proc_image_name, sig_of, zone_is_internet, Sig};
use crate::{Result, View};

pub const LEARN_DAYS: i64 = 14;
const DAY: i64 = 24 * 3600 * 10_000_000; // FILETIME 100ns

pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS baseline_program (
  program_key TEXT PRIMARY KEY,   -- "<경로 소문자>|<서명자>"
  since_ts    INTEGER NOT NULL,
  last_ts     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS baseline_item (
  program_key TEXT NOT NULL,
  kind        TEXT NOT NULL,      -- domain | port | child
  value       TEXT NOT NULL,
  first_ts    INTEGER NOT NULL,
  last_ts     INTEGER NOT NULL,
  count       INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(program_key, kind, value)
);
CREATE TABLE IF NOT EXISTS feedback_normal (
  root_key    TEXT PRIMARY KEY,   -- 서명됨: "<경로>|<서명자>" / 서명 없음: "<경로>|unsigned|<file_id>"
  created_ts  INTEGER NOT NULL
);
"#;

pub struct Baseline {
    pub now_ts: i64,
}

/// 2단계 TLD 근사 (PSL 채택 전)
const SECOND_LEVEL: &[&str] = &[
    "co", "com", "ne", "or", "go", "ac", "re", "pe", "net", "org", "gov", "edu", "mil",
];
pub fn etld1(domain: &str) -> String {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() <= 2 {
        return d;
    }
    let n = labels.len();
    if SECOND_LEVEL.contains(&labels[n - 2]) && labels[n - 1].len() == 2 {
        labels[n - 3..].join(".")
    } else {
        labels[n - 2..].join(".")
    }
}

pub fn program_key(file: &Node) -> Option<String> {
    if let Some(signer) = attr_str(file, "signer") {
        return Some(format!("{}|{}", file.key.to_ascii_lowercase(), signer));
    }
    // 서명 없는 설치 프로그램(학습 대상일 때만): 경로 + 내용 해시. 파일이 바뀌면(해시가 다르면) 다른 프로그램으로 처음부터 배운다
    if admin_installed_unsigned(file) {
        let h = attr_str(file, "sha256")?;
        return Some(format!("{}|unsigned|{}", file.key.to_ascii_lowercase(), h));
    }
    None
}

/// 관리자만 쓰는 설치 위치(Program Files·Program Files (x86))의 서명 없는 실행 파일 ∧ 인터넷에서 받은 표시(Zone 3·4) 없음.
/// L052(노트북): Git for Windows 의 sh.exe·bash.exe 처럼 서명 없이 배포되는 설치 프로그램이 매번 "의심"이 되던 오탐.
/// 근거: 이 위치에 파일을 놓으려면 관리자 권한이 필요하다(관리자 권한을 가진 공격자는 이 제품의 판정 범위를 이미 넘는다).
/// 위험: 관리자가 ACL 을 푼 Program Files 하위 폴더는 이 가정이 깨진다(경로 근사 — score::user_writable_path 와 같은 한계)
pub fn admin_installed_unsigned(file: &Node) -> bool {
    matches!(sig_of(file), Some(Sig::None_))
        && !zone_is_internet(file)
        && crate::score::admin_install_path(&file.key)
}

/// 기준선 학습 대상인가: (서명 유효 ∨ 관리자 설치 위치의 서명 없는 파일) ∧ Zone 3·4 아님
pub fn learnable(file: &Node) -> bool {
    (matches!(sig_of(file), Some(Sig::Microsoft) | Some(Sig::Valid)) && !zone_is_internet(file))
        || admin_installed_unsigned(file)
}

/// 뿌리 키 (피드백용)
/// 금고 경비 사건 전용 정상 키 (L063)
pub fn vault_key(file: &Node) -> String {
    format!("vault:{}", root_key(file))
}

pub fn root_key(file: &Node) -> String {
    match sig_of(file) {
        Some(Sig::Microsoft) | Some(Sig::Valid) => format!(
            "{}|{}",
            file.key.to_ascii_lowercase(),
            attr_str(file, "signer").unwrap_or_default()
        ),
        _ => format!(
            "{}|unsigned|{}",
            file.key.to_ascii_lowercase(),
            attr_str(file, "file_id").unwrap_or_default()
        ),
    }
}

impl Baseline {
    pub fn open(store: &Store, now_ts: i64) -> Result<Self> {
        store.conn().execute_batch(DDL)?;
        Ok(Self { now_ts })
    }

    /// 구간의 그래프에서 학습 가능한 프로그램의 행동을 기준선에 더한다 (하루 한 번).
    pub fn learn(&self, store: &Store, view: &View) -> Result<usize> {
        let tx = store.begin_write()?;
        let mut n = 0;
        for p in view.nodes.values().filter(|n| n.kind == "process") {
            let Some(file) = view.image_file(p.id) else {
                continue;
            };
            if !learnable(file) {
                continue;
            }
            let Some(key) = program_key(file) else {
                continue;
            };
            tx.execute(
                "INSERT INTO baseline_program(program_key, since_ts, last_ts) VALUES (?1, ?2, ?2)
                 ON CONFLICT(program_key) DO UPDATE SET last_ts = excluded.last_ts",
                rusqlite::params![key, self.now_ts],
            )?;
            for e in view.outs(p.id) {
                let dst = view.node(e.dst);
                let items: Vec<(&str, String)> = match e.rel.as_str() {
                    "connected" => {
                        let mut v = Vec::new();
                        if let Some(d) = attr_str(dst, "domain") {
                            v.push(("domain", etld1(&d)));
                        }
                        if let Some(port) = dst.attr("port").and_then(|x| x.as_u64()) {
                            v.push(("port", port.to_string()));
                        }
                        v
                    }
                    "spawned" => vec![("child", proc_image_name(dst))],
                    _ => vec![],
                };
                for (kind, value) in items {
                    tx.execute(
                        "INSERT INTO baseline_item(program_key, kind, value, first_ts, last_ts, count) VALUES (?1, ?2, ?3, ?4, ?4, 1)
                         ON CONFLICT(program_key, kind, value) DO UPDATE SET last_ts = excluded.last_ts, count = count + 1",
                        rusqlite::params![key, kind, value, e.ts],
                    )?;
                    n += 1;
                }
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// 학습이 끝났는가 (14일 경과)
    pub fn learned(&self, store: &Store, key: &str) -> Result<bool> {
        let since: Option<i64> = store
            .conn()
            .query_row(
                "SELECT since_ts FROM baseline_program WHERE program_key = ?1",
                [key],
                |r| r.get(0),
            )
            .ok();
        Ok(since.map_or(false, |s| self.now_ts - s >= LEARN_DAYS * DAY))
    }

    pub fn has(&self, store: &Store, key: &str, kind: &str, value: &str) -> Result<bool> {
        let c: i64 = store.conn().query_row("SELECT COUNT(*) FROM baseline_item WHERE program_key = ?1 AND kind = ?2 AND value = ?3", [key, kind, value], |r| r.get(0))?;
        Ok(c > 0)
    }

    /// PC 전체가 접속한 도메인(eTLD+1) 집합 — 학습된 프로그램들의 합. 제외 프로그램의 "처음 보는 곳" 기준.
    pub fn pc_domains(&self, store: &Store) -> Result<HashSet<String>> {
        let mut st = store
            .conn()
            .prepare("SELECT DISTINCT value FROM baseline_item WHERE kind = 'domain'")?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// PC 기준선이 쓸 만큼 쌓였는가 (가장 오래된 프로그램이 14일 넘음)
    pub fn pc_learned(&self, store: &Store) -> Result<bool> {
        let oldest: Option<i64> = store
            .conn()
            .query_row("SELECT MIN(since_ts) FROM baseline_program", [], |r| {
                r.get(0)
            })
            .ok()
            .flatten();
        Ok(oldest.map_or(false, |s| self.now_ts - s >= LEARN_DAYS * DAY))
    }

    pub fn mark_normal(&self, store: &Store, file: &Node) -> Result<()> {
        store.conn().execute(
            "INSERT OR REPLACE INTO feedback_normal(root_key, created_ts) VALUES (?1, ?2)",
            rusqlite::params![root_key(file), self.now_ts],
        )?;
        Ok(())
    }

    /// L063(사용자 결정 "정상 버튼으로"): 브라우저 금고 경비 사건만 정상으로 본다(그 프로그램의 다른 판정은 그대로).
    /// 개발 도구(node·chromedriver)를 통째로 정상으로 만들면 그 도구를 거치는 악성 코드까지 숨기므로 범위를 좁힌다
    pub fn mark_normal_vault(&self, store: &Store, file: &Node) -> Result<()> {
        store.conn().execute(
            "INSERT OR REPLACE INTO feedback_normal(root_key, created_ts) VALUES (?1, ?2)",
            rusqlite::params![vault_key(file), self.now_ts],
        )?;
        Ok(())
    }

    pub fn feedback_keys(&self, store: &Store) -> Result<HashSet<String>> {
        let mut st = store
            .conn()
            .prepare("SELECT root_key FROM feedback_normal")?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

#[allow(dead_code)]
fn _unused(_: &str) -> String {
    file_name_lower("")
}

#[cfg(test)]
mod tests {
    use super::etld1;
    #[test]
    fn etld1_approx() {
        assert_eq!(etld1("static.rust-lang.org"), "rust-lang.org");
        assert_eq!(etld1("www.naver.co.kr"), "naver.co.kr");
        assert_eq!(etld1("a.b.c.github.com"), "github.com");
        assert_eq!(etld1("example.com"), "example.com");
    }
}
