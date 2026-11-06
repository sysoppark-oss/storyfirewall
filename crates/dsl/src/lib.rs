//! dsl: 정책 YAML → 파싱 → 검증(규칙 1~9) → WFP 필터 명세(`policy::BlockSpec`) 전개
//!
//! 이 크레이트는 OS 를 만지지 않는다. 시각 조건·만료는 스케줄러가, `also` 는 정책 엔진이,
//! 디렉터리 열거·자손 조회는 호출자가 넘기는 `Resolver` 가 한다. 그래서 Linux 에서 전부 테스트한다.

pub mod expand;
pub mod model;
pub mod parse;
pub mod ranges;
pub mod validate;

pub use expand::{expand, Expanded, Resolver, Schedule};
pub use model::{Ack, Document, Policy};
pub use parse::parse;
pub use validate::{validate, Validation};

#[derive(Debug, thiserror::Error)]
pub enum DslError {
    #[error("문법 오류: {0}")]
    Syntax(String),
    #[error("지원하지 않는 문법 판: {0} (지원: 1)")]
    Version(u32),
    #[error("검증 실패 [{rule}] {policy}: {msg}")]
    Rule { rule: u8, policy: String, msg: String },
}

pub type Result<T> = std::result::Result<T, DslError>;

/// 서비스가 만드는 정책(끊기 등)을 YAML 문자열로. 경로·이름 같은 외부 문자열이 섞이므로 손으로 이어 붙이지 않고
/// 직렬화기로 따옴표·이스케이프를 맡긴다 (YAML 주입 방지, A19).
pub fn emit_yaml(v: &serde_json::Value) -> String {
    serde_yaml_ng::to_string(v).unwrap_or_default()
}
