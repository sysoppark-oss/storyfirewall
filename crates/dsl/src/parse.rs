//! YAML 파싱 + 입력 금지 필드 거부

use crate::model::{Document, DocumentVersioned, Policy, SUPPORTED_VERSION};
use crate::{DslError, Result};

/// 입력에 있으면 구문 오류로 거부하는 키 (서비스 전용). 6차 검증 Q6.
const SERVICE_ONLY_KEYS: &[&str] = &["source", "acknowledge"];

pub fn parse(text: &str) -> Result<Document> {
    // 서비스 전용 키는 역직렬화 전에 원문에서 찾는다 (skip_deserializing 이라 serde 가 못 잡는다)
    for line in text.lines() {
        let t = line.trim_start();
        let t = t.strip_prefix("- ").unwrap_or(t).trim_start();
        for k in SERVICE_ONLY_KEYS {
            if t.starts_with(&format!("{k}:")) {
                return Err(DslError::Syntax(format!("'{k}' 는 서비스가 붙이는 필드다. 입력에서는 쓸 수 없다")));
            }
        }
    }
    // untagged enum 은 실제 오류를 감추므로 상위 모양(목록/사전)을 먼저 보고 각각 역직렬화한다
    let syntax = |e: serde_yaml_ng::Error| DslError::Syntax(e.to_string());
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).map_err(syntax)?;
    let (version, policies) = if value.is_sequence() {
        let p: Vec<Policy> = serde_yaml_ng::from_value(value).map_err(syntax)?;
        (1, p)
    } else {
        let d: DocumentVersioned = serde_yaml_ng::from_value(value).map_err(syntax)?;
        (d.version, d.policies)
    };
    if version != SUPPORTED_VERSION {
        return Err(DslError::Version(version));
    }
    Ok(Document { version, policies })
}
