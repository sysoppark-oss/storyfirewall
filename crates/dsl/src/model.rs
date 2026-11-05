//! 정책 DSL 문법 (명세 2판 3장 + 6차 검증: `version`, `acknowledge`)
//!
//! - 모르는 필드는 거부 (규칙 1, `deny_unknown_fields`).
//! - `source`·`acknowledge` 는 서비스만 붙인다. 입력 텍스트에 있으면 구문 오류 (6차 검증 Q6).
//!   그래서 두 필드는 역직렬화 대상이 아니고(`skip_deserializing`), 파서가 원문에서 키를 찾아 거부한다.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub direction: Option<Direction>,
    #[serde(default)]
    pub process: Vec<String>,
    #[serde(default)]
    pub process_not: Vec<String>,
    pub descendants_of: Option<String>,
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub remote_ip: Vec<String>,
    /// 포트는 정수(445)·문자열("8000-8100") 둘 다 받아 문자열로 통일한다
    #[serde(default, deserialize_with = "ports")]
    pub remote_port: Vec<String>,
    #[serde(default, deserialize_with = "ports")]
    pub local_port: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PortItem {
    Num(u64),
    Str(String),
}

fn ports<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<String>, D::Error> {
    let items: Vec<PortItem> = Vec::deserialize(d)?;
    Ok(items
        .into_iter()
        .map(|i| match i {
            PortItem::Num(n) => n.to_string(),
            PortItem::Str(s) => s,
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct When {
    /// "HH:MM-HH:MM", 자정 넘김 허용
    pub time: Option<String>,
    #[serde(default)]
    pub days: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Also {
    Terminate,
    Quarantine,
    RemoveAutorun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnExpire {
    Notify,
    Silent,
}

/// 서비스가 붙이는 확인 표식 (규칙 2·3·9). 입력에서는 거부.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Ack {
    /// 규칙 2: 자기 차단(로컬·DNS·DHCP)
    SelfBlock,
    /// 규칙 3: 전체 차단
    Wide,
    /// 규칙 9: svchost 광역
    Svchost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    User,
    Ai,
    Template,
    Cut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    pub action: Action,
    #[serde(rename = "match")]
    pub matcher: Match,
    pub when: Option<When>,
    /// ISO 시각 또는 기간(30m, 14d)
    pub expires: Option<String>,
    /// 1차: manual 만
    pub until: Option<String>,
    pub on_expire: Option<OnExpire>,
    #[serde(default)]
    pub also: Vec<Also>,
    pub log: Option<bool>,
    /// 서비스가 채운다. 입력에 있으면 파서가 거부
    #[serde(skip_deserializing, default)]
    pub source: Option<Source>,
    #[serde(skip_deserializing, default)]
    pub acknowledge: Vec<Ack>,
}

/// 문서의 사전형: {version, policies}. 상위가 목록이면 version 1 로 본다 (parse 가 모양으로 가른다)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentVersioned {
    pub version: u32,
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub version: u32,
    pub policies: Vec<Policy>,
}

pub const SUPPORTED_VERSION: u32 = 1;
