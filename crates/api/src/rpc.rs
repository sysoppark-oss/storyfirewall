//! JSON-RPC 2.0 봉투: 요청·응답·알림. 한 줄 JSON. 요청 1MB 상한.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, RpcError};

/// api 판. 메이저가 다르면 version_mismatch
pub const API_VERSION: (u32, u32) = (1, 0);
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Num(i64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: Id,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// 서버 → 클라이언트 알림 (구독). id 없음
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
}

impl Request {
    pub fn new(id: i64, method: &str, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Id::Num(id),
            method: method.into(),
            params,
        }
    }

    /// 한 줄 JSON 을 파싱하고 봉투를 검증한다. 크기·jsonrpc·method 형식.
    pub fn parse_line(line: &str) -> Result<Self, RpcError> {
        if line.len() > MAX_REQUEST_BYTES {
            return Err(RpcError::with(
                ErrorCode::InvalidRequest,
                format!("요청이 {}바이트를 넘음", MAX_REQUEST_BYTES),
            ));
        }
        if line.contains('\n') {
            return Err(RpcError::with(ErrorCode::InvalidRequest, "한 줄이어야 함"));
        }
        let req: Request = serde_json::from_str(line)
            .map_err(|e| RpcError::with(ErrorCode::ParseError, e.to_string()))?;
        if req.jsonrpc != "2.0" {
            return Err(RpcError::with(
                ErrorCode::InvalidRequest,
                "jsonrpc 는 \"2.0\"",
            ));
        }
        if req.method.is_empty()
            || !req
                .method
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
        {
            return Err(RpcError::with(ErrorCode::InvalidRequest, "method 형식"));
        }
        if !(req.params.is_object() || req.params.is_null()) {
            return Err(RpcError::with(ErrorCode::InvalidParams, "params 는 객체"));
        }
        Ok(req)
    }
}

impl Response {
    pub fn ok(id: Id, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Some(id),
            result: Some(result),
            error: None,
        }
    }
    pub fn err(id: Option<Id>, e: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(e),
        }
    }
    /// 한 줄 JSON (개행 포함)
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).expect("serialize");
        s.push('\n');
        s
    }
}

impl Notification {
    pub fn new(method: &str, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        }
    }
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).expect("serialize");
        s.push('\n');
        s
    }
}

/// rpc.hello 요청·응답
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub client_version: String,
    pub api: (u32, u32),
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloReply {
    pub server_version: String,
    pub api: (u32, u32),
}

/// 판 협상: 메이저가 다르면 거부. 마이너는 서버 ≥ 클라이언트면 통과.
pub fn negotiate(client: (u32, u32)) -> Result<(), RpcError> {
    if client.0 != API_VERSION.0 || client.1 > API_VERSION.1 {
        return Err(RpcError::with(
            ErrorCode::VersionMismatch,
            format!(
                "client api {}.{}, server api {}.{} — 서비스 업데이트 필요",
                client.0, client.1, API_VERSION.0, API_VERSION.1
            ),
        )
        .data(serde_json::json!({"server_api": API_VERSION})));
    }
    Ok(())
}
