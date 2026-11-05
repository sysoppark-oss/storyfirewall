//! 오류 코드: JSON-RPC 표준(-32700~-32600) + 우리 코드(-32001~-32006)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "i64", try_from = "i64")]
pub enum ErrorCode {
    ParseError,      // -32700
    InvalidRequest,  // -32600
    MethodNotFound,  // -32601
    InvalidParams,   // -32602
    Internal,        // -32603
    Unauthorized, // -32001 관리자 아님 / 서명 실패(연결 단계에서 이미 거부되므로 요청 단계에서는 토큰 검사 실패만)
    GuardRejected, // -32002 가드 거부
    NeedsAck,     // -32003 사용자 확인 필요 (data: items)
    Busy,         // -32004 다른 변경이 진행 중
    NotConfirmedYet, // -32005 60초 확인 창 안의 정책에 다른 변경
    VersionMismatch, // -32006 api 판 불일치 / 정책 판 불일치
}

impl From<ErrorCode> for i64 {
    fn from(c: ErrorCode) -> i64 {
        match c {
            ErrorCode::ParseError => -32700,
            ErrorCode::InvalidRequest => -32600,
            ErrorCode::MethodNotFound => -32601,
            ErrorCode::InvalidParams => -32602,
            ErrorCode::Internal => -32603,
            ErrorCode::Unauthorized => -32001,
            ErrorCode::GuardRejected => -32002,
            ErrorCode::NeedsAck => -32003,
            ErrorCode::Busy => -32004,
            ErrorCode::NotConfirmedYet => -32005,
            ErrorCode::VersionMismatch => -32006,
        }
    }
}
impl TryFrom<i64> for ErrorCode {
    type Error = String;
    fn try_from(v: i64) -> Result<Self, String> {
        Ok(match v {
            -32700 => ErrorCode::ParseError,
            -32600 => ErrorCode::InvalidRequest,
            -32601 => ErrorCode::MethodNotFound,
            -32602 => ErrorCode::InvalidParams,
            -32603 => ErrorCode::Internal,
            -32001 => ErrorCode::Unauthorized,
            -32002 => ErrorCode::GuardRejected,
            -32003 => ErrorCode::NeedsAck,
            -32004 => ErrorCode::Busy,
            -32005 => ErrorCode::NotConfirmedYet,
            -32006 => ErrorCode::VersionMismatch,
            other => return Err(format!("알 수 없는 오류 코드 {other}")),
        })
    }
}
impl ErrorCode {
    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::ParseError => "parse error",
            ErrorCode::InvalidRequest => "invalid request",
            ErrorCode::MethodNotFound => "method not found",
            ErrorCode::InvalidParams => "invalid params",
            ErrorCode::Internal => "internal error",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::GuardRejected => "guard_rejected",
            ErrorCode::NeedsAck => "needs_ack",
            ErrorCode::Busy => "busy",
            ErrorCode::NotConfirmedYet => "not_confirmed_yet",
            ErrorCode::VersionMismatch => "version_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("rpc {code:?}: {message}")]
pub struct RpcError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
impl RpcError {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.message().into(),
            data: None,
        }
    }
    pub fn with(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            message: format!("{}: {}", code.message(), detail.into()),
            data: None,
        }
    }
    pub fn data(mut self, v: serde_json::Value) -> Self {
        self.data = Some(v);
        self
    }
}
