//! api: 서비스 ↔ UI JSON-RPC 2.0 메시지 규격 (10차 3장, 11차 Q5)
//!
//! 이 크레이트는 **메시지 타입과 검증만** 둔다. 파이프 전송·인증(관리자 검사 + 클라이언트 이미지 서명 검사,
//! 실패 시 연결 거부)·디스패처는 서비스 바이너리(`svc`)가 맡는다. 그래서 engine·judge·story 에 의존하지 않고
//! Linux 에서 전부 테스트한다.
//!
//! 규격
//! - JSON-RPC 2.0. 메시지 모드 파이프 + 개행 한 줄 JSON. 요청 1MB 상한.
//! - 변경 메서드(policy.*·cut.*·judge.feedback_normal·retention.set·settings.set)는 `request_id`(UUID) 필수 — 멱등 키.
//! - 목록 응답은 `cursor` 페이지, 한 쪽 최대 1,000건.
//! - 판 협상: `rpc.hello {client_version}` → `{server_version, api}`. `api` 메이저가 다르면 UI 가 "서비스 업데이트 필요".
//! - 오류: 표준 코드 + 우리 코드 `-32001 unauthorized` … `-32006 version_mismatch`.
//! - 구독: `connections.subscribe`·`events.subscribe` — 서버 → 클라이언트 알림(`id` 없음), 클라이언트당 각 1개.

pub mod error;
pub mod methods;
pub mod page;
pub mod rpc;

pub use error::{ErrorCode, RpcError};
pub use methods::{Method, Role};
pub use page::{Cursor, Page, PAGE_MAX};
pub use rpc::{Notification, Request, Response, API_VERSION, MAX_REQUEST_BYTES};
