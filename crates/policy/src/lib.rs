//! policy: WFP 정책 엔진 (명세 4판 2장 "WFP 적용 방식", 5차 검증 반영)
//!
//! 원칙
//! - 다른 Sublayer 에 영향을 주는 permit 은 만들지 않는다. 우리 Sublayer 안의 permit 은 우리 차단의 예외일 뿐 (6판, Defender 병행).
//! - 비동적 세션 + 영구(PERSISTENT) Provider·Sublayer·필터. 프로세스가 죽어도 필터는 남는다.
//! - 정책 1건 = 트랜잭션 1건. 필터 ID 는 호출자가 저장한다.
//! - 가드(규칙 8·자기 차단·러너 에이전트)는 엔진에 닿기 전에 `guard` 에서 거부한다.
//! - 자가 치유: 필터·Sublayer·Provider 삭제 구독 → 재등록. 차단 이벤트는 1초마다 200건 상한으로 읽는다.

pub mod emergency;
pub mod guard;
pub mod spec;
#[cfg(any(windows, feature = "host-check"))]
pub mod wfp;

/// 차단한 필터의 이름·공급자(차단 기록의 "막은 것")
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FilterInfo {
    pub name: String,
    pub description: String,
    pub provider_name: String,
    /// 공급자 GUID 문자열(없으면 빈 문자열)
    pub provider_key: String,
    /// 우리(Story Firewall) 공급자인가
    pub ours: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("가드 거부: {0}")]
    Guard(String),
    #[error("WFP 오류 {0:#x} ({1})")]
    Wfp(u32, &'static str),
}

pub type Result<T> = std::result::Result<T, PolicyError>;
