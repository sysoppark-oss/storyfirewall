//! collector: 수집 센서 (제품A 개발 명세 4판 2-2)
//!
//! 시작 순서: ① ETW 세션 시작(큐잉 시작) → ② 프로세스 스냅샷 + SCM 매핑 → ③ 큐 처리(중복 제거는
//! graph::Ingester 가 PID@CreateTime 으로 함) → ④ 폴링(연결 테이블·SCM·용량 flush·세션 통계).
//!
//! 스레드
//! - ETW 소비: ferrisetw 콜백. 프로세스·연결·DNS·파일 이벤트는 채널로, 용량 이벤트는 카운터에 누적만.
//! - 저장: 채널 → Ingester → SQLite. 100건 또는 200ms 마다 트랜잭션 묶음.
//! - 폴링: 1초. 연결 테이블(ETW 누락 대조), SCM(PID→서비스), 용량 카운터 flush, EventsLost.
//!
//! Windows 전용. Linux 에서는 `--features host-check` 로 cargo check 만 한다.

#[cfg(any(windows, feature = "host-check"))]
pub mod cmdline;
#[cfg(any(windows, feature = "host-check"))]
pub mod conntable;
#[cfg(any(windows, feature = "host-check"))]
mod ctx;
#[cfg(any(windows, feature = "host-check"))]
mod etw;
#[cfg(any(windows, feature = "host-check"))]
mod filering;
#[cfg(any(windows, feature = "host-check"))]
mod origin;
#[cfg(any(windows, feature = "host-check"))]
mod paths;
#[cfg(any(windows, feature = "host-check"))]
mod pipeline;
pub mod qpc;
#[cfg(any(windows, feature = "host-check"))]
mod scm;
#[cfg(any(windows, feature = "host-check"))]
mod session_stats;
#[cfg(any(windows, feature = "host-check"))]
pub mod signature;
#[cfg(any(windows, feature = "host-check"))]
mod snapshot;
/// 35차 Q3: 서비스 레지스트리 변경 알림
#[cfg(any(windows, feature = "host-check"))]
mod svcreg;
#[cfg(any(windows, feature = "host-check"))]
mod token;

#[cfg(any(windows, feature = "host-check"))]
pub use pipeline::{run, start, Config, Report, Session};

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("ETW 세션 시작 실패: {0} (관리자 권한인지 확인)")]
    Trace(String),
    #[error("그래프 저장 오류: {0}")]
    Graph(#[from] graph::GraphError),
    #[error("SQLite 오류: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Win32 오류 {0}: {1}")]
    Win32(u32, &'static str),
}

pub type Result<T> = std::result::Result<T, CollectorError>;
