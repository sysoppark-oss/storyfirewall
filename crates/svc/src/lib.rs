//! svc: 서비스 골격 (13차 검증 3장 확정)
//!
//! 한 프로세스, 스레드 분리:
//! - 엔진 스레드: `engine::Engine` + graph `Store` + `judge::Baseline` 을 **혼자 소유**. 다른 스레드는 `Command` 를
//!   채널로 보낸다(조회도 같은 큐. 읽기 전용 병렬 연결은 2차, 13차 Q3).
//! - 저장 스레드: 수집기 `Event` 를 배치로 graph 에 넣고, ProcessStart 는 엔진 큐에도 넣는다(틈 메우기).
//! - 연결 핸들러: 연결마다 하나. 서명 검사(실패면 끊음) → `rpc.hello` 첫 메시지 강제 → 요청마다 파싱·검증·권한 →
//!   엔진 큐 → 응답. panic 은 연결만 끊는다. 엔진 스레드 panic 은 프로세스를 내린다(SCM 재시작 → reconcile).
//! - 타이머: 엔진 스레드가 `next_wakeup()` 만큼 `recv_timeout` 으로 자다가 `tick()`.
//!
//! OS 를 만지는 부분은 트레이트 뒤에: `Transport`(줄 읽기·쓰기·클라이언트 PID), `Authn`(서명·관리자 검사),
//! 수집기는 `Event` 채널. Linux 에서는 가짜로 통합 테스트.

pub mod change;
pub mod cut;
/// 10판 5-9 (3): 제어된 폴더 액세스(CFA)·Defender 실시간 보호 설정 값(진단)
pub mod defender;
pub mod demo;
pub mod dev;
pub mod dispatch;
/// 첫 실행 관찰실 (기획서 17판 23-2 ①)
pub mod first_run;
pub mod handler;
pub mod host;
pub mod policy_view;
pub mod reads;
pub mod resolver;
pub mod runtime;
/// Windows 전용: 네임드 파이프 Transport, 토큰·서명 Authn, 시각대. Linux 는 `--features host-check` 로 check 만
#[cfg(any(windows, feature = "host-check"))]
pub mod win;

pub use handler::{Authn, Read, Transport};
pub use runtime::{Command, Runtime};
