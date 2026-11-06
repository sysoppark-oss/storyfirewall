//! Windows 구현 (A17, 러너에서 실측). 명세 7판 2-8장.
//!
//! - `pipe`: 메시지 모드 네임드 파이프 서버. FILE_FLAG_FIRST_PIPE_INSTANCE·REJECT_REMOTE_CLIENTS·ACL(SDDL).
//!   overlapped I/O + 이벤트 대기로 `Transport::read_line(timeout)` 을 만든다(알림을 흘리기 위해).
//! - `authn`: `GetNamedPipeClientProcessId` → 이미지 경로 → WinVerifyTrust(서명자 CN 비교) / Impersonate → CheckTokenMembership(Administrators).
//! - `time`: `GetDynamicTimeZoneInformation` 으로 로컬 시각(unix 초) — engine::Clock 의 wall.
//! - `service`: SCM 등록·해제, 서비스 본체 진입, 제어 코드(STOP·SHUTDOWN·POWEREVENT·TIMECHANGE) → 이벤트.
//! - `pipe_name`: 시작마다 무작위 파이프 이름 → HKLM 공개, 클라이언트 조회, 고정 이름 점유자 점검 (A25).
//! - `process`: TerminateProcess + 생성 시각 대조(PID 재사용 방지).

pub mod authn;
/// A26: 서비스 데이터 폴더 (소유자 검사·보호 DACL)
pub mod data_dir;
pub mod pipe;
/// A25: 무작위 파이프 이름 공개(HKLM)·조회, 가로채기 점검
pub mod pipe_name;
pub mod process;
pub mod service;
pub mod time;
/// A26: engine::WfpBackend 의 Windows 구현
pub mod wfp_backend;
/// 32차 Q1: 원격 데스크톱(RDP) 활성 세션
pub mod wts;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
