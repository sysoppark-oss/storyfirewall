//! OS 에 닿는 서비스 부품 (A19): 리스닝 포트, 프로세스 종료. Windows 구현은 `win::WinHost`, 테스트·개발은 `NoHost`/가짜.

/// 리스닝 소켓 (F4)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Listener {
    pub proto: String,
    pub laddr: String,
    pub lport: u16,
    pub pid: u32,
    /// 모든 주소에서 듣는가 (0.0.0.0 / ::) — 외부에서 닿을 수 있는 후보
    pub any_addr: bool,
}

pub trait Host: Send {
    /// 지금 열린 리스닝 소켓. 지원하지 않는 환경이면 Err
    fn listeners(&self) -> Result<Vec<Listener>, String> {
        Err("이 환경에서는 리스닝 포트를 볼 수 없습니다".into())
    }
    /// (PID, 생성 시각 FILETIME) 이 일치할 때만 종료. 결과 설명을 돌려준다
    fn terminate(&self, _pid: u32, _create_ft: Option<i64>) -> String {
        "no_terminator".into()
    }
}

/// 아무것도 하지 않는 호스트 (Linux 테스트·개발 기본값)
pub struct NoHost;
impl Host for NoHost {}
