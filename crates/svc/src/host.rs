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

/// ACL 정책 관리: 네트워크 인터페이스 한 개(정책 화면의 "인터페이스 선택")
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NetIf {
    /// 별칭(예: "Wi-Fi", "이더넷") — 정책에 저장하는 이름
    pub alias: String,
    pub description: String,
    pub up: bool,
    /// 이 PC 주소 "주소/접두 길이"
    pub addrs: Vec<String>,
    /// 인터페이스 LUID(화면에는 보내지 않음) — 37차 Q2: 별칭↔LUID 짝이 바뀌었는지 1분마다 비교
    #[serde(skip)]
    pub luid: u64,
}

pub trait Host: Send {
    /// 네트워크 인터페이스 목록. 지원하지 않는 환경이면 Err
    fn interfaces(&self) -> Result<Vec<NetIf>, String> {
        Err("이 환경에서는 네트워크 인터페이스를 볼 수 없습니다".into())
    }
    /// 지금 열린 리스닝 소켓. 지원하지 않는 환경이면 Err
    fn listeners(&self) -> Result<Vec<Listener>, String> {
        Err("이 환경에서는 리스닝 포트를 볼 수 없습니다".into())
    }
    /// (PID, 생성 시각 FILETIME) 이 일치할 때만 종료. 결과 설명을 돌려준다
    fn terminate(&self, _pid: u32, _create_ft: Option<i64>) -> String {
        "no_terminator".into()
    }
    /// 32차 Gemini Q1: 지금 활성인 원격 데스크톱(RDP) 세션 (세션 id, 접속한 쪽 이름 — 자료로만). 모르면 빈 목록
    fn rdp_sessions(&self) -> Vec<(u32, String)> {
        Vec::new()
    }
    /// 34차 Q3: RDP 가 듣는 포트(바꿔 둘 수 있다). 기본 3389
    fn rdp_port(&self) -> u16 {
        3389
    }
    /// 35차 Q4: 실행 파일의 버전 리소스 원래 이름(OriginalFileName, 소문자). 모르면 None
    fn original_name(&self, _path: &str) -> Option<String> {
        None
    }
}

/// 아무것도 하지 않는 호스트 (Linux 테스트·개발 기본값)
pub struct NoHost;
impl Host for NoHost {}
