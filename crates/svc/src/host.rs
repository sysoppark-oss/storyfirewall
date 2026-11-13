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

/// 지금 열린 TCP 연결 하나(UI 명세 4판 3-4). LISTEN·PID 0(TIME_WAIT 등)은 빼고 돌려준다
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenConn {
    pub laddr: String,
    pub lport: u16,
    pub raddr: String,
    pub rport: u16,
    /// MIB_TCP_STATE 숫자(5 = ESTABLISHED)
    pub state: u32,
    pub pid: u32,
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

/// 브라우저 확장 프로그램의 보조 프로그램 등록(네이티브 메시징 호스트) 한 건 — 레지스트리 NativeMessagingHosts 와 그 매니페스트
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NativeHost {
    /// "chrome" | "edge" | "brave" | "chromium" | "firefox"
    pub browser: String,
    /// 등록 이름(예: com.anthropic.claude_browser_extension) — 외부 문자열, 자료로만
    pub name: String,
    /// 등록 위치("HKLM" 또는 "HKU\<SID>")
    pub scope: String,
    pub manifest: String,
    /// 매니페스트의 path(상대 경로면 매니페스트 폴더 기준으로 푼 것)
    pub path: String,
}

/// 실행 파일 서명 조회 결과(WinVerifyTrust)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SigInfo {
    /// "valid" | "nosignature" | "untrusted:…" | "error:…"
    pub status: String,
    pub signer: Option<String>,
}

/// (PID, 생성 시각, 처음 본 시각) → 살아 있으면 (실행 파일 경로, 생성 시각). `Host::live_image` 와 같은 뜻
pub type LiveProbe = fn(u32, i64, i64) -> Option<(String, i64)>;

pub trait Host: Send {
    /// 네트워크 인터페이스 목록. 지원하지 않는 환경이면 Err
    fn interfaces(&self) -> Result<Vec<NetIf>, String> {
        Err("이 환경에서는 네트워크 인터페이스를 볼 수 없습니다".into())
    }
    /// 지금 열린 리스닝 소켓. 지원하지 않는 환경이면 Err
    fn listeners(&self) -> Result<Vec<Listener>, String> {
        Err("이 환경에서는 리스닝 포트를 볼 수 없습니다".into())
    }
    /// 지금 열린 TCP 연결(LISTEN 제외). 지원하지 않는 환경이면 Err
    fn open_connections(&self) -> Result<Vec<OpenConn>, String> {
        Err("이 환경에서는 열린 연결을 볼 수 없습니다".into())
    }
    /// IPv4 TCP 연결 하나 끊기(관리자). 지원하지 않는 환경이면 Err
    fn kill_tcp(&self, _c: &OpenConn) -> Result<(), String> {
        Err("이 환경에서는 연결을 끊을 수 없습니다".into())
    }
    /// (PID, 생성 시각 FILETIME) 이 일치할 때만 종료. 결과 설명을 돌려준다
    fn terminate(&self, _pid: u32, _create_ft: Option<i64>) -> String {
        "no_terminator".into()
    }
    /// 32차 Gemini Q1: 지금 활성인 원격 데스크톱(RDP) 세션 (세션 id, 접속한 쪽 이름 — 자료로만). 모르면 빈 목록
    fn rdp_sessions(&self) -> Vec<(u32, String)> {
        Vec::new()
    }
    /// 서비스 SID 유형이 Unrestricted·Restricted 인가(서비스 SID 로 WFP 조건을 걸어도 맞는가). 모르면 false —
    /// 긴급 차단 DNS·DHCP 예외는 이때만 서비스 SID 로 좁힌다(아니면 svchost 경로만)
    fn service_sid_usable(&self, _service: &str) -> bool {
        false
    }
    /// 34차 Q3: RDP 가 듣는 포트(바꿔 둘 수 있다). 기본 3389
    fn rdp_port(&self) -> u16 {
        3389
    }
    /// 끊기(2026-11-06 노트북 제보): 수집 때 실행 파일 경로를 못 얻은 프로세스가 지금도 살아 있으면 그 경로.
    /// (PID, 생성 시각)이 둘 다 맞을 때만 — PID 재사용으로 엉뚱한 프로그램 경로를 붙이지 않게. 모르면 None
    /// 반환: (실행 파일 경로, 실제 생성 시각). 같은 프로세스로 보는 조건 — 생성 시각이 기록과 같거나,
    /// 지금 살아 있는 그 PID 의 프로세스가 우리가 처음 본 시각(seen_ft) 이전에 생겼을 때(살아 있는 프로세스끼리는 PID 가 겹치지 않으므로
    /// 그때 본 것이 이 프로세스다). 2026-11-06 노트북: 수집 전부터 돌던 프로세스는 생성 시각 기록이 어긋나 경로를 못 채웠다
    fn live_image(&self, _pid: u32, _create_ft: i64, _seen_ft: i64) -> Option<(String, i64)> {
        None
    }
    /// 50차 2단계: 조회 작업자(엔진 밖 스레드)가 부를 수 있는 live_image. 상태 없는 함수만 내놓는다.
    /// None 이면 작업자는 "실행 중 아님"으로 본다(NoHost 의 live_image 와 같음) — live_image 를 바꾼 호스트는 이것도 함께 내놓을 것
    fn live_probe(&self) -> Option<LiveProbe> {
        None
    }
    /// 35차 Q4: 실행 파일의 버전 리소스 원래 이름(OriginalFileName, 소문자). 모르면 None
    fn original_name(&self, _path: &str) -> Option<String> {
        None
    }
    /// 자동 조사: (PID, 생성 시각)이 맞는 살아 있는 프로세스의 명령줄. 모르면 None
    fn cmdline(&self, _pid: u32, _create_ft: i64) -> Option<String> {
        None
    }
    /// 자동 조사: 실행 파일 서명. 모르면 None
    fn signature(&self, _path: &str) -> Option<SigInfo> {
        None
    }
    /// 자동 조사: 이 PC 에 등록된 브라우저 확장 보조 프로그램(HKLM + 로그온한 사용자들의 HKCU)
    fn native_hosts(&self) -> Vec<NativeHost> {
        Vec::new()
    }
}

/// 아무것도 하지 않는 호스트 (Linux 테스트·개발 기본값)
pub struct NoHost;
impl Host for NoHost {}
