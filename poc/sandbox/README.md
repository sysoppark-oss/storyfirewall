# Windows Sandbox 시험 환경 (L072~L077, 2026-11-07~08)

노트북 RAM 이 5.8GB(여유 0.6GB)라 정식 Hyper-V VM 대신 쓰는 일회용 시험 환경. 사용자 결정 2026-11-07 "러너 + Sandbox".

- 실집행 시험(정책·종료·되돌리기)은 GitHub Windows 러너(A29 등)에서 자동으로. Sandbox 는 깨끗한 Windows 에서의 설치·서비스·수집·Sysmon 대조용.
- Sandbox 는 닫으면 초기화된다. 장기 기준선·오탐 측정은 여기서 하지 않는다.

## 준비(개발 세션이 실행기 작업으로)

1. `sandbox` — Windows 기능 Containers-DisposableClientVM 설치(재시작 요구 시에만 같은 요청에서 120초 뒤 재부팅).
2. `install` — 개발판 설치 + 검증된 설치 파일·핀·이 폴더의 스크립트를 `C:\Program Files\StoryFirewallDev\sandbox`(읽기 전용 매핑)에 복사, `sandbox-out`(쓰기 가능, 자료 전용) 생성. **설치 작업은 저장소를 새로 받지 않으므로 스크립트를 바꿨으면 먼저 `selfupdate`.**
3. `sysmon` — Sysmon64.exe 를 받아 Microsoft 서명 확인 후 공유 폴더에.

## 실행

`C:\Program Files\StoryFirewallDev\sandbox\sf-sandbox.wsb`(네트워크 끔) 또는 `sf-sandbox-net.wsb`(켬)를 두 번 눌러 연다.
로그온 스크립트가 개발판 설치 → 서비스 등록(핀) → Sysmon → 화면 실행. 로그는 호스트 `sandbox-out\sf-setup.log`.
한 번에 하나만 실행된다. 닫기 단추가 안 먹으면 Sandbox 안 시작 → 전원 → 시스템 종료.

## 확인된 것

- 깨끗한 Windows 11(26100)에는 VC++ 런타임이 없다 → 서비스가 0xC0000135 로 시작 못 하던 결함을 정적 CRT(`.cargo/config.toml`)로 고침. Sandbox 에서 서비스 state=4 확인.
- Sysmon v15.22 가 우리 구성(schema 4.50)을 받아들임.

## 남은 문제

- 화면(UI): Sandbox 안에 WebView2 런타임이 없다. 오프라인 설치(0x80040902), 호스트 런타임 매핑 + `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`(매핑 경로·로컬 복사 둘 다) 모두 실패. 화면 확인은 노트북 설치판에서 한다.
- 제품 쪽: 설치 파일은 `embedBootstrapper`(설치 중 WebView2 를 인터넷에서 받음)라 오프라인 PC 에서는 화면이 안 뜬다.
