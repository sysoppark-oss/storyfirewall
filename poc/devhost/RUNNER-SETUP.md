# 노트북 실행 서버(self-hosted runner) 설정 — 사용자 결정 2026-11-03 "(다)"

GitHub 이 주는 무료 사용량을 다 쓴 동안, 노트북을 GitHub Actions 실행 서버로 쓴다. **빌드·단위 시험만** 노트북에서 한다.

## 노트북에서 도는 것 / 돌지 않는 것
| 워크플로 | 노트북 | 이유 |
| --- | --- | --- |
| Dev build for the laptop (devbuild) | 빌드·서명·dev-builds 게시만 | 설치·서비스 등록 시험은 건너뜀(노트북은 설치 대상) |
| Windows unit tests (laptop runner) | cargo test, vitest | 관리자 권한 불필요 |
| A3 수집기(ETW), A5 WFP, A17 서비스, A28 설치, B2, devhost, A15 UI e2e | 돌지 않음 | 관리자 권한·WFP·서비스 설치 — 실기기 보호(지침: 정책 적용은 VM 먼저). GitHub 사용량이 돌아오면 GitHub 러너에서 |

## 보안 조건
- 실행 서버 서비스 계정: 기본값 `NT AUTHORITY\NETWORK SERVICE`(관리자 아님). 관리자 계정으로 바꾸지 않는다.
- 저장소는 비공개 유지. 쓰기 권한자만 워크플로를 돌릴 수 있다(외부 PR 실행 없음).
- devbuild 는 실행마다 자체 서명 인증서(개인키)를 실행 계정의 인증서 저장소에 만들고 끝에 지운다. 지우기 실패 시 그 빌드의 지문으로만 통하는 키가 남는다 — 로그의 "dev certs left: 0" 확인.
- 실행 서버는 github.com 으로만 나간다(작업 내려받기·로그 올리기). 자동 업데이트 포함.

## 준비물 (노트북)
- Git for Windows, Visual Studio 2022 Build Tools("C++를 사용한 데스크톱 개발"), 디스크 여유 20GB 이상 권장(Rust·Tauri 빌드 폴더).
- Rust·Node 는 작업이 실행 계정에 직접 설치한다(dtolnay/rust-toolchain, actions/setup-node).
- 노트북 확인(L027): 디스크 107GB 여유, Git 2.56, VS 2022 Build Tools(C++) 있음, RAM 5.8GB(여유 0.5GB) — 컴파일은 2개씩(CARGO_BUILD_JOBS=2). 전원 연결 시 절전 안 함.

## 등록 (사용자가 직접 — 등록 토큰은 1시간짜리 비밀값)
1. github.com/sysoppark-oss/story-firewall → Settings → Actions → Runners → **New self-hosted runner** → Windows, x64.
2. 노트북에서 **관리자 PowerShell**: 화면의 "Download" 명령을 `C:\actions-runner` 에서 그대로 실행.
3. "Configure" 명령에 아래를 덧붙여 실행:
   `./config.cmd --url https://github.com/sysoppark-oss/story-firewall --token <화면의 토큰> --name laptop --labels sf-laptop --runasservice`
   서비스 계정을 물으면 Enter(기본값 NETWORK SERVICE).
4. GitHub 의 Runners 목록에 `laptop`(Idle) 이 보이면, 같은 Settings → **Secrets and variables → Actions → Variables** 에서
   **New repository variable**: 이름 `SF_LAPTOP_RUNNER`, 값 `1`. (개발 세션의 GitHub 연결은 Actions 설정 경로가 막혀 있어 사용자가 한다)
5. 개발 세션에 알리면 개발 세션이 devbuild·Windows 단위 시험을 수동 실행해 확인한다.
   주의(L027): 지금 GitHub 실패 사유가 "결제 실패"를 포함한다. 결제 문제로 계정이 제한된 경우 self-hosted 실행도 막히는지는 확인 못 함(추측) — 첫 실행에서 확인.

## 끄기
- 저장소 변수 `SF_LAPTOP_RUNNER` 를 지우면 노트북으로 가는 작업이 없어진다(개발 세션이 할 수 있음).
- 완전히 제거: 관리자 PowerShell 에서 `C:\actions-runner\config.cmd remove --token <Runners 화면의 Remove 토큰>`.
