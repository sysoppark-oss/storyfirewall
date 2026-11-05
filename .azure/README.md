# Azure Pipelines — 비용 0 CI (사용자 결정 2026-11-03)

GitHub Actions 무료 사용량이 바닥나고 결제 제한이 걸린 동안 쓰는 CI. **카드 등록 없이** 돌리는 길을 기본으로 한다.

| 실행 위치 | 비용 | 조건 | 여기서 도는 것 |
| --- | --- | --- | --- |
| laptop (노트북 자체 실행기, 선택) | 0 · 무제한 | Azure DevOps 조직의 무료 자체 실행기 1대 | 빌드·서명·dev-builds 게시, Windows 단위 시험 |
| **hosted (Microsoft 호스팅, 기본값)** | 0 (월 1,800분 안) | 조직 sysoppark 에 무료 1개·1,800분 열림 확인(2026-11-03, 지출 한도 걸린 구독 연결 — 넘으면 과금 대신 멈춤) | 위 + 설치·인증 시험 (ETW·WFP 실행 시험은 2단계에서 옮김) |

파이프라인: `devbuild.yml`(노트북용 개발 빌드, 커밋 메시지 `[devbuild]` 또는 수동), `win-tests.yml`(Windows cargo test + UI 시험, main 푸시).
결과: 둘 다 GitHub `ci-logs` 브랜치 `azure/<이름>/run-<번호>/` 에 로그를 올린다(개발 세션이 읽음). 개발 빌드는 `dev-builds` 브랜치.
커밋 메시지에 `[skip ci]` 가 있으면 Azure 도 돌지 않는다.

## 사용자가 할 일 (한 번)
1. https://dev.azure.com → Microsoft 계정으로 로그인 → 조직 만들기 → **비공개(Private)** 프로젝트 `story-firewall`.
2. 프로젝트 설정 → **Agent pools** → Add pool → Self-hosted, 이름 **`laptop`**, "모든 파이프라인에 권한" 켬.
3. (선택 — 1,800분이 모자랄 때만) 노트북 실행기 등록(노트북, **관리자 PowerShell**):
   - Azure DevOps 오른쪽 위 사용자 설정 → Personal access tokens → 새 토큰: 범위 **Agent Pools (Read & manage)** 만, 만료 30일. (등록에 한 번 쓰고 끝)
   - Agent pools → laptop → New agent → Windows x64 의 내려받기 명령을 `C:\azagent` 에서 실행.
   - `.\config.cmd` → 서버 URL `https://dev.azure.com/<조직>`, 인증 PAT(위 토큰), 풀 `laptop`, 이름 `laptop`,
     **서비스로 실행 Y**, 계정은 기본값(NETWORK SERVICE — 관리자 아님) 그대로 Enter.
4. Pipelines → New pipeline → **GitHub (YAML)** → Azure Pipelines 앱을 **이 저장소에만** 허용 → Existing YAML → `/.azure/devbuild.yml` → **Save**(Run 아님).
   같은 방법으로 `/.azure/win-tests.yml`.
5. GitHub fine-grained 토큰: 저장소 `story-firewall` 만, 권한 **Contents: Read and write**, 만료 90일.
   두 파이프라인 각각 Edit → Variables → `GH_PUSH_TOKEN` 에 넣고 **Keep this value secret** 체크.
6. 개발 세션에 알리면 `[devbuild]` 커밋으로 첫 실행을 시작한다.

## 보안
- 실행기 계정은 NETWORK SERVICE(관리자 아님). 노트북에서는 설치·서비스 등록·ETW·WFP 시험을 하지 않는다(실기기 보호, 정책 적용은 VM 먼저).
- GitHub 토큰은 이 저장소 쓰기만. 외부 PR 실행 없음(`pr: none`, 비공개 저장소).
- 개발 빌드 서명 키는 실행마다 새로 만들고 끝에 지운다("dev certs left: 0" 확인).
- GitHub Actions 노트북 실행기(poc/devhost/RUNNER-SETUP.md)는 같은 노트북 메모리를 다투므로 **둘 중 하나만** 쓴다 — Azure 를 쓰면 GitHub 쪽은 등록하지 않는다.
