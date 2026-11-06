# 개발 세션 인수인계 (2026-11-07 06시 갱신)

다음 개발 세션이 이어서 할 일. CLAUDE.md(지침)를 먼저 읽고, 이 메모는 변하는 진행 상황만 담는다.

## 1. 저장소·빌드 흐름

- 비공개: `sysoppark-oss/story-firewall`(이 저장소, 개발 기준). 공개: `sysoppark-oss/storyfirewall`(CI·릴리스).
- 커밋 반영: 비공개에서 커밋 → `git format-patch -1` → 공개 클론에서 `git am -3` → push. 커밋 해시는 두 저장소에서 다르다
  (공개 쪽 해시로 CI 를 본다). `[devbuild]` 가 붙은 커밋은 공개 CI 가 노트북용 시험 서명 설치 파일을 만든다.
- CI 확인: `gh api "repos/sysoppark-oss/storyfirewall/actions/runs?head_sha=<공개 해시>"` (GraphQL 은 막혀 있음, REST 만).
- 노트북 설치: CI 의 "Dev build" 성공 뒤 `sh scripts/sync-devbuild.sh`(공개 dev-builds → 비공개 dev-builds) →
  `{"job":"install"}` 파일을 노트북 `C:\Program Files\StoryFirewallDev\requests\install-N.json` 으로 보낸다(device_commit_files).
  결과 로그: `...\logs\jobs\install-N.txt`. **다음 번호: install-77, diag-26.**
  노트북 작업 실행기는 설치·진단만 한다 — 정책 적용(차단) 작업은 절대 넣지 않는다.
- `cargo fmt --all` 금지(2026-11-07 사고: 관련 없는 파일 10개가 바뀌어 수집기 목록 시험이 깨짐). 바꾼 파일만 정렬.
- 강제 push 금지. 되돌림은 추가 커밋으로.

## 2. 지금 상태

- 공개 릴리스: **v0.1.2 공개됨**. 다른 노트북에서 v0.1.1 → v0.1.2 자동 업데이트 성공 확인(2026-11-07 04:19).
- 업데이트 서명 키: 비밀 키는 사용자 PC 와 GitHub 저장소 비밀(TAURI_SIGNING_PRIVATE_KEY·_PASSWORD)에만. 세션은 비밀을 쓰지 못함(차단).
  릴리스는 초안으로만 만들고, 공개는 사용자가 브라우저에서 한다.
- 노트북: install-75(사건 추적, 공개 e907a32) 설치·검수 끝(06:13). install-76(공개 de262ef = 프로세스 사건 정상 처리 + 검수 반영) 요청함.
- 이번 세션 커밋(비공개 / 공개): 955f774/e907a32 사건 추적 · aa18ebc/d043818 프로세스 사건 정상 처리 · 9d1673b/de262ef 검수 반영.
- 검증 의뢰서 39차(사건 추적·프로세스 사건 정상 처리) 드라이브에 올림. Gemini 답변 오면 반영.

## 3. 사용자 결정(이번·지난 세션)

- "실시간으로 문제를 찾아야 바로 해결가능함" → 카드 지금 상태, 새 의심 사건 Windows 알림(기본 켬), 판정 15초.
- "지금과 같은 것을 할 수 있는 분석이 프로그램에 필요함" → 자동 조사.
- "분류된 사건에 대한 추적이 반듯이 필요함" → 사건 추적(구현·검수 끝).
- 카드 개편 "좋음" → UI 명세 3판 초안(docs/editions/UI명세_3판_초안.md, 드라이브 "UI 명세 (3판 초안)" — 저장소 초안이 더 새것: 3-8 사건 추적, 3-9 프로세스 사건 정상 처리. 확정 때 드라이브에 3판으로 올릴 것).
- 끊기에서 Windows 기본 프로그램 처리: 사용자가 "아니"(제안 철회) — **지금처럼 경로로 막기 유지**, 다시 묻지 않음.
- 저장소: 비공개 story-firewall 이 개발 기준, 공개 storyfirewall 은 CI·배포용(2026-11-07 사용자 확인).

## 4. 남은 일(순서)

1. install-76 결과(logs\jobs\install-76.txt) 확인 → 노트북에서 (라)·(바) 카드의 "이건 정상입니다" 확인 창·처리 기록 확인.
   (다)·(라)·(바) 사건이 노트북에 없으면 개수 줄·처리 기록 탭만 확인.
2. diag-26: 이야기 목록 응답 시간(지켜보기 뒤 전체 다시 불러오기 10초 넘음 — 39차 Q5). 상태 변경 뒤 카드만 옮기는 쪽 검토.
3. UI 검수 남은 것: 연결 표만 근거 접속이 "외부 접속" 칸을 채우는 카드(helper.exe, D042), 경로 고정폭, 밝은 테마 캡처,
   유입 칸 빗금 툴팁, "지금 상태 확인 못 함" 잡음.
4. 자동 조사 확장: 서비스 등록·예약 작업·Run 키 등록자 대조, 알림 클릭 → 그 카드(Tauri 지원 확인 필요).
5. v0.1.3 릴리스 초안(위가 안정되면). rc1~rc5·rc7 초안 정리.
6. 이전부터 남은 것: 시간대 막대 서비스 집계, 의심 행 "같은 판정 N건 · 처음~마지막", IBM Plex Sans KR, IPsec 문서 확인(38차 Q1③), 불안정 시험
   `rare_writer_is_not_starved_by_busy_writer`.
7. 발견한 것(결정 필요 없음, 고칠 때): score.rs 가 프로세스 뿌리 사건에서 `chain.files.first()`(뿌리가 쓴 첫 파일)를 "뿌리 파일"로 취급해
   서명·경로 가중치와 파일 정상 키를 그 파일에 적용한다. 점수에 영향이 있어 의뢰서에 넣고 Gemini 답변 뒤 손볼 것.

## 5. 노트북 실측 메모

- PID 16720 = Chrome 네트워크 서비스(chrome.exe --utility-sub-type=network.mojom.NetworkService) — 접속이 시작 이벤트보다 먼저 들어와
  "알 수 없는 프로그램"이 됐던 것. 5ac5402 로 고침(이미 저장된 사건은 그대로).
- cmd.exe(부모 chrome.exe) → chrome-native-host.exe = Claude 데스크톱의 Claude in Chrome 보조 프로그램
  (HKCU\...\Chrome\NativeMessagingHosts\com.anthropic.claude_browser_extension, 매니페스트는 Claude_pzs8sxrjxfjjc 패키지 LocalCache).
  같은 PC 에 Microsoft BrowserCore·OneDrive·Defender 등록도 있음. 자동 조사가 이것을 "알려진 정상 모양"으로 판단해야 한다(노트북 확인 필요).
- 진단(diag-25): 증분 판정 평균 360ms·최대 471ms, 전체 판정 3.6초.
