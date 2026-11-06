# 개발 세션 인수인계 (2026-11-07 05시)

다음 개발 세션이 이어서 할 일. CLAUDE.md(지침)를 먼저 읽고, 이 메모는 변하는 진행 상황만 담는다.

## 1. 저장소·빌드 흐름

- 비공개: `sysoppark-oss/story-firewall`(이 저장소, 개발 기준). 공개: `sysoppark-oss/storyfirewall`(CI·릴리스).
- 커밋 반영: 비공개에서 커밋 → `git format-patch -1` → 공개 클론에서 `git am -3` → push. 커밋 해시는 두 저장소에서 다르다
  (공개 쪽 해시로 CI 를 본다). `[devbuild]` 가 붙은 커밋은 공개 CI 가 노트북용 시험 서명 설치 파일을 만든다.
- CI 확인: `gh api "repos/sysoppark-oss/storyfirewall/actions/runs?head_sha=<공개 해시>"` (GraphQL 은 막혀 있음, REST 만).
- 노트북 설치: CI 의 "Dev build" 성공 뒤 `sh scripts/sync-devbuild.sh`(공개 dev-builds → 비공개 dev-builds) →
  `{"job":"install"}` 파일을 노트북 `C:\Program Files\StoryFirewallDev\requests\install-N.json` 으로 보낸다(device_commit_files).
  결과 로그: `...\logs\jobs\install-N.txt`. **다음 번호: install-75, diag-26.**
  노트북 작업 실행기는 설치·진단만 한다 — 정책 적용(차단) 작업은 절대 넣지 않는다.
- `cargo fmt --all` 금지(2026-11-07 사고: 관련 없는 파일 10개가 바뀌어 수집기 목록 시험이 깨짐). 바꾼 파일만 정렬.
- 강제 push 금지. 되돌림은 추가 커밋으로.

## 2. 지금 상태

- 공개 릴리스: **v0.1.2 공개됨**(사용자가 공개). 다른 노트북에서 v0.1.1 → v0.1.2 자동 업데이트 성공 확인(2026-11-07 04:19).
- 업데이트 서명 키: 비밀 키는 사용자 PC 와 GitHub 저장소 비밀(TAURI_SIGNING_PRIVATE_KEY·_PASSWORD)에만. 세션은 비밀을 쓰지 못함(차단).
  릴리스는 초안으로만 만들고, 공개는 사용자가 브라우저에서 한다.
- 노트북: install-72(실시간 1~3), install-73(자동 조사), install-74(카드 개편 65dd076, CI 전부 성공) 요청함.
  새 세션은 logs\jobs\install-72~74.txt 결과부터 확인하고, 이야기 화면(자동 조사 결론·Chrome 보조 프로그램 판단)을 볼 것.
- 이번 세션 커밋(비공개 해시): 5ac5402 늦은 ProcessStart 이름 넘겨받기 · eee9302 fmt 되돌림 · 3ec6e72/f2fa5d2 카드 지금 상태 ·
  c66ae4b Windows 알림 · eb89c0f 판정 15초 · 4ea9cc0 자동 조사(story.investigate, NativeMessagingHosts) ·
  6aebc29/c69416c 카드 개편(UI 3판 초안).

## 3. 사용자 결정(이번 세션)

- "실시간으로 문제를 찾아야 바로 해결가능함" → 제품: 카드 지금 상태, 새 의심 사건 Windows 알림(기본 켬), 판정 15초.
- "지금과 같은 것을 할 수 있는 분석이 프로그램에 필요함" → 자동 조사(실물·서명·명령줄·부모·브라우저 확장 보조 프로그램 등록).
- "분류된 사건에 대한 추적이 반듯이 필요함" → 사건 추적(아래 4-1). 설계 제시함, 반대 없음.
- 카드 개편 스케치 "좋음" → UI 명세 3판 초안(docs/editions/UI명세_3판_초안.md, 드라이브 "UI 명세 (3판 초안)").
  드라이브 초안은 첫 판 — 저장소 초안에 검수 반영분이 더 있다. 확정 때 맞출 것.
- 끊기에서 Windows 기본 프로그램 처리: 사용자가 "아니"(제안 철회) — **지금처럼 경로로 막기 유지**, 다시 묻지 않음(나중에 사용자가 정함).

## 4. 남은 일(순서)

1. **사건 추적**: 처리 상태(새 사건 → 조사됨 → 조치함[정상·끊음·지켜보기] → 닫힘), 처리 기록(조치할 때만 DB 쓰기, 보관 1년 제안),
   이야기 화면 상태별 개수·필터(기본 "처리 안 한 사건"), 대시보드 "처리 안 한 의심 N건", 알림은 처리 안 한 것만, 재발 이어 붙이기.
2. **프로세스에서 시작한 사건의 "이건 정상입니다"**: 예외 단위 = 부모 프로그램 → 실행된 도구 → 그 도구가 띄운 프로그램(경로+서명).
   judge baseline feedback_normal 에 새 키 종류, score.rs 에서 대조. 지금은 파일 뿌리·금고 경비만 된다.
3. UI 검수 남은 것: 연결 표만 근거 접속이 "외부 접속" 칸을 채우는 카드(helper.exe, D042 확인), 경로 고정폭, 밝은 테마 캡처,
   유입 칸 빗금 툴팁, "지금 상태 확인 못 함" 잡음(노트북 화면 보고 판단).
4. 자동 조사 확장: 서비스 등록·예약 작업·Run 키 등록자 대조, 알림 클릭 → 그 카드(Tauri 지원 확인 필요).
5. v0.1.3 릴리스 초안(위가 안정되면). rc1~rc5·rc7 초안 정리.
6. 이전부터 남은 것: 시간대 막대 서비스 집계, 의심 행 "같은 판정 N건 · 처음~마지막", IBM Plex Sans KR, IPsec 문서 확인(38차 Q1③), 불안정 시험
   `rare_writer_is_not_starved_by_busy_writer`.

## 5. 노트북 실측 메모

- PID 16720 = Chrome 네트워크 서비스(chrome.exe --utility-sub-type=network.mojom.NetworkService) — 접속이 시작 이벤트보다 먼저 들어와
  "알 수 없는 프로그램"이 됐던 것. 5ac5402 로 고침(이미 저장된 사건은 그대로).
- cmd.exe(부모 chrome.exe) → chrome-native-host.exe = Claude 데스크톱의 Claude in Chrome 보조 프로그램
  (HKCU\...\Chrome\NativeMessagingHosts\com.anthropic.claude_browser_extension, 매니페스트는 Claude_pzs8sxrjxfjjc 패키지 LocalCache).
  같은 PC 에 Microsoft BrowserCore·OneDrive·Defender 등록도 있음. 자동 조사가 이것을 "알려진 정상 모양"으로 판단해야 한다(노트북 확인 필요).
- 진단(diag-25): 증분 판정 평균 360ms·최대 471ms, 전체 판정 3.6초.
