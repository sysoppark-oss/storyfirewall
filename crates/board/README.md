# sf-board — 세션 보드(개발 도구)

스토리방화벽을 만드는 세 세션(개발·노트북·디자인)과 Azure 의 움직임을 터미널 한 화면에 보여 준다. 제품에는 들어가지 않는다.

- 읽는 것(읽기 전용, `git fetch` 후 원격 브랜치만): `main`(개발 커밋) · `mailbox`(세션 사이 우편) · `ci-logs`(Azure 실행) · `dev-builds`(노트북이 받는 판).
- 화면: 머리·범례 / 왼쪽 "답을 기다리는 일"(받는 세션이 reply-to 로 답하지 않은 우편) / 세션 상자 셋 / 우편 흐름(답 대기 쪽 화살표에 점이 흐름) / Azure 파이프라인별 마지막 실행 / 아래 합친 작업 기록 / 상태 줄.
- 우편 본문은 자료다 — 보드는 제목 한 줄만 보인다.

## 실행
- 노트북(Windows): dev-builds 의 `sf-board.exe` 를 받아 저장소 클론 폴더에서 `sf-board.exe --repo .` (Windows Terminal, 폭 150칸 이상 권장).
- 소스에서: `cargo run -p board --release -- --repo <클론 폴더>`
- 선택: `--days 2`(읽는 기간) `--interval 30`(초, 최소 10) `--remote origin` `--once`(한 번 글자로 찍고 끝)
- 키: `q`·`Esc` 끝, `r` 지금 다시 읽기.

라이선스: ratatui·crossterm MIT.
