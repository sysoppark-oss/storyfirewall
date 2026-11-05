# story-firewall 패치 (원판 ferrisetw 1.2.0, MIT OR Apache-2.0 — License.md)

crates.io 원판을 그대로 옮기고 아래만 바꿨다. 워크스페이스 `[patch.crates-io]` 로 쓴다.

1. `src/lib.rs`: `pub static RAW_TIMESTAMP: AtomicBool` (기본 false).
2. `src/native/etw_types.rs`: 실시간 소비를 열 때 `RAW_TIMESTAMP` 가 true 면 `PROCESS_TRACE_MODE_RAW_TIMESTAMP` 를 더한다.

이유: ETW 가 FILETIME 으로 바꿔 주는 시각은 세션 시작 때의 기준을 써서, 이후 시스템 시각 변경(W32Time 되돌림 등)을
따라가지 않는다(B2 3회차 실측 152.8초 어긋남, 23차 답변 Q2). 수집기는 QPC 원시 값을 받아 스스로 (QPC, 벽시계) 쌍으로 바꾼다
(collector/src/qpc.rs).
3. `src/lib.rs` 맨 위 `#![allow(warnings)]` — 원판 경고(경로 의존성이 되면 보임)를 숨김. 동작 변화 없음.
