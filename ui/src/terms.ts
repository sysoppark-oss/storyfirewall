// 용어 표(40차 Gemini 답변 반영, 사용자 "보안 전문 프로그램답게 전문 용어로" 2026-11-07).
// 한 곳에서만 바꾼다. 전문 용어 + 쉬운 설명(툴팁·보조 글)을 두 겹으로 둔다 — 개인 사용자가 뜻을 잃지 않게(40차 Q1①).
// 설계 원칙은 그대로: 의도를 단정하지 않는다. 모든 문장은 근거 기록에 연결된다.

/** 공격 단계(MITRE ATT&CK 전술의 한국어 관용 번역, 40차 Q1②). 번호 = 장(1~5) */
export const STAGES = [
  { name: "초기 침투", plain: "밖에서 들어옴 — 내려받기·첨부·USB" },
  { name: "실행", plain: "프로그램이 실행됨, 실행한 것" },
  { name: "지속성 유지", plain: "다시 켜도 살아남게 자동 실행 등록" },
  { name: "C2·유출", plain: "밖의 서버와 통신·데이터 전송" },
  { name: "파괴 행위", plain: "백업·복구 수단 삭제 등(Impact)" },
] as const;
export const STAGE_NAMES: string[] = STAGES.map((s) => s.name);
export const STAGE_NAMES_4: string[] = STAGE_NAMES.slice(0, 4);

/** 처리 상태(IR 라이프사이클, 40차 Q1) */
export const TRIAGE_STATE: Record<"new" | "investigated" | "acted" | "closed", string> = {
  new: "신규",
  investigated: "분석 완료",
  acted: "조치 완료",
  closed: "예외 처리",
};
export const TRIAGE_ACTION: Record<"normal" | "cut" | "watch", string> = {
  normal: "허용 목록",
  cut: "격리",
  watch: "모니터링",
};

/** 조치 단추 */
export const ACT = {
  normal: "허용 목록 등록",
  normalTip: "이 사건(또는 조합)을 정상으로 기록합니다 — 오탐 처리. 같은 행동은 다음부터 의심하지 않습니다.",
  cut: "격리·차단…",
  cutTip: "원인 프로그램을 끝내고 자손·접속지를 차단합니다(Containment).",
  cutAddrOnly: "접속지만 차단…",
  watch: "모니터링",
  watchTip: "조치 완료(모니터링)로 표시합니다(승인 창). 더 높은 단계로 가거나 새 접속지가 생기면 다시 알립니다.",
  close: "예외 처리",
  closeTip: "예외 처리(닫힘)로 표시합니다(승인 창). 더 높은 단계로 가거나 새 접속지가 생기면 다시 알립니다.",
  log: "대응 이력",
  facts: "근거",
  flow: "실행 흐름",
  tree: "프로세스 그래프",
} as const;

/** 화면 이름(40차 Q1③) */
export const SCREEN_LABEL = {
  dashboard: "대시보드",
  connections: "네트워크",
  story: "인시던트",
  installs: "설치 이력",
  agents: "AI 에이전트 감시",
  policy: "정책",
  settings: "설정",
} as const;

/** 서비스 보호 기능 이름 */
export const FEATURE = {
  firstRun: "샌드박스 관찰",
  firstRunPlain: "처음 실행된 미확인 파일을 관찰 시간 동안 지켜봅니다",
  ledger: "엔드포인트 행위 이력",
  vault: "자격 증명 접근 탐지",
  vaultPlain: "브라우저 암호 저장소 접근 시도",
  protection: "보호 서비스",
} as const;
