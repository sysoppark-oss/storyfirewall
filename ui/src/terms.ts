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
/// 심각도 4단계(개편안 2판 2-2). 서비스 Level: Critical/Suspicious/Watch/Normal(소문자로 비교)
export const LEVEL: Record<"critical" | "suspicious" | "watch" | "normal", string> = {
  critical: "심각", suspicious: "높음", watch: "중간", normal: "낮음",
};
/// 높음 이상(알림 대상)인가
export function isHigh(level: string): boolean {
  const l = level.toLowerCase();
  return l === "critical" || l === "suspicious";
}

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
  netx: "NetX로 정밀 진단",
  netxTip: "이 사건의 접속지 주소·포트와 그 이름만 NetX로 넘깁니다(진단 대상은 숫자 주소). 이 단추로는 아무것도 실행·차단되지 않습니다 — 진단 실행은 NetX에서 직접 누릅니다.",
  watch: "모니터링",
  watchTip: "조치 완료(모니터링)로 표시합니다(승인 창). 더 높은 단계로 가거나 새 접속지가 생기면 다시 알립니다.",
  undoAuto: "자동 대응 되돌리기",
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

/** UI 명세 4판 3-11: 용어 풀이(한두 문장, 단정 없음). 화면에서 점선 밑줄 + 0.2초 뒤 말풍선(키보드 포커스로도) */
export const GLOSSARY: Record<string, string> = {
  "초기 침투": "프로그램이 이 PC 에 처음 들어온 단계입니다 — 인터넷에서 내려받기, 메일 첨부, USB 등.",
  "실행": "들어온 프로그램이 실행된 단계입니다. 그 프로그램이 다른 프로그램을 띄운 것도 여기에 들어갑니다.",
  "지속성 유지": "다시 켜도 저절로 실행되도록 자동 실행에 등록한 단계입니다(Run 키·예약 작업·시작 폴더 등).",
  "C2·유출": "이 PC 의 프로그램이 바깥 서버에 접속해 명령을 받거나 자료를 보낼 수 있는 단계입니다. 접속했다는 사실만 보며, 오간 내용은 보지 않습니다.",
  "파괴 행위": "백업·복구 수단을 지우는 명령(섀도 복사본 삭제 등)이 실행된 단계입니다(MITRE T1490).",
  "WFP": "Windows Filtering Platform — Windows 에 들어 있는 통신 거름 장치입니다. 이 앱의 차단 정책은 WFP 필터로 걸립니다.",
  "샌드박스 관찰": "인터넷에서 받은 서명 없는 프로그램이 처음 실행되면, 정한 시간 동안 그 프로그램이 한 일을 따로 지켜보는 기능입니다.",
  "기준선": "프로그램별 평소 행동(어디에 접속하는지 등)을 모아 둔 기록입니다. 처음 14일은 모으는 기간이라 '처음 보는' 판정이 많을 수 있습니다.",
  "격리·차단": "원인 프로그램을 끝내고, 그 경로와 접속지를 WFP 로 막고, 자동 실행 등록을 지우는 조치입니다.",
  "허용 목록": "정상으로 기록한 행동입니다. 같은 행동은 다음부터 의심하지 않습니다.",
  "서명": "프로그램 파일에 붙은 디지털 서명입니다. 누가 만들었는지와 만든 뒤 바뀌지 않았는지를 확인합니다.",
  "ASN": "인터넷 망 번호(자율 시스템 번호)입니다. 그 주소를 어느 회사·기관의 망이 쓰는지 알려 줍니다.",
};
