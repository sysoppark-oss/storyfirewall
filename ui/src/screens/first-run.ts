/// 첫 실행 관찰실 (기획서 17판 23-2 ①) 설정의 순수 도우미. 서비스 기본값(svc::first_run::settings_of)과 같게 맞춘다

export type FirstRunMode = "off" | "notify" | "block";
export const FIRST_RUN_MINUTES = [5, 10, 30] as const;

export interface FirstRunSetting {
  mode: FirstRunMode;
  minutes: number;
}

/// 고르는 말과 한 문장 설명. 막기는 관리자 승인 창에서 관찰실 차단 정책(우산)을 확인해야 켜진다(방식 나)
export const FIRST_RUN_CHOICES: readonly { value: FirstRunMode; label: string; sentence: string }[] = [
  { value: "off", label: "사용 안 함", sentence: "처음 실행되는 프로그램을 따로 알리지 않습니다." },
  {
    value: "notify",
    label: "알림만 (기본)",
    sentence: "인터넷에서 받은 서명 없는 프로그램이 처음 실행되면 알리고, 정한 시간 동안 한 일을 이야기로 보여 줍니다.",
  },
  {
    value: "block",
    label: "알림 + 네트워크 차단",
    sentence: "알림에 더해 그 시간 동안 그 프로그램의 나가는 연결(인터넷·내부망)을 막습니다. 서명된 프로그램은 대상이 아니고, Windows 시스템 파일과 정상으로 표시한 프로그램은 막지 않습니다.",
  },
];

/// 막기를 골랐을 때 덧붙이는 한 문장
export const FIRST_RUN_BLOCK_APPROVAL = "관리자 승인 창에서 샌드박스 차단 정책을 확인해야 켜집니다.";

/// settings.get 의 first_run_umbrella(우산 정책 상태) → 한 줄. 막기 모드일 때만 의미가 있다
export function umbrellaText(mode: FirstRunMode, u: unknown): string {
  if (mode !== "block") return "";
  const st = u && typeof u === "object" ? (u as { state?: unknown }).state : undefined;
  if (st === "Confirmed") return "샌드박스 차단 정책: 켜짐 (확인됨)";
  if (st === "Applied") return "관찰실 차단 정책: 확인 대기 — 60초 안에 확인하지 않으면 되돌립니다";
  return "관찰실 차단 정책이 켜져 있지 않아 지금은 알림만 합니다. 저장하면 다시 확인을 받습니다.";
}

export const FIRST_RUN_MINUTES_SENTENCE = "처음 실행된 뒤 이 시간 동안 그 프로그램이 한 일을 따로 지켜봅니다.";

/// settings.get 결과 → 화면 값. 모르는 값은 서비스와 같은 기본(알리기, 10분)
export function firstRunSetting(v: Record<string, unknown>): FirstRunSetting {
  const m = v["first_run_watch"];
  const mode: FirstRunMode = m === "off" || m === "notify" || m === "block" ? m : "notify";
  const n = v["first_run_minutes"];
  const minutes = typeof n === "number" && (FIRST_RUN_MINUTES as readonly number[]).includes(n) ? n : 10;
  return { mode, minutes };
}

export function firstRunSentence(mode: FirstRunMode): string {
  const s = FIRST_RUN_CHOICES.find((c) => c.value === mode)?.sentence ?? "";
  return mode === "block" ? `${s} ${FIRST_RUN_BLOCK_APPROVAL}` : s;
}

/// 대시보드 서비스 사건 줄의 덧붙임: "관찰 끝 14:32" (대상에 until_ts 가 있을 때만)
export function watchUntilText(until: unknown, fmt: (unix: number) => string): string {
  return typeof until === "number" && until > 0 ? `관찰 끝 ${fmt(until)}` : "";
}

/// 변경 장부(17판 23-2 ③)의 기록 범위 안내 — 무엇을 적고 무엇을 못 적는지
export const LEDGER_SCOPE =
  "관찰 시간 동안 이 프로그램과 그 자손이 새로 만들거나 이름을 바꾼 파일을 적습니다(위치·종류 상관없음). 있던 파일의 내용을 고친 것과 지운 것은 아직 적지 못합니다.";

/// 33차 Q1: 대리 실행(시각으로 이음) 안내 — 무엇을 근거로 이었고 무엇을 놓치는지
export const LEDGER_PROXY_NOTE =
  "이 프로그램이 관찰 중일 때 등록된 예약 작업·서비스, 또는 예약 작업·WMI·서비스 도구를 실행한 뒤 2분 안에 그 시스템 기능이 띄운 프로그램이 만든 파일입니다. 등록한 쪽을 Windows 가 알려 주지 않아 부모-자식 관계가 아니라 시각으로 이었습니다 — 그때 관찰 중인 프로그램이 여럿이면 모두에 함께 적고, 관찰이 끝난 뒤(재부팅 뒤 포함, 30일 안) 그 작업·서비스가 실행돼도 적습니다. 다른 프로그램의 것이 섞일 수 있습니다."

/// 변경 장부 한 줄 요약(사실의 개수만)
export function ledgerSummary(run: { procs: string[]; files: string[]; autoruns: unknown[]; remotes: unknown[]; truncated?: boolean; facts_complete?: boolean }): string {
  const more = run.truncated ? " 이상" : "";
  const factMore = run.truncated && !run.facts_complete ? " 이상" : "";
  const parts: string[] = [];
  if (run.files.length) parts.push(`파일 ${run.files.length}개${factMore} 만듦·이름 바꿈`);
  if (run.procs.length > 1) parts.push(`프로그램 ${run.procs.length - 1}개${more} 실행`);
  if (run.autoruns.length) parts.push(`자동 실행 ${run.autoruns.length}건 등록`);
  if (run.remotes.length) parts.push(`접속한 곳 ${run.remotes.length}곳`);
  return parts.length ? parts.join(" · ") : "관찰 시간 동안 적힌 변경이 없습니다";
}
