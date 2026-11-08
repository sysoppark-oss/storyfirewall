// 인시던트 화면 드릴다운 필터(UI 명세 4판 3-2). 대시보드·상단 띠·팔레트가 주소 매개변수로 넘기고,
// 인시던트 화면은 이것을 지울 수 있는 칩으로 보여 준다. 서비스 질의(level_min·triage)로 못 거르는 것은 화면에서 거른다.
import { STAGES, LEVEL, TRIAGE_STATE } from "../terms";
type TriageState = "new" | "investigated" | "acted" | "closed";

export interface StoryFilter {
  /// 서비스 level_min (watch·suspicious·critical·normal)
  level?: string;
  /// 그 심각도만(도넛 조각) — level_min 위에서 화면이 한 번 더 거른다
  levelEq?: string;
  /// 서비스 triage (open·done·all)
  triage?: string;
  /// 처리 상태 한 가지만(처리 상태 막대)
  state?: TriageState;
  /// 조치함 · 지켜보기만(지켜보는 중 칩)
  watching?: boolean;
  /// 그 단계(1~4)까지 도달한 것만(킬체인 칸)
  stage?: number;
  /// 마지막 활동 시각 범위(unix 초, [from, to))
  from?: number;
  to?: number;
  /// 샌드박스 관찰 중인 것만
  sandbox?: boolean;
}

const LEVELS = new Set(["watch", "suspicious", "critical", "normal"]);
const TRIAGES = new Set(["open", "done", "all"]);
const STATES = new Set(["new", "investigated", "acted", "closed"]);

/// 주소 매개변수 → 필터(모르는 값은 버린다 — 매개변수도 외부 입력처럼 다룬다)
export function parseFilter(a: Record<string, unknown>): StoryFilter {
  const f: StoryFilter = {};
  if (typeof a["level"] === "string" && LEVELS.has(a["level"])) f.level = a["level"];
  if (typeof a["levelEq"] === "string" && LEVELS.has(a["levelEq"])) f.levelEq = a["levelEq"];
  if (typeof a["triage"] === "string" && TRIAGES.has(a["triage"])) f.triage = a["triage"];
  if (typeof a["state"] === "string" && STATES.has(a["state"])) f.state = a["state"] as TriageState;
  if (a["watching"] === true) f.watching = true;
  if (typeof a["stage"] === "number" && a["stage"] >= 1 && a["stage"] <= 4) f.stage = Math.floor(a["stage"]);
  if (typeof a["from"] === "number" && Number.isFinite(a["from"])) f.from = a["from"];
  if (typeof a["to"] === "number" && Number.isFinite(a["to"])) f.to = a["to"];
  if (a["sandbox"] === true) f.sandbox = true;
  // 상태·지켜보기는 서비스 triage 와 맞춘다(미조치 상태를 "조치함" 목록에서 찾지 않게)
  if (f.state && !f.triage) f.triage = f.state === "new" || f.state === "investigated" ? "open" : "done";
  if (f.watching && !f.triage) f.triage = "done";
  if (f.levelEq && !f.level) f.level = f.levelEq;
  return f;
}

/// 화면이 거르는 사건 모양(story.ts StoryEvent 중 쓰는 것)
export interface FilterableEvent {
  level: string;
  reached?: number[];
  last_ts?: number;
  sentences?: { ts?: number }[];
  triage?: { state: string; action?: string } | null;
  first_run_watch?: { until_ts: number } | null;
}

const FT_UNIX = 116_444_736_000_000_000;
const unixOf = (ft: number) => (ft - FT_UNIX) / 10_000_000;

/// 화면 쪽 거르기(순수 함수 — 시험용)
export function matches(ev: FilterableEvent, f: StoryFilter, nowSec: number): boolean {
  if (f.levelEq && ev.level.toLowerCase() !== f.levelEq) return false;
  if (f.state && (ev.triage?.state ?? "new") !== f.state) return false;
  if (f.watching && !(ev.triage?.state === "acted" && ev.triage.action === "watch")) return false;
  if (f.stage && !(ev.reached ?? []).includes(f.stage)) return false;
  if (f.from != null || f.to != null) {
    const ft = ev.last_ts || ev.sentences?.find((s) => s.ts)?.ts || 0;
    if (!ft) return false;
    const t = unixOf(ft);
    if (f.from != null && t < f.from) return false;
    if (f.to != null && t >= f.to) return false;
  }
  if (f.sandbox && !(ev.first_run_watch && ev.first_run_watch.until_ts > nowSec)) return false;
  return true;
}

/// 지울 수 있는 칩(화면이 거르는 것만 — 심각도·처리 상태 선택 상자는 따로 있다)
export function filterChips(f: StoryFilter): { key: keyof StoryFilter | "time"; label: string }[] {
  const out: { key: keyof StoryFilter | "time"; label: string }[] = [];
  if (f.levelEq) out.push({ key: "levelEq", label: `심각도: ${LEVEL[f.levelEq as keyof typeof LEVEL] ?? f.levelEq}만` });
  if (f.state) out.push({ key: "state", label: `처리 상태: ${TRIAGE_STATE[f.state]}` });
  if (f.watching) out.push({ key: "watching", label: "지켜보는 중" });
  if (f.stage) out.push({ key: "stage", label: `단계: ${STAGES[f.stage - 1]?.name ?? f.stage}까지 간 것` });
  if (f.from != null || f.to != null) out.push({ key: "time", label: `시간: ${hourLabel(f.from, f.to)}` });
  if (f.sandbox) out.push({ key: "sandbox", label: "샌드박스 관찰 중" });
  return out;
}

function hourLabel(from?: number, to?: number): string {
  const h = (t: number) => {
    const d = new Date(t * 1000);
    const hh = d.getHours();
    return `${hh < 12 ? "오전" : "오후"} ${hh % 12 === 0 ? 12 : hh % 12}시`;
  };
  if (from != null && to != null && to - from === 3600) return `${h(from)}대`;
  return [from != null ? h(from) : "", to != null ? h(to) : ""].join(" ~ ");
}

/// 칩 하나 지우기
export function dropChip(f: StoryFilter, key: keyof StoryFilter | "time"): StoryFilter {
  const g = { ...f };
  if (key === "time") {
    delete g.from;
    delete g.to;
  } else delete g[key];
  return g;
}
