import { withIcon, copyButton } from "./dash-viz";
import { parseFilter, matches, filterChips, dropChip, type StoryFilter } from "./story-filter";
import { STAGES, STAGE_NAMES_4, TRIAGE_STATE, TRIAGE_ACTION, ACT, LEVEL, isHigh } from "../terms";
import { mutation, rpc, uuid, type RpcResult, type RpcError } from "../rpc";
import { approvalBox, countdown, type ApplyReply } from "../confirm";
import { fileName } from "../sanitize";
import { flowView } from "./flow";
import { mindmap } from "./mindmap";
import type { Where } from "./connections";
import { summarizeGaps, groupStories, sumGroupSources } from "./story-group";
import { openProcessDrawer } from "./process";
import { el, ext, button, clear, fmtTs, fmtShort, fmtShortSec, fmtRange, filetimeToUnix, errorBox, extPath, dataPath, term } from "../ui";
import { loadingBox, failBox, isBusy, noDataBox, collectionStalled, type HealthLike } from "../list-state";
import { state } from "../state";

export interface Sentence {
  text: string;
  ts: number;
  edge_ids: number[];
  evidence: number[];
  chapter: number | null;
  /// 구조형(D003-2): 주체 → 동작 대상. 동작만 굵게
  parts?: { subject: string; verb: string; object: string };
  /// 수집 시작 때 이미 열려 있던 연결뿐인 줄(D006-1)
  already_open?: boolean;
  /// 근거 출처별 수(B1)
  sources?: [string, number][];
  /// D028-1: 서비스 경유 귀속이면 짝지은 두 이벤트의 시각 차(ms)
  via_lag_ms?: number;
}

/// 근거 출처 → 사용자 말(B1). 개발 용어는 툴팁에만
const SOURCE_KO: Record<string, string> = {
  etw: "실시간 기록", conntable: "연결 표", motw: "파일 표시", defender: "Windows 보안 기록", snapshot: "시작 시 목록",
  signature: "서명 검사", autorun: "레지스트리 대조", registry: "레지스트리 대조", sysmon: "Sysmon 기록", scm: "서비스 목록",
  capi2: "인증서 조회 기록", memscan: "메모리 검사",
};
/// D044-2: 연결 표만 근거인 접속 — 오늘 한 일 문장 끝(회색)과 배지 툴팁에 같은 말. 카드에는 항목을 만들지 않는다(판정도 4장으로 안 씀)
export const TABLE_ONLY_NOTE = "연결 표만(프로세스 확인 못 함)";
export function tableOnly(sources: [string, number][] | undefined): boolean {
  return !!sources && sources.length > 0 && sources.every(([s]) => s === "conntable");
}
/// "근거 3 · 실시간 기록 2 · 연결 표 1". 연결 표뿐이면 점선(덜 확실 — ETW 가 아니라 1초 대조로만 확인)
export function evidenceBadge(sources: [string, number][], onClick: () => void): HTMLElement {
  const n = sources.reduce((a, [, k]) => a + k, 0);
  const onlyTable = sources.length > 0 && sources.every(([s]) => s === "conntable");
  const text = onlyTable ? `근거 ${n} · 연결 표만` : [`근거 ${n}`, ...sources.map(([s, k]) => `${SOURCE_KO[s] ?? s} ${k}`)].join(" · ");
  const b = el("button", onlyTable ? "ev-badge weak" : "ev-badge", text);
  b.type = "button";
  b.title = `${sources.map(([s, k]) => `${s} ${k}`).join(", ")}${onlyTable ? ` — ${TABLE_ONLY_NOTE} · 실시간 기록(ETW)이 아니라 1초 연결 표 대조로만 확인` : ""}. 누르면 근거 이벤트`;
  b.addEventListener("click", onClick);
  return b;
}
interface StoryEvent {
  root: number;
  title: string;
  level: string;
  chapter: string;
  score: number;
  sentences: Sentence[];
  items?: { label: string; value: string; edge_ids: number[]; sources?: [string, number][] }[];
  reached?: number[];
  /// 10판 5-9 (1): 5장 파괴 징후(가장 이른 것)
  destroy?: { kind: string; sentence: string; cmdline: string; ts: number; edge_id: number };
  /// 정상 처리 가능(파일에서 시작한 사건). false 면 "이건 정상입니다"를 숨긴다
  feedback_ok?: boolean;
  /// 프로세스에서 시작한 사건의 정상 처리 단위 "부모 → 도구 → (띄운 프로그램)" — 있으면 누르기 전에 이 조합을 확인받는다
  feedback_unit?: string;
  /// 정상 처리를 할 수 없는 이유(39차 Q1②: 부모를 모르는 도구 등). 있으면 안내 줄에 이 문장을 쓴다
  feedback_note?: string;
  last_ts?: number;
  /// 수집 시작 전부터 실행 중이던 프로세스의 시작 시각(L024)
  running_since?: number;
  /// 25차 Q1: 기록 없는 구간(서비스 중지·절전) 안에서 시작 — [from, to] FILETIME
  started_in_gap?: [number, number];
  /// D020-1: 뿌리가 Windows 핵심 프로세스(svchost·explorer 등) — 끝내지 않는다
  root_core?: boolean;
  root_image?: string;
  /// 17판 23-2 ①: 첫 실행 관찰실 기록(사실 한 줄 + 관찰 끝 unix 초)
  first_run_watch?: { text: string; until_ts: number };
  root_signature?: { signer?: string | null; sig_status?: string | null } | null;
  /// D039-2: 뿌리가 파일이면 그 파일의 실행 횟수·처음·마지막(FILETIME)·가장 최근 프로세스 노드
  root_exec?: { count: number; first_ts: number; last_ts: number; latest_proc: number | null } | null;
  /// UI 3판 초안: 카드 제목 사슬(부모 → 주인공 → 실행한 프로그램)
  root_chain?: { parent?: string | null; children: string[]; children_total: number } | null;
  /// 실시간 1: 주인공 프로세스가 지금 실행 중인지(서비스가 카드를 줄 때 조회)
  root_live?: { running: boolean; pid: number; ended: boolean } | null;
  /// D022-4: 가장 늦은 외부 접속지와 그 나라
  egress?: string;
  egress_where?: Where | null;
  /// 오늘(관측 뒤) 새 활동이 있는가(D004-2). 없으면 접힌 묶음
  fresh?: boolean;
  /// 사건 추적: 처리 상태(서비스가 카드마다 붙임. 없으면 새 사건)
  triage?: Triage | null;
}
/// 사건 추적 — 처리 상태. 새 사건 → 조사됨 → 조치함(정상·끊음·지켜보기) → 닫힘
export type TriageState = "new" | "investigated" | "acted" | "closed";
export type TriageAction = "normal" | "cut" | "watch";
export interface Triage {
  state: TriageState;
  action?: TriageAction;
  chapter: number;
  /// unix 초
  updated_ts: number;
  note?: string;
  /// 재발 횟수(조치·닫기 뒤 새 사건으로 되돌아온 수)
  recur_count?: number;
}
export interface TriageCounts { new: number; investigated: number; acted: number; closed: number }
export const TRIAGE_STATE_KO: Record<TriageState, string> = TRIAGE_STATE;
export const TRIAGE_ACTION_KO: Record<TriageAction, string> = TRIAGE_ACTION;
/// 자동 대응 메모 `auto:<policy_id>:<version>` 풀기(개편안 2판 4-2)
export function parseAutoNote(note: string | null | undefined): { policyId: number; version: number } | null {
  const m = /^auto:(\d+):(\d+)$/.exec(note ?? "");
  return m ? { policyId: Number(m[1]), version: Number(m[2]) } : null;
}
/// 상태 칩 글자: "조치함 · 지켜보기"처럼 조치 종류까지
export function triageText(t: Triage | null | undefined): string {
  const st = t?.state ?? "new";
  return st === "acted" && t?.action ? `${TRIAGE_STATE_KO[st]} · ${TRIAGE_ACTION_KO[t.action]}` : TRIAGE_STATE_KO[st];
}
/// 처리 상태 칩. 새 사건=테두리만(눈에 띄게 할 것은 수준 칩), 조사됨=회색, 조치함=초록, 닫힘=연회색
export function triageChip(t: Triage | null | undefined): HTMLElement {
  const st = t?.state ?? "new";
  const c = el("span", `chip triage ${st}`, triageText(t) + (t?.recur_count ? ` · 재발 ${t.recur_count}회` : ""));
  const parts: string[] = [];
  if (t && t.updated_ts) parts.push(`${fmtTs(t.updated_ts)}에 바뀜`);
  if (t?.note) parts.push(`메모: ${t.note}`);
  c.title = parts.length ? parts.join(" · ") : "아직 아무 처리도 하지 않은 사건입니다.";
  return c;
}
/// 화면 위 개수 한 줄(39차 Q4: 화면에 보이는 묶음(카드)을 앞세우고 사건 수는 괄호 안에):
/// "처리 안 한 묶음 8개 (사건 81건: 새 사건 41 · 조사됨 40) · 조치함 4 · 닫힘 1". 카드 수를 모르면 사건 수만
export function triageCountsText(c: TriageCounts | undefined, cards?: number): string {
  if (!c) return "";
  const open = c.new + c.investigated;
  const head = cards === undefined ? `미조치 인시던트 ${open}` : `미조치 ${cards}건 (이벤트 ${open}건`;
  const tail = cards === undefined ? ` (${TRIAGE_STATE.new} ${c.new} · ${TRIAGE_STATE.investigated} ${c.investigated})` : `: ${TRIAGE_STATE.new} ${c.new} · ${TRIAGE_STATE.investigated} ${c.investigated})`;
  return `${head}${tail} · ${TRIAGE_STATE.acted} ${c.acted} · ${TRIAGE_STATE.closed} ${c.closed}`;
}

const LEVEL_KO: Record<string, string> = LEVEL;
const CHAPTERS = STAGE_NAMES_4;
/// D043-1: 5장(파괴 징후)은 칸을 늘리지 않는다(카드끼리 칸 위치가 같아야 훑어보기가 된다) — 막대 아래 destroyLine 한 줄

/// 수준 칩 (D002): 의심=빨강, 주의=주황
export function levelChip(level: string): HTMLElement {
  const l = level.toLowerCase();
  return el("span", `chip level-${l}`, LEVEL_KO[l] ?? level);
}
/// 카드 제목 = 프로그램 이름만(D003-3): "[의심] " 머리와 " — 4장 외부 접속까지 진행 (점수…)" 꼬리를 뗀다.
/// 수준은 칩이, 진행은 4칸 막대가 맡는다
export function bareTitle(t: string): string {
  return t.replace(/^\[[^\]]*\]\s*/, "").replace(/\s+—\s+\S+\s.*까지 진행.*$/, "");
}
/// 4칸 진행 막대 (D003-1): 6px 막대 + 아래 12px 글자. 해당함=수준 색 채움 / 해당 없음=연회색 / 기록 없음=빗금(D004).
/// 클릭할 수 없다(단추처럼 보이지 않게)
export function chapterSteps(reached: number[], score: number, unrecorded: number[] = []): HTMLElement {
  const box = el("div", "steps");
  CHAPTERS.forEach((name, i) => {
    const n = i + 1;
    const st = unrecorded.includes(n) && !reached.includes(n) ? "none" : reached.includes(n) ? "on" : "off";
    // 4판 3-11: 단계 이름에 용어 풀이(점선 밑줄)
    const cell = el("span", `step ${st}`, el("span", "bar"), el("span", "lbl", term(name)));
    if (st === "none") cell.title = "Story Firewall 이 기록을 시작하기 전의 일이라 기록이 없습니다.";
    box.append(cell);
  });
  box.title = `판정 규칙 점수 ${score} (0~100). 높을수록 4장 판정의 여러 칸이 맞았습니다.`;
  return box;
}
/// D022-2·3: 같은 이름 항목은 한 항목에 " · " 로(근거 수 합산). Windows 폴더 + 유효 서명이면 "출신: 확인되지 않음" → "Windows 기본 파일"
export function mergeItems<T extends { label: string; value: string; edge_ids: number[]; sources?: [string, number][] }>(items: T[], windowsSigned = false): T[] {
  const out: T[] = [];
  for (const it0 of items) {
    const it = windowsSigned && it0.label === "출신" && it0.value === "확인되지 않음" ? { ...it0, value: "Windows 기본 파일" } : it0;
    const prev = out.find((x) => x.label === it.label);
    if (!prev) { out.push({ ...it, edge_ids: [...it.edge_ids], sources: it.sources ? [...it.sources] : undefined }); continue; }
    if (!prev.value.split(" · ").includes(it.value)) prev.value = `${prev.value} · ${it.value}`;
    prev.edge_ids.push(...it.edge_ids);
    if (it.sources?.length) {
      const m = new Map<string, number>(prev.sources ?? []);
      for (const [k, n] of it.sources) m.set(k, (m.get(k) ?? 0) + n);
      prev.sources = [...m.entries()].sort((a, b) => b[1] - a[1]);
    }
  }
  return out;
}
export function isWindowsSigned(ev: { root_image?: string; root_signature?: { sig_status?: string | null } | null }): boolean {
  const p = (ev.root_image ?? "").toLowerCase().replace(/\//g, "\\");
  return /^[a-z]:\\windows\\/.test(p) && (ev.root_signature?.sig_status ?? "") === "valid";
}
/// D014-1·33차 검수 1: "기록 없는 구간(오후 12:36 ~ 오후 1:21)에 시작(오후 1:01) — …". 구간은 다른 화면과 같은 fmtRange 형식(명세 2-3, D042)
export function gapStartText(fromFt: number, toFt: number, startFt?: number, now: Date = new Date()): string {
  const range = fmtRange(filetimeToUnix(fromFt), filetimeToUnix(toFt), now);
  const st = startFt ? `(${fmtShort(filetimeToUnix(startFt), now)})` : "";
  return `기록 없는 구간(${range})에 시작${st} — 서비스가 멈췄거나 PC 가 절전 중이던 때`;
}
/// "시작 4월 14일 오후 2:38" — 연도는 올해가 아닐 때만(D004-1)
export function sinceText(unixSec: number, now: Date = new Date()): string {
  const d = new Date(unixSec * 1000);
  const hm = d.toLocaleTimeString("ko-KR", { hour: "numeric", minute: "2-digit" });
  const y = d.getFullYear() === now.getFullYear() ? "" : `${d.getFullYear()}년 `;
  return `수집 시작 전부터 실행 중 · 시작 ${y}${d.getMonth() + 1}월 ${d.getDate()}일 ${hm}`;
}
/// 오늘 한 일 한 줄(D003-2): [시각] 주체 → **동작** 대상. 외부 문자열은 텍스트 노드로만
let explainFn: ((edge: number, into: HTMLElement) => Promise<void>) | null = null;
/// D014-3: 이름을 모르는 프로세스("pid 4" — 예전 기록)는 "알 수 없는 프로그램(PID 4)" 회색
export function subjectName(subject: string): { text: string; unknown: boolean } {
  const m = /^pid (\d+)$/.exec(subject);
  if (m) return { text: `알 수 없는 프로그램(PID ${m[1]})`, unknown: true };
  return { text: subject, unknown: /^알 수 없는 프로그램\(PID \d+\)$/.test(subject) };
}
/// D014-4: "오늘"은 지역 시각 0시 이후. "최근 24시간"이면 지금부터 24시간 전 이후
export function sinceOf(mode: "today" | "24h", now: Date = new Date()): number {
  if (mode === "24h") return Math.floor(now.getTime() / 1000) - 86400;
  const d = new Date(now);
  d.setHours(0, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}
export function todayLine(s: Sentence, seconds = false): HTMLElement {
  // D032-2: 묶음(같은 분)을 펼친 줄은 초까지 — 머리 줄과 구분된다
  const when = el("span", "muted when", seconds ? fmtShortSec(filetimeToUnix(s.ts)) : fmtShort(filetimeToUnix(s.ts)));
  // D006-1: 수집 시작 때 이미 열려 있던 연결은 회색 + 동작 뒤에 표시(사실은 남긴다)
  const open = s.already_open ? [" ", el("span", "open-note", "(수집 시작 때 이미 열려 있음)")] : [];
  const line = s.parts
    ? el("div", s.already_open ? "sentence muted already-open" : "sentence", when, " ", subjectSpan(s.parts.subject), " → ", el("b", undefined, s.parts.verb), ...open, " ", extPath("span", s.parts.object))
    : el("div", s.already_open ? "sentence muted already-open" : "sentence", when, " ", extPath("span", s.text), ...open);
  line.title = fmtTs(filetimeToUnix(s.ts));
  if (tableOnly(s.sources)) line.append(el("span", "muted", ` · ${TABLE_ONLY_NOTE}`));
  if (s.sources?.length && explainFn && s.edge_ids[0] != null) {
    const box = el("div", "evidence-box");
    const edge = s.edge_ids[0];
    const badge = evidenceBadge(s.sources, () => (box.firstChild ? clear(box) : void explainFn!(edge, box)));
    // D028-1: 경유 문장의 근거("시각 대조" 등)는 짝지은 두 이벤트의 시각 차로 확인할 수 있게
    if (s.via_lag_ms != null) badge.title = `짝지은 두 이벤트의 시각 차 ${s.via_lag_ms}ms · ${badge.title}`;
    line.append(badge, box);
  }
  return line;
}
function subjectSpan(subject: string): HTMLElement {
  const n = subjectName(subject);
  return ext("span", n.text, n.unknown ? "muted" : undefined);
}
/// 시각순(오름차순). 같은 시각은 원래(장면) 순서 유지 — Array.sort 는 안정 정렬
export function sortToday<T extends { ts: number }>(xs: T[]): T[] {
  return [...xs].sort((a, b) => a.ts - b.ts);
}

/// D030-2: 같은 분 · 같은 주체 이름 · 같은 동작 · 같은 대상 이름은 한 줄로(예: git 작업 한 번에 "git-credential-manager.exe → 실행 git.exe" 수십 줄).
/// 사실은 버리지 않는다 — members 에 그대로, 근거 출처 수는 합친다. 결과는 대표(첫 줄) 시각 순
export interface TodayGroup { s: Sentence; members: Sentence[] }
export function groupToday(xs: Sentence[]): TodayGroup[] {
  const MIN = 60 * 10_000_000;
  const out: TodayGroup[] = [];
  const at = new Map<string, TodayGroup>();
  for (const s of xs) {
    const body = s.parts ? `${s.parts.subject}\u0000${s.parts.verb}\u0000${s.parts.object}` : s.text;
    const k = `${Math.floor(s.ts / MIN)}\u0000${s.already_open ? 1 : 0}\u0000${body}`;
    const g = at.get(k);
    if (g) {
      g.members.push(s);
      continue;
    }
    const ng = { s, members: [s] };
    at.set(k, ng);
    out.push(ng);
  }
  return out.map((g) => {
    if (g.members.length === 1) return g;
    const sum = new Map<string, number>();
    for (const m of g.members) for (const [src, n] of m.sources ?? []) sum.set(src, (sum.get(src) ?? 0) + n);
    return { s: { ...g.s, sources: [...sum.entries()] }, members: g.members };
  });
}

interface CutProc {
  node_id: number;
  pid: number;
  create_ts: number;
  image: string;
  system: boolean;
  ended: boolean;
}
interface CutAddress {
  who: string;
  ip: string;
  port: number;
  proto: number;
  why: string;
}
interface Gap {
  from_ts: number;
  to_ts: number;
  events: number;
  reason: string;
}
interface CutPlan {
  root: number;
  root_label: string;
  block_images: string[];
  terminate: CutProc[];
  excluded_system: CutProc[];
  injected_hosts: CutProc[];
  addresses: CutAddress[];
  system_addresses: [string, number][];
  autoruns: [string, string][];
  written_executables: string[];
  warnings: string[];
  validation?: { errors: string[]; warnings: string[] };
  root_hash: { recorded: string | null; current: string | null; status: string };
}

const HASH_TEXT: Record<string, [string, string]> = {
  match: ["ok", "뿌리 파일이 사건 당시(처음 본 때)와 같은 내용입니다."],
  changed: ["error", "뿌리 파일의 내용이 사건 당시와 다릅니다. 같은 경로에 다른 파일이 놓였을 수 있습니다."],
  missing: ["warn", "뿌리 파일이 이미 없습니다(삭제·이동)."],
  unrecorded: ["muted", "사건 당시 해시 기록이 없어 같은 파일인지 확인할 수 없습니다."],
  too_large: ["muted", "파일이 커서 지금 해시를 다시 계산하지 않았습니다."],
  no_root: ["muted", ""],
}

/// 오늘의 이야기 + 사건 카드. "왜?" → story.explain (근거 원시 이벤트).
export function story(args: Record<string, unknown> = {}): HTMLElement {
  // UI 명세 4판 3-2: 대시보드·띠·팔레트가 넘긴 필터. 심각도·처리 상태는 선택 상자에, 나머지는 지울 수 있는 칩으로
  let filt: StoryFilter = parseFilter(args);
  const root = el("section", "screen");
  root.append(el("h1", undefined, "인시던트"));
  const level = el("select");
  // 개편안 2판 2-2: 낮음은 기본 숨김, "전부"로 본다(토글)
  for (const [v, l] of [["watch", "중간 이상"], ["suspicious", "높음 이상"], ["critical", "심각만"], ["normal", "전부(낮음 포함)"]] as const) {
    const o = el("option", undefined, l);
    o.value = v;
    level.append(o);
  }
  // 사건 추적: 처리 상태 필터(기본 "처리 안 한 사건") + 상태별 개수
  const triageSel = el("select");
  for (const [v, l] of [["open", "미조치"], ["done", "조치·예외 처리"], ["all", "전부"]] as const) {
    const o = el("option", undefined, l);
    o.value = v;
    triageSel.append(o);
  }
  if (filt.level) level.value = filt.level;
  if (filt.triage) triageSel.value = filt.triage;
  triageSel.addEventListener("change", () => void load());
  const chipRow = el("div", "filter-chips");
  chipRow.setAttribute("aria-label", "적용된 필터");
  const paintChips = () => {
    const cs = filterChips(filt);
    chipRow.replaceChildren(...cs.map((c) => {
      const b = button(`${c.label} ×`, () => { filt = dropChip(filt, c.key); paintChips(); void load(); }, "chip filter-chip");
      b.title = "이 필터 지우기";
      b.setAttribute("aria-label", `${c.label} 필터 지우기`);
      return b;
    }));
    chipRow.hidden = !cs.length;
  };
  paintChips();
  // 4판 3-5: 일괄 처리 — 카드 왼쪽 체크칸, 2개 이상이면 아래 고정 바(처리 상태만: 분석 완료·지켜보기·예외 처리. 끊기·허용은 두지 않는다)
  const selected = new Set<number>();
  const bulk = el("div", "bulk-bar");
  bulk.setAttribute("role", "region");
  bulk.setAttribute("aria-label", "선택한 인시던트 일괄 처리");
  bulk.hidden = true;
  const paintBulk = () => {
    const n = selected.size;
    bulk.hidden = n < 2;
    if (n < 2) return clear(bulk);
    const roots = [...selected];
    const out = el("span", "muted small");
    const done = () => { selected.clear(); paintBulk(); void load(); };
    const viaSet = async (state: "acted" | "closed", action?: "watch") => {
      const note = state === "closed" ? (prompt("예외 처리 이유(선택, 200자까지)") ?? undefined) : undefined;
      const r = await mutation("story.triage_set", { root: roots[0], state, ...(action ? { action } : {}), ...(note ? { note: note.slice(0, 200) } : {}), also: roots.slice(1) });
      if (!r.ok) return void out.replaceChildren(el("span", "error", `실패: ${r.error.message}`));
      done();
    };
    bulk.replaceChildren(el("b", undefined, `${n}개 선택`),
      button("분석 완료", async () => {
        // 조사됨은 조회 권한(승인 창 없음) — 새 인시던트만 바뀐다
        await Promise.all(roots.map((root) => rpc("story.triage", { root, state: "investigated" })));
        done();
      }, "btn small"),
      withIcon(button(`${ACT.watch} (승인 창 1번)`, () => void viaSet("acted", "watch"), "btn small"), "eye"),
      withIcon(button(`${ACT.close}… (승인 창 1번)`, () => void viaSet("closed"), "btn small"), "check-circle"),
      button("선택 해제", () => { selected.clear(); for (const b of cards.querySelectorAll<HTMLInputElement>("input.pick")) b.checked = false; paintBulk(); }, "btn small"),
      out);
  };
  const pickBox = (root: number): HTMLInputElement => {
    const b = el("input", "pick") as HTMLInputElement;
    b.type = "checkbox";
    b.checked = selected.has(root);
    b.setAttribute("aria-label", `인시던트 #${root} 선택`);
    b.addEventListener("change", () => { if (b.checked) selected.add(root); else selected.delete(root); paintBulk(); });
    return b;
  };
  // 4판 3-3: [지켜보는 중] 칩 — 조치 완료 · 지켜보기만
  const watchChip = button("지켜보는 중", () => {
    filt = filt.watching ? dropChip(filt, "watching") : { ...filt, watching: true, triage: "done" };
    if (filt.watching) triageSel.value = "done";
    paintChips();
    void load();
  }, "chip filter-chip watch-chip");
  watchChip.title = "조치 완료 · 모니터링으로 표시한 인시던트만";
  const countsLine = el("div", "muted small triage-counts");
  // 사건 추적 개수(화면이 새 사건을 조사됨으로 올릴 때 서비스를 다시 부르지 않고 이 값을 고쳐 보인다)
  let counts: TriageCounts | undefined;
  let openCards: number | undefined;
  const cards = el("div", "cards-col");
  const today = el("div", "story-today");
  // D014-4: 오늘 한 일 범위(기본 오늘 = 지역 0시 이후)
  const range = el("select");
  for (const [v, l] of [["today", "오늘"], ["24h", "최근 24시간"]] as const) {
    const o = el("option", undefined, l);
    o.value = v;
    range.append(o);
  }
  range.addEventListener("change", () => void load());
  root.append(el("div", "toolbar", "심각도 ", level, " 처리 상태 ", triageSel, " ", watchChip), chipRow, countsLine, cards, bulk, el("h2", "today-head", "엔드포인트 활동 타임라인 ", range), today);

  const explain = async (edgeId: number, into: HTMLElement) => {
    clear(into);
    const r = await rpc<{ evidence: { id: number; ts: number; source: string; kind: string; detail?: string }[] }>("story.explain", { edge_id: edgeId });
    if (!r.ok) return into.append(errorBox(r.error.message));
    for (const e of r.result.evidence) {
      into.append(el("div", "evidence", `${fmtTs(filetimeToUnix(e.ts))} [${e.source}] `, ext("span", e.kind), " ", ext("span", e.detail ?? "")));
    }
  };

  explainFn = explain;
  const load = async () => {
    selected.clear();
    paintBulk();
    clear(cards);
    clear(today);
    cards.append(loadingBox());
    today.append(loadingBox());
    const [r, t, h] = await Promise.all([
      rpc<{ items: StoryEvent[]; gaps?: Gap[]; counts?: TriageCounts; hidden_low?: number }>("story.events", { level_min: level.value, triage: triageSel.value, cursor: { limit: 50 } }),
      // L030: 범위를 서비스에 넘긴다(전에는 서비스가 DB 전체를 문장으로 만들었다)
      rpc<{ sentences: Sentence[]; truncated?: boolean }>("story.today", { since_ts: sinceOf(range.value === "24h" ? "24h" : "today") * 10_000_000 + 116_444_736_000_000_000 }),
      rpc<HealthLike>("collector.health", {}),
    ]);
    const health = h.ok ? h.result : null;
    paintToday(t, r.ok ? null : r.error, health);
    clear(cards);
    // D013: 오류는 "사건 없음"으로 그리지 않는다
    if (!r.ok) return cards.append(failBox(r.error, () => void load(), "인시던트 목록"));
    counts = r.result.counts;
    countsLine.textContent = triageCountsText(counts);
    // 저장 실패·과부하로 버린 구간만(기록 없는 구간 no_record 는 이 문장이 아니다 — 카드의 ⚠ 줄·진단 화면에서 따로 보인다)
    // L053: 구간마다 카드 한 장씩이면 이야기가 화면 밖으로 밀린다 → 한 줄 요약 + 펼쳐 보기
    const gs = summarizeGaps(r.result.gaps ?? []);
    if (gs) {
      const det = el("details", "card gap");
      det.append(el("summary", undefined, `⚠ ${fmtRange(filetimeToUnix(gs.first_ts), filetimeToUnix(gs.last_ts))} 사이 ${gs.count}번, 기록 ${gs.events}건이 저장 과부하로 빠졌습니다. 이 구간의 인시던트는 완전하지 않을 수 있습니다.`));
      for (const g of gs.list) det.append(el("div", "muted", `${fmtTs(filetimeToUnix(g.from_ts))} ~ ${fmtTs(filetimeToUnix(g.to_ts))} · ${g.events}건`));
      cards.append(det);
    }
    // D015-4: 0건이어도 수집이 멈췄으면 "없음"이 아니라 "수집 안 됨"
    if (!r.result.items.length) cards.append(collectionStalled(health) ? noDataBox() : el("p", "muted", emptyText(triageSel.value, r.result.counts)));
    // 4판 3-2: 칩 필터(단계·시간·샌드박스·심각도만·처리 상태) — 서비스가 못 거르는 것
    const nowSec = Date.now() / 1000;
    const items = r.result.items.filter((ev) => matches(ev, filt, nowSec));
    if (r.result.items.length && !items.length) cards.append(el("p", "muted", "이 필터에 맞는 인시던트가 없습니다. 위 칩을 지우면 전체 목록으로 돌아갑니다."));
    // D004-2: 오늘 새 활동이 없는 "수집 전부터 실행 중" 사건은 아래 접힌 묶음(한 줄 목록)으로
    const stale = items.filter((ev) => ev.fresh === false);
    // D020-2: 같은 프로그램·같은 판정은 한 장 + "N건" + 발생 시각 목록(최신 먼저)
    const groups = groupStories(items.filter((ev) => ev.fresh !== false));
    // 39차 Q4: 묶음(카드) 수를 앞세운다 — 처리 안 한 사건 필터일 때만 카드 수가 "처리 안 한 묶음"이다
    openCards = triageSel.value === "open" ? groups.length : undefined; // 수집 전부터 실행 중 묶음(stale)은 한 줄 목록이라 세지 않는다
    countsLine.textContent = triageCountsText(counts, openCards);
    for (const g of groups) {
      // 근거 배지는 묶음 합계(대표만이 아니라 N건 전부). 발생 목록은 카드의 "발생 N번" 탭(UI 3판 초안)
      const card = buildCard(sumGroupSources(g.head, g.members), g.members);
      cards.append(card);
    }
    if (stale.length) {
      // D006-2: 머리에 수준 집계 — 의심이 접혀 안 보이는 일을 막는다. 의심이 있으면 빨간 세로 띠
      const sus = stale.filter((e) => isHigh(e.level)).length;
      const wat = stale.filter((e) => e.level.toLowerCase() === "watch").length;
      const det = el("details", sus ? "stale-group has-suspicious" : "stale-group");
      const summ = el("summary", undefined, `수집 전부터 실행 중 · 오늘 새 활동 없음 (${stale.length}건`);
      if (sus) summ.append(" · ", levelChip("suspicious"), ` ${sus}`); // 심각·높음 합산
      if (wat) summ.append(" · ", levelChip("watch"), ` ${wat}`);
      summ.append(")");
      det.append(summ);
      for (const ev of stale) {
        const row = el("div", "stale-row", levelChip(ev.level), ext("span", bareTitle(ev.title), "prog"),
          el("span", "muted", ev.running_since ? sinceText(filetimeToUnix(ev.running_since)).replace("수집 시작 전부터 실행 중 · ", "") : ""));
        const slot = el("div", "stale-card");
        row.dataset["root"] = String(ev.root);
        row.append(button("인시던트 보기", () => {
          if (slot.firstChild) return clear(slot);
          slot.append(buildCard(ev));
        }, "btn small"));
        det.append(row, slot);
      }
      cards.append(det);
    }
    // 개편안 2판 2-2(42차 Q3): 등급 필터로 숨긴 사건은 목록 하단 요약 칩으로 존재를 알린다 — 누르면 "전부"로
    const hidden = r.result.hidden_low ?? 0;
    if (hidden > 0 && level.value !== "normal") {
      const chipRow = el("div", "hidden-low-row");
      const b = button(level.value === "watch" ? `${LEVEL.normal} ${hidden}건 숨김 · 전부 보기` : `이 심각도 아래 ${hidden}건 숨김 · 전부 보기`, () => { level.value = "normal"; void load(); }, "btn small chip-low");
      chipRow.append(b);
      cards.append(chipRow);
    }
    // D023-1: 대시보드·상태 줄·정책에서 "이야기 보기"로 왔으면 그 카드로(처음 한 번)
    if (typeof args["root"] === "number" && !focused) {
      focused = true;
      focusRoot(args["root"]);
    }
  };
  let focused = false;
  /// 그 사건의 카드로 이동해 1.5초 강조. 접힌 묶음 안이면 펼치고, 묶인 사건이면 발생 시각 목록을 펼쳐 그 줄도 강조.
  /// 외부 문자열을 선택자에 쓰지 않는다 — data-root(숫자)와 대조
  const focusRoot = (root: number) => {
    const key = String(root);
    const flash = (x: HTMLElement) => {
      x.classList.add("flash");
      setTimeout(() => x.classList.add("flash-out"), 1500);
      setTimeout(() => x.classList.remove("flash", "flash-out"), 2300);
    };
    let target = [...cards.querySelectorAll<HTMLElement>(".card.event")].find((c) => c.dataset["root"] === key);
    if (!target) {
      // 묶인 사건(발생 N번 탭 안): 그 카드의 탭을 연다
      for (const c of cards.querySelectorAll<HTMLElement>(".card.event")) {
        const occ = c.querySelector<HTMLButtonElement>(".tab-btn[data-tab=occ]");
        if (occ && !c.querySelector(".detail-panel[data-tab=occ]")) {
          occ.click();
          if (![...c.querySelectorAll<HTMLElement>(".stale-row")].some((r) => r.dataset["root"] === key)) occ.click();
        }
      }
    }
    if (!target) {
      const row = [...cards.querySelectorAll<HTMLElement>(".stale-row")].find((r) => r.dataset["root"] === key);
      if (row) {
        const det = row.closest("details");
        if (det) det.open = true;
        const card = row.closest(".card.event") as HTMLElement | null;
        if (card) {
          // 묶인 사건: 대표 카드로 가고 그 줄을 강조
          target = card;
          flash(row);
        } else {
          // 접힌 "수집 전부터 실행 중" 묶음: 카드를 그 자리에 열고 그 카드로
          row.querySelector("button")?.click();
          target = (row.nextElementSibling?.firstElementChild as HTMLElement | null) ?? row;
        }
      }
    }
    if (!target) return;
    target.scrollIntoView({ block: "start" });
    flash(target);
    // D027-3: 프로그램 상세의 조치 단추로 왔으면 이 카드의 끊기(또는 이 접속지만 차단) 대화상자를 연다 — 대화상자는 한 곳에서만 만든다
    if (args["cut"] === true) target.querySelector<HTMLButtonElement>(".actions button.danger-outline")?.click();
  };
  // 오늘 한 일: 자기 상태를 따로(D015-3). 위 목록과 같은 오류면 한 번만 크게, 여기는 회색 한 줄
  const paintToday = (t: RpcResult<{ sentences: Sentence[]; truncated?: boolean }>, aboveErr: RpcError | null, health: HealthLike | null) => {
    clear(today);
    if (!t.ok) {
      if (aboveErr && aboveErr.code === t.error.code && aboveErr.message === t.error.message)
        return today.append(el("p", "muted", isBusy(t.error) ? "위 목록과 함께 잠시 뒤 다시 불러옵니다." : "위 오류로 표시하지 못했습니다."));
      return today.append(failBox(t.error, () => void load(), "오늘 한 일"));
    }
    const since = sinceOf(range.value === "24h" ? "24h" : "today");
    const xs = t.result.sentences.filter((s) => !s.ts || filetimeToUnix(s.ts) >= since);
    if (!xs.length) return today.append(collectionStalled(health) ? noDataBox() : el("p", "muted", range.value === "24h" ? "최근 24시간에 기록된 일이 없습니다." : "오늘 기록된 일이 없습니다."));
    if (t.result.truncated) today.append(el("p", "muted small", "기록이 많아 가장 최근 것부터 일부만 표시합니다."));
    for (const g of groupToday(sortToday(xs)).slice(-200)) {
      const line = todayLine(g.s);
      if (g.members.length > 1) {
        // 묶인 줄: "×N" 칩을 누르면 개별 시각·근거
        const more = el("div", "today-members");
        more.hidden = true;
        for (const m of g.members) more.append(todayLine(m, true));
        const chip = button(`×${g.members.length}`, () => { more.hidden = !more.hidden; }, "chip-n chip-btn");
        chip.title = "같은 분에 같은 일이 여러 번 — 눌러서 하나씩 보기";
        // D035 관찰: "×2 · 근거 11"이 헷갈리지 않게 근거 배지 툴팁에 "2번 · 기록 11개"
        const badge = line.querySelector<HTMLElement>(":scope > .ev-badge");
        const nRec = (g.s.sources ?? []).reduce((a, [, k]) => a + k, 0);
        if (badge) badge.title = `${g.members.length}번 · 기록 ${nRec}개 · ${badge.title}`;
        line.insertBefore(chip, line.querySelector(":scope > .ev-badge, :scope > .evidence-box") ?? null);
        today.append(line, more);
      } else today.append(line);
    }
  };
  // UI 3판 초안(사용자 "좋음" 2026-11-07): 요약(사슬 한 줄) → 결론(자동 조사) → 조치(권장 단추 하나) → 자세히(한 번에 하나).
  // 카드 안에 카드를 넣지 않는다 — 같은 모양의 반복은 "발생 N번" 탭의 줄로
  const buildCard = (ev: StoryEvent, members: StoryEvent[] = []): HTMLElement => {
    {
      const card = el("div", `card event ${ev.level.toLowerCase()}`);
      card.dataset["root"] = String(ev.root);
      // 카드 시각 = 마지막 활동(L021). 예전 서비스면 첫 문장 시각
      const lastTs = ev.last_ts || ev.sentences.find((s) => s.ts)?.ts;
      const when = el("span", "muted when", lastTs ? fmtShort(filetimeToUnix(lastTs)) : "");
      if (lastTs) when.title = `마지막 활동 ${fmtTs(filetimeToUnix(lastTs))}`;
      const fileRoot = ev.root_exec?.latest_proc != null ? ev.root_exec : null;
      // 1) 요약: 부모 → 주인공 → 실행한 프로그램. 주인공 이름은 프로그램 상세 단추(D025-A5·D030-4)
      const h3 = el("h3");
      const name = bareTitle(ev.title);
      const nameNode: Node = ev.root_image
        ? (() => {
            const b = button(name, () => (fileRoot ? openProcessDrawer(fileRoot.latest_proc!, execRange(fileRoot)) : openProcessDrawer(ev.root)), "cell-btn hero-name");
            b.title = "프로그램 상세";
            h3.classList.add("clickable");
            return b;
          })()
        : ext("span", name, "hero-name");
      const ch = ev.root_chain;
      if (ch?.parent) h3.append(ext("span", ch.parent, "chain-part"), el("span", "chain-arrow", " → "));
      h3.append(nameNode);
      if (ch?.children.length) {
        h3.append(el("span", "chain-arrow", " → "), ext("span", chainKids(ch.children, ch.children_total), "chain-part"));
      }
      h3.title = chainTitle(name, ch);
      if (members.length > 1) h3.append(el("span", "badge count", `${members.length}번`));
      const head = el("div", "card-head", pickBox(ev.root), levelChip(ev.level), triageChip(ev.triage), h3, when);
      card.append(head);
      if (members.length > 1) {
        const first = members.reduce((a, m) => Math.min(a, m.last_ts || a), Infinity);
        if (Number.isFinite(first) && lastTs) card.append(el("div", "since", `같은 모양 ${members.length}번 · ${fmtRange(filetimeToUnix(first), filetimeToUnix(lastTs))}`));
      }
      // 검수(2026-11-07 3판): "어디에 접속했는지"를 카드 머리에서 — 자세히를 열지 않아도
      if (ev.egress) card.append(el("div", "since egress", ext("span", `접속: ${ev.egress}${ev.egress_where?.country ? ` (${ev.egress_where.country}${ev.egress_where.org ? ` · ${ev.egress_where.org}` : ""})` : ""}`)));
      // 실시간 1: 지금 상태(시각은 오른쪽 위 하나만)
      if (ev.root_live) {
        const line = el("div", ev.root_live.running ? "since live on" : "since live", el("span", "dot"), " ", liveText(ev.root_live));
        if (!ev.root_live.running && !ev.root_live.ended) line.title = "끝난 기록이 없고, 지금 같은 번호(PID)로 떠 있는 프로세스가 같은 프로그램인지 확인되지 않았습니다(번호는 다른 프로그램이 다시 쓸 수 있음).";
        card.append(line);
      }
      card.append(chapterSteps(ev.reached ?? [], ev.score, ev.running_since ? [1, 2] : []));
      if (ev.destroy) card.append(destroyLine(ev.destroy));
      // 2) 결론: 자동 조사(판단 + 근거). 권장 조치가 정해지면 3)의 그 단추만 강조한다
      const actions = el("div", "actions");
      let normalBtn: HTMLButtonElement | null = null;
      if (ev.feedback_ok !== false) {
        normalBtn = withIcon(button(ACT.normal, async () => {
          // 프로세스에서 시작한 사건: 정상으로 보는 범위(조합)를 먼저 보이고 확인받는다 — 도구 전체가 아니라 이 조합만
          if (ev.feedback_unit && !confirm(feedbackUnitText(ev.feedback_unit))) return;
          const r2 = await mutation("judge.feedback_normal", { root: ev.root });
          if (!r2.ok) return alert(`실패: ${r2.error.message}`);
          // 정상 처리 = 조치함(정상)으로 서비스가 적는다 — 이 카드만 옮긴다(39차 Q5)
          settleCard({ state: "acted", action: "normal", chapter: ev.triage?.chapter ?? 0, updated_ts: Math.floor(Date.now() / 1000) });
        }), "shield-check");
      }
      // D020-1: 핵심 프로세스는 끝내지 않는다 — 같은 자리에 "이 접속지만 차단"
      const cutBtn = ev.root_core
        ? withIcon(button(ACT.cutAddrOnly, () => void cutDialog(ev.root, card, "접속지만 차단"), "btn danger-outline"), "ban")
        : withIcon(button(ACT.cut, () => void cutDialog(ev.root, card), "btn danger-outline"), "scissors");
      card.append(investigateBox(ev.root, ev.destroy?.cmdline ?? null, (rec) => {
        // D1: 빨간 채움 단추는 쓰지 않는다 — 권장이면 테두리를 굵게 하고 "권장" 표시만
        if (rec === "cut") { cutBtn.classList.add("recommended"); cutBtn.prepend("권장 · "); }
        if (rec === "mark_normal" && normalBtn) normalBtn.classList.add("primary");
        // 사건 추적: 자동 조사가 끝난 새 사건은 "조사됨"으로(한 번만 — 서비스는 상태가 바뀔 때만 기록한다)
        if ((ev.triage?.state ?? "new") === "new") {
          void rpc<Triage>("story.triage", { root: ev.root, state: "investigated" }).then((r) => {
            if (!r.ok) return;
            ev.triage = r.result;
            head.querySelector(".chip.triage")?.replaceWith(triageChip(r.result));
            // 노트북 검수(install-75): 전에는 개수 줄을 비워 첫 화면에서 늘 사라졌고, 조사됨이 된 카드에 "처리 기록" 탭이 없었다
            if (counts && r.result.state === "investigated") {
              counts = { ...counts, new: Math.max(0, counts.new - 1), investigated: counts.investigated + 1 };
              countsLine.textContent = triageCountsText(counts, openCards);
            }
            if (!actions.querySelector('[data-tab="log"]')) actions.querySelector(".spacer")?.before(tab(ACT.log, "log", () => triageLogPanel(ev.root)));
          });
        }
      }));
      // 사건 추적 단추: 지켜보기(조치함) · 닫기. 끊기·정상은 서비스가 성공할 때 스스로 조치함으로 적는다
      // 39차 Q3: 조치함·닫힘은 알림을 끄는 변경 — 승인 창(story.triage_set, 관리자)을 거친다. 조사됨만 조회 권한
      // 39차 Q5: 성공하면 목록 전체를 다시 부르지 않고(노트북 10초) 이 카드만 옮긴다 — 처리 안 한 사건 필터면 카드를 빼고 개수 줄을 고친다
      const triageSet = async (state: TriageState, action?: TriageAction) => {
        const note = state === "closed" ? (prompt("닫는 이유(선택, 200자까지)") ?? undefined) : undefined;
        const r = await mutation<Triage>("story.triage_set", { root: ev.root, state, ...(action ? { action } : {}), ...(note ? { note: note.slice(0, 200) } : {}) });
        if (!r.ok) return alert(`실패: ${r.error.message}`);
        settleCard(r.result);
      };
      /// 상태가 처리한 쪽으로 바뀐 뒤 화면만 고친다(목록 다시 안 부름)
      const settleCard = (t: Triage) => {
        const before = ev.triage?.state ?? "new";
        ev.triage = t;
        if (counts) {
          const c = { ...counts };
          if (before === "new") c.new = Math.max(0, c.new - 1); else if (before === "investigated") c.investigated = Math.max(0, c.investigated - 1); else if (before === "acted") c.acted = Math.max(0, c.acted - 1); else c.closed = Math.max(0, c.closed - 1);
          if (t.state === "acted") c.acted += 1; else if (t.state === "closed") c.closed += 1;
          counts = c;
        }
        if (triageSel.value === "open") {
          card.remove();
          if (openCards !== undefined) openCards = Math.max(0, openCards - 1);
          countsLine.textContent = triageCountsText(counts, openCards);
          if (!cards.querySelector(".card.event")) cards.append(el("p", "muted", emptyText(triageSel.value, counts)));
        } else {
          head.querySelector(".chip.triage")?.replaceWith(triageChip(t));
          countsLine.textContent = triageCountsText(counts, openCards);
          if (t.state === "closed") closeBtn.remove();
          if (t.state === "acted" && t.action === "watch") watchBtn.remove();
        }
      };
      const st = ev.triage?.state ?? "new";
      const watchBtn = withIcon(button(ACT.watch, () => void triageSet("acted", "watch"), "btn"), "eye");
      watchBtn.title = ACT.watchTip;
      const closeBtn = withIcon(button(ACT.close, () => void triageSet("closed"), "btn"), "check-circle");
      closeBtn.title = ACT.closeTip;
      // 3) 조치 + 4) 자세히(탭 단추: 누르면 아래 한 칸에 하나만)
      const panel = el("div", "detail-panel");
      const tabs: HTMLButtonElement[] = [];
      const tab = (label: string, key: string, make: () => HTMLElement) => {
        const b = button(label, () => {
          const open = panel.dataset["tab"] === key;
          clear(panel);
          tabs.forEach((t) => { t.classList.remove("on"); t.setAttribute("aria-selected", "false"); });
          if (open) { delete panel.dataset["tab"]; return; }
          panel.dataset["tab"] = key;
          b.classList.add("on");
          b.setAttribute("aria-selected", "true");
          panel.append(make());
        }, "u-tab tab-btn");
        // UI 명세 4판 3-5: 밑줄 탭(한 번에 하나, 다시 누르면 닫힘)
        b.setAttribute("role", "tab");
        b.setAttribute("aria-selected", "false");
        b.dataset["tab"] = key;
        tabs.push(b);
        return b;
      };
      // D1 단추 순서: 보조(자세히 탭) 왼쪽 → 주(정상) → 파괴적(끊기, 빨간 테두리) 오른쪽 끝
      actions.append(el("span", "muted small", "자세히"),
        tab(ACT.facts, "facts", () => factsPanel(ev, fileRoot)),
        // D049: 흐름 보기(장 레일 + 관계 지도 + 선택한 것 + 오늘 한 일 꼬리)
        tab(ACT.flow, "flow", () => flowView(ev)),
        tab(ACT.tree, "mindmap", () => mindmap(ev.root)));
      if (members.length > 1) actions.append(tab(`발생 ${members.length}번`, "occ", () => occurrencesPanel(members)));
      if (st !== "new") actions.append(tab(ACT.log, "log", () => triageLogPanel(ev.root)));
      actions.append(el("span", "spacer"));
      if (!(st === "acted" && ev.triage?.action === "watch")) actions.append(watchBtn);
      if (st !== "closed") actions.append(closeBtn);
      if (normalBtn) actions.append(normalBtn);
      actions.append(cutBtn);
      // 개편안 2판 4-2: 파괴 행위 자동 대응이 끊은 사건(메모 auto:<policy_id>:<version>) → [되돌리기] (정책 되돌리기 + 사건을 다시 염)
      const auto = parseAutoNote(ev.triage?.note);
      if (auto) {
        const undo = button(ACT.undoAuto, async () => {
          if (!confirm("자동 대응으로 넣은 차단 정책을 되돌리고 사건을 다시 엽니다. 종료된 프로세스는 돌아오지 않습니다.")) return;
          if (auto.policyId > 0) {
            // version 을 넘기면 "그 판으로 되돌리기"(판 1 → 판 1, 그대로 남음 — A29 실측). 빼야 제거된다
            const r = await mutation("policy.rollback", { policy_id: auto.policyId });
            if (!r.ok) return alert(`실패: ${r.error.message}`);
          }
          await triageSet("investigated");
          undo.remove();
        }, "btn");
        withIcon(undo, "rewind");
        undo.title = auto.policyId > 0 ? `자동 대응 정책 ${auto.policyId}:${auto.version} 을 되돌립니다` : "되돌릴 정책이 없습니다(종료만 했음) — 사건만 다시 엽니다";
        actions.append(undo);
      }
      card.append(actions);
      // D1: 안내 줄은 단추 줄 바로 아래 — 탭 패널이 열려도 떨어지지 않게
      const note = cardNote(!!ev.root_core, ev.feedback_ok === false, ev.feedback_note);
      if (note) card.append(el("p", "muted small core-note", note));
      card.append(panel);
      return card;
    }
  };
  /// "사실" 탭: 판정 항목(근거 배지) + 위치·서명 + 시작 시각 줄
  const factsPanel = (ev: StoryEvent, fileRoot: StoryEvent["root_exec"] | null): HTMLElement => {
    const box = el("div", "facts-panel");
    if (ev.first_run_watch) {
      const fw = el("div", "since", ext("span", ev.first_run_watch.text));
      fw.title = `관찰 끝 ${fmtTs(ev.first_run_watch.until_ts)}`;
      box.append(fw);
    }
    // D014-1: 기록 없는 구간에 시작했으면 "수집 시작 전부터"가 아니다 — 🕒 줄 대신 ⚠ 줄에 시작 시각을 합친다
    if (ev.running_since && !ev.started_in_gap) {
      const since = el("div", "since", el("span", "clock", "🕒"), " ", sinceText(filetimeToUnix(ev.running_since)));
      since.title = fmtTs(filetimeToUnix(ev.running_since));
      box.append(since);
    }
    if (ev.started_in_gap) {
      const [gf, gt] = ev.started_in_gap;
      const gap = el("div", "since gap", el("span", "clock", "⚠"), " ", gapStartText(gf, gt, ev.running_since));
      gap.title = `${fmtTs(filetimeToUnix(gf))} ~ ${fmtTs(filetimeToUnix(gt))}`;
      box.append(gap);
    }
    const hasPlace = (ev.items ?? []).some((it) => it.label === "위치");
    if (fileRoot && ev.root_image && !hasPlace) box.append(el("div", "sentence item", el("b", undefined, "위치: "), dataPath("span", ev.root_image)));
    if (ev.root_core && ev.root_image) {
      const sig = ev.root_signature;
      const signer = sig?.signer ? `${sig.signer}${sig.sig_status && sig.sig_status !== "valid" ? ` (${sig.sig_status})` : ""}` : sig?.sig_status ? `없음 (${sig.sig_status})` : "확인 전";
      box.append(el("div", "sentence item", el("b", undefined, "위치: "), extPath("span", ev.root_image)));
      box.append(el("div", "sentence item", el("b", undefined, "서명: "), ext("span", signer)));
    }
    const rows: { text: Node; edge?: number; sources?: [string, number][] }[] = ev.items?.length
      ? mergeItems(ev.items, isWindowsSigned(ev)).map((it0) => (fileRoot && ev.root_image && it0.label === "위치" ? { ...it0, value: `${ev.root_image} · ${it0.value}` } : it0)).map((it) => ({
          text: el("span", undefined, el("b", undefined, `${it.label}: `), (["위치", "자동 실행"].includes(it.label) ? dataPath : extPath)("span", fileRoot && it.value.startsWith("이 파일이 ") && fileRoot.count > 1 ? it.value.replace(/번 실행됨/, `번 실행됨 (${fmtRange(filetimeToUnix(fileRoot.first_ts), filetimeToUnix(fileRoot.last_ts))})`) : it.value)),
          edge: it.edge_ids[0],
          sources: it.sources,
        }))
      : ev.sentences.map((s) => ({ text: extPath("span", s.text), edge: s.edge_ids[0], sources: s.sources }));
    for (const r of rows) {
      const line = el("div", "sentence item");
      line.append(r.text);
      const cmd = ev.destroy && r.edge === ev.destroy.edge_id ? cmdlineLine(ev.destroy.cmdline) : null;
      if (r.edge != null) {
        const ebox = el("div", "evidence-box");
        const edge = r.edge;
        const toggle = () => (ebox.firstChild ? clear(ebox) : void explain(edge, ebox));
        line.append(" ", r.sources?.length ? evidenceBadge(r.sources, toggle) : button("왜?", toggle, "btn small"));
        if (cmd) line.append(cmd);
        line.append(ebox);
      } else if (cmd) line.append(cmd);
      box.append(line);
    }
    return box;
  };
  /// "발생 N번" 탭: 줄마다 시각·접속지 + 그 발생의 흐름 보기(카드를 다시 넣지 않는다)
  const occurrencesPanel = (members: StoryEvent[]): HTMLElement => {
    const box = el("div", "occurrences");
    for (const m of members) {
      const slot = el("div", "stale-card");
      const row = el("div", "stale-row", el("span", "muted", m.last_ts ? fmtShort(filetimeToUnix(m.last_ts)) : ""));
      row.dataset["root"] = String(m.root);
      if (m.root_live) row.append(el("span", "muted small", liveText(m.root_live)));
      // D022-4: 그 사건의 접속지 — 같은 판정이라도 접속지가 다르면 바로 보이게
      if (m.egress) row.append(ext("span", `${m.egress}${m.egress_where?.country ? ` (${m.egress_where.country})` : ""}`, "occ-where"));
      row.append(button("이 발생의 흐름", () => (slot.firstChild ? clear(slot) : void slot.append(flowView(m))), "btn small"));
      box.append(row, slot);
    }
    return box;
  };
  /// 끊기: 미리보기(무엇을 막고·끊고·남기는지) → 적용 → 정책마다 60초 확인
  const cutDialog = async (rootId: number, card: HTMLElement, title = "격리·차단") => {
    const r = await rpc<CutPlan>("cut.preview", { story_root: rootId, also: ["terminate"] });
    if (!r.ok) return card.append(errorBox(`cut.preview: ${r.error.message}`));
    const p = r.result;
    const dlg = el("dialog", "ack");
    dlg.append(el("h3", undefined, title));
    const list = (title: string, items: string[]) => {
      if (!items.length) return;
      dlg.append(el("h4", undefined, `${title} (${items.length})`));
      const ul = el("ul");
      for (const it of items.slice(0, 30)) ul.append(ext("li", it));
      if (items.length > 30) ul.append(el("li", "muted", `… 외 ${items.length - 30}개`));
      dlg.append(ul);
    };
    const [hcls, htxt] = HASH_TEXT[p.root_hash.status] ?? ["muted", p.root_hash.status];
    // changed·missing·unrecorded 는 서비스 경고 문장에 이미 있다 — 같은 말을 두 번 하지 않는다
    if (htxt && (p.root_hash.status === "match" || p.root_hash.status === "too_large")) {
      const hp = el("p", hcls, htxt);
      if (p.root_hash.recorded) hp.title = `기록: ${p.root_hash.recorded}\n지금: ${p.root_hash.current ?? "-"}`;
      dlg.append(hp);
    }
    list("통신을 막을 프로그램", p.block_images.map(fileName));
    const kill = el("input");
    kill.type = "checkbox";
    kill.checked = true;
    list("지금 실행 중이면 끝낼 프로세스", p.terminate.map((t) => `${fileName(t.image)} (PID ${t.pid})`));
    list("시스템 프로세스 — 막거나 끝내지 않음", p.excluded_system.map((t) => `${fileName(t.image)} (PID ${t.pid})`));
    list("코드를 주입당한 정상 프로그램 — 통째로 막지 않음", p.injected_hosts.map((t) => `${fileName(t.image)} (PID ${t.pid})`));
    const whyText: Record<string, string> = { system: "시스템", injected: "주입당한 프로그램", target: "대상" };
    list("24시간 막을 접속지 (주소·포트·프로토콜)", p.addresses.map((a) => `${a.ip}:${a.port}/${a.proto === 17 ? "udp" : "tcp"} — ${fileName(a.who)} (${whyText[a.why] ?? a.why})`));
    list("자동 실행 등록 (1차: 목록만, 직접 지우세요)", p.autoruns.map(([loc, tgt]) => `${loc} → ${tgt}`));
    list("만든 실행 파일·스크립트 (1차: 목록만)", p.written_executables);
    for (const w of p.warnings) dlg.append(el("p", "warn", ext("span", w)));
    for (const e of p.validation?.errors ?? []) dlg.append(el("p", "error", ext("span", e)));
    dlg.append(el("label", undefined, kill, " 실행 중인 대상 프로세스도 끝내기"));
    const killInj = el("input");
    killInj.type = "checkbox";
    if (p.injected_hosts.length) dlg.append(el("label", "block", killInj, " 주입당한 프로그램도 끝내기 (주입된 코드는 그 프로그램을 끝내야 사라집니다. 열려 있는 작업이 닫힐 수 있습니다)"));
    const out = el("div");
    const go = button("끊기 적용", async () => {
      go.disabled = true;
      const also = [...(kill.checked ? ["terminate"] : []), ...(killInj.checked ? ["terminate_injected"] : [])];
      const a = await mutation("cut.apply", { story_root: rootId, also }, uuid());
      if (!a.ok) {
        go.disabled = false;
        return out.replaceChildren(errorBox(`cut.apply: ${a.error.message}`));
      }
      dlg.close();
      const res = a.result as { policies: ApplyReply[]; terminated: { pid: number; image: string; outcome: string }[] };
      const box = el("div", "cut-result");
      if (a.approval) box.append(approvalBox(a.approval, "끊기 "));
      else for (const pol of res.policies) box.append(countdown(pol, root, () => {}, "끊기 "));
      for (const t of res.terminated) box.append(el("div", "muted", ext("span", `${fileName(t.image)} (PID ${t.pid}): ${t.outcome}`)));
      card.append(box);
    }, "btn danger-outline");
    go.disabled = !!(p.validation?.errors?.length) || (!p.block_images.length && !p.system_addresses.length);
    dlg.append(out, el("div", "actions", button("취소", () => dlg.close()), go));
    document.body.append(dlg);
    dlg.addEventListener("close", () => dlg.remove());
    dlg.showModal();
  };

  level.addEventListener("change", () => void load());
  void load();
  state.onNotify(root, (n) => {
    if (n.params["kind"] === "story_suspicious") void load();
  });
  return root;
}

/// 목록이 비었을 때 — 필터 때문에 비었으면 그렇게 말한다(처리한 사건이 있는데 "없다"고 하지 않게)
export function emptyText(filter: string, c?: TriageCounts): string {
  if (filter === "open" && c && c.acted + c.closed > 0) return `미조치 인시던트가 없습니다. (조치·예외 처리 ${c.acted + c.closed}건은 "처리 상태"에서 "조치·예외 처리"를 고르세요.)`;
  if (filter === "done") return "조치·예외 처리한 인시던트가 없습니다.";
  return "해당하는 인시던트가 없습니다.";
}
/// "처리 기록" 탭: 최신 먼저. 상태 · 조치 · 누가 · 언제 · 메모
function triageLogPanel(root: number): HTMLElement {
  const box = el("div", "facts-panel triage-log");
  box.append(loadingBox());
  void (async () => {
    const r = await rpc<{ items: { ts: number; state: TriageState; action?: TriageAction; actor: string; note?: string }[] }>("story.triage_log", { root });
    clear(box);
    if (!r.ok) return box.append(errorBox(r.error.message));
    if (!r.result.items.length) return box.append(el("p", "muted", "처리 기록이 없습니다."));
    for (const it of r.result.items) {
      const who = it.actor === "system" ? "자동(주기 판정)" : it.actor;
      const line = el("div", "sentence item", el("b", undefined, triageText({ state: it.state, action: it.action, chapter: 0, updated_ts: it.ts })), ` · ${fmtTs(it.ts)}`, el("span", "muted", ` · ${who}`));
      if (it.note) line.append(" · ", ext("span", it.note));
      box.append(line);
    }
  })();
  return box;
}
/// D039-2: 상세 패널 머리 한 줄 "이 파일로 실행 N번 · 처음~마지막"
/// D044-3: 단추 줄 아래 안내 한 줄(핵심 프로세스 + 정상 처리 못 함은 한 줄로 합친다)
export function cardNote(core: boolean, noFeedback: boolean, why?: string): string | null {
  const parts: string[] = [];
  if (core) parts.push("Windows 핵심 프로세스라 끝내지 않습니다. 의심 주소만 막을 수 있습니다.");
  if (noFeedback) parts.push(why || FEEDBACK_NOT_YET);
  return parts.length ? parts.join(" ") : null;
}
/// 프로세스에서 시작한 사건의 "이건 정상입니다" 확인 문구: 무엇이 정상이 되는지(조합)와 언제 다시 의심하는지를 밝힌다
export function feedbackUnitText(unit: string): string {
  return `이 실행 조합만 정상으로 봅니다:\n\n${unit}\n\n실행한 프로그램이나 띄우는 프로그램이 달라지면 다시 의심합니다. 도구(두 번째 프로그램) 자체를 정상으로 만들지는 않습니다.`;
}
export const FEEDBACK_NOT_YET = "이 종류의 사건(프로그램이 실행 중에 시작한 사건)은 아직 '정상'으로 표시하는 기능이 없습니다.";
/// D043-1: 4칸 막대 바로 아래 한 줄 — 왼쪽 빨간 띠 + [파괴 징후] 글자 칩 + 사실 문장 · 시각
export function destroyLine(d: { sentence: string; ts: number }): HTMLElement {
  return el("div", "destroy-line", el("span", "chip destroy", STAGES[4].name), " ", el("span", undefined, `${d.sentence} · ${fmtShort(filetimeToUnix(d.ts))}`));
}
/// 명령줄 원문 한 줄(외부 문자열 — 텍스트 노드). 80자 넘으면 말줄임, 툴팁에 전체, "복사"
export function cmdlineText(cmd: string, max = 80): string {
  const a = [...cmd];
  return a.length > max ? a.slice(0, max - 1).join("") + "…" : cmd;
}
function cmdlineLine(cmd: string): HTMLElement {
  const line = el("div", "cmdline");
  const t = el("span", "path", cmdlineText(cmd));
  t.title = cmd;
  line.append(t, " ", copyButton(cmd));
  return line;
}
/// 카드의 "지금 상태" 한 줄(시각 없음 — 카드 오른쪽 위가 마지막 활동). "수집 시작 전부터 실행 중" 줄과 엇갈려 보이지 않게
/// 모르는 경우를 "실행 중 아님"으로 쓰지 않는다
export function liveText(l: { running: boolean; pid: number; ended: boolean }): string {
  if (l.running) return `지금도 실행 중 (PID ${l.pid})`;
  if (l.ended) return `지금은 끝남 (PID ${l.pid})`;
  return `지금 상태 확인 못 함 (PID ${l.pid})`;
}

export interface Investigation {
  root: number;
  facts: { label: string; value: string; ok: boolean | null }[];
  verdict: "known_normal" | "risky" | "unknown";
  recommend: "mark_normal" | "cut" | "review";
  reason: string;
  native_host?: { browser: string; name: string; scope: string; manifest: string; path: string } | null;
}

/// 파괴 징후(5장)가 있는 사건은 조사로 정상 모양이 확인되지 않은 한 "끊기"를 권한다(검수 2026-11-07: vssadmin 복원 지점 삭제에 "보고 정하세요"가 나옴)
export function adjustForDestroy(v: Investigation, destroy: boolean): Investigation {
  if (!destroy || v.verdict === "known_normal") return v;
  return { ...v, verdict: "risky", recommend: "cut", reason: "복구 수단을 지우는 명령(파괴 행위)이 실행됐고, 알려진 정상 모양으로 확인되지 않았습니다." };
}

/// 결론 칸 사실: 지금 상태는 카드 머리 줄에 있으니 빼고(검수: 두 번 나옴), 파괴 징후 명령줄은 맨 앞에(직접 근거)
export function conclusionFacts(v: Investigation, destroyCmd: string | null): Investigation {
  const facts = v.facts.filter((f) => f.label !== "지금 상태");
  if (destroyCmd && !facts.some((f) => f.label === "명령줄")) facts.unshift({ label: "명령줄(파괴 행위)", value: destroyCmd, ok: false });
  return { ...v, facts };
}

/// 카드 제목 사슬의 자식 부분: 최대 3개 + "외 N"
export function chainKids(children: string[], total: number): string {
  const shown = children.slice(0, 3);
  const rest = Math.max(total, children.length) - shown.length;
  return shown.join(", ") + (rest > 0 ? ` 외 ${rest}` : "");
}

/// 카드 제목 사슬 전체(툴팁·접근성)
export function chainTitle(name: string, ch?: { parent?: string | null; children: string[]; children_total: number } | null): string {
  if (!ch) return name;
  return [ch.parent, name, ch.children.length ? chainKids(ch.children, ch.children_total) : null].filter(Boolean).join(" → ");
}

/// 권장 조치 문장(사실 판단은 서비스가, 화면은 말로만)
export function recommendText(r: Pick<Investigation, "recommend">): string {
  return r.recommend === "mark_normal" ? "권장: 알려진 정상 모양 — 끊지 마세요"
    : r.recommend === "cut" ? "권장: 격리·차단"
    : "권장: 아래 사실을 보고 정하세요";
}

/// 카드의 "자동 조사" 칸. 열 때 한 번 조회(서비스는 DB 에 쓰지 않는다)
function investigateBox(root: number, destroyCmd: string | null = null, onRecommend: (r: Investigation["recommend"]) => void = () => {}): HTMLElement {
  const box = el("details", "investigate");
  const sum = el("summary", undefined, "결론: 자동 조사 중…");
  box.append(sum);
  void (async () => {
    const r = await rpc<Investigation>("story.investigate", { root });
    if (!r.ok) {
      sum.textContent = "자동 조사를 하지 못했습니다";
      box.append(el("p", "muted small", r.error.message));
      return;
    }
    const v = conclusionFacts(adjustForDestroy(r.result, destroyCmd != null), destroyCmd);
    box.classList.add(v.verdict);
    sum.replaceChildren(el("b", undefined, recommendText(v)), " · ", ext("span", v.reason));
    // 검수: 닫혀 있어도 의심 쪽 사실(✗) 두 개까지는 첫 줄에
    const bad = v.facts.filter((f) => f.ok === false).slice(0, 2);
    if (bad.length) sum.append(el("span", "bad-facts", ...bad.flatMap((f) => [" · ✗ ", ext("span", f.value.includes(f.label) ? f.value : `${f.label}: ${f.value}`)])));
    onRecommend(v.recommend);
    box.open = v.verdict !== "unknown";
    const list = el("ul", "facts");
    for (const f of v.facts) {
      const mark = f.ok === true ? "✓" : f.ok === false ? "✗" : "·";
      list.append(el("li", f.ok === true ? "ok" : f.ok === false ? "bad" : undefined, el("span", "mark", mark), " ", el("b", undefined, `${f.label}: `), ext("span", f.value)));
    }
    box.append(list);
  })();
  return box;
}

export function execRange(x: { count: number; first_ts: number; last_ts: number }): string {
  return x.count > 1 ? `이 파일로 실행 ${x.count}번 · ${fmtRange(filetimeToUnix(x.first_ts), filetimeToUnix(x.last_ts))}` : "이 파일로 실행 1번";
}
