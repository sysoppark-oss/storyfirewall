import { rpc, mutation } from "../rpc";
import { el, ext, fmtTs, fmtShort, fmtRange, filetimeToUnix, button, clear } from "../ui";
import { diffShort, distinguishGroups, groupStories } from "./story-group";
import { listState, loadingBox, failBox, noDataBox, checkedLine, collectionStalled, cardFail } from "../list-state";
import { levelChip, bareTitle, type TriageCounts } from "./story";
import { engineStuckText, state } from "../state";
import { processPanel } from "./process";
import { watchUntilText } from "./first-run";
import { buildCard } from "./installs";
import type { InstallRun } from "./installs-text";
import { LEDGER_SCOPE, LEDGER_PROXY_NOTE, ledgerSummary } from "./first-run";
import { bars, type ConnLike } from "./conn-group";
import { icon, sparkline, barChart, hourlyCounts, donut, chapterReach, type Tone } from "./dash-viz";
import { STAGES, TRIAGE_STATE, LEVEL, ACT, isHigh } from "../terms";
import { distPanel, openAsConnLike } from "./dist-panel";
import { overview, type DashConn, type DashListener } from "./dash-overview";
import { bytes } from "./connections";
import { fileName } from "../sanitize";
import { LastGood } from "../last-good";
import { appendEmptyVerse } from "../word";

/// 서비스가 남긴 보호 사건 (A29): 파이프 이름 가로채기, 데이터 폴더 점유 등. 대상이 그래프의 프로세스면 상세로 잇는다
interface ServiceEvent {
  id: number;
  ts: number;
  kind: string;
  severity: number;
  detail: string;
  target?: { type?: string; pid?: number; image?: string; node_id?: number; defender_ts?: number; path?: string; until_ts?: number; tool?: string; trusted?: boolean } | null;
}
const SERVICE_EVENT_TITLE: Record<string, string> = {
  pipe_squat: "서비스 통로 이름을 다른 프로그램이 차지하려 했습니다",
  data_dir_held: "데이터 폴더를 다른 프로그램이 붙잡고 있었습니다",
  data_dir_untrusted: "서비스보다 먼저 만들어진 데이터 폴더를 치웠습니다",
  // 10판 5-9 (3): Windows 기본 보호(Defender 제어된 폴더 액세스) 기록을 이야기 재료로
  defender_cfa_blocked: "Windows 기본 보호가 보호 폴더 변경을 막았습니다",
  defender_cfa_audited: "Windows 기본 보호가 보호 폴더 변경을 기록했습니다(감사 모드)",
  // 17판 23-2 ①: 첫 실행 관찰실
  first_run_watch: "인터넷에서 받은 프로그램이 처음 실행되어 지켜보는 중입니다",
  // 31차 Q5: 관찰실 차단 자리가 참(채우기 공격일 수 있음 — 단정하지 않는다)
  first_run_cap: "처음 실행 관찰실의 차단 자리가 찼습니다",
  // 14판 20-4: 원격 제어 사기 경보 — 사실만(상대·의도를 단정하지 않는다)
  remote_session_start: "원격 제어 프로그램이 외부로 데이터를 계속 보내기 시작했습니다",
  remote_session_end: "원격 제어 세션 모양이 끝났습니다",
  // 34차 Q3: 새 세션 없이 붙는 원격 데스크톱 — 섀도(화면 엿보기)·세션 가로채기·들어오는 RDP 연결
  rdp_shadow: "원격 데스크톱 섀도(화면 엿보기) 도우미가 시작됐습니다",
  rdp_hijack: "세션 바꾸기 도구(tscon)가 실행됐습니다",
  rdp_inbound: "원격 데스크톱 포트로 들어온 연결",
};
/// 방어 피드용 — 보호 사건이 아닌 서비스 사건(정책·시계·절전)의 제목
const FEED_TITLE: Record<string, string> = {
  policy_expired: "기한부 정책이 만료됐습니다",
  policy_expiring: "정책이 곧 만료됩니다",
  policy_restored: "정책을 다시 적용했습니다",
  policy_tampered: "정책 필터가 바깥에서 바뀌었습니다",
  policy_tamper_backoff: "정책 복구를 잠시 멈췄습니다(반복 변조)",
  policy_auto_rollback: "정책을 자동으로 되돌렸습니다",
  policy_fill_limit: "접속지 차단 자리가 찼습니다",
  policy_interface_missing: "정책이 가리키는 네트워크 인터페이스가 없습니다",
  policy_filters_renumbered: "BFE 가 필터 번호를 다시 매겼습니다",
  address_block_expired: "접속지 차단이 만료됐습니다",
  child_block_expired: "자손 차단이 만료됐습니다",
  orphan_filters_removed: "주인 없는 필터를 정리했습니다",
  cut_applied: "격리·차단을 적용했습니다",
  cut_terminate: "프로세스를 끝냈습니다",
  power_resume: "절전에서 깨어났습니다",
  // 4판 3-4 방어 피드: 자동 대응·긴급 차단·연결 끊기
  auto_destroy: "파괴 행위 자동 대응 — 원인 프로그램을 끊었습니다",
  auto_destroy_failed: "파괴 행위 자동 대응을 끝내지 못했습니다",
  auto_destroy_skipped: "파괴 행위가 있었지만 자동 대응하지 않았습니다(허용 서명자·Microsoft 서명)",
  emergency_on: "긴급 차단을 걸었습니다",
  emergency_off: "긴급 차단을 풀었습니다",
  emergency_extended: "긴급 차단 기한을 늘렸습니다",
  conn_killed: "연결을 끊었습니다",
  time_changed: "PC 시계가 바뀌었습니다",
};
/// 방어 피드 기본에 보이는 사건(4판 3-4): 실제로 막거나 끊었거나 정책이 바뀐 것, 보호 사건 중 경고급
export function isDefenseEvent(e: { kind: string; severity: number }): boolean {
  if (/^(cut_|auto_destroy|emergency_|conn_killed|policy_(auto_rollback|tampered|restored|expired)|address_block_expired|defender_cfa_blocked)/.test(e.kind)) return true;
  return e.severity >= 2 && !QUIET_KINDS.has(e.kind) && e.kind in SERVICE_EVENT_TITLE;
}
/// 경고 테두리 없이 보여 줄 사건(막지 않은 사실·끝난 사실)
const QUIET_KINDS = new Set(["defender_cfa_audited", "first_run_watch", "remote_session_end", "rdp_inbound"]);
/// 보여 줄 보호 사건 (정책 변경 기록 등 평범한 사건은 정책 화면 몫)
const PROTECTION_KINDS = new Set(Object.keys(SERVICE_EVENT_TITLE));

interface StoryEvent {
  root: number;
  title: string;
  level: string;
  started_in_gap?: [number, number];
  chapter: string;
  destroy?: { kind: string; sentence: string; cmdline: string; ts: number; edge_id: number };
  score: number;
  sentences: { text: string; ts: number; edge_ids: number[] }[];
  last_ts?: number;
  fresh?: boolean;
  /// 도달한 장(1~4) — 4장 흐름 띠
  reached?: number[];
  root_image?: string;
  /// 핵심 프로세스(svchost·explorer 등) — 끝내지 않고 접속지만 차단
  root_core?: boolean;
  items?: { label: string; value: string }[];
}

interface Health {
  now: number;
  last_event_ft: number | null;
  lost_24h: number;
  gaps_24h: { from_ts: number; to_ts: number; events: number; reason?: string }[];
  clock_changes_24h: number[];
  timings?: { name: string; last_ms: number }[];
  wfp_filters?: number;
  db_bytes?: number | null;
}
// 긴급 차단·엔진 뱃지는 공통 상단 띠(topbar.ts)로 옮겼다(UI 명세 4판 3-1). 시험·다른 화면 호환용 다시 내보내기
export { emergencyText, engineBadges, type EmergencyStatus } from "../topbar";
/// C1 수집 상태 한 줄: 정상은 회색(초록 점만), 이상이면 주황 문장을 앞에. 원인을 단정하지 않는다
/// 마지막 사건이 얼마 전인지(상태 줄과 보호 서비스 카드가 같은 말을 쓰게 — 검수 B3)
export function agoText(lastSec: number | null): string {
  return lastSec == null ? "없음" : lastSec < 60 ? `${lastSec}초 전` : lastSec < 3600 ? `${Math.floor(lastSec / 60)}분 전` : `${Math.floor(lastSec / 3600)}시간 전`;
}
export function lastEventSec(h: { now: number; last_event_ft: number | null }): number | null {
  return h.last_event_ft ? Math.max(0, h.now - filetimeToUnix(h.last_event_ft)) : null;
}
export function healthLine(h: Health, onMore: () => void, gapStart?: { n: number; open: () => void }): HTMLElement {
  const lastSec = h.last_event_ft ? Math.max(0, h.now - filetimeToUnix(h.last_event_ft)) : null;
  const stalled = lastSec == null || lastSec > 60;
  const lost = h.lost_24h > 0;
  const clock = h.clock_changes_24h.length > 0;
  // D014: 구간 자체가 아니라 "구간 안에서 시작한 주의 이상 사건"이 있을 때만 주황 경고(절전은 흔함)
  const gapWarn = !!gapStart && gapStart.n > 0;
  const bad = stalled || lost || clock || gapWarn;
  const box = el("div", bad ? "health bad" : "health");
  box.append(el("span", "dot"));
  if (gapWarn) {
    const a = el("a", "lead", `기록 없는 구간에 시작한 프로그램 ${gapStart!.n}개 — 인시던트 보기 ›`);
    a.href = "#";
    a.addEventListener("click", (e) => { e.preventDefault(); gapStart!.open(); });
    box.append(a);
  }
  if (stalled) box.append(el("span", "lead", "기록이 멈췄을 수 있습니다"));
  else if (lost) box.append(el("span", "lead", "일부 기록이 빠졌을 수 있습니다"));
  else if (clock) box.append(el("span", "lead", "PC 시계가 바뀐 적이 있습니다"));
  else box.append(el("span", undefined, "기록 중"));
  box.append(el("span", undefined, `마지막 사건 ${agoText(lastSec)}`));
  const g = h.gaps_24h.find((x) => x.reason !== "no_record");
  box.append(el("span", undefined, lost && g ? `손실 ${h.lost_24h}건 (${fmtRange(filetimeToUnix(g.from_ts), filetimeToUnix(g.to_ts))})` : stalled ? "손실 — (기록이 멈췄으면 셀 수 없음)" : "손실 0 (최근 24시간)"));
  // 25차 Q1: 서비스가 멈췄거나 절전이던 구간. 노트북은 절전이 흔하므로 주황으로 올리지 않고 사실만 보인다
  const nr = h.gaps_24h.filter((x) => x.reason === "no_record");
  const lastNr = nr[nr.length - 1];
  if (lastNr) box.append(el("span", undefined, `기록 없는 구간 ${nr.length}곳 (최근 ${fmtRange(filetimeToUnix(lastNr.from_ts), filetimeToUnix(lastNr.to_ts))})`));
  const c = h.clock_changes_24h[h.clock_changes_24h.length - 1];
  // D041: 항목 하나하나는 줄바꿈하지 않고(.health > span nowrap) 항목 사이에서만 접힌다. "자세히 ›"는 마지막 항목에 붙여 홀로 떨어지지 않게
  const lastItem = el("span", undefined, clock && c ? `시계 변경 ${h.clock_changes_24h.length}회 (${fmtShort(c)})` : "시계 변경 없음");
  const more = el("a", undefined, "자세히 ›");
  more.href = "#";
  more.addEventListener("click", (e) => { e.preventDefault(); onMore(); });
  lastItem.append(" ", more);
  box.append(lastItem);
  return box;
}

/// 대시보드: 조용함이 기본. 의심 사건·정책 변조만 배지로.
/// 카드·칸을 누를 수 있게(UI 명세 4판 3-2 드릴다운). 키보드 Enter·Space 도 같은 동작. 누를 곳은 role=button
export function clickable<T extends Element>(x: T, go: () => void, label: string): T {
  x.classList.add("drill");
  x.setAttribute("role", "button");
  x.setAttribute("tabindex", "0");
  x.setAttribute("aria-label", label);
  if (x instanceof HTMLElement) x.title = label;
  x.addEventListener("click", go);
  x.addEventListener("keydown", (e) => {
    const k = (e as KeyboardEvent).key;
    if (k === "Enter" || k === " ") { e.preventDefault(); go(); }
  });
  return x;
}

// 검수(2026-11-11) 1·7번: 조회마다 마지막 성공 값. 엔진이 바쁘면 이것으로 그리고 "지난 값"이라고 밝힌다
const lastGood = new LastGood();
const DIST_SRC_KEY = "sf.dash.distSrc";
function loadDistSrc(): "today" | "now" {
  try {
    return localStorage.getItem(DIST_SRC_KEY) === "now" ? "now" : "today";
  } catch {
    return "today";
  }
}
function saveDistSrc(v: "today" | "now") {
  try {
    localStorage.setItem(DIST_SRC_KEY, v);
  } catch {
    /* 기억 못 해도 동작은 같다 */
  }
}

export function dashboard(): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "대시보드"));
  // 개편안 2판: KPI 4 → 그래프(상단 띠는 모든 화면 공통 topbar.ts — UI 명세 4판 3-1)
  const status = el("div", "cards kpi-row");
  // 목록은 새로 고칠 때마다 비운다 (전에는 알림마다 '지금 봐야 할 것' 목록이 아래에 계속 쌓였다)
  const body = el("div", "dash-body");
  // 대시보드 개요(사용자 "대시보드 UI 구성이 너무 약함" 2026-11-06): 네 질문 + 시간대 + 어디와 통신했나.
  // 숫자는 연결 기록·듣는 포트·설치 묶음에서 세기만 한다(dash-overview.ts). 위 카드 줄에도 개요 칸 3개를 끼운다
  const where = el("section", "dash-overview");
  // 2026-11-07: 그래프·도넛·4장 띠는 카드 바로 아래(첫 화면에 보이게), 네 질문·어디와 통신했나는 그 아래
  const viz = el("section", "dash-viz");
  // 사용자 2026-11-07: 서비스 보호 사건은 대시보드 맨 아래
  const foot = el("section", "dash-foot");
  // 개편안 2판 1-3: 심각 인시던트가 있을 때만 KPI 위에 뜨는 블록(없으면 자리를 쓰지 않는다)
  const critBlock = el("section", "crit-block");
  root.append(critBlock, status, viz, body, where, foot);
  let ovGen = 0;
  // 영역 그래프의 의심 사건 시각(unix 초) — refresh 가 채우고 drawOverview 가 읽는다
  let critTs: number[] = [];
  let triageCounts: TriageCounts | null = null;
  /// 방어 피드 재료(refresh 가 채움): 서비스 사건 전부(보호·정책·시계 등), 새것부터
  let feedItems: ServiceEvent[] = [];
  // 4판 3-4: 방어 피드 기본 = 차단·자동 대응·정책 적용/되돌림/만료 + 심각·높음 새 인시던트. [모두 보기] = 나머지 서비스 사건까지
  let feedAll = false;
  let feedIncidents: { root: number; level: string; title: string; ts: number }[] = [];
  // 빈 화면 사실 줄(4판 3-10): 오늘 기록·판정한 연결 수
  let emptyConnLine = "오늘 기록한 연결 수를 세는 중…";
  let emptyConnEl: HTMLElement | null = null;
  let highTs: number[] = [];
  // 수준별 수(의심·주의)와 4장 도달 수 — refresh 가 채운다(평범은 story.events 기본 수준에 안 들어와 세지 않는다)
  let levelN = { critical: 0, suspicious: 0, watch: 0 };
  let reach = [0, 0, 0, 0];
  // 검수 5번·원칙 6: 인시던트 목록을 아직 받지 못했으면 도넛·킬체인 숫자를 0 이 아니라 "—"로(0 은 "없다"로 읽힌다)
  let levelKnown = false;
  const drawOverview = async () => {
    const gen = ++ovGen;
    const [cr0, lr0, ir0, tr0] = await Promise.all([
      rpc<{ items: (DashConn & ConnLike)[] }>("connections.list", { since_secs: 86400, cursor: { limit: 500 } }),
      rpc<{ items: DashListener[] }>("listeners.list", {}),
      rpc<{ items: InstallRun[] }>("installs.list", { days: 1, limit: 30 }),
      // 개편안 2판 1-4: 시간대별 트래픽은 서비스가 쓰기 경로에서 쌓아 둔 요약 표에서(연결 기록을 세지 않는다)
      rpc<{ items: { hour: number; sent: number; recv: number; conns: number; blocked?: number; blocked_lost?: number }[] }>("traffic.hourly", { since_secs: 86400 }),
    ]);
    const cr = lastGood.keep("connections.list", cr0);
    const lr = lastGood.keep("listeners.list", lr0);
    const ir = lastGood.keep("installs.list", ir0);
    const tr = lastGood.keep("traffic.hourly", tr0);
    if (gen !== ovGen) return;
    clear(where);
    clear(viz);
    if (!cr.ok) return void where.append(el("div", "card", cardFail(cr.error, "연결 기록")));
    const conns = cr.result.items;
    const o = overview(conns, lr.ok ? lr.result.items : [], Date.now() / 1000);
    // 요약 표가 있으면(새 판) 그것을, 없으면(예전 서비스) 연결 기록의 마지막 접속 시각 기준 집계로
    const th = tr.ok ? hourlyFromSummary(tr.result.items, Date.now() / 1000) : null;
    // 빈 화면 사실 줄(4판 3-10)
    const connsToday = th ? th.conns.reduce((a, b) => a + b, 0) : null;
    emptyConnLine = connsToday == null ? "오늘 연결 기록 수를 읽지 못했습니다." : `오늘 연결 ${connsToday.toLocaleString("ko-KR")}건을 기록하고 판정했습니다.`;
    if (emptyConnEl) emptyConnEl.textContent = emptyConnLine;
    // 검수 2: "처음 본 나라·망" 수는 아래 막대의 "오늘 처음" 배지와 같은 기준(bars)으로 센다
    const newCc = bars(conns, "country", 999).bars.filter((b) => b.isNew).length;
    const newOrg = bars(conns, "org", 999).bars.filter((b) => b.isNew).length;
    // 위 카드 줄: 오늘 접속 · 주고받은 양 · 밖에서 닿는 포트 (의심 사건 카드 바로 뒤)
    // 2026-11-07 대시보드 다듬기: 카드마다 아이콘·색조·작은 추세선(오늘 시간대별). 숫자는 그대로, 보이는 밀도만
    const tile = (title: string, big: string, sub: string, go: () => void, ic: string, tone: Tone, spark?: number[]) => {
      const t = el("button", `card tile kpi tone-${tone}`, el("div", "kpi-head", icon(ic), el("h3", undefined, title)), el("div", "big", big), el("div", "muted small", sub));
      if (spark) t.append(sparkline(spark));
      (t as HTMLButtonElement).type = "button";
      t.addEventListener("click", go);
      return t;
    };
    // KPI ② 오늘 차단 통신(개편안 2판 1-2②, 6단계): 우리 WFP 필터가 막은 연결 수. 집계 채널이 넘쳐 못 센 건 "유실"로 밝힌다(최소 N건)
    const anchor = status.children[1] ?? null;
    const blocked = th ? th.blocked.reduce((a, b) => a + b, 0) : 0;
    const lost = th ? th.lost : 0;
    const blockedSub = !th ? "서비스 판이 낮아 집계 없음" : lost > 0 ? `최소 ${blocked}건 · 유실 ${lost}건(폭주)` : blocked ? "우리 정책이 막은 연결" : "막은 연결 없음";
    status.insertBefore(tile("오늘 차단 통신", th ? `${blocked}건` : "—", blockedSub, () => state.go("connections", { tab: "blocked", range: "today" }), "shield", blocked ? "bad" : "neutral", th ? th.blocked : undefined), anchor);
    // KPI ④ 일일 트래픽 — 보조 줄에 접속한 곳·프로그램 수
    status.append(tile("일일 트래픽", bytes(o.sent + o.recv), o.sent + o.recv ? `송신 ${bytes(o.sent)} · 수신 ${bytes(o.recv)}` : `${o.remotes}곳 · 프로그램 ${o.programs}개`, () => state.go("connections", { tab: "history" }), "swap", "neutral", th ? th.conns : o.hourly));

    // 네 질문(2×2)
    // 2026-11-07 다듬기: 네 칸을 KPI 와 같은 머리(아이콘+제목) → 큰 숫자 → 보조 글 → 목록 구조로 통일
    const q = (title: string, ic: string, lead: Node, ...rest: Node[]) => el("section", "card q-card", el("div", "kpi-head", icon(ic), el("h3", undefined, title)), lead, ...rest);
    const grid = el("div", "q-grid");
    // ① 밖에서 내 PC로
    const ports = el("ul", "q-list");
    for (const l of o.exposed.slice(0, 5)) ports.append(el("li", "q-row", el("span", "pill mono", `${l.lport}/${l.proto.toUpperCase()}`), ext("span", l.image ? fileName(l.image) : "(프로그램 확인 못 함)", "q-row-main")));
    if (!o.exposed.length) ports.append(el("li", "muted", "모든 주소에서 듣는 포트 없음"));
    grid.append(q("밖에서 내 PC로", "door",
      el("p", "q-lead", o.inbound ? `들어온 연결 ${o.inbound}건 (상대 ${o.inboundRemotes}곳)` : "오늘 들어온 연결 기록 없음"),
      el("div", "muted small", "모든 주소(0.0.0.0·::)에서 듣는 포트 — 밖에서 실제로 닿는지는 Windows 방화벽·공유기 설정에 따라 다릅니다"), ports));
    // ② 내 PC에서 밖으로
    const news = el("ul", "q-list");
    const fresh = conns.filter((c) => c.new_asn || c.new_cc).slice(0, 4);
    for (const c of fresh) news.append(el("li", "q-row", el("span", "badge-new", "오늘 처음"), ext("span", c.where?.org || c.where?.country || "—", "q-row-main"), ext("span", fileName(c.image), "muted q-row-side")));
    if (!fresh.length) news.append(el("li", "muted", "오늘 처음 본 망·나라 없음"));
    // UI 명세 4판 1-3c 대안: 목록 머리에 "지도에서 보기 ›" — 연결 이력 지도(처음 본 나라가 하나면 그 나라로 거른 채)
    const freshCc = [...new Set(fresh.map((c) => c.where?.cc).filter((x): x is string => !!x))];
    const mapLink = button("지도에서 보기 ›", () => state.go("connections", { tab: "history", map: true, ...(freshCc.length === 1 ? { cc: freshCc[0] } : {}) }), "btn small link-btn");
    grid.append(q("내 PC에서 밖으로", "globe",
      el("p", "q-lead", `처음 본 망 ${newOrg}곳 · 처음 본 나라 ${newCc}곳`),
      el("div", "muted small q-sub-row", "오늘 처음 접속한 곳 ", mapLink), news));
    // ③ 네트워크를 많이 쓴 프로그램
    const tops = el("div", "q-bars");
    // 양을 모르면(연결 표만 본 기록 등 0) 원격 수로 비교한다 — "—" 막대만 늘어서지 않게
    const byBytes = o.topPrograms.some((p) => p.sent + p.recv > 0);
    const val = (p: { sent: number; recv: number; remotes: number }) => (byBytes ? p.sent + p.recv : p.remotes);
    const maxB = Math.max(1, ...o.topPrograms.map(val));
    for (const p of o.topPrograms) {
      const fill = el("span", "bar-fill");
      fill.style.width = `${Math.max(2, Math.round((val(p) / maxB) * 100))}%`;
      tops.append(el("div", "bar-row q-bar", ext("span", p.name, "bar-name"), el("span", "bar-track", fill), el("span", "bar-val", byBytes ? bytes(p.sent + p.recv) : `${p.remotes}곳`)));
    }
    if (!o.topPrograms.length) tops.append(el("div", "muted small", "오늘 접속 기록 없음"));
    grid.append(q("네트워크를 많이 쓴 프로그램", "swap", el("p", "q-lead", `프로그램 ${o.programs}개 · 상위 ${o.topPrograms.length}개`), el("div", "muted small", byBytes ? "주고받은 양 기준" : "양 기록이 없어 접속한 곳 수 기준 — 프로그램끼리 같은 곳이 겹칠 수 있습니다"), tops));
    // ④ PC 안에서 새로 생긴 것
    const runs = ir.ok ? ir.result.items : [];
    const inst = el("ul", "q-list");
    for (const r of runs.slice(0, 4)) inst.append(el("li", "q-row", ext("span", fileName(r.image), "q-row-main"), el("span", "muted small q-row-side", `파일 ${r.files.length}개 · ${fmtShort(filetimeToUnix(r.start_ts))}`)));
    if (!runs.length) inst.append(el("li", "muted", ir.ok ? "오늘 설치·새 프로그램 기록 없음" : "불러오지 못함"));
    const instMore = button("설치 화면에서 자세히", () => state.go("installs", {}), "btn small");
    grid.append(q("PC 안에서 새로 생긴 것", "list", el("p", "q-lead", `설치 기록 ${runs.length}건`),
      el("div", "muted small", "설치 프로그램으로 묶인 것만 셉니다. 따로 내려받아 실행한 파일은 인시던트에서 봅니다."), inst, el("div", "q-more", instMore)));
    where.append(grid);

    // 시간대별 접속(오늘) + 어디와 통신했나 — 2026-11-07: 막대 → 영역 그래프 두 겹(전체 접속·의심 사건)
    // 개편안 2판 1-4: 이중 축 — 트래픽(송신·수신, 왼쪽 축) + 인시던트 마커(심각·높음, 오른쪽 축). 한 축에 접속 수와 사건 수를 겹치던 왜곡을 없앤다
    const hours = el("section", "card hour-card");
    const nowH = new Date().getHours();
    const nowSec = Date.now() / 1000;
    const critHourly = hourlyCounts(critTs, nowSec);
    const highHourly = hourlyCounts(highTs, nowSec);
    const maxH = Math.max(...o.hourly);
    const legend = el("div", "chart-legend", el("span", "lg recv", "수신"), el("span", "lg sent", "송신"), el("span", "lg crit", LEVEL.critical), el("span", "lg high", LEVEL.suspicious));
    const trafficSent = th ? th.sent : o.hourlySent;
    const trafficRecv = th ? th.recv : o.hourlyRecv;
    hours.append(el("div", "chart-head", el("h3", undefined, "트래픽 · 인시던트 (오늘, 시간대별)"), legend), barChart({ sent: trafficSent, recv: trafficRecv, critical: critHourly, high: highHourly }, nowH, (h) => {
      // 4판 3-2: 인시던트가 있는 시간 칸을 누르면 그 한 시간의 인시던트
      const d0 = new Date();
      d0.setHours(h, 0, 0, 0);
      const from = d0.getTime() / 1000;
      state.go("story", { from, to: from + 3600, level: "suspicious", triage: "all" });
    }));
    const peakConn = th ? Math.max(...th.conns) : maxH;
    hours.append(el("p", "muted small", peakConn || th ? `막대 = 시간대별 수신+송신 바이트 · 막대 위 점 = 그 시간의 인시던트 · 접속이 가장 많은 시간 ${peakConn}건${th ? "" : " · 마지막 접속 시각 기준"}` : "오늘 접속 기록이 없습니다."));
    // 사용자 요청(2026-11-09): 대시보드에도 통신 대상 분포 막대·지도. 오늘(연결 기록) / 지금(열린 연결, 10초마다) 전환.
    // 막대·나라를 누르면 연결 화면의 그 조건으로(오늘 → 연결 이력, 지금 → 지금 열린 연결)
    const whereCard = el("section", "card where-dash dist-card");
    const srcBtns = (["today", "now"] as const).map((v) => {
      const b = button(v === "today" ? "오늘" : "지금 열린 연결", () => { distSrc = v; saveDistSrc(v); srcBtns.forEach((x) => { x.classList.toggle("on", x === b); x.setAttribute("aria-pressed", String(x === b)); }); void paintDist(); }, "btn small seg-btn");
      b.classList.toggle("on", v === distSrc);
      b.setAttribute("aria-pressed", String(v === distSrc));
      return b;
    });
    const distTitle = el("h3", undefined, "통신 대상 분포");
    const distSub = el("span", "muted small");
    const dist = distPanel({ scope: "dashboard", defaultView: "map", compact: true, onPick: (f) => {
      if (!f) return;
      if (distSrc === "now") state.go("connections", { tab: "live", pick: f });
      else state.go("connections", { tab: "history", ...(f.by === "country" ? { cc: f.key, map: true } : { org: f.key }) });
    } });
    whereCard.append(el("div", "kpi-head", icon("globe"), distTitle, el("span", "seg dist-src", ...srcBtns), distSub), dist.root,
      el("p", "callout small", "나라는 IP 주소의 위치 정보(DB-IP)로 표시합니다. 실제 서버 위치와 다를 수 있습니다. 국가 표기는 정치적 입장을 뜻하지 않습니다."),
      el("div", "q-more", button("연결 화면에서 자세히", () => state.go("connections", { tab: distSrc === "now" ? "live" : "history" }), "btn small")));
    const paintDist = async () => {
      window.clearTimeout(distTimer);
      // 검수 7번: 전에는 "한 번 칠했음" 표시가 다시 그린 새 카드에도 남아, 아직 화면에 붙기 전인 새 카드를 칠하지 않고 돌아갔다
      // (엔진 바쁨 → 다시 그리기 뒤 분포 카드가 제목만 남음). 화면을 떠났는지는 타이머 쪽에서만 본다
      if (distSrc === "today") {
        // 검수 8번: 막대 숫자는 연결 건수, 500 은 상대 주소 수의 상한 — 둘을 섞어 "500곳인데 왜 수만" 으로 읽혔다
        distSub.textContent = `${connsToday != null ? `오늘 연결 ${connsToday.toLocaleString("ko-KR")}건 · ` : ""}상대 주소 ${conns.length >= 500 ? "많은 순 500곳" : `${conns.length}곳`} 기준`;
        dist.paint(conns, null);
        return;
      }
      const r = await rpc<{ items: { image?: string | null; raddr: string; where?: ConnLike["where"] }[] }>("connections.open", {});
      if (distSrc !== "now") return;
      if (r.ok) {
        distSub.textContent = `지금 열린 연결 ${r.result.items.length}건 · ${new Date().toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
        dist.paint(openAsConnLike(r.result.items), null);
      } else distSub.textContent = "지금 열린 연결을 읽지 못했습니다";
      // 대시보드에 있는 동안만 10초마다(화면을 떠나면 isConnected 가 false 라 멈춘다)
      distTimer = window.setTimeout(() => { if (whereCard.isConnected) void paintDist(); }, 10_000);
    };
    void paintDist();
    // 수준별 도넛(처리 안 한 사건) + 4장 흐름 띠(유입 → 실행 → 자리잡기 → 외부 접속, 오늘 도달한 사건 수)
    const open = levelN.critical + levelN.suspicious + levelN.watch;
    const num = (n: number) => (levelKnown ? String(n) : "—");
    const dn = el("section", "card donut-card", el("h3", undefined, "심각도별 미조치 인시던트"));
    const dnRow = el("div", "donut-row", donut([
      { label: LEVEL.critical, value: levelN.critical, cls: "d-crit" },
      { label: LEVEL.suspicious, value: levelN.suspicious, cls: "d-sus" },
      { label: LEVEL.watch, value: levelN.watch, cls: "d-watch" },
    ], num(open), "사건"));
    const dl = el("ul", "donut-legend");
    // 4판 3-2: 도넛 범례를 누르면 그 심각도만(미조치)
    dl.append(clickable(el("li", "d-crit", el("span", "sw"), `${LEVEL.critical} `, el("b", undefined, num(levelN.critical))), () => state.go("story", { levelEq: "critical", triage: "open" }), `미조치 ${LEVEL.critical} 인시던트 보기`));
    dl.append(clickable(el("li", "d-sus", el("span", "sw"), `${LEVEL.suspicious} `, el("b", undefined, num(levelN.suspicious))), () => state.go("story", { levelEq: "suspicious", triage: "open" }), `미조치 ${LEVEL.suspicious} 인시던트 보기`));
    dl.append(clickable(el("li", "d-watch", el("span", "sw"), `${LEVEL.watch} `, el("b", undefined, num(levelN.watch))), () => state.go("story", { levelEq: "watch", triage: "open" }), `미조치 ${LEVEL.watch} 인시던트 보기`));
    dnRow.append(dl);
    // 사용자 2026-11-07: 도넛 아래 빈 공간 → 처리 상태 막대(신규/분석 완료/조치 완료/예외 처리). 도넛은 틀 안 세로 중앙
    const tc = triageCounts;
    if (tc) {
      const tot = Math.max(1, tc.new + tc.investigated + tc.acted + tc.closed);
      const bars = el("div", "triage-bars");
      for (const [k, cls] of [["new", "t-new"], ["investigated", "t-inv"], ["acted", "t-act"], ["closed", "t-closed"]] as const) {
        const n = tc[k];
        const row = el("div", "triage-bar-row", el("span", "lbl", TRIAGE_STATE[k]), el("span", "bar", el("span", `fill ${cls}`)), el("b", undefined, String(n)));
        (row.querySelector(".fill") as HTMLElement).style.width = `${Math.round((n / tot) * 100)}%`;
        bars.append(clickable(row, () => state.go("story", { state: k, level: "normal" }), `${TRIAGE_STATE[k]} 인시던트 보기`));
      }
      dn.append(el("div", "donut-body", dnRow, el("h4", "muted small", "처리 상태 (전체)"), bars));
    } else {
      dn.append(el("div", "donut-body", dnRow));
    }
    dn.append(levelKnown
      ? el("p", "muted small", open ? `도넛은 미조치(${TRIAGE_STATE.new}·${TRIAGE_STATE.investigated})만 셉니다.` : "미조치 인시던트가 없습니다.")
      : el("p", "warn small", "인시던트 목록을 아직 받지 못했습니다. 잠시 뒤 다시 불러옵니다."));
    const flow = el("section", "card flow-card", el("h3", undefined, "공격 단계 도달 현황 (오늘)"));
    const strip = el("div", "flow-strip");
    const names = STAGES.slice(0, 4).map((s) => s.name);
    const subs = STAGES.slice(0, 4).map((s) => s.plain);
    names.forEach((nm, i) => {
      const n = reach[i] ?? 0;
      const step = el("div", `flow-step${n ? " on" : ""}`, el("div", "flow-n", num(n)), el("div", "flow-name", nm), el("div", "muted small", subs[i] ?? ""));
      strip.append(clickable(step, () => state.go("story", { stage: i + 1, level: "watch", triage: "open" }), `${nm}까지 간 미조치 인시던트 ${n}건 보기`));
      // 4판 1-3a: 앞뒤 칸이 모두 도달했으면 연결선을 굵은 브랜드 색으로(색만이 아니라 칸 숫자가 근거)
      if (i < 3) strip.append(el("div", `flow-arrow${n && (reach[i + 1] ?? 0) ? " on" : ""}`, "→"));
    });
    flow.append(strip, el("p", "muted small", "MITRE ATT&CK 전술 순서. 인시던트 하나는 도달한 모든 단계에 들어갑니다. 오른쪽으로 갈수록 위험합니다."));
    // 개편안 2판 3-1 방어 피드: 서비스 사건을 시간순 한 줄씩(같은 종류·대상 반복은 N회로). 연출 없음
    const feed = el("section", "card feed-card", el("div", "kpi-head", icon("shield"), el("h3", undefined, "실시간 방어 피드")));
    const flist = el("div", "feed-list");
    const allBtn = button(feedAll ? "기본만 보기" : "모두 보기", () => { feedAll = !feedAll; void drawOverview(); }, "btn small link-btn");
    allBtn.setAttribute("aria-pressed", String(feedAll));
    feed.querySelector(".kpi-head")?.append(el("span", "spacer"), allBtn);
    const shownItems = feedAll ? feedItems : feedItems.filter(isDefenseEvent);
    const fg = groupProtection(shownItems).slice(0, 8);
    // 검수 122-5: 인시던트 줄과 서비스 사건 줄을 시각으로 합쳐 최신 먼저(미조치 심각·높음 중 최근 활동 3건까지)
    const rows: { ts: number; row: HTMLElement }[] = [];
    for (const inc of feedAll ? [] : feedIncidents.slice(0, 3)) {
      const lv = LEVEL[inc.level as keyof typeof LEVEL] ?? inc.level;
      const text = el("span", "feed-text", "미조치 ", el("span", "lv", lv), " 인시던트 — ");
      text.append(ext("span", inc.title));
      const row = clickable(el("div", `feed-row inc lv-${inc.level}`, el("span", "muted when", fmtShort(inc.ts)), text), () => state.go("story", { root: inc.root, level: "normal", triage: "all" }), "그 인시던트 보기");
      rows.push({ ts: inc.ts, row });
    }
    for (const { head: e, n } of fg) {
      const row = el("div", `feed-row${QUIET_KINDS.has(e.kind) || e.severity < 2 ? "" : " alert"}`);
      const dts = typeof e.target?.defender_ts === "number" && e.target.defender_ts > 0 ? e.target.defender_ts : e.ts;
      row.append(el("span", "muted when", fmtShort(dts)));
      const label = SERVICE_EVENT_TITLE[e.kind] ?? FEED_TITLE[e.kind] ?? e.detail;
      // 끊기 사건은 대상(뿌리 프로그램)까지 한 줄에
      row.append(ext("span", e.kind.startsWith("cut_") ? `${label} — ${e.detail}` : label, "feed-text"));
      if (n > 1) row.append(el("span", "chip count", `${n}회`));
      row.title = e.detail;
      rows.push({ ts: dts, row });
    }
    rows.sort((a, b) => b.ts - a.ts);
    for (const r of rows) flist.append(r.row);
    if (!fg.length && !(feedIncidents.length && !feedAll)) flist.append(el("p", "muted small", feedAll ? "최근 7일 서비스 사건이 없습니다." : "최근 7일 차단·대응 기록이 없습니다. [모두 보기]로 다른 서비스 사건을 볼 수 있습니다."));
    feed.append(flist);
    // 2판 화면 구성: [킬체인 | 도넛] → [트래픽 그래프 | 방어 피드]
    viz.append(el("div", "dash-row2 row-chain", flow, dn), el("div", "dash-row2", hours, feed), whereCard);
  };
  // install-99 실측: 화면 진입과 서비스 이벤트로 refresh 가 겹치면 둘 다 clear 뒤 KPI 칸을 덧붙여 6칸이 됐다 → 늦게 끝난 옛 호출은 버린다
  let rfGen = 0;
  // 통신 대상 분포 카드: 오늘 / 지금(열린 연결) 고른 것 기억, 지금이면 10초 갱신 타이머
  let distSrc: "today" | "now" = loadDistSrc();
  let distTimer = 0;
  const refresh = async () => {
    const my = ++rfGen;
    // 검수 1번: 이미 그린 화면이 있으면 지우지 않고 새 값이 오면 바꾼다(불러오는 동안 빈 화면으로 깜빡이지 않게)
    if (!body.childElementCount) {
      clear(status);
      body.append(loadingBox());
    }
    // D035-2: 네 조회를 동시에 보내고 칸마다 따로 그린다(rpc 는 던지지 않고 결과로 돌려준다) — 한 조회가 늦거나 실패해도 나머지 칸은 그린다.
    // 전에는 의심 사건 → 정책 → 서비스 사건을 차례로 기다려, 엔진이 바쁘면 카드 하나만 그려진 반쪽 화면이 됐다(L044)
    const [ev0, hr0, se0] = await Promise.all([
      // 2026-11-07: 주의까지 받아 도넛·흐름 띠에 쓰고, "의심 사건" 카드·목록은 의심만 센다(전과 같음)
      rpc<{ items: StoryEvent[]; counts?: TriageCounts; pending?: number }>("story.events", { level_min: "watch", cursor: { limit: 60 } }),
      rpc<Health>("collector.health", {}),
      rpc<{ items: ServiceEvent[] }>("service.events", { since_secs: 7 * 86400, limit: 50 }),
    ]);
    if (my !== rfGen) return;
    // diag-184: 서비스가 설명을 다 만들지 못했으면(pending) 그 사건들은 한 줄 요약(partial)으로 온다 — 사건 수는 완전하므로 그대로 쓰고
    // "설명 준비 중" 한 줄 + 5초 뒤 다시
    const evPending = ev0.ok ? ev0.result.pending ?? 0 : 0;
    const ev = lastGood.keep("story.events", ev0);
    if (evPending > 0) window.setTimeout(() => { if (body.isConnected && my === rfGen) void refresh(); }, 5000);
    // 화면 확인(2026-11-11): 앱을 막 열었을 때 엔진이 바쁘면 보여 줄 지난 값도 없이 60초를 기다렸다 → 5초 뒤 다시
    if (!ev.ok) window.setTimeout(() => { if (body.isConnected && my === rfGen) void refresh(); }, 5000);
    const hr = lastGood.keep("collector.health", hr0);
    const se = lastGood.keep("service.events", se0);
    clear(status);
    clear(body);
    // 검수 1번: 엔진이 바빠 지난 값으로 그렸으면 그렇다고 밝힌다(숫자를 지금 값처럼 보이지 않게)
    const staleAt = LastGood.oldest(ev, hr, se);
    if (staleAt != null) {
      body.append(el("p", "warn small stale-note", `엔진이 바빠 ${fmtShort(staleAt)}에 받은 값을 보여 줍니다. 잠시 뒤 다시 불러옵니다.`));
      // 지난 값은 유효 기간(2분)이 있으므로 60초 주기를 기다리지 않고 10초 뒤 다시
      window.setTimeout(() => { if (body.isConnected && my === rfGen) void refresh(); }, 10_000);
    }
    else if (evPending > 0) body.append(el("p", "warn small stale-note", `인시던트 ${evPending}건의 설명을 아직 만드는 중입니다(제목만 표시). 잠시 뒤 다시 불러옵니다.`));
    const stalledNow = hr.ok && collectionStalled(hr.result);
    // D004-2: 숫자는 오늘 새로 일어난 일 기준. 수집 전부터 실행 중·오늘 새 활동 없는 것은 보조 줄로
    const allLv = ev.ok ? ev.result.items : [];
    const all = allLv.filter((s) => isHigh(s.level));
    const sus = all.filter((s) => s.fresh !== false);
    const watchFresh = allLv.filter((s) => s.fresh !== false && s.level.toLowerCase() === "watch");
    const staleN = all.length - sus.length;
    // D020-2·3: 같은 프로그램·같은 판정은 한 줄로, 최신이 위. 숫자는 묶은 뒤 개수(보조 줄에 사건 수)
    const groups = groupStories(sus);
    const tsOf = (xs: StoryEvent[]) => xs.map((x) => x.last_ts || x.sentences.find((y) => y.ts)?.ts || 0).filter((t) => t > 0).map((t) => filetimeToUnix(t));
    triageCounts = ev.ok ? ev.result.counts ?? null : null;
    feedItems = se.ok ? se.result.items : [];
    // 심각 블록: 가장 최근 심각 인시던트 하나. 사실 문장(파괴 행위면 그 문장) · 시각 · [격리·차단…] [인시던트 보기]
    clear(critBlock);
    const crit = sus.filter((s) => s.level.toLowerCase() === "critical");
    if (crit.length) {
      const c = crit[0]!;
      const ts = c.destroy?.ts ?? c.last_ts ?? c.sentences.find((x) => x.ts)?.ts;
      const fact = c.destroy?.sentence ?? c.sentences[c.sentences.length - 1]?.text ?? bareTitle(c.title);
      const card = el("div", "card crit-card");
      const head = el("div", "crit-head", levelChip("critical"), ext("span", bareTitle(c.title), "crit-title"));
      if (c.destroy) head.append(el("span", "chip destroy", STAGES[4].name));
      if (crit.length > 1) head.append(el("span", "muted small", ` 외 ${crit.length - 1}건`));
      const factLine = el("div", "crit-fact", ext("span", fact), el("span", "muted when", ts ? ` · ${fmtShort(filetimeToUnix(ts))}` : ""));
      const acts = el("div", "crit-actions",
        button(c.root_core ? ACT.cutAddrOnly : ACT.cut, () => state.go("story", { root: c.root, cut: true }), "btn danger"),
        button("인시던트 보기", () => state.go("story", { root: c.root }), "btn"));
      card.append(head, factLine, acts);
      critBlock.append(card);
    }
    critTs = tsOf(sus.filter((s) => s.level.toLowerCase() === "critical"));
    highTs = tsOf(sus.filter((s) => s.level.toLowerCase() !== "critical"));
    const susTs = [...critTs, ...highTs];
    const critN = sus.filter((s) => s.level.toLowerCase() === "critical").length;
    levelN = { critical: critN, suspicious: sus.length - critN, watch: watchFresh.length };
    // 방어 피드: 미조치 심각·높음 중 최근 것(오늘 새 활동)
    feedIncidents = sus
      .map((x) => ({ root: x.root, level: x.level.toLowerCase(), title: bareTitle(x.title), ts: x.last_ts ? filetimeToUnix(x.last_ts) : 0 }))
      .filter((x) => x.ts > 0)
      .sort((a, b) => b.ts - a.ts);
    reach = chapterReach([...sus, ...watchFresh].map((x) => x.reached ?? []));
    levelKnown = ev.ok;
    const susSpark = hourlyCounts(susTs, Date.now() / 1000);
    const card = (title: string, body: Node, cls = "card", ic?: string, tone: Tone = "neutral", spark?: number[]) => {
      const c = el("div", `${cls} kpi tone-${tone}`, ic ? el("div", "kpi-head", icon(ic), el("h3", undefined, title)) : el("h3", undefined, title), body);
      if (spark) c.append(sparkline(spark));
      return c;
    };
    // D013: 불러오지 못하면 숫자 대신 "—" + 주황 "불러오지 못함"
    // D015-1: 기록이 멈췄으면 0 은 믿을 수 없는 숫자 — 초록 0 대신 회색 "—"
    const susBody = !ev.ok
      ? cardFail(ev.error, "미조치 인시던트")
      : stalledNow && !sus.length
        ? el("div", undefined, el("div", "big muted", "—"), el("div", "warn small", "기록이 없어 셀 수 없음"))
        : el("div", undefined, el("div", "big " + (sus.length ? "bad" : "ok"), String(sus.length)));
    // 검수 B1: 기록이 멈췄는데 이미 찾은 의심 사건이 있으면 숫자는 그대로 두되(찾은 경보를 숨기지 않는다) 그 뒤는 세지 못했다고 밝힌다
    if (ev.ok && stalledNow && sus.length) susBody.append(el("div", "warn small", "기록이 멈췄을 수 있어 그 뒤 일은 세지 못했을 수 있음"));
    // 검수 122 덧붙임: 큰 숫자는 도넛·HUD 와 같은 "사건 수". 같은 일로 묶인 카드 수는 보조 줄로
    if (ev.ok && groups.length !== sus.length) susBody.append(el("div", "muted small", `같은 일 묶음 ${groups.length}개`));
    if (staleN) susBody.append(el("div", "muted small", `그 밖에 수집 전부터 실행 중 ${staleN}건`));
    // 사건 추적: story.events 기본(triage=open)이라 조치함·닫힘은 빠진다 — 제목도 그렇게
    status.append(clickable(card("미조치 심각·높음", susBody, sus.length ? "card alert alert-bad" : "card", "shield", sus.length ? "bad" : "ok", susSpark), () => state.go("story", { level: "suspicious", triage: "open" }), "미조치 심각·높음 인시던트 보기"));
    // D006-3: 지금 Windows 에 걸려 있는 정책 수(확인 대기 + 적용 중, 일시 중지 제외). 서비스는 상태를 "Applied"·"Confirmed"로 준다 —
    // 전에는 소문자와 비교해 늘 0 이었다
    // KPI ③ 샌드박스 관찰 중: 첫 실행 관찰실에서 아직 관찰 끝 시각이 지나지 않은 프로그램 수
    const nowSec = Date.now() / 1000;
    const watching = se.ok ? se.result.items.filter((e) => e.kind === "first_run_watch" && typeof e.target?.until_ts === "number" && e.target.until_ts > nowSec).length : 0;
    status.append(clickable(card("샌드박스 관찰 중", se.ok ? el("div", undefined, el("div", "big", String(watching)), el("div", "muted small", watching ? "인터넷에서 받은 프로그램의 첫 실행" : "관찰 중인 프로그램 없음")) : cardFail(se.error, "샌드박스 관찰"), "card", "eye", watching ? "info" : "neutral"), () => state.go("story", { sandbox: true, level: "normal", triage: "all" }), "샌드박스 관찰 중인 프로그램의 인시던트 보기"));
    void drawOverview();
    // C1: 카드 아래, 상태 줄과 별개. D014: 기록 없는 구간에 시작한 의심 사건이 있으면 맨 앞 주황 경고
    const inGap = all.filter((s) => s.started_in_gap);
    if (hr.ok) body.append(healthLine(hr.result, () => state.go("settings", { tab: "diag" }), { n: inGap.length, open: () => state.go("story", { root: inGap[0]?.root }) }));
    const prot = se.ok ? se.result.items.filter((e) => PROTECTION_KINDS.has(e.kind)) : [];
    let protBox: HTMLElement | null = null;
    if (prot.length) {
      const list = el("div", "list service-events");
      // 개편안 2판 3-1: 같은 종류·같은 프로그램의 반복은 한 줄로 접는다(실기기: TeamViewer 시작/끝 47건이 화면을 채움).
      // 대표는 최신 사건, "N회 · 처음~마지막" 보조 줄. 연출 없이 사실만
      const groupedProt = groupProtection(prot);
      for (const { head: e, n, first_ts } of groupedProt) {
        // 감사 모드 기록은 막지 않은 사실이라 경고 테두리 없이
        const row = el("div", QUIET_KINDS.has(e.kind) ? "row" : "row alert");
        row.append(el("span", "title", SERVICE_EVENT_TITLE[e.kind] ?? e.kind));
        if (n > 1) row.append(el("span", "chip count", `${n}회`), el("span", "muted", ` · ${fmtShort(first_ts)}부터`));
        // Defender 기록은 서비스가 읽은 시각이 아니라 Defender 가 남긴 시각
        const dts = typeof e.target?.defender_ts === "number" && e.target.defender_ts > 0 ? e.target.defender_ts : e.ts;
        const when = el("span", "muted", ` · ${fmtShort(dts)}`);
        when.title = fmtTs(dts);
        row.append(when);
        const until = watchUntilText(e.target?.until_ts, fmtShort);
        if (until) row.append(el("span", "muted", ` · ${until}`));
        // 사건 문장에는 외부에서 온 경로·이미지 이름이 섞인다 → 위생 처리
        row.append(el("br"), ext("span", e.detail, "detail"));
        const node = e.target?.node_id;
        if (typeof node === "number") {
          const slot = el("div", "slot");
          row.append(button("그 프로그램 보기", () => { clear(slot); slot.append(processPanel(node)); }));
          // 17판 23-2 ③ 변경 장부: 관찰 대상과 자손이 만든 파일·자동 실행·접속(사실만)
          if (e.kind === "first_run_watch") {
            row.append(" ", button("변경 장부", () => {
              clear(slot);
              slot.append(loadingBox({ word: false })); // 말씀 규칙 3: 변경 장부(기록)
              void rpc<{ run: InstallRun; inferred?: { path: string; bulk: boolean }[] }>("ledger.get", { node_id: node }).then((r) => {
                clear(slot);
                if (!r.ok) return void slot.append(failBox(r.error, () => {}, "변경 장부"));
                slot.append(el("p", "muted small", LEDGER_SCOPE), buildCard(r.result.run, ledgerSummary(r.result.run)));
                // 33차 Q1: 예약 작업·WMI·서비스로 맡긴 일 — 부모-자식이 아니라 시각으로 이은 것
                const inf = r.result.inferred ?? [];
                if (inf.length) {
                  const ul = el("ul", "install-list");
                  for (const f of inf) ul.append(ext("li", f.bulk ? `${f.path} (파일이 많아 폴더로 묶음)` : f.path, "mono"));
                  slot.append(el("h4", undefined, `대리 실행으로 이어 적은 파일 (시각으로 이음, ${inf.length})`), el("p", "muted small", LEDGER_PROXY_NOTE), ul);
                }
              });
            }));
          }
          row.append(slot);
        }
        // 33차 Q4: 원격 세션 시작 — 내가 직접 연 접속이면 그 도구를 "내가 쓰는 원격 도구"로 표시(관리자 승인). 그 뒤 같은 도구는 작은 알림
        const tool = e.target?.tool;
        if (e.kind === "remote_session_start" && typeof tool === "string" && !e.target?.trusted) {
          const note = el("span", "muted small");
          row.append(" ", button("내가 쓰는 원격 도구로 표시", () => void markTrusted(tool, note)), " ", note);
        }
        list.append(row);
      }
      // 사용자 2026-11-07: 이 목록이 화면을 다 차지해 아래 위젯이 안 보였다 → 우선 대응 목록 뒤, 접힌 상자(details)로.
      // 경고(막은 사건)가 24시간 안에 있으면 펼쳐 둔다. 나머지는 머리글 한 줄(건수 · 최근 사건)만
      const recentAlert = prot.some((e) => !QUIET_KINDS.has(e.kind) && Date.now() / 1000 - e.ts < 86400);
      const box = el("details", "card prot-box");
      if (recentAlert) box.open = true;
      const latest = prot[0];
      const sum = el("summary", undefined, `서비스 보호 사건 ${prot.length}건 (7일)`);
      if (latest) sum.append(el("span", "muted small", ` · 최근 ${SERVICE_EVENT_TITLE[latest.kind] ?? latest.kind} ${fmtShort(latest.ts)}`));
      box.append(sum, list);
      protBox = box;
    }
    if (sus.length) {
      const list = el("div", "list");
      const diffs = distinguishGroups(groups, (x) => bareTitle(x.title));
      for (const [gi, g] of groups.entries()) {
        const s = g.head;
        // D002: [수준 칩] 제목 … 시각 · 이야기 보기. 점수는 툴팁. D020-2: 묶이면 "같은 판정 N건 · 처음~마지막"
        const row = el("div", "row alert watch-row");
        row.title = `판정 규칙 점수 ${s.score}`;
        const ts = s.last_ts || s.sentences.find((x) => x.ts)?.ts;
        // D040-1: 줄 = [칩][이름][설명(한 줄·남는 폭·말줄임, 구분 항목부터 줄임)][시각][단추] — 단추·시각은 줄바꿈하지 않는다
        // D046-2: 끝 시각은 오른쪽 시각 칸에 있으므로 설명에는 시작만("…부터")
        const many = g.members.length > 1 ? `${g.members.length}건 · ${fmtShort(filetimeToUnix(g.first_ts))}부터` : "";
        // D035-3: 같은 제목 묶음이 여럿이면 무엇이 다른지(판정 항목 또는 폴더)를 회색으로
        const full = diffs[gi] ?? "";
        const desc = el("span", "row-desc muted");
        if (full) {
          const d = ext("span", ` · ${diffShort(full)}`, "desc-diff");
          d.title = full;
          desc.append(d);
        }
        if (many) desc.append(el("span", "desc-many", ` · ${many}`));
        row.append(levelChip(s.level), ext("span", bareTitle(s.title), "title"));
        // D043-1: 5장 파괴 징후는 수준 칩([의심])과 따로 글자 칩 하나(색만으로 구분하지 않게)
        if (s.destroy) row.append(el("span", "chip destroy", STAGES[4].name));
        row.append(desc, el("span", "muted when", ts ? fmtShort(filetimeToUnix(ts)) : ""));
        row.append(button("인시던트 보기", () => state.go("story", { root: s.root })));
        list.append(row);
      }
      body.append(el("h2", undefined, "우선 대응 인시던트"), list);
    } else {
      // D013: 오류 / 수집 안 됨 / 비어 있음을 가른다. "조용합니다"는 응답이 성공했고 수집이 돌 때만
      const st = listState(ev, hr.ok ? hr.result : null);
      if (st === "error" && !ev.ok) body.append(failBox(ev.error, () => void refresh(), "인시던트 목록"));
      else if (st === "nodata") body.append(noDataBox(() => state.go("settings", { tab: "diag" })));
      else {
        // UI 명세 4판 3-10: 의미 있는 빈 화면 — 사실만(안심 색·축하 없음). 오늘 연결 수는 개요(drawOverview)가 채운다
        const box = el("div", "empty-state", icon("shield"));
        const facts = el("div", undefined, el("p", undefined, "미조치 심각·높음 인시던트가 없습니다."), el("p", "muted small", emptyConnLine), checkedLine(hr.ok ? hr.result : null));
        emptyConnEl = facts.querySelector("p.muted.small");
        box.append(facts);
        body.append(box);
        appendEmptyVerse(body); // 말씀 규칙 2: 빈 목록 화면
      }
    }
    clear(foot);
    if (protBox) foot.append(protBox);
  };
  void refresh();
  state.onNotify(root, (n) => {
    const k = String(n.params["kind"]);
    if (k === "story_suspicious" || k.startsWith("policy_") || PROTECTION_KINDS.has(k)) void refresh();
  });
  // D046-3: 엔진 묶임이 생기거나 풀리면 "보호 서비스" 카드도 다시 그린다(main.ts 가 바뀔 때만 알린다)
  const onEngine = () => void refresh();
  window.addEventListener("engine-state", onEngine);
  // 2026-11-07 "실시간으로 바로바로": 알림이 없어도 60초마다 다시 그린다(접속 수·그래프는 알림이 없으므로)
  const timer = window.setInterval(() => { if (document.visibilityState === "visible") void refresh(); }, 60_000);
  root.addEventListener("screen-leave", () => { window.removeEventListener("engine-state", onEngine); window.clearInterval(timer); });
  return root;
}

/// 33차 Gemini Q4: 원격 도구를 "내가 쓰는 도구"로 표시 — 설정 remote_trusted_tools 에 더한다(관리자 승인 경로)
async function markTrusted(tool: string, note: HTMLElement) {
  note.textContent = "승인 창을 여는 중…";
  const g = await rpc<Record<string, unknown>>("settings.get", {});
  if (!g.ok) {
    note.textContent = "설정을 불러오지 못했습니다";
    return;
  }
  const cur = Array.isArray(g.result["remote_trusted_tools"]) ? (g.result["remote_trusted_tools"] as unknown[]).filter((x): x is string => typeof x === "string") : [];
  if (cur.includes(tool)) {
    note.textContent = "이미 표시돼 있습니다";
    return;
  }
  const r = await mutation("settings.set", { remote_trusted_tools: [...cur, tool] });
  note.textContent = r.ok ? "표시했습니다. 이 도구의 다음 원격 세션은 작은 알림으로 알립니다." : r.error.message;
}

/// 보호 사건 묶기: 같은 종류 + 같은 대상(프로그램 경로·도구)이면 한 묶음. 최신(head)이 대표, n 은 건수, first_ts 는 가장 이른 시각
export function groupProtection<T extends { kind: string; ts: number; target?: { image?: string; tool?: string; path?: string } | null }>(items: T[]): { head: T; n: number; first_ts: number }[] {
  const out: { head: T; n: number; first_ts: number }[] = [];
  const idx = new Map<string, number>();
  for (const e of items) {
    const key = `${e.kind}|${(e.target?.tool ?? e.target?.image ?? e.target?.path ?? "").toLowerCase()}`;
    const i = idx.get(key);
    if (i === undefined) {
      idx.set(key, out.length);
      out.push({ head: e, n: 1, first_ts: e.ts });
    } else {
      const g = out[i]!;
      g.n += 1;
      if (e.ts < g.first_ts) g.first_ts = e.ts;
      if (e.ts > g.head.ts) g.head = e;
    }
  }
  return out;
}

/// traffic.hourly 응답 → 오늘 0~23시 버킷(현지 시각). 어제 시간대는 버린다
export function hourlyFromSummary(items: { hour: number; sent: number; recv: number; conns: number; blocked?: number; blocked_lost?: number }[], nowSec: number): { sent: number[]; recv: number[]; conns: number[]; blocked: number[]; lost: number } {
  const sent = new Array<number>(24).fill(0), recv = new Array<number>(24).fill(0), conns = new Array<number>(24).fill(0), blocked = new Array<number>(24).fill(0);
  let lost = 0;
  const d = new Date(nowSec * 1000);
  d.setHours(0, 0, 0, 0);
  const dayStart = d.getTime() / 1000;
  for (const it of items) {
    if (it.hour < dayStart || it.hour > nowSec) continue;
    const h = new Date(it.hour * 1000).getHours();
    sent[h]! += it.sent;
    recv[h]! += it.recv;
    conns[h]! += it.conns;
    blocked[h]! += it.blocked ?? 0;
    lost += it.blocked_lost ?? 0;
  }
  return { sent, recv, conns, blocked, lost };
}
