// 차단 기록 탭(사용자 요청 2026-11-09: "인터넷 액세스가 차단되었습니다"가 뜰 때 무엇이 왜 막았는지 쉽게 찾기).
// 서비스의 blocked.recent(읽기만): WFP 가 떨어뜨린 연결과 그 필터의 이름·공급자. 우리 정책뿐 아니라 Windows 방화벽·다른 보안 프로그램도.
// 판단 말을 붙이지 않는다 — 어느 규칙이 막았는지(사실)와 그 규칙을 어디서 고치는지만.
import { rpc } from "../rpc";
import { el, ext, button, clear } from "../ui";
import { sanitize, fileName } from "../sanitize";
import { state } from "../state";
import { failBox, loadingBox } from "../list-state";
import { copyButton } from "./dash-viz";

export type RuleKind = "ours" | "ours_unknown" | "windows_firewall" | "windows_service_hardening" | "windows_app_isolation" | "windows_other" | "system" | "other" | "unknown";

export interface BlockedItem {
  ts: number;
  app: string;
  dir: "in" | "out" | "fwd" | "";
  proto: number;
  remote: string;
  rport: number;
  lport: number;
  loopback: boolean;
  filter_id: number;
  rule: {
    kind: RuleKind;
    name: string;
    description: string;
    provider: string;
    gone: boolean;
    policy_id?: number | null;
    policy_name?: string | null;
    policy_state?: string | null;
  };
}

/// 규칙·프로그램별 누적 한 줄
export interface RuleSum {
  filter_id: number;
  app: string;
  n: number;
  first: number;
  last: number;
  remote: string;
  rport: number;
  dir: BlockedItem["dir"];
  loopback: boolean;
  rule: Pick<BlockedItem["rule"], "kind" | "name" | "provider" | "policy_id" | "policy_name">;
}

export const KIND_LABEL: Record<RuleKind, string> = {
  ours: "Story Firewall 정책",
  ours_unknown: "우리 목록에 없는 필터",
  windows_firewall: "Windows 방화벽 규칙",
  windows_service_hardening: "Windows 서비스 강화",
  windows_app_isolation: "Windows 앱 격리",
  windows_other: "Windows 보안 기능",
  system: "시스템 필터",
  other: "다른 보안 프로그램",
  unknown: "규칙 정보 없음",
};

export function protoWord(p: number): string {
  return p === 6 ? "TCP" : p === 17 ? "UDP" : p === 1 ? "ICMP" : p === 58 ? "ICMPv6" : p ? `프로토콜 ${p}` : "";
}

/// 대상 한 줄: 같은 PC 안이면 "이 PC 안(localhost) :포트", 들어온 것은 "보낸 곳 → 내 포트"
export function targetText(b: Pick<BlockedItem, "dir" | "remote" | "rport" | "lport" | "loopback">): string {
  if (b.loopback) return `이 PC 안(localhost) :${b.dir === "in" ? b.lport : b.rport || b.lport}`;
  const addr = b.remote.includes(":") ? `[${b.remote}]` : b.remote;
  if (b.dir === "in") return `${addr || "(주소 없음)"}${b.rport ? `:${b.rport}` : ""} → 내 포트 ${b.lport}`;
  return `${addr || "(주소 없음)"}${b.rport ? `:${b.rport}` : ""}`;
}

/// 막은 규칙 한 줄(무엇이) + 고치는 곳(어디서). 외부 문자열은 위생 처리한 글자로만
export function ruleText(r: BlockedItem["rule"], filterId: number): { what: string; fix: string } {
  const nm = sanitize(r.policy_name || r.name || "", 120).text;
  const q = nm ? ` '${nm}'` : "";
  switch (r.kind) {
    case "ours":
      return { what: `Story Firewall 정책${q}${r.gone && !r.policy_id ? " (지금은 해제됨)" : ""}`, fix: "정책 화면에서 이 정책을 보고 해제하거나 고칠 수 있습니다." };
    case "ours_unknown":
      // 46차 Q2·Q3: 우리 공급자 키를 달았지만 받은 때 우리 정책 필터 목록에 없던 필터 — 단정하지 않는다
      return { what: `Story Firewall 공급자 키를 단 필터${q} — 지금 우리 정책 목록에 없음`, fix: "해제한 정책의 옛 기록이거나, 다른 프로그램이 우리 공급자 키를 단 필터일 수 있습니다. 정책 화면에 없는 이름이면 진단 정보를 남겨 주세요." };
    case "windows_firewall":
      return {
        what: `Windows 방화벽 규칙${q}`,
        fix: /^(default|기본)/i.test(nm) ? "맞는 허용 규칙이 없어 Windows 방화벽 기본 정책으로 막혔습니다. wf.msc 에서 허용 규칙을 만듭니다." : "wf.msc(Windows Defender 방화벽 고급 설정)에서 이 이름의 규칙을 찾아 끄거나 고칩니다.",
      };
    case "windows_service_hardening":
      return { what: `Windows 서비스 강화 규칙${q}`, fix: "Windows 가 서비스마다 허용한 통신 밖을 막은 것입니다. 보통 고칠 대상이 아닙니다." };
    case "windows_app_isolation":
      return { what: `Windows 앱 격리 규칙${q}`, fix: "스토어 앱·샌드박스 앱의 통신 제한입니다(예: 같은 PC 의 localhost 접속 제한). 앱 쪽 설정이나 Windows 의 앱 격리 예외로 다룹니다." };
    case "windows_other":
      return { what: `Windows 보안 기능의 규칙${q}`, fix: "Windows 보안(조직 정책·데이터 보호 등) 설정에서 다룹니다." };
    case "system":
      return { what: `공급자 없는 시스템 필터${q}`, fix: "공급자를 밝히지 않은 필터입니다. 다른 보안 프로그램이나 Windows 구성 요소일 수 있습니다." };
    case "other": {
      const pv = sanitize(r.provider || "", 80).text;
      return { what: `다른 보안 프로그램${pv ? ` '${pv}'` : ""}의 규칙${q}`, fix: "그 프로그램의 방화벽·웹 보호 설정에서 이 규칙을 찾습니다." };
    }
    default:
      return { what: `필터 #${filterId} (이미 지워져 이름을 모름)`, fix: "막은 뒤 그 필터가 지워졌습니다. 같은 일이 다시 일어나면 그때 이름이 남습니다." };
  }
}

export interface BlockedGroup {
  first: BlockedItem;
  n: number;
  from: number;
  to: number;
}

/// 같은 일(규칙·프로그램·대상·방향·프로토콜)이 잇달아 오면 한 줄로(새것부터 받은 순서 유지). 순수 함수
export function groupBlocked(items: BlockedItem[]): BlockedGroup[] {
  const key = (b: BlockedItem) => `${b.rule.kind}|${b.rule.name}|${b.app}|${targetText(b)}|${b.dir}|${b.proto}`;
  const out: BlockedGroup[] = [];
  for (const b of items) {
    const last = out[out.length - 1];
    if (last && key(last.first) === key(b)) {
      last.n++;
      last.from = Math.min(last.from, b.ts);
      last.to = Math.max(last.to, b.ts);
    } else out.push({ first: b, n: 1, from: b.ts, to: b.ts });
  }
  return out;
}

/// 글자 거르기(화면 쪽 — 서비스도 q 로 거르지만, 종류 칩 거르기와 함께 쓰려고 순수 함수로 둔다)
export function kindFilter(items: BlockedItem[], kind: RuleKind | null): BlockedItem[] {
  return kind ? items.filter((x) => x.rule.kind === kind) : items;
}

/// 차단 기록 탭
export function blockedLog(): { root: HTMLElement; stop: () => void } {
  const root = el("div", "blocked-log");
  const q = el("input") as HTMLInputElement;
  q.type = "search";
  q.placeholder = "프로그램·주소·포트·규칙 이름";
  q.setAttribute("aria-label", "차단 기록 찾기");
  const pause = button("일시 정지", () => { paused = !paused; pause.textContent = paused ? "다시 갱신" : "일시 정지"; pause.setAttribute("aria-pressed", String(paused)); if (!paused) void refresh(); }, "btn small");
  pause.setAttribute("aria-pressed", "false");
  const status = el("span", "muted small");
  const chips = el("div", "kind-chips");
  const box = el("div");
  // 46차 Q2: 규칙·프로그램별 누적 — 최근 3,000건이 다량 차단으로 밀려나도 남는다
  const rulesBox = el("details", "where-panel blocked-rules");
  const rulesBody = el("div");
  const rulesSum = el("summary", undefined, "규칙·프로그램별 누적");
  rulesBox.append(rulesSum, rulesBody);
  root.append(
    el("p", "callout small", "브라우저에 \"인터넷 액세스가 차단되었습니다\"(ERR_NETWORK_ACCESS_DENIED)가 뜨면, 그 시각의 브라우저 줄(msedge.exe·chrome.exe 등)을 찾으세요. 막은 규칙과 그 규칙을 고치는 곳이 나옵니다. 여기에 줄이 없으면 Windows 필터(WFP)가 막은 것이 아닙니다 — 브라우저 설정·확장 프로그램·프록시·백신의 웹 보호일 수 있습니다. 규칙의 주인(Windows 방화벽 등)은 필터에 적힌 공급자로 가립니다. 관리자 권한 프로그램은 다른 공급자를 흉내 낼 수 있습니다."),
    el("div", "toolbar", q, " ", pause, " ", status),
    chips,
    rulesBox,
    box,
  );
  let paused = false;
  let kind: RuleKind | null = null;
  let timer = 0;
  let gen = 0;
  let qT = 0;
  q.addEventListener("input", () => { window.clearTimeout(qT); qT = window.setTimeout(() => void refresh(), 250); });

  const paintRules = (rules: RuleSum[], n: number, evicted: number, overflow: number) => {
    rulesSum.textContent = `규칙·프로그램별 누적 (${n}가지${evicted ? ` · 목록에서 밀려난 ${evicted}건 포함` : ""})`;
    clear(rulesBody);
    if (!rules.length) return void rulesBody.append(el("p", "muted small", "아직 없습니다."));
    const t = el("table", "grid blocked-sum");
    const h = el("tr");
    for (const x of ["횟수", "마지막", "프로그램", "막은 규칙", "최근 대상"]) h.append(el("th", undefined, x));
    const tb = el("tbody");
    for (const a of rules) {
      const tr = el("tr", `k-${a.rule.kind}`);
      const app = sanitize(a.app || "", 400).text;
      const pc = ext("td", app ? fileName(app) : "(프로그램 모름)");
      if (app) pc.title = app;
      tr.append(el("td", "mono", String(a.n)), el("td", "mono", new Date(a.last * 1000).toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" })), pc,
        el("td", `rule-what k-${a.rule.kind}`, ruleText({ ...a.rule, description: "", gone: false }, a.filter_id).what), el("td", "mono", targetText({ ...a, lport: 0 })));
      tb.append(tr);
    }
    t.append(el("thead", undefined, h), tb);
    rulesBody.append(t);
    if (overflow) rulesBody.append(el("p", "muted small", `가짓수 상한(2,000)을 넘어 따로 세지 못한 사건 ${overflow}건`));
  };

  const paint = (items: BlockedItem[], kinds: Partial<Record<RuleKind, number>>, total: number, oldest: number | null) => {
    clear(chips);
    const all = button(`전체 ${total}`, () => { kind = null; void refresh(); }, `filter-chip${kind ? "" : " on"}`);
    all.setAttribute("aria-pressed", String(!kind));
    chips.append(all);
    for (const k of Object.keys(KIND_LABEL) as RuleKind[]) {
      const n = kinds[k] ?? 0;
      if (!n) continue;
      const c = button(`${KIND_LABEL[k]} ${n}`, () => { kind = kind === k ? null : k; void refresh(); }, `filter-chip k-${k}${kind === k ? " on" : ""}`);
      c.setAttribute("aria-pressed", String(kind === k));
      chips.append(c);
    }
    clear(box);
    const shown = kindFilter(items, kind);
    if (!shown.length) {
      box.append(el("p", "muted", total ? "조건에 맞는 차단 기록이 없습니다." : "서비스가 켜진 뒤(그리고 그 전 하루) 막힌 연결이 없습니다."));
      return;
    }
    const table = el("table", "grid blocked");
    const head = el("tr");
    for (const [h, cls] of [["시각", "c-time"], ["프로그램", "c-prog"], ["방향", "c-dir"], ["대상", "c-remote"], ["막은 규칙", "c-rule"]] as const) head.append(el("th", cls, h));
    const body = el("tbody");
    const fmt = (ts: number) => new Date(ts * 1000).toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
    for (const g of groupBlocked(shown)) {
      const b = g.first;
      const tr = el("tr", `k-${b.rule.kind}`);
      const tcell = el("td", "c-time mono", fmt(g.to));
      if (g.n > 1) {
        tcell.append(el("div", "muted small", `×${g.n} · ${fmt(g.from)} 부터`));
      }
      tr.append(tcell);
      const prog = el("td", "c-prog");
      const appTxt = sanitize(b.app || "", 400).text;
      prog.append(ext("span", appTxt ? fileName(appTxt) : "(프로그램 모름)", "prog"));
      if (appTxt) prog.title = appTxt;
      tr.append(prog, el("td", "c-dir", `${b.dir === "in" ? "들어옴" : b.dir === "out" ? "나감" : b.dir === "fwd" ? "거쳐 감" : ""} ${protoWord(b.proto)}`.trim()), el("td", "c-remote mono", targetText(b)));
      const rt = ruleText(b.rule, b.filter_id);
      const cell = el("td", "c-rule");
      cell.append(el("div", `rule-what k-${b.rule.kind}`, rt.what), el("div", "muted small", rt.fix));
      const acts = el("div", "rule-acts");
      if (b.rule.kind === "ours") acts.append(button("정책 보기 ›", () => state.go("policy", b.rule.policy_id ? { focus: b.rule.policy_id } : {}), "btn small"));
      const rn = sanitize(b.rule.name || "", 200).text;
      if (rn && b.rule.kind !== "ours") acts.append(el("span", "muted small", "규칙 이름 복사 "), copyButton(rn));
      if (acts.childNodes.length) cell.append(acts);
      tr.append(cell);
      body.append(tr);
    }
    table.append(el("thead", undefined, head), body);
    box.append(table);
    if (oldest) box.append(el("p", "muted small", `기록 범위: ${new Date(oldest * 1000).toLocaleString("ko-KR")} 부터 · 최근 3,000건까지 메모리에 둡니다(서비스를 다시 켜면 Windows 기록에서 최근 하루를 다시 읽습니다).`));
  };

  const refresh = async () => {
    const my = ++gen;
    if (!box.firstChild) box.append(loadingBox());
    const r = await rpc<{ items: BlockedItem[]; kinds: Partial<Record<RuleKind, number>>; total: number; oldest?: number | null; rules?: RuleSum[]; rules_total?: number; evicted?: number; rules_overflow?: number }>("blocked.recent", { limit: 500, q: q.value.slice(0, 128) });
    if (my !== gen) return;
    if (!r.ok) {
      clear(box);
      box.append(failBox(r.error, () => void refresh(), "차단 기록"));
      return;
    }
    status.textContent = `마지막 갱신 ${new Date().toLocaleTimeString("ko-KR")}`;
    // 표를 보고(포인터·포커스) 있는 동안에는 줄을 움직이지 않는다
    if (box.matches(":hover") || box.contains(document.activeElement)) return;
    paintRules(r.result.rules ?? [], r.result.rules_total ?? 0, r.result.evicted ?? 0, r.result.rules_overflow ?? 0);
    paint(r.result.items, r.result.kinds, r.result.total, r.result.oldest ?? null);
  };
  void refresh();
  timer = window.setInterval(() => { if (!paused) void refresh(); }, 5000);
  return { root, stop: () => window.clearInterval(timer) };
}
