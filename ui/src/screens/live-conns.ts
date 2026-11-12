// 연결 화면 = [지금 열린 연결] | [연결 이력] (UI 명세 4판 3-4, 기본 탭 = 지금 열린 연결 — 사용자 확정 2026-11-09).
// 지금 열린 연결: 서비스가 요청 때 연결 테이블(GetExtendedTcpTable)을 읽어 준다(connections.open, DB 를 읽지 않음).
// 실시간 목록 규칙(UI 명세 2판 2-10): 포인터가 표 위에 있거나 일시 정지면 행을 움직이지 않고 "변경 N건 — 보기" 알약.
// 닫힌 연결은 다음 갱신에 한 번 회색 "닫힘" 줄로 보인 뒤 사라진다(갑자기 없어지지 않게).
import { rpc, mutation } from "../rpc";
import { el, ext, button, clear } from "../ui";
import { state } from "../state";
import { distPanel, openAsConnLike, type DistFilter } from "./dist-panel";
import { matchesFilter } from "./conn-group";
import { blockedLog, scopeArg } from "./blocked-log";
import { fileName } from "../sanitize";
import { failBox, loadingBox } from "../list-state";
import { connections, whereCell, type Where } from "./connections";
import { LEVEL } from "../terms";

export interface OpenConn {
  proto: string;
  laddr: string;
  lport: number;
  raddr: string;
  rport: number;
  state: string;
  pid: number;
  process_id?: number | null;
  image?: string | null;
  where?: Where | null;
  v4: boolean;
  story_root?: number | null;
  story_level?: string | null;
  /// 서비스가 이 연결을 처음 본 시각(unix 초). 낮은 판 서비스는 주지 않는다
  first_seen_ts?: number;
  /// 서비스가 처음 볼 때 이미 열려 있었다 — 실제로는 더 오래됐을 수 있다("N분 넘게")
  since_before?: boolean;
}

/// 이 PC 의 나라(코드) 추정: Windows 표시 언어의 지역(ko-KR → KR). "해외 먼저" 정렬에만 쓴다 — 판정에는 쓰지 않는다
export function homeCountry(lang: string | undefined = typeof navigator !== "undefined" ? navigator.language : undefined): string {
  const m = /[-_]([A-Za-z]{2})$/.exec(lang ?? "");
  return (m ? m[1]! : "KR").toUpperCase();
}

/// "열린 지" 글자(순수 함수): 3분 · 2시간 10분 · 방금. `sinceBefore` 면 "…넘게"(서비스가 처음 볼 때 이미 열려 있었음). 시각을 모르면 "—"
export function openedText(firstSeen: number | undefined, now: number, sinceBefore?: boolean): string {
  if (!firstSeen || !now || now < firstSeen) return "—";
  const s = now - firstSeen;
  const t = s < 60 ? (sinceBefore ? "1분 안" : "방금") : s < 3600 ? `${Math.floor(s / 60)}분` : s < 86400 ? `${Math.floor(s / 3600)}시간 ${Math.floor((s % 3600) / 60)}분` : `${Math.floor(s / 86400)}일`;
  return sinceBefore && s >= 60 ? `${t} 넘게` : sinceBefore ? "—" : t;
}

/// 연결 하나의 열쇠(같은 연결인가)
export const connKey = (c: OpenConn) => `${c.pid}|${c.laddr}|${c.lport}|${c.raddr}|${c.rport}`;

/// 정렬(순수 함수 — 시험용, UI 명세 4판 3-4): 인시던트 있는 것 → 해외 → 최신(늦게 열린 것) → 프로그램 이름 → 상대 주소.
/// 나라를 모르는 주소는 해외도 국내도 아니다(해외 다음).
export function sortOpen(xs: OpenConn[], home = homeCountry()): OpenConn[] {
  const rank = (c: OpenConn) => (c.story_root ? 0 : 1);
  const abroad = (c: OpenConn) => { const cc = (c.where as { cc?: string } | null | undefined)?.cc; return cc ? (cc.toUpperCase() !== home ? 0 : 2) : 1; };
  return [...xs].sort((a, b) =>
    rank(a) - rank(b) ||
    abroad(a) - abroad(b) ||
    (b.first_seen_ts ?? 0) - (a.first_seen_ts ?? 0) ||
    Number(b.state === "연결됨") - Number(a.state === "연결됨") ||
    fileName(a.image ?? "").localeCompare(fileName(b.image ?? "")) ||
    a.raddr.localeCompare(b.raddr) || a.rport - b.rport);
}

/// 이전 목록과 비교해 이번에 닫힌 것(순수 함수 — 시험용)
export function closedSince(prev: OpenConn[], now: OpenConn[]): OpenConn[] {
  const keys = new Set(now.map(connKey));
  return prev.filter((c) => !keys.has(connKey(c)));
}

/// 연결 화면(탭 둘). args.tab === "history" 면 이력 탭으로 연다(대시보드 일일 트래픽 드릴다운)
export function connectionsScreen(args: Record<string, unknown> = {}): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "네트워크 연결"));
  const tabs = el("div", "u-tabs");
  tabs.setAttribute("role", "tablist");
  const panel = el("div", "u-tab-panel");
  const liveBtn = button("지금 열린 연결", () => show("live"), "u-tab");
  const histBtn = button("연결 이력", () => show("history"), "u-tab");
  // 사용자 요청(2026-11-09): 차단 목록·차단 이유 추적
  const blkBtn = button("차단 기록", () => show("blocked"), "u-tab");
  for (const b of [liveBtn, histBtn, blkBtn]) b.setAttribute("role", "tab");
  tabs.append(liveBtn, histBtn, blkBtn);
  root.append(tabs, panel);
  let live: { root: HTMLElement; stop: () => void } | null = null;
  let lastOpenN: number | null = null;
  // 주소 매개변수의 거르기(오늘만·정책)는 들어올 때 한 번만 쓴다 — 탭을 다시 누르면 전체
  let firstBlocked = true;
  const show = (which: "live" | "history" | "blocked") => {
    liveBtn.setAttribute("aria-selected", String(which === "live"));
    histBtn.setAttribute("aria-selected", String(which === "history"));
    blkBtn.setAttribute("aria-selected", String(which === "blocked"));
    live?.stop();
    live = null;
    // 이력 탭(connections)은 자기 root 에서 screen-leave 를 듣고 구독을 끊는다
    for (const ch of [...panel.children]) ch.dispatchEvent(new Event("screen-leave"));
    clear(panel);
    if (which === "live") {
      live = liveConns((n) => { lastOpenN = n; }, pickArg(args["pick"]));
      panel.append(live.root);
    } else if (which === "blocked") {
      live = blockedLog(firstBlocked ? scopeArg(args) : {});
      firstBlocked = false;
      panel.append(live.root);
    } else {
      const h = connections({ map: args["map"] === true, cc: typeof args["cc"] === "string" ? args["cc"] : undefined, org: typeof args["org"] === "string" ? args["org"] : undefined, q: typeof args["q"] === "string" ? args["q"] : undefined });
      h.querySelector("h1")?.remove();
      // 4판 2-2: 이력 안내 옆 "지금 열린 연결 N건 ›" 바로 가기
      const quick = button(lastOpenN == null ? "지금 열린 연결 보기 ›" : `지금 열린 연결 ${lastOpenN}건 ›`, () => show("live"), "btn small link-btn");
      panel.append(el("div", "muted small conn-quick", "이 탭은 정한 범위 안의 연결 기록(이력)입니다. ", quick), h);
    }
  };
  // 화면을 떠나면 갱신을 멈춘다
  root.addEventListener("screen-leave", () => { live?.stop(); for (const ch of [...panel.children]) ch.dispatchEvent(new Event("screen-leave")); });
  show(args["tab"] === "history" ? "history" : args["tab"] === "blocked" ? "blocked" : "live");
  return root;
}

/// 지금 열린 연결 탭
/// 대시보드 분포 카드에서 넘어온 거르기(나라 코드 두 글자 또는 AS 번호만 받는다)
function pickArg(v: unknown): DistFilter {
  const o = v as { by?: unknown; key?: unknown } | null;
  if (!o || typeof o.key !== "string") return null;
  if (o.by === "country" && /^[A-Z]{2}$/.test(o.key)) return { by: "country", key: o.key };
  if (o.by === "org" && /^\d{1,10}$/.test(o.key)) return { by: "org", key: o.key };
  return null;
}

function liveConns(onCount: (n: number) => void, initial: DistFilter = null): { root: HTMLElement; stop: () => void } {
  const root = el("div", "live-conns");
  const every = el("select") as HTMLSelectElement;
  for (const [v, t] of [[5, "5초"], [15, "15초"], [30, "30초"]] as const) {
    const o = el("option", undefined, t) as HTMLOptionElement;
    o.value = String(v);
    every.append(o);
  }
  const pause = button("일시 정지", () => {
    paused = !paused;
    pause.textContent = paused ? "다시 갱신" : "일시 정지";
    pause.setAttribute("aria-pressed", String(paused));
    if (!paused) void refresh(true);
  }, "btn small");
  pause.setAttribute("aria-pressed", "false");
  const status = el("span", "muted small");
  const pill = el("div", "new-pill-row");
  const box = el("div");
  // 사용자 요청(2026-11-09): 지금 열린 연결도 통신 대상 분포(막대·지도)를 실시간으로 — 갱신 때마다 다시 그린다.
  // 막대·나라를 누르면 아래 표를 거른다(다시 누르면 해제)
  let filter: DistFilter = initial;
  const dist = distPanel({ scope: "live", onPick: (f) => { filter = f; if (pending) paint(pending.now, pending.closed); else paint(shown, []); } });
  const distBox = el("details", "where-panel live-dist");
  distBox.open = true;
  const distNote = el("span", "muted small");
  distBox.append(el("summary", undefined, "통신 대상 분포 (지금 열린 연결) ", distNote), dist.root);
  root.append(el("div", "toolbar", "갱신 ", every, " ", pause, " ", status), el("p", "muted small", "지금 소켓이 열려 있는 이 PC 의 TCP 연결입니다(이 PC 안 연결 제외). 듣는 포트는 연결 이력 탭 아래에 있습니다."), distBox, pill, box);
  let paused = false;
  let nowTs = 0;
  let timer = 0;
  let prev: OpenConn[] = [];
  let shown: OpenConn[] = [];
  let pending: { now: OpenConn[]; closed: OpenConn[] } | null = null;
  let gen = 0;
  const hovering = () => box.matches(":hover") || box.contains(document.activeElement) || !!document.querySelector("dialog[open]");

  const paint = (now: OpenConn[], closed: OpenConn[]) => {
    shown = now;
    pending = null;
    clear(pill);
    clear(box);
    onCount(now.length);
    dist.paint(openAsConnLike(now), filter);
    if (filter) {
      const n = now.filter((c) => matchesFilter({ where: c.where ?? null } as never, filter)).length;
      const chip = button(`거름: ${filter.by === "country" ? "나라" : "망"} ${filter.key} · ${n}건 ×`, () => { filter = null; paint(now, closed); }, "filter-chip");
      chip.setAttribute("aria-label", "분포 거르기 해제");
      box.append(el("p", "muted small", chip));
      now = now.filter((c) => matchesFilter({ where: c.where ?? null } as never, filter));
      closed = closed.filter((c) => matchesFilter({ where: c.where ?? null } as never, filter));
    }
    if (!now.length && !closed.length) {
      box.append(el("p", "muted", filter ? "거른 조건에 맞는 열린 연결이 없습니다." : "지금 열린 외부 연결이 없습니다."));
      return;
    }
    const table = el("table", "grid conn live");
    const head = el("tr");
    for (const [h, cls] of [["프로그램", "c-prog"], ["상대", "c-remote"], ["나라 · 망", "c-where"], ["상태", "c-st"], ["열린 지", "c-num"], ["조치", "c-act"]] as const) head.append(el("th", cls, h));
    const body = el("tbody");
    table.append(el("thead", undefined, head), body);
    for (const c of sortOpen(now)) body.append(row(c, false));
    for (const c of closed) body.append(row(c, true));
    box.append(table);
  };

  const row = (c: OpenConn, closed: boolean): HTMLElement => {
    const tr = el("tr", closed ? "closed" : c.story_root ? "has-story" : "");
    const prog = el("td", "c-prog");
    prog.append(ext("span", c.image ? fileName(c.image) : `(pid ${c.pid})`, "prog"));
    if (c.story_root && c.story_level) prog.append(" ", button(`${LEVEL[c.story_level.toLowerCase() as keyof typeof LEVEL] ?? c.story_level} 인시던트 ›`, () => state.go("story", { root: c.story_root }), "chip level-link"));
    if (c.image) prog.title = c.image;
    // 3판 2-3 와 같은 '어디' 칸(국기 · 나라 · 망, 툴팁에 AS 번호)
    const where = whereCell(c.where);
    where.classList.add("c-where");
    const act = el("td", "c-act");
    if (!closed) {
      const kill = button("이 연결 끊기…", () => void killDialog(c), "btn small danger");
      if (!c.v4) {
        kill.disabled = true;
        kill.title = "Windows 가 IPv6 연결 하나를 끊는 기능을 제공하지 않습니다 — [접속지 차단…]을 쓰세요";
      }
      const block = button("접속지 차단…", () => c.story_root ? state.go("story", { root: c.story_root, cut: true }) : state.go("policy", { aclAdd: { remote: c.raddr } }), "btn small");
      block.title = c.story_root ? "이 인시던트의 격리·차단으로" : "정책 › ACL 에 이 주소를 막는 규칙을 채워 엽니다";
      act.append(block, " ", kill);
    }
    // 4판 3-4 의 열: 프로그램 · 상대 · 나라·망 · 상태 · 열린 지 · 조치. 이 PC 쪽 포트는 상대 칸 툴팁으로 옮겼다
    const remote = el("td", "c-remote mono", `${c.raddr}:${c.rport}`);
    remote.title = `이 PC ${c.laddr}:${c.lport} → ${c.raddr}:${c.rport}`;
    const opened = el("td", "c-num", closed ? "—" : openedText(c.first_seen_ts, nowTs, c.since_before));
    if (c.since_before) opened.title = "보호 서비스가 처음 볼 때 이미 열려 있던 연결입니다 — 실제로는 더 오래됐을 수 있습니다";
    tr.append(prog, remote, where, el("td", "c-st", closed ? "닫힘" : c.state), opened, act);
    return tr;
  };

  const killDialog = async (c: OpenConn) => {
    const dlg = el("dialog", "ack");
    dlg.append(el("h3", undefined, "연결 끊기"), el("p", undefined, `${c.image ? fileName(c.image) : `pid ${c.pid}`} 의 연결 하나를 끊습니다.`), el("p", "mono small", `${c.laddr}:${c.lport} → ${c.raddr}:${c.rport}`),
      el("p", "muted small", "승인 창에서 확인합니다. 프로그램이 곧바로 다시 접속할 수 있습니다 — 계속 막으려면 [접속지 차단…]을 쓰세요."));
    const out = el("div");
    const cancel = button("취소", () => { dlg.close(); dlg.remove(); }, "btn");
    const go = button("승인 창 열기", async () => {
      go.disabled = true;
      const r = await mutation("connections.kill", { laddr: c.laddr, lport: c.lport, raddr: c.raddr, rport: c.rport, pid: c.pid });
      go.disabled = false;
      if (!r.ok) return out.replaceChildren(el("p", "error", `연결 끊기: ${r.error.message}`));
      dlg.close();
      dlg.remove();
      void refresh(true);
    }, "btn danger");
    dlg.append(out, el("div", "actions", cancel, go));
    document.body.append(dlg);
    dlg.showModal();
  };

  const refresh = async (force = false) => {
    if (paused && !force) return;
    const my = ++gen;
    if (!shown.length && !box.firstChild) box.append(loadingBox());
    const r = await rpc<{ items: OpenConn[]; now_ts?: number }>("connections.open", {});
    if (my !== gen) return;
    if (!r.ok) {
      clear(box);
      box.append(failBox(r.error, () => void refresh(true), "지금 열린 연결"));
      return;
    }
    const now = r.result.items;
    // "열린 지"는 서비스 시계 기준(이 PC 화면 시계와 어긋나도 음수가 되지 않게)
    nowTs = r.result.now_ts ?? Math.floor(Date.now() / 1000);
    const closed = closedSince(prev, now);
    prev = now;
    status.textContent = `${now.length}건 · 마지막 갱신 ${new Date().toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
    if (!force && shown.length && hovering()) {
      // 2판 2-10: 보고 있는 동안 행을 움직이지 않는다(분포 막대·지도는 계속 실시간)
      pending = { now, closed };
      dist.paint(openAsConnLike(now), filter);
      const added = now.filter((c) => !shown.some((s) => connKey(s) === connKey(c))).length;
      clear(pill);
      pill.append(button(`변경 ${added + closed.length}건 — 보기`, () => pending && paint(pending.now, pending.closed), "new-pill"));
      return;
    }
    paint(now, closed);
  };
  const schedule = () => {
    window.clearInterval(timer);
    timer = window.setInterval(() => void refresh(), Number(every.value) * 1000);
  };
  every.addEventListener("change", schedule);
  void refresh(true);
  schedule();
  return { root, stop: () => window.clearInterval(timer) };
}
