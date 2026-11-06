import { rpc } from "../rpc";
import { FLAG_CODES } from "../flag-codes";
import { el, ext, clear, errorBox, button, filetimeToUnix, fmtTs, fmtHms } from "../ui";
import { failBox, noDataBox, collectionStalled, loadingBox, type HealthLike } from "../list-state";
import { fileName } from "../sanitize";
import { openProcessDrawer } from "./process";
import { bars, groupConns, matchesFilter, offMapLine, type GroupMode } from "./conn-group";
import { worldMap } from "./worldmap";

interface Conn {
  process_id: number;
  pid: number;
  image: string;
  remote_id: number;
  raddr: string;
  rport: number;
  proto: string;
  domain: string | null;
  direction: string;
  count: number;
  first_ft: number;
  last_ft: number;
  sent: number;
  recv: number;
  proxied_for: number | null;
  where?: Where | null;
  /// 하루 전까지 30일 안에 없던 ASN·나라(A2 "오늘 처음")
  new_asn?: boolean;
  new_cc?: boolean;
}

/// 묶음 선택은 이 브라우저에만 기억(실패해도 기본값 = 망)
function loadMode(): GroupMode {
  try {
    const v = localStorage.getItem("sf.conn.group");
    if (v === "org" || v === "program" || v === "country" || v === "none") return v;
  } catch { /* 저장소 없음 */ }
  return "org";
}
function saveMode(m: GroupMode) {
  try { localStorage.setItem("sf.conn.group", m); } catch { /* 무시 */ }
}
/// 서비스가 붙여 주는 원격 주소의 "어디" (geo 크레이트). 나라는 IP 위치 정보(DB-IP)다 — 서버 위치와 다를 수 있다
export interface Where {
  scope: string;
  cc?: string;
  country?: string;
  asn?: number;
  org?: string;
}
const SCOPE_KO: Record<string, string> = {
  public: "인터넷", loopback: "이 PC", private: "로컬망", link_local: "로컬망(링크로컬)", multicast: "멀티캐스트",
  broadcast: "브로드캐스트", cgnat: "통신사 NAT", unspecified: "지정 안 됨", documentation: "문서용 주소",
};

/// 국기를 쓰는 코드 = 번들에 SVG 가 있는 코드 − 지역·미정 코드(D005). 그 밖은 회색 점
const REGION_CODES = new Set(["EU", "AP", "ZZ"]);
export function flagPath(cc: string | null | undefined): string | null {
  if (!cc || !/^[A-Z]{2}$/.test(cc) || REGION_CODES.has(cc) || !FLAG_CODES.has(cc)) return null;
  return `flags/${cc.toLowerCase()}.svg`;
}
/// 국가 표시 이름(D005): 서비스가 준 한국어 이름 → 없으면 코드 두 글자. 지역 코드는 "○○(나라 미상)"
const REGION_KO: Record<string, string> = { EU: "유럽(나라 미상)", AP: "아시아·태평양(나라 미상)", ZZ: "지정 안 됨" };
export function placeName(w: Where): string | null {
  if (w.cc && REGION_KO[w.cc]) return REGION_KO[w.cc]!;
  return w.country ?? w.cc ?? null;
}
const ZZ_TIP = "위치·소유자가 정해지지 않은 주소 블록";

/// '어디' 칸 한 줄(D001): [국기 16px] 국가 · 조직. 고정 너비, 넘치면 말줄임, 전체는 툴팁. 특수 주소는 회색 점 + 종류.
/// 국기는 public/flags(flag-icons MIT — Windows 는 국기 이모지를 못 그림). 국가 코드는 대문자 두 글자일 때만 경로에 쓴다.
/// 조직 이름은 외부 문자열이라 텍스트 노드로만, 원문 그대로(법인 꼬리 정리 안 함)
export function whereCell(w: Where | null | undefined): HTMLElement {
  const td = el("td", "where");
  const inner = el("span", "where-inner");
  td.append(inner);
  if (!w) return td;
  const fp = flagPath(w.cc);
  if (fp) {
    const img = el("img", "flag");
    img.src = fp;
    img.alt = w.cc ?? "";
    // 파일이 없거나 못 읽으면 깨진 그림 대신 회색 점 (인라인 핸들러 아님 — CSP)
    img.addEventListener("error", () => img.replaceWith(el("span", "where-dot")));
    inner.append(img);
  } else {
    inner.append(el("span", "where-dot"));
  }
  const place = placeName(w);
  const text = place ? (w.org ? `${place} · ${w.org}` : place) : w.org ?? SCOPE_KO[w.scope] ?? "알 수 없음";
  inner.append(el("span", "where-text", text));
  td.title = w.cc ? `${text}${w.asn ? ` (AS${w.asn})` : ""}${w.cc === "ZZ" ? ` — ${ZZ_TIP}` : ""}` : text;
  return td;
}
interface Listener {
  proto: string;
  laddr: string;
  lport: number;
  pid: number;
  any_addr: boolean;
  process_id: number | null;
  image: string | null;
}

/// 값 없음 표시(D003 004-2): 회색 "—" 하나로 통일
export const NONE = "—";
function numCell(text: string): HTMLElement {
  return el("td", text === NONE ? "c-num none" : "c-num", text);
}
/// D020-4: 짧게 — 1 KB 미만 B, 1 MB 미만 정수 KB, 그 이상 소수 1자리 MB/GB. 숫자는 자르지 않는다
export function bytes(n: number): string {
  if (!n) return NONE;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

/// 연결 목록(최근 N분, 2초 갱신) + 리스닝 포트. 행을 누르면 프로세스 상세.
export function connections(): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "연결"));
  const windowSel = el("select");
  for (const [v, l] of [["300", "최근 5분"], ["3600", "최근 1시간"], ["86400", "오늘"]] as const) {
    const o = el("option", undefined, l);
    o.value = v;
    windowSel.append(o);
  }
  const note = el("div");
  const pill = el("div", "new-pill-row");
  const table = el("table", "grid conn");
  const head = el("tr");
  // D001: 시각 · 프로그램 · 방향 · 원격(도메인 우선, 없으면 IP:포트) · 어디 · 프로토콜 · 횟수 · 보냄 · 받음
  for (const [h, cls, tip] of [
    ["시각", "c-time", "이 범위 안에서 마지막으로 접속한 시각"],
    ["프로그램", "c-prog", ""],
    ["방향", "c-dir", ""],
    ["원격", "c-remote", "도메인을 알면 도메인, 모르면 IP 주소"],
    ["어디", "c-where", "나라는 IP 주소의 위치 정보(DB-IP)로 표시합니다. 실제 서버 위치와 다를 수 있습니다. 국가 표기는 정치적 입장을 뜻하지 않습니다."],
    ["프로토콜", "c-proto", ""],
    ["횟수", "c-num", ""],
    ["보냄", "c-num", ""],
    ["받음", "c-num", ""],
  ] as const) {
    const th = el("th", cls, h);
    if (tip) th.title = tip;
    head.append(th);
  }
  const body = el("tbody");
  table.append(el("thead", undefined, head), body);
  const lnote = el("div");
  const ltable = el("table", "grid");
  const lhead = el("tr");
  for (const h of ["프로토콜", "주소", "포트", "PID", "프로세스", ""]) {
    const th = el("th", undefined, h);
    // D003-5: 주황 0.0.0.0 의 뜻
    if (h === "주소") th.title = "0.0.0.0·:: = 모든 네트워크에서 받음, 127.0.0.1 = 이 PC 안에서만";
    lhead.append(th);
  }
  const lbody = el("tbody");
  ltable.append(el("thead", undefined, lhead), lbody);
  const detail = el("div", "detail");
  const hideEph = el("input");
  hideEph.type = "checkbox";
  hideEph.checked = true;
  // A2: 묶음 선택(분절 단추)
  let mode: GroupMode = loadMode();
  const seg = el("span", "seg");
  const MODES: [GroupMode, string][] = [["org", "망(조직)"], ["program", "프로그램"], ["country", "국가"], ["none", "묶지 않음"]];
  const segBtns = MODES.map(([m, label]) => {
    const b = button(label, () => { mode = m; saveMode(m); paintSeg(); void tick(); }, "btn small seg-btn");
    b.dataset["mode"] = m;
    return b;
  });
  const paintSeg = () => segBtns.forEach((b) => b.classList.toggle("on", b.dataset["mode"] === mode));
  seg.append(...segBtns);
  paintSeg();
  const expanded = new Set<string>();
  // A3: "오늘 어디와 통신했나" 접이식 막대 패널(기본 접힘). 막대를 누르면 표를 거른다(다시 누르면 해제)
  let filter: { by: "country" | "org"; key: string } | null = null;
  const where3 = el("details", "where-panel");
  const where3Body = el("div", "where-bars");
  // 막대 / 지도 전환(사용자 요청). 지도도 같은 거르기
  let view: "bars" | "map" = "bars";
  const viewBtns = (["bars", "map"] as const).map((v) => {
    const b = button(v === "bars" ? "막대" : "지도", () => { view = v; viewBtns.forEach((x) => x.classList.toggle("on", x === b)); void tick(); }, "btn small seg-btn");
    if (v === view) b.classList.add("on");
    return b;
  });
  where3.append(el("summary", undefined, "오늘 어디와 통신했나"), el("div", "where-head", el("span", "seg", ...viewBtns)), where3Body,
    el("p", "callout small", "나라는 IP 주소의 위치 정보(DB-IP)로 표시합니다. 실제 서버 위치와 다를 수 있습니다. 국가 표기는 정치적 입장을 뜻하지 않습니다."));
  root.append(
    el("div", "toolbar", "묶음 ", seg, " · 범위 ", windowSel, el("span", "muted", " · 지금 열린 연결이 아니라 이 범위 안의 접속 기록(이력)입니다")),
    where3,
    note,
    pill,
    table,
    el("h2", undefined, "듣고 있는 포트"),
    el("label", "muted", hideEph, " 임시 UDP 포트(49152 이상) 숨기기"),
    lnote,
    ltable,
    detail,
  );

  const open = (id: number | null) => {
    if (id == null) return;
    // D025-A5: 오른쪽 패널로(표 위치를 잃지 않게)
    openProcessDrawer(id);
  };

  // D021: 첫 응답 전에는 빈 표 대신 "불러오는 중". 앞 요청이 끝나기 전에는 다음 갱신을 보내지 않는다(느릴 때 대기열을 키우지 않게)
  let busy = false;
  let again = false;
  let againAuto = true;
  let loaded = false;
  // D030-3: 보는 중(표 위 포인터·표 안 포커스·스크롤 내림·상세 패널 열림)에는 자동 갱신으로 행을 끼워 넣지 않는다.
  // 새 접속은 "새 접속 N건 — 보기" 알약으로 알리고, 누르면 반영 후 맨 위로
  let hover = false;
  table.addEventListener("pointerenter", () => { hover = true; });
  table.addEventListener("pointerleave", () => { hover = false; });
  let shownKeys = new Set<string>();
  const watching = (): boolean => {
    const sc = (root.closest("main") as HTMLElement | null)?.scrollTop ?? 0;
    // D035-1: pointerenter 를 놓칠 수 있다(SetCursorPos·창 밖에서 들어온 포인터) — 갱신 직전에 :hover 로도 다시 본다
    return hover || table.matches(":hover") || table.contains(document.activeElement) || !!document.querySelector(".pd-drawer") || sc > 0 || (document.scrollingElement?.scrollTop ?? 0) > 0;
  };
  const tick = async (auto = false) => {
    // 진행 중에 누른 것(묶음 펼치기 등)은 끝난 뒤 한 번 더 그린다.
    // D035-1 원인: 자동 갱신이 겹쳐 미뤄지면 예전엔 사용자 동작처럼(auto=false) 다시 돌아 "보는 중 멈춤"을 건너뛰었다.
    // 미뤄진 것 중 하나라도 사용자 동작이면 바로 그리고, 모두 자동 갱신이면 자동 갱신으로 다시 돈다
    if (busy) { again = true; if (!auto) againAuto = false; return; }
    busy = true;
    if (!loaded) { clear(note); clear(body); note.append(loadingBox()); }
    const r = await rpc<{ items: Conn[] }>("connections.list", { since_secs: Number(windowSel.value), cursor: { limit: 500 } }).finally(() => {
      busy = false;
      if (again) { const a = againAuto; again = false; againAuto = true; setTimeout(() => void tick(a), 0); }
    });
    if (auto && loaded && r.ok && watching()) {
      const fresh = pausedNew(shownKeys, r.result.items);
      clear(pill);
      if (fresh > 0) {
        pill.append(button(`새 접속 ${fresh}건 — 보기`, () => {
          clear(pill);
          (root.closest("main") as HTMLElement | null)?.scrollTo({ top: 0 });
          window.scrollTo({ top: 0 });
          void tick();
        }, "btn small new-pill"));
      }
      return;
    }
    clear(pill);
    loaded = true;
    clear(note);
    clear(body);
    if (!r.ok) return note.append(failBox(r.error, () => void tick(), "접속 목록"));
    shownKeys = new Set(r.result.items.map(connKey));
    // D028-4: 비어 있으면 표 머리줄을 숨긴다(문장만)
    table.classList.toggle("empty", !r.result.items.length);
    if (!r.result.items.length) {
      // D015-4: 0건이고 수집이 멈췄으면 "기록 없음"이 아니라 "수집 안 됨"
      const h = await rpc<HealthLike>("collector.health", {});
      note.append(h.ok && collectionStalled(h.result) ? noDataBox() : el("p", "muted", "이 범위에 접속 기록이 없습니다."));
    }
    paintBars(r.result.items);
    const shown = r.result.items.filter((c) => matchesFilter(c, filter));
    if (filter) note.append(el("p", "muted", "막대로 거른 목록입니다. 같은 막대를 다시 누르면 해제됩니다."));
    if (mode === "none") {
      for (const c of shown) body.append(rowOf(c));
      return;
    }
    for (const g of groupConns(shown, mode)) {
      const open1 = expanded.has(g.key);
      // D009-9: 시각~원격 칸을 합친 한 칸에 두 줄(조직 [오늘 처음] / AS · 원격 N곳 · 프로그램), 어디 = [국기] 국가, 프로토콜 비움
      const tr = el("tr", g.isNew ? "group-row clickable is-new" : "group-row clickable");
      const title = el("td", "c-group");
      title.colSpan = 4;
      const l1 = el("div", "g-l1", el("span", "caret", open1 ? "▾ " : "▸ "), ext("span", g.title, "g-title"));
      if (g.isNew) l1.append(" ", el("span", "badge-new", "오늘 처음"));
      title.append(l1, ext("div", `${g.sub} · ${g.programs}`, "muted small g-l2"));
      const local = g.items.every((c) => c.where && c.where.scope !== "public");
      const place = whereCell(g.placeCc ? { scope: "public", cc: g.placeCc, country: g.place } : { scope: local ? "private" : "public", country: g.place });
      tr.append(title, place, el("td", "c-proto"), numCell(String(g.count)), numCell(bytes(g.sent)), numCell(bytes(g.recv)));
      tr.addEventListener("click", () => { if (expanded.has(g.key)) expanded.delete(g.key); else expanded.add(g.key); void tick(); });
      body.append(tr);
      if (open1) for (const c of g.items) body.append(rowOf(c, true));
    }
  };
  const paintBars = (items: Conn[]) => {
    clear(where3Body);
    where3Body.classList.toggle("map-view", view === "map");
    if (view === "map") {
      const { bars: bs } = bars(items, "country", 1000);
      const sel = filter?.by === "country" ? filter.key : null;
      where3Body.append(
        worldMap(bs.map((b) => ({ cc: b.key, label: b.label, value: b.value, isNew: b.isNew })), sel, (cc) => {
          filter = sel === cc ? null : { by: "country", key: cc };
          void tick();
        }),
        el("div", "map-legend muted small", "접속 수 ", el("i", "lg lv0"), " 0 ", el("i", "lg lv1"), " 1 ", el("i", "lg lv2"), " 2–5 ", el("i", "lg lv3"), " 6–20 ", el("i", "lg lv4"), " 21+ · ", el("i", "lg new"), " 오늘 처음"),
      );
      const off = offMapLine(items);
      if (off) where3Body.append(el("div", "muted small", off));
      return;
    }
    for (const [by, title] of [["country", "나라별 (접속 수)"], ["org", "망(조직)별 (접속 수)"]] as const) {
      const { bars: bs, rest } = bars(items, by);
      const col = el("div", "bar-col", el("h4", undefined, title));
      const max = Math.max(1, ...bs.map((b) => b.value));
      for (const b of bs) {
        const on = filter?.by === by && filter.key === b.key;
        const row = el("div", `bar-row${b.isNew ? " is-new" : ""}${on ? " on" : ""}`);
        const name = ext("span", b.label, "bar-name");
        name.title = b.label;
        const fill = el("span", "bar-fill");
        fill.style.width = `${Math.round((b.value / max) * 100)}%`;
        row.append(name, el("span", "bar-track", fill), el("span", "bar-val", String(b.value)));
        if (b.isNew) row.append(el("span", "badge-new", "오늘 처음"));
        row.addEventListener("click", () => { filter = on ? null : { by, key: b.key }; void tick(); });
        col.append(row);
      }
      if (rest) col.append(el("div", "muted small", `그 밖에 ${rest}곳`));
      // D010-2: 막대 보기에도 같은 줄(국가 막대 아래)
      if (by === "country") {
        const off = offMapLine(items, "막대");
        if (off) col.append(el("div", "muted small", off));
      }
      if (!bs.length) col.append(el("div", "muted small", "공인 주소 접속이 없습니다."));
      where3Body.append(col);
    }
  };
  const rowOf = (c: Conn, child = false): HTMLElement => {
    {
      const tr = el("tr", child ? "clickable child-row" : "clickable");
      const last = filetimeToUnix(c.last_ft);
      const tdTime = el("td", "c-time", fmtHms(last));
      tdTime.title = fmtTs(last);
      // D030-4: 누를 수 있는 것은 실제 button(접근성·UIA Invoke). 행 전체 클릭은 보조
      const progBtn = button(fileName(c.image), () => open(c.process_id), "cell-btn");
      progBtn.addEventListener("click", (e) => e.stopPropagation());
      const prog = el("td", "c-prog", progBtn);
      prog.title = `${c.image} (PID ${c.pid})`;
      const out = c.direction === "out";
      const dir = el("td", "c-dir", el("span", "dir-icon", out ? "↗" : "↙"), el("span", "dir-text", out ? " 나감" : " 받음"));
      // IPv6 는 [주소]:포트
      const hostPort = `${c.domain ?? (c.raddr.includes(":") ? `[${c.raddr}]` : c.raddr)}:${c.rport}`;
      const remote = ext("td", hostPort);
      remote.className = "c-remote";
      remote.title = c.domain ? `${c.domain} (${c.raddr}:${c.rport})` : hostPort;
      tr.append(tdTime, prog, dir, remote, whereCell(c.where), el("td", "c-proto", c.proto.toUpperCase()));
      tr.append(numCell(c.count ? String(c.count) : NONE), numCell(bytes(c.sent)), numCell(bytes(c.recv)));
      if (c.proxied_for != null) tr.title = "서비스가 다른 프로그램 대신 접속 (기록 대조로 짝지음)";
      tr.addEventListener("click", () => open(c.process_id));
      return tr;
    }
  };
  let lbusy = false;
  let lloaded = false;
  const ltick = async () => {
    if (lbusy) return;
    lbusy = true;
    if (!lloaded) { clear(lnote); clear(lbody); lnote.append(loadingBox()); }
    const r = await rpc<{ items: Listener[] }>("listeners.list", {}).finally(() => { lbusy = false; });
    lloaded = true;
    clear(lnote);
    clear(lbody);
    if (!r.ok) return lnote.append(failBox(r.error, () => void ltick(), "듣는 포트 목록"));
    const items = r.result.items.filter((l) => !(hideEph.checked && l.proto === "udp" && l.lport >= 49152));
    const hidden = r.result.items.length - items.length;
    // D028-4: 빈 표는 머리줄 대신 문장
    ltable.classList.toggle("empty", !items.length);
    if (!items.length) lnote.append(el("p", "muted", "듣고 있는 포트가 없습니다."));
    if (hidden) lnote.append(el("p", "muted", `임시 UDP 포트 ${hidden}개를 숨겼습니다.`));
    const sorted = [...items].sort((a, b) => Number(b.any_addr) - Number(a.any_addr) || a.lport - b.lport);
    for (const l of sorted) {
      const tr = el("tr", l.any_addr ? "any-addr" : undefined);
      tr.append(el("td", undefined, l.proto), ext("td", l.laddr), el("td", undefined, String(l.lport)), el("td", undefined, String(l.pid)), listenerName(l.pid, l.image));
      // D028-5·D029-5: 상세 버튼 기준 하나 — 그래프에 프로세스 노드가 있고, 커널 의사 프로세스(PID 4·0)가 아니면
      tr.append(el("td", undefined, hasListenerDetail(l.pid, l.process_id) ? button("상세", () => open(l.process_id), "btn small") : ""));
      if (l.any_addr) tr.title = "모든 주소에서 듣고 있습니다 (외부에서 닿을 수 있음)";
      lbody.append(tr);
    }
  };
  windowSel.addEventListener("change", () => { loaded = false; void tick(); });
  hideEph.addEventListener("change", () => void ltick());
  void tick();
  void ltick();
  const t1 = window.setInterval(() => void tick(true), 2000);
  const t2 = window.setInterval(() => void ltick(), 5000);
  root.addEventListener("screen-leave", () => {
    window.clearInterval(t1);
    window.clearInterval(t2);
  });
  return root;
}

/// D028-5: 듣는 포트의 프로그램 칸. PID 4·0 은 이름을 알 수 없는 것이 아니라 커널·유휴 의사 프로세스다
/// (관리자로 실행 중에 "권한 부족"이 보이면 모순으로 읽힌다)
export function listenerName(pid: number, image?: string | null): HTMLElement {
  if (image) return ext("td", fileName(image));
  if (pid === 4) return el("td", undefined, "System (Windows 커널)");
  if (pid === 0) return el("td", undefined, "System Idle");
  return el("td", "muted", "알 수 없음");
}

/// D029-5: 듣는 포트 줄의 상세 버튼 표시 기준. PID 4(System)·0(Idle)은 실행 파일·출신이 없는 커널 의사 프로세스라 상세가 뜻이 없다
export function hasListenerDetail(pid: number, processId: number | null | undefined): boolean {
  return processId != null && pid !== 4 && pid !== 0;
}

/// D030-3: 연결 행의 정체(위치가 아니라 ID) — 프로세스 노드·원격 노드·방향
export function connKey(c: { process_id: number; remote_id: number; direction: string }): string {
  return `${c.process_id}:${c.remote_id}:${c.direction}`;
}
/// 멈춘 동안 새로 생긴 행 수(지금 보이는 행에 없는 것)
export function pausedNew(shown: Set<string>, items: { process_id: number; remote_id: number; direction: string }[]): number {
  return items.filter((c) => !shown.has(connKey(c))).length;
}
