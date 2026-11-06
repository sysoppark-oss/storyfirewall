// 흐름 보기 (D049: 1번 d045-flow 의 장 레일·오늘 한 일 꼬리 + B안 그물 지도의 관계 지도·선택한 것 패널).
// 이야기 카드 · 마인드맵과 같은 사실의 세 번째 보기다. 데이터는 마인드맵과 같은 graph.neighbors(근거가 있는 선만).
// 원칙: 모든 상자·선은 출처 그래프의 노드·선 하나에 대응하고 선을 누르면 근거가 나온다. 늘 움직이는 장식은 없다.
// 외부 문자열(파일명·도메인·명령줄)은 텍스트 노드로만 넣는다(innerHTML 금지).
import { rpc } from "../rpc";
import { el, clear, errorBox, ext, button, fmtShort, fmtShortSec, filetimeToUnix, fmtTs } from "../ui";
import { sanitize } from "../sanitize";
import { REL, hostOf, portOf, type Branch } from "./mindmap";
import { placeName, flagPath } from "./connections";
import { openProcessDrawer } from "./process";

/// 관계 지도의 네 열(B안): 출신 → 파일 → 프로세스 → 한 일
export type FlowCol = "origin" | "file" | "process" | "did";
export const FLOW_COLS: { key: FlowCol; name: string }[] = [
  { key: "origin", name: "출신" },
  { key: "file", name: "파일" },
  { key: "process", name: "프로세스" },
  { key: "did", name: "한 일" },
];

/// 노드가 어느 열에 서는가. 주인공(hero)과 그 자손 프로세스는 "프로세스", 파일은 "파일",
/// 조상 쪽 프로세스·받아 온 곳은 "출신", 주인공 쪽 결과(접속지·자동 실행·명령줄·만든 파일)는 "한 일"
export function flowColumn(b: Pick<Branch, "side" | "depth"> & { node: { kind: string }; via: { rel: string } | null }): FlowCol {
  const k = b.node.kind;
  if (b.depth === 0) return k === "file" ? "file" : "process";
  if (b.side === "origin") return k === "file" ? "file" : "origin";
  if (k === "process") return "process";
  // 주인공 파일에서 실행된 프로세스(executed_as)는 프로세스 열
  if (k === "file" && b.via?.rel === "wrote") return "did";
  if (k === "file") return "file";
  return "did";
}

/// 장 레일 한 칸(d045-flow): 5장 = 파괴 징후. 사실 문장이 없는 장은 "해당 없음"
export interface RailStep {
  n: number;
  name: string;
  on: boolean;
  text: string | null;
  ts: number | null;
  edge: number | null;
}
export const RAIL_NAMES = ["유입", "실행", "자리잡기", "외부 접속", "파괴 징후"];
/// 카드 항목 이름 → 장(항목에는 장 번호가 없다). 사실 문장이 없는 장은 이 항목으로 채운다
export const ITEM_CHAPTER: Record<string, number> = { 출신: 1, 위치: 2, 서명: 2, "자동 실행": 3, 접속: 4 };
export function railSteps(ev: {
  reached?: number[];
  sentences: { text: string; ts: number; edge_ids: number[]; chapter: number | null }[];
  destroy?: { sentence: string; ts: number; edge_id: number };
  items?: { label: string; value: string; edge_ids: number[] }[];
}): RailStep[] {
  return RAIL_NAMES.map((name, i) => {
    const n = i + 1;
    if (n === 5) {
      const d = ev.destroy;
      return { n, name, on: !!d, text: d?.sentence ?? null, ts: d?.ts ?? null, edge: d?.edge_id ?? null };
    }
    // 그 장의 가장 이른 사실 문장
    const s = ev.sentences.filter((x) => x.chapter === n).sort((a, b) => a.ts - b.ts)[0];
    // 문장이 없으면 그 장에 해당하는 카드 항목("출신: 인터넷에서 받은 파일" 등) — 켜진 장에 "기록 없음"이 뜨는 모순 방지
    const it = s ? undefined : (ev.items ?? []).find((x) => ITEM_CHAPTER[x.label] === n);
    const on = (ev.reached ?? []).includes(n) || !!s || !!it;
    if (it) return { n, name, on, text: `${it.label}: ${it.value}`, ts: null, edge: it.edge_ids[0] ?? null };
    return { n, name, on, text: s?.text ?? null, ts: s && s.ts > 0 ? s.ts : null, edge: s?.edge_ids[0] ?? null };
  });
}

/// 상자 글자: 첫 줄 이름, 둘째 줄 종류·장소. 자동 실행은 위치의 마지막 이름, 접속지는 호스트 + 포트·나라
export function boxText(b: Branch): { title: string; sub: string; mono: boolean; spoof: boolean } {
  const k = b.node.kind;
  const full = k === "autorun" ? (b.node.key.split(/[\\/]/).pop() ?? b.node.key) : b.node.label || b.node.key;
  const host = k === "remote" ? hostOf(full) || full : full;
  const s = sanitize(host, k === "command" ? 60 : 40);
  const port = k === "remote" ? portOf(full) : "";
  const place = b.where ? placeName(b.where) ?? "" : "";
  const viaWord = b.via ? REL[b.via.rel] ?? b.via.rel : "";
  const kindWord: Record<string, string> = { process: "프로그램", file: "파일", remote: "접속지", domain: "도메인", autorun: "시작 프로그램", command: "명령줄" };
  // 관계 말(접속·실행 등)이 있으면 종류 말은 겹치므로 뺀다("접속 · 접속지" 방지). 주인공·관계 없는 것만 종류 말
  const head = b.depth === 0 ? `주인공 · ${kindWord[k] ?? ""}` : viaWord || kindWord[k] || "";
  const sub = [head, port && `포트 ${port}`, place].filter(Boolean).join(" · ");
  return { title: s.text, sub, mono: k === "command" || k === "remote", spoof: s.spoofRisk };
}

const SVG = "http://www.w3.org/2000/svg";
/// 열마다 보이는 상자 수(나머지는 "외 N개" — 전부는 마인드맵)
export const PER_COL = 8;

/// 조상 쪽의 "실행 파일" 노드(판정 근거 아님)는 그리지 않는다 — 같은 이름이 파일·출신 열에 두 번 보이는 혼동(마인드맵 D006-6)
export function hiddenOrigin(b: { side: string; node: { kind: string }; via: { rel: string; chapter: number | null } | null }): boolean {
  return b.side === "origin" && b.node.kind === "file" && b.via?.rel === "executed_as" && b.via.chapter == null;
}

/// 도메인 노드 id → 같은 호스트의 접속지 노드 id
export function domainAliases(branches: { node: { id: number; kind: string; key: string; label: string } }[]): Map<number, number> {
  const remoteByHost = new Map<string, number>();
  for (const b of branches) {
    if (b.node.kind !== "remote") continue;
    const host = hostOf(b.node.label || b.node.key);
    if (host && !remoteByHost.has(host)) remoteByHost.set(host, b.node.id);
  }
  const alias = new Map<number, number>();
  for (const b of branches) {
    if (b.node.kind !== "domain") continue;
    const to = remoteByHost.get((b.node.label || b.node.key).toLowerCase());
    if (to != null) alias.set(b.node.id, to);
  }
  return alias;
}

export function flowView(ev: {
  root: number;
  reached?: number[];
  sentences: { text: string; ts: number; edge_ids: number[]; chapter: number | null }[];
  destroy?: { sentence: string; ts: number; edge_id: number; cmdline: string };
  items?: { label: string; value: string; edge_ids: number[] }[];
}): HTMLElement {
  const root = el("div", "card flowview");
  const rail = el("ol", "flow-rail");
  const map = el("div", "flow-map");
  const side = el("aside", "flow-side");
  const tail = el("div", "flow-tail");
  // B안 제목 줄: "○○ 에서 시작한 일" · 시각 범위 · 선 N개 · 근거 N건 (불러온 뒤 채움)
  const titleRow = el("div", "flow-titlebar");
  const legend = el("div", "flow-legend muted small", el("span", undefined, "굵은 청록 선 = 판정에 쓰인 선"), el("span", undefined, "빨간 선 = 파괴 징후로 이어지는 선"), el("span", undefined, "상자를 누르면 오른쪽에 그 사실"));
  root.append(titleRow, el("div", "flow-body", rail, map, side), tail);

  const explain = async (edgeId: number, into: HTMLElement) => {
    clear(into);
    const r = await rpc<{ evidence: { id: number; ts: number; source: string; kind?: string; payload_json?: string }[] }>("story.explain", { edge_id: edgeId });
    if (!r.ok) return into.append(errorBox(r.error.message));
    into.append(el("h4", undefined, "근거"));
    for (const e of r.result.evidence) into.append(el("div", "evidence", `${fmtTs(filetimeToUnix(e.ts))} [${e.source}] `, ext("span", e.kind ?? e.payload_json ?? "")));
  };

  // 장 레일(왼쪽): ◆ 해당 · ◇ 해당 없음 · 5장은 빨강
  for (const s of railSteps(ev)) {
    const li = el("li", `rail-step ${s.on ? "on" : "off"}${s.n === 5 ? " destroy" : ""}`);
    li.append(el("span", "rail-mark", s.on ? "◆" : "◇"));
    const head = el("div", "rail-head", el("b", undefined, `${s.n}장 ${s.name}`));
    if (s.ts) head.append(" ", el("span", "muted small", fmtShortSec(filetimeToUnix(s.ts))));
    const body = el("div", "rail-body", head);
    if (s.text) body.append(ext("div", s.text));
    else body.append(el("div", "muted small", s.on ? "판정에 포함됨 — 근거는 카드 항목" : s.n === 3 ? "자동 실행 등록 기록 없음" : "해당 기록 없음"));
    if (s.edge != null) {
      const box = el("div", "evidence-box");
      const edge = s.edge;
      body.append(button("근거", () => (box.firstChild ? clear(box) : void explain(edge, box)), "btn small"), box);
    }
    li.append(body);
    rail.append(li);
  }

  // 선택한 것(오른쪽)
  const showSide = (b: Branch) => {
    clear(side);
    const t = boxText(b);
    side.append(el("div", "muted small", "선택한 것"), el("div", "flow-side-title", ext("span", t.title), " ", el("span", "muted small", t.sub)));
    // B안: 이 상자에 걸린 사실 문장을 시각순으로(주인공이면 사건 전체)
    const mine = (b.node.id === heroNode ? ev.sentences : ev.sentences.filter((x) => b.via != null && x.edge_ids.includes(b.via.id)))
      .slice().sort((a, c) => a.ts - c.ts).slice(0, 8);
    if (mine.length) {
      const ol = el("ol", "flow-facts");
      for (const f of mine) {
        const when = f.ts > 0 && filetimeToUnix(f.ts) > 946684800 ? fmtShort(filetimeToUnix(f.ts)) : "—";
        ol.append(el("li", f.chapter === 5 ? "destroy" : undefined, el("span", "muted small time", when), ext("span", f.text)));
      }
      side.append(ol);
      const ev_n = new Set(mine.flatMap((x) => x.edge_ids)).size;
      side.append(el("div", "muted small", `근거 ${ev_n}건`));
    } else if (b.via) {
      side.append(el("p", undefined, `${REL[b.via.rel] ?? b.via.rel} · ${fmtShortSec(filetimeToUnix(b.via.ts))}`));
    }
    if (b.via) {
      const box = el("div", "evidence-box");
      const eid = b.via.id;
      side.append(el("div", "flow-side-actions", button("근거 보기", () => void explain(eid, box), "btn small")), box);
    }
    // 프로그램 자세히는 단추로(늘 펼치면 오른쪽 패널이 길어져 지도가 빈 칸으로 늘어났다 — B안 검수)
    // UI 3판 초안(2026-11-07): 좁은 옆 칸에 넣으면 한 단어씩 줄이 바뀐다 — 넓은 오른쪽 서랍으로 연다
    if (b.node.kind === "process") {
      const btn = button("프로그램 자세히", () => openProcessDrawer(b.node.id), "btn small");
      const acts = side.querySelector(".flow-side-actions");
      if (acts) acts.append(btn); else side.append(el("div", "flow-side-actions", btn));
    }
  };

  // 관계 지도(가운데): 네 열 + 선(SVG). 데이터를 받아 상자를 놓고, 그려진 뒤 상자 위치로 선을 긋는다
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", "flow-lines");
  svg.setAttribute("aria-hidden", "true");
  const grid = el("div", "flow-cols");
  const colEls = new Map<FlowCol, HTMLElement>();
  for (const c of FLOW_COLS) {
    const col = el("div", `flow-col col-${c.key}`, el("div", "flow-col-name", c.name));
    colEls.set(c.key, col);
    grid.append(col);
  }
  map.append(svg, grid);
  const boxes = new Map<number, HTMLElement>();
  let heroNode = -1;
  let links: { src: number; dst: number; chapter: boolean; destroy: boolean; eid: number; rel: string }[] = [];

  const drawLines = () => {
    const base = map.getBoundingClientRect();
    svg.setAttribute("width", String(base.width));
    svg.setAttribute("height", String(base.height));
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    for (const l of links) {
      const a = boxes.get(l.src), b = boxes.get(l.dst);
      if (!a || !b) continue;
      const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
      // 왼쪽 상자의 오른쪽 가운데 → 오른쪽 상자의 왼쪽 가운데(같은 열이면 아래로)
      const leftToRight = ra.left <= rb.left;
      const [p, q] = leftToRight ? [ra, rb] : [rb, ra];
      const sameCol = Math.abs(ra.left - rb.left) < 4;
      // 같은 열 안의 선(예: 출신 열의 조상 사이)은 끝이 상자에 닿지 않아 끊긴 선처럼 보였다 — 긋지 않는다(근거는 마인드맵)
      if (sameCol) continue;
      const x1 = sameCol ? ra.left + 16 - base.left : p.right - base.left;
      const y1 = sameCol ? ra.bottom - base.top : p.top + p.height / 2 - base.top;
      const x2 = sameCol ? rb.left + 16 - base.left : q.left - base.left;
      const y2 = sameCol ? rb.top - base.top : q.top + q.height / 2 - base.top;
      const path = document.createElementNS(SVG, "path");
      const mx = (x1 + x2) / 2;
      path.setAttribute("d", sameCol ? `M${x1},${y1} L${x2},${y2}` : `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`);
      // B안: 빨간 선은 파괴 징후(5장)로 이어지는 선에만. 판정(1~4장) 선은 굵은 청록, 나머지는 점선
      path.setAttribute("class", l.destroy ? "flow-line destroy" : l.chapter ? "flow-line chapter" : "flow-line");
      const title = document.createElementNS(SVG, "title");
      title.textContent = REL[l.rel] ?? l.rel;
      path.append(title);
      svg.append(path);
    }
  };

  const load = async () => {
    const r = await rpc<{ branches: Branch[]; truncated: boolean; cap: number }>("graph.neighbors", { node_id: ev.root, max_depth: 3 });
    if (!r.ok) return map.append(errorBox(`graph.neighbors: ${r.error.message}`));
    // 같은 노드는 가장 얕은 자리 하나에만(마인드맵과 같은 규칙)
    const rank = (b: Branch) => b.depth * 2 + (b.side === "origin" ? 1 : 0);
    // 같은 접속지의 "도메인"(조회) 노드는 "접속지" 노드와 하나로 — 상자가 두 번 보이지 않게(마인드맵 D003-6 과 같은 규칙)
    const alias = domainAliases(r.result.branches);
    const best = new Map<number, Branch>();
    for (const b of r.result.branches) {
      if (alias.has(b.node.id) || hiddenOrigin(b)) continue;
      const cur = best.get(b.node.id);
      if (!cur || rank(b) < rank(cur)) best.set(b.node.id, b);
    }
    // 주인공 프로세스: 뿌리가 파일이면 그 파일로 실행된 첫 프로세스(마인드맵 D007-4 와 같은 규칙)
    const root0 = [...best.values()].find((b) => b.depth === 0);
    let heroId = root0?.node.id ?? ev.root;
    if (root0?.node.kind === "file") {
      const p = [...best.values()].find((b) => b.side === "action" && b.depth === 1 && b.node.kind === "process" && b.via?.rel === "executed_as");
      if (p) heroId = p.node.id;
    }
    heroNode = heroId;
    // 접속지는 주인공의 것과 판정 근거만 상자로. 다른 프로그램(조상 브라우저 등)의 접속은 그 상자 안 "접속 N" 으로 접는다(마인드맵 D007-5)
    const foldN = new Map<number, number>();
    for (const b of [...best.values()]) {
      const target = b.node.kind === "remote" || b.node.kind === "domain";
      if (!target || !b.via || b.via.chapter != null || b.via.src === heroId) continue;
      best.delete(b.node.id);
      foldN.set(b.via.src, (foldN.get(b.via.src) ?? 0) + 1);
    }
    // 열 안 순서: 판정 선(chapter) 먼저, 그다음 시각순. 열마다 PER_COL 개까지(나머지는 "외 N개" — 화면이 길어지지 않게)
    const byCol = new Map<FlowCol, Branch[]>();
    for (const b of best.values()) {
      const c = flowColumn(b);
      byCol.set(c, [...(byCol.get(c) ?? []), b]);
    }
    for (const c of FLOW_COLS) {
      const list = (byCol.get(c.key) ?? []).sort((a, b) => Number(b.via?.chapter != null) - Number(a.via?.chapter != null) || (a.via?.ts ?? 0) - (b.via?.ts ?? 0));
      const col = colEls.get(c.key)!;
      if (!list.length) col.append(el("div", "muted small flow-empty", "기록 없음"));
      for (const b of list.slice(0, PER_COL)) {
        const t = boxText(b);
        const box = el("button", `flow-box kind-${b.node.kind}${b.node.id === heroId ? " hero" : ""}${b.via?.chapter != null ? " chapter" : ""}${b.via?.chapter === 5 ? " destroy" : ""}${b.node.kind === "command" ? " command" : ""}`);
        box.type = "button";
        const titleEl = ext("span", t.title);
        titleEl.className = t.mono ? "flow-box-title path" : "flow-box-title";
        box.append(el("span", "flow-box-sub", t.sub), titleEl);
        const flag = b.node.kind === "remote" ? flagPath(b.where?.cc) : null;
        if (flag) {
          const img = el("img", "flag");
          img.src = flag;
          img.alt = "";
          box.prepend(img);
        }
        const fold = foldN.get(b.node.id);
        if (fold) box.append(el("span", "flow-box-sub", `접속 ${fold}곳 · 마인드맵에`));
        box.title = b.node.label || b.node.key;
        box.addEventListener("click", () => {
          for (const x of boxes.values()) x.classList.remove("selected");
          box.classList.add("selected");
          showSide(b);
        });
        boxes.set(b.node.id, box);
        col.append(box);
      }
      if (list.length > PER_COL) col.append(el("div", "muted small", `… 외 ${list.length - PER_COL}개 (마인드맵에서 전부)`));
    }
    if (r.result.truncated) map.append(el("p", "badge warn", `축약됨: 가지가 많아 ${r.result.cap}개까지만 — 전체 그림이 아닙니다`));
    const nid = (id: number) => alias.get(id) ?? id;
    links = [...best.values()].filter((b) => b.via).map((b) => ({ src: nid(b.via!.src), dst: nid(b.via!.dst), chapter: b.via!.chapter != null, destroy: b.via!.chapter === 5, eid: b.via!.id, rel: b.via!.rel })).filter((l) => l.src !== l.dst);
    // 처음 선택 = 주인공
    const hero = best.get(heroId) ?? [...best.values()].find((b) => b.depth === 0);
    if (hero) {
      showSide(hero);
      boxes.get(hero.node.id)?.classList.add("selected");
      // 제목 줄: 주인공 이름 · 시각 범위 · 선 수 · 근거 수
      const tsv = ev.sentences.map((x) => x.ts).filter((x) => x > 0 && filetimeToUnix(x) > 946684800).sort((a, c) => a - c);
      const span = tsv.length ? (tsv.length > 1 && tsv[0] !== tsv[tsv.length - 1] ? `${fmtShort(filetimeToUnix(tsv[0]!))} – ${fmtShort(filetimeToUnix(tsv[tsv.length - 1]!))}` : fmtShort(filetimeToUnix(tsv[0]!))) : "";
      const evn = new Set(ev.sentences.flatMap((x) => x.edge_ids)).size;
      titleRow.append(el("h3", "flow-title", ext("span", boxText(hero).title), " 에서 시작한 일"), el("span", "muted small", [span, `선 ${links.length}개`, `근거 ${evn}건`].filter(Boolean).join(" · ")));
    }
    map.append(legend);
    requestAnimationFrame(drawLines);
  };

  // 오늘 한 일 꼬리(아래): 이 사건의 사실 문장, 새 것이 위로
  const rows = [...ev.sentences].sort((a, b) => b.ts - a.ts).slice(0, 8);
  tail.append(el("h4", undefined, "오늘 한 일 — 이 사건 (새 줄이 위로)"));
  if (!rows.length) tail.append(el("p", "muted small", "기록 없음"));
  for (const s of rows) {
    // 시각 없는 문장(요약·속성 문장)은 "—" — 1601년·1970년 같은 가짜 시각을 보이지 않는다
    const when = s.ts > 0 && filetimeToUnix(s.ts) > 946684800 ? fmtShortSec(filetimeToUnix(s.ts)) : "—";
    const line = el("div", "flow-tail-row", el("span", "muted small time", when), ext("span", s.text));
    tail.append(line);
  }

  // 크기가 바뀌면 선을 다시 긋는다(창 폭·상세 패널). 움직임 장식은 없다
  const ro = new ResizeObserver(() => drawLines());
  ro.observe(map);
  root.addEventListener("screen-leave", () => ro.disconnect());
  requestAnimationFrame(() => void load());
  return root;
}
