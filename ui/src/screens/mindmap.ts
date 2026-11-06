// 마인드맵 (A21): 주인공 기준 투영. 왼쪽 = 어디서 왔나(origin), 오른쪽 = 무엇을 했나(action).
// 그래프는 그물(DAG)이므로 이미 나온 노드로 가는 가지는 선만 잇는다(seen). 모든 선은 근거로 이어진다("왜?").
// 외부 문자열(파일명·도메인)은 sanitize 후 라벨에 넣는다 — Cytoscape 는 캔버스에 그리므로 HTML 주입은 없지만
// 양방향·폭0 문자 위장은 그대로 보이므로 지운다.
import { flagPath, placeName, type Where } from "./connections";
import cytoscape from "cytoscape";
import { isNewToday } from "./conn-group";
import { rpc } from "../rpc";
import { el, clear, errorBox, fmtTs, filetimeToUnix, ext, button } from "../ui";
import { sanitize } from "../sanitize";
import { processPanel } from "./process";

const SCOPE_SHORT: Record<string, string> = { loopback: "이 PC", private: "로컬망", link_local: "로컬망", multicast: "멀티캐스트", broadcast: "브로드캐스트", cgnat: "통신사 NAT" };
export interface NodeJ {
  id: number;
  kind: string;
  key: string;
  label: string;
}
export interface EdgeJ {
  id: number;
  src: number;
  dst: number;
  rel: string;
  ts: number;
  chapter: number | null;
}
export interface Branch {
  depth: number;
  node: NodeJ;
  via: EdgeJ | null;
  side: "origin" | "action";
  seen: boolean;
  where?: Where;
  /// D012: 오늘 처음 본 ASN·나라(서비스가 계산)
  new_asn?: boolean;
  new_cc?: boolean;
}

/// 선 글자 사전 — 그래프의 관계 이름 전부(crates/graph Rel)에 한국어가 있어야 한다(D044-1, 시험)
export const REL: Record<string, string> = {
  spawned: "실행",
  wrote: "만듦",
  downloaded: "받음",
  connected: "접속",
  resolved: "조회",
  registered: "자동 실행 등록",
  injected: "주입",
  executed_as: "실행됨",
  connected_via: "대신 접속",
  // 10판 5-9 (1): 프로세스 → 명령줄
  ran: "실행",
  // 17판 23-2 ②: 프로세스 → 브라우저 금고·미끼 파일
  opened: "열기",
};

/// D011: Cytoscape 는 CSS 변수를 직접 못 읽는다 — 그릴 때 토큰 값을 읽어 스타일을 만들고, 테마가 바뀌면 다시 적용한다
function tok(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "gray";
}
/// D016: 화면 맞춤 확대 상한
export const FIT_MAX_ZOOM = 1.0;
function mmStyle(): cytoscape.StylesheetJson {
  const muted = tok("--muted"), bad = tok("--bad"), warn = tok("--warn"), card = tok("--card"), line = tok("--line");
  return [
    { selector: "node", style: { label: "data(label)", "font-size": 13, "text-valign": "bottom", "text-margin-y": 4, color: muted, "background-color": tok("--mm-node"), width: 18, height: 18 } },
    { selector: "node.process", style: { "background-color": tok("--mm-proc"), shape: "ellipse" } },
    // D006-6: 파일 노드는 프로세스와 헷갈리지 않게 회색 둥근 사각형(라벨 앞 "파일 ")
    { selector: "node.file", style: { "background-color": tok("--mm-file"), shape: "round-rectangle", width: 22, height: 16 } },
    // D012: 접속지 기본색은 청록(--mm-domain). 주황(--warn)은 "주의·오늘 처음" 뜻이라 쓰지 않는다
    { selector: "node.remote", style: { "background-color": tok("--mm-domain"), shape: "diamond", "text-wrap": "wrap" } },
    // 나라 국기를 접속지 마름모 안에 (앱 안의 SVG, CSP self)
    // D018: 국기가 늦게 오거나 실패해도 빈 칸이 아니게 — 연한 접속지 색 채움(불투명도 0.25) 위에 국기
    { selector: "node.remote[flag != '']", style: { "background-image": "data(flag)", "background-fit": "contain", "background-clip": "node", "background-color": tok("--mm-domain"), "background-opacity": 0.25, "background-image-opacity": 1, "border-width": 2, "border-color": tok("--mm-domain"), width: 26, height: 26 } },
    { selector: "node.domain", style: { "background-color": tok("--mm-domain"), shape: "hexagon" } },
    { selector: "node.autorun", style: { "background-color": bad, shape: "star" } },
    // D043-4: 빨강 채움은 판정 수준·4장 근거 선 뜻으로 이미 쓴다 — 카드색 채움 + 빨간 테두리, 고정폭 글자
    // D044-2: 글자가 둥근 사각형 안(노드 폭 = 글자 폭 + 여백), 고정폭, 카드색 + 빨간 테두리
    { selector: "node.command", style: { "background-color": card, "border-width": 2, "border-color": bad, shape: "round-rectangle", width: "label", height: "label", padding: "6px", "text-valign": "center", "text-halign": "center", "text-margin-y": 0, color: tok("--fg"), "font-family": "Consolas, 'Cascadia Mono', monospace", "font-size": 12 } },
    // D007-5: 주인공이 아닌 노드의 접은 접속 배지 — 누르면 그 노드 기준으로 펼친다
    { selector: "node.badge", style: { shape: "round-rectangle", "background-color": line, "border-width": 1, "border-color": muted, width: 54, height: 16, label: "data(label)", "text-valign": "center", "text-margin-y": 0, color: tok("--fg"), "font-size": 11 } },
    { selector: "node.center", style: { width: 30, height: 30, "border-width": 3, "border-color": tok("--mm-center"), "font-weight": "bold", color: tok("--fg") } },
    // D012: 오늘 처음 접속지만 주황 테두리
    { selector: "node.remote.newtoday", style: { "border-width": 3, "border-color": warn } },
    { selector: "node.spoof", style: { "border-width": 2, "border-style": "dashed", "border-color": warn } },
    // D003-6: 선 글자는 기본 숨김 — 마우스를 올린 선과 빨간(4장) 경로 선만 보인다
    { selector: "edge", style: { width: 1.5, "line-color": tok("--mm-edge"), "target-arrow-color": tok("--mm-edge"), "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)", "font-size": 11, color: muted, "text-rotation": "autorotate", "text-opacity": 0,
      // D012: 선 글자 바탕을 카드색으로 깔아 다크에서도 읽히게
      "text-background-color": card, "text-background-opacity": 1, "text-background-padding": "2px" } },
    { selector: "edge.chapter", style: { "line-color": bad, "target-arrow-color": bad, width: 2.5, color: bad, "text-opacity": 1 } },
    { selector: "edge.hover", style: { "text-opacity": 1, width: 2.5 } },
    { selector: "edge.seen", style: { "line-style": "dashed" } },
    { selector: ":selected", style: { "overlay-opacity": 0.15 } },
  ];
}

/// "host:port" / "[v6]:port" → host(소문자). 포트가 없으면 전체
export function hostOf(label: string): string {
  const m = /^\[([^\]]+)\]:(\d+)$/.exec(label) ?? /^([^:]+):(\d+)$/.exec(label);
  return (m?.[1] ?? label).toLowerCase();
}
export function portOf(label: string): string {
  const m = /:(\d+)$/.exec(label);
  return m && (label.startsWith("[") || label.split(":").length === 2) ? (m[1] ?? "") : "";
}

/// Cytoscape 는 처음 그릴 때 <style id="__________cytoscape_stylesheet"> 를 head 에 끼워 넣는다 → CSP style-src 'self' 위반
/// (A22 실제 WebView2 에서 발견). 같은 id 의 요소가 이미 있으면 넣지 않으므로 빈 자리표를 미리 두고,
/// 그 규칙(.__________cytoscape_container { position: relative })은 style.css 에 둔다. 'unsafe-inline' 을 다시 열지 않는다.
function preventCytoscapeInlineStyle() {
  const id = "__________cytoscape_stylesheet";
  if (!document.getElementById(id)) {
    const m = document.createElement("meta");
    m.id = id;
    document.head.append(m);
  }
}

/// 주인공 노드 id 로 마인드맵 패널을 만든다
export function mindmap(center: number): HTMLElement {
  preventCytoscapeInlineStyle();
  const root = el("div", "card mindmap");
  const head = el("div", "toolbar");
  const depthSel = el("select");
  for (const d of [2, 3, 4, 6]) {
    const o = el("option", undefined, `깊이 ${d}`);
    o.value = String(d);
    if (d === 3) o.selected = true;
    depthSel.append(o);
  }
  const note = el("span", "muted");
  head.append("마인드맵 ", depthSel, " ", note);
  const canvas = el("div", "cy");
  // D003-6: 안내문은 그래프 위 한 줄, 오른쪽 칸은 무언가 눌렀을 때만 연다(그래프를 넓게)
  const hint = el("p", "muted mm-hint", "프로세스를 누르면 상세가, 선을 누르면 근거가 나옵니다.");
  // D006-6: 범례 한 줄
  const legend = el("p", "mm-legend", "● 프로그램  ▢ 파일  ◆ 접속지  ★ 자동 실행  ▭ 명령줄 — 빨간 선 = 판정 근거");
  const side = el("div", "cy-side");
  const wrap = el("div", "cy-wrap", canvas, side);
  const openSide = () => wrap.classList.add("has-side");
  root.append(head, hint, legend, wrap);
  let cy: cytoscape.Core | undefined;

  const explain = async (edgeId: number) => {
    clear(side);
    openSide();
    const r = await rpc<{ evidence: { id: number; ts: number; source: string; payload_json?: string; kind?: string; detail?: string }[] }>("story.explain", { edge_id: edgeId });
    if (!r.ok) return side.append(errorBox(r.error.message));
    side.append(el("h4", undefined, "근거"));
    for (const e of r.result.evidence) side.append(el("div", "evidence", `${fmtTs(filetimeToUnix(e.ts))} [${e.source}] `, ext("span", e.kind ?? e.payload_json ?? "")));
  };

  // 지금 기준 노드(배지를 누르면 바뀐다). 처음은 사건의 뿌리
  let current = center;
  const back = button("주인공으로 돌아가기", () => { current = center; back.hidden = true; void load(); }, "btn small");
  back.hidden = true;
  head.append(" ", back);
  const load = async () => {
    const r = await rpc<{ branches: Branch[]; truncated: boolean; cap: number }>("graph.neighbors", { node_id: current, max_depth: Number(depthSel.value) });
    if (!r.ok) {
      clear(canvas);
      canvas.append(errorBox(`graph.neighbors: ${r.error.message}`));
      return;
    }
    note.textContent = r.result.truncated ? `축약됨: 가지가 많아 ${r.result.cap}개까지만, 4장 판정 선을 먼저 표시했습니다 — 전체 그림이 아닙니다` : "";
    note.className = r.result.truncated ? "badge warn" : "muted";
    // D003-6: 같은 접속지의 "도메인" 노드와 "도메인:포트" 노드를 하나로 — 도메인 노드의 선은 접속지 노드로 옮긴다
    const remoteByHost = new Map<string, number>();
    for (const b of r.result.branches) {
      if (b.node.kind !== "remote") continue;
      const host = hostOf(b.node.label || b.node.key);
      if (host && !remoteByHost.has(host)) remoteByHost.set(host, b.node.id);
    }
    const alias = new Map<number, number>(); // 도메인 노드 id → 접속지 노드 id
    for (const b of r.result.branches) {
      if (b.node.kind === "domain") {
        const to = remoteByHost.get((b.node.label || b.node.key).toLowerCase());
        if (to != null) alias.set(b.node.id, to);
      }
    }
    const nid = (id: number) => alias.get(id) ?? id;
    // 같은 노드가 양쪽에 나오면(예: 주입 관계로 조상이자 대상) 가장 얕은 자리 하나에만 그린다. 같은 깊이면 오른쪽(한 일) 우선
    const rank = (b: Branch) => b.depth * 2 + (b.side === "origin" ? 1 : 0);
    const best = new Map<number, Branch>();
    for (const b of r.result.branches) {
      const cur = best.get(b.node.id);
      if (!cur || rank(b) < rank(cur)) best.set(b.node.id, b);
    }
    // 조상 쪽의 "실행 파일" 노드(4장 판정 근거 아님)는 그리지 않는다 — 같은 이름이 두 번 보이는 혼동(D006-6)
    const hidden = (b: Branch) => b.side === "origin" && b.node.kind === "file" && b.via?.rel === "executed_as" && b.via.chapter == null;
    // D007-4: 주인공 = 프로세스. 뿌리가 파일이면 그 파일로 실행된 첫 프로세스(오른쪽 깊이 1)를 주인공으로 강조한다
    const centerB = r.result.branches.find((b) => b.depth === 0);
    let hero = current;
    if (centerB?.node.kind === "file") {
      const p = r.result.branches.find((b) => b.side === "action" && b.depth === 1 && b.node.kind === "process" && b.via?.rel === "executed_as");
      if (p) hero = p.node.id;
    }
    // D007-5: 접속지 열에는 주인공의 접속만. 다른 노드의 접속은 그 노드 옆 "접속 N" 배지로 접는다. 4장 근거(빨간 선)는 늘 펼침
    const isTarget = (b: Branch) => b.node.kind === "remote" || b.node.kind === "domain";
    const keep = new Set<number>();
    const ownerOf = new Map<number, number>();
    for (const b of r.result.branches) {
      if (!isTarget(b) || !b.via) continue;
      const id = nid(b.node.id);
      if (b.via.src === hero || b.via.chapter != null) keep.add(id);
      else if (!ownerOf.has(id)) ownerOf.set(id, b.via.src);
    }
    const folded = (b: Branch) => isTarget(b) && !keep.has(nid(b.node.id)) && ownerOf.has(nid(b.node.id));
    const foldCount = new Map<number, number>();
    for (const [id, owner] of ownerOf) if (!keep.has(id) && !alias.has(id)) foldCount.set(owner, (foldCount.get(owner) ?? 0) + 1);
    const branches = r.result.branches.filter((b) => !hidden(b) && !folded(b));
    // D006-6 열 배치: 조상(왼쪽, 깊이만큼) → 주인공 → 주인공이 만든 것(파일·자식·자동 실행, 깊이만큼) → 접속지(맨 오른쪽 한 열).
    // 열 간격 200px, 같은 열 안에서는 위아래로 고르게
    const COL = 200;
    const ROW = 64;
    const maxActDepth = Math.max(0, ...[...best.values()].filter((b) => b.side === "action" && b.node.kind !== "remote" && b.node.kind !== "domain").map((b) => b.depth));
    const colOf = (b: Branch): number => {
      if (b.depth === 0) return 0;
      if (b.side === "origin") return -b.depth;
      if (b.node.kind === "remote" || b.node.kind === "domain") return maxActDepth + 1;
      return b.depth;
    };
    const colCount = new Map<number, number>();
    for (const b of best.values()) if (!alias.has(b.node.id) && !hidden(b) && !folded(b)) colCount.set(colOf(b), (colCount.get(colOf(b)) ?? 0) + 1);
    const slots = new Map<string, number>();
    const nodes = new Map<number, cytoscape.ElementDefinition>();
    const edges: cytoscape.ElementDefinition[] = [];
    for (const b of branches) {
      if (!alias.has(b.node.id) && !nodes.has(b.node.id) && best.get(b.node.id) === b) {
        const col = colOf(b);
        const k = String(col);
        const i = slots.get(k) ?? 0;
        slots.set(k, i + 1);
        // 자동 실행 노드: key=위치(레지스트리 값·작업 이름), label=대상 경로 → 위치의 마지막 이름이 더 짧고 뜻이 분명하다
        const full = b.node.kind === "autorun" ? (b.node.key.split(/[\\/]/).pop() ?? b.node.key) : b.node.label || b.node.key;
        // 접속지: 첫 줄 = 호스트, 둘째 줄 = 포트 · 나라(또는 로컬망 등). 국기는 꾸밈이 아니라 한눈에 "어디"를 보이려는 것
        const port = b.node.kind === "remote" ? portOf(full) : "";
        const raw = b.node.kind === "remote" ? hostOf(full) || full : full;
        // D043-4: 명령줄은 40자 말줄임(툴팁에 전체)
        const s = sanitize(raw, b.node.kind === "command" ? 40 : 28);
        // D006-6: 파일·자동 실행은 무엇인지 글자로도 밝힌다(같은 이름의 프로세스와 구분)
        const prefix = b.node.kind === "file" ? "파일 " : b.node.kind === "autorun" ? "시작 프로그램: " : "";
        const w = b.where;
        const place = w ? (placeName(w) ?? (w.scope === "public" ? "" : SCOPE_SHORT[w.scope] ?? "")) : "";
        const whereLine = [port, place].filter(Boolean).join(" · ");
        const flag = flagPath(w?.cc) ?? "";
        const x = col * COL;
        const n = colCount.get(col) ?? 1;
        const y = (i - (n - 1) / 2) * ROW;
        nodes.set(b.node.id, {
          data: { id: `n${b.node.id}`, nid: b.node.id, kind: b.node.kind, label: whereLine ? `${prefix}${s.text}\n${whereLine}` : `${prefix}${s.text}`, flag },
          position: { x, y },
          classes: [b.node.kind, b.node.id === hero ? "center" : "", s.spoofRisk ? "spoof" : "", isNewToday(b) ? "newtoday" : ""].join(" "),
        });
      }
      if (b.via) {
        const e = b.via;
        edges.push({
          data: { id: `e${e.id}`, eid: e.id, source: `n${nid(e.src)}`, target: `n${nid(e.dst)}`, label: REL[e.rel] ?? e.rel },
          classes: [e.chapter != null ? "chapter" : "", b.seen ? "seen" : ""].join(" "),
        });
      }
    }
    // 같은 선이 양쪽 펼침에 두 번 나올 수 있다
    for (const [owner, n] of foldCount) {
      const o = nodes.get(owner);
      if (!o?.position) continue;
      nodes.set(-owner, {
        data: { id: `b${owner}`, badgeOf: owner, label: `접속 ${n} ▸` },
        position: { x: o.position.x + 60, y: o.position.y - 16 },
        classes: "badge",
      });
    }
    const have = new Set([...nodes.values()].map((n) => n.data.id as string));
    const uniq = new Map(edges.filter((e) => have.has(e.data.source as string) && have.has(e.data.target as string)).map((e) => [e.data.id as string, e]));
    // D018: 이 그림이 쓰는 국기 경로(앱 안 정적 파일) — 캡처 시험이 다 읽힐 때까지 기다리는 데 쓴다
    canvas.dataset["flags"] = JSON.stringify([...new Set([...nodes.values()].map((n) => n.data["flag"] as string).filter((f) => !!f))]);
    // D018: 축소(1배 이하)일 때 Cytoscape 는 노드를 미리 그린 그림(텍스처)으로 그린다 — 그 그림이 국기를 읽기 전에 만들어지면
    // 국기가 빠진다. 그래프를 만들기 전에 국기를 먼저 읽어 둔다(최대 1.5초, 실패해도 채움만 남는다)
    const flagUrls = JSON.parse(canvas.dataset["flags"] ?? "[]") as string[];
    await Promise.race([
      Promise.all(flagUrls.map((u) => new Promise((r) => { const i = new Image(); i.onload = i.onerror = () => r(null); i.src = u; }))),
      new Promise((r) => setTimeout(r, 1500)),
    ]);
    cy?.destroy();
    cy = cytoscape({
      container: canvas,
      elements: [...nodes.values(), ...uniq.values()],
      style: mmStyle(),
      layout: { name: "preset", fit: true, padding: 30 },
      wheelSensitivity: 0.3,
      minZoom: 0.2,
      // D016: 화면 맞춤은 1배를 넘지 않게(노드가 적으면 글자가 26px 까지 커졌다) — 맞춤이 이 상한을 지키며 가운데 둔다.
      // 그린 뒤 휠 확대 상한을 2배로 푼다(맞춤 뒤 zoom() 을 직접 바꾸면 국기 그림이 빠지는 일이 있었다 — D018)
      maxZoom: FIT_MAX_ZOOM,
    });
    cy.ready(() => cy?.maxZoom(2));
    cy.on("tap", "node.badge", (ev) => {
      current = (ev.target.data() as { badgeOf: number }).badgeOf;
      back.hidden = current === center;
      void load();
    });
    cy.on("tap", "node[nid]", (ev) => {
      const d = ev.target.data() as { nid: number; kind: string };
      clear(side);
      openSide();
      if (d.kind === "process") side.append(processPanel(d.nid));
      else side.append(el("p", "muted", "프로세스를 누르면 상세가, 선을 누르면 근거가 나옵니다."));
    });
    cy.on("tap", "edge", (ev) => void explain((ev.target.data() as { eid: number }).eid));
    // D011: 테마가 바뀌면(Windows 설정 또는 설정 화면) 토큰을 다시 읽어 적용
    const retheme = () => { cy?.style(mmStyle()); };
    window.addEventListener("sf-theme", retheme);
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", retheme);
    root.addEventListener("screen-leave", () => window.removeEventListener("sf-theme", retheme));
    cy.on("mouseover", "edge", (ev) => ev.target.addClass("hover"));
    cy.on("mouseout", "edge", (ev) => ev.target.removeClass("hover"));
    // D003-6: 화면에서 노드 글자 최소 11px — 맞춤 확대율이 작아지면 글자 크기를 그만큼 키운다
    const keepReadable = () => {
      const z = cy!.zoom();
      cy!.nodes().style("font-size", Math.max(13, 11 / z));
      cy!.edges().style("font-size", Math.max(11, 11 / z));
    };
    keepReadable();
    cy.on("zoom", keepReadable);
  };
  depthSel.addEventListener("change", () => void load());
  // DOM 에 붙은 뒤 그려야 크기를 안다
  requestAnimationFrame(() => void load());
  root.addEventListener("screen-leave", () => cy?.destroy());
  return root;
}
