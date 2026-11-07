// 대시보드 시각 요소(2026-11-07, 사용자 "대시보드 UI가 이 정도는 돼야"): 숫자 카드의 아이콘·색조·스파크라인, 24시간 영역 그래프.
// 숫자는 만들지 않는다 — 받은 배열을 그릴 뿐. 색은 의미에만(의심=빨강, 주의=주황, 정상=초록, 정보=브랜드).

const NS = "http://www.w3.org/2000/svg";

export type Tone = "bad" | "warn" | "ok" | "info" | "neutral";

/** 아이콘 이름 → path (24×24, stroke 기준) */
const ICONS: Record<string, string> = {
  shield: "M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zm-9 9h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
  swap: "M4 8h13l-3-3M20 16H7l3 3",
  door: "M5 4h10v16H5zM15 12h4M17 10l2 2-2 2",
  list: "M5 7h14M5 12h14M5 17h9",
  heart: "M12 20s-7-4.5-7-10a4 4 0 0 1 7-2.5A4 4 0 0 1 19 10c0 5.5-7 10-7 10z",
  eye: "M2 12s4-6 10-6 10 6 10 6-4 6-10 6-10-6-10-6zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
};

export function icon(name: string): SVGElement {
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("class", "kpi-icon");
  s.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(NS, "path");
  p.setAttribute("d", ICONS[name] ?? ICONS["list"]!);
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", "1.8");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  s.append(p);
  return s;
}

/** 작은 추세선(카드 아래). 값이 모두 0이면 바닥 선만 */
export function sparkline(values: number[], w = 120, h = 28): SVGElement {
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", `0 0 ${w} ${h}`);
  s.setAttribute("class", "spark");
  s.setAttribute("aria-hidden", "true");
  const max = Math.max(1, ...values);
  const n = Math.max(1, values.length - 1);
  const pts = values.map((v, i) => [(i / n) * w, h - 2 - (v / max) * (h - 6)] as const);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const area = document.createElementNS(NS, "path");
  area.setAttribute("d", `${line} L${w} ${h} L0 ${h} Z`);
  area.setAttribute("class", "spark-area");
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", line);
  path.setAttribute("class", "spark-line");
  s.append(area, path);
  return s;
}

export interface AreaSeries {
  name: string;
  values: number[];
  cls: string;
}

/**
 * 24시간 영역 그래프(겹침). x = 시(0~23), 지금 시각까지 실선·그 뒤는 비움. 툴팁은 title 로.
 * 최댓값 눈금 2개(0·max). 숫자가 전부 0이면 "기록 없음" 문구를 만든 쪽이 붙인다.
 */
/// 축 눈금 숫자: 만 단위로 줄인다(124706 → "12.5만"). 왼쪽 여백이 잘리지 않게
export function axisNum(v: number): string {
  if (v >= 10_000) return `${(v / 10_000).toFixed(v >= 100_000 ? 0 : 1)}만`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(1)}천`;
  return String(Math.round(v));
}

export function areaChart(series: AreaSeries[], nowHour: number, w = 720, h = 160): SVGElement {
  const L = 40, R = 8, T = 10, B = 22;
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", `0 0 ${w} ${h}`);
  s.setAttribute("class", "area-chart");
  s.setAttribute("role", "img");
  s.setAttribute("aria-label", series.map((x) => x.name).join(" · ") + " 24시간 추이");
  const max = Math.max(1, ...series.flatMap((x) => x.values));
  const x = (i: number) => L + (i / 23) * (w - L - R);
  const y = (v: number) => T + (h - T - B) * (1 - v / max);
  for (const v of [0, max / 2, max]) {
    const g = document.createElementNS(NS, "line");
    g.setAttribute("x1", String(L)); g.setAttribute("x2", String(w - R));
    g.setAttribute("y1", y(v).toFixed(1)); g.setAttribute("y2", y(v).toFixed(1));
    g.setAttribute("class", "grid");
    s.append(g);
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", String(L - 4)); t.setAttribute("y", (y(v) + 3).toFixed(1));
    t.setAttribute("class", "ax"); t.setAttribute("text-anchor", "end");
    t.textContent = axisNum(v);
    s.append(t);
  }
  for (let hh = 0; hh <= 23; hh += 6) {
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", x(hh).toFixed(1)); t.setAttribute("y", String(h - 6));
    t.setAttribute("class", "ax"); t.setAttribute("text-anchor", "middle");
    t.textContent = `${hh}시`;
    s.append(t);
  }
  const last = Math.max(0, Math.min(23, nowHour));
  for (const se of series) {
    const pts = se.values.slice(0, last + 1).map((v, i) => `${x(i).toFixed(1)} ${y(v).toFixed(1)}`);
    if (pts.length < 2) continue;
    const area = document.createElementNS(NS, "path");
    area.setAttribute("d", `M${pts[0]} L${pts.join(" L")} L${x(last).toFixed(1)} ${y(0).toFixed(1)} L${x(0).toFixed(1)} ${y(0).toFixed(1)} Z`);
    area.setAttribute("class", `area ${se.cls}`);
    const line = document.createElementNS(NS, "path");
    line.setAttribute("d", `M${pts[0]} L${pts.join(" L")}`);
    line.setAttribute("class", `line ${se.cls}`);
    s.append(area, line);
  }
  // 지금 시각 표시
  const now = document.createElementNS(NS, "line");
  now.setAttribute("x1", x(last).toFixed(1)); now.setAttribute("x2", x(last).toFixed(1));
  now.setAttribute("y1", String(T)); now.setAttribute("y2", String(h - B));
  now.setAttribute("class", "now");
  s.append(now);
  // 시각별 툴팁(투명 기둥)
  for (let i = 0; i <= last; i++) {
    const r = document.createElementNS(NS, "rect");
    const half = (w - L - R) / 23 / 2;
    r.setAttribute("x", (x(i) - half).toFixed(1)); r.setAttribute("y", String(T));
    r.setAttribute("width", (half * 2).toFixed(1)); r.setAttribute("height", String(h - T - B));
    r.setAttribute("fill", "transparent");
    const title = document.createElementNS(NS, "title");
    title.textContent = `${i}시 · ` + series.map((se) => `${se.name} ${se.values[i] ?? 0}`).join(" · ");
    r.append(title);
    s.append(r);
  }
  return s;
}

/** 의심 사건의 마지막 활동 시각(unix 초)을 오늘 시간대별로 센다 */
export function hourlyCounts(tsList: number[], nowSec: number): number[] {
  const out = new Array<number>(24).fill(0);
  const d = new Date(nowSec * 1000);
  d.setHours(0, 0, 0, 0);
  const dayStart = d.getTime() / 1000;
  for (const t of tsList) {
    if (t >= dayStart && t <= nowSec + 60) out[new Date(t * 1000).getHours()]! += 1;
  }
  return out;
}

/** 수준별 도넛: 의심·주의·평범 비율. 가운데 숫자는 처리 안 한 사건 수. 0이면 테두리 원만 */
export function donut(parts: { label: string; value: number; cls: string }[], center: string, sub: string, size = 120): SVGElement {
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", `0 0 ${size} ${size}`);
  s.setAttribute("class", "donut");
  s.setAttribute("role", "img");
  s.setAttribute("aria-label", parts.map((p) => `${p.label} ${p.value}`).join(" · "));
  const r = size / 2 - 10, cx = size / 2, cy = size / 2, circ = 2 * Math.PI * r;
  const total = parts.reduce((a, p) => a + p.value, 0);
  const ring = document.createElementNS(NS, "circle");
  ring.setAttribute("cx", String(cx)); ring.setAttribute("cy", String(cy)); ring.setAttribute("r", String(r));
  ring.setAttribute("class", "donut-ring");
  s.append(ring);
  let off = 0;
  for (const p of parts) {
    if (!p.value || !total) continue;
    const len = (p.value / total) * circ;
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("cx", String(cx)); c.setAttribute("cy", String(cy)); c.setAttribute("r", String(r));
    c.setAttribute("class", `donut-seg ${p.cls}`);
    c.setAttribute("stroke-dasharray", `${len.toFixed(2)} ${(circ - len).toFixed(2)}`);
    c.setAttribute("stroke-dashoffset", (-off).toFixed(2));
    c.setAttribute("transform", `rotate(-90 ${cx} ${cy})`);
    const t = document.createElementNS(NS, "title");
    t.textContent = `${p.label} ${p.value}건`;
    c.append(t);
    s.append(c);
    off += len;
  }
  const big = document.createElementNS(NS, "text");
  big.setAttribute("x", String(cx)); big.setAttribute("y", String(cy + 2));
  big.setAttribute("class", "donut-big"); big.setAttribute("text-anchor", "middle");
  big.textContent = center;
  const small = document.createElementNS(NS, "text");
  small.setAttribute("x", String(cx)); small.setAttribute("y", String(cy + 18));
  small.setAttribute("class", "donut-sub"); small.setAttribute("text-anchor", "middle");
  small.textContent = sub;
  s.append(big, small);
  return s;
}

/** 4장 흐름 띠의 재료: 오늘 사건이 각 장까지 도달한 수(사건 하나는 도달한 모든 장에 들어간다) */
export function chapterReach(reached: number[][]): number[] {
  const out = [0, 0, 0, 0];
  for (const r of reached) for (const ch of r) if (ch >= 1 && ch <= 4) out[ch - 1]! += 1;
  return out;
}
