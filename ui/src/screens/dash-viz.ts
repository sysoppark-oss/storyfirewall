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

/// 개편안 2판 1-4: 이중 축 그래프 — 왼쪽 트래픽(송신·수신 바이트, 반투명 면적), 오른쪽 인시던트 건수(세로 마커: 심각 빨강·높음 주황)
export interface DualInput {
  sent: number[];
  recv: number[];
  critical: number[];
  high: number[];
}
export function bytesAxis(v: number): string {
  if (v >= 1024 ** 3) return `${(v / 1024 ** 3).toFixed(1)}GB`;
  if (v >= 1024 ** 2) return `${(v / 1024 ** 2).toFixed(v >= 10 * 1024 ** 2 ? 0 : 1)}MB`;
  if (v >= 1024) return `${Math.round(v / 1024)}KB`;
  return `${Math.round(v)}B`;
}
export function dualChart(d: DualInput, nowHour: number, w = 520, h = 160): SVGElement {
  const L = 44, R = 30, T = 10, B = 22;
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", `0 0 ${w} ${h}`);
  s.setAttribute("class", "area-chart dual-chart");
  s.setAttribute("role", "img");
  s.setAttribute("aria-label", "트래픽(송신·수신)과 인시던트 24시간 추이");
  const maxB = Math.max(1, ...d.sent, ...d.recv);
  const maxI = Math.max(1, ...d.critical.map((c, i) => c + (d.high[i] ?? 0)));
  const x = (i: number) => L + (i / 23) * (w - L - R);
  const yB = (v: number) => T + (h - T - B) * (1 - v / maxB);
  const yI = (v: number) => T + (h - T - B) * (1 - v / maxI);
  const text = (tx: number, ty: number, anchor: string, label: string, cls = "ax") => {
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", tx.toFixed(1)); t.setAttribute("y", ty.toFixed(1));
    t.setAttribute("class", cls); t.setAttribute("text-anchor", anchor);
    t.textContent = label;
    return t;
  };
  for (const f of [0, 0.5, 1]) {
    const g = document.createElementNS(NS, "line");
    g.setAttribute("x1", String(L)); g.setAttribute("x2", String(w - R));
    g.setAttribute("y1", yB(maxB * f).toFixed(1)); g.setAttribute("y2", yB(maxB * f).toFixed(1));
    g.setAttribute("class", "grid");
    s.append(g, text(L - 4, yB(maxB * f) + 3, "end", bytesAxis(maxB * f)));
    // 오른쪽 축: 인시던트 건수(정수만)
    const iv = Math.round(maxI * f);
    if (f === 0 || iv > 0) s.append(text(w - R + 4, yI(iv) + 3, "start", String(iv), "ax ax-right"));
  }
  for (let hh = 0; hh <= 23; hh += 6) s.append(text(x(hh), h - 6, "middle", `${hh}시`));
  const last = Math.max(0, Math.min(23, nowHour));
  for (const [vals, cls] of [[d.recv, "s-recv"], [d.sent, "s-sent"]] as const) {
    const pts = vals.slice(0, last + 1).map((v, i) => `${x(i).toFixed(1)} ${yB(v).toFixed(1)}`);
    if (pts.length < 2) continue;
    const area = document.createElementNS(NS, "path");
    area.setAttribute("d", `M${pts[0]} L${pts.join(" L")} L${x(last).toFixed(1)} ${yB(0).toFixed(1)} L${x(0).toFixed(1)} ${yB(0).toFixed(1)} Z`);
    area.setAttribute("class", `area ${cls}`);
    const line = document.createElementNS(NS, "path");
    line.setAttribute("d", `M${pts[0]} L${pts.join(" L")}`);
    line.setAttribute("class", `line ${cls}`);
    s.append(area, line);
  }
  // 인시던트 마커: 높음 위에 심각을 쌓은 가는 기둥
  const bw = Math.max(3, (w - L - R) / 23 * 0.28);
  for (let i = 0; i <= last; i++) {
    const hi = d.high[i] ?? 0, cr = d.critical[i] ?? 0;
    if (!hi && !cr) continue;
    const mk = (from: number, to: number, cls: string) => {
      const r = document.createElementNS(NS, "rect");
      r.setAttribute("x", (x(i) - bw / 2).toFixed(1)); r.setAttribute("y", yI(to).toFixed(1));
      r.setAttribute("width", bw.toFixed(1)); r.setAttribute("height", Math.max(1, yI(from) - yI(to)).toFixed(1));
      r.setAttribute("rx", "1.5"); r.setAttribute("class", `mark ${cls}`);
      s.append(r);
    };
    if (hi) mk(0, hi, "m-high");
    if (cr) mk(hi, hi + cr, "m-crit");
  }
  const now = document.createElementNS(NS, "line");
  now.setAttribute("x1", x(last).toFixed(1)); now.setAttribute("x2", x(last).toFixed(1));
  now.setAttribute("y1", String(T)); now.setAttribute("y2", String(h - B));
  now.setAttribute("class", "now");
  s.append(now);
  for (let i = 0; i <= last; i++) {
    const r = document.createElementNS(NS, "rect");
    const half = (w - L - R) / 23 / 2;
    r.setAttribute("x", (x(i) - half).toFixed(1)); r.setAttribute("y", String(T));
    r.setAttribute("width", (half * 2).toFixed(1)); r.setAttribute("height", String(h - T - B));
    r.setAttribute("fill", "transparent");
    const title = document.createElementNS(NS, "title");
    title.textContent = `${i}시 · 송신 ${bytesAxis(d.sent[i] ?? 0)} · 수신 ${bytesAxis(d.recv[i] ?? 0)} · 심각 ${d.critical[i] ?? 0} · 높음 ${d.high[i] ?? 0}`;
    r.append(title);
    s.append(r);
  }
  return s;
}

/// 사용자 2026-11-07 "다른 그래프로": 시간대별 막대 — 수신 위에 송신을 쌓고(왼쪽 축 바이트), 인시던트는 막대 위 점(심각 진홍·높음 주황).
/// 한 시간에 몰린 자료도 면적 선과 달리 막대 하나로 또렷이 보인다
export function barChart(d: DualInput, nowHour: number, w = 520, h = 160): SVGElement {
  const L = 44, R = 8, T = 14, B = 22;
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", `0 0 ${w} ${h}`);
  s.setAttribute("class", "area-chart bar-chart");
  s.setAttribute("role", "img");
  s.setAttribute("aria-label", "시간대별 트래픽(송신·수신)과 인시던트");
  const maxB = Math.max(1, ...d.sent.map((v, i) => v + (d.recv[i] ?? 0)));
  const slot = (w - L - R) / 24;
  const bw = slot * 0.62;
  const x = (i: number) => L + i * slot + (slot - bw) / 2;
  const yB = (v: number) => T + (h - T - B) * (1 - v / maxB);
  const text = (tx: number, ty: number, anchor: string, label: string, cls = "ax") => {
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", tx.toFixed(1)); t.setAttribute("y", ty.toFixed(1));
    t.setAttribute("class", cls); t.setAttribute("text-anchor", anchor);
    t.textContent = label;
    return t;
  };
  for (const f of [0, 0.5, 1]) {
    const g = document.createElementNS(NS, "line");
    g.setAttribute("x1", String(L)); g.setAttribute("x2", String(w - R));
    g.setAttribute("y1", yB(maxB * f).toFixed(1)); g.setAttribute("y2", yB(maxB * f).toFixed(1));
    g.setAttribute("class", "grid");
    s.append(g, text(L - 4, yB(maxB * f) + 3, "end", bytesAxis(maxB * f)));
  }
  for (let hh = 0; hh <= 23; hh += 6) s.append(text(x(hh) + bw / 2, h - 6, "middle", `${hh}시`));
  const last = Math.max(0, Math.min(23, nowHour));
  const rect = (rx: number, ry: number, rw: number, rh: number, cls: string) => {
    const r = document.createElementNS(NS, "rect");
    r.setAttribute("x", rx.toFixed(1)); r.setAttribute("y", ry.toFixed(1));
    r.setAttribute("width", rw.toFixed(1)); r.setAttribute("height", Math.max(0, rh).toFixed(1));
    r.setAttribute("rx", "2"); r.setAttribute("class", cls);
    return r;
  };
  for (let i = 0; i <= last; i++) {
    const rv = d.recv[i] ?? 0, sn = d.sent[i] ?? 0;
    if (rv) s.append(rect(x(i), yB(rv), bw, yB(0) - yB(rv), "bar b-recv"));
    if (sn) s.append(rect(x(i), yB(rv + sn), bw, yB(rv) - yB(rv + sn), "bar b-sent"));
    if (!rv && !sn) s.append(rect(x(i), yB(0) - 1.5, bw, 1.5, "bar b-empty"));
    // 인시던트 점: 막대 위, 높음 → 심각 순으로 쌓아 올림(최대 4개씩)
    const hi = d.high[i] ?? 0, cr = d.critical[i] ?? 0;
    let top = yB(rv + sn) - 6;
    for (const [n, cls] of [[hi, "m-high"], [cr, "m-crit"]] as const) {
      for (let k = 0; k < Math.min(n, 4); k++) {
        const c = document.createElementNS(NS, "circle");
        c.setAttribute("cx", (x(i) + bw / 2).toFixed(1)); c.setAttribute("cy", top.toFixed(1)); c.setAttribute("r", "3");
        c.setAttribute("class", `mark ${cls}`);
        s.append(c);
        top -= 7;
      }
    }
    const hit = rect(L + i * slot, T, slot, h - T - B, "hit");
    const title = document.createElementNS(NS, "title");
    title.textContent = `${i}시 · 송신 ${bytesAxis(sn)} · 수신 ${bytesAxis(rv)} · 심각 ${cr} · 높음 ${hi}`;
    hit.append(title);
    s.append(hit);
  }
  return s;
}
