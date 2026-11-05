// A3 지도(사용자 요청 2026-11-03, 화면 규칙 D009): 나라별 접속 수를 나라 색으로. 오프라인(앱에 넣은 Natural Earth 국경), 타일·외부 통신 없음.
// 점·도시 표시는 하지 않는다 — IP 위치 정보는 서버 위치와 다를 수 있다. 예외: 화면에서 6x6px 보다 작은 나라에 접속이 있으면 그 나라 중심에 작은 원(D009-4).
import { MAP_H, MAP_W, WORLD } from "../worldmap-data";

const NS = "http://www.w3.org/2000/svg";
/// 경계 상자 면적이 이보다 작으면(지도 좌표, 약 6x6px) 작은 나라 원을 그린다
const SMALL_AREA = 25;

export interface CountryCount {
  cc: string;
  label: string;
  value: number;
  isNew: boolean;
}

/// 접속 수 → 색 단계(D009-2 고정 구간): 0 / 1 / 2–5 / 6–20 / 21 이상
export function level(v: number): number {
  if (v <= 0) return 0;
  if (v === 1) return 1;
  if (v <= 5) return 2;
  if (v <= 20) return 3;
  return 4;
}

export function worldMap(counts: CountryCount[], selected: string | null, onPick: (cc: string) => void): SVGSVGElement {
  const by = new Map(counts.map((c) => [c.cc, c]));
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${MAP_W} ${MAP_H}`);
  svg.setAttribute("class", "worldmap");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "나라별 접속 수 지도");
  const dots: SVGElement[] = [];
  for (const [cc, d, cx, cy, area] of WORLD) {
    const c = by.get(cc);
    const cls = [`lv${c ? level(c.value) : 0}`];
    if (c?.isNew) cls.push("is-new");
    if (selected === cc) cls.push("on");
    if (c) cls.push("has");
    // 외부 문자열(국가 이름)은 텍스트 노드로
    const tip = c ? `${c.label} · 접속 ${c.value}${c.isNew ? " · 오늘 처음" : ""}` : cc;
    const shapes: SVGElement[] = [];
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d);
    shapes.push(p);
    if (c && area < SMALL_AREA) {
      const dot = document.createElementNS(NS, "circle");
      dot.setAttribute("cx", String(cx));
      dot.setAttribute("cy", String(cy));
      dot.setAttribute("r", "3");
      dot.setAttribute("class", `${cls.join(" ")} small-dot`);
      shapes.push(dot);
      dots.push(dot);
    }
    for (const s of shapes) {
      if (s.tagName === "path") s.setAttribute("class", cls.join(" "));
      const t = document.createElementNS(NS, "title");
      t.textContent = tip;
      s.append(t);
      if (c) s.addEventListener("click", () => onPick(cc));
    }
    svg.append(p);
  }
  // 작은 나라 원은 맨 위에
  for (const d of dots) svg.append(d);
  return svg;
}
