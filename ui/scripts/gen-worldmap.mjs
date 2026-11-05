// 세계지도 데이터 생성(A3 지도, 사용자 요청 2026-11-03). 앱은 이 결과(src/worldmap-data.ts)만 쓰고 실행 중 아무것도 내려받지 않는다.
// 원천: Natural Earth 1:50m 국경(퍼블릭 도메인) — world-atlas 2.0.2(ISC) 의 countries-50m.json.
// 투영: Natural Earth 1(d3-geo 3.1.1, ISC), 960x420, 남극 제외. 각 나라: [코드, 경로, 중심x, 중심y, 가장 큰 조각의 경계 상자 면적]. 1px 보다 가까운 점은 버리고 소수 1자리로 줄인다.
// 국가 코드: ISO 3166-1 숫자 → 두 글자(i18n-iso-countries 7.14.0, MIT). 숫자 코드가 없는 지역은 이름으로(코소보 XK 등).
// 사용(빈 폴더에서): npm i world-atlas@2.0.2 topojson-client@3.1.0 d3-geo@3.1.1 i18n-iso-countries@7.14.0
//                   node <이 파일> <그 폴더> <출력 .ts>
import { createRequire } from "node:module";
import fs from "node:fs";
const [, , dir, outFile] = process.argv;
const req = createRequire(`${dir}/package.json`);
const topo = req("world-atlas/countries-50m.json");
const { feature } = req("topojson-client");
const d3 = await import(`${dir}/node_modules/d3-geo/src/index.js`);
const iso = req("i18n-iso-countries");
const W = 960, H = 420;
const fc0 = feature(topo, topo.objects.countries);
// D009-3: 남극 제외(세로 공간). 나머지로 투영을 맞춘다
const fc = { type: "FeatureCollection", features: fc0.features.filter((f) => f.id !== "010" && f.properties.name !== "Antarctica") };
const proj = d3.geoNaturalEarth1().fitExtent([[4, 4], [W - 4, H - 4]], fc);
const BY_NAME = { Kosovo: "XK", "N. Cyprus": "CY", Somaliland: "SO" };
// 경로 문자열을 줄인다: 소수 1자리, 직전 점과 1px 안이면 버림
function shrink(d) {
  const out = [];
  let lx = null, ly = null;
  for (const seg of d.match(/[MLZ][^MLZ]*/g) ?? []) {
    const c = seg[0];
    if (c === "Z") { out.push("Z"); lx = ly = null; continue; }
    const [x, y] = seg.slice(1).split(",").map(Number);
    if (c === "L" && lx != null && Math.hypot(x - lx, y - ly) < 1.0) continue;
    out.push(`${c}${x.toFixed(1)},${y.toFixed(1)}`.replace(/\.0(?=,|$)/g, ""));
    lx = x; ly = y;
  }
  return out.join("");
}
const path = d3.geoPath(proj);
const rows = [];
for (const f of fc.features) {
  const cc = f.id ? iso.numericToAlpha2(f.id) : BY_NAME[f.properties.name];
  if (!cc) { console.error(`no code: ${f.properties.name} (${f.id})`); continue; }
  const d = path(f);
  if (!d) continue;
  // D009-4: 작은 나라 표시용 중심점·크기(투영 좌표)
  const [[x0, y0], [x1, y1]] = path.bounds(f);
  const [cx, cy] = path.centroid(f);
  rows.push([cc, shrink(d), Math.round(cx * 10) / 10, Math.round(cy * 10) / 10, Math.round((x1 - x0) * (y1 - y0))]);
}
// 같은 코드(본토·섬 따로)는 합친다
const m = new Map();
for (const [cc, d, cx, cy, area] of rows) {
  const o = m.get(cc);
  // 같은 코드가 여러 조각이면 경로는 합치고, 중심·면적은 가장 큰 조각 기준
  if (!o) m.set(cc, { d, cx, cy, area });
  else { o.d += d; if (area > o.area) { o.cx = cx; o.cy = cy; o.area = area; } }
}
const body = [...m.entries()].sort().map(([cc, o]) => `  [${JSON.stringify(cc)}, ${JSON.stringify(o.d)}, ${o.cx}, ${o.cy}, ${o.area}],`).join("\n");
fs.writeFileSync(outFile, `// 생성 파일: scripts/gen-worldmap.mjs (Natural Earth 1:50m, 퍼블릭 도메인 · world-atlas ISC · d3-geo ISC). 손으로 고치지 않는다.\n// 국경은 Natural Earth 기본 표기 그대로이며 정치적 입장을 뜻하지 않는다.\nexport const MAP_W = ${W};\nexport const MAP_H = ${H};\nexport const WORLD: ReadonlyArray<readonly [string, string, number, number, number]> = [\n${body}\n];\n`);
console.log(`countries: ${m.size}, bytes: ${fs.statSync(outFile).size}`);
