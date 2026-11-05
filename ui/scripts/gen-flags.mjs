// public/flags 에 있는 국기 SVG 코드 목록 → src/flag-codes.ts (디자인 D005: 번들에 있는 코드만 국기, 나머지는 회색 점).
// 사용: node scripts/gen-flags.mjs  (국기 파일을 바꾸면 다시 실행. vitest 가 목록과 폴더가 같은지 검사한다)
import fs from "node:fs";
// D018: 루트 <svg> 에 width·height 가 없으면 viewBox 크기로 넣는다. 없으면 브라우저가 원래 크기를 거의 0 으로 읽어
// Cytoscape 가 축소 화면(텍스처 캐시)에서 국기를 점처럼 그렸다. flag-icons(MIT) 수정은 크기 속성 추가뿐
const dir = new URL("../public/flags/", import.meta.url);
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".svg"))) {
  const p = new URL(f, dir);
  const svg = fs.readFileSync(p, "utf8");
  const root = /<svg\b[^>]*>/.exec(svg)?.[0];
  if (!root || /\swidth=/.test(root)) continue;
  const vb = /viewBox="\s*[-\d.]+\s+[-\d.]+\s+([\d.]+)\s+([\d.]+)\s*"/.exec(root);
  if (!vb) continue;
  fs.writeFileSync(p, svg.replace(root, root.replace("<svg", `<svg width="${vb[1]}" height="${vb[2]}"`)));
}
const codes = fs.readdirSync(new URL("../public/flags/", import.meta.url))
  .filter((f) => /^[a-z]{2}\.svg$/.test(f))
  .map((f) => f.slice(0, 2).toUpperCase())
  .sort();
const out = `// 생성 파일: scripts/gen-flags.mjs. 손으로 고치지 않는다.\nexport const FLAG_CODES: ReadonlySet<string> = new Set(${JSON.stringify(codes)});\n`;
fs.writeFileSync(new URL("../src/flag-codes.ts", import.meta.url), out);
console.log(`flag codes: ${codes.length}`);
