// 말씀 표시(기획자 확정 2026-11-11, 통합프로젝트 설계 11장). 규칙: docs/proposals/word/README.md
// 헌정 문구·교회 안내는 모든 프로그램이 같은 문구 — 다시 타이핑하지 않고 자료 묶음 파일을 빌드에 그대로 넣는다(?raw).
// 줄바꿈·띄어쓰기를 그대로 두고, 글자로만 표시한다(마크다운을 해석하지 않는다).
import DEDICATION from "../../docs/proposals/word/dedication.ko.md?raw";
import CHURCH from "../../docs/proposals/word/church.ko.md?raw";
import { el } from "./ui";

export { DEDICATION, CHURCH };

/** 끝의 빈 줄만 걷는다(파일 끝 줄바꿈). 본문 글자는 건드리지 않는다 */
const body = (s: string) => s.replace(/\s+$/, "");

/** 글자 그대로 + 줄바꿈 유지 */
function textBlock(s: string, cls: string): HTMLElement {
  const p = el("div", cls);
  p.style.whiteSpace = "pre-wrap";
  p.textContent = body(s);
  return p;
}

/** "정보" 화면의 헌정 문구 */
export function dedicationBlock(): HTMLElement {
  return textBlock(DEDICATION, "word-dedication");
}

/** 전자우편 주소는 글자로 보이고, 누르면 사용자의 메일 프로그램이 열리는 것까지만(README 규칙 5) */
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

/** 글을 보통 글자와 전자우편 조각으로 나눈다(합치면 원문 그대로) */
export function splitEmail(s: string): { text: string; email: boolean }[] {
  const out: { text: string; email: boolean }[] = [];
  let at = 0;
  for (const m of s.matchAll(EMAIL)) {
    const i = m.index ?? 0;
    if (i > at) out.push({ text: s.slice(at, i), email: false });
    out.push({ text: m[0], email: true });
    at = i + m[0].length;
  }
  if (at < s.length) out.push({ text: s.slice(at), email: false });
  return out;
}

/** 화면에 넣는 본문(끝 줄바꿈만 걷음) */
export const churchText = () => body(CHURCH);
export const dedicationText = () => body(DEDICATION);

/** [교회 안내]를 눌렀을 때의 문안 */
export function churchBlock(): HTMLElement {
  const box = el("div", "word-church");
  box.style.whiteSpace = "pre-wrap";
  for (const part of splitEmail(churchText())) {
    if (!part.email) {
      box.append(document.createTextNode(part.text));
      continue;
    }
    const a = document.createElement("a");
    a.href = `mailto:${part.text}`;
    a.textContent = part.text;
    box.append(a);
  }
  return box;
}
