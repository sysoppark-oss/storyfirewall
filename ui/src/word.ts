// 말씀 표시(기획자 확정 2026-11-11, 통합프로젝트 설계 11장). 규칙: docs/proposals/word/README.md
// 헌정 문구·교회 안내는 모든 프로그램이 같은 문구 — 다시 타이핑하지 않고 자료 묶음 파일을 빌드에 그대로 넣는다(?raw).
// 줄바꿈·띄어쓰기를 그대로 두고, 글자로만 표시한다(마크다운을 해석하지 않는다).
import DEDICATION from "../../docs/proposals/word/dedication.ko.md?raw";
import CHURCH from "../../docs/proposals/word/church.ko.md?raw";
import WORD from "../../docs/proposals/word/ko.json";
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

// ── 구절 고르기(README "고르는 규칙") — 모든 프로그램이 같은 날 같은 구절. 무작위를 쓰지 않는다 ──

export interface Verse {
  id: string;
  ref: string;
  group: string;
  long: boolean;
  text: string;
}

/** 번역본 이름(표시 형식: 본문 · 장절 · 번역본) */
export const VERSION: string = WORD.version;
export const VERSES: readonly Verse[] = WORD.verses as Verse[];
/** G: 복음의 핵심 20곳, O: 나머지 80곳, W: 짧은 구절(기다리는·빈·시작 화면) — 모두 파일 순서 */
const G = VERSES.filter((v) => v.group === "gospel");
const O = VERSES.filter((v) => v.group !== "gospel");
export const W: readonly Verse[] = VERSES.filter((v) => !v.long);

/** 현지 날짜가 1970-01-01 부터 며칠째인가(1970-01-01 이 0) — 사용자 PC 의 현지 날짜 기준 */
export function localDay(d: Date = new Date()): number {
  return Math.floor(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) / 86_400_000);
}

/** 오늘의 말씀: 사흘에 한 번은 복음의 핵심 구절 */
export function todayVerse(day: number): Verse {
  if (day % 3 === 0) return G[Math.floor(day / 3) % G.length]!;
  return O[(day - Math.floor(day / 3) - 1) % O.length]!;
}

/** 기다리는·빈·시작 화면: 오늘 시작 위치(day % |W|)에서 step 번째 */
export function waitVerse(day: number, step = 0): Verse {
  return W[(day + step) % W.length]!;
}

/** 한 화면 안에서 구절을 바꾸는 간격(규칙: 10초보다 빨리 바꾸지 않는다) */
export const ROTATE_MS = 15_000;

/** 구절 한 덩어리: 본문, 그 아래 장·절과 번역본 이름 — 글자로만 */
export function verseBlock(v: Verse): HTMLElement {
  const box = el("div", "word-verse");
  box.append(el("div", "word-verse-text", v.text), el("div", "word-verse-ref", `${v.ref} · ${VERSION}`));
  return box;
}

/** 기다리는 화면용: 화면에 붙어 있는 동안 ROTATE_MS 마다 다음 짧은 구절로 바꾼다 */
export function rotatingVerse(day = localDay()): HTMLElement {
  const slot = el("div", "word-slot");
  let step = 0;
  slot.append(verseBlock(waitVerse(day, step)));
  const t = window.setInterval(() => {
    if (!slot.isConnected) { window.clearInterval(t); return; }
    step += 1;
    slot.replaceChildren(verseBlock(waitVerse(day, step)));
  }, ROTATE_MS);
  return slot;
}
