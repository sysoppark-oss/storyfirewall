// 말씀 표시(기획자 확정 2026-11-11, 통합프로젝트 설계 11장). 규칙: docs/proposals/word/README.md
// 헌정 문구·교회 안내는 모든 프로그램이 같은 문구 — 다시 타이핑하지 않고 자료 묶음 파일을 빌드에 그대로 넣는다(?raw).
// 줄바꿈·띄어쓰기를 그대로 두고, 글자로만 표시한다(마크다운을 해석하지 않는다).
// 언어(README "언어 선택"): 이 폴더에 말씀 자료(<언어>.json)가 있는 언어만 목록에 넣는다. 실린 언어: ko, en(World English Bible).
import DEDICATION from "../../docs/proposals/word/dedication.ko.md?raw";
import CHURCH from "../../docs/proposals/word/church.ko.md?raw";
import WORD from "../../docs/proposals/word/ko.json";
import DEDICATION_EN from "../../docs/proposals/word/dedication.en.md?raw";
import CHURCH_EN from "../../docs/proposals/word/church.en.md?raw";
import WORD_EN from "../../docs/proposals/word/en.json";
import { invoke } from "@tauri-apps/api/core";
import { el } from "./ui";

export { DEDICATION, CHURCH };

export interface Verse {
  id: string;
  ref: string;
  group: string;
  long: boolean;
  text: string;
}
export type WordLang = "ko" | "en";
/** 말씀 자료가 내장된 언어 — 설정의 목록 순서. 코어(src-tauri/src/wordlang.rs)의 WORD_LANGS 와 같아야 한다 */
export const WORD_LANGS: readonly { id: WordLang; name: string }[] = [{ id: "ko", name: "한국어" }, { id: "en", name: "English" }];

interface Pack { version: string; verses: readonly Verse[]; G: readonly Verse[]; O: readonly Verse[]; W: readonly Verse[]; dedication: string; church: string }
function makePack(word: { version: string; verses: unknown }, dedication: string, church: string): Pack {
  const verses = word.verses as Verse[];
  // G: 복음의 핵심 20곳, O: 나머지 80곳, W: 짧은 구절(기다리는·빈·시작 화면) — 모두 파일 순서. long 은 언어마다 다르다
  return { version: word.version, verses, G: verses.filter((v) => v.group === "gospel"), O: verses.filter((v) => v.group !== "gospel"), W: verses.filter((v) => !v.long), dedication, church };
}
const PACKS: Record<WordLang, Pack> = { ko: makePack(WORD, DEDICATION, CHURCH), en: makePack(WORD_EN, DEDICATION_EN, CHURCH_EN) };

let current: WordLang = "ko";
/** 지금 말씀 언어 */
export const wordLang = (): WordLang => current;
export function setWordLangLocal(l: WordLang): void { current = l; }
/** 그 언어의 자료 묶음(안 주면 지금 언어) */
export const pack = (l: WordLang = current): Pack => PACKS[l];

const isLang = (x: unknown): x is WordLang => typeof x === "string" && WORD_LANGS.some((l) => l.id === x);
/** README 의 읽는 순서: HKCU → HKLM → Windows 표시 언어 → en → ko. 내장 목록에 없는 값은 다음으로 넘어간다.
 * 값은 목록과 글자 비교만 한다. 표시 언어는 "en-US" 처럼 오므로 앞 낱말만 본다 */
export function pickWordLang(hkcu: unknown, hklm: unknown, osLang: unknown): WordLang {
  for (const c of [hkcu, hklm]) if (isLang(c)) return c;
  const os = typeof osLang === "string" ? osLang.toLowerCase().split(/[-_]/)[0] : "";
  if (isLang(os)) return os;
  return "en";
}

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
/** 시작할 때 한 번: 저장된 값을 읽어 말씀 언어를 정한다. 설치판이 아니면(개발·캡처) 한국어 — 캡처는 window.__SF_WORD_LANG 으로 바꿀 수 있다 */
export async function initWordLang(): Promise<WordLang> {
  if (!inTauri) {
    const forced = (window as unknown as Record<string, unknown>)["__SF_WORD_LANG"];
    current = isLang(forced) ? forced : "ko";
    return current;
  }
  try {
    const v = (await invoke("word_lang_get")) as { hkcu?: unknown; hklm?: unknown } | null;
    current = pickWordLang(v?.hkcu, v?.hklm, navigator.language);
  } catch {
    current = pickWordLang(null, null, navigator.language);
  }
  return current;
}
/** 설정에서 바꿀 때: HKCU 에 쓰고(모든 안디옥 프로그램이 함께 읽는다) 지금 화면에도 적용. 실패하면 사유 글자 */
export async function saveWordLang(l: WordLang): Promise<string | null> {
  if (!isLang(l)) return "말씀 자료가 없는 언어입니다";
  if (inTauri) {
    try {
      await invoke("word_lang_set", { lang: l });
    } catch (err) {
      return String(err).slice(0, 200);
    }
  }
  current = l;
  return null;
}

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
  return textBlock(pack().dedication, "word-dedication");
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
export const churchText = (l?: WordLang) => body(pack(l).church);
export const dedicationText = (l?: WordLang) => body(pack(l).dedication);

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

/** 한국어 자료(시험·대조용). 화면은 pack() 으로 지금 언어의 것을 쓴다 */
export const VERSION: string = PACKS.ko.version;
export const VERSES: readonly Verse[] = PACKS.ko.verses;
export const W: readonly Verse[] = PACKS.ko.W;

/** 현지 날짜가 1970-01-01 부터 며칠째인가(1970-01-01 이 0) — 사용자 PC 의 현지 날짜 기준 */
export function localDay(d: Date = new Date()): number {
  return Math.floor(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) / 86_400_000);
}

/** 오늘의 말씀: 사흘에 한 번은 복음의 핵심 구절 */
export function todayVerse(day: number, l?: WordLang): Verse {
  const { G, O } = pack(l);
  if (day % 3 === 0) return G[Math.floor(day / 3) % G.length]!;
  return O[(day - Math.floor(day / 3) - 1) % O.length]!;
}

/** 기다리는·빈·시작 화면: 오늘 시작 위치(day % |W|)에서 step 번째 */
export function waitVerse(day: number, step = 0, l?: WordLang): Verse {
  const w = pack(l).W;
  return w[(day + step) % w.length]!;
}

/** 한 화면 안에서 구절을 바꾸는 간격(규칙: 10초보다 빨리 바꾸지 않는다) */
export const ROTATE_MS = 15_000;

/** 구절 한 덩어리: 본문, 그 아래 장·절과 번역본 이름 — 글자로만 */
export function verseBlock(v: Verse): HTMLElement {
  const box = el("div", "word-verse");
  box.append(el("div", "word-verse-text", v.text), el("div", "word-verse-ref", `${v.ref} · ${pack().version}`));
  return box;
}

/** 지금 보일 차례: 현지 자정부터 ROTATE_MS 칸 수. 자정에는 0 이라 시작 위치가 day % |W| 이고(README),
 * 여러 상자·짧은 조회가 반복돼도 같은 시각엔 같은 구절이며 하루 동안 W 를 차례로 돈다 */
export function waitStep(now: Date): number {
  const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  return Math.floor((now.getTime() - midnight) / ROTATE_MS);
}

/** 기다리는 화면용: 화면에 붙어 있는 동안 칸이 바뀔 때 다음 짧은 구절로(자정이 지나면 새 날짜 기준) */
export function rotatingVerse(): HTMLElement {
  const slot = el("div", "word-slot");
  const pick = () => { const now = new Date(); return waitVerse(localDay(now), waitStep(now)); };
  let cur = pick();
  slot.append(verseBlock(cur));
  const t = window.setInterval(() => {
    if (!slot.isConnected) { window.clearInterval(t); return; }
    const next = pick();
    if (next.id !== cur.id) { cur = next; slot.replaceChildren(verseBlock(cur)); }
  }, 1_000);
  return slot;
}

/** 빈 목록 화면용(규칙 2): 기다리는 화면과 같은 차례의 짧은 구절. 한 화면에 구절은 하나만 —
 * 이미 붙어 있는(화면에 보이는) 구절이 있으면 null. 수집 안 됨·불러오지 못함·필터 결과 없음에는 쓰지 않는다 */
export function emptyVerse(): HTMLElement | null {
  for (const x of document.querySelectorAll(".word-slot")) if ((x as HTMLElement).offsetParent !== null) return null;
  return rotatingVerse();
}

/** 빈 화면 문장 뒤에 구절을 붙인다(있을 때만) */
export function appendEmptyVerse(parent: HTMLElement): void {
  const v = emptyVerse();
  if (v) parent.append(v);
}
