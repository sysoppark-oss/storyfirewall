// 작은 DOM 도우미. innerHTML 은 쓰지 않는다 (외부 문자열이 섞이므로).
import { textEl, sanitize } from "./sanitize";

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  for (const c of children) e.append(typeof c === "string" ? document.createTextNode(c) : c);
  return e;
}

/// 외부에서 온 문자열은 이걸로만 (위생 처리)
export const ext = textEl;

export function button(label: string, onClick: () => void, cls = "btn"): HTMLButtonElement {
  const b = el("button", cls, label);
  b.addEventListener("click", onClick);
  return b;
}

export function clear(node: HTMLElement) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function fmtTs(unixSec: number | undefined | null): string {
  if (!unixSec) return "-";
  return new Date(unixSec * 1000).toLocaleString("ko-KR", { hour12: false });
}

/// 짧은 시각(D002): 오늘이면 "오전 2:35", 아니면 "11월 2일 오후 3:10". 초는 상세에서만(fmtTs)
export function fmtShort(unixSec: number | undefined | null, now: Date = new Date()): string {
  if (!unixSec) return "-";
  const d = new Date(unixSec * 1000);
  const hm = d.toLocaleTimeString("ko-KR", { hour: "numeric", minute: "2-digit" });
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  return sameDay ? hm : `${d.getMonth() + 1}월 ${d.getDate()}일 ${hm}`;
}

/// 상세용 짧은 시각 + 초(D027-1, UI 명세 2-3): 오늘이면 "오후 5:53:55", 아니면 "11월 2일 오후 3:10:05"
export function fmtShortSec(unixSec: number | undefined | null, now: Date = new Date()): string {
  if (!unixSec) return "-";
  const d = new Date(unixSec * 1000);
  const hms = d.toLocaleTimeString("ko-KR", { hour: "numeric", minute: "2-digit", second: "2-digit" });
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  return sameDay ? hms : `${d.getMonth() + 1}월 ${d.getDate()}일 ${hms}`;
}

/// D042-2(UI 명세 2판 2-3): "처음 ~ 마지막". 날짜가 다르면 끝에도 날짜(끝이 오늘이면 "오늘"), "~" 앞뒤 한 칸.
/// 같은 날이면 끝은 시각만. sec = 초까지(상세)
export function fmtRange(a: number | undefined | null, b: number | undefined | null, now: Date = new Date(), sec = false): string {
  const f = sec ? fmtShortSec : fmtShort;
  if (!a || !b) return `${f(a, now)} ~ ${f(b, now)}`;
  const da = new Date(a * 1000);
  const db = new Date(b * 1000);
  const day = (d: Date) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  const time = (d: Date) => d.toLocaleTimeString("ko-KR", sec ? { hour: "numeric", minute: "2-digit", second: "2-digit" } : { hour: "numeric", minute: "2-digit" });
  // D046-1: 같은 날 같은 시각(표시 단위)이면 한 번만
  if (day(da) === day(db)) return time(da) === time(db) ? f(a, now) : `${f(a, now)} ~ ${time(db)}`;
  const end = day(db) === day(now) ? `오늘 ${time(db)}` : `${db.getMonth() + 1}월 ${db.getDate()}일 ${time(db)}`;
  return `${f(a, now)} ~ ${end}`;
}

/// 시:분:초 (표의 시각 칸, D001)
export function fmtHms(unixSec: number | undefined | null): string {
  if (!unixSec) return "-";
  const d = new Date(unixSec * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/// FILETIME(100ns, 1601) → unix 초
export function filetimeToUnix(ft: number): number {
  return Math.floor((ft - 116444736000000000) / 10000000);
}

export function errorBox(msg: string): HTMLElement {
  return el("div", "error", msg);
}

/// D039-1: 한국어 글꼴(맑은 고딕 등)은 역슬래시(0x5C)를 ₩ 로 그린다. 글 속의 Windows 경로(C:\…, \\서버\…)만 고정폭(.path)으로 감싼다.
/// 글자는 모두 텍스트 노드로 넣는다(외부 문자열).
/// D042-1: 폴더 이름의 공백·괄호(Program Files (x86), 사용자 이름 공백)는 경로에 넣는다 — 폴더 구간은 다음 역슬래시까지,
/// 마지막 구간(파일 이름)은 공백·괄호·가운뎃점·쉼표 앞까지. 폴더 구간은 가운뎃점·쉼표·줄바꿈·콜론(다른 경로의 드라이브)을 넘지 않는다
export const PATH_RE = /(?:[A-Za-z]:\\|\\\\)(?:[^\\\r\n·,:]*?\\)*[^\s()·,\\:]*/g;
export function splitPaths(text: string): { t: string; path: boolean }[] {
  const out: { t: string; path: boolean }[] = [];
  let last = 0;
  for (const m of text.matchAll(PATH_RE)) {
    if (m.index! > last) out.push({ t: text.slice(last, m.index!), path: false });
    out.push({ t: m[0], path: true });
    last = m.index! + m[0].length;
  }
  if (last < text.length) out.push({ t: text.slice(last), path: false });
  return out;
}
/// D042-1: 자료에서 경로로 온 값(위치·자동 실행)은 정규식으로 고르지 않고 통째로. "경로 · 설명" 모양이면 가운뎃점 앞까지가 경로
/** L058: 화면에 넣을 외부 문자열에서 양방향·폭 0·제어 문자를 지운다(길이는 문장째라 넉넉히 2000) */
export function cleanText(s: string): string {
  return sanitize(s, 2000).text;
}

export function dataPath<K extends keyof HTMLElementTagNameMap>(tag: K, value: string, cls?: string): HTMLElementTagNameMap[K] {
  // L058: 경로·문장 안의 양방향·폭 0·제어 문자를 지운다(파일 이름 위장 방지). 길이는 문장째 들어오므로 넉넉히
  value = cleanText(value);
  const i = value.indexOf(" · ");
  const head = i >= 0 ? value.slice(0, i) : value;
  if (!/^(?:[A-Za-z]:\\|\\\\)/.test(head)) return extPath(tag, value, cls);
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  const sp = document.createElement("span");
  sp.className = "path";
  sp.textContent = head;
  e.append(sp);
  if (i >= 0) e.append(document.createTextNode(value.slice(i)));
  return e;
}
export function extPath<K extends keyof HTMLElementTagNameMap>(tag: K, text: string, cls?: string): HTMLElementTagNameMap[K] {
  // L058: dataPath 와 같은 위생 처리
  text = cleanText(text);
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  for (const p of splitPaths(text)) {
    if (p.path) {
      const s = document.createElement("span");
      s.className = "path";
      s.textContent = p.t;
      e.append(s);
    } else e.append(document.createTextNode(p.t));
  }
  return e;
}
