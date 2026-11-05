// 외부에서 온 문자열(도메인·파일명·프로세스 이름)은 자료다. 화면에 넣기 전에 위생 처리한다 (14차 Q5).
// - DOM 삽입은 항상 textContent (innerHTML 금지) — 이 파일은 그 위에 제어 문자·양방향 위장만 다룬다.
// - 제어 문자(C0·C1·U+2028/2029)는 제거.
// - 양방향 제어(RLO·LRO·RLE·LRE·PDF·RLI·LRI·FSI·PDI·RLM·LRM·ALM)는 제거하고 "표시 위장 가능" 표를 남긴다
//   (예: "invoice\u202Eexe.pdf" 는 invoicefdp.exe 로 보인다).
// - 너무 긴 문자열은 가운데를 줄인다 (UI 가 밀리지 않게).

const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029]/g;
const BIDI = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;
const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/g;

export interface Sanitized {
  text: string;
  /// 양방향 제어·폭 0 문자를 지웠다 → 원본은 화면과 다르게 보였을 수 있다
  spoofRisk: boolean;
  /// 잘렸는가
  truncated: boolean;
}

export function sanitize(raw: unknown, maxLen = 160): Sanitized {
  let s = typeof raw === "string" ? raw : raw == null ? "" : String(raw);
  const before = s.length;
  s = s.replace(BIDI, "").replace(ZERO_WIDTH, "");
  const spoofRisk = s.length !== before;
  s = s.replace(CONTROL, "");
  let truncated = false;
  if (s.length > maxLen) {
    const half = Math.floor((maxLen - 1) / 2);
    s = s.slice(0, half) + "…" + s.slice(s.length - half);
    truncated = true;
  }
  return { text: s, spoofRisk, truncated };
}

/// 파일 경로에서 파일 이름만 (표시용). 경로 구분자는 \ 와 / 둘 다.
export function fileName(path: string): string {
  const i = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return i >= 0 ? path.slice(i + 1) : path;
}

/// 텍스트 노드를 만든다. spoofRisk 면 경고 표시를 붙인다.
export function textEl(tag: string, raw: unknown, cls?: string): HTMLElement {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  const s = sanitize(raw);
  el.textContent = s.text;
  if (s.spoofRisk) {
    el.classList.add("spoof-risk");
    el.title = "이 이름에는 표시를 뒤집거나 숨기는 문자가 들어 있었습니다 (제거하고 표시함)";
  }
  if (s.truncated) el.title = (el.title ? el.title + " · " : "") + "전체 길이 " + String(raw).length;
  return el;
}
