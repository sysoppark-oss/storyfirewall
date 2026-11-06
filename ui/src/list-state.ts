// D013 목록 화면의 네 상태: 불러오는 중 / 비어 있음 / 수집 안 됨 / 불러오지 못함.
// L028: 조회가 시간 초과·오류여도 "오늘은 조용합니다"처럼 빈 목록으로 그려져 사용자가 오판할 수 있었다 — 오류는 오류로 보인다.
import { el, ext, button, fmtShort, filetimeToUnix } from "./ui";
import type { RpcError, RpcResult } from "./rpc";

export type ListState = "error" | "nodata" | "empty" | "items";

export interface HealthLike {
  now: number;
  last_event_ft: number | null;
}

/// 수집 기록이 멈췄거나(마지막 사건 60초 넘게 전) 아예 없는가 — C1 과 같은 기준
export function collectionStalled(h: HealthLike | null | undefined): boolean {
  if (!h) return false; // 상태를 모르면 단정하지 않는다
  if (h.last_event_ft == null) return true;
  return h.now - filetimeToUnix(h.last_event_ft) > 60;
}

/// 응답 → 상태. 오류는 절대 "비어 있음"이 되지 않는다
export function listState<T>(r: RpcResult<{ items: T[] }>, health?: HealthLike | null): ListState {
  if (!r.ok) return "error";
  if (r.result.items.length) return "items";
  return collectionStalled(health) ? "nodata" : "empty";
}

/// 불러오는 중: 회색 뼈대 3줄, 2초 넘으면 "불러오는 중…"
export function loadingBox(): HTMLElement {
  const b = el("div", "loading", el("div", "sk"), el("div", "sk"), el("div", "sk"));
  const p = el("p", "muted", "불러오는 중…");
  setTimeout(() => { if (b.isConnected) b.append(p); }, 2000);
  // D021-2: 10초가 넘으면 이유를 덧붙인다
  setTimeout(() => { if (b.isConnected) p.textContent = "불러오는 중… (기록이 많으면 시간이 걸릴 수 있습니다)"; }, 10000);
  return b;
}

/// D030-1: busy(-32004)는 일시 상태다 — 엔진이 다른 작업 중. 진짜 실패와 다르게 보이고 스스로 다시 부른다
export const BUSY_CODE = -32004;
/// D033-1: 응답 시간 초과(-1 timeout — 읽기 작업자·엔진이 아직 답하지 않음)도 다시 부르면 풀리는 일시 상태다
export function isBusy(err: RpcError): boolean {
  return err.code === BUSY_CODE || (err.code === -1 && /time(d)? ?out/i.test(err.message));
}
/// 자동 재시도 간격(ms): 처음 busy 를 본 뒤 경과에 따라 5초 → 15초 → 30초, 3분이 지나면 null(진짜 실패로 보인다)
export function busyRetryDelay(firstSeenMs: number, nowMs: number): number | null {
  const e = nowMs - firstSeenMs;
  if (e < 10_000) return 5_000;
  if (e < 40_000) return 15_000;
  if (e < 180_000) return 30_000;
  return null;
}
/// 목록별 busy 처음 본 시각(1분 넘게 busy 가 없었으면 새로 센다)
const busySeen = new Map<string, { first: number; last: number }>();

/// busy 를 처음 본 뒤 3분 안인가(그동안은 일시 상태로 보인다). 기록은 failBox 와 같은 표를 쓴다
export function busyTransient(err: RpcError, what: string, nowMs = Date.now()): boolean {
  if (!isBusy(err)) return false;
  const prev = busySeen.get(what);
  const rec = prev && nowMs - prev.last < 60_000 ? { first: prev.first, last: nowMs } : { first: nowMs, last: nowMs };
  busySeen.set(what, rec);
  return busyRetryDelay(rec.first, nowMs) != null;
}

/// D031-1: 숫자 카드의 실패 표시. busy 는 "—" + 회색 "잠시 뒤 다시 불러옵니다", 진짜 실패(또는 3분 넘은 busy)만 "불러오지 못함"
export function cardFail(err: RpcError, what: string): HTMLElement {
  const b = busyTransient(err, `카드:${what}`)
    ? el("div", undefined, el("div", "big muted", "—"), el("div", "muted small", "잠시 뒤 다시 불러옵니다"))
    : el("div", undefined, el("div", "big", "—"), el("div", "warn small", "불러오지 못함"));
  b.title = `${err.code} ${err.message}`;
  return b;
}

/// 불러오지 못함: 주황 문장 + 오류 코드(서비스 문자열은 텍스트 노드로만) + 다시 시도
export function failBox(err: RpcError, retry?: () => void, what = "목록"): HTMLElement {
  if (isBusy(err) && retry) {
    const now = Date.now();
    const prev = busySeen.get(what);
    const rec = prev && now - prev.last < 60_000 ? { first: prev.first, last: now } : { first: now, last: now };
    busySeen.set(what, rec);
    const delay = busyRetryDelay(rec.first, now);
    if (delay != null) {
      // 일시 상태: 주황 한 줄, 코드는 툴팁에만. 탭이 보일 때만 스스로 다시 부른다
      const b = el("div", "busy-note", `엔진이 다른 작업 중이라 ${what}을 아직 받지 못했습니다. 잠시 뒤 다시 불러옵니다.`);
      b.title = `${err.code} ${err.message}`;
      b.append(" ", button("지금 다시 시도", retry, "btn small"));
      const t = window.setTimeout(function again() {
        if (!b.isConnected) return;
        if (document.visibilityState !== "visible") { window.setTimeout(again, 2_000); return; }
        retry();
      }, delay);
      void t;
      return b;
    }
    busySeen.delete(what);
  }
  const b = el("div", "fail");
  b.append(`${what}을 불러오지 못했습니다 (오류: `, ext("span", `${err.code} ${err.message}`), ")");
  if (retry) b.append(" ", button("다시 시도", retry, "btn small"));
  return b;
}

/// 수집 안 됨: 주황 안내 + 설정 진단으로
export function noDataBox(onMore?: () => void): HTMLElement {
  // F2: "자세히 ›"가 홀로 다음 줄로 떨어지지 않게 마지막 말과 한 덩어리(nowrap)로 묶는다
  const b = el("div", "fail nodata", "아직 기록된 것이 없습니다 — 수집이 시작되지 않았거나 멈췄을 수 ");
  const tail = el("span", "nowrap", "있습니다.");
  if (onMore) {
    const a = el("a", undefined, "자세히 ›");
    a.href = "#";
    a.addEventListener("click", (e) => { e.preventDefault(); onMore(); });
    tail.append(" ", a);
  }
  b.append(tail);
  return b;
}

/// 비어 있음의 보조 줄: "마지막 확인 오후 1:10 · 수집 기록 중"
export function checkedLine(h: HealthLike | null | undefined): HTMLElement {
  return el("p", "muted small", `마지막 확인 ${fmtShort(h?.now ?? Date.now() / 1000)}${h ? " · 수집 기록 중" : ""}`);
}
