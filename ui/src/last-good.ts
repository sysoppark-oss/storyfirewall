// UI 명세 2판 2-5 "엔진 바쁨: 뼈대 유지(직전 목록이 있으면 그대로)" · 3-1 "칸마다 독립".
// 검수(2026-11-11): 엔진이 바쁘면 대시보드가 통째로 비었다 → 조회마다 마지막 성공 값을 기억해 두고,
// 실패하면 그 값을 쓰되 "지난 값"임을 표시한다(받지 못한 값을 0 으로 그리지 않는다 — 원칙 6)
import type { RpcResult } from "./rpc";

export type Kept<T> = RpcResult<T> & { stale_at?: number };

export class LastGood {
  private m = new Map<string, { at: number; v: unknown }>();
  /** 성공이면 기억하고 그대로, 실패면 기억한 값이 있을 때 그것을 stale_at(성공했던 unix 초)과 함께 돌려준다 */
  keep<T>(key: string, r: RpcResult<T>, now: number = Date.now() / 1000): Kept<T> {
    if (r.ok) {
      this.m.set(key, { at: now, v: r.result });
      return r;
    }
    const last = this.m.get(key);
    if (!last) return r;
    return { ok: true, result: last.v as T, stale_at: last.at };
  }
  /** 이번 화면에서 지난 값을 쓴 조회 중 가장 오래된 성공 시각(없으면 null) */
  static oldest(...xs: Kept<unknown>[]): number | null {
    const ts = xs.map((x) => x.stale_at).filter((t): t is number => typeof t === "number");
    return ts.length ? Math.min(...ts) : null;
  }
}
