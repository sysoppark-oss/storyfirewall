import { describe, expect, it } from "vitest";
import { LastGood } from "./last-good";

describe("LastGood", () => {
  it("실패하면 마지막 성공 값을 지난 값 표시와 함께 돌려준다", () => {
    const g = new LastGood();
    const busy = { ok: false as const, error: { code: -32004, message: "busy" } };
    // 처음부터 실패면 그대로 실패(0 으로 그리지 않게)
    expect(g.keep("a", busy, 100).ok).toBe(false);
    expect(g.keep("a", { ok: true, result: [1, 2] }, 200)).toEqual({ ok: true, result: [1, 2] });
    const k = g.keep("a", busy, 300);
    expect(k).toEqual({ ok: true, result: [1, 2], stale_at: 200 });
    expect(LastGood.oldest(k, { ok: true, result: 1 })).toBe(200);
    expect(LastGood.oldest({ ok: true, result: 1 })).toBeNull();
    // 다른 키는 따로
    expect(g.keep("b", busy, 300).ok).toBe(false);
  });
});
