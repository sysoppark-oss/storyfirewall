import { describe, expect, it } from "vitest";
import { level } from "./worldmap";
import { WORLD } from "../worldmap-data";

describe("A3 지도", () => {
  it("색 단계: 0 / 1 / 2–5 / 6–20 / 21+ (D009-2)", () => {
    expect([0, 1, 2, 5, 6, 20, 21, 500].map(level)).toEqual([0, 1, 2, 2, 3, 3, 4, 4]);
  });
  it("국경 데이터: 두 글자 코드, 자주 나오는 나라·작은 나라 포함, 남극 없음", () => {
    const codes = new Set(WORLD.map(([c]) => c));
    for (const c of ["KR", "US", "JP", "CN", "TW", "HK", "SG", "MO", "MT", "XK", "DE", "NL"]) expect(codes.has(c), c).toBe(true);
    expect(codes.has("AQ")).toBe(false);
    expect(WORLD.every(([c, d]) => /^[A-Z]{2}$/.test(c) && d.startsWith("M"))).toBe(true);
    // 작은 나라는 면적이 작아 원으로 그려진다
    const area = new Map(WORLD.map(([c, , , , a]) => [c, a]));
    expect(area.get("HK")!).toBeLessThan(25);
    expect(area.get("SG")!).toBeLessThan(25);
    expect(area.get("US")!).toBeGreaterThan(1000);
  });
});
