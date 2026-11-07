import { describe, it, expect } from "vitest";
import { hourlyCounts, chapterReach } from "./dash-viz";

describe("대시보드 시각 요소", () => {
  it("시간대별 수: 오늘 것만, 미래 60초 넘는 것은 제외", () => {
    const now = new Date(2026, 10, 7, 9, 30).getTime() / 1000;
    const t = (h: number) => new Date(2026, 10, 7, h, 10).getTime() / 1000;
    const out = hourlyCounts([t(9), t(9), t(3), t(9) - 86400, now + 3600], now);
    expect(out[9]).toBe(2); expect(out[3]).toBe(1); expect(out.reduce((a, b) => a + b, 0)).toBe(3);
  });
  it("4장 도달 수: 사건 하나가 도달한 모든 장에 들어간다", () => {
    expect(chapterReach([[1, 2, 4], [2], [9]])).toEqual([1, 2, 0, 1]);
  });
});

import { axisNum } from "./dash-viz";
describe("축 눈금 숫자", () => {
  it("만·천 단위로 줄인다", () => {
    expect(axisNum(124706)).toBe("12만");
    expect(axisNum(47060)).toBe("4.7만");
    expect(axisNum(2353)).toBe("2.4천");
    expect(axisNum(20)).toBe("20");
  });
});

import { bytesAxis } from "./dash-viz";
describe("바이트 축 눈금", () => {
  it("단위를 붙여 짧게", () => {
    expect(bytesAxis(0)).toBe("0B");
    expect(bytesAxis(1536)).toBe("2KB");
    expect(bytesAxis(1.5 * 1024 * 1024)).toBe("1.5MB");
    expect(bytesAxis(142 * 1024 * 1024)).toBe("142MB");
    expect(bytesAxis(1.2 * 1024 ** 3)).toBe("1.2GB");
  });
});
