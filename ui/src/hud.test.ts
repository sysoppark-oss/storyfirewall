import { describe, it, expect } from "vitest";
import { hudLines } from "./hud";

describe("hudLines (HUD ① 상시 창 문구)", () => {
  it("끊김·없음·수·긴급 차단·최근 사건", () => {
    expect(hudLines({ tone: "down", critical: 1, high: 0, latest: "x", emergency_left_min: 3 }).top).toBe("보호 서비스 연결 끊김");
    expect(hudLines({ tone: "ok", critical: 0, high: 0, latest: null, emergency_left_min: null })).toEqual({ tone: "ok", top: "보호 중 · 미조치 심각·높음 없음", sub: "최근 사건 없음" });
    const v = hudLines({ tone: "critical", critical: 1, high: 2, latest: "invoice-viewer.exe — 5장", emergency_left_min: 12 });
    expect(v.top).toBe("미조치 심각 1 · 높음 2");
    expect(v.sub).toBe("긴급 차단 중 · 12분 남음 · invoice-viewer.exe — 5장");
  });
});
