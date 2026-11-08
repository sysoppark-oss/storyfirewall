import { describe, it, expect } from "vitest";
import { hudLines } from "./hud";

describe("hudLines (HUD ① 상시 창 문구)", () => {
  it("끊김·없음·수·긴급 차단·최근 인시던트, 보호 상태는 늘 있다", () => {
    const d = hudLines({ tone: "down", critical: 1, high: 0, latest: "x", emergency_left_min: 3 });
    expect([d.state, d.top]).toEqual(["연결 끊김", "보호 서비스에 닿지 않음"]);
    expect(hudLines({ tone: "ok", critical: 0, high: 0, latest: null, emergency_left_min: null })).toEqual({ tone: "ok", state: "보호 중", top: "미조치 심각·높음 없음", sub: "최근 인시던트 없음" });
    const v = hudLines({ tone: "critical", critical: 1, high: 2, latest: "invoice-viewer.exe — 5장", emergency_left_min: 12 });
    expect([v.state, v.top]).toEqual(["긴급 차단 중", "미조치 심각 1 · 높음 2"]);
    expect(v.sub).toBe("긴급 차단 중 · 12분 남음 · invoice-viewer.exe — 5장");
    // 건수가 있어도 보호 상태 문구가 빠지지 않는다(검수 2026-11-08 4번)
    expect(hudLines({ tone: "high", critical: 0, high: 14, latest: null, emergency_left_min: null }).state).toBe("보호 중");
  });
});
