import { describe, it, expect } from "vitest";

// 개편안 2판 3-2: 상단 띠 뱃지 — 수치가 있는 것만, 정책은 항상
import { engineBadges } from "./dashboard";
describe("engineBadges", () => {
  it("수치가 있는 뱃지만 만들고 정책 수는 항상 넣는다", () => {
    expect(engineBadges(null, 3, 0)).toEqual(["정책 3개"]);
    const h = { now: 0, last_event_ft: null, lost_24h: 0, gaps_24h: [], clock_changes_24h: [], timings: [{ name: "엔진: 주기 판정", last_ms: 2 }], wfp_filters: 12, db_bytes: 42 * 1024 * 1024 };
    expect(engineBadges(h, 5, 1)).toEqual(["판정 지연 2ms", "필터 12개", "DB 42.0 MB", "정책 5개 (확인 대기 1)"]);
  });
});
