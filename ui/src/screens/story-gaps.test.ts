import { describe, expect, it } from "vitest";
import { summarizeGaps } from "./story-group";

describe("L053 기록 빠짐 구간 묶기", () => {
  it("빠진 구간 여러 개를 한 묶음으로: 개수·합계·처음·끝, 최신이 위", () => {
    const s = summarizeGaps([
      { from_ts: 100, to_ts: 110, events: 7 },
      { from_ts: 300, to_ts: 320, events: 100 },
      { from_ts: 200, to_ts: 205, events: 94 },
    ]);
    expect(s).not.toBeNull();
    expect(s!.count).toBe(3);
    expect(s!.events).toBe(201);
    expect([s!.first_ts, s!.last_ts]).toEqual([100, 320]);
    expect(s!.list.map((g) => g.from_ts)).toEqual([300, 200, 100]);
  });
  it("기록 없는 구간(no_record)·0건은 이 묶음이 아니다", () => {
    expect(summarizeGaps([{ from_ts: 1, to_ts: 2, events: 0 }, { from_ts: 3, to_ts: 4, events: 5, reason: "no_record" }])).toBeNull();
    expect(summarizeGaps([])).toBeNull();
  });
});
