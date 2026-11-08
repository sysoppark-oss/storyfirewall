import { describe, it, expect } from "vitest";
import { parseFilter, matches, filterChips, dropChip } from "./story-filter";

const FT = (unix: number) => unix * 10_000_000 + 116_444_736_000_000_000;

describe("인시던트 드릴다운 필터(UI 명세 4판 3-2)", () => {
  it("모르는 값은 버리고, 처리 상태에 맞는 서비스 triage 를 고른다", () => {
    expect(parseFilter({ level: "x", triage: "y", stage: 9, state: "acted" })).toEqual({ state: "acted", triage: "done" });
    expect(parseFilter({ state: "new" }).triage).toBe("open");
    expect(parseFilter({ watching: true }).triage).toBe("done");
    expect(parseFilter({ levelEq: "critical" }).level).toBe("critical");
    expect(parseFilter({ stage: 4 }).stage).toBe(4);
  });
  it("단계·시간·샌드박스·심각도만·지켜보기를 화면에서 거른다", () => {
    const ev = { level: "Suspicious", reached: [1, 2, 4], last_ts: FT(1000), triage: { state: "acted", action: "watch" }, first_run_watch: { until_ts: 2000 } };
    expect(matches(ev, { stage: 4 }, 1500)).toBe(true);
    expect(matches(ev, { stage: 3 }, 1500)).toBe(false);
    expect(matches(ev, { from: 1000, to: 4600 }, 1500)).toBe(true);
    expect(matches(ev, { from: 1001 }, 1500)).toBe(false);
    expect(matches(ev, { sandbox: true }, 1500)).toBe(true);
    expect(matches(ev, { sandbox: true }, 2500)).toBe(false); // 관찰이 끝났다
    expect(matches(ev, { levelEq: "suspicious" }, 0)).toBe(true);
    expect(matches(ev, { levelEq: "critical" }, 0)).toBe(false);
    expect(matches(ev, { watching: true }, 0)).toBe(true);
    expect(matches({ level: "critical" }, { watching: true }, 0)).toBe(false);
    expect(matches({ level: "critical" }, { state: "new" }, 0)).toBe(true); // 처리 기록 없음 = 신규
    expect(matches({ level: "critical" }, { from: 0 }, 0)).toBe(false); // 시각을 모르면 시간 필터에 넣지 않는다
  });
  it("칩 글자와 지우기", () => {
    const f = parseFilter({ stage: 4, from: 0, to: 3600, sandbox: true });
    const keys = filterChips(f).map((c) => c.key);
    expect(keys).toEqual(["stage", "time", "sandbox"]);
    expect(filterChips(f)[0]!.label).toBe("단계: C2·유출까지 간 것");
    const g = dropChip(f, "time");
    expect(g.from).toBeUndefined();
    expect(g.to).toBeUndefined();
    expect(g.stage).toBe(4);
  });
});
