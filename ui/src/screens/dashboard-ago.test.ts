import { describe, it, expect } from "vitest";
import { agoText } from "./dashboard";

describe("마지막 사건 표기(검수 B3: 상태 줄과 카드가 같은 말)", () => {
  it("초·분·시간·없음", () => {
    expect(agoText(null)).toBe("없음");
    expect(agoText(5)).toBe("5초 전");
    expect(agoText(125)).toBe("2분 전");
    expect(agoText(7300)).toBe("2시간 전");
  });
});
