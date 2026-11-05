// D029-5: 듣는 포트 상세 버튼 — PID 4·0 은 없음, 노드가 있으면 있음
import { describe, expect, it } from "vitest";
import { connKey, hasListenerDetail, pausedNew } from "./connections";

describe("듣는 포트 상세 버튼", () => {
  it("PID 4·0 줄에는 상세 버튼이 없다(노드가 있어도)", () => {
    expect(hasListenerDetail(4, 12)).toBe(false);
    expect(hasListenerDetail(0, 12)).toBe(false);
  });
  it("그 밖은 노드가 있으면 있다", () => {
    expect(hasListenerDetail(1234, 12)).toBe(true);
    expect(hasListenerDetail(1234, null)).toBe(false);
  });
});

describe("D030-3 보는 중 새 행 세기", () => {
  it("ID 로 센다(위치가 아니라)", () => {
    const a = { process_id: 1, remote_id: 2, direction: "out" };
    const b = { process_id: 1, remote_id: 3, direction: "out" };
    const shown = new Set([connKey(a)]);
    expect(pausedNew(shown, [b, a])).toBe(1);
    expect(pausedNew(shown, [a])).toBe(0);
  });
});

import { showReleaseAll } from "./policy";
describe("D032-3 주소 차단 모두 해제 단추", () => {
  it("지울 것이 있을 때만, 수를 모르면 보인다", () => {
    expect(showReleaseAll(0)).toBe(false);
    expect(showReleaseAll(2)).toBe(true);
    expect(showReleaseAll(undefined)).toBe(true);
  });
});

import { expiryText } from "./policy";
describe("D036 주소 차단 만료", () => {
  it("오늘이면 '오늘', 없으면 '기한 없음'", () => {
    const now = new Date(2026, 10, 3, 12, 0, 0);
    const t = Math.floor(new Date(2026, 10, 3, 23, 59, 0).getTime() / 1000);
    expect(expiryText(t, now)).toMatch(/^오늘 .*11:59까지$/);
    expect(expiryText(null, now)).toBe("기한 없음");
    const t2 = Math.floor(new Date(2026, 10, 4, 9, 0, 0).getTime() / 1000);
    expect(expiryText(t2, now)).toMatch(/^11월 4일 .*까지$/);
  });
});
