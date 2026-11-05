import { describe, expect, it } from "vitest";
import { busyRetryDelay, busyTransient, collectionStalled, isBusy, listState } from "./list-state";

const FT = (unix: number) => unix * 10_000_000 + 116_444_736_000_000_000;

describe("D013 목록 상태", () => {
  it("RPC 오류는 어떤 경우에도 비어 있음(조용합니다)이 되지 않는다", () => {
    const err = { ok: false as const, error: { code: -1, message: "timeout" } };
    expect(listState(err)).toBe("error");
    expect(listState(err, { now: 100, last_event_ft: FT(99) })).toBe("error");
  });
  it("성공 0건: 수집 중이면 비어 있음, 기록이 멈췄거나 없으면 수집 안 됨", () => {
    const empty = { ok: true as const, result: { items: [] as number[] } };
    expect(listState(empty, { now: 1000, last_event_ft: FT(990) })).toBe("empty");
    expect(listState(empty, { now: 1000, last_event_ft: FT(100) })).toBe("nodata");
    expect(listState(empty, { now: 1000, last_event_ft: null })).toBe("nodata");
    expect(listState(empty)).toBe("empty");
    expect(listState({ ok: true as const, result: { items: [1] } })).toBe("items");
  });
  it("상태를 모르면 멈췄다고 단정하지 않는다", () => {
    expect(collectionStalled(null)).toBe(false);
  });
});

describe("D030-1 busy 는 일시 상태", () => {
  it("-32004 만 busy", () => {
    expect(isBusy({ code: -32004, message: "busy" })).toBe(true);
    // D033-1: 응답 시간 초과도 일시 상태
    expect(isBusy({ code: -1, message: "timeout" })).toBe(true);
    expect(isBusy({ code: -1, message: "연결 없음" })).toBe(false);
    expect(isBusy({ code: -32603, message: "internal" })).toBe(false);
  });
  it("재시도 간격 5초 → 15초 → 30초, 3분 뒤에는 진짜 실패", () => {
    expect(busyRetryDelay(0, 0)).toBe(5_000);
    expect(busyRetryDelay(0, 12_000)).toBe(15_000);
    expect(busyRetryDelay(0, 60_000)).toBe(30_000);
    expect(busyRetryDelay(0, 181_000)).toBeNull();
  });
});

describe("D031-1 busy 동안 카드는 일시 상태", () => {
  it("처음 3분은 일시, 그 뒤는 진짜 실패", () => {
    const e = { code: -32004, message: "busy" };
    expect(busyTransient(e, "t1", 0)).toBe(true);
    expect(busyTransient(e, "t1", 50_000)).toBe(true);
    expect(busyTransient(e, "t1", 100_000)).toBe(true);
    expect(busyTransient(e, "t1", 150_000)).toBe(true);
    expect(busyTransient(e, "t1", 200_000)).toBe(false);
    expect(busyTransient({ code: -1, message: "x" }, "t2", 0)).toBe(false);
    expect(busyTransient({ code: -1, message: "timeout" }, "t3", 0)).toBe(true);
  });
});

import { engineStuckText } from "./state";
describe("27차 Q1 엔진 묶임 상태 줄", () => {
  it("15초 넘으면 경고, 아니면 빈 문자열", () => {
    expect(engineStuckText(0)).toBe("");
    expect(engineStuckText(14_000)).toBe("");
    expect(engineStuckText(42_000)).toContain("42초째");
  });
});
