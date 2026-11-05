import { describe, expect, it } from "vitest";
import { FIRST_RUN_BLOCK_APPROVAL, FIRST_RUN_CHOICES, firstRunSentence, firstRunSetting, umbrellaText, watchUntilText } from "./first-run";

describe("첫 실행 관찰실 설정", () => {
  it("값이 없거나 이상하면 서비스 기본(알리기, 10분)", () => {
    expect(firstRunSetting({})).toEqual({ mode: "notify", minutes: 10 });
    expect(firstRunSetting({ first_run_watch: "kill", first_run_minutes: 7 })).toEqual({ mode: "notify", minutes: 10 });
    expect(firstRunSetting({ first_run_watch: "10", first_run_minutes: "30" })).toEqual({ mode: "notify", minutes: 10 });
  });
  it("저장된 값은 그대로", () => {
    expect(firstRunSetting({ first_run_watch: "off", first_run_minutes: 5 })).toEqual({ mode: "off", minutes: 5 });
    expect(firstRunSetting({ first_run_watch: "block", first_run_minutes: 30 })).toEqual({ mode: "block", minutes: 30 });
  });
  it("세 선택지 모두 한 문장 설명이 있고, 막기는 승인 창 확인이 필요하다고 밝힌다", () => {
    expect(FIRST_RUN_CHOICES.map((c) => c.value)).toEqual(["off", "notify", "block"]);
    for (const c of FIRST_RUN_CHOICES) expect(firstRunSentence(c.value)).toMatch(/다\.$/);
    expect(firstRunSentence("block")).toContain(FIRST_RUN_BLOCK_APPROVAL);
    expect(firstRunSentence("block")).not.toContain("준비 중");
    expect(firstRunSentence("notify")).not.toContain(FIRST_RUN_BLOCK_APPROVAL);
  });
  it("우산 정책 상태 줄은 막기 모드에서만, 상태를 사실대로", () => {
    expect(umbrellaText("notify", { state: "Confirmed" })).toBe("");
    expect(umbrellaText("block", { state: "Confirmed" })).toContain("켜짐");
    expect(umbrellaText("block", { state: "Applied" })).toContain("확인 대기");
    expect(umbrellaText("block", { state: "RolledBack" })).toContain("알림만");
    expect(umbrellaText("block", null)).toContain("알림만");
  });
  it("관찰 끝 시각은 숫자일 때만", () => {
    const fmt = (u: number) => `T${u}`;
    expect(watchUntilText(1700000600, fmt)).toBe("관찰 끝 T1700000600");
    expect(watchUntilText(undefined, fmt)).toBe("");
    expect(watchUntilText("x", fmt)).toBe("");
  });
});
