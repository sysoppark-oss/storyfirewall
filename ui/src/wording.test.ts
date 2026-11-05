// D026(사용자 결정 2026-11-03): 나라 표기에 "등록"·화면 어디에도 "추정" 0. DB-IP Lite 국가는 위치 정보다(등록 국가 아님).
// 다른 뜻의 "등록"(자동 실행 등록·시작 프로그램 등록)은 허용. 주석 줄은 검사하지 않는다.
import { describe, expect, it } from "vitest";
const ts = import.meta.glob(["./**/*.ts", "!./**/*.test.ts", "!./worldmap-data.ts", "!./flag-codes.ts"], { query: "?raw", import: "default", eager: true }) as Record<string, string>;
const code = (src: string) => src.split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).map((l) => l.replace(/\s\/\/.*$/, ""));

describe("D026 나라 표기 문구", () => {
  it("화면 코드에 '등록 국가'·'지역 등록'·'추정' 0건", () => {
    const bad = Object.entries(ts).flatMap(([f, s]) => code(s).filter((l) => /등록 국가|지역 등록|추정/.test(l)).map((l) => `${f}: ${l.trim()}`));
    expect(bad).toEqual([]);
  });
  it("D028-1: '보임'·'보입니다' 0건 — 확신 정도 대신 근거를 쓴다", () => {
    const bad = Object.entries(ts).flatMap(([f, s]) => code(s).filter((l) => /보임|보입니다/.test(l)).map((l) => `${f}: ${l.trim()}`));
    expect(bad).toEqual([]);
  });
});
