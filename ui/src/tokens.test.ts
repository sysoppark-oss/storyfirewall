// D011 완료 기준: 색 hex 는 토큰 정의 줄에만. 화면 코드(ts)와 style.css 의 나머지에 hex 직접 사용 0
import { describe, expect, it } from "vitest";
import css from "./style.css?raw";

const HEX = /#[0-9A-Fa-f]{3,8}\b/;
const ts = import.meta.glob(["./**/*.ts", "!./**/*.test.ts", "!./worldmap-data.ts", "!./flag-codes.ts"], { query: "?raw", import: "default", eager: true }) as Record<string, string>;

describe("색 토큰", () => {
  it("style.css: hex 는 토큰 정의(--이름: #값)에만", () => {
    const bad = css.split("\n").map((l, i) => [i + 1, l] as const).filter(([, l]) => HEX.test(l.replace(/--[\w-]+:\s*#[0-9A-Fa-f]{3,8}\b/g, "")));
    expect(bad).toEqual([]);
  });
  it("ts: hex 직접 사용 0 (주석 포함)", () => {
    expect(Object.keys(ts).length).toBeGreaterThan(10);
    const bad = Object.entries(ts).flatMap(([f, src]) => src.split("\n").map((l, i) => [f, i + 1, l] as const).filter(([, , l]) => HEX.test(l) && !/&#\w+;/.test(l)));
    expect(bad).toEqual([]);
  });
  it("--accent 를 쓰지 않는다(남색 제거)", () => {
    expect(css.includes("--accent")).toBe(false);
  });
});
