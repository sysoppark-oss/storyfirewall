// D011 완료 기준: 색 hex 는 토큰 정의 줄에만. 화면 코드(ts)와 style.css 의 나머지에 hex 직접 사용 0
import { describe, expect, it } from "vitest";
// vitest 에서 style.css?raw 는 빈 문자열이었다(2026-11-09 발견 — CSS 시험이 아무것도 검사하지 않았음) → 파일을 직접 읽는다
// @ts-ignore — node 내장 모듈(@types/node 없이 시험에서만 씀)
import { readFileSync } from "node:fs";
const css: string = readFileSync(new URL("./style.css", import.meta.url), "utf8");

const HEX = /#[0-9A-Fa-f]{3,8}\b/;
const ts = import.meta.glob(["./**/*.ts", "!./**/*.test.ts", "!./worldmap-data.ts", "!./flag-codes.ts"], { query: "?raw", import: "default", eager: true }) as Record<string, string>;

describe("색 토큰", () => {
  it("style.css: hex 는 토큰 정의(--이름: #값)에만", () => {
    expect(css.length).toBeGreaterThan(10_000); // 빈 문자열로 통과하지 않게
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

// UI 명세 2판 2-4: 빨간 채움 단추 0개 — 파괴적 단추는 테두리만(배경을 빨강으로 채우는 규칙이 없어야 한다)
describe("단추 위계", () => {
  it(".btn.danger 는 배경을 채우지 않는다", () => {
    const rules = css.split("}").filter((r) => /\.btn\.danger\s*\{/.test(r) || /\.btn\.danger\s*,/.test(r));
    expect(rules.length).toBeGreaterThan(0);
    const filled = rules.filter((r) => /background\s*:\s*var\(--(bad|crit)\)/.test(r));
    expect(filled).toEqual([]);
  });
});
