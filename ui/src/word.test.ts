import { describe, expect, it } from "vitest";
// @ts-ignore — node 내장 모듈(@types/node 없이 시험에서만 씀). ?raw 가 빈 문자열이 되는 경우(tokens.test 참고)를 잡으려고 파일을 직접 읽어 비교
import { readFileSync } from "node:fs";
import { CHURCH, DEDICATION, churchText, dedicationText, splitEmail } from "./word";

const file = (n: string): string => readFileSync(new URL(`../../docs/proposals/word/${n}`, import.meta.url), "utf8");

describe("말씀 표시 — 헌정 문구·교회 안내", () => {
  it("자료 묶음 파일을 글자 하나 바꾸지 않고 넣는다", () => {
    expect(DEDICATION.length).toBeGreaterThan(100);
    expect(DEDICATION).toBe(file("dedication.ko.md"));
    expect(CHURCH).toBe(file("church.ko.md"));
    expect(dedicationText()).toBe(file("dedication.ko.md").replace(/\s+$/, ""));
  });
  it("교회 안내: 전자우편 하나만 조각으로, 합치면 원문 그대로", () => {
    const parts = splitEmail(churchText());
    expect(parts.map((p) => p.text).join("")).toBe(file("church.ko.md").replace(/\s+$/, ""));
    expect(parts.filter((p) => p.email).length).toBe(1);
  });
});
