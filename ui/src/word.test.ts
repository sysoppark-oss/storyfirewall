import { describe, expect, it } from "vitest";
// @ts-ignore — node 내장 모듈(@types/node 없이 시험에서만 씀). ?raw 가 빈 문자열이 되는 경우(tokens.test 참고)를 잡으려고 파일을 직접 읽어 비교
import { readFileSync } from "node:fs";
import { CHURCH, DEDICATION, VERSES, W, churchText, dedicationText, localDay, splitEmail, todayVerse, waitVerse } from "./word";

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

describe("말씀 표시 — 고르는 규칙(README 확인 값)", () => {
  const cases: [string, number, string][] = [
    ["2026-11-11", 20768, "jhn.7.37-38"],
    ["2026-11-12", 20769, "rom.6.23"],
    ["2026-11-13", 20770, "jhn.8.12"],
    ["2026-11-14", 20771, "jhn.10.9-11"],
    ["2026-12-25", 20812, "jhn.14.27"],
    ["2027-01-01", 20819, "psa.119.105"],
    ["2028-02-29", 21243, "rom.3.23-24"],
  ];
  it.each(cases)("%s → day %i → %s", (date, day, id) => {
    const [y, m, d] = date.split("-").map(Number) as [number, number, number];
    // 현지 날짜(자정 직전·직후 모두 같은 day)
    expect(localDay(new Date(y, m - 1, d, 0, 0, 1))).toBe(day);
    expect(localDay(new Date(y, m - 1, d, 23, 59, 59))).toBe(day);
    expect(todayVerse(day).id).toBe(id);
  });
  it("자료 개수: 100곳, 복음 20곳, 짧은 구절 96곳", () => {
    expect(VERSES.length).toBe(100);
    expect(VERSES.filter((v) => v.group === "gospel").length).toBe(20);
    expect(W.length).toBe(96);
  });
  it("기다리는 화면은 긴 구절을 쓰지 않고, 시작 위치는 day % |W|", () => {
    for (let s = 0; s < 200; s++) expect(waitVerse(20768, s).long).toBe(false);
    expect(waitVerse(20768).id).toBe(W[20768 % W.length]!.id);
  });
});
