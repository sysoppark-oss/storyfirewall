import { describe, expect, it } from "vitest";
// @ts-ignore — node 내장 모듈(@types/node 없이 시험에서만 씀). ?raw 가 빈 문자열이 되는 경우(tokens.test 참고)를 잡으려고 파일을 직접 읽어 비교
import { readFileSync } from "node:fs";
import { CHURCH, DEDICATION, VERSES, W, churchText, dedicationText, localDay, splitEmail, todayVerse, waitStep, waitVerse, ROTATE_MS, WORD_LANGS, pack, pickWordLang, setWordLangLocal } from "./word";

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

describe("말씀 표시 — 넣지 않는 자리·바꾸는 간격", () => {
  const src = (n: string): string => readFileSync(new URL(`./${n}`, import.meta.url), "utf8");
  it("진단·처리 기록·차단 기록·변경 장부의 불러오기에는 구절이 없다(규칙 3)", () => {
    for (const f of ["screens/diag.ts", "screens/blocked-log.ts"]) {
      for (const m of src(f).matchAll(/loadingBox\(([^)]*)\)/g)) expect(m[1], f).toContain("word: false");
    }
    expect(src("screens/story.ts")).toMatch(/triage-log"\);\s*box\.append\(loadingBox\(\{ word: false \}\)\)/);
    expect(src("screens/dashboard.ts")).toMatch(/loadingBox\(\{ word: false \}\)\); \/\/ 말씀 규칙 3: 변경 장부/);
  });
  it("빈 화면 구절: 기록·진단 화면과 필터 결과 없음·수집 안 됨에는 붙이지 않는다", () => {
    for (const f of ["screens/diag.ts", "screens/blocked-log.ts", "screens/live-conns.ts", "screens/policy.ts"]) expect(src(f), f).not.toContain("appendEmptyVerse");
    // 수집 안 됨(noDataBox)·필터 결과 없음과 같은 줄에 붙지 않는다
    for (const f of ["screens/story.ts", "screens/connections.ts", "screens/dashboard.ts"]) {
      for (const line of src(f).split("\n").filter((l) => l.includes("appendEmptyVerse") && !l.startsWith("import"))) {
        expect(line, f).not.toMatch(/noDataBox|필터에 맞는/);
      }
    }
  });
  it("10초보다 빨리 바꾸지 않고, 자정에 day % |W| 에서 시작", () => {
    expect(ROTATE_MS).toBeGreaterThanOrEqual(10_000);
    expect(waitStep(new Date(2026, 10, 11, 0, 0, 0))).toBe(0);
    expect(waitStep(new Date(2026, 10, 11, 0, 0, 14))).toBe(0);
    expect(waitStep(new Date(2026, 10, 11, 0, 0, 15))).toBe(1);
    expect(waitVerse(20768, waitStep(new Date(2026, 10, 11, 0, 0, 1))).id).toBe(W[20768 % W.length]!.id);
  });
});

describe("말씀 언어(README 언어 선택)", () => {
  it("영어 자료는 파일 그대로 — 다시 타이핑하지 않는다", () => {
    expect(pack("en").dedication).toBe(file("dedication.en.md"));
    expect(pack("en").church).toBe(file("church.en.md"));
    const en = JSON.parse(file("en.json")) as { version: string; verses: { id: string; text: string; long: boolean }[] };
    expect(pack("en").version).toBe(en.version);
    expect(pack("en").verses.map((v) => v.text)).toEqual(en.verses.map((v) => v.text));
  });
  it("언어 파일은 같은 id 100곳을 같은 순서로 — 어느 언어에서나 같은 날 같은 곳", () => {
    expect(pack("en").verses.map((v) => v.id)).toEqual(VERSES.map((v) => v.id));
    expect(pack("en").verses.map((v) => v.group)).toEqual(VERSES.map((v) => v.group));
    for (const day of [20768, 20769, 20770, 20771, 20812, 20819, 21243]) expect(todayVerse(day, "en").id).toBe(todayVerse(day, "ko").id);
  });
  it("긴 구절(long=true)은 기다리는·빈·시작 화면에 쓰지 않는다 — long 은 언어마다 다르다", () => {
    const long = pack("en").verses.filter((v) => v.long).map((v) => v.id);
    expect(long.length).toBeGreaterThan(0);
    expect(pack("en").W.length).toBe(100 - long.length);
    for (let step = 0; step < 300; step++) expect(long).not.toContain(waitVerse(20771, step, "en").id);
  });
  it("읽는 순서: HKCU → HKLM → Windows 표시 언어 → en. 목록에 없는 값은 넘어간다", () => {
    expect(pickWordLang("en", "ko", "ko-KR")).toBe("en");
    expect(pickWordLang(null, "en", "ko-KR")).toBe("en");
    expect(pickWordLang("fr", "..\\x", "ko-KR")).toBe("ko");
    expect(pickWordLang(null, null, "en-US")).toBe("en");
    expect(pickWordLang(undefined, 7, "ja-JP")).toBe("en");
    expect(pickWordLang("KO", null, "")).toBe("en");
  });
  it("고른 언어의 본문·장절·번역본 이름·문안을 쓴다", () => {
    setWordLangLocal("en");
    expect(`${todayVerse(20769).ref} · ${pack().version}`).toBe("Romans 6:23 · World English Bible");
    expect(dedicationText()).toContain("Living Waters Church");
    expect(churchText()).toBe(file("church.en.md").replace(/\s+$/, ""));
    setWordLangLocal("ko");
    expect(pack().version).toContain("개역한글판");
    expect(dedicationText()).toBe(file("dedication.ko.md").replace(/\s+$/, ""));
  });
  it("화면의 언어 목록 = 코어의 목록", () => {
    // @ts-ignore — node 내장 모듈
    const rs = readFileSync(new URL("../src-tauri/src/wordlang.rs", import.meta.url), "utf8") as string;
    const m = /WORD_LANGS: &\[&str\] = &\[([^\]]*)\]/.exec(rs)!;
    expect(m[1]!.split(",").map((x) => x.trim().replace(/"/g, ""))).toEqual(WORD_LANGS.map((l) => l.id));
  });
});
