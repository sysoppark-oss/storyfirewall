// L058: 공용 경로 표시 도우미(extPath·dataPath)가 쓰는 위생 처리
import { describe, expect, it } from "vitest";
import { cleanText } from "./ui";

describe("L058 경로 표시 위생 처리", () => {
  it("양방향·폭 0 문자를 지운다", () => {
    const t = cleanText("C:\\Users\\u\\Downloads\\in\u202Egpj.exe 를 실행했습니다");
    expect(t).not.toMatch(/[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]/);
    expect(t).toContain("ingpj.exe");
    expect(cleanText("C:\\Temp\\a\u200Bb.exe · 위치")).toBe("C:\\Temp\\ab.exe · 위치");
  });
  it("문장 길이는 자르지 않는다(2000자까지)", () => {
    const long = "가".repeat(1500);
    expect(cleanText(long)).toBe(long);
  });
});
