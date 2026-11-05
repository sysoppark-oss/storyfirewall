import { describe, expect, it } from "vitest";
import { flagPath, placeName, type Where } from "./connections";
import { FLAG_CODES } from "../flag-codes";

const w = (cc: string, country?: string): Where => ({ scope: "public", cc, country, org: "Org" }) as Where;

describe("D005 국기·국가 표기", () => {
  it("지역·미정 코드는 국기 없이 글자", () => {
    expect(flagPath("ZZ")).toBeNull();
    expect(placeName(w("ZZ", "지정 안 됨"))).toBe("지정 안 됨");
    expect(flagPath("EU")).toBeNull();
    expect(placeName(w("EU", "유럽(나라 미상)"))).toBe("유럽(나라 미상)");
    expect(flagPath("AP")).toBeNull();
    expect(placeName(w("AP"))).toBe("아시아·태평양(나라 미상)");
  });
  it("나라 코드는 번들에 있을 때만 국기", () => {
    expect(flagPath("XK")).toBe("flags/xk.svg");
    expect(placeName(w("XK", "코소보"))).toBe("코소보");
    expect(flagPath("TW")).toBe("flags/tw.svg");
    expect(placeName(w("TW", "대만"))).toBe("대만");
    // 없는 코드: 국기 없음(깨진 그림 0), 이름 없으면 코드 두 글자
    expect(flagPath("QZ")).toBeNull();
    expect(placeName(w("QZ"))).toBe("QZ");
    expect(flagPath("kr")).toBeNull(); // 소문자·이상한 값은 경로에 쓰지 않는다
    expect(flagPath("../x")).toBeNull();
  });
  it("국기 목록은 public/flags 와 같다 (scripts/gen-flags.mjs)", () => {
    // Vite 의 glob(빌드 도구가 아는 파일 목록) — node:fs 없이
    const files = Object.keys(import.meta.glob("../../public/flags/*.svg")).map((p) => p.split("/").pop()!).filter((f) => /^[a-z]{2}\.svg$/.test(f)).map((f) => f.slice(0, 2).toUpperCase()).sort();
    expect([...FLAG_CODES].sort()).toEqual(files);
  });
});
