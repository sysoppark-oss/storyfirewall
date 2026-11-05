import { describe, expect, it } from "vitest";
import { fileName, sanitize } from "./sanitize";

describe("sanitize", () => {
  it("RLO 파일명 위장을 지우고 표시한다", () => {
    const r = sanitize("invoice\u202Eexe.pdf");
    expect(r.text).toBe("invoiceexe.pdf");
    expect(r.spoofRisk).toBe(true);
  });
  it("제어 문자를 지운다", () => {
    expect(sanitize("a\u0000b\u001Bc\u2028d").text).toBe("abcd");
    expect(sanitize("a\u0000b").spoofRisk).toBe(false);
  });
  it("폭 0 문자를 지우고 위장으로 본다", () => {
    const r = sanitize("goo\u200Bgle.com");
    expect(r.text).toBe("google.com");
    expect(r.spoofRisk).toBe(true);
  });
  it("긴 문자열은 가운데를 줄인다", () => {
    const r = sanitize("x".repeat(500), 21);
    expect(r.text.length).toBe(21);
    expect(r.truncated).toBe(true);
  });
  it("문자열이 아니면 문자열로", () => {
    expect(sanitize(null).text).toBe("");
    expect(sanitize(42).text).toBe("42");
  });
  it("한글·일반 유니코드는 그대로", () => {
    expect(sanitize("크롬.exe → 네이버").text).toBe("크롬.exe → 네이버");
  });
});

describe("fileName", () => {
  it("양쪽 구분자", () => {
    expect(fileName("C:\\a\\b\\payload.exe")).toBe("payload.exe");
    expect(fileName("/usr/bin/curl")).toBe("curl");
    expect(fileName("plain")).toBe("plain");
  });
});
