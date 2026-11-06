import { describe, expect, it } from "vitest";
import { ledgerSummary } from "./first-run";

describe("변경 장부 요약", () => {
  it("사실 개수만, 비면 그렇다고", () => {
    expect(ledgerSummary({ procs: ["a.exe", "b.exe"], files: ["C:\\x.dat"], autoruns: [], remotes: [] })).toBe("파일 1개 만듦·이름 바꿈 · 프로그램 1개 실행");
    expect(ledgerSummary({ procs: ["a.exe"], files: [], autoruns: [], remotes: [] })).toContain("변경이 없습니다");
    expect(ledgerSummary({ procs: ["a.exe"], files: ["x"], autoruns: [], remotes: [], truncated: true })).toContain("1개 이상");
  });
});
