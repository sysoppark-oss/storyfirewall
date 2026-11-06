import { describe, expect, it } from "vitest";
import { agentSummary, foundByText, agentEmptyText, signerText, groupByTool, moreText, agentDidSomething } from "./agents-text";
import type { InstallRun } from "./installs-text";

type Part = Pick<InstallRun, "image" | "procs" | "files" | "autoruns" | "remotes" | "commands" | "truncated">;
const base: Part = { image: "C:\\a\\claude.exe", procs: ["C:\\a\\claude.exe"], files: [], autoruns: [], remotes: [], commands: [], truncated: false };

describe("agents-text", () => {
  it("요약은 0인 항목을 뺀다", () => {
    expect(agentSummary({ ...base, procs: ["C:\\a\\claude.exe", "C:\\w\\cmd.exe"], commands: ["cmd /c dir"], remotes: [["api.example.com", 3]] })).toBe(
      "명령 1개 실행 · 프로그램 1개 실행 · 접속한 곳 1곳",
    );
  });
  it("모두 0이면 실행만 기록됨", () => {
    expect(agentSummary({ ...base })).toContain("실행만 기록됨");
    expect(agentDidSomething({ ...base })).toBe(false);
  });
  it("잘렸으면 이상", () => {
    expect(agentSummary({ ...base, procs: ["C:\\a\\claude.exe", "x", "y"], truncated: true })).toBe("프로그램 2개 이상 실행");
  });
  it("도구별 묶기·상한 안내", () => {
    const r = (key: string, t: number) => ({ key, display: key, run: { start_ts: t } });
    const g = groupByTool([r("claude", 3), r("cursor", 2), r("claude", 1)]);
    expect(g.map((x) => [x.key, x.runs.length])).toEqual([["claude", 2], ["cursor", 1]]);
    expect(moreText(50, 50)).toBe("");
    expect(moreText(50, 80)).toContain("전체 80건");
  });
  it("알아본 방법", () => {
    expect(foundByText("cmdline")).toContain("명령줄");
    expect(foundByText("image")).toBe("");
  });
  it("빈 상태", () => {
    expect(agentEmptyText(1)).toBe("최근 24시간 동안 찾은 AI 도구 실행이 없습니다.");
    expect(agentEmptyText(7)).toContain("7일");
  });
  it("서명", () => {
    expect(signerText("Anthropic, PBC")).toEqual({ text: "서명: Anthropic, PBC", warn: false });
    expect(signerText(null).warn).toBe(true);
  });
});
