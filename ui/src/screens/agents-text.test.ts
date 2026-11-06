import { describe, expect, it } from "vitest";
import { agentSummary, foundByText, agentEmptyText, signerText, groupByTool, moreText, agentDidSomething, runCountText } from "./agents-text";
import type { InstallRun } from "./installs-text";

type Part = Pick<InstallRun, "image" | "procs" | "files" | "autoruns" | "remotes" | "commands" | "truncated" | "facts_complete">;
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
  it("잘려도 사실을 모두 담았으면 파일·접속은 정확값", () => {
    const r = { ...base, procs: ["C:\\a\\claude.exe", "x"], files: ["f"], remotes: [["h", 1]] as [string, number][], truncated: true, facts_complete: true };
    expect(agentSummary(r)).toBe("프로그램 1개 이상 실행 · 파일 1개 만듦 · 접속한 곳 1곳");
    expect(agentSummary({ ...r, facts_complete: false })).toContain("파일 1개 이상");
    expect(runCountText(5, false)).toBe("실행 5건");
    expect(runCountText(50, true)).toBe("실행 50건 이상");
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
