import { describe, expect, it } from "vitest";
import { agentSummary, foundByText, agentEmptyText } from "./agents-text";
import type { InstallRun } from "./installs-text";

type Part = Pick<InstallRun, "image" | "procs" | "files" | "autoruns" | "remotes" | "commands">;
const base: Part = { image: "C:\\a\\claude.exe", procs: ["C:\\a\\claude.exe"], files: [], autoruns: [], remotes: [], commands: [] };

describe("agents-text", () => {
  it("요약은 0인 항목을 뺀다", () => {
    expect(agentSummary({ ...base, procs: ["C:\\a\\claude.exe", "C:\\w\\cmd.exe"], commands: ["cmd /c dir"], remotes: [["api.example.com", 3]] })).toBe(
      "명령 1개 실행 · 프로그램 1개 실행 · 접속한 곳 1곳",
    );
  });
  it("모두 0이면 기록 없음(판정 아님)", () => {
    expect(agentSummary({ ...base })).toContain("모은 기록이 없습니다");
  });
  it("알아본 방법", () => {
    expect(foundByText("cmdline")).toContain("명령줄");
    expect(foundByText("image")).toContain("실행 파일 이름");
  });
  it("빈 상태", () => {
    expect(agentEmptyText(1)).toBe("최근 하루 동안 찾은 AI 도구 실행이 없습니다.");
    expect(agentEmptyText(7)).toContain("7일");
  });
});
