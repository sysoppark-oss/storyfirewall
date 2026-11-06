// AI 도구 화면(AI 에이전트 감시, 기획서 14판 20-5)의 순수 도우미. DOM 없음 — 단위 시험 대상.
// 판정하지 않는다: 도구별로 한 일의 개수와 목록만 말한다.
import { type InstallRun, childProcs } from "./installs-text";

/// 서비스 agents.list 의 한 항목 (crates/graph/src/agent.rs AgentRun)
export interface AgentRun {
  key: string;
  display: string;
  /// "image"(실행 파일 이름으로 알아봄) | "cmdline"(명령줄의 패키지 이름으로 알아봄)
  found_by: string;
  run: InstallRun;
}

/// 조회 범위(일). 서비스 허용 범위 1..7(미리 계산 범위)
export const AGENT_DAYS = [1, 7] as const;

/// 어떻게 찾는지(목록 위 안내). 서버 목록 graph::agent::AGENTS 와 같은 내용
export const AGENT_HOW_FOUND =
  "Claude·ChatGPT·Codex·Gemini CLI·Cursor·Windsurf·Ollama·LM Studio 와 따로 도는 MCP 서버를 실행 파일 이름이나 명령줄의 패키지 이름으로 알아봅니다. 이름을 바꾼 사본과 명령줄을 받지 못한 프로세스는 빠질 수 있습니다.";

/// 알아본 방법 한 줄
export function foundByText(found_by: string): string {
  return found_by === "cmdline" ? "명령줄의 패키지 이름으로 알아봄" : "실행 파일 이름으로 알아봄";
}

/// 한 줄 요약: "명령 2개 실행 · 프로그램 3개 실행 · 파일 1개 만듦 · 접속한 곳 4곳". 모두 0이면 그 사실과 한계
export function agentSummary(run: Pick<InstallRun, "image" | "procs" | "files" | "autoruns" | "remotes" | "commands" | "persistence">): string {
  const parts: string[] = [];
  if (run.commands.length) parts.push(`명령 ${run.commands.length}개 실행`);
  const procs = childProcs(run).length;
  if (procs) parts.push(`프로그램 ${procs}개 실행`);
  if (run.files.length) parts.push(`파일 ${run.files.length}개 만듦`);
  const auto = run.autoruns.length + (run.persistence?.length ?? 0);
  if (auto) parts.push(`자동 실행 관련 ${auto}건`);
  if (run.remotes.length) parts.push(`접속한 곳 ${run.remotes.length}곳`);
  return parts.length ? parts.join(" · ") : "이 도구와 그 자손에서 모은 기록이 없습니다";
}

/// 빈 상태 문장
export function agentEmptyText(days: number): string {
  return `최근 ${days === 1 ? "하루" : `${days}일`} 동안 찾은 AI 도구 실행이 없습니다.`;
}
