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

/// 범위 이름(검수 8: "하루"는 0시부터인지 모호 — 실제는 24시간)
export function agentRangeLabel(days: number): string {
  return days === 1 ? "최근 24시간" : `최근 ${days}일`;
}

/// 어떻게 찾는지(목록 위 안내). 서버 목록 graph::agent::AGENTS 와 같은 내용
export const AGENT_HOW_FOUND =
  "카드 한 장은 도구가 한 번 실행된 기간입니다(같은 도구도 다시 켜면 새 카드). Claude·ChatGPT·Codex·Gemini CLI·Cursor·Windsurf·Ollama·LM Studio 와 따로 도는 MCP 서버를 실행 파일 이름이나 명령줄의 패키지 이름으로 알아봅니다. 이름을 바꾼 사본과 명령줄을 받지 못한 프로세스는 빠질 수 있습니다.";

/// 알아본 방법 한 줄. 실행 파일 이름(기본)은 쓰지 않고 명령줄로 알아본 것만(검수 4)
export function foundByText(found_by: string): string {
  return found_by === "cmdline" ? "명령줄의 패키지 이름으로 알아봄" : "";
}

/// 한 일이 있는 실행인가(검수 3: 한 일이 없는 실행은 접어서 개수만)
export function agentDidSomething(run: Pick<InstallRun, "image" | "procs" | "files" | "autoruns" | "remotes" | "commands" | "persistence">): boolean {
  return !!(run.commands.length || childProcs(run).length || run.files.length || run.autoruns.length || run.persistence?.length || run.remotes.length);
}

/// 한 줄 요약: "명령 2개 실행 · 프로그램 3개 실행 · 파일 1개 만듦 · 접속한 곳 4곳".
/// 검수 1: 상한에서 잘렸으면 숫자는 "이상"(상한 값이 실제 개수로 읽히지 않게)
export function agentSummary(run: Pick<InstallRun, "image" | "procs" | "files" | "autoruns" | "remotes" | "commands" | "persistence" | "truncated">): string {
  const more = run.truncated ? " 이상" : "";
  const parts: string[] = [];
  if (run.commands.length) parts.push(`명령 ${run.commands.length}개${more} 실행`);
  const procs = childProcs(run).length;
  if (procs) parts.push(`프로그램 ${procs}개${more} 실행`);
  if (run.files.length) parts.push(`파일 ${run.files.length}개${more} 만듦`);
  const auto = run.autoruns.length + (run.persistence?.length ?? 0);
  if (auto) parts.push(`자동 실행 관련 ${auto}건${more}`);
  if (run.remotes.length) parts.push(`접속한 곳 ${run.remotes.length}곳${more}`);
  return parts.length ? parts.join(" · ") : "실행만 기록됨 — 실행한 프로그램·명령·접속·만든 파일 없음";
}

/// 도구별로 묶는다(검수 2): 도구 이름 순서는 가장 최근 실행이 앞선 도구부터. 묶음 안은 최신 먼저(서비스 순서 유지)
export function groupByTool<T extends { key: string; display: string; run: { start_ts: number } }>(items: T[]): { key: string; display: string; runs: T[] }[] {
  const out: { key: string; display: string; runs: T[] }[] = [];
  for (const it of items) {
    let g = out.find((x) => x.key === it.key);
    if (!g) {
      g = { key: it.key, display: it.display, runs: [] };
      out.push(g);
    }
    g.runs.push(it);
  }
  return out;
}

/// 목록 상한 안내(검수 7)
export function moreText(shown: number, total: number): string {
  return total > shown ? `최근 ${shown}건만 표시했습니다 — 이 기간 전체 ${total}건` : "";
}

/// 빈 상태 문장
export function agentEmptyText(days: number): string {
  return `${agentRangeLabel(days)} 동안 찾은 AI 도구 실행이 없습니다.`;
}

/// 32차 Gemini Q4: 이름·명령줄만으로 알아본 것은 위장일 수 있다 — 유효 서명이 없으면 그 사실을 붙인다(판정은 따로 돈다)
export function signerText(signer: string | null | undefined): { text: string; warn: boolean } {
  // warn 은 굵게만 쓴다(주황은 판정 결과에만 — 명세 2-1)
  return signer ? { text: `서명: ${signer}`, warn: false } : { text: "서명 확인 안 됨 — 이름만 같은 다른 프로그램일 수 있습니다", warn: true };
}
