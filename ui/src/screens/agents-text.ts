// AI 도구 화면(AI 에이전트 감시, 기획서 14판 20-5)의 순수 도우미. DOM 없음 — 단위 시험 대상.
// 판정하지 않는다: 도구별로 한 일의 개수와 목록만 말한다.
import { type InstallRun, childProcs } from "./installs-text";

/// 서비스 agents.list 의 한 항목 (crates/graph/src/agent.rs AgentRun)
export interface AgentRun {
  key: string;
  display: string;
  /// "image"(실행 파일 이름으로 알아봄) | "cmdline"(명령줄의 패키지 이름으로 알아봄)
  found_by: string;
  run: InstallRun & { where?: Record<string, import("./connections").Where> };
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
/// 상한에서 잘렸으면 프로그램·명령 수는 "이상". 파일·자동 실행·접속은 서비스가 그것을 한 자손을 모두 담았다고 하면(facts_complete) 정확값
export function agentSummary(run: Pick<InstallRun, "image" | "procs" | "files" | "autoruns" | "remotes" | "commands" | "persistence" | "truncated" | "facts_complete">): string {
  const more = run.truncated ? " 이상" : "";
  const factMore = run.truncated && !run.facts_complete ? " 이상" : "";
  const parts: string[] = [];
  if (run.commands.length) parts.push(`명령 ${run.commands.length}개${more} 실행`);
  const procs = childProcs(run).length;
  if (procs) parts.push(`프로그램 ${procs}개${more} 실행`);
  if (run.files.length) parts.push(`파일 ${run.files.length}개${factMore} 만듦`);
  const auto = run.autoruns.length + (run.persistence?.length ?? 0);
  if (auto) parts.push(`자동 실행 관련 ${auto}건${factMore}`);
  if (run.remotes.length) parts.push(`접속한 곳 ${run.remotes.length}곳${factMore}`);
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

/// 묶음 머리의 건수(재검수 N2): 목록이 상한에서 잘렸으면 화면에 받은 건수 뒤에 "이상"
export function runCountText(n: number, listTruncated: boolean): string {
  return `실행 ${n}건${listTruncated ? " 이상" : ""}`;
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

// ── UI 명세 4판 3-7 / 2장 5-2a: [외부 통신 차단…] ──
export type BlockSpan = "1h" | "today" | "always";
export const BLOCK_SPAN_LABEL: Record<BlockSpan, string> = { "1h": "1시간", today: "오늘(자정까지)", always: "계속(직접 해제할 때까지)" };

/// 지금부터 지역 자정까지 남은 분(최소 1)
export function minutesToMidnight(now: Date): number {
  const mid = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1, 0, 0, 0, 0);
  return Math.max(1, Math.ceil((mid.getTime() - now.getTime()) / 60_000));
}

/// 그 에이전트 실행 파일의 인터넷 방향 나가기 차단 정책(YAML 1건). LAN·로컬(로컬 MCP 서버 등)은 막지 않는다.
/// 경로는 외부 문자열 — JSON 문자열로 넣어 YAML 해석을 바꾸지 못하게 한다. 이름은 우리 표(도구 이름)에서만 만든다
export function agentBlockYaml(exePath: string, display: string, span: BlockSpan, now: Date = new Date()): string {
  const name = `AI 에이전트 외부 통신 차단 - ${display}`.slice(0, 64);
  const lines = [
    `- name: ${JSON.stringify(name)}`,
    "  action: block",
    `  match: { direction: out, process: [${JSON.stringify(exePath.replace(/\\/g, "/"))}], remote_ip: [internet] }`,
  ];
  if (span === "1h") lines.push("  expires: 60m");
  else if (span === "today") lines.push(`  expires: ${minutesToMidnight(now)}m`);
  return lines.join("\n") + "\n";
}

/// 접속지 한 줄 글자: "example.com ×3"
export function remoteCountText(name: string, count: number): string {
  return count > 1 ? `${name} ×${count}` : name;
}

/// 공용 실행기(node·python 등)로 도는 에이전트: 그 실행 파일을 막으면 같은 실행기를 쓰는 다른 프로그램도 막힌다
const SHARED_RUNTIMES = new Set(["node.exe", "python.exe", "pythonw.exe", "py.exe", "bun.exe", "deno.exe", "uv.exe", "uvx.exe", "npx.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "java.exe", "javaw.exe"]);
export function sharedRuntime(path: string): boolean {
  const b = path.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "";
  return SHARED_RUNTIMES.has(b.toLowerCase());
}
