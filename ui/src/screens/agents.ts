// AI 도구 화면 (AI 에이전트 감시, 기획서 14판 20-5): AI 도구 실행 한 번마다 실행한 명령·프로그램·접속한 곳·만든 파일을 카드로.
// 판정하지 않는다 — 사실의 개수와 목록만. 카드 모양은 설치 화면과 같다(installs.ts buildCard).
// 화면 검수(2026-11-06): 도구별로 묶고, 한 일이 없는 실행은 개수만, 잘린 숫자는 "이상", 목록 상한 안내, 범위 "최근 24시간".
import { rpc } from "../rpc";
import { el, ext, clear } from "../ui";
import { loadingBox, failBox, noDataBox, collectionStalled, type HealthLike } from "../list-state";
import { buildCard } from "./installs";
import {
  type AgentRun, AGENT_DAYS, AGENT_HOW_FOUND, agentSummary, agentEmptyText, foundByText, signerText,
  agentRangeLabel, agentDidSomething, groupByTool, moreText,
} from "./agents-text";

const LIMIT = 50;

function runCard(a: AgentRun): HTMLElement {
  const card = buildCard(a.run, agentSummary(a.run));
  // 알아본 방법(명령줄일 때만)·서명은 시각 줄 끝에. 서명자는 서명 검증 결과(외부 문자열) — 텍스트 노드로만
  const meta = card.querySelector(".install-meta");
  const how = foundByText(a.found_by);
  if (how) meta?.append(` · ${how}`);
  const sg = signerText(a.run.signer);
  meta?.append(" · ", ext("span", sg.text, sg.warn ? "strong" : undefined));
  return card;
}

export function agents(): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "AI 도구"));
  const range = el("select");
  for (const d of AGENT_DAYS) {
    const o = el("option", undefined, agentRangeLabel(d));
    o.value = String(d);
    range.append(o);
  }
  range.addEventListener("change", () => void load());
  const cards = el("div", "cards-col");
  root.append(el("div", "toolbar", "범위 ", range), cards);

  const load = async () => {
    const days = Number(range.value) || 1;
    clear(cards);
    cards.append(loadingBox());
    const [r, h] = await Promise.all([
      rpc<{ ready: boolean; items: AgentRun[]; total?: number }>("agents.list", { days, limit: LIMIT }),
      rpc<HealthLike>("collector.health", {}),
    ]);
    if (Number(range.value) !== days) return;
    clear(cards);
    if (!r.ok) return void cards.append(failBox(r.error, () => void load(), "AI 도구 목록"));
    // 서비스가 막 켜져 아직 미리 계산 전: 빈 목록으로 그리지 않는다
    if (!r.result.ready) {
      cards.append(el("p", "muted", "AI 도구 목록을 만드는 중입니다(서비스가 켜진 뒤 1분쯤). 잠시 뒤 다시 열어 주세요."));
      return;
    }
    if (!r.result.items.length) {
      if (collectionStalled(h.ok ? h.result : null)) return void cards.append(noDataBox());
      cards.append(el("p", undefined, agentEmptyText(days)), el("p", "muted small", AGENT_HOW_FOUND));
      return;
    }
    cards.append(el("p", "muted small", AGENT_HOW_FOUND));
    for (const g of groupByTool(r.result.items)) {
      const head = el("h2", undefined, g.display);
      head.append(el("span", "badge count", `실행 ${g.runs.length}건`));
      cards.append(head);
      const busy = g.runs.filter((a) => agentDidSomething(a.run));
      for (const a of busy) cards.append(runCard(a));
      // 한 일이 없는 실행(잠깐 뜬 보조 프로세스 등)은 접어서 개수만
      const idle = g.runs.length - busy.length;
      if (idle > 0) {
        const det = el("details", "muted small");
        det.append(el("summary", undefined, `한 일이 없는 실행 ${idle}건`));
        for (const a of g.runs.filter((x) => !agentDidSomething(x.run))) det.append(runCard(a));
        cards.append(det);
      }
    }
    const more = moreText(r.result.items.length, r.result.total ?? r.result.items.length);
    if (more) cards.append(el("p", "muted small", more));
  };
  void load();
  return root;
}
