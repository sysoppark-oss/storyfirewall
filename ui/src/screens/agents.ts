// AI 도구 화면 (AI 에이전트 감시, 기획서 14판 20-5): AI 도구 실행 한 번마다 통신한 곳·실행한 명령·만든 파일을 카드로.
// 판정하지 않는다 — 사실의 개수와 목록만. 카드 모양은 설치 화면과 같다(installs.ts buildCard).
import { rpc } from "../rpc";
import { el, ext, clear } from "../ui";
import { loadingBox, failBox, noDataBox, collectionStalled, type HealthLike } from "../list-state";
import { buildCard } from "./installs";
import { type AgentRun, AGENT_DAYS, AGENT_HOW_FOUND, agentSummary, agentEmptyText, foundByText, signerText } from "./agents-text";

export function agents(): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "AI 도구"));
  const range = el("select");
  for (const d of AGENT_DAYS) {
    const o = el("option", undefined, `최근 ${d === 1 ? "하루" : `${d}일`}`);
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
      rpc<{ ready: boolean; items: AgentRun[] }>("agents.list", { days, limit: 20 }),
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
    for (const a of r.result.items) {
      const card = buildCard(a.run, agentSummary(a.run));
      // 도구 이름(서비스 목록의 상수)과 알아본 방법을 카드 머리에
      const head = card.querySelector(".card-head");
      head?.prepend(ext("span", a.display, "badge"), " ");
      head?.append(el("span", "muted small", ` · ${foundByText(a.found_by)}`));
      // 서명자는 서명 검증 결과(외부 문자열) — 텍스트 노드로만
      const sg = signerText(a.run.signer);
      head?.append(" ", ext("span", sg.text, sg.warn ? "small warn" : "muted small"));
      cards.append(card);
    }
  };
  void load();
  return root;
}
