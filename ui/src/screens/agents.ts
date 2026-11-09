// AI 도구 화면 (AI 에이전트 감시, 기획서 14판 20-5): AI 도구 실행 한 번마다 실행한 명령·프로그램·접속한 곳·만든 파일을 카드로.
// 판정하지 않는다 — 사실의 개수와 목록만. 카드 모양은 설치 화면과 같다(installs.ts buildCard).
// 화면 검수(2026-11-06): 도구별로 묶고, 한 일이 없는 실행은 개수만, 잘린 숫자는 "이상 징후", 목록 상한 안내, 범위 "최근 24시간".
import { rpc, mutation, uuid } from "../rpc";
import { el, ext, clear, button, errorBox } from "../ui";
import { sanitize } from "../sanitize";
import { countdown, approvalBox, type ApplyReply } from "../confirm";
import { whereCell, type Where } from "./connections";
import { withIcon } from "./dash-viz";
import { isPackagePath } from "./process";
import { childProcs, countPaths } from "./installs-text";
import { loadingBox, failBox, noDataBox, collectionStalled, type HealthLike } from "../list-state";
import { buildCard, section, pathLine, safePath } from "./installs";
import {
  type AgentRun, AGENT_DAYS, AGENT_HOW_FOUND, agentSummary, agentEmptyText, foundByText, signerText,
  agentRangeLabel, agentDidSomething, groupByTool, moreText, runCountText,
  agentBlockYaml, BLOCK_SPAN_LABEL, remoteCountText, sharedRuntime, type BlockSpan,
} from "./agents-text";

const LIMIT = 50;

/// 접속지 한 줄: 국기 · 나라 (AS 망) · 이름 ×횟수. 나라·망은 오프라인 DB(서비스가 붙임) — 없으면 이름만
function remoteLine(name: string, count: number, w: Where | undefined): HTMLElement {
  const li = el("li", "agent-remote");
  if (w) {
    const td = whereCell(w);
    const span = el("span", "where");
    span.title = td.title;
    span.append(...Array.from(td.childNodes));
    li.append(span, " · ");
  }
  li.append(ext("span", remoteCountText(name, count), "mono"));
  return li;
}

/// UI 명세 4판 3-7 / 5-1: 자세히 = 실행한 프로그램 / 만든 파일 / 접속지 (+ 자동 실행 관련은 있을 때만)
function agentDetail(run: AgentRun["run"]): HTMLElement[] {
  const kinds = countPaths(childProcs(run));
  const runs = kinds.reduce((a, [, n]) => a + n, 0);
  const progs = [
    ...kinds.map(([p, n]) => pathLine(p, n)),
    ...run.commands.map((c) => safePath("li", c, "mono", 1000)),
  ];
  const out = [
    section("실행한 프로그램", progs, run.commands.length ? "프로그램 경로와 실행한 명령줄" : undefined, "cog",
      runs > kinds.length ? `${kinds.length}종 · ${runs}번${run.truncated ? " 이상" : ""}${run.commands.length ? ` · 명령 ${run.commands.length}개` : ""}` : undefined),
    section("만든 파일", run.files.map((p) => pathLine(p)), "수집 범위: 실행 파일·스크립트, 사용자 쓰기 가능 폴더", "file"),
    section("접속지", run.remotes.map(([n, c]) => remoteLine(n, c, run.where?.[n])), "나라·망은 PC 안의 오프라인 DB 로 붙입니다(위치가 아니라 등록 정보)", "globe"),
  ];
  const auto = [
    ...run.autoruns.map(([loc, target]) => { const li = el("li"); li.append(safePath("span", loc), " → ", safePath("span", target)); return li; }),
    ...(run.persistence ?? []).map((p) => safePath("li", p, "mono", 1000)),
  ];
  if (auto.length) out.push(section("자동 실행 관련", auto));
  return out;
}

/// [외부 통신 차단…] 대화상자: 대상 경로, 기한(1시간·오늘·계속) → 정책 적용(승인 창 + 60초 [유지])
function blockDialog(a: AgentRun, status: HTMLElement): void {
  const path = a.run.image;
  const dlg = el("dialog", "ack");
  dlg.append(el("h3", undefined, `${a.display} 외부 통신 차단`));
  const p = el("p", undefined, "대상 실행 파일: ");
  p.append(ext("span", sanitize(path, 400).text, "mono"));
  dlg.append(p, el("p", "muted small", "이 경로의 실행 파일이 인터넷 쪽으로 나가는 연결을 막습니다. 같은 PC 안(로컬 MCP 서버)·사설망 연결은 막지 않습니다. 이미 열린 연결은 다음 연결부터 막힐 수 있습니다. 경로로 막으므로, 같은 파일을 다른 폴더로 복사하거나 다른 이름(링크)으로 실행하면 막히지 않습니다."));
  // 공용 실행기면 함께 막히는 범위를 먼저 알린다(주의 — 판정 아님)
  // 스토어(WindowsApps) 앱은 업데이트 때 판 번호가 든 폴더가 바뀐다 → 경로 차단이 새 판에는 걸리지 않는다
  if (isPackagePath(path)) dlg.append(el("p", "warn", "스토어 앱 경로입니다. 앱이 업데이트되면 폴더 이름(판 번호)이 바뀌어 이 차단이 새 판에는 걸리지 않습니다. 기한을 짧게 두고, 업데이트 뒤에는 다시 확인하세요."));
  if (sharedRuntime(path)) dlg.append(el("p", "warn", "이 실행 파일은 여러 프로그램이 함께 쓰는 실행기입니다. 같은 실행 파일로 도는 다른 도구·스크립트의 인터넷 연결도 함께 막힙니다."));
  const fs = el("fieldset", "span-pick");
  fs.append(el("legend", undefined, "기한"));
  let span: BlockSpan = "1h";
  for (const k of Object.keys(BLOCK_SPAN_LABEL) as BlockSpan[]) {
    const r = el("input");
    r.type = "radio";
    r.name = "span";
    r.value = k;
    r.checked = k === span;
    r.addEventListener("change", () => { span = k; });
    const l = el("label", undefined, r, ` ${BLOCK_SPAN_LABEL[k]}`);
    fs.append(l);
  }
  dlg.append(fs, el("p", "muted small", "적용하면 승인 창이 뜨고, 60초 안에 [유지]를 누르지 않으면 자동으로 되돌립니다."));
  const err = el("div");
  const go = withIcon(button("차단 적용…", async () => {
    go.disabled = true;
    const yaml = agentBlockYaml(path, a.display, span);
    const r = await mutation<ApplyReply>("policy.apply", { yaml }, uuid());
    go.disabled = false;
    if (!r.ok) return void err.replaceChildren(errorBox(r.error.code === -32003 ? "이 정책은 정책 화면에서 항목별 확인 뒤 적용해야 합니다." : `적용 실패: ${r.error.message}`));
    dlg.close();
    clear(status);
    status.append(r.approval ? approvalBox(r.approval) : countdown(r.result, status, () => {}));
  }, "btn danger"), "ban");
  const cancel = button("취소", () => dlg.close(), "btn");
  dlg.append(err, el("div", "actions", cancel, go));
  document.body.append(dlg);
  dlg.addEventListener("close", () => dlg.remove());
  dlg.showModal();
  cancel.focus();
}

function runCard(a: AgentRun): HTMLElement {
  const card = buildCard(a.run, agentSummary(a.run), { chips: false, flowNote: "이 실행의 흐름", flowTip: "이 실행이 한 일을 실행 흐름으로 보기" });
  // 3-7: 자세히 = 세 단락
  const det = card.querySelector("details.install-detail");
  if (det) det.replaceChildren(el("summary", undefined, "자세히"), ...agentDetail(a.run));
  // 5-2a: 카드 오른쪽 위 [외부 통신 차단…] — 파괴적 위계(빨간 테두리), 오른쪽 끝
  const status = el("div", "agent-block-status");
  const head = card.querySelector(".card-head");
  head?.append(withIcon(button("외부 통신 차단…", () => blockDialog(a, status), "btn small danger head-act"), "ban"));
  card.append(status);
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
  root.append(el("h1", undefined, "AI 에이전트"));
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
    const listCut = (r.result.total ?? r.result.items.length) > r.result.items.length;
    for (const g of groupByTool(r.result.items)) {
      const head = el("h2", undefined, g.display);
      head.append(el("span", "badge count", runCountText(g.runs.length, listCut)));
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
