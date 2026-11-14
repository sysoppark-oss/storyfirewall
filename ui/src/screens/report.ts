// 보고서 만들기(통합프로젝트 「상세 보고서 기능 — 공통 규칙과 개발 의뢰 (1판)」 1장, 3.3 의 1단계).
// 구역을 고르고 → 기간 → 가리기 → [만들기] → (진행·취소) → 저장 위치는 코어의 저장 대화상자에서 사용자가 고른다 → [열기] [폴더 열기].
// 자료는 기존 조회 메서드(읽기 전용)로만 받는다. 서비스는 파일을 쓰지 않는다. 업로드·보내기 단추는 없다(2.3).
import { rpc } from "../rpc";
import { state } from "../state";
import { el, button, clear } from "../ui";
import {
  SECTIONS_1, type SectionId, type Section, type Period, type PeriodKind, type REvent, type RBlocked, type RPolicy, type RAddressBlock, type RHistory,
  periodOf, incidentsSection, blockedSection, policySection, makeReport, saveReport, openReport,
} from "../report";

/// 뒤 단계에서 넣을 구역(3.3 의 2·3단계) — 고를 수 없다는 것을 보여 준다
const LATER = ["대시보드 요약", "네트워크", "설치 이력", "AI 에이전트 감시", "설정 › 진단"];
const EVENTS_PAGE = 200;
const EVENTS_MAX = 2000;
/// blocked.recent 의 limit 상한(1~1000). 기간 안이 더 많으면 구역 설명에 "N건 가운데 최근 1000건만"이라고 적힌다
const BLOCKED_LIMIT = 1000;
const POLICY_HISTORY_MAX = 200;

class Cancelled extends Error {}

/// 사건 목록을 쪽마다 받아 모은다(처리 상태와 관계없이 전부, 낮음 포함). partial = 끝까지 받지 못함
export async function collectEvents(alive: () => boolean, call: typeof rpc = rpc): Promise<{ events: REvent[]; partial: boolean; error?: string }> {
  const events: REvent[] = [];
  let after: string | undefined;
  for (;;) {
    if (!alive()) throw new Cancelled();
    const r = await call<{ items: REvent[]; next?: string | null }>("story.events", { level_min: "normal", triage: "all", cursor: { limit: EVENTS_PAGE, ...(after ? { after } : {}) } });
    if (!r.ok) return { events, partial: true, error: r.error.message };
    events.push(...(r.result.items ?? []));
    const next = r.result.next;
    if (!next || !(r.result.items ?? []).length) return { events, partial: false };
    if (events.length >= EVENTS_MAX) return { events, partial: true };
    after = String(next);
  }
}

export function reportScreen(): HTMLElement {
  const root = el("div", "screen report-make");
  root.append(el("h2", undefined, "보고서 만들기"));
  root.append(el("p", "muted", "고른 메뉴의 기록을 HTML 한 파일로 저장합니다. 브라우저로 열어 보고, 브라우저 인쇄로 PDF를 만들 수 있습니다. 파일은 고르신 위치에만 저장하며 어디로도 보내지 않습니다."));

  // 1) 구역
  const secBox = el("fieldset", "card");
  secBox.append(el("legend", undefined, "담을 메뉴"));
  const checks = new Map<SectionId, HTMLInputElement>();
  for (const s of SECTIONS_1) {
    const c = el("input");
    c.type = "checkbox";
    c.checked = true;
    checks.set(s.id, c);
    secBox.append(el("label", "block", c, ` ${s.title}`));
  }
  secBox.append(el("p", "muted small", `다음 판에서 더합니다: ${LATER.join(", ")}`));

  // 2) 기간
  const perBox = el("fieldset", "card");
  perBox.append(el("legend", undefined, "기간"));
  const kinds: [PeriodKind, string][] = [["today", "오늘"], ["7d", "최근 7일"], ["30d", "최근 30일"], ["custom", "직접"]];
  const radios = new Map<PeriodKind, HTMLInputElement>();
  const from = el("input");
  const to = el("input");
  from.type = to.type = "date";
  from.setAttribute("aria-label", "시작 날짜");
  to.setAttribute("aria-label", "끝 날짜");
  const custom = el("span", "report-custom", " ", from, " ~ ", to);
  for (const [k, label] of kinds) {
    const r = el("input");
    r.type = "radio";
    r.name = "report-period";
    r.checked = k === "7d";
    r.addEventListener("change", () => { custom.hidden = !radios.get("custom")!.checked; });
    radios.set(k, r);
    perBox.append(el("label", "block", r, ` ${label}`, ...(k === "custom" ? [custom] : [])));
  }
  custom.hidden = true;
  perBox.append(el("p", "muted small", "정책은 기간이 없는 메뉴라 만든 시각 기준으로 적습니다(변경 이력만 기간으로 거릅니다)."));

  // 3) 가리기
  const maskBox = el("fieldset", "card");
  maskBox.append(el("legend", undefined, "가리기"));
  const mask = el("input");
  mask.type = "checkbox";
  mask.checked = true;
  maskBox.append(el("label", "block", mask, " 남에게 보여 줄 수 있게 가리기"));
  maskBox.append(el("p", "muted small", "내부 주소는 ‘내부-1’처럼, PC 이름·사용자 이름은 ‘PC-1’·‘사용자’로, MAC 주소는 앞 절반만 남깁니다. 바깥 목적지 주소와 도메인은 가리지 않습니다 — 보는 사람이 판단할 대상입니다."));

  const out = el("div", "report-out");
  out.setAttribute("role", "status");
  let running: { cancelled: boolean } | null = null;
  const make = button("만들기", () => void start(), "btn primary");
  const cancel = button("취소", () => { if (running) running.cancelled = true; }, "btn");
  cancel.hidden = true;
  root.append(secBox, perBox, maskBox, el("div", "actions", make, cancel), out);
  root.addEventListener("screen-leave", () => { if (running) running.cancelled = true; });

  const say = (text: string, cls = "muted") => out.replaceChildren(el("p", cls, text));

  /// 가리기를 끄면 저장 전에 한 번 확인(2.4)
  const confirmUnmasked = () => new Promise<boolean>((resolve) => {
    const dlg = el("dialog", "ack");
    dlg.append(
      el("h3", undefined, "가리지 않고 만들까요?"),
      el("p", undefined, "내부 주소, PC 이름이 그대로 들어갑니다."),
      el("div", "actions", button("돌아가기", () => dlg.close("no"), "btn"), button("가리지 않고 만들기", () => dlg.close("yes"), "btn danger")),
    );
    document.body.append(dlg);
    dlg.addEventListener("close", () => { dlg.remove(); resolve(dlg.returnValue === "yes"); });
    dlg.showModal();
  });

  async function start() {
    if (running) return;
    const picked = SECTIONS_1.filter((s) => checks.get(s.id)!.checked).map((s) => s.id);
    if (!picked.length) return say("담을 메뉴를 하나 이상 골라 주세요.", "warn");
    const now = Math.floor(Date.now() / 1000);
    const kind = kinds.find(([k]) => radios.get(k)!.checked)![0];
    const period = periodOf(kind, now, from.value, to.value);
    if (!period) return say("시작 날짜와 끝 날짜를 확인해 주세요(시작이 끝보다 뒤일 수 없습니다).", "warn");
    // 앞서 만든 결과 줄이 확인 창 뒤에 남아 지금 것처럼 보이지 않게 먼저 지운다
    clear(out);
    if (!mask.checked && !(await confirmUnmasked())) return;
    const run = (running = { cancelled: false });
    const alive = () => !run.cancelled;
    make.disabled = true;
    cancel.hidden = false;
    try {
      const sections: Section[] = [];
      const warns: string[] = [];
      for (const [i, id] of picked.entries()) {
        const title = SECTIONS_1.find((s) => s.id === id)!.title;
        say(`${title} 기록을 모으는 중… (${i + 1}/${picked.length})`);
        const sec = await collect(id, period, now, alive, warns);
        if (!alive()) throw new Cancelled();
        sections.push(sec);
      }
      say("저장 위치를 골라 주세요…");
      const r = await saveReport(makeReport(sections, period, now, state.serverVersion || "판 모름", mask.checked), now);
      if (!r.ok) return say(`보고서를 만들지 못했습니다: ${r.message}`, "error");
      if (!r.saved) return say("저장을 취소했습니다. 파일은 만들지 않았습니다.");
      const note = el("p", "muted small");
      const open = (what: "file" | "folder") => void openReport(what).then((e) => { note.textContent = e ?? ""; });
      out.replaceChildren(
        el("p", "ok", `저장했습니다 (${Math.max(1, Math.round(r.bytes / 1024))} KB, ${mask.checked ? "가리기 켬" : "가리기 끔"})`),
        el("p", "mono", r.path),
        ...warns.map((w) => el("p", "warn small", w)),
        el("div", "actions", button("열기", () => open("file"), "btn primary"), button("폴더 열기", () => open("folder"), "btn")),
        note,
      );
    } catch (e) {
      if (e instanceof Cancelled) say("취소했습니다. 파일은 만들지 않았습니다.");
      else say(`보고서를 만들지 못했습니다: ${String(e).slice(0, 200)}`, "error");
    } finally {
      running = null;
      make.disabled = false;
      cancel.hidden = true;
    }
  }
  return root;
}

/// 구역 하나의 자료를 받아 모형으로. 못 받은 것은 0건으로 그리지 않고 구역 설명·경고에 적는다
async function collect(id: SectionId, period: Period, now: number, alive: () => boolean, warns: string[]): Promise<Section> {
  if (id === "incidents") {
    const got = await collectEvents(alive);
    if (got.error) warns.push(`인시던트 목록을 끝까지 받지 못했습니다(${got.error}). 받은 ${got.events.length}건만 실었습니다.`);
    return incidentsSection(got.events, period, got.partial);
  }
  if (id === "blocked") {
    const r = await rpc<{ items: RBlocked[]; matched?: number; total?: number; oldest?: number | null }>("blocked.recent", { limit: BLOCKED_LIMIT, q: "", since: period.from });
    if (!r.ok) {
      warns.push(`차단 기록을 받지 못했습니다(${r.error.message}).`);
      const sec = blockedSection([], period);
      sec.notes.unshift("차단 기록을 받지 못했습니다 — 아래는 ‘없음’이 아니라 ‘받지 못함’입니다.");
      return sec;
    }
    return blockedSection(r.result.items ?? [], period, { matched: r.result.matched, ringTotal: r.result.total, oldest: r.result.oldest ?? null });
  }
  const list = await rpc<{ items: RPolicy[]; address_block_items?: RAddressBlock[] }>("policy.list", {});
  if (!list.ok) {
    warns.push(`정책 목록을 받지 못했습니다(${list.error.message}).`);
    const sec = policySection([], [], [], period, now);
    sec.notes.unshift("정책 목록을 받지 못했습니다 — 아래는 ‘없음’이 아니라 ‘받지 못함’입니다.");
    return sec;
  }
  const history: RHistory[] = [];
  let missing = 0;
  for (const p of list.result.items.slice(0, POLICY_HISTORY_MAX)) {
    if (!alive()) throw new Cancelled();
    const h = await rpc<{ items: { ts: number; action: string; result: string; actor: string }[] }>("policy.history", { policy_id: p.id });
    if (!h.ok) { missing++; continue; }
    for (const x of h.result.items ?? []) history.push({ policy: p.name, ts: x.ts, action: String(x.action), result: String(x.result), actor: String(x.actor) });
  }
  missing += Math.max(0, list.result.items.length - POLICY_HISTORY_MAX);
  if (missing) warns.push(`정책 ${missing}건의 변경 이력은 받지 못했습니다.`);
  return policySection(list.result.items, list.result.address_block_items ?? [], history, period, now, missing);
}

/// 사건 카드의 [이 건 보고서] 결과 한 줄
export function savedLine(path: string): string {
  return `보고서를 저장했습니다(가리기 켬): ${path}`;
}
