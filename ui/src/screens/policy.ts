import { mutation, rpc, uuid } from "../rpc";
import { countByPolicy, type RuleSum } from "./blocked-log";
import { approvalBox, countdown, type ApplyReply } from "../confirm";
import { el, ext, button, clear, errorBox, fmtShort, extPath } from "../ui";
import { failBox } from "../list-state";
import { state } from "../state";
import { aclEditor } from "./acl";

interface Validation {
  errors: string[];
  warnings: string[];
  needs_ack: [string, string][];
}
interface AddressBlock {
  filter_id: number;
  policy_id: number;
  policy_name: string;
  address: string;
  expires_at: number | null;
}
interface PolicyRow {
  id: number;
  name: string;
  state: string;
  version: number;
  state_ko?: string;
  state_tip?: string;
  summary?: string;
  expires?: string | null;
  created_ts?: number | null;
  origin?: { kind: "story"; root: number; label: string } | { kind: "manual" } | { kind: "first_run_watch" };
  confirm_deadline?: number | null;
  /// 첫 실행 관찰실 우산 정책 아래 지금 걸린 기한부 실행 파일 차단
  child_blocks?: { filter_id: number; path: string | null; expires_at: number | null }[];
  /// ACL 정책 관리: "ACL" 기록의 원문(정책 화면 ACL 표가 다시 읽는다)
  acl_yaml?: string;
}
/// 상태 칩 색(D006-4): 적용 중 초록, 확인 대기·일시 중지 주황, 만료·되돌림 회색
const STATE_CLS: Record<string, string> = { Confirmed: "ok", Applied: "warn", Paused: "warn", Expired: "muted", RolledBack: "muted" };

const SAMPLE = `- name: block-updater
  action: block
  match:
    direction: out
    process: ['C:/Users/pjg/AppData/Local/Temp/payload.exe']
`;

const ACK_TEXT: Record<string, string> = {
  self: "이 정책은 Story Firewall 자신의 통신을 막을 수 있습니다.",
  wide: "이 정책은 매우 넓은 범위(전체 또는 대부분의 통신)를 막습니다.",
  svchost: "이 정책은 시스템 서비스 호스트(svchost)의 통신을 막습니다.",
};

/// 정책: YAML 편집 → 검증 → 적용(needs_ack 확인 대화상자) → 60초 확인 카운트다운 → 롤백·일시 중지.
/// 승인 상태는 서비스가 든다: 60초 안에 confirm 을 못 보내면 서비스가 되돌린다 (10차).
export function policy(args: Record<string, unknown> = {}): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "정책"));
  const ta = el("textarea", "yaml");
  ta.value = SAMPLE;
  ta.spellcheck = false;
  const out = el("div", "out");
  const pending = el("div", "pending");
  const list = el("div", "list");

  const showValidation = (v: Validation) => {
    clear(out);
    for (const e of v.errors) out.append(el("div", "error", ext("span", e)));
    for (const w of v.warnings) out.append(el("div", "warn", ext("span", w)));
    if (!v.errors.length && !v.warnings.length) out.append(el("div", "ok", "검증 통과"));
    for (const [name, kind] of v.needs_ack) out.append(el("div", "warn", `확인 필요: `, ext("span", name), ` — ${ACK_TEXT[kind] ?? kind}`));
  };

  const validate = async (yaml: string = ta.value) => {
    const r = await rpc<Validation>("policy.validate", { yaml });
    if (!r.ok) return out.replaceChildren(errorBox(r.error.message));
    showValidation(r.result);
  };

  /// needs_ack 대화상자: 사용자가 항목마다 확인해야 적용으로 간다
  const askAck = (items: [string, string][]): Promise<boolean> =>
    new Promise((resolve) => {
      const dlg = el("dialog", "ack");
      dlg.append(el("h3", undefined, "적용 전 검토"));
      for (const [name, kind] of items) dlg.append(el("p", undefined, ext("b", name), ` — ${ACK_TEXT[kind] ?? kind}`));
      const yes = button("검토 후 적용", () => { dlg.close(); resolve(true); }, "btn danger");
      const no = button("취소", () => { dlg.close(); resolve(false); });
      dlg.append(el("div", "actions", no, yes));
      document.body.append(dlg);
      dlg.showModal();
      dlg.addEventListener("close", () => dlg.remove());
    });

  const apply = async (yaml: string = ta.value): Promise<boolean> => {
    const requestId = uuid(); // 재시도해도 같은 id (멱등)
    let r = await mutation("policy.apply", { yaml }, requestId);
    if (!r.ok && r.error.code === -32003) {
      const items = ((r.error.data as { items?: [string, string][] } | undefined)?.items) ?? [];
      if (!(await askAck(items))) return false;
      r = await mutation("policy.apply", { yaml, acknowledge: items }, requestId);
    }
    if (!r.ok) {
      out.replaceChildren(errorBox(`적용 실패: ${r.error.message}`));
      return false;
    }
    const a = r.result as ApplyReply;
    showValidation({ errors: [], warnings: a.warnings, needs_ack: [] });
    if (a.address_block_notice) out.append(el("div", "warn", ext("span", a.address_block_notice)));
    clear(out); // 검수 38-3: 적용하면 지난 검증 결과("검증 통과")를 지운다
    if (r.approval) {
      clear(pending);
      pending.append(approvalBox(r.approval));
    } else startCountdown(a);
    void refreshList();
    return true;
  };

  // 위 카드가 세는 정책 번호 — 목록 줄은 같은 정책의 카운트다운을 다시 세지 않는다(검수: 두 곳에서 겹쳐 셈)
  let cardPolicyId: number | null = null;
  const startCountdown = (a: ApplyReply) => {
    clear(pending);
    cardPolicyId = a.policy_id;
    pending.append(countdown(a, root, () => { cardPolicyId = null; void refreshList(); }));
  };

  // ACL 표(위): 처음 목록을 받을 때 한 번만 지금 걸린 ACL 을 읽는다(편집 중인 표를 새로 고침이 덮지 않게)
  const acl = aclEditor((y) => void apply(y).then((ok) => { if (ok) acl.markApplied(y); }), (y) => void validate(y));
  let aclLoaded = false;
  // 정책 목록을 못 받았을 때의 안내 자리(화면 맨 위). ACL 표는 처음 받을 때까지 숨긴다 — 빈 상자를 그리지 않는다
  const listNote = el("div", "list-note");
  acl.root.hidden = true;
  const refreshList = async () => {
    const r = await rpc<{ items: PolicyRow[]; address_blocks?: number; address_block_items?: AddressBlock[] }>("policy.list", {});
    clear(listNote);
    if (!r.ok) {
      // UI 명세 5판 2장: 못 받았다는 안내는 화면 맨 위에(전에는 "정책 변경 이력" 제목 아래라 이력 조회가 실패한 것처럼 읽혔다).
      // 이미 그린 목록·ACL 표는 지우지 않는다. 처음부터 못 받았으면 빈 ACL 상자 대신 이 안내만, 이력 자리에는 "—"
      listNote.append(failBox(r.error, () => void refreshList(), "활성 정책"));
      if (!aclLoaded) list.replaceChildren(el("p", "muted", "— 정책 목록을 받으면 여기에 나옵니다."));
      return;
    }
    // 정책별 누적 차단 수(차단 기록의 규칙별 누적에서). 못 받으면 링크를 만들지 않을 뿐이다 — 0 으로 그리지 않는다
    const br = await rpc<{ rules?: RuleSum[] }>("blocked.recent", { limit: 1 });
    const blockedN = br.ok ? countByPolicy(br.result.rules ?? []) : new Map<number, number>();
    clear(list);
    acl.root.hidden = false;
    // 지금 걸린 ACL = 적용(확인 대기)·확인됨 상태만. 되돌림·일시 중지·만료는 걸려 있지 않다
    const live = r.result.items.find((x) => x.acl_yaml && (x.state === "Applied" || x.state === "Confirmed"));
    if (!aclLoaded) {
      aclLoaded = true;
      // 지금 열린 연결 › [접속지 차단…]: 채운 새 규칙 대화상자를 연다(외부 문자열은 IP 형식만 받는다)
      const add = args["aclAdd"] as { remote?: unknown } | undefined;
      if (add && typeof add.remote === "string" && /^[0-9a-fA-F:.]{2,45}$/.test(add.remote)) {
        const remote = add.remote;
        window.setTimeout(() => acl.prefill({ action: "block", dir: "out", dstIp: remote }), 0);
      }
      // 걸린 ACL 이 없으면 마지막 ACL(되돌림·일시 중지 포함)을 '걸려 있지 않은 표'로 보여 준다 — 되돌린 뒤 빈 표가 되어 다시 입력하던 것(노트북 제보)
      const row = live ?? r.result.items.find((x) => x.acl_yaml);
      acl.load(row?.acl_yaml ?? null, live?.acl_yaml ?? null);
    } else acl.setActive(live?.acl_yaml ?? null);
    // D032-3: 비어 있음(2-5)
    if (!r.result.items.length) list.append(el("p", "muted", "아직 만든 정책이 없습니다. 위 ACL 표, 이야기 카드의 '격리·차단…' 또는 아래 '고급'에서 만들 수 있습니다."));
    for (const p of r.result.items) {
      // D006-4: [상태 칩] 이름 · 한국어 요약 · 만료 · 만든 곳 · (오른쪽) 일시 중지 / 되돌리기. 영어 상태 문자열을 보이지 않는다
      const chip = el("span", `chip state ${STATE_CLS[p.state] ?? "muted"}`, p.state_ko ?? "알 수 없음");
      if (p.state_tip) chip.title = p.state_tip;
      const name = ext("span", p.name, "title");
      const ver = el("span", "muted", `판 ${p.version}`);
      ver.title = `정책 번호 #${p.id}`;
      const meta = el("div", "policy-meta");
      if (p.summary) meta.append(extPath("span", p.summary, "summary"));
      if (p.expires) meta.append(el("span", "muted", ` · 만료 ${p.expires}`));
      if (p.origin?.kind === "story") {
        const o = p.origin;
        const when = p.created_ts ? `, ${fmtShort(p.created_ts)}` : "";
        const link = el("a", "origin", `이야기에서(${o.label}${when})`);
        link.href = "#";
        link.addEventListener("click", (e) => { e.preventDefault(); state.go("story", { root: o.root }); });
        meta.append(el("span", "muted", " · "), link);
      } else if (p.origin?.kind === "first_run_watch") {
        meta.append(el("span", "muted", " · 설정에서(첫 실행 관찰실)"));
      } else {
        meta.append(el("span", "muted", " · 직접 작성"));
      }
      // UI 명세 5판 1장: "이 정책으로 막힌 기록 N건 ›" → 네트워크 › 차단 기록을 그 정책으로 걸러 연다. 막힌 것이 없으면 줄을 만들지 않는다
      const hits = blockedN.get(p.id) ?? 0;
      if (hits > 0) {
        const link = el("a", "origin", `이 정책으로 막힌 기록 ${hits}건 ›`);
        link.href = "#";
        link.addEventListener("click", (e) => { e.preventDefault(); state.go("connections", { tab: "blocked", policy: p.id, policyName: p.name }); });
        meta.append(el("span", "muted", " · "), link);
      }
      const row = el("div", "row policy-row", el("div", "policy-main", el("div", "policy-head", chip, " ", name, " ", ver), meta), el("span", "spacer"));
      // D007-1: 확인 대기 — 남은 시간(1초 갱신, 주황) + 주 단추 "승인(유지)". 확인은 기존 경로(mutation: 보기 모드면 승인 창)
      if (p.state === "Applied" && p.confirm_deadline && p.id === cardPolicyId) {
        row.append(el("span", "muted", "위 카드에서 유지/되돌리기"));
      } else if (p.state === "Applied" && p.confirm_deadline) {
        const left = el("span", "warn countdown-inline");
        const tick = () => {
          const s = p.confirm_deadline! - Math.floor(Date.now() / 1000);
          left.textContent = s > 0 ? `자동 되돌림까지 ${s}초` : "기한 지남 — 새로 고침";
          if (s <= 0) window.clearInterval(t);
        };
        const t = window.setInterval(tick, 1000);
        tick();
        root.addEventListener("screen-leave", () => window.clearInterval(t));
        row.append(left, button("승인(유지)", async () => {
          const r2 = await mutation("policy.confirm", { policy_id: p.id, version: p.version });
          if (!r2.ok) out.replaceChildren(errorBox(`확인 실패: ${r2.error.message}`));
          void refreshList();
        }, "btn small primary"));
      }
      // 이미 되돌렸거나 만료된 정책에는 걸 것이 없으므로 단추를 두지 않는다(노트북 확인 2026-11-06)
      // 검수 38-4: 위 카드가 확인을 기다리는 동안에는 같은 동작을 줄에 또 두지 않는다
      if (p.state !== "RolledBack" && p.state !== "Expired" && p.id !== cardPolicyId) {
        row.append(
          button("일시 정지", async () => { await mutation("policy.pause", { policy_id: p.id }); void refreshList(); }, "btn small"),
          button("되돌리기", async () => { await mutation("policy.rollback", { policy_id: p.id }); void refreshList(); }, "btn small"),
        );
      }
      list.append(row);
      // 우산 아래 자동 차단: 실행 파일 · 만료 · 줄마다 해제(같은 필터 해제 경로)
      for (const c of p.child_blocks ?? []) {
        const crow = el("div", "row ab-row", el("span", "muted", "└ 자동 차단 "), extPath("span", c.path ?? "", "mono"), el("span", "muted", ` · ${expiryText(c.expires_at)}`), el("span", "spacer"));
        crow.append(button("해제", async () => { await mutation("policy.release_address_blocks", { policy_id: p.id, filter_id: c.filter_id }); void refreshList(); }, "btn small"));
        list.append(crow);
      }
    }
    // D036: 해제될 주소 차단이 무엇인지 — "주소 차단 필터 (N)" 소단락: 주소 · 만든 곳 · 만료 · 줄마다 해제. 모두 해제는 그 끝(빨간 테두리)
    const nBlocks = r.result.address_blocks;
    const items = r.result.address_block_items ?? [];
    if (items.length) {
      const sec = el("div", "address-blocks", el("h3", undefined, `주소 차단 (${items.length})`));
      for (const b of items) {
        const pol = r.result.items.find((p) => p.id === b.policy_id);
        const from = pol?.origin?.kind === "story" ? `이야기에서(${pol.origin.label}${pol.created_ts ? `, ${fmtShort(pol.created_ts)}` : ""})` : "직접 작성";
        const row = el("div", "row ab-row", ext("span", b.address, "mono"), el("span", "muted", " · "), ext("span", from, "muted"), el("span", "muted", ` · ${expiryText(b.expires_at)}`), el("span", "spacer"));
        row.append(button("해제", async () => { await mutation("policy.release_address_blocks", { policy_id: b.policy_id, filter_id: b.filter_id }); void refreshList(); }, "btn small"));
        sec.append(row);
      }
      list.append(sec);
    }
    // 파괴적 동작: 소단락 끝 오른쪽, 빨간 테두리(승인 창 경유는 그대로, 승인 창에도 주소 목록). D032-3: 지울 것이 있을 때만(예전 서비스면 수를 몰라 보인다)
    if (showReleaseAll(nBlocks)) {
      const rel = button(nBlocks ? `주소 차단 ${nBlocks}건 모두 해제` : "주소 차단 필터 모두 해제", async () => { await mutation("policy.release_address_blocks", { policy_id: 0 }); void refreshList(); }, "btn small danger-outline");
      list.append(el("div", "actions", el("span", "spacer"), rel));
    }
  };

  // 고급 — YAML 직접 편집(기본 닫힘)
  const adv = el("details", "advanced");
  adv.append(
    el("summary", undefined, "고급 — 정책 DSL(YAML) 편집"),
    el("div", "editor", ta, el("div", "actions", button("구문 검증", () => void validate()), button("적용", () => void apply(), "btn primary"))),
  );
  root.append(listNote, acl.root, out, pending, el("h2", undefined, "정책 변경 이력"), list, adv);
  void refreshList();
  state.onNotify(root, (n) => {
    const k = String(n.params["kind"] ?? "");
    if (k.startsWith("policy_") || k === "auto_rollback") void refreshList();
  });
  return root;
}

/// D032-3: "주소 차단 필터 모두 해제"는 지울 것이 있을 때만. 수를 모르면(예전 서비스) 보인다
export function showReleaseAll(n: number | undefined): boolean {
  return n == null || n > 0;
}

/// D036: 만료 — "오늘 오후 11:59까지" 꼴(fmtShort 가 오늘·날짜를 정한다), 없으면 "기한 없음"
export function expiryText(at: number | null | undefined, now: Date = new Date()): string {
  if (!at) return "기한 없음";
  const d = new Date(at * 1000);
  const today = d.toDateString() === now.toDateString();
  return `${today ? "오늘 " : ""}${fmtShort(at, now)}까지`;
}
