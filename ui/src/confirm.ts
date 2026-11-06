// 60초 확인 카운트다운 (정책·끊기 공용). 승인 상태는 서비스가 든다: 기한 안에 confirm 을 못 보내면 서비스가 되돌린다.
// 남은 시간은 서비스가 준 confirm_deadline_ts(unix 초) 기준 — UI 시계가 어긋나면 표시만 틀린다 (15차 Q7).
import { mutation, type Approval } from "./rpc";
import { el, button, errorBox } from "./ui";

export interface ApplyReply {
  policy_id: number;
  version: number;
  filters: number;
  confirm_deadline_ts: number;
  warnings: string[];
  address_block_notice?: string;
}

export function countdown(a: ApplyReply, owner: HTMLElement, onDone: () => void, label = ""): HTMLElement {
  const box = el("div", "card alert");
  const txt = el("div", "big");
  // 검수 A5: 내부 번호·WFP 용어("필터")를 제목에 내지 않는다 — 번호는 툴팁에
  const h = el("h3", undefined, `${label}적용했습니다 (판 ${a.version}) — 자동 되돌림까지`);
  h.title = `정책 번호 #${a.policy_id} · WFP 필터 ${a.filters}개`;
  box.append(h, txt, el("p", "muted", "60초 안에 ‘유지’를 누르지 않으면 서비스가 자동으로 되돌립니다."));
  let t = 0;
  const stop = () => window.clearInterval(t);
  const confirm = button("유지 (확인)", async () => {
    const r = await mutation("policy.confirm", { policy_id: a.policy_id, version: a.version });
    if (!r.ok) return txt.replaceChildren(errorBox(`확인 실패: ${r.error.message}`));
    stop();
    box.replaceChildren(el("div", "ok", "유지했습니다"));
    onDone();
  }, "btn primary");
  const rollback = button("되돌리기", async () => {
    const r = await mutation("policy.rollback", { policy_id: a.policy_id });
    stop();
    box.replaceChildren(r.ok ? el("div", "ok", "되돌렸습니다") : errorBox(r.error.message));
    onDone();
  });
  box.append(el("div", "actions", rollback, confirm));
  const render = () => {
    const left = a.confirm_deadline_ts - Math.floor(Date.now() / 1000);
    txt.textContent = left > 0 ? `${left}초` : "기한 지남 — 서비스가 되돌렸습니다(목록을 새로 읽는 중)";
    if (left <= 0) {
      stop();
      // 서비스가 되돌릴 시간을 조금 준 뒤 목록·표를 새로 읽는다(되돌린 뒤에도 '걸림'으로 보이던 것)
      window.setTimeout(onDone, 3000);
    }
  };
  render();
  t = window.setInterval(render, 500);
  owner.addEventListener("screen-leave", stop);
  return box;
}

/// 승인 창을 거친 결과: 60초 확인은 승인 창에서 이미 끝났다. 정책의 지금 상태만 보여 준다
export function approvalBox(ap: Approval, label = ""): HTMLElement {
  const box = el("div", "card approval");
  if (!ap.policies.length) box.append(el("div", "ok", `${label}적용했습니다 (승인 창)`));
  for (const p of ap.policies) {
    const kept = p.state === "Confirmed";
    const back = p.state === "RolledBack";
    box.append(el("div", kept ? "ok" : back ? "warn" : "muted", `${label}정책 #${p.policy_id}: ${kept ? "유지됨 (승인 창에서 확인)" : back ? "되돌렸습니다" : `상태 ${p.state ?? "알 수 없음"} — 60초 안에 확인하지 않으면 서비스가 되돌립니다`}`));
  }
  return box;
}
