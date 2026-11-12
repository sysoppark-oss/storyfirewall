// 공통 상단 띠(UI 명세 4판 3-1): 모든 화면 위에 보호 서비스 상태·엔진 뱃지·정책 수와 긴급 차단 단추를 둔다.
// 전에는 대시보드에만 있어서 다른 화면에서는 긴급 차단을 누를 수도, 걸려 있는지 볼 수도 없었다.
// - 뱃지는 모두 단추(누르면 설정 › 진단 또는 정책 화면). 누를 수 있게 보이면 실제 button(2판 원칙 9).
// - 긴급 차단 단추는 빨간 테두리(채움 아님, 2판 2-4). 차단 중이면 상태 단추 + 띠 아래 빨간 선.
// - 남은 시간은 분 단위, 마지막 5분만 m:ss(4판 1-1: 매초 바뀌는 숫자는 불안을 키우고 화면 읽기 프로그램을 시끄럽게 한다).
import { rpc, mutation } from "./rpc";
import { el, button } from "./ui";
import { engineStuckText, state } from "./state";
import { collectionStalled, type HealthLike } from "./list-state";
import { icon } from "./screens/dash-viz";
import { LastGood } from "./last-good";
import { bytes } from "./screens/connections";

/// collector.health 중 띠가 쓰는 것
export interface TopHealth extends HealthLike {
  timings?: { name: string; last_ms: number }[];
  wfp_filters?: number;
  db_bytes?: number | null;
}

/// 긴급 차단 상태(emergency.status) — 대시보드 개편안 3판 1-1
export interface EmergencyStatus {
  active: boolean;
  policy_id?: number;
  version?: number;
  expires_at?: number;
  remaining_secs?: number;
  confirmed?: boolean;
  /// 걸려 있지 않을 때: 지금 통신 중인 원격 도구(대화상자가 예외 칸을 미리 채움)
  suggested_tools?: { display: string; path: string }[];
}

/// 남은 시간 문구(순수 함수 — 시험용): 5분 넘으면 분(올림), 1시간 넘으면 시간+분, 5분 이하는 m:ss
export function leftText(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  if (s <= 300) return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")} 남음`;
  const m = Math.ceil(s / 60);
  return m >= 60 ? `${Math.floor(m / 60)}시간 ${m % 60}분 남음` : `${m}분 남음`;
}

/// 상단 띠의 긴급 차단 문구(순수 함수 — 시험용). 걸려 있지 않으면 null. `left` 를 주면 그 값(초)을 쓴다(띠의 1초 갱신)
export function emergencyText(st: EmergencyStatus | null, left?: number): string | null {
  if (!st || !st.active) return null;
  if (st.confirmed === false) return "긴급 차단 · 유지 확인 대기";
  return `긴급 차단 중 · ${leftText(left ?? st.remaining_secs ?? 0)}`;
}

/// 엔진 뱃지 문구(순수 함수 — 시험용). 수치가 없으면 그 뱃지는 뺀다(개편안 2판 3-2)
/// policies 가 null 이면 정책 수를 받지 못한 것 — 0 이 아니라 "정책 —"(UI 명세 5판 2장: 모르는 값을 0 으로 그리지 않는다)
export function engineBadges(h: TopHealth | null, policies: number | null, pending: number): string[] {
  const out: string[] = [];
  const j = h?.timings?.find((t) => t.name === "엔진: 주기 판정");
  if (j) out.push(`판정 지연 ${j.last_ms}ms`);
  if (typeof h?.wfp_filters === "number") out.push(`필터 ${h.wfp_filters}개`);
  if (typeof h?.db_bytes === "number") out.push(`DB ${bytes(h.db_bytes)}`);
  if (policies === null) out.push("정책 —");
  else out.push(pending ? `정책 ${policies}개 (확인 대기 ${pending})` : `정책 ${policies}개`);
  return out;
}

/// 보호 서비스 한 단어(순수 함수 — 시험용): 연결 끊김 / 기록 멈춤? / 작동 중 · 응답 늦음 / 작동 중
export function serviceWord(connected: boolean, stalled: boolean, stuck: boolean): { word: string; tone: "ok" | "warn" } {
  if (!connected) return { word: "연결 끊김", tone: "warn" };
  if (stalled) return { word: "기록 멈춤?", tone: "warn" };
  if (stuck) return { word: "작동 중 · 응답 늦음", tone: "warn" };
  return { word: "작동 중", tone: "ok" };
}

/// 기준선 뱃지 문구(순수 함수 — 시험용). 다 모았으면 null
export function learnText(b: { pc_learned: boolean; days_left?: number }): string | null {
  if (b.pc_learned) return null;
  const d = b.days_left;
  return typeof d === "number" && d > 0 ? `기준선 수집 중 · ${d}일 남음` : "기준선 수집 중";
}

/// 긴급 차단·해제가 끝났다고 화면들에 알린다(대시보드 등이 다시 그림)
export const EMERGENCY_EVENT = "sf-emergency";

/// 긴급 차단 대화상자: 기한·원격 도구 예외를 고르고 승인 창으로 보낸다(서비스가 RDP 세션은 자동으로 예외)
/// `note`: 상태를 읽지 못한 채 여는 경우의 안내(5판 2장: 엔진이 바빠도 단추는 늘 누를 수 있다 — 대화상자 안에서 알린다)
export function emergencyDialog(done: () => void, suggested: { display: string; path: string }[] = [], note?: string) {
  const dlg = el("dialog", "ack");
  dlg.append(el("h3", undefined, "긴급 차단"));
  if (note) dlg.append(el("p", "warn small", note));
  dlg.append(el("p", undefined, "이 PC 의 나가는·들어오는 통신을 모두 막습니다. 예외: 이 PC 안 통신(루프백) · DNS · DHCP · 이 앱 · 지금 접속한 원격 데스크톱 세션의 상대 IP · 아래에 적은 원격 도구."));
  dlg.append(el("p", "muted small", "승인 창에서 확인한 뒤 60초 안에 [유지]를 눌러야 유지됩니다(원격으로 접속해 있다가 끊기면 자동으로 되돌아갑니다). 재부팅하면 풀립니다. 이미 열려 있는 연결도 끊길 수 있습니다. 예외로 연 원격 도구 안에 다른 프로그램이 숨어 들어가면 막지 못합니다."));
  const mins = el("select") as HTMLSelectElement;
  for (const [v, t] of [[15, "15분"], [30, "30분 (기본)"], [60, "1시간"], [120, "2시간"], [480, "8시간"]] as const) {
    const o = el("option", undefined, t) as HTMLOptionElement;
    o.value = String(v);
    if (v === 30) o.selected = true;
    mins.append(o);
  }
  dlg.append(el("label", undefined, "기한 ", mins));
  // D039: 경로는 고정폭 글꼴(한국어 글꼴은 \ 를 ₩ 로 그린다)
  const tools = el("textarea", "mono") as HTMLTextAreaElement;
  tools.rows = 3;
  tools.placeholder = "예외로 둘 원격 도구 실행 파일 경로(한 줄에 하나, 8개까지)\n예: C:\\Program Files\\TeamViewer\\TeamViewer.exe";
  tools.style.width = "100%";
  // 사용자 승인 2026-11-08: 지금 통신 중인 원격 도구를 미리 채운다(지우면 막힌다)
  tools.value = suggested.map((t) => t.path).join("\n");
  dlg.append(el("label", "block", "원격 도구 예외", tools));
  if (suggested.length) dlg.append(el("p", "muted small", `지금 통신 중인 원격 도구를 미리 넣었습니다: ${suggested.map((t) => t.display).join(", ")}. 지운 줄은 막힙니다.`));
  const out = el("div");
  const go = button("승인 창 열기", async () => {
    go.disabled = true;
    const list = tools.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean).slice(0, 8);
    const r = await mutation("emergency.start", { minutes: Number(mins.value), remote_tools: list });
    go.disabled = false;
    if (!r.ok) return out.replaceChildren(el("p", "error", `긴급 차단: ${r.error.message}`));
    dlg.close();
    dlg.remove();
    done();
  }, "btn danger");
  const cancel = button("취소", () => { dlg.close(); dlg.remove(); }, "btn");
  // 2판 2-4: 보조(취소) 왼쪽 → 파괴적(승인 창 열기, 빨간 테두리) 오른쪽 끝
  dlg.append(out, el("div", "actions", cancel, go));
  document.body.append(dlg);
  dlg.showModal();
}

/// 공통 상단 띠. 20초마다·엔진 상태가 바뀔 때·긴급 차단을 바꾼 뒤 다시 그린다. 차단 중 마지막 5분은 1초마다 남은 시간만 고친다
export function topbar(): { root: HTMLElement; refresh: () => Promise<void> } {
  const root = el("div", "topbar");
  root.setAttribute("role", "region");
  root.setAttribute("aria-label", "보호 상태");
  const badges = el("div", "tb-badges");
  const emg = el("div", "tb-emg");
  root.append(badges, emg);
  let gen = 0;
  let endAt = 0; // 긴급 차단 끝 시각(ms, 이 PC 시계) — 1초 갱신용
  let emgLabel: HTMLElement | null = null;
  let lastSt: EmergencyStatus | null = null;
  // 5판 2장: 엔진이 바빠 받지 못하면 마지막으로 받은 값을 쓴다(유효 기간 안에서만 — last-good)
  const kept = new LastGood();

  const toDiag = () => state.go("settings", { tab: "diag" });
  const badgeBtn = (cls: string, text: string, onClick: () => void, title?: string, ico?: string) => {
    const b = button("", onClick, `tb-badge ${cls}`.trim());
    if (ico) b.append(icon(ico), " ");
    b.append(text);
    if (title) b.title = title;
    return b;
  };

  const tick = () => {
    if (!emgLabel || !lastSt?.active || lastSt.confirmed === false) return;
    const left = (endAt - Date.now()) / 1000;
    if (left <= 300) emgLabel.textContent = emergencyText(lastSt, left);
    if (left <= 0) void refresh();
  };
  window.setInterval(tick, 1000);

  async function refresh(): Promise<void> {
    const my = ++gen;
    if (!state.connected) {
      const sw = serviceWord(false, false, false);
      badges.replaceChildren(badgeBtn(`badge-${sw.tone}`, `보호 서비스 ${sw.word}`, toDiag, "서비스가 멈췄거나 시작 중일 수 있습니다", "heart"));
      emg.replaceChildren();
      root.classList.remove("emg-on");
      return;
    }
    const [hr, pol0, er0, bl] = await Promise.all([
      rpc<TopHealth>("collector.health", {}),
      rpc<{ items: { state: string }[] }>("policy.list", {}),
      rpc<EmergencyStatus>("emergency.status", {}),
      rpc<{ pc_learned: boolean; days_left?: number }>("judge.baseline_status", {}),
    ]);
    if (my !== gen) return; // 더 새 갱신이 시작됐다(겹침 방지 — 대시보드 KPI 중복 결함과 같은 원인)
    const pol = kept.keep("policy.list", pol0);
    const er = kept.keep("emergency.status", er0);
    const h = hr.ok ? hr.result : null;
    const sw = serviceWord(true, !!h && collectionStalled(h), !!engineStuckText(state.engineBusyMs));
    const items = pol.ok ? pol.result.items : [];
    // 받지 못했으면(지난 값도 없으면) 0 이 아니라 null → "정책 —"
    const applied = pol.ok ? items.filter((p) => /^(applied|confirmed)$/i.test(p.state)).length : null;
    const pend = items.filter((p) => /^applied$/i.test(p.state)).length;
    const row: HTMLElement[] = [badgeBtn(`badge-${sw.tone}`, `보호 서비스 ${sw.word}`, toDiag, `서비스 ${state.serverVersion} · 누르면 진단`, "heart")];
    const extra = engineBadges(h, applied, pend);
    for (const t of extra) {
      const isPolicy = t.startsWith("정책 ");
      // tb-extra: 좁은 창에서 접히는 뱃지(4판 3-1) — 보호 서비스 뱃지와 긴급 차단은 접지 않는다
      // 확인 대기가 있는 정책 뱃지는 주의 색으로, 접지 않는다(검수: 경고까지 접혀 숨으면 안 됨)
      const warn = isPolicy && /확인 대기/.test(t);
      const polTitle = !pol.ok ? "정책 수를 아직 받지 못했습니다(엔진 바쁨) · 정책 화면" : pol.stale_at ? "엔진이 바빠 조금 전에 받은 값입니다 · 정책 화면" : "정책 화면";
      row.push(badgeBtn(warn ? "badge-warn" : "tb-extra", t, isPolicy ? () => state.go("policy", {}) : toDiag, isPolicy ? polTitle : "설정 › 진단"));
    }
    const nFold = row.filter((b) => b.classList.contains("tb-extra")).length;
    const moreText = () => (root.classList.contains("tb-expanded") ? "접기" : `⋯ ${nFold}개`);
    const more = button(moreText(), () => {
      const open = root.classList.toggle("tb-expanded");
      more.setAttribute("aria-expanded", String(open));
      more.textContent = moreText();
    }, "tb-badge tb-more");
    more.setAttribute("aria-expanded", String(root.classList.contains("tb-expanded")));
    more.title = "접힌 상태 뱃지 보기";
    // 4판 8-4: 기준선 수집 중 · N일 남음(애니메이션 없음). 탐지는 그대로 돈다는 것을 툴팁에 분명히
    const left = bl.ok ? learnText(bl.result) : null;
    if (left) row.push(badgeBtn("tb-learn", left, toDiag, "이 PC 의 프로그램별 평소 행동(기준선)을 모으는 기간입니다. 이 기간에는 '처음 보는' 판정이 많을 수 있습니다. 탐지는 그대로 동작합니다."));
    row.push(more);
    badges.replaceChildren(...row);

    // 긴급 차단
    const st = er.ok ? er.result : null;
    lastSt = st;
    emgLabel = null;
    const on = !!st?.active;
    root.classList.toggle("emg-on", on);
    if (on && st) {
      endAt = Date.now() + Math.max(0, st.remaining_secs ?? 0) * 1000;
      const label = el("span", "tb-emg-text", emergencyText(st) ?? "");
      emgLabel = label;
      const stat = button("", () => {
        const opened = menu.hasAttribute("hidden");
        menu.toggleAttribute("hidden");
        stat.setAttribute("aria-expanded", String(opened));
        if (opened) (menu.querySelector("button") as HTMLButtonElement | null)?.focus();
      }, "tb-badge badge-crit tb-emg-state");
      stat.dataset["cmd"] = "emg-state";
      stat.append(el("span", "tb-dot"), label, " ▾");
      stat.setAttribute("aria-haspopup", "true");
      stat.setAttribute("aria-expanded", "false");
      const menu = el("div", "tb-menu");
      menu.setAttribute("hidden", "");
      const off = button("지금 해제…", async () => {
        off.disabled = true;
        const r = await mutation("emergency.stop", {});
        off.disabled = false;
        if (!r.ok) return menu.append(el("p", "error small", `해제: ${r.error.message}`));
        window.dispatchEvent(new Event(EMERGENCY_EVENT));
        void refresh();
      }, "btn small danger");
      // UI 명세 4판 3-1: [연장 30분] — 막는 범위는 그대로, 만료만 늦춘다(승인 창). 확인(유지) 전에는 서비스가 거부한다
      const ext30 = button("30분 연장…", async () => {
        ext30.disabled = true;
        const r = await mutation("emergency.extend", { minutes: 30 });
        ext30.disabled = false;
        if (!r.ok) return menu.append(el("p", "error small", `연장: ${r.error.message}`));
        window.dispatchEvent(new Event(EMERGENCY_EVENT));
        void refresh();
      }, "btn small");
      ext30.dataset["cmd"] = "emg-extend";
      menu.append(el("div", "tb-menu-actions", ext30, off), el("p", "muted small", "기한이 지나거나 재부팅하면 저절로 풀립니다. 연장은 한 번에 30분, 지금부터 하루를 넘지 않습니다."));
      emg.replaceChildren(stat, menu);
    } else if (er.ok) {
      // 5판 2장: 긴급 차단 상태는 읽었어도 엔진이 바쁘면(정책 수를 못 받았거나 지난 값, 엔진 묶임) 대화상자 안에서 알린다
      const busyNote = !pol.ok || pol.stale_at || engineStuckText(state.engineBusyMs) ? "보호 엔진이 지금 바쁩니다. 요청은 보낼 수 있지만 반영이 늦을 수 있습니다." : undefined;
      const start = button("긴급 차단…", () => emergencyDialog(() => { window.dispatchEvent(new Event(EMERGENCY_EVENT)); void refresh(); }, st?.suggested_tools ?? [], busyNote), "btn small danger");
      start.dataset["cmd"] = "emg-start";
      emg.replaceChildren(start);
    } else {
      // 5판 2장: 상태를 못 읽어도(엔진 바쁨) 단추는 늘 누를 수 있다 — 대화상자 안에서 알린다.
      // 이미 걸려 있었다면 같은 긴급 차단 정책의 새 판으로 바뀐다(engine::apply_emergency — 겹쳐 쌓이지 않고 기한이 새로 잡힌다)
      const b = button("긴급 차단…", () => emergencyDialog(() => { window.dispatchEvent(new Event(EMERGENCY_EVENT)); void refresh(); }, [], "지금 긴급 차단 상태를 읽지 못했습니다(엔진이 바쁠 수 있습니다). 요청은 보낼 수 있지만 반영이 늦을 수 있고, 지금 통신 중인 원격 도구를 미리 채우지 못했습니다."), "btn small danger");
      b.dataset["cmd"] = "emg-start";
      b.title = `긴급 차단 상태를 읽지 못했습니다: ${er.error.message}`;
      emg.replaceChildren(b);
    }
  }

  window.setInterval(() => void refresh(), 20_000);
  window.addEventListener("engine-state", () => void refresh());
  window.addEventListener(EMERGENCY_EVENT, () => void refresh());
  // Esc 로 메뉴를 닫고 상태 단추로 포커스를 돌린다
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    const m = emg.querySelector(".tb-menu");
    if (m && !m.hasAttribute("hidden")) {
      m.setAttribute("hidden", "");
      const st = emg.querySelector<HTMLButtonElement>(".tb-emg-state");
      st?.setAttribute("aria-expanded", "false");
      st?.focus();
    }
  });
  // 펼친 메뉴 밖을 누르면 닫는다
  document.addEventListener("click", (e) => {
    const m = emg.querySelector(".tb-menu");
    if (m && !m.hasAttribute("hidden") && !emg.contains(e.target as Node)) m.setAttribute("hidden", "");
  });
  return { root, refresh };
}
