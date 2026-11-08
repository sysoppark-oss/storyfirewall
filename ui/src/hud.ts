// HUD ① 작은 상시 창(창 이름 "hud-N", 대시보드 개편안 3판 4-1). 서비스에 직접 붙지 않는다 — Rust(hud.rs)가 20초마다 보내는
// `hud-state` 이벤트만 그린다. 누르면 본 창을 열고, 끌면 옮긴다(4px 넘게 움직였을 때만 끌기 — 누르기와 구분).
// 검수(2026-11-08): 높음은 빨강(--bad), 주황은 "주의"에만(UI 명세 2판 2-1) · 보호 상태는 늘 보인다 · 앱 표시로 알림 토스트와 구분
import { el } from "./ui";

export interface HudPayload {
  tone: "critical" | "high" | "ok" | "down";
  critical: number;
  high: number;
  latest: string | null;
  emergency_left_min: number | null;
}

/// 세 줄 문구(순수 함수 — 시험용). state = 보호 상태, top = 미조치 수, sub = 긴급 차단·최근 인시던트
export function hudLines(st: HudPayload): { tone: string; state: string; top: string; sub: string } {
  if (st.tone === "down") return { tone: "down", state: "연결 끊김", top: "보호 서비스에 닿지 않음", sub: "다시 닿으면 자동으로 이어집니다" };
  const top = st.critical + st.high === 0 ? "미조치 심각·높음 없음" : `미조치 심각 ${st.critical} · 높음 ${st.high}`;
  const parts: string[] = [];
  if (st.emergency_left_min != null) parts.push(`긴급 차단 중 · ${st.emergency_left_min}분 남음`);
  if (st.latest) parts.push(st.latest);
  return { tone: st.tone, state: st.emergency_left_min != null ? "긴급 차단 중" : "보호 중", top, sub: parts.join(" · ") || "최근 인시던트 없음" };
}

export async function hudMain(root: HTMLElement): Promise<void> {
  const { invoke } = await import("@tauri-apps/api/core");
  const { listen } = await import("@tauri-apps/api/event");
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  document.body.classList.add("hud-body");
  const card = el("div", "hud-card");
  card.title = "누르면 Story Firewall 을 엽니다 · 끌어서 옮길 수 있습니다";
  const dot = el("span", "hud-dot");
  const state = el("span", "hud-state");
  const top = el("div", "hud-top");
  const sub = el("div", "hud-sub");
  card.append(el("div", "hud-head", dot, el("span", "hud-app", "Story Firewall"), state), top, sub);
  root.replaceChildren(card);
  // 누르기 = 본 창 열기, 4px 넘게 움직이면 창 끌기
  let down: { x: number; y: number } | null = null;
  card.addEventListener("mousedown", (e) => {
    if (e.button === 0) down = { x: e.screenX, y: e.screenY };
  });
  card.addEventListener("mousemove", (e) => {
    if (down && Math.abs(e.screenX - down.x) + Math.abs(e.screenY - down.y) > 4) {
      down = null;
      void getCurrentWindow().startDragging();
    }
  });
  card.addEventListener("mouseup", () => {
    if (down) void invoke("open_main");
    down = null;
  });
  const draw = (st: HudPayload) => {
    const v = hudLines(st);
    card.dataset["tone"] = v.tone;
    state.textContent = v.state;
    top.textContent = v.top;
    sub.textContent = v.sub;
    card.setAttribute("aria-label", `Story Firewall ${v.state}. ${v.top}. ${v.sub}`);
  };
  draw((await invoke("hud_state")) as HudPayload);
  await listen<HudPayload>("hud-state", (e) => draw(e.payload));
}
