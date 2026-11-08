// HUD ① 작은 상시 창(창 이름 "hud", 대시보드 개편안 3판 4-1). 서비스에 직접 붙지 않는다 — Rust(hud.rs)가 20초마다 보내는
// `hud-state` 이벤트만 그린다. 누르면 본 창을 연다. 끌어서 옮길 수 있다(data-tauri-drag-region).
import { el } from "./ui";

export interface HudPayload {
  tone: "critical" | "high" | "ok" | "down";
  critical: number;
  high: number;
  latest: string | null;
  emergency_left_min: number | null;
}

/// 두 줄 문구(순수 함수 — 시험용)
export function hudLines(st: HudPayload): { tone: string; top: string; sub: string } {
  if (st.tone === "down") return { tone: "down", top: "보호 서비스 연결 끊김", sub: "다시 닿으면 자동으로 이어집니다" };
  const top = st.critical + st.high === 0 ? "보호 중 · 미조치 심각·높음 없음" : `미조치 심각 ${st.critical} · 높음 ${st.high}`;
  const parts: string[] = [];
  if (st.emergency_left_min != null) parts.push(`긴급 차단 중 · ${st.emergency_left_min}분 남음`);
  if (st.latest) parts.push(st.latest);
  return { tone: st.tone, top, sub: parts.join(" · ") || "최근 사건 없음" };
}

export async function hudMain(root: HTMLElement): Promise<void> {
  const { invoke } = await import("@tauri-apps/api/core");
  const { listen } = await import("@tauri-apps/api/event");
  document.body.classList.add("hud-body");
  const card = el("div", "hud-card");
  card.setAttribute("data-tauri-drag-region", "");
  const dot = el("span", "hud-dot");
  const top = el("div", "hud-top");
  const sub = el("div", "hud-sub");
  const open = el("button", "hud-open", "열기");
  open.title = "Story Firewall 본 창 열기";
  open.addEventListener("click", () => void invoke("open_main"));
  card.append(el("div", "hud-row", dot, top), sub, open);
  root.replaceChildren(card);
  const draw = (st: HudPayload) => {
    const v = hudLines(st);
    card.dataset["tone"] = v.tone;
    top.textContent = v.top;
    sub.textContent = v.sub;
    card.title = `${v.top}\n${v.sub}`;
  };
  draw((await invoke("hud_state")) as HudPayload);
  await listen<HudPayload>("hud-state", (e) => draw(e.payload));
}
