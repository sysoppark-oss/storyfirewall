import { dashboard } from "./screens/dashboard";
import { connections } from "./screens/connections";
import { story } from "./screens/story";
import { installs } from "./screens/installs";
import { agents } from "./screens/agents";
import { policy } from "./screens/policy";
import { settings } from "./screens/settings";
import { engineStuckText, state } from "./state";
import { applyTheme } from "./theme";
applyTheme();
import { el, button, clear } from "./ui";
import { isElevated, setUnauthorizedHandler } from "./rpc";
import { listen } from "@tauri-apps/api/event";

/// 승격된 UI 인데 서비스가 변경을 거부함 = 이 계정이 관리자 그룹이 아니다
function notAdmin() {
  if (document.querySelector("dialog.elevate")) return;
  const dlg = el("dialog", "ack elevate");
  dlg.append(
    el("h3", undefined, "관리자 그룹이 아닙니다"),
    el("p", undefined, "정책 적용·되돌리기·끊기는 로컬 관리자 그룹의 계정만 할 수 있습니다."),
    el("div", "actions", button("닫기", () => dlg.close(), "btn primary")),
  );
  document.body.append(dlg);
  dlg.addEventListener("close", () => dlg.remove());
  dlg.showModal();
}
setUnauthorizedHandler(notAdmin);

const SCREENS = {
  dashboard: { label: "대시보드", make: () => dashboard() },
  connections: { label: "연결", make: () => connections() },
  story: { label: "이야기", make: (a?: Record<string, unknown>) => story(a) },
  installs: { label: "설치", make: () => installs() },
  agents: { label: "AI 도구", make: () => agents() },
  policy: { label: "정책", make: () => policy() },
  settings: { label: "설정", make: () => settings() },
} as const;
type Key = keyof typeof SCREENS;

const app = document.getElementById("app")!;
const nav = el("nav", "nav");
const main = el("main", "main");
const status = el("div", "status");
app.append(nav, main, status);

let current: HTMLElement | undefined;
function go(key: Key, args?: Record<string, unknown>) {
  current?.dispatchEvent(new Event("screen-leave"));
  clear(main);
  current = SCREENS[key].make(args);
  main.append(current);
  for (const b of nav.querySelectorAll("button")) b.classList.toggle("active", b.dataset["key"] === key);
}
state.go = go as typeof state.go;

for (const key of Object.keys(SCREENS) as Key[]) {
  const b = button(SCREENS[key].label, () => go(key), "nav-btn");
  b.dataset["key"] = key;
  nav.append(b);
}

async function showStatus(ok: boolean) {
  const elevated = await isElevated();
  // 정상: 보기 모드(일반 권한) — 변경은 승인 창(UAC)으로. UI 를 관리자 권한으로 띄웠으면 경고 (WebView2 를 승격해 돌리지 말라는 권고)
  // D003-4: 경고 문구는 주의 색(주황), 정상 문구만 초록. 한 줄에 섞이면 경고를 앞에
  if (!ok) {
    status.textContent = `서비스 연결 안 됨: ${state.lastError}`;
    status.className = "status error";
    return;
  }
  // 검수 8번(UI 명세 2판 374행 "보호 서비스 연결·판"): 연결 통로(pipe)는 개발 말이라 툴팁으로만
  const good = `보호 서비스 연결됨 · ${state.serverVersion}판`;
  status.title = `연결 통로: ${state.endpoint}`;
  // 27차 Gemini Q1: 연결은 됐지만 엔진이 한 일에 오래 묶여 있으면 "연결됨"만 보이지 않게 — 주황 경고를 앞에
  const stuck = engineStuckText(state.engineBusyMs);
  if (stuck) {
    status.replaceChildren(el("span", "st-warn", stuck), " · ", el("span", "st-ok", good));
    status.className = "status ok mixed elevated";
    return;
  }
  // 검수 38-11(F2): 항목 단위로만 접힌다 — 항목마다 nowrap 덩어리
  const okItems = el("span", "st-ok");
  const parts = [`보호 서비스 연결됨`, `${state.serverVersion}판`, ...(elevated ? [] : ["보기 모드(변경은 승인 창에서)"])];
  parts.forEach((t, i) => okItems.append(...(i ? [" · "] : []), el("span", "nowrap", t)));
  status.replaceChildren(
    ...(elevated ? [el("span", "st-warn", "관리자 권한으로 실행 중 — 권장하지 않음 (일반 권한으로 실행해도 변경은 승인 창으로 됩니다)"), " · "] : []),
    okItems,
  );
  status.className = elevated ? "status ok mixed elevated" : "status ok mixed";
}

async function boot() {
  await state.start();
  const ok = await state.connect();
  await showStatus(ok);
  state.onDisconnect = (reason) => {
    status.textContent = `서비스 연결 끊김 (${reason}) — 다시 닿으면 자동으로 연결합니다`;
    status.className = "status error";
  };
  // 트레이 감시(A28)가 서비스에 다시 닿았다고 알리면 다시 연결하고 대시보드를 새로 연다
  if ("__TAURI_INTERNALS__" in window) {
    void listen("svc-available", async () => {
      if (state.connected) return;
      const again = await state.connect();
      await showStatus(again);
      if (again) go("dashboard");
    });
  }
  go("dashboard");
  // 10초마다 엔진 묶임 확인 — 바뀌었을 때만 상태 줄을 다시 그린다.
  // L050: 처음 연결 때 이미 "묶여 있음"으로 그렸으면 그 상태에서 시작해야 풀릴 때 다시 그린다(전에는 false 로 시작해 문구가 남았다)
  let wasStuck = !!engineStuckText(state.engineBusyMs);
  window.setInterval(async () => {
    if (!state.connected) return;
    const stuck = !!engineStuckText(await state.pingEngine());
    if (stuck || wasStuck) await showStatus(true);
    if (stuck !== wasStuck) window.dispatchEvent(new Event("engine-state"));
    wasStuck = stuck;
  }, 10_000);
}
void boot();
