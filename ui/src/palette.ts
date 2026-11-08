// 명령 팔레트(Ctrl+K, UI 명세 4판 3-9). 이동·검색 + ">" 명령.
// 정책을 바꾸는 명령은 그 기능의 대화상자·메뉴를 여는 데까지 — 팔레트 안에서 집행하지 않는다.
// 외부 문자열(인시던트 제목·프로그램 이름·주소)은 텍스트 노드로만, 강조는 일치 범위 span 으로.
import { rpc } from "./rpc";
import { el } from "./ui";
import { sanitize } from "./sanitize";
import { state } from "./state";
import { loadTheme, setTheme } from "./theme";
import { openProcessDrawer } from "./screens/process";
import {
  type PaletteItem, SCREEN_ITEMS, SETTING_ITEMS, COMMAND_ITEMS, search, matchRange, looksLikeAddress, incidentNo, pushRecent, nextTheme,
} from "./palette-items";

let recent: PaletteItem[] = [];
let open = false;

/// 팔레트를 열 때마다 한 번 읽는 동적 목록(인시던트·지금 열린 연결의 프로그램)
async function loadDynamic(): Promise<{ incidents: PaletteItem[]; programs: PaletteItem[] }> {
  const [ev, oc] = await Promise.all([
    rpc<{ items: { root: number; title: string; level: string }[] }>("story.events", { level_min: "watch", triage: "all", cursor: { limit: 100 } }),
    rpc<{ items: { image?: string | null; process_id?: number | null }[] }>("connections.open", {}),
  ]);
  const incidents: PaletteItem[] = ev.ok
    ? ev.result.items.map((x) => ({ kind: "incident", label: sanitize(x.title, 160).text, hint: `인시던트 #${x.root}`, target: x.root, keys: String(x.root) }))
    : [];
  const progs = new Map<string, PaletteItem>();
  if (oc.ok) {
    for (const c of oc.result.items) {
      if (!c.image || c.process_id == null) continue;
      const name = sanitize(c.image.split(/[\\/]/).pop() ?? c.image, 120).text;
      if (!progs.has(name.toLowerCase())) progs.set(name.toLowerCase(), { kind: "program", label: name, hint: "프로그램 상세", target: c.process_id, keys: sanitize(c.image, 300).text });
    }
  }
  return { incidents, programs: [...progs.values()] };
}

/// 고른 항목 실행: 화면 이동, 서랍 열기, 또는 대화상자·메뉴 열기
function run(it: PaletteItem): void {
  recent = pushRecent(recent, it);
  switch (it.kind) {
    case "screen": {
      const [key, tab] = String(it.target).split(":");
      state.go(key as Parameters<typeof state.go>[0], tab ? { tab } : {});
      return;
    }
    case "setting":
      state.go("settings", { tab: it.target, find: it.find });
      return;
    case "incident":
      state.go("story", { root: it.target, level: "normal", triage: "all" });
      return;
    case "program":
      openProcessDrawer(Number(it.target));
      return;
    case "address":
      state.go("connections", { tab: "history", q: String(it.target) });
      return;
    case "command":
      return runCommand(String(it.target));
  }
}

function runCommand(id: string): void {
  // 상단 띠의 단추를 누른다 — 대화상자·메뉴는 한 곳(topbar.ts)에서만 만든다
  const click = (cmd: string) => document.querySelector<HTMLButtonElement>(`[data-cmd="${cmd}"]`)?.click();
  switch (id) {
    case "emg-start":
      if (document.querySelector('[data-cmd="emg-start"]')) click("emg-start");
      else click("emg-state"); // 이미 걸려 있으면 상태 메뉴
      return;
    case "emg-stop":
      if (document.querySelector('[data-cmd="emg-state"]')) click("emg-state");
      else state.go("dashboard");
      return;
    case "watching":
      state.go("story", { watching: true });
      return;
    case "diag-copy":
      state.go("settings", { tab: "diag", find: "진단 정보 복사", focus: true });
      return;
    case "theme":
      setTheme(nextTheme(loadTheme()));
      return;
    case "hud":
      state.go("settings", { tab: "notify", find: "HUD" });
      return;
  }
}

/// 글자 + 일치 범위 강조(외부 문자열 — 텍스트 노드 셋으로 나눠 넣는다)
function labelWithMatch(label: string, q: string): HTMLElement {
  const span = el("span", "pal-label");
  const r = matchRange(label, q.replace(/^\s*>/, ""));
  if (!r) span.textContent = label;
  else span.append(label.slice(0, r[0]), el("mark", undefined, label.slice(r[0], r[1])), label.slice(r[1]));
  return span;
}

export function openPalette(): void {
  if (open) return;
  open = true;
  const prevFocus = document.activeElement as HTMLElement | null;
  const dlg = el("dialog", "palette");
  dlg.setAttribute("aria-label", "명령 팔레트");
  const input = el("input");
  input.type = "text";
  input.placeholder = "화면·인시던트·프로그램·주소·설정 찾기   ( > 명령 )";
  input.setAttribute("role", "combobox");
  input.setAttribute("aria-expanded", "true");
  input.setAttribute("aria-controls", "pal-list");
  input.spellcheck = false;
  const list = el("ul", "pal-list");
  list.id = "pal-list";
  list.setAttribute("role", "listbox");
  const foot = el("div", "pal-foot muted small", "↑↓ 고르기 · Enter 열기 · Esc 닫기 · 정책을 바꾸는 명령은 대화상자·승인 창을 엽니다");
  dlg.append(input, list, foot);
  document.body.append(dlg);

  let dyn: { incidents: PaletteItem[]; programs: PaletteItem[] } = { incidents: [], programs: [] };
  let items: PaletteItem[] = [];
  let sel = 0;
  const paint = () => {
    const q = input.value;
    if (!q.trim()) {
      items = [...recent, ...COMMAND_ITEMS.filter((c) => !recent.some((r) => r.kind === "command" && r.target === c.target)).slice(0, 4), ...SCREEN_ITEMS.filter((s) => !recent.includes(s))].slice(0, 12);
    } else {
      items = search(q, [SCREEN_ITEMS, SETTING_ITEMS, dyn.incidents, dyn.programs]);
      const no = incidentNo(q);
      if (no != null && !items.some((x) => x.kind === "incident" && x.target === no)) {
        items.unshift({ kind: "incident", label: `인시던트 #${no}`, hint: "인시던트 목록에서 찾기", target: no });
      }
      if (!q.trimStart().startsWith(">") && looksLikeAddress(q)) {
        const t = q.trim();
        items.push({ kind: "address", label: t, hint: "연결 이력에서 이 글자로 거르기", target: t });
      }
    }
    sel = Math.min(sel, Math.max(0, items.length - 1));
    list.replaceChildren();
    if (!items.length) list.append(el("li", "muted pal-empty", "맞는 항목이 없습니다"));
    items.forEach((it, i) => {
      const li = el("li", `pal-item k-${it.kind}`);
      li.setAttribute("role", "option");
      li.id = `pal-${i}`;
      li.setAttribute("aria-selected", String(i === sel));
      li.append(labelWithMatch(it.label, q), el("span", "pal-hint", it.hint));
      li.addEventListener("mousemove", () => { if (sel !== i) { sel = i; mark(); } });
      li.addEventListener("click", () => choose(it));
      list.append(li);
    });
    mark();
  };
  const mark = () => {
    list.querySelectorAll<HTMLElement>(".pal-item").forEach((li, i) => li.setAttribute("aria-selected", String(i === sel)));
    input.setAttribute("aria-activedescendant", items.length ? `pal-${sel}` : "");
    list.querySelector<HTMLElement>(`#pal-${sel}`)?.scrollIntoView({ block: "nearest" });
  };
  const close = () => dlg.close();
  const choose = (it: PaletteItem) => {
    close();
    // 대화상자를 닫은 뒤 실행해야 새 대화상자(긴급 차단)의 포커스가 남는다
    window.setTimeout(() => run(it), 0);
  };
  input.addEventListener("input", () => { sel = 0; paint(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); mark(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); mark(); }
    else if (e.key === "Enter") { e.preventDefault(); const it = items[sel]; if (it) choose(it); }
  });
  dlg.addEventListener("click", (e) => { if (e.target === dlg) close(); });
  dlg.addEventListener("close", () => {
    open = false;
    dlg.remove();
    if (prevFocus && document.contains(prevFocus)) prevFocus.focus();
  });
  paint();
  dlg.showModal();
  input.focus();
  void loadDynamic().then((d) => { dyn = d; if (open && input.value.trim()) paint(); });
}

/// Ctrl+K(맥 Cmd+K) 어디서나. 입력 칸에서 쓰던 중이어도 연다(브라우저 기본 동작 막음)
export function installPalette(): void {
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openPalette();
    }
  });
}
