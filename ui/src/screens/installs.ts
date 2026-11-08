// 설치 화면 (설치 엑스레이, 기획서 14판 20-3): 설치 프로그램 실행 한 번이 PC 에 한 일을 카드로 보인다.
// 판정하지 않는다 — 사실의 개수와 목록만. 경로·도메인·명령은 외부 문자열이므로 위생 처리 후 텍스트 노드로만 넣는다.
import { copyButton, icon } from "./dash-viz";
import { openProcessDrawer } from "./process";
import { state } from "../state";
import { rpc } from "../rpc";
import { sanitize } from "../sanitize";
import { el, ext, clear, fmtRange, fmtTs, filetimeToUnix, extPath, button } from "../ui";
import { loadingBox, failBox, noDataBox, collectionStalled, type HealthLike } from "../list-state";
import {
  type InstallRun, INSTALL_DAYS, daysLabel, emptyText, HOW_FOUND, FILES_SCOPE, AUTORUN_SCOPE, GROUPED_NOTE,
  baseName, childProcs, originHost, summaryText, remoteText, sortInstalls, countPaths, installChips, installEdge,
} from "./installs-text";

/// UI 명세 4판 4-2: 요약 단추 — 이 설치(뿌리)가 인시던트면 그 카드로, 아니면 프로그램 상세 서랍(실행 흐름)으로.
/// 인시던트가 아닌 것을 인시던트처럼 보이지 않는다. 목록을 못 받으면 서랍으로(잘못된 카드로 보내지 않음)
export async function openRunFlow(root: number): Promise<void> {
  const r = await rpc<{ items: { root: number }[] }>("story.events", { level_min: "normal", triage: "all", cursor: { limit: 200 } });
  if (r.ok && r.result.items.some((x) => x.root === root)) return void state.go("story", { root, level: "normal", triage: "all" });
  openProcessDrawer(root, "이 설치 프로그램의 실행 흐름");
}

/// 외부 문자열(경로 등) → 위생 처리 + 경로 고정폭. 표시 위장 문자를 지웠으면 표시를 남긴다
export function safePath<K extends keyof HTMLElementTagNameMap>(tag: K, raw: string, cls?: string, maxLen = 400): HTMLElementTagNameMap[K] {
  const s = sanitize(raw, maxLen);
  const e = extPath(tag, s.text, cls);
  if (s.spoofRisk) {
    e.classList.add("spoof-risk");
    e.title = "이 이름에는 표시를 뒤집거나 숨기는 문자가 들어 있었습니다 (제거하고 표시함)";
  }
  if (s.truncated) e.title = (e.title ? e.title + " · " : "") + "전체 길이 " + raw.length;
  return e;
}

/// 검수 4번(UI 명세 2판: 주소·경로는 링크 아님 + "복사"): 원문 그대로 복사
function withCopy(e: HTMLElement, raw: string): HTMLElement {
  e.append(" ", copyButton(raw));
  return e;
}

/// 경로 한 줄 + 횟수(2번 이상) + 복사
export function pathLine(path: string, count = 1): HTMLElement {
  const li = safePath("li", path);
  if (count > 1) li.append(` ×${count}`);
  return withCopy(li, path);
}

/// 상세의 한 갈래: 제목 + 목록. 비었으면 "없음"
export function section(title: string, items: HTMLElement[], note?: string, iconName?: string): HTMLElement {
  const box = el("div", "install-sec");
  const h = el("h4", undefined, `${title} (${items.length})`);
  if (iconName) h.prepend(icon(iconName), " ");
  box.append(h);
  if (note) box.append(el("p", "muted small", note));
  if (!items.length) box.append(el("p", "muted small", "없음"));
  else box.append(el("ul", "install-list", ...items));
  return box;
}

/// 카드 하나. AI 도구 화면(14판 20-5)도 같은 모양을 쓴다 — `summary` 로 요약 문장만 바꾼다
export function buildCard(run: InstallRun, summary: string = summaryText(run), opts: { chips?: boolean } = {}): HTMLElement {
  const card = el("div", "card install");
  const title = ext("h3", baseName(run.image));
  title.title = sanitize(run.image, 400).text;
  card.append(el("div", "card-head", title));
  // UI 명세 4판 3-6: 사실 칩(사용자가 실행 / 다른 프로그램이 실행 / 조용한 설치 / 출처 기록 없음). 툴팁은 외부 문자열 — 위생 처리
  const chips = opts.chips === false ? [] : installChips(run);
  if (chips.length) {
    const row = el("div", "install-chips");
    for (const c of chips) {
      const x = el("span", `chip install-chip ${c.kind}`, c.text);
      x.title = sanitize(c.tip, 600).text;
      row.append(x);
    }
    card.append(row);
  }
  if (opts.chips !== false) card.classList.add(installEdge(chips) === "warn" ? "edge-warn" : "edge-line");

  // 시각 범위 + 내려받은 곳(알 때만)
  const start = filetimeToUnix(run.start_ts);
  const last = filetimeToUnix(run.last_ts || run.start_ts);
  const meta = el("div", "muted small install-meta", fmtRange(start, last));
  meta.title = `${fmtTs(start)} ~ ${fmtTs(last)}${run.pid != null ? ` · PID ${run.pid}` : ""}`;
  const host = originHost(run.origin);
  if (host) {
    const o = ext("span", host);
    if (run.origin && run.origin !== host) o.title = sanitize(run.origin, 400).text;
    meta.append(" · 내려받은 곳: ", o);
    withCopy(meta, run.origin ?? host);
  }
  card.append(meta);

  // 4-2: 요약은 단추 — 인시던트면 그 카드, 아니면 프로그램 상세 서랍
  const sumBtn = button(summary, () => void openRunFlow(run.root), "btn link install-summary");
  sumBtn.title = "이 설치가 한 일을 실행 흐름으로 보기";
  card.append(el("p", undefined, sumBtn));
  // 검수(AI 도구 1): 수집 한계는 주의 뜻이 아니라 회색(명세 2-1: 주황은 주의·오늘 처음에만)
  if (run.truncated) card.append(el("p", "muted small", "기록이 많아 일부만 모았습니다(접속·자동 실행·파일 쓰기를 한 것 먼저). 아래 목록은 전부가 아닙니다."));

  const det = el("details", "install-detail");
  det.append(el("summary", undefined, "자세히"));
  det.append(
    section("자식 프로세스", countPaths(childProcs(run)).map(([p, n]) => pathLine(p, n))),
    ...(run.grouped?.length ? [section("설치 세션(묶음)", run.grouped.map((p) => pathLine(p)), GROUPED_NOTE)] : []),
    section("생성 파일", run.files.map((p) => pathLine(p)), FILES_SCOPE),
    section("지속성(자동 실행 등록)", [
      ...run.autoruns.map(([loc, target]) => {
        const li = el("li");
        li.append(safePath("span", loc), " → ", safePath("span", target));
        return withCopy(li, `${loc} -> ${target}`);
      }),
      ...(run.persistence ?? []).map((p) => safePath("li", p, "mono", 1000)),
    ], AUTORUN_SCOPE),
    section("네트워크 연결", run.remotes.map((r) => ext("li", remoteText(r)))),
    section("명령줄", run.commands.map((c) => safePath("li", c, "mono", 1000))),
  );
  card.append(det);
  return card;
}

export function installs(): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "설치 이력"));
  const range = el("select");
  for (const d of INSTALL_DAYS) {
    const o = el("option", undefined, `최근 ${daysLabel(d)}`);
    o.value = String(d);
    if (d === 7) o.selected = true;
    range.append(o);
  }
  range.addEventListener("change", () => void load());
  const cards = el("div", "cards-col");
  root.append(el("div", "toolbar", "범위 ", range), cards);

  const load = async () => {
    const days = Number(range.value) || 7;
    clear(cards);
    cards.append(loadingBox());
    const [r, h] = await Promise.all([
      rpc<{ items: InstallRun[] }>("installs.list", { days, limit: 30 }),
      rpc<HealthLike>("collector.health", {}),
    ]);
    // 범위를 바꾸는 사이 늦게 온 답은 버린다
    if (Number(range.value) !== days) return;
    clear(cards);
    // D013: 오류는 "설치 이벤트 없음"으로 그리지 않는다
    if (!r.ok) return void cards.append(failBox(r.error, () => void load(), "설치 이벤트"));
    const health = h.ok ? h.result : null;
    if (!r.result.items.length) {
      if (collectionStalled(health)) return void cards.append(noDataBox());
      cards.append(el("p", undefined, emptyText(days)), el("p", "muted small", HOW_FOUND));
      return;
    }
    // 31차 검수 2: 왜 이 항목이 설치인지 — 기준을 목록 위에 둔다
    cards.append(el("p", "muted small", HOW_FOUND));
    for (const run of sortInstalls(r.result.items)) cards.append(buildCard(run));
  };
  void load();
  return root;
}
