// 설치 화면 (설치 엑스레이, 기획서 14판 20-3): 설치 프로그램 실행 한 번이 PC 에 한 일을 카드로 보인다.
// 판정하지 않는다 — 사실의 개수와 목록만. 경로·도메인·명령은 외부 문자열이므로 위생 처리 후 텍스트 노드로만 넣는다.
import { rpc } from "../rpc";
import { sanitize } from "../sanitize";
import { el, ext, clear, fmtRange, fmtTs, filetimeToUnix, extPath, button } from "../ui";
import { loadingBox, failBox, noDataBox, collectionStalled, type HealthLike } from "../list-state";
import {
  type InstallRun, INSTALL_DAYS, daysLabel, emptyText, HOW_FOUND, FILES_SCOPE, AUTORUN_SCOPE, GROUPED_NOTE,
  baseName, childProcs, originHost, summaryText, remoteText, sortInstalls, countPaths,
} from "./installs-text";

/// 외부 문자열(경로 등) → 위생 처리 + 경로 고정폭. 표시 위장 문자를 지웠으면 표시를 남긴다
function safePath<K extends keyof HTMLElementTagNameMap>(tag: K, raw: string, cls?: string, maxLen = 400): HTMLElementTagNameMap[K] {
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
  e.append(" ", button("복사", () => { void navigator.clipboard?.writeText(raw).catch(() => {}); }, "btn link small"));
  return e;
}

/// 경로 한 줄 + 횟수(2번 이상) + 복사
function pathLine(path: string, count = 1): HTMLElement {
  const li = safePath("li", path);
  if (count > 1) li.append(` ×${count}`);
  return withCopy(li, path);
}

/// 상세의 한 갈래: 제목 + 목록. 비었으면 "없음"
function section(title: string, items: HTMLElement[], note?: string): HTMLElement {
  const box = el("div", "install-sec");
  box.append(el("h4", undefined, `${title} (${items.length})`));
  if (note) box.append(el("p", "muted small", note));
  if (!items.length) box.append(el("p", "muted small", "없음"));
  else box.append(el("ul", "install-list", ...items));
  return box;
}

/// 카드 하나. AI 도구 화면(14판 20-5)도 같은 모양을 쓴다 — `summary` 로 요약 문장만 바꾼다
export function buildCard(run: InstallRun, summary: string = summaryText(run)): HTMLElement {
  const card = el("div", "card install");
  const title = ext("h3", baseName(run.image));
  title.title = sanitize(run.image, 400).text;
  card.append(el("div", "card-head", title));

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

  card.append(el("p", "install-summary", summary));
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
