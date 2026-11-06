import { rpc } from "../rpc";
import { el, ext, fmtTs, fmtShort, fmtRange, filetimeToUnix, button, clear } from "../ui";
import { diffShort, distinguishGroups, groupStories } from "./story-group";
import { listState, loadingBox, failBox, noDataBox, checkedLine, collectionStalled, cardFail } from "../list-state";
import { levelChip, bareTitle } from "./story";
import { engineStuckText, state } from "../state";
import { processPanel } from "./process";
import { watchUntilText } from "./first-run";

/// 서비스가 남긴 보호 사건 (A29): 파이프 이름 가로채기, 데이터 폴더 점유 등. 대상이 그래프의 프로세스면 상세로 잇는다
interface ServiceEvent {
  id: number;
  ts: number;
  kind: string;
  severity: number;
  detail: string;
  target?: { type?: string; pid?: number; image?: string; node_id?: number; defender_ts?: number; path?: string; until_ts?: number } | null;
}
const SERVICE_EVENT_TITLE: Record<string, string> = {
  pipe_squat: "서비스 통로 이름을 다른 프로그램이 차지하려 했습니다",
  data_dir_held: "데이터 폴더를 다른 프로그램이 붙잡고 있었습니다",
  data_dir_untrusted: "서비스보다 먼저 만들어진 데이터 폴더를 치웠습니다",
  // 10판 5-9 (3): Windows 기본 보호(Defender 제어된 폴더 액세스) 기록을 이야기 재료로
  defender_cfa_blocked: "Windows 기본 보호가 보호 폴더 변경을 막았습니다",
  defender_cfa_audited: "Windows 기본 보호가 보호 폴더 변경을 기록했습니다(감사 모드)",
  // 17판 23-2 ①: 첫 실행 관찰실
  first_run_watch: "인터넷에서 받은 프로그램이 처음 실행되어 지켜보는 중입니다",
  // 31차 Q5: 관찰실 차단 자리가 참(채우기 공격일 수 있음 — 단정하지 않는다)
  first_run_cap: "처음 실행 관찰실의 차단 자리가 찼습니다",
  // 14판 20-4: 원격 제어 사기 경보 — 사실만(상대·의도를 단정하지 않는다)
  remote_session_start: "원격 제어 프로그램이 외부로 데이터를 계속 보내기 시작했습니다",
  remote_session_end: "원격 제어 세션 모양이 끝났습니다",
};
/// 경고 테두리 없이 보여 줄 사건(막지 않은 사실·끝난 사실)
const QUIET_KINDS = new Set(["defender_cfa_audited", "first_run_watch", "remote_session_end"]);
/// 보여 줄 보호 사건 (정책 변경 기록 등 평범한 사건은 정책 화면 몫)
const PROTECTION_KINDS = new Set(Object.keys(SERVICE_EVENT_TITLE));

interface StoryEvent {
  root: number;
  title: string;
  level: string;
  started_in_gap?: [number, number];
  chapter: string;
  destroy?: { kind: string; sentence: string; cmdline: string; ts: number; edge_id: number };
  score: number;
  sentences: { text: string; ts: number; edge_ids: number[] }[];
  last_ts?: number;
  fresh?: boolean;
  root_image?: string;
  items?: { label: string; value: string }[];
}

interface Health {
  now: number;
  last_event_ft: number | null;
  lost_24h: number;
  gaps_24h: { from_ts: number; to_ts: number; events: number; reason?: string }[];
  clock_changes_24h: number[];
}
/// C1 수집 상태 한 줄: 정상은 회색(초록 점만), 이상이면 주황 문장을 앞에. 원인을 단정하지 않는다
export function healthLine(h: Health, onMore: () => void, gapStart?: { n: number; open: () => void }): HTMLElement {
  const lastSec = h.last_event_ft ? Math.max(0, h.now - filetimeToUnix(h.last_event_ft)) : null;
  const stalled = lastSec == null || lastSec > 60;
  const lost = h.lost_24h > 0;
  const clock = h.clock_changes_24h.length > 0;
  // D014: 구간 자체가 아니라 "구간 안에서 시작한 주의 이상 사건"이 있을 때만 주황 경고(절전은 흔함)
  const gapWarn = !!gapStart && gapStart.n > 0;
  const bad = stalled || lost || clock || gapWarn;
  const box = el("div", bad ? "health bad" : "health");
  box.append(el("span", "dot"));
  if (gapWarn) {
    const a = el("a", "lead", `기록 없는 구간에 시작한 프로그램 ${gapStart!.n}개 — 이야기 보기 ›`);
    a.href = "#";
    a.addEventListener("click", (e) => { e.preventDefault(); gapStart!.open(); });
    box.append(a);
  }
  if (stalled) box.append(el("span", "lead", "기록이 멈췄을 수 있습니다"));
  else if (lost) box.append(el("span", "lead", "일부 기록이 빠졌을 수 있습니다"));
  else if (clock) box.append(el("span", "lead", "PC 시계가 바뀐 적이 있습니다"));
  else box.append(el("span", undefined, "기록 중"));
  const ago = lastSec == null ? "없음" : lastSec < 60 ? `${lastSec}초 전` : lastSec < 3600 ? `${Math.floor(lastSec / 60)}분 전` : `${Math.floor(lastSec / 3600)}시간 전`;
  box.append(el("span", undefined, `마지막 사건 ${ago}`));
  const g = h.gaps_24h.find((x) => x.reason !== "no_record");
  box.append(el("span", undefined, lost && g ? `손실 ${h.lost_24h}건 (${fmtRange(filetimeToUnix(g.from_ts), filetimeToUnix(g.to_ts))})` : "손실 0 (최근 24시간)"));
  // 25차 Q1: 서비스가 멈췄거나 절전이던 구간. 노트북은 절전이 흔하므로 주황으로 올리지 않고 사실만 보인다
  const nr = h.gaps_24h.filter((x) => x.reason === "no_record");
  const lastNr = nr[nr.length - 1];
  if (lastNr) box.append(el("span", undefined, `기록 없는 구간 ${nr.length}곳 (최근 ${fmtRange(filetimeToUnix(lastNr.from_ts), filetimeToUnix(lastNr.to_ts))})`));
  const c = h.clock_changes_24h[h.clock_changes_24h.length - 1];
  // D041: 항목 하나하나는 줄바꿈하지 않고(.health > span nowrap) 항목 사이에서만 접힌다. "자세히 ›"는 마지막 항목에 붙여 홀로 떨어지지 않게
  const lastItem = el("span", undefined, clock && c ? `시계 변경 ${h.clock_changes_24h.length}회 (${fmtShort(c)})` : "시계 변경 없음");
  const more = el("a", undefined, "자세히 ›");
  more.href = "#";
  more.addEventListener("click", (e) => { e.preventDefault(); onMore(); });
  lastItem.append(" ", more);
  box.append(lastItem);
  return box;
}

/// 대시보드: 조용함이 기본. 의심 사건·정책 변조만 배지로.
export function dashboard(): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "대시보드"));
  const status = el("div", "cards");
  // 목록은 새로 고칠 때마다 비운다 (전에는 알림마다 '지금 봐야 할 것' 목록이 아래에 계속 쌓였다)
  const body = el("div", "dash-body");
  root.append(status, body);
  const refresh = async () => {
    clear(status);
    clear(body);
    body.append(loadingBox());
    // D035-2: 네 조회를 동시에 보내고 칸마다 따로 그린다(rpc 는 던지지 않고 결과로 돌려준다) — 한 조회가 늦거나 실패해도 나머지 칸은 그린다.
    // 전에는 의심 사건 → 정책 → 서비스 사건을 차례로 기다려, 엔진이 바쁘면 카드 하나만 그려진 반쪽 화면이 됐다(L044)
    const [ev, hr, pol, se] = await Promise.all([
      rpc<{ items: StoryEvent[] }>("story.events", { level_min: "suspicious", cursor: { limit: 20 } }),
      rpc<Health>("collector.health", {}),
      rpc<{ items: { name: string; state: string }[] }>("policy.list", {}),
      rpc<{ items: ServiceEvent[] }>("service.events", { since_secs: 7 * 86400, limit: 50 }),
    ]);
    clear(body);
    const stalledNow = hr.ok && collectionStalled(hr.result);
    // D004-2: 숫자는 오늘 새로 일어난 일 기준. 수집 전부터 실행 중·오늘 새 활동 없는 것은 보조 줄로
    const all = ev.ok ? ev.result.items : [];
    const sus = all.filter((s) => s.fresh !== false);
    const staleN = all.length - sus.length;
    // D020-2·3: 같은 프로그램·같은 판정은 한 줄로, 최신이 위. 숫자는 묶은 뒤 개수(보조 줄에 사건 수)
    const groups = groupStories(sus);
    const card = (title: string, body: Node, cls = "card") => el("div", cls, el("h3", undefined, title), body);
    // D013: 불러오지 못하면 숫자 대신 "—" + 주황 "불러오지 못함"
    // D015-1: 기록이 멈췄으면 0 은 믿을 수 없는 숫자 — 초록 0 대신 회색 "—"
    const susBody = !ev.ok
      ? cardFail(ev.error, "의심 사건")
      : stalledNow && !sus.length
        ? el("div", undefined, el("div", "big muted", "—"), el("div", "warn small", "기록이 없어 셀 수 없음"))
        : el("div", undefined, el("div", "big " + (sus.length ? "bad" : "ok"), String(groups.length)));
    if (ev.ok && groups.length !== sus.length) susBody.append(el("div", "muted small", `사건 ${sus.length}건`));
    if (staleN) susBody.append(el("div", "muted small", `그 밖에 수집 전부터 실행 중 ${staleN}건`));
    status.append(card("의심 사건", susBody, sus.length ? "card alert alert-bad" : "card"));
    // D006-3: 지금 Windows 에 걸려 있는 정책 수(확인 대기 + 적용 중, 일시 중지 제외). 서비스는 상태를 "Applied"·"Confirmed"로 준다 —
    // 전에는 소문자와 비교해 늘 0 이었다
    const applied = pol.ok ? pol.result.items.filter((p) => /^(applied|confirmed)$/i.test(p.state)).length : 0;
    status.append(card("적용된 정책", pol.ok ? el("div", "big", String(applied)) : cardFail(pol.error, "적용된 정책")));
    // D002: 왼쪽 메뉴 "연결"(네트워크)과 헷갈리지 않게 "보호 서비스"
    // D015-2: 서비스 연결 + 기록 상태를 한 단어로(작동 중 / 기록 멈춤? / 연결 끊김)
    const svcBody = !state.connected
      ? el("div", undefined, el("div", "big-text warn", "연결 끊김"), el("div", "muted", "서비스가 멈췄거나 시작 중일 수 있습니다"))
      : stalledNow
        ? el("div", undefined, el("div", "big-text warn", "기록 멈춤?"), el("div", "muted", "서비스는 연결됨 · 마지막 사건 없음"))
        : engineStuckText(state.engineBusyMs)
          // D046-3: 아래 상태 줄이 "엔진이 묶여 있다"고 말하는 동안 카드도 초록 "작동 중"만 보이지 않게(같은 기준값)
          ? el("div", undefined, el("div", "big-text warn", "작동 중 · 응답 늦음"), el("div", "muted", `서비스 ${state.serverVersion}`))
          : el("div", undefined, el("div", "big-text ok", "작동 중"), el("div", "muted", `서비스 ${state.serverVersion}`));
    status.append(card("보호 서비스", svcBody));
    // C1: 카드 아래, 상태 줄과 별개. D014: 기록 없는 구간에 시작한 의심 사건이 있으면 맨 앞 주황 경고
    const inGap = all.filter((s) => s.started_in_gap);
    if (hr.ok) body.append(healthLine(hr.result, () => state.go("settings", {}), { n: inGap.length, open: () => state.go("story", { root: inGap[0]?.root }) }));
    const prot = se.ok ? se.result.items.filter((e) => PROTECTION_KINDS.has(e.kind)) : [];
    if (prot.length) {
      const list = el("div", "list service-events");
      for (const e of prot) {
        // 감사 모드 기록은 막지 않은 사실이라 경고 테두리 없이
        const row = el("div", QUIET_KINDS.has(e.kind) ? "row" : "row alert");
        row.append(el("span", "title", SERVICE_EVENT_TITLE[e.kind] ?? e.kind));
        // Defender 기록은 서비스가 읽은 시각이 아니라 Defender 가 남긴 시각
        const dts = typeof e.target?.defender_ts === "number" && e.target.defender_ts > 0 ? e.target.defender_ts : e.ts;
        const when = el("span", "muted", ` · ${fmtShort(dts)}`);
        when.title = fmtTs(dts);
        row.append(when);
        const until = watchUntilText(e.target?.until_ts, fmtShort);
        if (until) row.append(el("span", "muted", ` · ${until}`));
        // 사건 문장에는 외부에서 온 경로·이미지 이름이 섞인다 → 위생 처리
        row.append(el("br"), ext("span", e.detail, "detail"));
        const node = e.target?.node_id;
        if (typeof node === "number") {
          const slot = el("div", "slot");
          row.append(button("그 프로그램 보기", () => { clear(slot); slot.append(processPanel(node)); }), slot);
        }
        list.append(row);
      }
      body.append(el("h2", undefined, "서비스 보호 사건 (7일)"), list);
    }
    if (sus.length) {
      const list = el("div", "list");
      const diffs = distinguishGroups(groups, (x) => bareTitle(x.title));
      for (const [gi, g] of groups.entries()) {
        const s = g.head;
        // D002: [수준 칩] 제목 … 시각 · 이야기 보기. 점수는 툴팁. D020-2: 묶이면 "같은 판정 N건 · 처음~마지막"
        const row = el("div", "row alert watch-row");
        row.title = `판정 규칙 점수 ${s.score}`;
        const ts = s.last_ts || s.sentences.find((x) => x.ts)?.ts;
        // D040-1: 줄 = [칩][이름][설명(한 줄·남는 폭·말줄임, 구분 항목부터 줄임)][시각][단추] — 단추·시각은 줄바꿈하지 않는다
        // D046-2: 끝 시각은 오른쪽 시각 칸에 있으므로 설명에는 시작만("…부터")
        const many = g.members.length > 1 ? `${g.members.length}건 · ${fmtShort(filetimeToUnix(g.first_ts))}부터` : "";
        // D035-3: 같은 제목 묶음이 여럿이면 무엇이 다른지(판정 항목 또는 폴더)를 회색으로
        const full = diffs[gi] ?? "";
        const desc = el("span", "row-desc muted");
        if (full) {
          const d = ext("span", ` · ${diffShort(full)}`, "desc-diff");
          d.title = full;
          desc.append(d);
        }
        if (many) desc.append(el("span", "desc-many", ` · ${many}`));
        row.append(levelChip(s.level), ext("span", bareTitle(s.title), "title"));
        // D043-1: 5장 파괴 징후는 수준 칩([의심])과 따로 글자 칩 하나(색만으로 구분하지 않게)
        if (s.destroy) row.append(el("span", "chip destroy", "파괴 징후"));
        row.append(desc, el("span", "muted when", ts ? fmtShort(filetimeToUnix(ts)) : ""));
        row.append(button("이야기 보기", () => state.go("story", { root: s.root })));
        list.append(row);
      }
      body.append(el("h2", undefined, "지금 봐야 할 것"), list);
    } else {
      // D013: 오류 / 수집 안 됨 / 비어 있음을 가른다. "조용합니다"는 응답이 성공했고 수집이 돌 때만
      const st = listState(ev, hr.ok ? hr.result : null);
      if (st === "error" && !ev.ok) body.append(failBox(ev.error, () => void refresh(), "의심 사건 목록"));
      else if (st === "nodata") body.append(noDataBox(() => state.go("settings", {})));
      else body.append(el("p", "muted", "오늘은 조용합니다. 의심스러운 이야기가 없습니다."), checkedLine(hr.ok ? hr.result : null));
    }
  };
  void refresh();
  state.onNotify(root, (n) => {
    const k = String(n.params["kind"]);
    if (k === "story_suspicious" || k.startsWith("policy_") || PROTECTION_KINDS.has(k)) void refresh();
  });
  // D046-3: 엔진 묶임이 생기거나 풀리면 "보호 서비스" 카드도 다시 그린다(main.ts 가 바뀔 때만 알린다)
  const onEngine = () => void refresh();
  window.addEventListener("engine-state", onEngine);
  root.addEventListener("screen-leave", () => window.removeEventListener("engine-state", onEngine));
  return root;
}
