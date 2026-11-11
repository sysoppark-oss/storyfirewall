// D025-B 진단(설정 › 진단, 수집 상태 줄 "자세히 ›" 대상). 사실과 숫자만, 원인을 단정하지 않는다.
// "진단 정보 복사"는 아래 값만 글자로 — 연결 기록·주소·경로는 넣지 않는다. 외부 전송 없음.
import { rpc, isElevated } from "../rpc";
import { el, ext, button, clear, fmtShort, fmtRange, filetimeToUnix } from "../ui";
import { state } from "../state";
import { failBox, loadingBox, collectionStalled } from "../list-state";
import { retentionText } from "./settings";

interface Gap { from_ts: number; to_ts: number; events: number; reason?: string }
interface Timing { name: string; count: number; avg_ms: number; max_ms: number; last_ms: number }
interface Defender { cfa: string; cfa_source: string; realtime: boolean | null }
interface CmdlineCounts { kernel_session_ok: number; kernel_session_failed: number; cmdline_kernel: number; cmdline_ok: number; cmdline_renamed_tool: number; cmdline_unmatched: number; cmdline_open_failed: number }
interface Health { now: number; last_event_ft: number | null; lost_24h: number; gaps_24h: Gap[]; clock_changes_24h: number[]; timings?: Timing[]; defender?: Defender | null; cmdline?: CmdlineCounts | null }

/// 29차 미결: 복구 도구 명령줄 수집 상태(사실·숫자만)
export function cmdlineText(c: CmdlineCounts): { text: string; warn: boolean } {
  if (c.kernel_session_failed > 0 && c.kernel_session_ok === 0) {
    return { text: `커널 세션을 열지 못함 — 짧게 끝나는 복구 도구 명령은 놓칠 수 있습니다 (직접 읽기 ${c.cmdline_ok}건 · 읽기 실패 ${c.cmdline_open_failed}건)`, warn: true };
  }
  const got = c.cmdline_kernel + c.cmdline_ok;
  const extra = [c.cmdline_renamed_tool ? `이름 바꾼 도구 ${c.cmdline_renamed_tool}` : "", c.cmdline_unmatched ? `짝 못 지음 ${c.cmdline_unmatched}` : ""].filter(Boolean).join(" · ");
  return { text: `커널 세션 정상 · 받은 명령줄 ${got}건${extra ? ` · ${extra}` : ""}`, warn: c.cmdline_unmatched > 0 };
}

/// 10판 5-9 (3): 제어된 폴더 액세스(CFA) 설정 값 → 사람 말. 레지스트리 설정 값이지 "동작 확인"이 아니다(다른 백신이면 Defender 가 쉴 수 있음)
export function cfaText(d: Defender): { text: string; warn: boolean; hint: string | null } {
  const pol = d.cfa_source === "policy" ? " (그룹 정책으로 설정됨)" : "";
  const hint = "켜면 Windows 가 보호 폴더(문서·사진·바탕 화면 등)의 파일 변경을 허용된 앱만 하게 막습니다. Windows 보안 앱 › 바이러스 및 위협 방지 › 랜섬웨어 방지 관리에서 켭니다.";
  switch (d.cfa) {
    case "block": return { text: `켜짐 · 차단${pol}`, warn: false, hint: null };
    case "audit": return { text: `감사만 — 막지 않고 기록${pol}`, warn: true, hint };
    case "block_disk": return { text: `디스크 수정만 차단${pol}`, warn: true, hint };
    case "audit_disk": return { text: `디스크 수정만 감사${pol}`, warn: true, hint };
    case "off": return { text: `꺼짐${pol}`, warn: true, hint };
    case "unset": return { text: "설정 없음 (Windows 기본은 꺼짐)", warn: true, hint };
    default: return { text: `알 수 없는 값${pol}`, warn: true, hint: null };
  }
}
export function realtimeText(r: boolean | null): string {
  if (r === true) return "켜짐";
  if (r === false) return "꺼짐 — 제어된 폴더 액세스는 실시간 보호가 켜져 있어야 동작합니다";
  return "설정 값 없음 (다른 백신을 쓰면 Defender 가 쉬고 있을 수 있습니다)";
}

/// 구간 원인 → 사람 말(단정하지 않는다)
export function gapReason(r?: string): string {
  if (r === "no_record") return "알 수 없음 (서비스 정지 또는 절전)";
  if (r === "store_failed") return "이벤트 저장 실패";
  if (r === "channel_full") return "처리 과부하로 일부 이벤트 폐기";
  return "알 수 없음";
}

/// 길이 "45분", "2시간 5분", "30초"
export function spanText(fromFt: number, toFt: number): string {
  const s = Math.max(0, Math.round(filetimeToUnix(toFt) - filetimeToUnix(fromFt)));
  if (s < 60) return `${s}초`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}분`;
  return `${Math.floor(m / 60)}시간${m % 60 ? ` ${m % 60}분` : ""}`;
}

export function diagnostics(): HTMLElement {
  const root = el("section", "diag");
  root.id = "diag";
  root.append(el("h2", undefined, "진단"));
  const body = el("div");
  root.append(body);
  const load = async () => {
    clear(body);
    body.append(loadingBox({ word: false })); // 말씀 규칙 3: 진단 자리에는 넣지 않는다
    const [h, ev, c, ret, elevated] = await Promise.all([
      rpc<Health>("collector.health", {}),
      rpc<{ items: { root: number; title: string; started_in_gap?: [number, number] }[] }>("story.events", { level_min: "normal", triage: "all", cursor: { limit: 200 } }),
      rpc<{ geo?: { built?: number | null } }>("connections.list", { since_secs: 1 }),
      rpc<Record<string, unknown>>("retention.get", {}),
      isElevated(),
    ]);
    clear(body);
    const copy: string[] = [];
    const row = (k: string, v: Node | string, plain: string) => {
      body.append(el("div", "diag-row", el("span", "muted", k), typeof v === "string" ? el("span", undefined, v) : v));
      copy.push(`${k}: ${plain}`);
    };
    // 1. 수집
    body.append(el("h3", undefined, "텔레메트리 수집"));
    if (!h.ok) {
      body.append(failBox(h.error, () => void load(), "텔레메트리 상태"));
    } else {
      const x = h.result;
      const lastSec = x.last_event_ft ? Math.max(0, x.now - filetimeToUnix(x.last_event_ft)) : null;
      const st = collectionStalled(x) ? `기록이 멈췄을 수 있습니다 · 마지막 사건 ${lastSec == null ? "없음" : `${lastSec}초 전`}` : `기록 중 · 마지막 사건 ${lastSec}초 전`;
      row("상태", el("span", collectionStalled(x) ? "warn" : undefined, st), st);
      row("손실 이벤트 (최근 24시간)", `${x.lost_24h}건`, `${x.lost_24h}건`);
      const nr = x.gaps_24h.filter((g) => g.reason === "no_record");
      row("수집 공백 구간 (최근 24시간)", `${nr.length}곳`, `${nr.length}곳`);
      const clocks = x.clock_changes_24h.map((t) => fmtShort(t)).join(", ");
      row("PC 시계 변경", clocks || "없음", clocks || "없음");
      if (x.gaps_24h.length) {
        const t = el("table", "grid diag-gaps");
        t.append(el("tr", undefined, el("th", undefined, "구간"), el("th", undefined, "길이"), el("th", undefined, "원인"), el("th", undefined, "공백 중 시작된 프로세스")));
        const items = ev.ok ? ev.result.items : [];
        for (const g of x.gaps_24h) {
          const progs = el("td");
          for (const s of items.filter((s) => s.started_in_gap && s.started_in_gap[0] === g.from_ts)) {
            const a = el("a", undefined, "인시던트 보기 ›");
            a.href = "#";
            a.addEventListener("click", (e) => { e.preventDefault(); state.go("story", { root: s.root }); });
            progs.append(ext("span", s.title.replace(/^\[[^\]]*\]\s*/, "").split(" — ")[0] ?? s.title), " ", a, " ");
          }
          t.append(el("tr", undefined, el("td", undefined, `${fmtShort(filetimeToUnix(g.from_ts))} ~ ${fmtShort(filetimeToUnix(g.to_ts))}`), el("td", undefined, spanText(g.from_ts, g.to_ts)), el("td", "muted", gapReason(g.reason)), progs));
          copy.push(`구간: ${fmtRange(filetimeToUnix(g.from_ts), filetimeToUnix(g.to_ts))} ${spanText(g.from_ts, g.to_ts)} ${gapReason(g.reason)}${g.events ? ` ${g.events}건` : ""}`);
        }
        body.append(t);
      }
    }
    // 1-b. 처리 시간(서비스 시작 뒤): 무엇이 느린지 사실로. 화면 말은 초, 복사에는 ms
    if (h.ok && h.result.timings?.length) {
      const det = el("details", "diag-timings", el("summary", undefined, "처리 시간 (서비스 시작 뒤, 오래 걸린 순)"));
      const t = el("table", "grid");
      t.append(el("tr", undefined, el("th", undefined, "일"), el("th", undefined, "횟수"), el("th", undefined, "평균"), el("th", undefined, "가장 길게"), el("th", undefined, "마지막")));
      for (const x of h.result.timings) {
        // D040-2: 일 칸은 사람 말, 메서드 이름은 툴팁·복사에만. 평균 2초 넘으면 숫자만 주황(굵기 없이)
        const name = ext("td", timingName(x.name));
        name.title = x.name;
        t.append(el("tr", undefined, name, el("td", undefined, String(x.count)), el("td", x.avg_ms > 2000 ? "warn" : undefined, secText(x.avg_ms)), el("td", undefined, secText(x.max_ms)), el("td", undefined, secText(x.last_ms))));
        copy.push(`처리 시간: ${x.name} n=${x.count} avg=${x.avg_ms}ms max=${x.max_ms}ms last=${x.last_ms}ms`);
      }
      det.append(t);
      body.append(det);
    }
    // 2. 서비스
    body.append(el("h3", undefined, "서비스"));
    const svc = state.connected ? `연결됨 · ${state.serverVersion}` : "연결 끊김";
    row("보호 서비스", el("span", state.connected ? "ok" : "warn", svc), svc);
    const perm = elevated ? "관리자 권한으로 실행 중(권장하지 않음)" : "보기 모드(변경은 승인 창 경유)";
    // D027-5: 관리자 권한 실행은 주황(경고), 보기 모드는 기본색
    row("이 화면의 권한", el("span", elevated ? "warn" : undefined, perm), perm);
    const built = c.ok ? c.result.geo?.built : null;
    const geo = built ? `DB-IP Lite · 기준일 ${new Date(built * 1000).toISOString().slice(0, 10)}` : "설치 안 됨";
    row("IP 국가·ASN 데이터", geo, geo);
    const rt = ret.ok ? retentionText(ret.result).replace(/^보관: /, "") : "";
    if (rt) row("데이터 보관", rt, rt);
    // 27차: 마지막 보관 정리(서비스가 1시간마다). 결과 숫자만
    const last = ret.ok ? (ret.result.last as { at?: number; ms?: number; ok?: boolean; raw_deleted?: number; edges_compacted?: number; phases?: Record<string, number> } | null | undefined) : null;
    // D033-2: 화면은 사용자 말·초 단위, "진단 정보 복사"에는 원래 값(ms)
    const lt = last?.at
      ? `${fmtShort(last.at)} · ${last.ok ? `지운 기록 ${last.raw_deleted ?? 0}건 · 하루 요약으로 합친 연결 ${last.edges_compacted ?? 0}건` : "실패"} · ${durText(last.ms ?? 0)}`
      : "아직 안 함(서비스 시작 뒤 첫 판정 다음)";
    // L050: 단계별 시간(ms) — 복사·툴팁에(어디가 느린지 실기기에서 찾는다)
    const ph = last?.phases ? Object.entries(last.phases).map(([k, v]) => `${k}=${v}`).join(" ") : "";
    const ltCopy = last?.at ? `${fmtShort(last.at)} ok=${last.ok} raw_deleted=${last.raw_deleted ?? 0} edges_compacted=${last.edges_compacted ?? 0} ms=${last.ms ?? 0}${ph ? ` phases: ${ph}` : ""}` : "none";
    const ltEl = el("span", last?.at && !last.ok ? "warn" : undefined, lt);
    if (ph) ltEl.title = `단계별(ms): ${ph}`;
    row("마지막 보관 정리", ltEl, ltCopy);
    const cl = h.ok ? h.result.cmdline : null;
    if (cl) {
      const t = cmdlineText(cl);
      row("복구 도구(vssadmin 등) 명령줄 수집", el("span", t.warn ? "warn" : undefined, t.text), JSON.stringify(cl));
    }
    // 2-b. Windows 기본 보호(10판 5-9 (3)) — 설정 값만. Defender 는 경쟁이 아니라 이야기의 재료
    const df = h.ok ? h.result.defender : null;
    if (df) {
      body.append(el("h3", undefined, "Windows 기본 보호 (설정 값)"));
      const c = cfaText(df);
      row("제어된 폴더 액세스", el("span", c.warn ? "warn" : undefined, c.text), `cfa=${df.cfa} source=${df.cfa_source}`);
      if (c.hint) body.append(el("p", "muted small", c.hint));
      const r = realtimeText(df.realtime);
      row("Defender 실시간 보호", el("span", df.realtime === false ? "warn" : undefined, r), `realtime=${df.realtime}`);
    }
    // 3. 복사
    body.append(el("h3", undefined, "진단 정보"));
    const done = el("span", "muted small");
    body.append(el("div", undefined, button("진단 정보 복사", () => {
      void navigator.clipboard?.writeText(copy.join("\n")).then(() => { done.textContent = " 복사했습니다."; }, () => { done.textContent = " 복사하지 못했습니다."; });
    }), " ", el("span", "muted small", "위 값만 글자로 복사합니다. 어디로도 보내지 않습니다. 연결 기록·주소는 넣지 않습니다."), done));
  };
  void load();
  return root;
}

/// D033-2: 걸린 시간 사람 말 — 1초 미만은 "1초 미만", 그 위는 소수 한 자리 초
export function durText(ms: number): string {
  if (ms < 1000) return "1초 미만";
  return `${(ms / 1000).toFixed(1)}초`;
}

/// 처리 시간 표: 초, 소수 두 자리(0.25초) — 짧은 일도 서로 비교할 수 있게
export function secText(ms: number): string {
  return `${(ms / 1000).toFixed(2)}초`;
}

/// D040-2: 처리 시간 표의 일 이름(사람 말). 엔진 일("엔진: …")과 모르는 이름은 그대로
const TIMING_KO: Record<string, string> = {
  "story.events": "인시던트 목록",
  "story.today": "활동 타임라인",
  "story.explain": "근거 보기",
  "connections.list": "연결 목록",
  "listeners.list": "리스닝 포트 목록",
  "collector.health": "텔레메트리 상태",
  "policy.list": "정책 목록",
  "service.events": "서비스 사건",
  "events.subscribe": "실시간 알림 연결",
  "connections.subscribe": "실시간 연결 알림",
  "process.detail": "프로세스 상세",
  "process.find": "프로그램 찾기",
  "blocked.recent": "차단 기록",
  "graph.neighbors": "마인드맵",
  "retention.get": "보관 설정",
  "settings.get": "설정",
  "(대기열)": "차례 기다림(대기열)",
};
export function timingName(n: string): string {
  return TIMING_KO[n] ?? n;
}
