// 상세 보고서(통합프로젝트 「상세 보고서 기능 — 공통 규칙과 개발 의뢰 (1판)」 1·2·3장) — 1단계: incidents·blocked·policy.
// 여기서는 조회 결과를 **보고서 모형**(구역 → 문단·표)으로만 바꾼다(순수 함수). 가리기·HTML 바꿔 쓰기·파일 쓰기는 코어(src-tauri/report.rs →
// crates/report)가 한다. 모형에는 글자만 넣는다 — HTML 을 넣을 수 없고, 넣어도 코어가 전부 바꿔 쓴다.
// 문장은 화면 문장을 그대로 싣는다(3.1: 보고서용으로 다시 쓰지 않는다).
import { invoke } from "@tauri-apps/api/core";
import { LEVEL, STAGE_NAMES_4, TRIAGE_STATE, TRIAGE_ACTION } from "./terms";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export type Block =
  | { kind: "heading"; text: string }
  | { kind: "para"; text: string }
  | { kind: "facts"; rows: [string, string][] }
  | { kind: "table"; headers: string[]; rows: string[][] };
export interface Section { id: string; title: string; count: number; shown?: number; notes: string[]; blocks: Block[]; items: unknown[] }
export interface Report {
  program: "storyfirewall";
  program_title: string;
  version: string;
  generated_at: string;
  period_from: string;
  period_to: string;
  masked: boolean;
  source_url: string;
  sections: Section[];
}
/// 기간(unix 초, 양 끝 포함)
export interface Period { from: number; to: number }
export type PeriodKind = "today" | "7d" | "30d" | "custom";

export const SOURCE_URL = "https://github.com/sysoppark-oss/storyfirewall";
/// 1단계에서 고를 수 있는 구역(3.1 의 id·메뉴 순서)
export const SECTIONS_1 = [
  { id: "incidents", title: "인시던트" },
  { id: "blocked", title: "차단 기록" },
  { id: "policy", title: "정책" },
] as const;
export type SectionId = (typeof SECTIONS_1)[number]["id"];
/// 사건 상한(구역 하나). 넘으면 "전체 N건 중 상위 M건"
export const MAX_INCIDENTS = 200;
/// 표 행 상한(2.7)
export const MAX_ROWS = 2000;

const p2 = (n: number) => String(n).padStart(2, "0");
/// 이 PC 시각대의 RFC 3339("2026-11-14T05:12:00+09:00")
export function rfc3339(unixSec: number): string {
  const d = new Date(unixSec * 1000);
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const a = Math.abs(off);
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}T${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}${sign}${p2(Math.floor(a / 60))}:${p2(a % 60)}`;
}
/// 파일 이름용 "YYYYMMDD-HHMMSS"
export function stampOf(unixSec: number): string {
  const d = new Date(unixSec * 1000);
  return `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}-${p2(d.getHours())}${p2(d.getMinutes())}${p2(d.getSeconds())}`;
}
/// 표에 적는 시각 "2026-11-14 05:12:00"(이 PC 시각대). 없으면 "-"
export function when(unixSec: number | null | undefined): string {
  if (!unixSec) return "-";
  return rfc3339(unixSec).slice(0, 19).replace("T", " ");
}
const ftToUnix = (ft: number) => Math.floor((ft - 116444736000000000) / 10000000);

/// 기간: 오늘(자정부터) / 최근 7일 / 최근 30일 / 직접("YYYY-MM-DD" 시작·끝 날짜, 끝 날짜는 그날 끝까지 — 지금보다 뒤면 지금까지).
/// 직접에서 날짜가 틀리거나 시작이 끝보다 뒤면 null
export function periodOf(kind: PeriodKind, nowSec: number, fromDate?: string, toDate?: string): Period | null {
  const midnight = (t: number) => { const d = new Date(t * 1000); d.setHours(0, 0, 0, 0); return Math.floor(d.getTime() / 1000); };
  if (kind === "today") return { from: midnight(nowSec), to: nowSec };
  if (kind === "7d") return { from: nowSec - 7 * 86400, to: nowSec };
  if (kind === "30d") return { from: nowSec - 30 * 86400, to: nowSec };
  const day = (s: string | undefined): number | null => {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s ?? "");
    if (!m) return null;
    const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
    // 2월 30일 같은 날짜는 다른 날로 넘어간다 — 받지 않는다
    return d.getMonth() === Number(m[2]) - 1 && d.getDate() === Number(m[3]) ? Math.floor(d.getTime() / 1000) : null;
  };
  const a = day(fromDate);
  const b = day(toDate);
  if (a === null || b === null || a > b) return null;
  return { from: a, to: Math.min(b + 86400 - 1, nowSec) };
}

// ── 인시던트 ─────────────────────────────────────────────────────────────
export interface RSentence { text: string; ts: number; sources?: [string, number][] }
export interface RWhere { scope?: string; cc?: string; country?: string; asn?: number; org?: string }
export interface RTriage { state: "new" | "investigated" | "acted" | "closed"; action?: "normal" | "cut" | "watch"; updated_ts?: number; recur_count?: number }
/// story.events 카드에서 보고서가 읽는 칸(없는 칸은 싣지 않는다)
export interface REvent {
  root: number;
  title: string;
  level: string;
  score?: number;
  sentences: RSentence[];
  items?: { label: string; value: string }[];
  reached?: number[];
  destroy?: { sentence: string; ts: number };
  last_ts?: number;
  root_image?: string;
  root_signature?: { signer?: string | null; sig_status?: string | null } | null;
  egress?: string;
  egress_ip?: string;
  egress_where?: RWhere | null;
  triage?: RTriage | null;
}

const SOURCE_KO: Record<string, string> = {
  etw: "실시간 기록", conntable: "연결 표", motw: "파일 표시", defender: "Windows 보안 기록", snapshot: "시작 시 목록",
  signature: "서명 검사", autorun: "레지스트리 대조", registry: "레지스트리 대조", sysmon: "Sysmon 기록", scm: "서비스 목록",
  capi2: "인증서 조회 기록", memscan: "메모리 검사",
};
/// 서명 검사 결과 낱말(서비스 값 → 화면 말). 모르는 값은 받은 그대로
const SIG_KO: Record<string, string> = { valid: "서명 확인됨", nosignature: "서명 없음", invalid: "서명이 맞지 않음", untrusted: "믿을 수 없는 서명" };
/// 카드 제목의 "[의심] " 머리와 " — … 까지 진행 …" 꼬리를 뗀다(화면 카드와 같은 규칙)
function bare(t: unknown): string {
  return typeof t === "string" ? t.replace(/^\[[^\]]*\]\s*/, "").replace(/\s+—\s+\S+\s.*까지 진행.*$/, "") : "";
}
function levelKo(level: string): string {
  return (LEVEL as Record<string, string>)[String(level).toLowerCase()] ?? String(level);
}
function triageKo(t: RTriage | null | undefined): string {
  const st = t?.state ?? "new";
  const base = st === "acted" && t?.action ? `${TRIAGE_STATE[st]} · ${TRIAGE_ACTION[t.action]}` : TRIAGE_STATE[st] ?? String(st);
  return t?.recur_count ? `${base} · 재발 ${t.recur_count}회` : base;
}
/// 접속지의 나라·조직(오프라인 DB 기준 — 구역 설명에 적는다)
export function whereText(w: RWhere | null | undefined): string {
  if (!w) return "";
  const place = w.country ?? w.cc ?? "";
  return [place, w.org ?? ""].filter(Boolean).join(" · ");
}
/// 사건의 마지막 활동 시각(unix 초). 모르면 null
export function eventTime(ev: REvent): number | null {
  const ft = ev.last_ts || ev.sentences.find((s) => s.ts)?.ts;
  return ft ? ftToUnix(ft) : null;
}
const LEVEL_RANK: Record<string, number> = { critical: 3, suspicious: 2, watch: 1, normal: 0 };

/// 한 사건의 문단들: 제목 → 사실 표 → 이야기 문장 표(시각·문장·근거)
export function incidentBlocks(ev: REvent): Block[] {
  const facts: [string, string][] = [["심각도", levelKo(ev.level)]];
  if (ev.reached?.length) facts.push(["이어진 장", ev.reached.map((n) => `${n}장 ${STAGE_NAMES_4[n - 1] ?? (n === 5 ? "파괴 징후" : "")}`.trim()).join(", ")]);
  facts.push(["처리 상태", triageKo(ev.triage)]);
  const t = eventTime(ev);
  if (t) facts.push(["마지막 활동", when(t)]);
  if (ev.root_image) facts.push(["시작 프로그램", ev.root_image]);
  // 카드의 사실 줄(items)에 같은 이름이 있으면 그쪽(화면 말)을 쓴다 — 같은 줄이 두 번 나오지 않게
  const has = (label: string) => (ev.items ?? []).some((it) => it?.label === label);
  if (ev.root_signature && !has("서명")) {
    const st = ev.root_signature.sig_status ? SIG_KO[ev.root_signature.sig_status.toLowerCase()] ?? ev.root_signature.sig_status : "";
    facts.push(["서명", ev.root_signature.signer ? `${ev.root_signature.signer}${st ? ` (${st})` : ""}` : st || "서명 정보 없음"]);
  }
  if (ev.egress) {
    const w = whereText(ev.egress_where);
    // 접속지가 이미 숫자 주소면 같은 주소를 괄호로 되풀이하지 않는다
    const ip = ev.egress_ip && !ev.egress.includes(ev.egress_ip) ? ` (${ev.egress_ip})` : "";
    facts.push(["가장 늦은 외부 접속지", `${ev.egress}${ip}${w ? ` — ${w}` : ""}`]);
  }
  for (const it of ev.items ?? []) if (it && typeof it.label === "string" && typeof it.value === "string") facts.push([it.label, it.value]);
  const out: Block[] = [{ kind: "heading", text: bare(ev.title) || `사건 #${ev.root}` }, { kind: "facts", rows: facts }];
  if (ev.destroy?.sentence) out.push({ kind: "para", text: `5장 파괴 징후: ${ev.destroy.sentence} (${when(ftToUnix(ev.destroy.ts))})` });
  const rows = (ev.sentences ?? []).map((s) => [
    s.ts ? when(ftToUnix(s.ts)) : "",
    s.text,
    (s.sources ?? []).map(([k, n]) => `${SOURCE_KO[k] ?? k} ${n}`).join(", "),
  ]);
  if (rows.length) out.push({ kind: "table", headers: ["근거 사건 시각", "이야기 문장", "근거"], rows });
  return out;
}
function incidentItem(ev: REvent): unknown {
  const t = eventTime(ev);
  return {
    root: ev.root, title: bare(ev.title), level: String(ev.level).toLowerCase(), score: ev.score ?? null, reached: ev.reached ?? [],
    triage: ev.triage?.state ?? "new", action: ev.triage?.action ?? null, last_activity: t ? rfc3339(t) : null,
    root_image: ev.root_image ?? null, egress: ev.egress ?? null, egress_ip: ev.egress_ip ?? null,
    sentences: (ev.sentences ?? []).map((s) => ({ at: s.ts ? rfc3339(ftToUnix(s.ts)) : null, text: s.text })),
    facts: (ev.items ?? []).map((it) => ({ label: it.label, value: it.value })),
  };
}
/// 인시던트 구역. 기간 안에 마지막 활동이 있는 사건만(시각을 모르는 사건은 싣고 그 수를 설명에 적는다). 심각도 → 최신 순.
/// `partial` = 목록을 끝까지 받지 못했는가(받은 것만 실었다고 적는다)
export function incidentsSection(events: REvent[], period: Period, partial = false): Section {
  let unknown = 0;
  const inRange = events.filter((ev) => {
    const t = eventTime(ev);
    if (t === null) { unknown++; return true; }
    return t >= period.from && t <= period.to;
  });
  inRange.sort((a, b) => (LEVEL_RANK[String(b.level).toLowerCase()] ?? 0) - (LEVEL_RANK[String(a.level).toLowerCase()] ?? 0) || (eventTime(b) ?? 0) - (eventTime(a) ?? 0));
  const shown = inRange.slice(0, MAX_INCIDENTS);
  const notes = ["기간 안에 마지막 활동이 있는 사건입니다(처리 상태와 관계없이 모두). 심각도 높은 순, 같은 심각도는 최신 순.",
    "문장은 화면에 보이는 문장 그대로이며, 이 PC가 기록한 사실입니다. 접속지의 나라·조직은 PC 안의 오프라인 주소 자료 기준이라 실제 위치와 다를 수 있습니다."];
  notes.push("시각·근거 칸이 빈 문장은 서비스가 그 문장에 시각과 근거 건수를 따로 붙이지 않은 것입니다.");
  if (unknown) notes.push(`마지막 활동 시각을 받지 못한 사건 ${unknown}건은 기간과 관계없이 실었습니다.`);
  if (partial) notes.push("사건 목록을 끝까지 받지 못했습니다. 받은 사건만 실었습니다.");
  return {
    id: "incidents", title: "인시던트", count: inRange.length, shown: shown.length, notes,
    blocks: shown.length ? shown.flatMap(incidentBlocks) : [{ kind: "para", text: "기간 안에 기록된 사건이 없습니다." }],
    items: shown.map(incidentItem),
  };
}

// ── 차단 기록 ────────────────────────────────────────────────────────────
export interface RBlocked {
  ts: number; app: string; dir: string; proto: number; remote: string; rport: number; lport: number; loopback: boolean; filter_id: number;
  rule: { kind: string; name: string; provider?: string; gone?: boolean; policy_id?: number | null; policy_name?: string | null };
}
export const BLOCK_KIND_KO: Record<string, string> = {
  ours: "Story Firewall 정책", ours_unknown: "우리 목록에 없는 필터", windows_firewall: "Windows 방화벽 규칙",
  windows_service_hardening: "Windows 서비스 강화", windows_app_isolation: "Windows 앱 격리", windows_other: "Windows 보안 기능",
  system: "시스템 필터", other: "다른 보안 프로그램", unknown: "규칙 정보 없음",
};
function blockedTarget(b: RBlocked): string {
  if (b.loopback) return `이 PC 안(localhost) :${b.dir === "in" ? b.lport : b.rport || b.lport}`;
  const addr = b.remote.includes(":") ? `[${b.remote}]` : b.remote;
  const head = `${addr || "(주소 없음)"}${b.rport ? `:${b.rport}` : ""}`;
  return b.dir === "in" ? `${head} → 내 포트 ${b.lport}` : head;
}
const DIR_KO: Record<string, string> = { in: "들어옴", out: "나감", fwd: "전달" };
function ruleName(b: RBlocked): string {
  const nm = b.rule.policy_name || b.rule.name || "";
  return nm ? `${BLOCK_KIND_KO[b.rule.kind] ?? b.rule.kind} '${nm}'` : BLOCK_KIND_KO[b.rule.kind] ?? b.rule.kind;
}
/// 차단 기록 구역. `items` = blocked.recent 가 준 줄(최신 순), `matched` = 서비스가 기간 안에서 센 수, `ringTotal`·`oldest` = 보관 고리의 크기와 가장 오래된 시각.
/// 규칙별 건수와 상위 차단 목적지는 **받은 줄 안에서** 센다 — 그 기준을 설명에 적는다(2.6·3.1 "기준")
export function blockedSection(items: RBlocked[], period: Period, meta: { matched?: number; ringTotal?: number; oldest?: number | null } = {}): Section {
  const rows = items.filter((b) => b.ts >= period.from && b.ts <= period.to);
  const count = Math.max(meta.matched ?? rows.length, rows.length);
  const tally = <K>(key: (b: RBlocked) => string, make: (b: RBlocked) => K) => {
    const m = new Map<string, { n: number; first: number; last: number; v: K }>();
    for (const b of rows) {
      const k = key(b);
      const e = m.get(k);
      if (e) { e.n++; e.first = Math.min(e.first, b.ts); e.last = Math.max(e.last, b.ts); } else m.set(k, { n: 1, first: b.ts, last: b.ts, v: make(b) });
    }
    return [...m.values()].sort((a, b) => b.n - a.n || b.last - a.last);
  };
  const byRule = tally((b) => `${b.rule.kind}\u0000${b.rule.policy_id ?? ""}\u0000${b.rule.name}`, (b) => ({ kind: b.rule.kind, name: ruleName(b) }));
  const byDest = tally((b) => `${b.dir}\u0000${blockedTarget(b)}\u0000${b.app}`, (b) => ({ target: blockedTarget(b), dir: b.dir, app: b.app }));
  const notes = [`기준: 서비스가 메모리에 둔 최근 차단 기록${meta.ringTotal !== undefined ? `(지금 ${meta.ringTotal}건` : "("}${meta.oldest ? `, 가장 오래된 것 ${when(meta.oldest)}` : ""}) 가운데 기간 안의 것을 셌습니다. 그보다 오래된 차단은 들어 있지 않습니다.`,
    "Windows 방화벽·다른 보안 프로그램이 막은 것도 함께 셉니다(규칙 종류로 구별)."];
  // 53차 Q5: 서비스가 가진 기록이 기간을 다 덮지 못하면 구역 맨 위에 눈에 띄게 적는다 — "기간 안 전체"로 읽히면 안 된다
  if (meta.oldest && meta.oldest > period.from) notes.unshift(`주의: 이 구역은 기간 전체가 아니라 ${when(meta.oldest)} 이후의 차단만 담고 있습니다. 서비스가 가진 가장 오래된 차단 기록이 그 시각이며, 그 전은(서비스가 다시 시작됐거나 오래된 기록이 밀려나) 이 보고서에 없습니다 — 차단이 없었다는 뜻이 아닙니다.`);
  else if (meta.oldest === null && !rows.length) notes.unshift("주의: 서비스가 가진 차단 기록이 없습니다. 서비스를 다시 시작한 뒤라면 그 전의 차단은 이 보고서에 없습니다(없었다는 뜻이 아닙니다).");
  if (rows.length < count) notes.push(`기간 안 ${count}건 가운데 최근 ${rows.length}건만 받아, 아래 표는 그 ${rows.length}건으로 셌습니다.`);
  const blocks: Block[] = rows.length
    ? [
        { kind: "heading", text: "규칙별 차단 건수" },
        { kind: "table", headers: ["건수", "막은 규칙", "처음", "마지막"], rows: byRule.slice(0, MAX_ROWS).map((e) => [String(e.n), e.v.name, when(e.first), when(e.last)]) },
        { kind: "heading", text: "상위 차단 목적지" },
        { kind: "table", headers: ["건수", "방향", "상대", "프로그램", "마지막"], rows: byDest.slice(0, 100).map((e) => [String(e.n), DIR_KO[e.v.dir] ?? "-", e.v.target, e.v.app || "(프로그램 모름)", when(e.last)]) },
        { kind: "heading", text: "차단 기록(최신 순)" },
        { kind: "table", headers: ["시각", "방향", "상대", "프로그램", "막은 규칙"], rows: rows.slice(0, MAX_ROWS).map((b) => [when(b.ts), DIR_KO[b.dir] ?? "-", blockedTarget(b), b.app || "(프로그램 모름)", ruleName(b)]) },
      ]
    : [{ kind: "para", text: "기간 안에 받은 차단 기록이 없습니다." }];
  return {
    id: "blocked", title: "차단 기록", count, shown: Math.min(rows.length, MAX_ROWS), notes, blocks,
    items: rows.slice(0, MAX_ROWS).map((b) => ({ at: rfc3339(b.ts), dir: b.dir, proto: b.proto, remote: b.remote, rport: b.rport, lport: b.lport, loopback: b.loopback, app: b.app, rule_kind: b.rule.kind, rule: b.rule.policy_name || b.rule.name || null, policy_id: b.rule.policy_id ?? null })),
  };
}

// ── 정책 ─────────────────────────────────────────────────────────────────
export interface RPolicy {
  id: number; name: string; state: string; version: number; state_ko?: string; summary?: string; expires?: string | null; created_ts?: number | null;
  origin?: { kind: string; label?: string };
  child_blocks?: { path: string | null; expires_at: number | null }[];
}
export interface RAddressBlock { policy_name: string; address: string; expires_at: number | null }
export interface RHistory { policy: string; ts: number; action: string; result: string; actor: string }
/// 기한까지 남은 시간("3시간 12분 남음" · "지남" · "기한 없음")
export function remainText(at: number | null | undefined, nowSec: number): string {
  if (!at) return "기한 없음";
  const left = at - nowSec;
  if (left <= 0) return `${when(at)} (지남)`;
  const d = Math.floor(left / 86400), h = Math.floor((left % 86400) / 3600), m = Math.floor((left % 3600) / 60);
  return `${when(at)}까지 (${d ? `${d}일 ` : ""}${h ? `${h}시간 ` : ""}${m}분 남음)`;
}
const originKo = (o: RPolicy["origin"]) => (o?.kind === "story" ? `인시던트에서(${o.label ?? ""})` : o?.kind === "first_run_watch" ? "첫 실행 관찰실" : "직접 작성");
/// 정책 구역 — 기간이 없는 구역이라 "만든 시각 기준"으로 적는다(1장 2번). 변경 이력만 기간으로 거른다
export function policySection(list: RPolicy[], addr: RAddressBlock[], history: RHistory[], period: Period, nowSec: number, historyMissing = 0): Section {
  const live = list.filter((p) => p.state === "Applied" || p.state === "Confirmed");
  const rest = list.filter((p) => !live.includes(p));
  const row = (p: RPolicy) => [p.state_ko ?? p.state, p.name, p.summary ?? "", p.expires ?? "기한 없음", originKo(p.origin), `판 ${p.version}`, when(p.created_ts)];
  const hist = history.filter((h) => h.ts >= period.from && h.ts <= period.to).sort((a, b) => b.ts - a.ts);
  const notes = ["건수는 지금 적용된 규칙(정책) 수입니다.", `지금 적용된 규칙은 보고서를 만든 시각(${when(nowSec)}) 기준입니다. 변경 이력만 기간으로 걸렀습니다.`];
  if (historyMissing) notes.push(`정책 ${historyMissing}건의 변경 이력은 받지 못해 싣지 못했습니다.`);
  const blocks: Block[] = [{ kind: "heading", text: `지금 적용된 규칙 ${live.length}건` }];
  const headers = ["상태", "이름", "내용", "만료", "만든 곳", "판", "만든 시각"];
  blocks.push(live.length ? { kind: "table", headers, rows: live.map(row) } : { kind: "para", text: "지금 적용된 정책이 없습니다." });
  const kids = live.flatMap((p) => (p.child_blocks ?? []).map((c) => [p.name, c.path ?? "(경로 모름)", remainText(c.expires_at, nowSec)]));
  if (kids.length) blocks.push({ kind: "heading", text: "기한부 실행 파일 차단" }, { kind: "table", headers: ["정책", "실행 파일", "남은 시간"], rows: kids.slice(0, MAX_ROWS) });
  if (addr.length) blocks.push({ kind: "heading", text: "기한부 주소 차단" }, { kind: "table", headers: ["정책", "주소", "남은 시간"], rows: addr.slice(0, MAX_ROWS).map((a) => [a.policy_name, a.address, remainText(a.expires_at, nowSec)]) });
  if (rest.length) blocks.push({ kind: "heading", text: `지금 걸려 있지 않은 정책 ${rest.length}건(되돌림·일시 중지·만료)` }, { kind: "table", headers, rows: rest.slice(0, MAX_ROWS).map(row) });
  blocks.push({ kind: "heading", text: "기간 안 변경 이력" });
  blocks.push(hist.length ? { kind: "table", headers: ["시각", "정책", "한 일", "결과", "누가"], rows: hist.slice(0, MAX_ROWS).map((h) => [when(h.ts), h.policy, h.action, h.result, h.actor]) } : { kind: "para", text: "기간 안에 정책 변경 기록이 없습니다." });
  return {
    id: "policy", title: "정책", count: live.length, shown: live.length, notes, blocks,
    items: list.map((p) => ({ id: p.id, name: p.name, state: p.state, live: live.includes(p), version: p.version, summary: p.summary ?? null, expires: p.expires ?? null, origin: p.origin?.kind ?? "manual", created_at: p.created_ts ? rfc3339(p.created_ts) : null })),
  };
}

// ── 모형·저장 ────────────────────────────────────────────────────────────
export function makeReport(sections: Section[], period: Period, nowSec: number, version: string, masked: boolean): Report {
  return { program: "storyfirewall", program_title: "Story Firewall", version, generated_at: rfc3339(nowSec), period_from: rfc3339(period.from), period_to: rfc3339(period.to), masked, source_url: SOURCE_URL, sections };
}
/// 한 건짜리 보고서(사건 카드의 [이 건 보고서]): 같은 형식으로 그 한 건만. 기간 = 그 사건의 첫 문장 ~ 마지막 활동
export function singleIncidentReport(ev: REvent, nowSec: number, version: string, masked: boolean): Report {
  const times = (ev.sentences ?? []).filter((s) => s.ts).map((s) => ftToUnix(s.ts));
  const last = eventTime(ev) ?? nowSec;
  const first = times.length ? Math.min(...times, last) : last;
  const period = { from: first, to: Math.max(last, first) };
  const sec = incidentsSection([ev], period);
  sec.notes = ["사건 한 건만 담은 보고서입니다.", ...sec.notes.slice(1)];
  return makeReport([sec], period, nowSec, version, masked);
}

export type SaveResult = { ok: true; saved: false } | { ok: true; saved: true; path: string; bytes: number } | { ok: false; message: string };
/// 코어가 가리기 → HTML → 저장 대화상자 → 쓰기. 대화상자에서 취소하면 saved:false(파일을 남기지 않는다)
export async function saveReport(r: Report, nowSec: number): Promise<SaveResult> {
  if (!inTauri) return { ok: false, message: "이 화면에서는 보고서를 파일로 저장할 수 없습니다" };
  try {
    const v = (await invoke("report_save", { model: r, stamp: stampOf(nowSec) })) as { saved?: boolean; path?: string; bytes?: number } | null;
    return v?.saved === true ? { ok: true, saved: true, path: String(v.path ?? ""), bytes: Number(v.bytes ?? 0) } : { ok: true, saved: false };
  } catch (err) {
    return { ok: false, message: String(err).slice(0, 300) };
  }
}
export async function openReport(what: "file" | "folder"): Promise<string | null> {
  if (!inTauri) return "이 화면에서는 열 수 없습니다";
  try {
    await invoke("report_open", { what });
    return null;
  } catch (err) {
    return String(err).slice(0, 200);
  }
}
