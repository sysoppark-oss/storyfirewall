// 상세 보고서 2단계(통합프로젝트 「상세 보고서 기능 — 공통 규칙과 개발 의뢰 (2판)」 3.1·3.3 의 2번): summary·network·installs.
// report.ts 와 같은 규칙: 조회 결과 → 보고서 모형(글자만)으로 바꾸는 순수 함수. 가리기·HTML 바꿔 쓰기·파일 쓰기는 코어가 한다.
// 각 구역은 "무엇을 기준으로 셌는지"를 설명(notes)에 적는다 — 서비스 조회의 기간 상한(연결 7일, 시간대 요약 30일, 설치 30일)을
// 넘는 기간이면 "기간 전체가 아니다"라고 먼저 밝힌다(차단 기록 구역의 53차 Q5 와 같은 원칙).
import { type Block, type Period, type Section, type REvent, MAX_ROWS, when, rfc3339, eventTime } from "./report";
import { HOW_FOUND, AUTORUN_SCOPE } from "./screens/installs-text";

const ftToUnix = (ft: number) => Math.floor((ft - 116444736000000000) / 10000000);
const n = (x: number) => x.toLocaleString("ko-KR");
/// 바이트 → "12.3 MB"(화면과 같은 1024 단위)
export function bytesText(b: number): string {
  if (!Number.isFinite(b) || b <= 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${i ? v.toFixed(1) : v} ${u[i]}`;
}
/// 실행 파일 경로의 끝 이름(가리기는 코어가 경로 전체에 한다 — 여기서는 보기 좋게만)
const baseName = (p: string | null | undefined) => (p ? p.split(/[\\/]/).pop() || p : "");

/// 서비스 조회가 덮는 기간의 시작(unix 초). 기간이 그보다 앞서면 구역 설명 맨 위에 적을 문장. `what` 은 조사까지("이 구역은")
export function coverNote(period: Period, coverFrom: number, what: string): string | null {
  if (coverFrom > period.to) return `주의: ${what} 받지 못했습니다. 이 기간은 서비스가 이 조회로 돌려주지 않는 기간(${when(coverFrom)} 이후만 줌)이라 이 보고서에 없습니다 — 없었다는 뜻이 아닙니다.`;
  return period.from < coverFrom ? `주의: ${what} ${when(coverFrom)} 이후만 담고 있습니다. 그 전은 서비스가 이 조회로 돌려주지 않는 기간이라 이 보고서에 없습니다 — 없었다는 뜻이 아닙니다.` : null;
}
/// 조회가 기간과 전혀 겹치지 않는가(그러면 0 이 아니라 "받지 못함")
export const outOfCover = (period: Period, coverFrom: number) => coverFrom > period.to;

// ── 대시보드 요약(summary) ──────────────────────────────────────────────
export interface RHour { hour: number; sent: number; recv: number; conns: number; blocked?: number; blocked_lost?: number }
export interface RHealth { now: number; last_event_ft: number | null; lost_24h: number; gaps_24h?: { from_ts: number; to_ts: number }[]; clock_changes_24h?: number[] }
/// connections.list 한 줄에서 요약·네트워크 구역이 읽는 칸
export interface RConn {
  process_id: number; image: string; remote_id: number; raddr: string; rport: number; proto?: string; domain?: string | null;
  direction: string; count: number; first_ft: number; last_ft: number; sent: number; recv: number;
  /// 원격지를 처음 기록한 시각(FILETIME, 조회 창과 무관). 예전 서비스는 없다
  remote_first_ft?: number | null;
  where?: { scope?: string; cc?: string; country?: string; asn?: number; org?: string } | null;
}
export interface SummaryInput {
  hours: RHour[] | null; hoursFrom: number;
  events: REvent[] | null; eventsPartial: boolean;
  conns: RConn[] | null; connsFrom: number; connsCapped: boolean;
  health: RHealth | null;
}
const OPEN = new Set(["new", "investigated"]);
/// 기간 안 사건 수: 처리 안 함(새 사건·조사됨) / 처리함(조치함·닫힘). 시각을 모르는 사건은 센다(인시던트 구역과 같은 기준)
export function incidentCounts(events: REvent[], period: Period): { open: number; closed: number; total: number } {
  let open = 0, closed = 0;
  for (const ev of events) {
    const t = eventTime(ev);
    if (t !== null && (t < period.from || t > period.to)) continue;
    if (OPEN.has(ev.triage?.state ?? "new")) open++; else closed++;
  }
  return { open, closed, total: open + closed };
}
/// 기간 안에 처음 기록된 목적지 수: 내 PC 에서 **나간** 연결의 목적지 주소(IP)마다, 이 PC가 그 주소를 처음 기록한 때(remote_first_ft — 조회 창과 무관,
/// 같은 주소의 여러 포트 가운데 가장 이른 값)가 기간 안인 것. 조회 창 안 첫 접속(first_ft)으로 세면 오래 쓰던 목적지도 "처음"이 되고(검수 1번),
/// 원격지 노드(주소:포트)로 세면 들어온 연결의 상대 임시 포트·같은 서버의 다른 포트가 따로 세어진다(재검수 1번).
/// 칸 자체가 없으면(예전 서비스) null. 칸이 null 인 줄(처음 시각 모름)은 뺀다
export function firstSeenRemotes(conns: RConn[], period: Period): number | null {
  if (conns.length && conns.every((c) => !("remote_first_ft" in c))) return null;
  const first = new Map<string, number>();
  for (const c of conns) {
    if (c.direction !== "out" || c.remote_first_ft == null) continue;
    const k = c.raddr || `#${c.remote_id}`;
    const t = ftToUnix(c.remote_first_ft);
    const p = first.get(k);
    if (p === undefined || t < p) first.set(k, t);
  }
  let k = 0;
  for (const t of first.values()) if (t >= period.from && t <= period.to) k++;
  return k;
}
export function collectorText(h: RHealth): string {
  const last = h.last_event_ft ? Math.max(0, h.now - ftToUnix(h.last_event_ft)) : null;
  const ago = last == null ? "받은 기록 없음" : last < 60 ? `${last}초 전` : last < 3600 ? `${Math.floor(last / 60)}분 전` : `${Math.floor(last / 3600)}시간 전`;
  const parts = [`마지막 기록 ${ago}`, h.lost_24h ? `최근 24시간 놓친 기록 ${n(h.lost_24h)}건` : "최근 24시간 놓친 기록 없음"];
  if (h.gaps_24h?.length) parts.push(`기록이 끊긴 구간 ${h.gaps_24h.length}곳(절전 등)`);
  if (h.clock_changes_24h?.length) parts.push(`시계 변경 ${h.clock_changes_24h.length}번`);
  return parts.join(" · ");
}
export function summarySection(x: SummaryInput, period: Period): Section {
  const notes: string[] = ["이 PC가 기록한 숫자를 기간으로 모은 것입니다. 숫자마다 센 기준을 아래에 적었습니다."];
  const facts: [string, string][] = [];
  const item: Record<string, unknown> = {};
  // 시간대 요약: 서비스가 쓰기 경로에서 시간마다 쌓아 둔 표(30일 보관). 시간 단위라 기간 양 끝 시간은 통째로 들어간다
  if (x.hours && !outOfCover(period, x.hoursFrom)) {
    const hs = x.hours.filter((h) => h.hour + 3600 > period.from && h.hour <= period.to);
    const sum = (f: (h: RHour) => number) => hs.reduce((a, h) => a + (f(h) || 0), 0);
    const conns = sum((h) => h.conns), sent = sum((h) => h.sent), recv = sum((h) => h.recv), blocked = sum((h) => h.blocked ?? 0), lost = sum((h) => h.blocked_lost ?? 0);
    facts.push(["연결 수", `${n(conns)}건`], ["주고받은 양", `보냄 ${bytesText(sent)} · 받음 ${bytesText(recv)}`]);
    facts.push(["차단 수(우리 정책)", lost ? `최소 ${n(blocked)}건 (집계가 밀려 못 센 ${n(lost)}건 따로)` : `${n(blocked)}건`]);
    Object.assign(item, { connections: conns, sent_bytes: sent, recv_bytes: recv, blocked, blocked_lost: lost });
    notes.push("연결 수·주고받은 양·차단 수는 서비스가 시간마다 쌓아 둔 요약 표에서 셌습니다(시간 단위라 기간 양 끝의 시간은 그 시간 전체가 들어갑니다). 차단 수는 Story Firewall 정책이 막은 것만입니다 — Windows 방화벽이 막은 것은 ‘차단 기록’ 구역에 있습니다.");
    const c = coverNote(period, x.hoursFrom, "연결 수·주고받은 양·차단 수는");
    if (c) notes.unshift(c);
  } else {
    facts.push(["연결 수", "받지 못함"], ["주고받은 양", "받지 못함"], ["차단 수(우리 정책)", "받지 못함"]);
    if (x.hours) notes.unshift(coverNote(period, x.hoursFrom, "연결 수·주고받은 양·차단 수는")!);
  }
  const k = x.conns && !outOfCover(period, x.connsFrom) ? firstSeenRemotes(x.conns, period) : null;
  if (k !== null) {
    facts.push(["처음 본 목적지", `${n(k)}곳${x.connsCapped ? " 이상" : ""}`]);
    item.first_seen_remotes = k;
    notes.push(`‘처음 본 목적지’는 기간 안에 이 PC에서 나간 연결의 목적지 주소(포트는 따지지 않음) 가운데, 이 PC가 그 주소를 처음 기록한 때가 기간 안인 곳입니다(서비스가 돌려준 연결 기록 — ${when(x.connsFrom)} 이후, 최근 것부터 최대 1,000줄 — 기준). 그 전 기록이 보관 기간이 지나 지워졌거나 이 PC가 기록을 시작한 지 얼마 안 됐으면(설치 직후) 대부분을 처음으로 셉니다.`);
    const c = coverNote(period, x.connsFrom, "‘처음 본 목적지’ 수는");
    if (c) notes.unshift(c);
  } else {
    facts.push(["처음 본 목적지", "받지 못함"]);
    if (x.conns && outOfCover(period, x.connsFrom)) notes.unshift(coverNote(period, x.connsFrom, "‘처음 본 목적지’ 수는")!);
    else if (x.conns) notes.push("‘처음 본 목적지’는 서비스 판이 낮아(목적지를 처음 기록한 시각을 주지 않음) 세지 못했습니다.");
  }
  if (x.events) {
    const ic = incidentCounts(x.events, period);
    facts.push(["사건", `처리 안 함 ${n(ic.open)}건 · 처리함 ${n(ic.closed)}건`]);
    Object.assign(item, { incidents_open: ic.open, incidents_closed: ic.closed });
    notes.push("사건 수는 ‘인시던트’ 구역과 같은 기준(기간 안에 마지막 활동이 있는 사건, 처리 상태와 관계없이)입니다. 처리 안 함 = 새 사건·조사됨, 처리함 = 조치함·닫힘.");
    if (x.eventsPartial) notes.push("사건 목록을 끝까지 받지 못해 받은 사건만 셌습니다.");
  } else facts.push(["사건", "받지 못함"]);
  if (x.health) {
    facts.push(["수집기 상태", collectorText(x.health)]);
    Object.assign(item, { collector_last_event: x.health.last_event_ft ? rfc3339(ftToUnix(x.health.last_event_ft)) : null, collector_lost_24h: x.health.lost_24h });
    notes.push("수집기 상태는 보고서를 만든 시각 기준입니다.");
  } else facts.push(["수집기 상태", "받지 못함"]);
  return { id: "summary", title: "대시보드 요약", count: 1, shown: 1, notes, blocks: [{ kind: "facts", rows: facts }], items: [item] };
}

// ── 네트워크(network) ───────────────────────────────────────────────────
export interface RListener { proto: string; laddr: string; lport: number; any_addr: boolean; image: string | null }
const isPublic = (c: RConn) => !c.where?.scope || c.where.scope === "public";
/// `windowed` = 서비스가 기간 끝(until)으로 잘라 준 기록인가(지금까지가 끝인 기간이면 늘 참). 거짓이면(예전 서비스의 직접 기간)
/// 마지막 기록이 기간 안인 짝만 싣고, 그 짝의 횟수에 기간 뒤의 것이 섞였을 수 있다고 적는다
export function networkSection(conns: RConn[] | null, listeners: RListener[] | null, period: Period, meta: { connsFrom: number; capped: boolean; windowed?: boolean }): Section {
  const notes: string[] = [];
  const blocks: Block[] = [];
  const items: unknown[] = [];
  let total = 0;
  const cut = (what: string, all: number, shown: number) => { if (all > shown) notes.push(`${what}는 전체 ${n(all)}개 가운데 상위 ${n(shown)}개만 실었습니다.`); };
  if (!conns || outOfCover(period, meta.connsFrom)) {
    notes.push(conns ? coverNote(period, meta.connsFrom, "연결 기록은")! : "연결 기록을 받지 못했습니다 — 아래는 ‘없음’이 아니라 ‘받지 못함’입니다.");
  } else {
    const windowed = meta.windowed !== false;
    // 서비스가 [기간 시작(또는 덮는 시작) ~ 기간 끝]으로 이미 잘라 준다. 잘라 주지 못한 경우만 마지막 기록으로 거른다
    const rows = windowed ? conns : conns.filter((c) => { const t = ftToUnix(c.last_ft); return t >= period.from && t <= period.to; });
    notes.push(`서비스가 돌려준 연결 기록(${when(meta.connsFrom)} 이후, 최근 것부터 최대 1,000줄 — 한 줄은 프로그램 하나와 목적지 하나의 짝) ${n(rows.length)}줄로 셌습니다.${meta.capped ? " 1,000줄을 다 받아, 더 오래된 짝은 빠졌을 수 있습니다." : ""}`);
    if (!windowed) notes.unshift("주의: 서비스 판이 낮아 연결 기록을 기간 끝에서 자르지 못했습니다. 마지막 기록이 기간 안인 짝만 실었고, 그 짝의 횟수에는 기간 뒤의 접속이 섞였을 수 있습니다. 기간 안에 접속했지만 기간 뒤에도 접속한 짝은 빠졌습니다.");
    notes.push("보냄·받음은 프로그램과 목적지 짝마다 쌓인 누계라 기간으로 자르지 못합니다(그 짝을 처음 기록한 때부터의 양). 기간 안의 전체 양은 ‘대시보드 요약’ 구역의 ‘주고받은 양’을 보십시오.");
    const c = coverNote(period, meta.connsFrom, "이 구역은");
    if (c) notes.unshift(c);
    // 프로그램별: 연결 횟수·목적지 수·양
    // 목적지·상대 수는 주소(IP)로 센다 — 원격지 노드는 주소:포트라 상대의 임시 포트마다 따로 세어진다(재검수 2번)
    const addr = (r: RConn) => r.raddr || `#${r.remote_id}`;
    const byProc = new Map<string, { image: string; count: number; remotes: Set<string>; sent: number; recv: number }>();
    for (const r of rows) {
      const k = r.image || "(프로그램 확인 못 함)";
      const e = byProc.get(k) ?? { image: k, count: 0, remotes: new Set<string>(), sent: 0, recv: 0 };
      e.count += r.count || 0; e.remotes.add(addr(r)); e.sent += r.sent || 0; e.recv += r.recv || 0;
      byProc.set(k, e);
    }
    const procs = [...byProc.values()].sort((a, b) => b.sent + b.recv - (a.sent + a.recv) || b.count - a.count);
    total = procs.length;
    cut("프로그램 표", procs.length, 100);
    blocks.push({ kind: "heading", text: "프로그램별 연결·사용량 상위" });
    blocks.push(procs.length
      ? { kind: "table", headers: ["프로그램", "경로", "연결 횟수", "상대 주소 수", "보냄", "받음"], rows: procs.slice(0, 100).map((p) => [baseName(p.image), p.image, n(p.count), n(p.remotes.size), bytesText(p.sent), bytesText(p.recv)]) }
      : { kind: "para", text: "기간 안 연결 기록이 없습니다." });
    // 목적지 나라·조직(공인 주소만)
    const tally = (key: (c: RConn) => string | undefined) => {
      const m = new Map<string, { n: number; remotes: Set<string> }>();
      for (const r of rows) {
        if (!isPublic(r)) continue;
        const k = key(r) || "(자료 없음)";
        const e = m.get(k) ?? { n: 0, remotes: new Set<string>() };
        e.n += r.count || 0; e.remotes.add(addr(r));
        m.set(k, e);
      }
      return [...m.entries()].sort((a, b) => b[1].remotes.size - a[1].remotes.size || b[1].n - a[1].n);
    };
    const cc = tally((r) => r.where?.country ?? r.where?.cc);
    const org = tally((r) => r.where?.org ?? (r.where?.asn ? `AS${r.where.asn}` : undefined));
    cut("나라 표", cc.length, 50);
    cut("조직 표", org.length, 50);
    blocks.push({ kind: "heading", text: "목적지 나라 상위" });
    blocks.push(cc.length ? { kind: "table", headers: ["나라", "주소 수", "연결 횟수"], rows: cc.slice(0, 50).map(([k, v]) => [k, n(v.remotes.size), n(v.n)]) } : { kind: "para", text: "기간 안 공인 주소 연결이 없습니다." });
    blocks.push({ kind: "heading", text: "목적지 조직(망) 상위" });
    if (org.length) blocks.push({ kind: "table", headers: ["조직", "주소 수", "연결 횟수"], rows: org.slice(0, 50).map(([k, v]) => [k, n(v.remotes.size), n(v.n)]) });
    notes.push("나라·조직은 PC 안의 오프라인 주소 자료(DB-IP Lite) 기준이라 실제 위치와 다를 수 있습니다. 내부망·이 PC 안 주소는 나라·조직 표에서 뺐습니다.");
    // 들어온 연결
    const inbound = rows.filter((r) => r.direction === "in");
    const inByProc = new Map<string, { image: string; count: number; remotes: Set<string> }>();
    for (const r of inbound) {
      const k = r.image || "(프로그램 확인 못 함)";
      const e = inByProc.get(k) ?? { image: k, count: 0, remotes: new Set<string>() };
      e.count += r.count || 0; e.remotes.add(addr(r));
      inByProc.set(k, e);
    }
    blocks.push({ kind: "heading", text: "들어온 연결(받은 프로그램별)" });
    blocks.push(inByProc.size
      ? { kind: "table", headers: ["받은 프로그램", "경로", "들어온 횟수", "상대 주소 수"], rows: [...inByProc.values()].sort((a, b) => b.count - a.count).slice(0, 100).map((e) => [baseName(e.image), e.image, n(e.count), n(e.remotes.size)]) }
      : { kind: "para", text: "기간 안에 들어온 연결 기록이 없습니다." });
    cut("들어온 연결 표", inByProc.size, 100);
    notes.push("연결 기록에는 들어온 연결을 받은 이 PC 쪽 포트가 없어, 들어온 연결은 받은 프로그램별로 셌습니다. 그 프로그램이 듣는 포트는 아래 ‘듣는 포트’ 표에서 볼 수 있습니다(만든 시각 기준).");
    for (const p of procs.slice(0, MAX_ROWS)) items.push({ image: p.image, connections: p.count, remotes: p.remotes.size, sent_bytes: p.sent, recv_bytes: p.recv });
  }
  // 듣는 포트(만든 시각 기준)
  blocks.push({ kind: "heading", text: "모든 주소에서 듣는 포트(만든 시각 기준)" });
  if (!listeners) {
    blocks.push({ kind: "para", text: "듣는 포트 목록을 받지 못했습니다." });
  } else {
    const open = listeners.filter((l) => l.any_addr).sort((a, b) => a.lport - b.lport || a.proto.localeCompare(b.proto));
    cut("듣는 포트 표", open.length, MAX_ROWS);
    blocks.push(open.length
      ? { kind: "table", headers: ["포트", "듣는 주소", "프로그램", "경로"], rows: open.slice(0, MAX_ROWS).map((l) => [`${l.lport}/${l.proto.toUpperCase()}`, l.laddr, l.image ? baseName(l.image) : "(프로그램 확인 못 함)", l.image ?? ""]) }
      : { kind: "para", text: "모든 주소(0.0.0.0·::)에서 듣는 포트가 없습니다." });
    notes.push("듣는 포트는 기간이 없는 목록이라 보고서를 만든 시각 기준입니다. 밖에서 실제로 닿는지는 Windows 방화벽·공유기 설정에 따라 다릅니다.");
  }
  return { id: "network", title: "네트워크", count: total, shown: Math.min(total, 100), notes, blocks, items };
}

// ── 설치 이력(installs) ─────────────────────────────────────────────────
/// installs.list 한 묶음에서 보고서가 읽는 칸(화면의 InstallRun 과 같은 모양)
export interface RInstall {
  root: number; image: string; start_ts: number; last_ts: number; origin: string | null; procs: string[]; files: string[];
  autoruns: [string, string][]; remotes: [string, number][]; persistence?: string[]; grouped?: string[]; signer?: string | null; truncated?: boolean;
  /// 잘렸어도 접속·자동 실행·파일 쓰기를 한 자손은 모두 담았나(그러면 개수에 "이상"을 붙이지 않는다 — 화면과 같게)
  facts_complete?: boolean;
}
/// 만든 파일 수 칸: 자손이 잘렸고 사실을 다 담았다고 하지 않으면 "이상", 0 이면서 잘렸으면 "확인 못 함(잘림)"
function filesText(r: RInstall): string {
  const partial = !!r.truncated && !r.facts_complete;
  if (partial && !r.files.length) return "확인 못 함(잘림)";
  return `${n(r.files.length)}개${partial ? " 이상" : ""}`;
}
export function installsSection(runs: RInstall[] | null, period: Period, meta: { coverFrom: number; limit: number }): Section {
  const notes = [
    `${HOW_FOUND} 화면의 설치 이력과 같은 기준이며, 기간 안에 시작한 설치만 실었습니다.`,
    `자동 실행 등록의 ${AUTORUN_SCOPE}.`,
    "‘인터넷 출신’은 설치 파일에 붙은 내려받은 곳 표시(MOTW)를 읽은 것입니다. 표시가 없으면 비워 둡니다 — 인터넷에서 오지 않았다는 뜻은 아닙니다.",
    "‘만든 실행 파일’은 사용자가 쓸 수 있는 경로(사용자 폴더 등)에 만든 실행 파일·스크립트만 셉니다. Program Files·Windows 폴더처럼 관리자만 쓰는 곳에 만든 파일은 수집 범위 밖이라 0으로 나옵니다.",
    "‘서명’은 Windows가 믿는 인증서로 유효하게 서명한 회사 이름입니다. 자체 서명(시험용) 파일은 ‘유효한 서명 확인 안 됨’으로 나옵니다 — 인시던트 구역에서는 같은 파일을 ‘자체 서명’으로 자세히 적을 수 있습니다.",
    "한계: 이름 기준에 맞지 않는 실행 파일(예: 내려받아 바로 실행한 이름 모를 프로그램)은 이 구역에 나오지 않습니다 — 그런 실행은 ‘인시던트’ 구역의 4장 판정(유입 → 실행 → 자리잡기 → 외부 접속)으로 봅니다. 서명은 설치 프로그램 자신의 것만 적었습니다. 서비스는 설치 묶음을 최근 것부터 400개까지 들고 있습니다.",
  ];
  if (runs && outOfCover(period, meta.coverFrom)) {
    notes.unshift(coverNote(period, meta.coverFrom, "설치 이력은")!);
    return { id: "installs", title: "설치 이력", count: 0, shown: 0, notes, blocks: [{ kind: "para", text: "이 기간의 설치 이력은 받을 수 없습니다." }], items: [] };
  }
  if (!runs) {
    notes.unshift("설치 이력을 받지 못했습니다 — 아래는 ‘없음’이 아니라 ‘받지 못함’입니다.");
    return { id: "installs", title: "설치 이력", count: 0, shown: 0, notes, blocks: [{ kind: "para", text: "설치 이력을 받지 못했습니다." }], items: [] };
  }
  const c = coverNote(period, meta.coverFrom, "이 구역은");
  if (c) notes.unshift(c);
  const rows = runs.filter((r) => { const t = ftToUnix(r.start_ts); return t >= period.from && t <= period.to; }).sort((a, b) => b.start_ts - a.start_ts);
  if (runs.length >= meta.limit) notes.push(`서비스가 최근 것부터 ${meta.limit}건까지만 돌려줘, 그보다 오래된 설치는 빠졌을 수 있습니다.`);
  const blocks: Block[] = [];
  if (!rows.length) blocks.push({ kind: "para", text: "기간 안에 시작한 설치가 없습니다." });
  else {
    blocks.push({ kind: "table", headers: ["시작", "설치 프로그램", "서명", "인터넷 출신", "만든 실행 파일", "자동 실행 등록"], rows: rows.map((r) => [
      when(ftToUnix(r.start_ts)), r.image, r.signer ? r.signer : "유효한 서명 확인 안 됨", r.origin ?? "", filesText(r), `${n(r.autoruns.length)}건`,
    ]) });
    const auto = rows.flatMap((r) => r.autoruns.map(([where, target]) => [when(ftToUnix(r.start_ts)), baseName(r.image), where, target]));
    if (auto.length > MAX_ROWS) notes.push(`자동 실행 등록이 ${n(auto.length)}건이라 표에는 ${n(MAX_ROWS)}건만 실었습니다.`);
    if (auto.length) blocks.push({ kind: "heading", text: "자동 실행 등록" }, { kind: "table", headers: ["설치 시작", "설치 프로그램", "등록 위치", "대상"], rows: auto.slice(0, MAX_ROWS) });
    const pers = rows.flatMap((r) => (r.persistence ?? []).map((p) => [when(ftToUnix(r.start_ts)), baseName(r.image), p]));
    if (pers.length > MAX_ROWS) notes.push(`자리잡기 명령이 ${n(pers.length)}건이라 표에는 ${n(MAX_ROWS)}건만 실었습니다.`);
    if (pers.length) blocks.push({ kind: "heading", text: "자리잡기 명령(예약 작업·서비스 등록 등)" }, { kind: "table", headers: ["설치 시작", "설치 프로그램", "명령"], rows: pers.slice(0, MAX_ROWS) });
    const files = rows.flatMap((r) => r.files.map((f) => [when(ftToUnix(r.start_ts)), baseName(r.image), f]));
    if (files.length) blocks.push({ kind: "heading", text: "만든 실행 파일·스크립트" }, { kind: "table", headers: ["설치 시작", "설치 프로그램", "파일"], rows: files.slice(0, MAX_ROWS) });
    if (files.length > MAX_ROWS) notes.push(`만든 파일이 ${n(files.length)}개라 표에는 ${n(MAX_ROWS)}개만 실었습니다.`);
  }
  return {
    id: "installs", title: "설치 이력", count: rows.length, shown: rows.length, notes, blocks,
    items: rows.map((r) => ({ started_at: rfc3339(ftToUnix(r.start_ts)), image: r.image, signer: r.signer ?? null, origin: r.origin, files: r.files.length, autoruns: r.autoruns, persistence: r.persistence ?? [], truncated: !!r.truncated && !r.facts_complete })),
  };
}
