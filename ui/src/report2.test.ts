// 상세 보고서 2단계 구역(summary·network·installs) 모형 시험
import { describe, it, expect } from "vitest";
import { summarySection, networkSection, installsSection, firstSeenRemotes, incidentCounts, coverNote, bytesText, type RConn, type RInstall } from "./report2";
import { SECTIONS, madeCells, type REvent } from "./report";

const ft = (unix: number) => unix * 10_000_000 + 116444736000000000;
const NOW = 1_795_800_000;
const P = { from: NOW - 86400, to: NOW };
const conn = (o: Partial<RConn>): RConn => ({
  process_id: 1, image: "C:\\Apps\\a.exe", remote_id: 1, raddr: "8.8.8.8", rport: 443, direction: "out", count: 1,
  first_ft: ft(NOW - 100), last_ft: ft(NOW - 50), sent: 0, recv: 0, where: { scope: "public", country: "미국", org: "Google" }, ...o,
});
const ev = (state: "new" | "investigated" | "acted" | "closed", lastUnix: number | null): REvent => ({
  root: 1, title: "t", level: "suspicious", sentences: [], ...(lastUnix ? { last_ts: ft(lastUnix) } : {}), triage: { state },
});

describe("구역 목록", () => {
  it("3.1 의 메뉴 순서이고 2단계 구역이 들어 있다", () => {
    expect(SECTIONS.map((s) => s.id)).toEqual(["summary", "network", "incidents", "blocked", "installs", "policy"]);
  });
  it("보고서 만든 기록이 2단계 구역 이름을 화면 말로 보여 준다", () => {
    const c = madeCells({ at: "2026-11-28T07:00:00+09:00", sections: ["summary", "installs"], period_from: "2026-11-21T07:00:00+09:00", period_to: "2026-11-28T07:00:00+09:00", masked: true, raw_json: false, path: "x", ok: true });
    expect(c[1]).toBe("대시보드 요약, 설치 이력");
  });
});

describe("summary", () => {
  it("시간대 요약을 기간으로 더하고 기간 밖 시간은 뺀다", () => {
    const hours = [
      { hour: NOW - 3 * 86400, sent: 999, recv: 999, conns: 999 },
      { hour: NOW - 7200, sent: 1024, recv: 2048, conns: 5, blocked: 2 },
      { hour: NOW - 3600, sent: 0, recv: 0, conns: 3, blocked: 1, blocked_lost: 4 },
    ];
    const s = summarySection({ hours, hoursFrom: NOW - 30 * 86400, events: [], eventsPartial: false, conns: [], connsFrom: NOW - 7 * 86400, connsCapped: false, health: null }, P);
    const f = Object.fromEntries((s.blocks[0] as { rows: [string, string][] }).rows);
    expect(f["연결 수"]).toBe("8건");
    expect(f["주고받은 양"]).toBe("보냄 1.0 KB · 받음 2.0 KB");
    expect(f["차단 수(우리 정책)"]).toContain("최소 3건");
    expect(f["수집기 상태"]).toBe("받지 못함");
  });
  it("받지 못한 조회는 0 이 아니라 '받지 못함'", () => {
    const s = summarySection({ hours: null, hoursFrom: 0, events: null, eventsPartial: false, conns: null, connsFrom: 0, connsCapped: false, health: null }, P);
    const f = Object.fromEntries((s.blocks[0] as { rows: [string, string][] }).rows);
    for (const k of ["연결 수", "사건", "처음 본 목적지"]) expect(f[k]).toBe("받지 못함");
  });
  it("조회가 기간을 다 덮지 못하면 맨 위에 적는다", () => {
    const long = { from: NOW - 20 * 86400, to: NOW };
    const s = summarySection({ hours: [], hoursFrom: NOW - 30 * 86400, events: [], eventsPartial: false, conns: [], connsFrom: NOW - 7 * 86400, connsCapped: false, health: null }, long);
    expect(s.notes[0]).toMatch(/^주의: ‘처음 본 목적지’ 수는 /);
  });
  it("사건은 처리 안 함/처리함으로, 기간 밖은 빼고 시각 모르는 것은 센다", () => {
    const c = incidentCounts([ev("new", NOW - 10), ev("investigated", NOW - 10), ev("acted", NOW - 10), ev("closed", NOW - 5 * 86400), ev("closed", null)], P);
    expect(c).toEqual({ open: 2, closed: 2, total: 4 });
  });
  it("처음 본 목적지: 조회 창 안 첫 접속이 아니라 목적지를 처음 기록한 때로 센다(검수 1번)", () => {
    const cs = [
      // 몇 달째 매일 쓰는 목적지 — 조회 창 안 첫 접속(first_ft)은 기간 안이지만 처음 본 것은 아니다
      conn({ remote_id: 1, raddr: "1.1.1.1", first_ft: ft(NOW - 100), remote_first_ft: ft(NOW - 90 * 86400) }),
      conn({ process_id: 2, remote_id: 2, raddr: "2.2.2.2", first_ft: ft(NOW - 100), remote_first_ft: ft(NOW - 100) }),
      conn({ process_id: 3, remote_id: 2, raddr: "2.2.2.2", first_ft: ft(NOW - 50), remote_first_ft: ft(NOW - 100) }),
    ];
    expect(firstSeenRemotes(cs, P)).toBe(1);
    // 예전 서비스(칸 없음)는 셀 수 없다 — 0 이 아니라 null
    expect(firstSeenRemotes([conn({})], P)).toBeNull();
  });
  it("처음 본 목적지: 나간 연결의 주소(IP)로 센다 — 들어온 임시 포트·같은 서버의 다른 포트는 하나(재검수 1번)", () => {
    const cs = [
      conn({ remote_id: 10, raddr: "5.5.5.5", rport: 51001, direction: "in", remote_first_ft: ft(NOW - 10) }),
      conn({ remote_id: 11, raddr: "5.5.5.5", rport: 51002, direction: "in", remote_first_ft: ft(NOW - 10) }),
      conn({ remote_id: 12, raddr: "6.6.6.6", rport: 443, remote_first_ft: ft(NOW - 10) }),
      conn({ remote_id: 13, raddr: "6.6.6.6", rport: 80, remote_first_ft: ft(NOW - 20) }),
      // 처음 시각을 모르는 줄은 빼고 센다(전체를 "판이 낮음"으로 만들지 않는다)
      conn({ remote_id: 14, raddr: "7.7.7.7", remote_first_ft: null }),
    ];
    expect(firstSeenRemotes(cs, P)).toBe(1);
  });
  it("상대 주소 수는 주소로 센다(재검수 2번)", () => {
    const s = networkSection([
      conn({ remote_id: 10, raddr: "5.5.5.5", rport: 51001, direction: "in", image: "C:\\S\\srv.exe" }),
      conn({ remote_id: 11, raddr: "5.5.5.5", rport: 51002, direction: "in", image: "C:\\S\\srv.exe" }),
    ], [], P, { connsFrom: NOW - 7 * 86400, capped: false });
    const inT = s.blocks.find((b) => b.kind === "table" && b.headers[0] === "받은 프로그램") as { rows: string[][] };
    expect(inT.rows[0]![3]).toBe("1");
  });
  it("기간이 조회 창과 겹치지 않으면 0 이 아니라 '받지 못함'(검수 4번)", () => {
    const old = { from: NOW - 20 * 86400, to: NOW - 19 * 86400 };
    const s = summarySection({ hours: [], hoursFrom: NOW - 30 * 86400, events: [], eventsPartial: false, conns: [], connsFrom: NOW - 7 * 86400, connsCapped: false, health: null }, old);
    const f = Object.fromEntries((s.blocks[0] as { rows: [string, string][] }).rows);
    expect(f["처음 본 목적지"]).toBe("받지 못함");
    expect(f["연결 수"]).toBe("0건");
    expect(s.notes[0]).toContain("받지 못했습니다");
    const s40 = summarySection({ hours: [], hoursFrom: NOW - 30 * 86400, events: [], eventsPartial: false, conns: [], connsFrom: NOW - 7 * 86400, connsCapped: false, health: null }, { from: NOW - 40 * 86400, to: NOW - 39 * 86400 });
    expect(Object.fromEntries((s40.blocks[0] as { rows: [string, string][] }).rows)["연결 수"]).toBe("받지 못함");
  });
});

describe("network", () => {
  it("프로그램별로 묶고 양 많은 순, 내부 주소는 나라 표에서 뺀다", () => {
    const cs = [
      conn({ image: "C:\\A\\small.exe", sent: 10, recv: 10, count: 9 }),
      conn({ image: "C:\\A\\big.exe", remote_id: 2, sent: 5000, recv: 0, count: 1, where: { scope: "public", country: "일본", org: "X" } }),
      conn({ image: "C:\\A\\big.exe", remote_id: 3, raddr: "192.168.0.2", where: { scope: "private" } }),
    ];
    const s = networkSection(cs, [], P, { connsFrom: NOW - 7 * 86400, capped: false });
    const t = s.blocks.find((b) => b.kind === "table") as { rows: string[][] };
    expect(t.rows.map((r) => r[0])).toEqual(["big.exe", "small.exe"]);
    expect(t.rows[0]![3]).toBe("2");
    const cc = s.blocks[3] as { rows: string[][] };
    expect(cc.rows.map((r) => r[0]).sort()).toEqual(["미국", "일본"]);
  });
  it("들어온 연결과 모든 주소에서 듣는 포트", () => {
    const s = networkSection([conn({ direction: "in", image: "C:\\S\\srv.exe", count: 4 })], [
      { proto: "tcp", laddr: "0.0.0.0", lport: 445, any_addr: true, image: "System" },
      { proto: "tcp", laddr: "127.0.0.1", lport: 9000, any_addr: false, image: "x.exe" },
    ], P, { connsFrom: NOW - 7 * 86400, capped: true });
    const txt = JSON.stringify(s.blocks);
    expect(txt).toContain("srv.exe");
    expect(txt).toContain("445/TCP");
    expect(txt).not.toContain("9000");
    expect(s.notes.join(" ")).toContain("더 오래된 짝은 빠졌을 수 있습니다");
  });
  it("서비스가 기간 끝으로 못 자른 경우(예전 서비스)만 마지막 기록으로 거르고 그렇다고 적는다", () => {
    const cs = [conn({ image: "C:\\A\\in.exe" }), conn({ image: "C:\\A\\late.exe", last_ft: ft(NOW + 3600) })];
    const s = networkSection(cs, [], P, { connsFrom: NOW - 7 * 86400, capped: false, windowed: false });
    const t = s.blocks.find((b) => b.kind === "table") as { rows: string[][] };
    expect(t.rows.map((r) => r[0])).toEqual(["in.exe"]);
    expect(s.notes[0]).toContain("자르지 못했습니다");
    // 잘라 준 경우는 받은 줄을 모두 센다(마지막 기록이 '만든 시각' 뒤여도 — 검수 2번 a)
    const w = networkSection(cs, [], P, { connsFrom: NOW - 7 * 86400, capped: false });
    expect(w.count).toBe(2);
  });
  it("연결 기록을 못 받으면 '받지 못함'으로 적고 듣는 포트는 그대로", () => {
    const s = networkSection(null, [], P, { connsFrom: NOW - 7 * 86400, capped: false });
    expect(s.notes[0]).toContain("받지 못함");
  });
});

describe("installs", () => {
  const run = (o: Partial<RInstall>): RInstall => ({
    root: 1, image: "C:\\Users\\me\\Downloads\\setup.exe", start_ts: ft(NOW - 100), last_ts: ft(NOW - 50), origin: "https://example.com/setup.exe",
    procs: [], files: ["C:\\Users\\me\\AppData\\Local\\X\\x.exe"], autoruns: [["HKCU\\...\\Run", "x.exe"]], remotes: [], persistence: ["schtasks /create"], signer: null, ...o,
  });
  it("기간 안 설치만, 서명 없음·인터넷 출신·자동 실행을 싣는다", () => {
    const s = installsSection([run({}), run({ root: 2, start_ts: ft(NOW - 5 * 86400) })], P, { coverFrom: NOW - 86400, limit: 100 });
    expect(s.count).toBe(1);
    const t = s.blocks[0] as { rows: string[][] };
    expect(t.rows[0]![2]).toBe("유효한 서명 확인 안 됨");
    expect(t.rows[0]![3]).toBe("https://example.com/setup.exe");
    expect(JSON.stringify(s.blocks)).toContain("schtasks /create");
  });
  it("잘렸어도 사실을 모두 담았으면(facts_complete) '이상'을 붙이지 않는다 — 화면과 같게", () => {
    const s = installsSection([run({ truncated: true, facts_complete: true })], P, { coverFrom: NOW - 86400, limit: 100 });
    expect((s.blocks[0] as { rows: string[][] }).rows[0]![4]).toBe("1개");
    const t = installsSection([run({ truncated: true })], P, { coverFrom: NOW - 86400, limit: 100 });
    expect((t.blocks[0] as { rows: string[][] }).rows[0]![4]).toBe("1개 이상");
  });
  it("기간이 30일 밖이면 '받을 수 없음'", () => {
    const s = installsSection([], { from: NOW - 40 * 86400, to: NOW - 39 * 86400 }, { coverFrom: NOW - 30 * 86400, limit: 100 });
    expect(JSON.stringify(s.blocks)).toContain("받을 수 없습니다");
  });
  it("못 받으면 '받지 못함', 상한에 닿으면 적는다", () => {
    expect(installsSection(null, P, { coverFrom: 0, limit: 100 }).notes[0]).toContain("받지 못함");
    const many = Array.from({ length: 3 }, (_, i) => run({ root: i }));
    expect(installsSection(many, P, { coverFrom: NOW - 86400, limit: 3 }).notes.join(" ")).toContain("최근 것부터 3건까지만");
  });
});

describe("작은 함수", () => {
  it("bytesText·coverNote", () => {
    expect(bytesText(0)).toBe("0 B");
    expect(bytesText(1536)).toBe("1.5 KB");
    expect(coverNote(P, P.from, "x")).toBeNull();
    expect(coverNote(P, P.from + 1, "이 구역은")).toMatch(/^주의: 이 구역은 \d{4}-/);
  });
});
