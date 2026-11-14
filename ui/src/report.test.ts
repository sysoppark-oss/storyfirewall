import { describe, expect, it } from "vitest";
import { blockedSection, incidentsSection, incidentBlocks, makeReport, periodOf, policySection, remainText, rfc3339, singleIncidentReport, stampOf, MAX_INCIDENTS, type REvent, type RBlocked } from "./report";

const FT = (unix: number) => unix * 10_000_000 + 116_444_736_000_000_000;
const NOW = Math.floor(new Date(2026, 10, 14, 5, 12, 0).getTime() / 1000);
const ev = (root: number, level: string, lastUnix: number | null, extra: Partial<REvent> = {}): REvent => ({
  root, title: `[의심] app${root}.exe — 4장 외부 접속까지 진행 (점수 80)`, level,
  sentences: [{ text: `app${root}.exe 가 203.0.113.${root % 250}:443 에 접속했습니다`, ts: lastUnix ? FT(lastUnix) : 0, sources: [["etw", 2]] }],
  ...(lastUnix ? { last_ts: FT(lastUnix) } : {}), ...extra,
});

describe("기간", () => {
  it("오늘은 자정부터, 직접은 끝 날짜의 끝까지(지금보다 뒤면 지금까지)", () => {
    const t = periodOf("today", NOW)!;
    expect(new Date(t.from * 1000).getHours()).toBe(0);
    expect(t.to).toBe(NOW);
    expect(periodOf("7d", NOW)).toEqual({ from: NOW - 7 * 86400, to: NOW });
    const c = periodOf("custom", NOW, "2026-11-10", "2026-11-12")!;
    expect(c.to - c.from).toBe(3 * 86400 - 1);
    expect(periodOf("custom", NOW, "2026-11-10", "2026-11-14")!.to).toBe(NOW);
  });
  it("틀린 날짜·거꾸로 된 기간은 받지 않는다", () => {
    expect(periodOf("custom", NOW, "2026-02-30", "2026-03-01")).toBeNull();
    expect(periodOf("custom", NOW, "2026-11-12", "2026-11-10")).toBeNull();
    expect(periodOf("custom", NOW, "", "2026-11-10")).toBeNull();
  });
  it("시각 글자", () => {
    expect(rfc3339(NOW)).toMatch(/^2026-11-14T05:12:00[+-]\d\d:\d\d$/);
    expect(stampOf(NOW)).toBe("20261114-051200");
  });
});

describe("인시던트 구역", () => {
  const period = { from: NOW - 86400, to: NOW };
  it("기간 밖 사건은 빼고, 심각도 → 최신 순으로 싣는다", () => {
    const s = incidentsSection([ev(1, "Watch", NOW - 100), ev(2, "Critical", NOW - 5000), ev(3, "Suspicious", NOW - 10), ev(4, "Critical", NOW - 3 * 86400)], period);
    expect(s.count).toBe(3);
    expect(s.shown).toBe(3);
    expect(s.blocks.filter((b) => b.kind === "heading").map((b) => (b as { text: string }).text)).toEqual(["app2.exe", "app3.exe", "app1.exe"]);
  });
  it("문장은 받은 그대로 싣고, 제목의 머리·꼬리는 뗀다", () => {
    const b = incidentBlocks(ev(7, "Suspicious", NOW - 10, { triage: { state: "acted", action: "cut", recur_count: 2 }, reached: [2, 4], egress: "evil.example:443", egress_ip: "203.0.113.7", egress_where: { country: "미국", org: "Example LLC" } }));
    expect(b[0]).toEqual({ kind: "heading", text: "app7.exe" });
    const facts = (b[1] as { rows: [string, string][] }).rows;
    expect(facts).toContainEqual(["심각도", "높음"]);
    expect(facts).toContainEqual(["처리 상태", "조치 완료 · 격리 · 재발 2회"]);
    expect(facts).toContainEqual(["가장 늦은 외부 접속지", "evil.example:443 (203.0.113.7) — 미국 · Example LLC"]);
    const table = b.find((x) => x.kind === "table") as { rows: string[][] };
    expect(table.rows[0]![1]).toBe("app7.exe 가 203.0.113.7:443 에 접속했습니다");
    expect(table.rows[0]![2]).toBe("실시간 기록 2");
  });
  it("카드 사실 줄에 서명이 있으면 겹쳐 적지 않고, 숫자 접속지는 주소를 되풀이하지 않는다. 5장에도 이름이 붙는다", () => {
    const b = incidentBlocks(ev(8, "Critical", NOW - 10, { reached: [2, 5], root_signature: { signer: null, sig_status: "nosignature" }, items: [{ label: "서명", value: "없음" }], egress: "203.0.113.8:443", egress_ip: "203.0.113.8" }));
    const facts = (b[1] as { rows: [string, string][] }).rows;
    expect(facts.filter(([k]) => k === "서명")).toEqual([["서명", "없음"]]);
    expect(facts).toContainEqual(["가장 늦은 외부 접속지", "203.0.113.8:443"]);
    expect(facts.find(([k]) => k === "이어진 장")![1]).toContain("5장 파괴 징후");
  });
  it("상한을 넘으면 전체 수와 실은 수가 다르다", () => {
    const many = Array.from({ length: MAX_INCIDENTS + 30 }, (_, i) => ev(i + 1, "Watch", NOW - i));
    const s = incidentsSection(many, period);
    expect(s.count).toBe(MAX_INCIDENTS + 30);
    expect(s.shown).toBe(MAX_INCIDENTS);
    expect(s.items.length).toBe(MAX_INCIDENTS);
  });
  it("시각을 모르는 사건은 빼지 않고 그 수를 적는다. 다 못 받았으면 그렇게 적는다", () => {
    const s = incidentsSection([ev(1, "Watch", null)], period, true);
    expect(s.count).toBe(1);
    expect(s.notes.join(" ")).toContain("시각을 받지 못한 사건 1건");
    expect(s.notes.join(" ")).toContain("끝까지 받지 못했습니다");
  });
  it("사건이 없으면 0건이라고 적는다", () => {
    const s = incidentsSection([], period);
    expect(s.count).toBe(0);
    expect(s.blocks).toEqual([{ kind: "para", text: "기간 안에 기록된 사건이 없습니다." }]);
  });
  it("한 건 보고서: 구역 하나, 사건 하나, 기간은 그 사건의 시각", () => {
    const r = singleIncidentReport(ev(9, "Critical", NOW - 500), NOW, "0.1.6-dev.abc", true);
    expect(r.sections.length).toBe(1);
    expect(r.sections[0]!.count).toBe(1);
    expect(r.masked).toBe(true);
    expect(r.period_to).toBe(rfc3339(NOW - 500));
    expect(r.sections[0]!.notes[0]).toBe("사건 한 건만 담은 보고서입니다.");
  });
  it("판이 다른 서비스가 칸을 빼도 죽지 않는다", () => {
    const odd = { root: 1, title: null, level: "weird", sentences: [] } as unknown as REvent;
    expect(() => incidentsSection([odd], period)).not.toThrow();
    expect(incidentBlocks(odd)[0]).toEqual({ kind: "heading", text: "사건 #1" });
  });
});

describe("차단 기록 구역", () => {
  const b = (ts: number, kind: string, name: string, remote: string, extra: Partial<RBlocked> = {}): RBlocked => ({ ts, app: "C:\\Users\\pjg\\a.exe", dir: "out", proto: 6, remote, rport: 443, lport: 50000, loopback: false, filter_id: 1, rule: { kind, name }, ...extra });
  const period = { from: NOW - 3600, to: NOW };
  it("규칙별 건수·상위 목적지를 받은 줄에서 세고 기준을 적는다", () => {
    const s = blockedSection([b(NOW - 1, "ours", "block-x", "203.0.113.1", { rule: { kind: "ours", name: "f", policy_id: 3, policy_name: "block-x" } }), b(NOW - 2, "windows_firewall", "Default Outbound", "203.0.113.2"), b(NOW - 3, "windows_firewall", "Default Outbound", "203.0.113.2"), b(NOW - 7200, "ours", "old", "203.0.113.9")], period, { matched: 3, ringTotal: 1408, oldest: NOW - 90000 });
    expect(s.count).toBe(3);
    const tables = s.blocks.filter((x) => x.kind === "table") as { rows: string[][] }[];
    expect(tables[0]!.rows.map((r) => [r[0], r[1]])).toEqual([["2", "Windows 방화벽 규칙 'Default Outbound'"], ["1", "Story Firewall 정책 'block-x'"]]);
    expect(tables[1]!.rows[0]!.slice(0, 3)).toEqual(["2", "나감", "203.0.113.2:443"]);
    expect(tables[2]!.rows.length).toBe(3);
    expect(s.notes[0]).toContain("지금 1408건");
  });
  it("서비스가 가진 기록이 기간을 다 덮지 못하면 맨 위에 주의를 적는다", () => {
    const week = { from: NOW - 7 * 86400, to: NOW };
    const s = blockedSection([b(NOW - 1, "ours", "p", "203.0.113.1")], week, { matched: 1, ringTotal: 1, oldest: NOW - 3600 });
    expect(s.notes[0]).toMatch(/^주의: 이 구역은 기간 전체가 아니라 .* 이후의 차단만/);
    // 기간을 다 덮으면 주의가 없다
    expect(blockedSection([b(NOW - 1, "ours", "p", "203.0.113.1")], period, { oldest: NOW - 90000 }).notes[0]).toMatch(/^기준:/);
    // 기록이 하나도 없을 때(서비스 재시작 직후)
    expect(blockedSection([], week, { matched: 0, ringTotal: 0, oldest: null }).notes[0]).toMatch(/^주의: 서비스가 가진 차단 기록이 없습니다/);
  });
  it("기간 안 전체보다 적게 받았으면 그렇게 적는다", () => {
    const s = blockedSection([b(NOW - 1, "ours", "p", "203.0.113.1")], period, { matched: 5000 });
    expect(s.count).toBe(5000);
    expect(s.shown).toBe(1);
    expect(s.notes.join(" ")).toContain("5000건 가운데 최근 1건만");
  });
  it("들어오는 차단·IPv6·localhost 표기", () => {
    const s = blockedSection([b(NOW - 1, "ours", "p", "2001:db8::1", { dir: "in", lport: 3389 }), b(NOW - 2, "ours", "p", "127.0.0.1", { loopback: true, rport: 8080 })], period);
    const rows = (s.blocks.filter((x) => x.kind === "table")[2] as { rows: string[][] }).rows;
    expect(rows[0]![2]).toBe("[2001:db8::1]:443 → 내 포트 3389");
    expect(rows[1]![2]).toBe("이 PC 안(localhost) :8080");
  });
});

describe("정책 구역", () => {
  it("지금 적용된 것과 아닌 것을 나누고, 이력만 기간으로 거른다", () => {
    const s = policySection(
      [{ id: 1, name: "block-a", state: "Confirmed", version: 2, state_ko: "적용 중", summary: "a.exe 나감 차단", created_ts: NOW - 500, origin: { kind: "story", label: "a.exe" }, child_blocks: [{ path: "C:\\x.exe", expires_at: NOW + 3 * 3600 + 12 * 60 }] }, { id: 2, name: "old", state: "RolledBack", version: 1, state_ko: "되돌림" }],
      [{ policy_name: "block-a", address: "203.0.113.5", expires_at: null }],
      [{ policy: "block-a", ts: NOW - 100, action: "apply", result: "ok", actor: "pjg" }, { policy: "old", ts: NOW - 40 * 86400, action: "rollback", result: "ok", actor: "pjg" }],
      { from: NOW - 86400, to: NOW }, NOW,
    );
    expect(s.count).toBe(1);
    const heads = s.blocks.filter((x) => x.kind === "heading").map((x) => (x as { text: string }).text);
    expect(heads).toEqual(["지금 적용된 규칙 1건", "기한부 실행 파일 차단", "기한부 주소 차단", "지금 걸려 있지 않은 정책 1건(되돌림·일시 중지·만료)", "기간 안 변경 이력"]);
    const tables = s.blocks.filter((x) => x.kind === "table") as { rows: string[][] }[];
    expect(tables[0]!.rows[0]!.slice(0, 5)).toEqual(["적용 중", "block-a", "a.exe 나감 차단", "기한 없음", "인시던트에서(a.exe)"]);
    expect(tables[1]!.rows[0]![2]).toContain("3시간 12분 남음");
    expect(tables[4]!.rows.length).toBe(1);
  });
  it("남은 시간", () => {
    expect(remainText(null, NOW)).toBe("기한 없음");
    expect(remainText(NOW - 1, NOW)).toContain("지남");
    expect(remainText(NOW + 86400 + 60, NOW)).toContain("1일 1분 남음");
  });
});

describe("모형", () => {
  it("공통 머리 값", () => {
    const r = makeReport([], { from: NOW - 10, to: NOW }, NOW, "0.1.6", false);
    expect(r.program).toBe("storyfirewall");
    expect(r.masked).toBe(false);
    expect(r.generated_at).toBe(rfc3339(NOW));
    expect(r.source_url).toBe("https://github.com/sysoppark-oss/storyfirewall");
  });
});

// 접점(Rust crates/report ↔ 화면): 같은 고정 자료를 Rust 시험(crates/report/tests/ui_model.rs)이 읽는다.
// 모형의 모양을 바꾸면 VITE_SF_WRITE_FIXTURE=1 로 다시 쓰고 Rust 시험도 함께 돌린다
// @ts-ignore — node 내장 모듈(@types/node 없이 시험에서만 씀)
import { readFileSync, writeFileSync } from "node:fs";
describe("접점", () => {
  it("화면이 만든 모형 = Rust 가 읽는 고정 자료", () => {
    const T = 1794000000; // 고정 시각(시각대와 무관하게 같은 값이 되도록 시각 글자는 빼고 견준다)
    const period = { from: T - 86400, to: T };
    const r = makeReport([
      incidentsSection([ev(7, "Suspicious", T - 10, { title: "[의심] <img src=x onerror=1>.exe — 4장 외부 접속까지 진행", root_image: "C:\\Users\\pjg\\Downloads\\a.exe", egress: "evil.example:443", egress_ip: "203.0.113.7", items: [{ label: "내 주소", value: "192.168.0.7" }] })], period),
      blockedSection([
        { ts: T - 1, app: "C:\\Users\\pjg\\a.exe", dir: "out", proto: 6, remote: "203.0.113.7", rport: 443, lport: 50000, loopback: false, filter_id: 1, rule: { kind: "ours", name: "f", policy_id: 3, policy_name: "block-x" } },
        { ts: T - 2, app: "", dir: "in", proto: 6, remote: "192.168.0.7", rport: 51000, lport: 3389, loopback: false, filter_id: 2, rule: { kind: "windows_firewall", name: "Default Inbound" } },
      ], period, { matched: 2, ringTotal: 2, oldest: T - 2 }),
      policySection([{ id: 1, name: "block-x", state: "Confirmed", version: 1, state_ko: "적용 중", created_ts: T - 500 }], [], [{ policy: "block-x", ts: T - 400, action: "apply", result: "ok", actor: "pjg" }], period, T),
    ], period, T, "0.1.6-dev.test", true);
    // 시각 글자는 시험을 돌리는 PC 의 시각대를 따른다 — 견줄 때는 숫자 시각으로 바꿔 뺀다
    const stable = JSON.stringify(r, null, 1).replace(/\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d([+-]\d\d:\d\d)?/g, "T");
    const file = new URL("../../crates/report/tests/ui-model.json", import.meta.url);
    if ((import.meta.env as Record<string, string | undefined>)["VITE_SF_WRITE_FIXTURE"] === "1") writeFileSync(file, stable + "\n");
    expect(readFileSync(file, "utf8") as string).toBe(stable + "\n");
  });
});
