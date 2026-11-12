import { describe, expect, it } from "vitest";
import { targetText, ruleText, protoWord, kindFilter, groupBlocked, type BlockedItem } from "./blocked-log";

const rule = (kind: BlockedItem["rule"]["kind"], extra: Partial<BlockedItem["rule"]> = {}): BlockedItem["rule"] => ({ kind, name: "", description: "", provider: "", gone: false, ...extra });

describe("차단 기록(사용자 요청 2026-11-09)", () => {
  it("대상 줄: localhost·들어옴·IPv6", () => {
    expect(targetText({ dir: "out", remote: "127.0.0.1", rport: 8815, lport: 51000, loopback: true })).toBe("이 PC 안(localhost) :8815");
    expect(targetText({ dir: "in", remote: "203.0.113.5", rport: 4444, lport: 3389, loopback: false })).toBe("203.0.113.5:4444 → 내 포트 3389");
    expect(targetText({ dir: "out", remote: "2001:db8::1", rport: 443, lport: 0, loopback: false })).toBe("[2001:db8::1]:443");
  });
  it("막은 규칙: 종류마다 무엇이·어디서 고치나, 판단 말 없음", () => {
    expect(ruleText(rule("ours", { policy_name: "긴급 차단", policy_id: 4 }), 1).what).toBe("Story Firewall 정책 '긴급 차단'");
    expect(ruleText(rule("windows_firewall", { name: "Block Edge" }), 1).what).toBe("Windows 방화벽 규칙 'Block Edge'");
    expect(ruleText(rule("other", { provider: "Acme AV", name: "web" }), 1).what).toBe("다른 보안 프로그램 'Acme AV'의 규칙 'web'");
    expect(ruleText(rule("unknown"), 77).what).toContain("#77");
    expect(ruleText(rule("ours_unknown", { name: "Story Firewall core" }), 1).what).toContain("지금 우리 정책 목록에 없음");
    for (const k of ["ours", "ours_unknown", "windows_firewall", "windows_service_hardening", "windows_app_isolation", "windows_other", "system", "other", "unknown"] as const) {
      const t = ruleText(rule(k, { name: "x" }), 1);
      expect(t.what + t.fix).not.toMatch(/악성|의심|위험|안전/);
    }
  });
  it("규칙 이름의 제어 문자는 지운다", () => {
    expect(ruleText(rule("windows_firewall", { name: "a‮b" }), 1).what).not.toContain("‮");
  });
  it("프로토콜·종류 거르기", () => {
    expect(protoWord(6)).toBe("TCP");
    expect(protoWord(17)).toBe("UDP");
    const items = [{ rule: rule("ours") }, { rule: rule("other") }] as BlockedItem[];
    expect(kindFilter(items, "other").length).toBe(1);
    expect(kindFilter(items, null).length).toBe(2);
  });
});

describe("차단 기록 묶기", () => {
  const it0 = (ts: number, app = "a.exe", name = "Query User"): BlockedItem => ({ ts, app, dir: "in", proto: 6, remote: "192.168.0.3", rport: 7680, lport: 7680, loopback: false, filter_id: 1, rule: rule("windows_firewall", { name }) });
  it("잇단 같은 일은 한 줄, 사이에 다른 것이 끼면 따로", () => {
    const g = groupBlocked([it0(30), it0(20), it0(10), it0(5, "b.exe"), it0(1)]);
    expect(g.map((x) => x.n)).toEqual([3, 1, 1]);
    expect([g[0]!.from, g[0]!.to]).toEqual([10, 30]);
  });
  it("Default 규칙은 허용 규칙이 없다는 설명", () => {
    expect(ruleText(rule("windows_firewall", { name: "Default Outbound" }), 1).fix).toContain("허용 규칙");
  });
});

import { scopeArg, scopeFilter, todayHead, countByPolicy, type RuleSum as RS, type BlockedItem as BI } from "./blocked-log";
describe("차단 기록 첫 화면·거르기(UI 명세 5판 1장, 5장 6·7항)", () => {
  const item = (ts: number, policy_id: number | null = null): BI => ({ ts, app: "a.exe", dir: "out", proto: 6, remote: "1.2.3.4", rport: 443, lport: 0, loopback: false, filter_id: 1,
    rule: { kind: policy_id ? "ours" : "windows_firewall", name: "r", description: "", provider: "", gone: false, policy_id } });
  const mid = 1_000_000;
  it("주소 매개변수는 모양이 맞을 때만", () => {
    expect(scopeArg({ range: "today", policy: 7, policyName: "p" })).toEqual({ today: true, policyId: 7, policyName: "p" });
    expect(scopeArg({ range: "week", policy: "7", policyName: 3 })).toEqual({});
    expect(scopeArg({ policy: -1 })).toEqual({});
    expect(scopeArg({ policy: 1.5 })).toEqual({});
    expect(scopeArg({ kind: "ours" })).toEqual({ kind: "ours" });
    expect(scopeArg({ kind: "constructor" })).toEqual({});
  });
  it("오늘만·정책 거르기", () => {
    const xs = [item(mid + 10, 7), item(mid - 10, 7), item(mid + 20, 8), item(mid + 30)];
    expect(scopeFilter(xs, { today: true }, mid).length).toBe(3);
    expect(scopeFilter(xs, { policyId: 7 }, mid).length).toBe(2);
    expect(scopeFilter(xs, { today: true, policyId: 7 }, mid).length).toBe(1);
    expect(scopeFilter(xs, {}, mid).length).toBe(4);
  });
  it("머리: 오늘 건수와 마지막 시각, 잘렸으면 '이상', 없으면 숫자를 그리지 않는다", () => {
    expect(todayHead([], mid, 500)).toBe("오늘 차단 없음");
    expect(todayHead([item(mid - 5)], mid, 500)).toBe("오늘 차단 없음");
    expect(todayHead([item(mid + 60), item(mid + 30), item(mid - 5)], mid, 500)).toMatch(/^오늘 차단 2건\(모든 규칙\) · 마지막 /);
    // 받은 목록이 상한까지 찼고 전부 오늘 것이면 더 있을 수 있다
    expect(todayHead([item(mid + 3), item(mid + 2)], mid, 2)).toMatch(/^오늘 차단 2건 이상\(모든 규칙\) · /);
    expect(todayHead([item(mid + 3), item(mid - 2)], mid, 2)).toMatch(/^오늘 차단 1건\(모든 규칙\) · /);
  });
  it("정책별 누적: 우리 정책만 더한다", () => {
    const r = (n: number, kind: RS["rule"]["kind"], policy_id: number | null): RS => ({ filter_id: 1, app: "", n, first: 0, last: 0, remote: "", rport: 0, dir: "out", loopback: false, rule: { kind, name: "", provider: "", policy_id } });
    const m = countByPolicy([r(3, "ours", 7), r(4, "ours", 7), r(9, "windows_firewall", null), r(2, "ours", 8), r(5, "ours", null)]);
    expect([...m.entries()]).toEqual([[7, 7], [8, 2]]);
  });
});
