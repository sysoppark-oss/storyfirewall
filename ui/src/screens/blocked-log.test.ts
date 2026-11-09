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
    for (const k of ["ours", "windows_firewall", "windows_service_hardening", "windows_app_isolation", "windows_other", "system", "other", "unknown"] as const) {
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
