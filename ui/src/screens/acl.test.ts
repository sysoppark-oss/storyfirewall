import { describe, it, expect } from "vitest";
import { aclToYaml, yamlToAcl, sides, endText, endLabels, splitList, ruleSentence, addrListError, portListError, type AclRule } from "./acl";

const r = (o: Partial<AclRule>): AclRule => ({ action: "block", dir: "out", iface: "", proto: "any", srcIp: "", srcPort: "", dstIp: "", dstPort: "", ...o });

describe("ACL 표 ↔ 정책 YAML", () => {
  it("방향에 따라 출발지·목적지가 이 PC·상대로 바뀐다", () => {
    expect(sides(r({ dir: "out", srcIp: "192.168.0.10", dstIp: "1.1.1.1" }))).toMatchObject({ localIp: "192.168.0.10", remoteIp: "1.1.1.1" });
    expect(sides(r({ dir: "in", srcIp: "1.1.1.1", dstIp: "192.168.0.10", dstPort: "3389" }))).toMatchObject({ localIp: "192.168.0.10", localPort: "3389", remoteIp: "1.1.1.1" });
    expect(endLabels("in")).toEqual(["출발지 (상대)", "목적지 (이 PC)"]);
  });

  it("번호 순서대로 acl.N·priority N, 빈 칸은 조건 없음", () => {
    const y = aclToYaml([
      r({ action: "allow", iface: "Wi-Fi", proto: "tcp", dstIp: "10.0.0.5", dstPort: "443" }),
      r({ dir: "both", dstIp: "10.0.0.0/24" }),
      r({ dir: "in", proto: "icmp", srcIp: "203.0.113.0/24" }),
    ]);
    expect(y).toContain('- name: "acl.1"\n  priority: 1\n  action: allow\n');
    expect(y).toContain('"interface":"Wi-Fi"');
    expect(y).toContain('- name: "acl.3"\n  priority: 3\n  action: block\n');
    expect(y).toContain('"protocol":"icmp"');
    expect(y).not.toContain("local_ip\":[]");
  });

  it("만든 YAML 을 다시 읽으면 같은 표", () => {
    const rules = [
      r({ action: "allow", iface: "이더넷 2", proto: "udp", srcIp: "192.168.0.10", srcPort: "5000-5010", dstIp: "10.0.0.1, 10.0.0.2", dstPort: "53" }),
      r({ dir: "in", srcIp: "203.0.113.9", dstPort: "3389" }),
    ];
    const back = yamlToAcl(aclToYaml(rules));
    expect(back).not.toBeNull();
    expect(back![0]).toEqual({ ...rules[0], dstIp: "10.0.0.1, 10.0.0.2" });
    expect(back![1]).toEqual(rules[1]);
  });

  it("인터페이스 이름에 따옴표·콜론이 있어도 YAML 이 깨지지 않는다", () => {
    const y = aclToYaml([r({ iface: 'Wi-Fi "집": 2' })]);
    expect(yamlToAcl(y)![0]!.iface).toBe('Wi-Fi "집": 2');
  });

  it("손으로 쓴 다른 꼴은 표로 읽지 않는다", () => {
    expect(yamlToAcl("- name: x\n  action: block\n  match:\n    direction: out\n")).toBeNull();
  });

  it("목록·표기", () => {
    expect(splitList(" 1.1.1.1,  8.8.8.8 ")).toEqual(["1.1.1.1", "8.8.8.8"]);
    expect(endText("", "")).toBe("모두");
    expect(endText("10.0.0.1", "443")).toBe("10.0.0.1:443");
    expect(endText("10.0.0.1, 10.0.0.2", "443")).toBe("10.0.0.1, 10.0.0.2 · 포트 443");
    expect(endText("", "3389")).toBe("포트 3389");
  });
});

describe("규칙 미리보기·칸 검사", () => {
  it("조사 병기 없이 화살표 꼴", () => {
    expect(ruleSentence(r({ dstIp: "1.1.1.1", dstPort: "443", proto: "tcp" }))).toBe("이 PC → 1.1.1.1:443 · TCP · 나가는 통신 차단");
    const inAllow = ruleSentence(r({ action: "allow", dir: "in", srcIp: "192.168.0.0/24", dstPort: "3389" }));
    expect(inAllow).toBe("192.168.0.0/24 → 이 PC 포트 3389 · TCP·UDP · 들어오는 통신 허용 (Windows 방화벽 규칙은 그대로)");
    expect(inAllow).not.toMatch(/\(으\)|\(이\)|\(을\)/);
    expect(ruleSentence(r({ dir: "both", iface: "Wi-Fi" }))).toBe("이 PC ↔ 모든 상대 · TCP·UDP · 양방향 통신 차단 · Wi-Fi에서만");
  });
  it("주소·포트 칸", () => {
    expect(addrListError("1.1.1.1, 10.0.0.0/8, lan, 2001:db8::1", false)).toBeNull();
    expect(addrListError("1.1.1.999", false)).not.toBeNull();
    expect(addrListError("internet", true)).not.toBeNull();
    expect(portListError("443, 8000-8100")).toBeNull();
    expect(portListError("70000")).not.toBeNull();
    expect(portListError("9000-8000")).not.toBeNull();
  });
});
