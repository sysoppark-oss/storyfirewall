import { describe, expect, it } from "vitest";
import { parseEndpoint, parseNamed, targetOf, endpointText, uniqueEndpoints, diagnoseText } from "./netx";

describe("NetX 인계 대상(주소·포트만)", () => {
  it("IPv4 주소와 포트", () => {
    expect(parseEndpoint("203.0.113.9:443")).toEqual({ ip: "203.0.113.9", port: 443 });
    expect(parseEndpoint(" 203.0.113.9 ")).toEqual({ ip: "203.0.113.9" });
    expect(parseEndpoint("010.0.0.1:80")).toEqual({ ip: "10.0.0.1", port: 80 });
  });
  it("IPv6 주소", () => {
    expect(parseEndpoint("[2001:db8::1]:8443")).toEqual({ ip: "2001:db8::1", port: 8443 });
    expect(parseEndpoint("2001:db8::1")).toEqual({ ip: "2001:db8::1" });
  });
  it("도메인·이상한 값은 보내지 않는다", () => {
    for (const s of ["c2.evil.example:8443", "example.com", "", undefined, null, "1.2.3.4:0", "1.2.3.4:70000", "256.1.1.1:80", "1.2.3.4:80; calc", "1.2.3", "[::1]:x", "a".repeat(100)]) {
      expect(parseEndpoint(s as string)).toBeNull();
    }
  });
  it("표시와 중복 제거", () => {
    expect(endpointText({ ip: "2001:db8::1", port: 443 })).toBe("[2001:db8::1]:443");
    expect(endpointText({ ip: "1.2.3.4" })).toBe("1.2.3.4");
    const l = uniqueEndpoints([{ ip: "1.1.1.1", port: 1 }, { ip: "1.1.1.1", port: 1 }, { ip: "1.1.1.1", port: 2 }], 8);
    expect(l).toHaveLength(2);
    expect(uniqueEndpoints(Array.from({ length: 20 }, (_, i) => ({ ip: `10.0.0.${i}` })), 8)).toHaveLength(8);
  });
  it("이름 접속지는 숫자 주소를 따라간다", () => {
    expect(parseNamed("Edge.Microsoft.com:443")).toEqual({ name: "edge.microsoft.com", port: 443 });
    expect(parseNamed("example.com.")).toEqual({ name: "example.com" });
    for (const s of ["203.0.113.9:443", "localhost:80", "a b.com", "evil.com/x", "-a.com:1", "a..com", "한글.kr", "a.com:0", "", null]) expect(parseNamed(s as string)).toBeNull();
    // 숫자 접속지: 그대로(짝 주소는 쓰지 않는다)
    expect(targetOf("203.0.113.9:443", "1.1.1.1")).toEqual({ ip: "203.0.113.9", port: 443 });
    // 이름 접속지 + 서비스가 준 짝 주소: 주소가 대상, 이름은 꼬리표
    expect(targetOf("edge.microsoft.com:443", "142.250.197.142")).toEqual({ ip: "142.250.197.142", port: 443, name: "edge.microsoft.com" });
    // 짝 주소가 없거나 주소가 아니면 넘길 대상이 없다(이름만으로는 넘기지 않는다)
    expect(targetOf("edge.microsoft.com:443", undefined)).toBeNull();
    expect(targetOf("edge.microsoft.com:443", "not-an-ip")).toBeNull();
    expect(targetOf(undefined, "1.1.1.1")).toBeNull();
  });
  it("결과 문장: 이름이 따라갔을 때만 이름을 적고 단정하지 않는다", () => {
    const e = { ip: "142.250.197.142", port: 443, name: "edge.microsoft.com" };
    expect(diagnoseText(e, { ok: true, accepted: true, opened: true, nameSent: true })).toBe("142.250.197.142:443 (edge.microsoft.com 접속으로 기록된 주소) — NetX로 넘겼습니다. 진단 실행은 NetX에서 직접 누르세요");
    expect(diagnoseText(e, { ok: true, accepted: true, opened: true, nameSent: false })).toBe("142.250.197.142:443 — NetX로 넘겼습니다. 진단 실행은 NetX에서 직접 누르세요");
  });
  it("결과 문장은 실행을 약속하지 않는다", () => {
    const e = { ip: "203.0.113.9", port: 443 };
    expect(diagnoseText(e, { ok: true, accepted: true, opened: true })).toBe("203.0.113.9:443 — NetX로 넘겼습니다. 진단 실행은 NetX에서 직접 누르세요");
    expect(diagnoseText(e, { ok: true, accepted: true, opened: false })).toContain("NetX 창을 직접 열어 주세요");
    expect(diagnoseText(e, { ok: true, accepted: false, opened: false })).toContain("받지 않았습니다");
    expect(diagnoseText(e, { ok: false, message: "NetX를 먼저 켜 주세요" })).toBe("NetX를 먼저 켜 주세요");
  });
});
