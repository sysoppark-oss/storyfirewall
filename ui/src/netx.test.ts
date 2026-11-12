import { describe, expect, it } from "vitest";
import { parseEndpoint, endpointText, uniqueEndpoints, diagnoseText } from "./netx";

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
  it("결과 문장은 실행을 약속하지 않는다", () => {
    const e = { ip: "203.0.113.9", port: 443 };
    expect(diagnoseText(e, { ok: true, accepted: true, opened: true })).toBe("203.0.113.9:443 — NetX로 넘겼습니다. 진단 실행은 NetX에서 직접 누르세요");
    expect(diagnoseText(e, { ok: true, accepted: true, opened: false })).toContain("NetX 창을 직접 열어 주세요");
    expect(diagnoseText(e, { ok: true, accepted: false, opened: false })).toContain("받지 않았습니다");
    expect(diagnoseText(e, { ok: false, message: "NetX를 먼저 켜 주세요" })).toBe("NetX를 먼저 켜 주세요");
  });
});
