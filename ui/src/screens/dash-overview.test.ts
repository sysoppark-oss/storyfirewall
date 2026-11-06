import { describe, it, expect } from "vitest";
import { overview, type DashConn } from "./dash-overview";

// 2026-11-06 12:00 (현지 시각 기준으로 계산)
const noon = new Date(2026, 10, 6, 12, 0, 0).getTime() / 1000;
const ft = (unix: number) => (unix + 11_644_473_600) * 10_000_000;
const c = (o: Partial<DashConn>): DashConn => ({ image: "C:\\a\\chrome.exe", direction: "out", count: 1, sent: 0, recv: 0, remote_id: 1, last_ft: ft(noon - 60), ...o });

describe("대시보드 개요 숫자", () => {
  it("원격·프로그램·양·들어온 연결·오늘 처음", () => {
    const o = overview(
      [
        c({ remote_id: 1, sent: 100, recv: 1000, new_asn: true, where: { scope: "public", org: "Example", cc: "NL" }, new_cc: true }),
        c({ remote_id: 2, sent: 50, recv: 10 }),
        c({ image: "C:\\b\\helper.exe", remote_id: 3, direction: "in", count: 4, sent: 5, recv: 5 }),
      ],
      [
        { proto: "tcp", laddr: "0.0.0.0", lport: 3389, any_addr: true, image: "svchost.exe" },
        { proto: "tcp", laddr: "::", lport: 3389, any_addr: true, image: "svchost.exe" },
        { proto: "tcp", laddr: "127.0.0.1", lport: 9000, any_addr: false, image: "x.exe" },
      ],
      noon,
    );
    expect(o.remotes).toBe(3);
    expect(o.programs).toBe(2);
    expect([o.sent, o.recv]).toEqual([155, 1015]);
    expect([o.inbound, o.inboundRemotes]).toEqual([4, 1]);
    expect([o.newOrgs, o.newCountries]).toEqual([1, 1]);
    expect(o.exposed.map((l) => l.lport)).toEqual([3389]);
    expect(o.topPrograms[0]).toMatchObject({ name: "chrome.exe", remotes: 2 });
  });

  it("시간대 막대는 오늘 것만, 마지막 접속 시각의 시(hour)에", () => {
    const o = overview([c({ count: 3, last_ft: ft(noon - 60) }), c({ count: 9, last_ft: ft(noon - 86400) })], [], noon);
    expect(o.hourly[11]).toBe(3);
    expect(o.hourly.reduce((a, b) => a + b, 0)).toBe(3);
  });
});
