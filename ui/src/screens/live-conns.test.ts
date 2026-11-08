import { describe, it, expect } from "vitest";
import { sortOpen, closedSince, connKey, type OpenConn } from "./live-conns";

const c = (o: Partial<OpenConn>): OpenConn => ({ proto: "tcp", laddr: "10.0.0.2", lport: 50000, raddr: "203.0.113.1", rport: 443, state: "연결됨", pid: 1, v4: true, ...o });

describe("지금 열린 연결(UI 명세 4판 3-4)", () => {
  it("인시던트 있는 연결 → 연결됨 → 프로그램 이름 순", () => {
    const xs = [c({ pid: 1, image: "C:\\b.exe" }), c({ pid: 2, image: "C:\\a.exe", state: "닫는 중" }), c({ pid: 3, image: "C:\\z.exe", story_root: 9 }), c({ pid: 4, image: "C:\\a.exe" })];
    expect(sortOpen(xs).map((x) => x.pid)).toEqual([3, 4, 1, 2]);
  });
  it("이번 갱신에 사라진 연결만 '닫힘'", () => {
    const a = c({ pid: 1 }), b = c({ pid: 2, rport: 80 });
    expect(closedSince([a, b], [a]).map(connKey)).toEqual([connKey(b)]);
    expect(closedSince([], [a])).toEqual([]);
    // 같은 주소라도 PID 가 다르면 다른 연결
    expect(closedSince([a], [c({ pid: 7 })]).length).toBe(1);
  });
});
