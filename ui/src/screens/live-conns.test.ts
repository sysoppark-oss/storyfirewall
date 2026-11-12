import { describe, it, expect } from "vitest";
import { sortOpen, closedSince, connKey, openedText, homeCountry, type OpenConn } from "./live-conns";

const c = (o: Partial<OpenConn>): OpenConn => ({ proto: "tcp", laddr: "10.0.0.2", lport: 50000, raddr: "203.0.113.1", rport: 443, state: "연결됨", pid: 1, v4: true, ...o });

describe("지금 열린 연결(UI 명세 4판 3-4)", () => {
  it("인시던트 있는 연결 → 연결됨 → 프로그램 이름 순", () => {
    const xs = [c({ pid: 1, image: "C:\\b.exe" }), c({ pid: 2, image: "C:\\a.exe", state: "닫는 중" }), c({ pid: 3, image: "C:\\z.exe", story_root: 9 }), c({ pid: 4, image: "C:\\a.exe" })];
    expect(sortOpen(xs).map((x) => x.pid)).toEqual([3, 4, 1, 2]);
  });
  it("인시던트 → 해외 → 최신(늦게 열린 것) 순", () => {
    const w = (cc: string) => ({ cc, scope: "public" }) as never;
    const xs = [
      c({ pid: 1, where: w("KR"), first_seen_ts: 900 }),
      c({ pid: 2, where: w("US"), first_seen_ts: 100 }),
      c({ pid: 3, where: w("US"), first_seen_ts: 500 }),
      c({ pid: 4, where: null, first_seen_ts: 999 }),
      c({ pid: 5, where: w("KR"), story_root: 7, first_seen_ts: 1 }),
    ];
    // 인시던트(5) → 해외 최신(3) → 해외(2) → 나라 모름(4) → 국내(1)
    expect(sortOpen(xs, "KR").map((x) => x.pid)).toEqual([5, 3, 2, 4, 1]);
    expect(homeCountry("ko-KR")).toBe("KR");
    expect(homeCountry("en-US")).toBe("US");
    expect(homeCountry("ko")).toBe("KR");
  });
  it("열린 지: 모르는 값을 지어내지 않는다", () => {
    expect(openedText(1000, 1030)).toBe("방금");
    expect(openedText(1000, 1000 + 185)).toBe("3분");
    expect(openedText(1000, 1000 + 7800)).toBe("2시간 10분");
    expect(openedText(1000, 1000 + 90000)).toBe("1일");
    // 서비스가 처음 볼 때 이미 열려 있던 연결: "넘게", 1분이 안 됐으면 알 수 없으니 "—"
    expect(openedText(1000, 1000 + 185, true)).toBe("3분 넘게");
    expect(openedText(1000, 1030, true)).toBe("—");
    // 시각이 없거나(낮은 판 서비스) 거꾸로면 "—"
    expect(openedText(undefined, 1000)).toBe("—");
    expect(openedText(2000, 1000)).toBe("—");
  });
  it("이번 갱신에 사라진 연결만 '닫힘'", () => {
    const a = c({ pid: 1 }), b = c({ pid: 2, rport: 80 });
    expect(closedSince([a, b], [a]).map(connKey)).toEqual([connKey(b)]);
    expect(closedSince([], [a])).toEqual([]);
    // 같은 주소라도 PID 가 다르면 다른 연결
    expect(closedSince([a], [c({ pid: 7 })]).length).toBe(1);
  });
});
