import { describe, it, expect } from "vitest";

// 개편안 2판 3-2: 상단 띠 뱃지 — 수치가 있는 것만, 정책은 항상
import { engineBadges } from "./dashboard";
describe("engineBadges", () => {
  it("수치가 있는 뱃지만 만들고 정책 수는 항상 넣는다", () => {
    expect(engineBadges(null, 3, 0)).toEqual(["정책 3개"]);
    const h = { now: 0, last_event_ft: null, lost_24h: 0, gaps_24h: [], clock_changes_24h: [], timings: [{ name: "엔진: 주기 판정", last_ms: 2 }], wfp_filters: 12, db_bytes: 42 * 1024 * 1024 };
    expect(engineBadges(h, 5, 1)).toEqual(["판정 지연 2ms", "필터 12개", "DB 42.0 MB", "정책 5개 (확인 대기 1)"]);
  });
});

import { groupProtection } from "./dashboard";
describe("groupProtection", () => {
  it("같은 종류·같은 프로그램은 한 묶음, 최신이 대표, 처음 시각 보존", () => {
    const g = groupProtection([
      { kind: "remote_start", ts: 300, target: { image: "C:\\TV\\TeamViewer.exe" } },
      { kind: "remote_end", ts: 250, target: { image: "C:\\TV\\TeamViewer.exe" } },
      { kind: "remote_start", ts: 100, target: { image: "c:\\tv\\teamviewer.exe" } },
      { kind: "remote_start", ts: 200, target: { image: "C:\\Other\\x.exe" } },
    ]);
    expect(g.map((x) => [x.head.kind, x.n, x.first_ts, x.head.ts])).toEqual([["remote_start", 2, 100, 300], ["remote_end", 1, 250, 250], ["remote_start", 1, 200, 200]]);
  });
});

import { hourlyFromSummary } from "./dashboard";
describe("hourlyFromSummary", () => {
  it("오늘 시간대만 현지 시각 버킷에 넣고 어제는 버린다", () => {
    const now = new Date(2026, 10, 7, 12, 30).getTime() / 1000;
    const h9 = new Date(2026, 10, 7, 9).getTime() / 1000;
    const yesterday = new Date(2026, 10, 6, 23).getTime() / 1000;
    const r = hourlyFromSummary([{ hour: h9, sent: 10, recv: 5, conns: 3 }, { hour: yesterday, sent: 99, recv: 99, conns: 99 }], now);
    expect(r.sent[9]).toBe(10); expect(r.recv[9]).toBe(5); expect(r.conns[9]).toBe(3);
    expect(r.sent.reduce((a, b) => a + b, 0)).toBe(10);
  });
});
