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

describe("hourlyFromSummary — 차단 통신", () => {
  it("시간대별 차단 수를 모으고 유실은 합산한다", () => {
    const now = new Date(2026, 10, 7, 12, 30).getTime() / 1000;
    const h9 = new Date(2026, 10, 7, 9).getTime() / 1000;
    const h11 = new Date(2026, 10, 7, 11).getTime() / 1000;
    const r = hourlyFromSummary([{ hour: h9, sent: 0, recv: 0, conns: 0, blocked: 3, blocked_lost: 1 }, { hour: h11, sent: 0, recv: 0, conns: 0, blocked: 2, blocked_lost: 4 }], now);
    expect(r.blocked[9]).toBe(3); expect(r.blocked[11]).toBe(2); expect(r.lost).toBe(5);
  });
});

import { emergencyText } from "./dashboard";
describe("emergencyText (대시보드 개편안 3판 1-1 긴급 차단 상태)", () => {
  it("걸려 있지 않으면 null", () => {
    expect(emergencyText(null)).toBeNull();
    expect(emergencyText({ active: false })).toBeNull();
  });
  it("유지 확인 전·남은 시간", () => {
    expect(emergencyText({ active: true, confirmed: false, remaining_secs: 1800 })).toBe("긴급 차단 · 유지 확인 대기");
    expect(emergencyText({ active: true, confirmed: true, remaining_secs: 719 })).toBe("긴급 차단 중 · 12분 남음");
    expect(emergencyText({ active: true, confirmed: true, remaining_secs: 7200 })).toBe("긴급 차단 중 · 2시간 0분 남음");
    // UI 명세 4판 1-1: 5분 이하는 m:ss(띠가 1초마다 고침), 5분 넘으면 분(올림)
    expect(emergencyText({ active: true, confirmed: true, remaining_secs: -5 })).toBe("긴급 차단 중 · 0:00 남음");
    expect(emergencyText({ active: true, confirmed: true, remaining_secs: 300 })).toBe("긴급 차단 중 · 5:00 남음");
    expect(emergencyText({ active: true, confirmed: true, remaining_secs: 301 })).toBe("긴급 차단 중 · 6분 남음");
    expect(emergencyText({ active: true, confirmed: true, remaining_secs: 59 })).toBe("긴급 차단 중 · 0:59 남음");
    // 띠의 1초 갱신은 남은 초를 따로 넘긴다
    expect(emergencyText({ active: true, confirmed: true, remaining_secs: 1800 }, 125.7)).toBe("긴급 차단 중 · 2:05 남음");
  });
});

import { serviceWord } from "../topbar";
describe("공통 상단 띠(UI 명세 4판 3-1)", () => {
  it("보호 서비스 한 단어 — 끊김·멈춤이 '작동 중'보다 앞선다", () => {
    expect(serviceWord(false, true, true)).toEqual({ word: "연결 끊김", tone: "warn" });
    expect(serviceWord(true, true, true)).toEqual({ word: "기록 멈춤?", tone: "warn" });
    expect(serviceWord(true, false, true)).toEqual({ word: "작동 중 · 응답 늦음", tone: "warn" });
    expect(serviceWord(true, false, false)).toEqual({ word: "작동 중", tone: "ok" });
  });
  it("엔진 뱃지 — 수치가 없으면 빼고 정책 수는 늘", () => {
    expect(engineBadges(null, 0, 0)).toEqual(["정책 0개"]);
    expect(engineBadges({ now: 0, last_event_ft: null, timings: [{ name: "엔진: 주기 판정", last_ms: 400 }], wfp_filters: 4 }, 2, 1)).toEqual(["판정 지연 400ms", "필터 4개", "정책 2개 (확인 대기 1)"]);
  });
});
