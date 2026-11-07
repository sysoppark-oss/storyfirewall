// 27차: 보관 정책 문구 — 서버 필드(suspicious_days)와 예전 이름(incident_days) 모두
import { describe, expect, it } from "vitest";
import { retentionText } from "./settings";
import { durText, timingName } from "./diag";

describe("retentionText", () => {
  it("서버가 돌려주는 정책 필드를 읽는다", () => {
    expect(retentionText({ raw_days: 7, summary_days: 30, suspicious_days: 30, last: null })).toBe("보관: 원시 이벤트 7일 · 연결 요약 30일 · 인시던트 30일");
  });
  it("예전 이름 incident_days 도 읽는다", () => {
    expect(retentionText({ incident_days: 14 })).toBe("보관: 인시던트 14일");
  });
  it("아는 키가 없으면 빈 문자열", () => {
    expect(retentionText({ voice: "plain" })).toBe("");
  });
});

describe("D033-2 걸린 시간", () => {
  it("1초 미만 / 소수 한 자리 초", () => {
    expect(durText(400)).toBe("1초 미만");
    expect(durText(1729)).toBe("1.7초");
  });
});

describe("D040-2 처리 시간 이름", () => {
  it("메서드 이름은 사람 말로, 엔진 일은 그대로", () => {
    expect(timingName("listeners.list")).toBe("리스닝 포트 목록");
    expect(timingName("(대기열)")).toBe("차례 기다림(대기열)");
    expect(timingName("엔진: 수집 배치")).toBe("엔진: 수집 배치");
  });
});

import { cfaText, realtimeText, cmdlineText } from "./diag";
describe("10판 5-9 (3) CFA 진단 문구", () => {
  it("상태별 문구·경고·안내", () => {
    expect(cfaText({ cfa: "block", cfa_source: "local", realtime: true })).toEqual({ text: "켜짐 · 차단", warn: false, hint: null });
    const off = cfaText({ cfa: "unset", cfa_source: "none", realtime: true });
    expect(off.warn).toBe(true);
    expect(off.hint).toContain("랜섬웨어 방지 관리");
    expect(cfaText({ cfa: "audit", cfa_source: "policy", realtime: true }).text).toBe("감사만 — 막지 않고 기록 (그룹 정책으로 설정됨)");
    expect(realtimeText(false)).toContain("실시간 보호가 켜져 있어야");
    expect(realtimeText(null)).toContain("설정 값 없음");
  });
});

describe("29차 명령줄 수집 진단", () => {
  const base = { kernel_session_ok: 1, kernel_session_failed: 0, cmdline_kernel: 3, cmdline_ok: 1, cmdline_renamed_tool: 0, cmdline_unmatched: 0, cmdline_open_failed: 2 };
  it("정상·짝 못 지음·세션 실패", () => {
    expect(cmdlineText(base)).toEqual({ text: "커널 세션 정상 · 받은 명령줄 4건", warn: false });
    expect(cmdlineText({ ...base, cmdline_unmatched: 2, cmdline_renamed_tool: 1 }).text).toBe("커널 세션 정상 · 받은 명령줄 4건 · 이름 바꾼 도구 1 · 짝 못 지음 2");
    const f = cmdlineText({ ...base, kernel_session_ok: 0, kernel_session_failed: 1 });
    expect(f.warn).toBe(true);
    expect(f.text).toContain("커널 세션을 열지 못함");
  });
});
