import { describe, expect, it } from "vitest";
import { cardNote, tableOnly, cmdlineText, FEEDBACK_NOT_YET, bareTitle, groupToday, sinceText, sortToday, subjectName, sinceOf, gapStartText, mergeItems, isWindowsSigned, liveText, recommendText } from "./story";
import { hostOf, portOf, REL } from "./mindmap";
// 그래프 관계 이름의 원본(Rust) — vite ?raw 로 글자 그대로 읽는다
import graphLib from "../../../crates/graph/src/lib.rs?raw";

describe("D044", () => {
  it("마인드맵 선 글자 사전이 그래프의 관계 이름 전부를 한국어로 덮는다", () => {
    const src: string = graphLib;
    const rels = [...src.matchAll(/Rel::\w+ => "([a-z_]+)"/g)].map((m) => m[1]!);
    expect(rels.length).toBeGreaterThan(8);
    for (const r of rels) {
      expect(REL[r], r).toBeTruthy();
      expect(/[a-z]/i.test(REL[r]!), r).toBe(false);
    }
  });
  it("단추 줄 아래 안내는 한 줄로 합친다", () => {
    expect(cardNote(false, false)).toBeNull();
    expect(cardNote(true, true)).toBe(`Windows 핵심 프로세스라 끝내지 않습니다. 의심 주소만 막을 수 있습니다. ${FEEDBACK_NOT_YET}`);
    expect(cardNote(false, true)).toBe(FEEDBACK_NOT_YET);
  });
  it("연결 표만 근거", () => {
    expect(tableOnly([["conntable", 2]])).toBe(true);
    expect(tableOnly([["conntable", 1], ["etw", 1]])).toBe(false);
    expect(tableOnly([])).toBe(false);
  });
});

describe("D043 5장 화면 조각", () => {
  it("명령줄 80자 말줄임(문자 단위), 짧으면 그대로", () => {
    expect(cmdlineText("vssadmin delete shadows /all /quiet")).toBe("vssadmin delete shadows /all /quiet");
    const long = "가".repeat(100);
    expect([...cmdlineText(long)].length).toBe(80);
    expect(cmdlineText(long).endsWith("…")).toBe(true);
  });
  it("정상 처리 못 하는 사건의 안내 문구에 단정·추정 낱말이 없다", () => {
    for (const w of ["추정", "악성", "랜섬"]) expect(FEEDBACK_NOT_YET.includes(w)).toBe(false);
  });
});

describe("D003·D004 화면 조각", () => {
  it("카드 제목은 프로그램 이름만", () => {
    expect(bareTitle("[의심] payload.exe — 4장 외부 접속까지 진행")).toBe("payload.exe");
    expect(bareTitle("[주의] BrYNSvc.exe — 2장 실행까지 진행 (점수 45, 근거 3건)")).toBe("BrYNSvc.exe");
    expect(bareTitle("[의심] a — b.exe")).toBe("a — b.exe");
    // 10판 5-9: 5장 제목
    expect(bareTitle("[의심] vssadmin.exe — 5장 파괴 징후까지 진행")).toBe("vssadmin.exe");
  });
  it("시작 시각은 올해면 연도 생략", () => {
    const now = new Date(2026, 10, 3);
    const t = new Date(2026, 3, 14, 14, 38).getTime() / 1000;
    expect(sinceText(t, now)).toMatch(/^수집 시작 전부터 실행 중 · 시작 4월 14일 /);
    const old = new Date(2025, 3, 14, 14, 38).getTime() / 1000;
    expect(sinceText(old, now)).toContain("2025년 4월 14일");
  });
  it("오늘 한 일은 시각 오름차순, 같은 시각은 원래 순서", () => {
    const xs = [{ ts: 3, k: "a" }, { ts: 1, k: "b" }, { ts: 3, k: "c" }, { ts: 2, k: "d" }];
    expect(sortToday(xs).map((x) => x.k)).toEqual(["b", "d", "a", "c"]);
  });
  it("접속지 라벨에서 호스트·포트", () => {
    expect(hostOf("WWW.Google.com:443")).toBe("www.google.com");
    expect(portOf("www.google.com:443")).toBe("443");
    expect(hostOf("[2001:db8::1]:53")).toBe("2001:db8::1");
    expect(portOf("[2001:db8::1]:53")).toBe("53");
    expect(portOf("2001:db8::1")).toBe("");
  });
});

describe("D014 이름 모르는 프로세스·오늘 범위·기록 없는 구간 문구", () => {
  it("pid N(예전 기록)·알 수 없는 프로그램(PID N)은 같은 말로, 회색", () => {
    expect(subjectName("pid 4")).toEqual({ text: "알 수 없는 프로그램(PID 4)", unknown: true });
    expect(subjectName("알 수 없는 프로그램(PID 880)").unknown).toBe(true);
    expect(subjectName("chrome.exe")).toEqual({ text: "chrome.exe", unknown: false });
    expect(subjectName("pid 4 helper.exe").unknown).toBe(false);
  });
  it("오늘 = 지역 0시 이후, 최근 24시간 = 지금-86400", () => {
    const now = new Date(2026, 10, 3, 13, 30, 0);
    expect(sinceOf("today", now)).toBe(Math.floor(new Date(2026, 10, 3, 0, 0, 0).getTime() / 1000));
    expect(sinceOf("24h", now)).toBe(Math.floor(now.getTime() / 1000) - 86400);
  });
  it("구간 문구에 시작 시각을 합치고 같은 오전/오후는 반복하지 않는다", () => {
    const ft = (d: Date) => Math.floor(d.getTime() / 1000) * 10_000_000 + 116_444_736_000_000_000;
    const today = new Date();
    const at = (h: number, m: number) => { const d = new Date(today); d.setHours(h, m, 0, 0); return ft(d); };
    const t = gapStartText(at(12, 36), at(13, 21), at(13, 1));
    expect(t).toBe("기록 없는 구간(오후 12:36 ~ 오후 1:21)에 시작(오후 1:01) — 서비스가 멈췄거나 PC 가 절전 중이던 때");
    expect(gapStartText(at(12, 36), at(13, 21))).not.toContain("시작(");
  });
});

describe("D022-2·3 항목 합치기·Windows 기본 파일", () => {
  it("같은 이름 항목은 한 줄로, 근거 수 합산", () => {
    const m = mergeItems([
      { label: "접속", value: "서비스 호스트가 요청한 프로그램 없이 외부 접속", edge_ids: [1], sources: [["etw", 1]] as [string, number][] },
      { label: "서명", value: "Microsoft Windows", edge_ids: [] },
      { label: "접속", value: "도메인 없이 IP 로 바로 접속", edge_ids: [2], sources: [["etw", 2], ["conntable", 1]] as [string, number][] },
    ]);
    expect(m.length).toBe(2);
    expect(m[0]!.value).toBe("서비스 호스트가 요청한 프로그램 없이 외부 접속 · 도메인 없이 IP 로 바로 접속");
    expect(m[0]!.edge_ids).toEqual([1, 2]);
    expect(m[0]!.sources).toEqual([["etw", 3], ["conntable", 1]]);
  });
  it("Windows 폴더 + 유효 서명일 때만 출신을 Windows 기본 파일로", () => {
    const it0 = [{ label: "출신", value: "확인되지 않음", edge_ids: [] }];
    expect(mergeItems(it0, true)[0]!.value).toBe("Windows 기본 파일");
    expect(mergeItems(it0, false)[0]!.value).toBe("확인되지 않음");
    expect(isWindowsSigned({ root_image: "C:\\Windows\\System32\\svchost.exe", root_signature: { sig_status: "valid" } })).toBe(true);
    expect(isWindowsSigned({ root_image: "C:\\Users\\u\\AppData\\Local\\Temp\\svchost.exe", root_signature: { sig_status: "valid" } })).toBe(false);
    expect(isWindowsSigned({ root_image: "C:\\Windows\\System32\\svchost.exe", root_signature: { sig_status: "nosignature" } })).toBe(false);
  });
});

describe("D030-2 오늘 한 일 같은 줄 묶기", () => {
  const MIN = 60 * 10_000_000;
  const T = 133_800_000_000_000_000 - (133_800_000_000_000_000 % MIN);
  const line = (ts: number, obj = "git.exe", sources: [string, number][] = [["etw", 1]]) => ({
    text: "x", ts, edge_ids: [ts], evidence: [], chapter: null, parts: { subject: "git-credential-manager.exe", verb: "실행", object: obj }, sources,
  });
  it("같은 분·같은 주체·동작·대상은 한 줄, 근거 수는 합친다", () => {
    const g = groupToday([line(T + 1), line(T + 2), line(T + 3)]);
    expect(g.length).toBe(1);
    expect(g[0]!.members.length).toBe(3);
    expect(g[0]!.s.sources).toEqual([["etw", 3]]);
  });
  it("다른 분이거나 대상이 다르면 따로", () => {
    expect(groupToday([line(T + 1), line(T + MIN + 1)]).length).toBe(2);
    expect(groupToday([line(T + 1), line(T + 2, "sh.exe")]).length).toBe(2);
  });
});

describe("실시간 1: 카드의 지금 상태 줄", () => {
  it("실행 중", () => expect(liveText({ running: true, pid: 16720, ended: false })).toBe("지금도 실행 중 (PID 16720)"));
  it("끝남 기록이 있으면 끝남", () => expect(liveText({ running: false, pid: 5, ended: true })).toBe("지금은 끝남 (PID 5)"));
  it("끝남 기록 없이 안 보이면 단정하지 않는다", () => expect(liveText({ running: false, pid: 5, ended: false })).toBe("지금 상태 확인 못 함 (PID 5)"));
});

describe("자동 조사: 권장 조치 문장", () => {
  it("세 가지", () => {
    expect(recommendText({ recommend: "mark_normal" })).toBe("권장: 알려진 정상 모양 — 끊지 마세요");
    expect(recommendText({ recommend: "cut" })).toBe("권장: 여기서부터 끊기");
    expect(recommendText({ recommend: "review" })).toBe("권장: 아래 사실을 보고 정하세요");
  });
});
