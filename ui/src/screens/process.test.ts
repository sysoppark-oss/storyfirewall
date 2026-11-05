import { describe, expect, it } from "vitest";
import { mainPath, placeKind, sigText } from "./process";
import { gapReason, spanText } from "./diag";
import procSrc from "./process.ts?raw";
import diagSrc from "./diag.ts?raw";

const FT = (u: number) => u * 10_000_000 + 116_444_736_000_000_000;

describe("D025 프로그램 상세·진단", () => {
  it("서명 상태 사람 말", () => {
    expect(sigText({ sig_status: "valid", signer: "Microsoft Windows" })).toEqual({ text: "Microsoft Windows", ok: true });
    expect(sigText({ sig_status: "nosignature" }).text).toBe("없음");
    expect(sigText({ sig_status: "untrusted:bad_digest" }).text).toBe("파일 내용과 서명이 맞지 않음");
    expect(sigText({ sig_status: "untrusted:root" }).text).toBe("있지만 신뢰하는 인증 기관이 아님");
    expect(sigText(null).text).toBe("확인 전");
  });
  it("위치 종류", () => {
    expect(placeKind("C:\\Windows\\System32\\svchost.exe")).toBe("Windows 폴더");
    expect(placeKind("C:\\Program Files (x86)\\App\\a.exe")).toBe("Program Files");
    expect(placeKind("C:\\Users\\pjg\\AppData\\Local\\Temp\\payload.exe")).toBe("누구나 쓸 수 있는 폴더");
    expect(placeKind("D:\\tools\\x.exe")).toBe("그 밖의 폴더");
  });
  it("구간 원인·길이", () => {
    expect(gapReason("no_record")).toBe("알 수 없음 (서비스 정지 또는 절전)");
    expect(spanText(FT(0), FT(45 * 60))).toBe("45분");
    expect(spanText(FT(0), FT(125 * 60))).toBe("2시간 5분");
    expect(spanText(FT(0), FT(30))).toBe("30초");
  });
  it("주소·경로를 링크(a[href])로 만들지 않는다 — 프로그램 상세는 a 요소 자체를 쓰지 않는다", () => {
    expect(procSrc.includes('el("a"')).toBe(false);
    expect(/href\s*=/.test(procSrc)).toBe(false);
    // 진단의 a 는 내부 이동("#")뿐
    expect(diagSrc.match(/href = "([^"]*)"/g)?.every((x) => x === 'href = "#"')).toBe(true);
  });
});

describe("D025-A3 어디서 왔나 한 줄", () => {
  it("explorer → 실행 chrome → 만듦 파일 payload → 실행 payload (그물에서 한 줄)", () => {
    const n = (id: number, kind: string, label: string) => ({ id, kind, label });
    const st = (depth: number, node: ReturnType<typeof n>, rel: string, dst: number) => ({ depth, node, via: { rel, src: node.id, dst } });
    const rw = [
      { depth: 0, node: n(10, "process", "payload.exe"), via: null },
      st(1, n(11, "file", "payload.exe"), "executed_as", 10),
      st(1, n(20, "process", "explorer.exe"), "spawned", 10),
      st(2, n(30, "process", "chrome.exe"), "wrote", 11),
      st(2, n(40, "domain", "evil.example"), "downloaded", 11),
      st(3, n(20, "process", "explorer.exe"), "spawned", 30),
      st(3, n(31, "file", "chrome.exe"), "executed_as", 30),
    ];
    expect(mainPath(10, rw).map((s) => `${s.via!.rel}:${s.node.label}`)).toEqual(["spawned:explorer.exe", "wrote:chrome.exe", "executed_as:payload.exe"]);
  });
});

describe("D027 실행 파일 출신이 없으면 부모 쪽", () => {
  it("svchost: 파일 출신 없음 → services.exe → 실행 svchost", () => {
    const rw = [
      { depth: 0, node: { id: 1, kind: "process", label: "svchost.exe" }, via: null },
      { depth: 1, node: { id: 2, kind: "file", label: "svchost.exe" }, via: { rel: "executed_as", src: 2, dst: 1 } },
      { depth: 1, node: { id: 3, kind: "process", label: "services.exe" }, via: { rel: "spawned", src: 3, dst: 1 } },
    ];
    expect(mainPath(1, rw).map((s) => s.node.label)).toEqual(["services.exe"]);
  });
});

import { isPackagePath } from "./process";
describe("패키지 앱 경로(28차 Q1)", () => {
  it("드라이브 바로 아래 WindowsApps 만", () => {
    expect(isPackagePath("C:\\Program Files\\WindowsApps\\A_1\\a.exe")).toBe(true);
    expect(isPackagePath("\\\\?\\C:\\Program Files\\WindowsApps\\A_1\\a.exe")).toBe(true);
    expect(isPackagePath("D:\\Program Files\\WindowsApps\\A_1\\a.exe")).toBe(false);
    expect(isPackagePath("C:\\Users\\u\\x\\Program Files\\WindowsApps\\a.exe")).toBe(false);
  });
});
