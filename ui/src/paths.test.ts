// D039-1: 글 속 Windows 경로만 고정폭으로 감싼다
import { describe, expect, it } from "vitest";
import { splitPaths, fmtRange } from "./ui";

describe("splitPaths", () => {
  it("경로만 골라낸다", () => {
    const r = splitPaths("payload.exe(C:\\Users\\pjg\\AppData\\Local\\Temp) 의 모든 연결 차단");
    expect(r.filter((x) => x.path).map((x) => x.t)).toEqual(["C:\\Users\\pjg\\AppData\\Local\\Temp"]);
    expect(r.map((x) => x.t).join("")).toBe("payload.exe(C:\\Users\\pjg\\AppData\\Local\\Temp) 의 모든 연결 차단");
  });
  it("UNC 경로·경로 없는 글", () => {
    expect(splitPaths("\\\\srv\\share\\a.exe 실행").filter((x) => x.path).length).toBe(1);
    expect(splitPaths("github.com:443").every((x) => !x.path)).toBe(true);
  });
});

describe("D042 경로·기간", () => {
  it("폴더 이름의 공백·괄호는 경로에 든다", () => {
    const one = (t: string) => splitPaths(t).filter((x) => x.path).map((x) => x.t);
    expect(one("C:\\Program Files (x86)\\A B\\c.exe")).toEqual(["C:\\Program Files (x86)\\A B\\c.exe"]);
    expect(one("위치: C:\\Program Files\\Git\\usr\\bin\\sh.exe · 누구나 쓸 수 있는 폴더")).toEqual(["C:\\Program Files\\Git\\usr\\bin\\sh.exe"]);
    expect(one("C:\\a\\b.exe 또는 D:\\c\\d.exe")).toEqual(["C:\\a\\b.exe", "D:\\c\\d.exe"]);
  });
  it("날짜가 다르면 끝에도 날짜, 끝이 오늘이면 '오늘'", () => {
    const now = new Date(2026, 10, 4, 3, 0, 0);
    const t = (d: number, h: number, m: number) => new Date(2026, 10, d, h, m).getTime() / 1000;
    expect(fmtRange(t(3, 2, 36), t(4, 2, 30), now)).toBe("11월 3일 오전 2:36 ~ 오늘 오전 2:30");
    expect(fmtRange(t(4, 2, 5), t(4, 2, 7), now)).toBe("오전 2:05 ~ 오전 2:07");
    expect(fmtRange(t(2, 9, 0), t(3, 10, 0), now)).toBe("11월 2일 오전 9:00 ~ 11월 3일 오전 10:00");
    expect(fmtRange(t(2, 9, 0), t(2, 10, 0), now)).toBe("11월 2일 오전 9:00 ~ 오전 10:00");
    // D046-1: 같은 분이면 한 번
    expect(fmtRange(t(4, 15, 24), t(4, 15, 24) + 30, now)).toBe("오후 3:24");
  });
});
