import { describe, expect, it } from "vitest";
import { baseName, childProcs, daysLabel, emptyText, originHost, remoteText, sortInstalls, summaryText } from "./installs-text";

const run = (o: Partial<Parameters<typeof summaryText>[0]> = {}) => ({
  image: "C:\\Users\\a\\Downloads\\FooSetup.exe",
  procs: ["C:\\Users\\a\\Downloads\\FooSetup.exe"],
  files: [] as string[],
  autoruns: [] as [string, string][],
  remotes: [] as [string, number][],
  ...o,
});

describe("설치 화면 도우미", () => {
  it("파일 이름: 역슬래시·슬래시·끝 구분자", () => {
    expect(baseName("C:\\Program Files (x86)\\Foo\\setup.exe")).toBe("setup.exe");
    expect(baseName("C:/a/b/install.exe")).toBe("install.exe");
    expect(baseName("msiexec.exe")).toBe("msiexec.exe");
    expect(baseName("C:\\a\\dir\\")).toBe("dir");
  });

  it("함께 실행된 프로그램은 뿌리 한 번만 뺀다(대소문자 무시)", () => {
    const r = run({ procs: ["c:\\users\\a\\downloads\\foosetup.exe", "C:\\Windows\\System32\\msiexec.exe", "C:\\Users\\a\\Downloads\\FooSetup.exe"] });
    expect(childProcs(r)).toEqual(["C:\\Windows\\System32\\msiexec.exe", "C:\\Users\\a\\Downloads\\FooSetup.exe"]);
  });

  it("요약 한 줄: 개수만, 0인 항목은 뺀다", () => {
    const r = run({
      procs: ["C:\\Users\\a\\Downloads\\FooSetup.exe", "C:\\x\\a.exe", "C:\\x\\b.exe", "C:\\x\\c.exe"],
      files: ["C:\\Users\\a\\AppData\\Local\\Foo\\foo.exe", "C:\\Users\\a\\AppData\\Local\\Foo\\up.ps1"],
      autoruns: [["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "C:\\Users\\a\\AppData\\Local\\Foo\\foo.exe"]],
      remotes: [["cdn.example.com", 3], ["api.example.com", 1]],
    });
    expect(summaryText(r)).toBe("프로그램 3개 실행 · 파일 2개 만듦 · 자동 실행 관련 1건 · 접속한 곳 2곳");
    expect(summaryText(run({ remotes: [["a.example", 1]] }))).toBe("접속한 곳 1곳");
  });

  it("요약: 아무 기록도 없으면 없다고만(판정 문구 없음)", () => {
    const t = summaryText(run());
    expect(t).toContain("기록이 없습니다");
    expect(t).not.toMatch(/의심|위험|안전|정상|악성|점수/);
  });

  it("내려받은 곳: URL 이면 호스트, 아니면 그대로, 비면 null", () => {
    expect(originHost("https://dl.example.com/x/FooSetup.exe?t=1")).toBe("dl.example.com");
    expect(originHost("dl.example.com")).toBe("dl.example.com");
    expect(originHost("  ")).toBeNull();
    expect(originHost(null)).toBeNull();
  });

  it("접속한 곳 횟수, 범위 문구, 최신 먼저", () => {
    expect(remoteText(["a.example", 3])).toBe("a.example ×3");
    expect(remoteText(["a.example", 1])).toBe("a.example");
    expect(daysLabel(1)).toBe("하루");
    expect(emptyText(7)).toBe("최근 7일 동안 찾은 설치가 없습니다.");
    const xs = [{ start_ts: 1 }, { start_ts: 3 }, { start_ts: 2 }];
    expect(sortInstalls(xs).map((x) => x.start_ts)).toEqual([3, 2, 1]);
    expect(xs.map((x) => x.start_ts)).toEqual([1, 3, 2]);
  });
});

describe("L060 설치 엑스레이 검수 반영", () => {
  it("모두 0이면 모은 범위와 한계를 함께 말한다", async () => {
    const { summaryText } = await import("./installs-text");
    const t = summaryText({ image: "C:\\a\\Setup.exe", procs: ["C:\\a\\Setup.exe"], files: [], autoruns: [], remotes: [], persistence: [] });
    expect(t).toContain("모은 기록이 없습니다");
    expect(t).toContain("잡히지 않을 수 있습니다");
  });
  it("자리잡기 명령도 자동 실행 관련으로 센다", async () => {
    const { summaryText } = await import("./installs-text");
    const t = summaryText({ image: "s.exe", procs: ["s.exe"], files: [], autoruns: [], remotes: [], persistence: ["schtasks.exe 실행 (명령줄을 받지 못해 무엇을 바꿨는지 모름)"] });
    expect(t).toBe("자동 실행 관련 1건");
  });
  it("같은 경로는 한 줄 ×N 으로", async () => {
    const { countPaths } = await import("./installs-text");
    expect(countPaths(["C:\\W\\schtasks.exe", "c:/w/SCHTASKS.exe", "C:\\W\\sc.exe"])).toEqual([["C:\\W\\schtasks.exe", 2], ["C:\\W\\sc.exe", 1]]);
  });
});

import { silentFlag, installChips, installEdge } from "./installs-text";
describe("설치 사실 칩(UI 명세 4판 3-6)", () => {
  it("조용한 설치 플래그를 단어 단위로 찾는다", () => {
    expect(silentFlag('msiexec.exe /i "C:\\a b\\x.msi" /qn')).toBe("/qn");
    expect(silentFlag("setup.exe /S")).toBe("/S");
    expect(silentFlag("setup.exe /VERYSILENT /NORESTART")).toBe("/VERYSILENT");
    expect(silentFlag("setup.exe --silent")).toBe("--silent");
    expect(silentFlag("msiexec /i x.msi /qb-")).toBe("/qb-");
    expect(silentFlag("setup.exe /SILENT=1")).toBe("/SILENT=1");
  });
  it("경로·다른 옵션 안의 글자는 플래그가 아니다", () => {
    expect(silentFlag('"C:\\tools\\/s\\setup.exe" /norestart')).toBeNull();
    expect(silentFlag("setup.exe /silently /sp-")).toBeNull();
    expect(silentFlag("/S")).toBeNull(); // 첫 토큰(실행 파일)은 보지 않는다
    expect(silentFlag(null)).toBeNull();
  });
  it("부모로 실행한 쪽을 나눈다, 부모 기록이 없으면 그 칩은 없다", () => {
    expect(installChips({ parent: "C:\\Windows\\explorer.exe", cmdline: "s.exe", origin: "https://x.com/s.exe" }).map((c) => c.kind)).toEqual(["user"]);
    expect(installChips({ parent: "C:\\Program Files\\Google\\Chrome\\Application\\CHROME.EXE", cmdline: null, origin: "x.com" }).map((c) => c.kind)).toEqual(["user"]);
    expect(installChips({ parent: "C:\\Users\\a\\AppData\\Local\\Temp\\upd.exe", cmdline: "s.exe /S", origin: null }).map((c) => c.kind)).toEqual(["other", "silent", "no-origin"]);
    expect(installChips({ parent: null, cmdline: null, origin: " " }).map((c) => c.kind)).toEqual(["no-origin"]);
  });
  it("테두리: 조용한 설치 + 다른 프로그램만 주의", () => {
    expect(installEdge(installChips({ parent: "C:\\a\\upd.exe", cmdline: "s.exe /S", origin: "x" }))).toBe("warn");
    expect(installEdge(installChips({ parent: "C:\\Windows\\explorer.exe", cmdline: "s.exe /S", origin: "x" }))).toBe("line");
    expect(installEdge(installChips({ parent: "C:\\a\\upd.exe", cmdline: "s.exe", origin: null }))).toBe("line");
  });
  it("칩 문구에 판단 말이 없다", () => {
    const all = installChips({ parent: "C:\\a\\upd.exe", cmdline: "s.exe /S", origin: null });
    for (const c of all) expect(c.text + c.tip).not.toMatch(/의심|악성|위험/);
  });
});
