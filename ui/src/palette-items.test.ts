import { describe, expect, it } from "vitest";
import { search, score, matchRange, looksLikeAddress, incidentNo, pushRecent, nextTheme, SCREEN_ITEMS, SETTING_ITEMS, COMMAND_ITEMS, type PaletteItem } from "./palette-items";

describe("명령 팔레트(UI 명세 4판 3-9)", () => {
  it("화면 이름 앞부분 일치가 먼저", () => {
    const r = search("설치", [SCREEN_ITEMS, SETTING_ITEMS]);
    expect(r[0]?.label).toBe("설치 이력");
  });
  it("숨은 낱말(영문)로도 찾는다", () => {
    expect(search("hud", [SCREEN_ITEMS, SETTING_ITEMS])[0]?.find).toBe("HUD");
  });
  it("\">\" 는 명령만, 명령은 모두 화면 이동·대화상자 열기", () => {
    const r = search(">", [SCREEN_ITEMS]);
    expect(r.every((x) => x.kind === "command")).toBe(true);
    expect(r.length).toBe(COMMAND_ITEMS.length);
    expect(search(">긴급", [])[0]?.target).toBe("emg-start");
    // 집행을 뜻하는 말("실행"·"적용")을 명령 이름에 쓰지 않는다
    for (const c of COMMAND_ITEMS) expect(c.label + c.hint).not.toMatch(/실행|적용함|즉시/);
  });
  it("짧은 입력은 퍼지로 아무거나 맞지 않는다", () => {
    const it0: PaletteItem = { kind: "screen", label: "대시보드", hint: "", target: "x" };
    expect(score(it0, "대보")).toBe(0);
    expect(score(it0, "대시보")).toBeGreaterThan(50);
  });
  it("강조 범위는 원래 글자 기준", () => {
    expect(matchRange("Chrome.exe", "chrome")).toEqual([0, 6]);
    expect(matchRange("abc", "z")).toBeNull();
  });
  it("주소·번호 알아보기", () => {
    expect(looksLikeAddress("1.2.3.4")).toBe(true);
    expect(looksLikeAddress("api.example.com")).toBe(true);
    expect(looksLikeAddress("2001:db8::1")).toBe(true);
    expect(looksLikeAddress("chrome.exe")).toBe(true); // 도메인 꼴 — 이력 거르기는 글자 찾기라 무해
    expect(looksLikeAddress("설치")).toBe(false);
    expect(incidentNo("#42")).toBe(42);
    expect(incidentNo("a42")).toBeNull();
  });
  it("최근 이동은 5개, 같은 것은 앞으로", () => {
    let r: PaletteItem[] = [];
    for (const x of [...SCREEN_ITEMS, SCREEN_ITEMS[0]!]) r = pushRecent(r, x);
    expect(r.length).toBe(5);
    expect(r[0]).toBe(SCREEN_ITEMS[0]);
    expect(r.filter((x) => x.target === SCREEN_ITEMS[0]!.target).length).toBe(1);
  });
  it("테마 순환", () => {
    expect(nextTheme("system")).toBe("light");
    expect(nextTheme("dark")).toBe("system");
  });
});
