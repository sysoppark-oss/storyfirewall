import { describe, expect, it } from "vitest";
import { groupStories, sumGroupSources } from "./story-group";

const s = (root: number, last_ts: number, image = "C:\\Windows\\System32\\svchost.exe", level = "suspicious", items = [{ label: "접속", value: "알려진 서비스 없는 외부 접속" }]) =>
  ({ root, title: "[의심] svchost.exe", level, last_ts, root_image: image, items });

describe("D020-2 같은 판정 묶기", () => {
  it("같은 경로·수준·항목은 한 장, 대표는 최신, 묶음은 최신이 위", () => {
    const g = groupStories([s(1, 100), s(2, 300), s(3, 200), s(9, 250, "C:\\Users\\u\\AppData\\Local\\Temp\\svchost.exe")]);
    expect(g.length).toBe(2);
    expect(g[0]!.head.root).toBe(2);
    expect(g[0]!.members.map((x) => x.root)).toEqual([2, 3, 1]);
    expect([g[0]!.first_ts, g[0]!.last_ts]).toEqual([100, 300]);
    // 같은 이름이라도 다른 폴더(사칭 가능)는 따로
    expect(g[1]!.head.root).toBe(9);
  });
  it("수준이나 판정 항목이 다르면 따로, 시작 경위 문구 차이는 무시", () => {
    const a = s(1, 1);
    const b = { ...s(2, 2), level: "watch" };
    const c = s(3, 3, undefined, undefined, [{ label: "접속", value: "다른 판정" }]);
    const d = { ...s(4, 4), items: [...s(4, 4).items, { label: "시작 경위", value: "기록 없음" }] };
    expect(groupStories([a, b, c, d]).length).toBe(3);
  });
});

describe("경로를 모르면(빈 문자열) 제목으로 가른다", () => {
  it("helper·agent 는 같은 판정이어도 따로", () => {
    const a = { root: 1, title: "[의심] helper.exe", level: "suspicious", last_ts: 1, root_image: "", items: [] };
    const b = { root: 2, title: "[의심] agent.exe", level: "suspicious", last_ts: 2, root_image: "", items: [] };
    expect(groupStories([a, b]).length).toBe(2);
  });
});

describe("묶음 카드 근거 배지 합계", () => {
  const ev = (root: number, n: number) => ({ root, title: "svchost.exe", level: "suspicious", items: [{ label: "접속", value: "외부 접속", sources: [["etw", n]] as [string, number][] }] });
  it("같은 항목의 근거 수를 묶음 전체로 더한다", () => {
    const a = ev(1, 1), b = ev(2, 2), c = ev(3, 1);
    const h = sumGroupSources(a, [a, b, c]);
    expect(h.items![0]!.sources).toEqual([["etw", 4]]);
    expect(a.items[0]!.sources).toEqual([["etw", 1]]); // 원본은 그대로
  });
  it("한 건이면 그대로", () => {
    const a = ev(1, 1);
    expect(sumGroupSources(a, [a])).toBe(a);
  });
});

import { distinguishGroups, groupStories as gs2 } from "./story-group";
describe("D035-3 같은 제목 묶음 구분", () => {
  const ev = (root: number, items: { label: string; value: string }[], img = "C:\\Windows\\System32\\svchost.exe") => ({ root, title: "svchost.exe", level: "suspicious", root_image: img, items });
  it("다른 판정 항목 값을 보인다", () => {
    const g = gs2([ev(1, [{ label: "접속", value: "서비스 없이 외부 접속" }]), ev(2, [{ label: "접속", value: "처음 보는 나라" }])]);
    const d = distinguishGroups(g, (x) => x.title);
    expect(d.sort()).toEqual(["접속: 서비스 없이 외부 접속", "접속: 처음 보는 나라"]);
  });
  it("항목이 같고 경로만 다르면 끝 폴더", () => {
    const g = gs2([ev(1, [], "C:\\Windows\\System32\\svchost.exe"), ev(2, [], "C:\\Temp\\x\\svchost.exe")]);
    expect(distinguishGroups(g, (x) => x.title).sort()).toEqual(["위치: System32", "위치: x"]);
  });
  it("제목이 하나뿐이면 빈 문자열", () => {
    expect(distinguishGroups(gs2([ev(1, [])]), (x) => x.title)).toEqual([""]);
  });
});
