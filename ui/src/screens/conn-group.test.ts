import { describe, expect, it } from "vitest";
import { bars, groupConns, isNewToday, matchesFilter, offMapLine, type ConnLike } from "./conn-group";

const pub = (asn: number, org: string, cc: string, country: string) => ({ scope: "public", asn, org, cc, country });
const c = (image: string, remote_id: number, count: number, where: ConnLike["where"], extra: Partial<ConnLike> = {}): ConnLike => ({
  image, remote_id, count, sent: 10, recv: 20, where, ...extra,
});

const items: ConnLike[] = [
  c("C:\\p\\chrome.exe", 1, 12, pub(15169, "Google LLC", "US", "미국")),
  c("C:\\p\\chrome.exe", 2, 9, pub(15169, "Google LLC", "US", "미국")),
  c("C:\\p\\edge.exe", 3, 5, pub(15169, "Google LLC", "US", "미국")),
  c("C:\\p\\chrome.exe", 4, 7, pub(3786, "LG POWERCOMM", "KR", "대한민국")),
  c("C:\\u\\helper.exe", 5, 3, pub(64502, "Example Hosting LLC", "US", "미국"), { new_asn: true }),
  c("C:\\p\\chrome.exe", 6, 2, { scope: "multicast" }),
  c("C:\\u\\payload.exe", 7, 4, { scope: "public", cc: "US", country: "미국" }),
];

describe("A2 연결 묶음", () => {
  it("망(조직) 묶음: 오늘 처음이 위, 그다음 접속 수, 정보 없음·로컬망은 맨 아래", () => {
    const g = groupConns(items, "org");
    expect(g.slice(0, 3).map((x) => x.title)).toEqual(["Example Hosting LLC", "Google LLC", "LG POWERCOMM"]);
    expect(new Set(g.slice(3).map((x) => x.title))).toEqual(new Set(["사설망 · 멀티캐스트", "조직 정보 없음"]));
    expect(g[0]!.isNew).toBe(true);
    const google = g.find((x) => x.title === "Google LLC")!;
    expect(google.count).toBe(26);
    expect(google.sub).toBe("AS15169 · 원격지 3곳");
    expect(google.programs).toBe("chrome.exe 외 1");
    expect(google.place).toBe("미국");
    expect(g.slice(-2).every((x) => x.bottom)).toBe(true);
  });
  it("프로그램·국가 묶음, 묶지 않음", () => {
    expect(groupConns(items, "program")[0]!.title).toBe("chrome.exe");
    const byC = groupConns(items, "country");
    expect(byC[0]!.title).toBe("미국");
    expect(groupConns(items, "none")).toEqual([]);
  });
});

describe("A3 막대", () => {
  it("공인 주소만, 접속 수 순, 상위 N + 나머지", () => {
    const b = bars(items, "country");
    expect(b.bars.map((x) => [x.label, x.value])).toEqual([["미국", 33], ["대한민국", 7]]);
    const o = bars(items, "org", 2);
    expect(o.bars.map((x) => x.label)).toEqual(["Google LLC", "LG POWERCOMM"]);
    expect(o.rest).toBe(1);
    expect(bars(items, "org").bars.find((x) => x.label === "Example Hosting LLC")!.isNew).toBe(true);
  });
  it("막대로 거르기", () => {
    expect(items.filter((x) => matchesFilter(x, { by: "country", key: "KR" })).length).toBe(1);
    expect(items.filter((x) => matchesFilter(x, { by: "org", key: "15169" })).length).toBe(3);
    expect(items.filter((x) => matchesFilter(x, null)).length).toBe(items.length);
  });
});

describe("D009 지도에 없는 주소·지역 코드", () => {
  it("ZZ·EU·AP 는 국가 막대에서 빠지고 오늘 처음 배지도 없다", () => {
    const xs: ConnLike[] = [
      c("a.exe", 1, 2, { scope: "public", cc: "ZZ", country: "지정 안 됨", asn: 1 }, { new_cc: true }),
      c("a.exe", 2, 3, { scope: "public", cc: "EU", country: "유럽 지역", asn: 2 }),
      c("a.exe", 3, 4, { scope: "public", cc: "KR", country: "대한민국", asn: 3 }, { new_cc: true }),
      c("a.exe", 4, 5, { scope: "private" }),
    ];
    const b = bars(xs, "country").bars;
    expect(b.map((x) => x.key)).toEqual(["KR"]);
    expect(b[0]!.isNew).toBe(true);
    expect(offMapLine(xs)).toBe("지도에 없는 주소: 지정 안 됨 2 · 유럽(나라 미상) 3 · 사설망 5");
    expect(offMapLine([xs[2]!])).toBe("");
  });
});

describe("D012 마인드맵 오늘 처음 접속지", () => {
  const r = (extra: object) => ({ node: { kind: "remote" }, where: { cc: "KR" }, ...extra });
  it("ASN 또는 나라가 오늘 처음이면 참, 지역 코드·접속지 아닌 노드는 거짓", () => {
    expect(isNewToday(r({ new_asn: true }))).toBe(true);
    expect(isNewToday(r({ new_cc: true }))).toBe(true);
    expect(isNewToday(r({}))).toBe(false);
    expect(isNewToday({ node: { kind: "remote" }, where: { cc: "ZZ" }, new_cc: true })).toBe(false);
    expect(isNewToday({ node: { kind: "process" }, new_asn: true })).toBe(false);
  });
});

describe("D020-4·5 숫자·여러 나라 묶음", () => {
  it("여러 나라면 접속이 가장 많은 나라 + 외 N, 그 나라 국기", () => {
    const xs: ConnLike[] = [
      c("a.exe", 1, 2, pub(1, "X", "US", "미국")),
      c("a.exe", 2, 9, pub(1, "X", "KR", "대한민국")),
      c("a.exe", 3, 1, pub(1, "X", "JP", "일본")),
    ];
    const g = groupConns(xs, "program")[0]!;
    expect(g.place).toBe("대한민국 외 2");
    expect(g.placeCc).toBe("KR");
  });
});
