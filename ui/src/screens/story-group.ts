// D020-2: 같은 프로그램(실행 파일 경로) + 같은 판정(수준·항목)이 여러 번이면 한 장으로 묶는다.
// 노트북 실측: 고립 svchost 의심 카드 12장이 대시보드·이야기를 채웠다. 사실은 버리지 않고 묶음 안 "발생 시각"으로 남긴다.

export interface Groupable {
  root: number;
  title: string;
  level: string;
  last_ts?: number;
  root_image?: string;
  items?: { label: string; value: string }[];
}

export interface StoryGroup<T> {
  /// 대표(가장 최근)
  head: T;
  /// 묶인 사건 전부(최근 먼저)
  members: T[];
  first_ts: number;
  last_ts: number;
}

export function groupKey(s: Groupable): string {
  const str = (x: unknown) => (typeof x === "string" ? x : "");
  const prog = (str(s.root_image) || str(s.title)).toLowerCase(); // 빈 문자열(경로 모름)도 제목으로
  const items = (s.items ?? []).filter((i) => i.label !== "시작 경위").map((i) => `${i.label}=${i.value}`).sort().join("|");
  return `${prog}#${str(s.level).toLowerCase()}#${items}`;
}

/// 묶기. 결과는 최신 사건이 위(대표 시각 내림차순)
export function groupStories<T extends Groupable>(xs: T[]): StoryGroup<T>[] {
  const m = new Map<string, T[]>();
  for (const s of xs) {
    const k = groupKey(s);
    const g = m.get(k);
    if (g) g.push(s);
    else m.set(k, [s]);
  }
  const out: StoryGroup<T>[] = [];
  for (const members of m.values()) {
    members.sort((a, b) => (b.last_ts ?? 0) - (a.last_ts ?? 0));
    const ts = members.map((x) => x.last_ts ?? 0).filter((t) => t > 0);
    out.push({ head: members[0]!, members, first_ts: ts.length ? Math.min(...ts) : 0, last_ts: ts.length ? Math.max(...ts) : 0 });
  }
  return out.sort((a, b) => b.last_ts - a.last_ts);
}

type SourcedItem = { label: string; value: string; sources?: [string, number][] };
/// D020·D030 보류: 묶음 카드의 근거 배지는 묶인 사건 전부의 합계(같은 항목 = 같은 이름·같은 값).
/// 대표 사건 객체는 바꾸지 않고 항목만 새로 만든 사본을 돌려준다
export function sumGroupSources<T extends { items?: SourcedItem[] }>(head: T, members: T[]): T {
  if (members.length < 2 || !head.items) return head;
  const items = head.items.map((it) => {
    const sum = new Map<string, number>();
    for (const m of members) {
      const same = (m.items ?? []).find((x) => x.label === it.label && x.value === it.value);
      for (const [src, n] of same?.sources ?? []) sum.set(src, (sum.get(src) ?? 0) + n);
    }
    return sum.size ? { ...it, sources: [...sum.entries()] as [string, number][] } : it;
  });
  return { ...head, items };
}

/// D035-3: 제목이 같은 묶음이 둘 이상이면 무엇이 다른지 줄에 보인다 — 다른 판정 항목 값(짧게), 그것도 같으면 실행 파일의 끝 폴더.
/// 돌려주는 배열은 groups 와 같은 순서(차이가 없거나 제목이 하나뿐이면 "")
export function distinguishGroups<T extends Groupable>(groups: StoryGroup<T>[], titleOf: (s: T) => string): string[] {
  const itemSet = (s: T) => new Set((s.items ?? []).filter((i) => i.label !== "시작 경위").map((i) => `${i.label}=${i.value}`));
  return groups.map((g, gi) => {
    const t = titleOf(g.head);
    const others = groups.filter((o, oi) => oi !== gi && titleOf(o.head) === t);
    if (!others.length) return "";
    const mine = itemSet(g.head);
    const diff = [...mine].filter((x) => others.some((o) => !itemSet(o.head).has(x)));
    // D037-2: "항목 이름: 값"(이야기 카드 항목 이름 그대로). 말줄임은 화면에서(diffShort), 전체는 툴팁
    if (diff.length) return diff.map((x) => `${x.slice(0, x.indexOf("="))}: ${x.slice(x.indexOf("=") + 1)}`).join(" · ");
    const path = g.head.root_image ?? "";
    const parts = path.split(/[\\/]/);
    return parts.length > 1 ? `위치: ${parts[parts.length - 2]!}` : "";
  });
}

/// 40자 넘으면 말줄임(전체는 툴팁으로)
export function diffShort(s: string): string {
  if (typeof s !== "string") return "";
  return s.length > 40 ? `${s.slice(0, 39)}…` : s;
}

/** 저장 과부하로 기록이 빠진 구간 묶음(L053): 카드 여러 장 대신 한 줄 요약 + 펼쳐 보기 */
export interface GapLike { from_ts: number; to_ts: number; events: number; reason?: string }
export interface GapSummary<T extends GapLike> { count: number; events: number; first_ts: number; last_ts: number; list: T[] }

/** 기록 없는 구간(no_record)·0건은 빼고, 최신 구간이 위로 오게 묶는다. 없으면 null */
export function summarizeGaps<T extends GapLike>(gaps: T[]): GapSummary<T> | null {
  const list = gaps.filter((g) => g.reason !== "no_record" && g.events > 0).sort((a, b) => b.from_ts - a.from_ts);
  if (!list.length) return null;
  return {
    count: list.length,
    events: list.reduce((n, g) => n + g.events, 0),
    first_ts: Math.min(...list.map((g) => g.from_ts)),
    last_ts: Math.max(...list.map((g) => g.to_ts)),
    list,
  };
}
