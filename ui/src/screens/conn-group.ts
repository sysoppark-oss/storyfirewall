// 연결 표 묶음(제안 A2)과 "어디" 막대(제안 A3)의 계산. 화면 그리기와 떼어 단위 시험한다.
// 나라는 IP 위치 정보(DB-IP, 서버 위치와 다를 수 있음), 조직은 ASN 등록 조직 이름 — 외부 문자열이라 그리는 쪽이 텍스트 노드로만 넣는다.

export type GroupMode = "org" | "program" | "country" | "none";

export interface ConnLike {
  image: string;
  count: number;
  sent: number;
  recv: number;
  remote_id: number;
  where?: { scope: string; cc?: string; country?: string; asn?: number; org?: string } | null;
  new_asn?: boolean;
  new_cc?: boolean;
}

export interface Group<T> {
  key: string;
  title: string;
  /// "AS15169 · 원격 4곳"
  sub: string;
  place: string;
  /// 묶음의 나라가 하나면 그 코드(국기용)
  placeCc: string | null;
  programs: string;
  count: number;
  sent: number;
  recv: number;
  isNew: boolean;
  /// 정렬 맨 아래(조직 정보 없음·로컬망)
  bottom: boolean;
  items: T[];
}

const SCOPE_SHORT: Record<string, string> = {
  loopback: "이 PC", private: "로컬망", link_local: "로컬망", multicast: "멀티캐스트", broadcast: "브로드캐스트",
  cgnat: "통신사 NAT", documentation: "문서용 주소", unspecified: "지정 안 됨",
};
const base = (p: string) => p.split(/[\\/]/).pop() ?? p;

function keyOf(c: ConnLike, mode: GroupMode): { key: string; title: string; bottom: boolean } {
  const w = c.where;
  if (mode === "program") return { key: `p:${c.image}`, title: base(c.image), bottom: false };
  if (mode === "country") {
    if (!w || w.scope !== "public") return { key: "local", title: "로컬망 · 특수 주소", bottom: true };
    return w.cc ? { key: `c:${w.cc}`, title: w.country ?? w.cc, bottom: false } : { key: "c:?", title: "국가 정보 없음", bottom: true };
  }
  if (!w || w.scope !== "public") return { key: "local", title: "로컬망 · 멀티캐스트", bottom: true };
  if (w.asn == null) return { key: "o:?", title: "조직 정보 없음", bottom: true };
  return { key: `o:${w.asn}`, title: w.org ?? `AS${w.asn}`, bottom: false };
}

/// 묶음 계산. 정렬: "오늘 처음" → 접속 수 많은 순. 조직 정보 없음·로컬망은 맨 아래
export function groupConns<T extends ConnLike>(items: T[], mode: GroupMode): Group<T>[] {
  if (mode === "none") return [];
  const m = new Map<string, Group<T>>();
  for (const c of items) {
    const k = keyOf(c, mode);
    let g = m.get(k.key);
    if (!g) {
      g = { key: k.key, title: k.title, sub: "", place: "", placeCc: null, programs: "", count: 0, sent: 0, recv: 0, isNew: false, bottom: k.bottom, items: [] };
      m.set(k.key, g);
    }
    g.items.push(c);
    g.count += c.count;
    g.sent += c.sent;
    g.recv += c.recv;
    if ((mode === "org" && c.new_asn) || (mode === "country" && c.new_cc)) g.isNew = true;
  }
  for (const g of m.values()) {
    const remotes = new Set(g.items.map((c) => c.remote_id)).size;
    const asn = g.items[0]?.where?.asn;
    g.sub = mode === "org" && asn != null && !g.bottom ? `AS${asn} · 원격 ${remotes}곳` : `원격 ${remotes}곳`;
    // D010-3: 공인 주소가 아니면 국가 대신 주소 종류 이름("로컬망 외 1"). 대시(—)는 값 없음에만
    // D020-5: 여러 곳이면 접속이 가장 많은 곳을 앞에(그 나라 국기) + "외 N"
    const placeCount = new Map<string, { n: number; cc: string | null }>();
    for (const c of g.items) {
      const name = c.where && c.where.scope !== "public" ? SCOPE_SHORT[c.where.scope] ?? "로컬망" : c.where?.country;
      if (!name) continue;
      const cur = placeCount.get(name) ?? { n: 0, cc: c.where && c.where.scope === "public" && c.where.cc && !REGION_CODES.has(c.where.cc) ? c.where.cc : null };
      cur.n += c.count;
      placeCount.set(name, cur);
    }
    const places = [...placeCount.entries()].sort((a, b) => b[1].n - a[1].n);
    g.place = places.length === 0 ? "—" : places.length === 1 ? places[0]![0] : `${places[0]![0]} 외 ${places.length - 1}`;
    g.placeCc = places[0]?.[1].cc ?? null;
    const progs = [...new Set(g.items.map((c) => base(c.image)))];
    g.programs = progs.length === 1 ? progs[0]! : `${progs[0]} 외 ${progs.length - 1}`;
  }
  return [...m.values()].sort((a, b) => Number(a.bottom) - Number(b.bottom) || Number(b.isNew) - Number(a.isNew) || b.count - a.count);
}

export interface Bar {
  key: string;
  label: string;
  value: number;
  isNew: boolean;
}

/// 나라가 아닌 등록 코드(D009-8): 국가 막대·지도에 넣지 않고 "지도에 없는 주소" 줄로
export const REGION_CODES = new Set(["ZZ", "EU", "AP"]);
const REGION_LABEL: Record<string, string> = { ZZ: "지정 안 됨", EU: "유럽(나라 미상)", AP: "아시아·태평양(나라 미상)" };

/// "지도에 없는 주소: 지정 안 됨 1 · 로컬망 4" (접속 수, 0 은 생략). 전부 0 이면 빈 문자열
export function offMapLine(items: ConnLike[], label: "지도" | "막대" = "지도"): string {
  const m = new Map<string, number>();
  for (const c of items) {
    const w = c.where;
    const k = !w || w.scope !== "public" ? "로컬망" : w.cc && REGION_CODES.has(w.cc) ? REGION_LABEL[w.cc]! : null;
    if (k) m.set(k, (m.get(k) ?? 0) + c.count);
  }
  const order = ["지정 안 됨", "유럽(나라 미상)", "아시아·태평양(나라 미상)", "로컬망"];
  const parts = order.filter((k) => (m.get(k) ?? 0) > 0).map((k) => `${k} ${m.get(k)}`);
  return parts.length ? `${label}에 없는 주소: ${parts.join(" · ")}` : "";
}

/// A3 막대: 나라별·조직별 접속 수. 공인 주소만. 상위 8 + "그 밖에 N곳"
export function bars(items: ConnLike[], by: "country" | "org", top = 8): { bars: Bar[]; rest: number } {
  const m = new Map<string, Bar>();
  for (const c of items) {
    const w = c.where;
    if (!w || w.scope !== "public") continue;
    if (by === "country" && w.cc && REGION_CODES.has(w.cc)) continue;
    const key = by === "country" ? w.cc : w.asn != null ? String(w.asn) : undefined;
    if (!key) continue;
    const label = by === "country" ? (w.country ?? w.cc ?? key) : (w.org ?? `AS${w.asn}`);
    const b = m.get(key) ?? { key, label, value: 0, isNew: false };
    b.value += c.count;
    if (by === "country" ? c.new_cc && !REGION_CODES.has(w.cc ?? "") : c.new_asn) b.isNew = true;
    m.set(key, b);
  }
  const all = [...m.values()].sort((a, b) => b.value - a.value);
  return { bars: all.slice(0, top), rest: Math.max(0, all.length - top) };
}

/// 막대로 표를 거르는 조건
export function matchesFilter(c: ConnLike, f: { by: "country" | "org"; key: string } | null): boolean {
  if (!f) return true;
  const w = c.where;
  if (!w) return false;
  return f.by === "country" ? w.cc === f.key : String(w.asn) === f.key;
}

/// D012: 접속지가 "오늘 처음"(ASN 또는 나라 코드. ZZ·EU·AP 지역 코드는 나라가 아니므로 제외)
export function isNewToday(b: { node: { kind: string }; where?: { cc?: string } | null; new_asn?: boolean; new_cc?: boolean }): boolean {
  if (b.node.kind !== "remote") return false;
  return !!b.new_asn || (!!b.new_cc && !REGION_CODES.has(b.where?.cc ?? ""));
}
