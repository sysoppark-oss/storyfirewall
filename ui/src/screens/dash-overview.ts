// 대시보드 개요(사용자 "대시보드 UI 구성이 너무 약함" 2026-11-06): 제품이 답하는 네 질문을 첫 화면에.
// 숫자는 서비스가 준 사실(연결 기록·듣는 포트·설치 묶음)에서 화면이 세기만 한다. 의도를 단정하는 말은 쓰지 않는다.
import { fileName } from "../sanitize";

export interface DashConn {
  image: string;
  direction: string;
  count: number;
  sent: number;
  recv: number;
  remote_id: number;
  last_ft: number;
  where?: { scope: string; cc?: string; country?: string; asn?: number; org?: string } | null;
  new_asn?: boolean;
  new_cc?: boolean;
}

export interface DashListener {
  proto: string;
  laddr: string;
  lport: number;
  any_addr: boolean;
  image: string | null;
}

/// 공인 주소인가(로컬망·루프백·멀티캐스트·지정 안 됨 제외)
export function isPublic(c: DashConn): boolean {
  const s = c.where?.scope;
  return !s || s === "public";
}

export interface Overview {
  remotes: number;
  programs: number;
  sent: number;
  recv: number;
  inbound: number;
  inboundRemotes: number;
  newOrgs: number;
  newCountries: number;
  exposed: DashListener[];
  topPrograms: { name: string; sent: number; recv: number; remotes: number }[];
  hourly: number[];
}

/// 오늘 연결 기록 → 대시보드 숫자. 시간대 막대는 "마지막 접속 시각" 기준(묶인 기록이라 처음~마지막 사이 분포는 모른다)
export function overview(conns: DashConn[], listeners: DashListener[], nowSec: number): Overview {
  const remotes = new Set<number>();
  const progs = new Map<string, { name: string; sent: number; recv: number; remotes: Set<number> }>();
  const inRemotes = new Set<number>();
  const newOrgs = new Set<string>();
  const newCc = new Set<string>();
  let sent = 0, recv = 0, inbound = 0;
  const hourly = new Array<number>(24).fill(0);
  const dayStart = (() => { const d = new Date(nowSec * 1000); d.setHours(0, 0, 0, 0); return d.getTime() / 1000; })();
  for (const c of conns) {
    remotes.add(c.remote_id);
    sent += c.sent;
    recv += c.recv;
    const key = c.image.toLowerCase();
    const p = progs.get(key) ?? { name: fileName(c.image) || c.image, sent: 0, recv: 0, remotes: new Set<number>() };
    p.sent += c.sent;
    p.recv += c.recv;
    p.remotes.add(c.remote_id);
    progs.set(key, p);
    if (c.direction === "in") { inbound += c.count; inRemotes.add(c.remote_id); }
    if (c.new_asn && c.where?.org) newOrgs.add(c.where.org);
    if (c.new_cc && c.where?.cc) newCc.add(c.where.cc);
    const t = c.last_ft > 0 ? c.last_ft / 10_000_000 - 11_644_473_600 : 0;
    if (t >= dayStart && t <= nowSec + 60) hourly[new Date(t * 1000).getHours()]! += c.count;
  }
  const topPrograms = [...progs.values()]
    .map((p) => ({ name: p.name, sent: p.sent, recv: p.recv, remotes: p.remotes.size }))
    .sort((a, b) => b.sent + b.recv - (a.sent + a.recv) || b.remotes - a.remotes)
    .slice(0, 5);
  // 밖에서 닿을 수 있는 듣는 포트 = 모든 주소(0.0.0.0/::)에서 듣는 것. 같은 포트·프로토콜은 한 번
  const seen = new Set<string>();
  const exposed = listeners.filter((l) => l.any_addr).filter((l) => {
    const k = `${l.proto}/${l.lport}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  }).sort((a, b) => a.lport - b.lport);
  return {
    remotes: remotes.size,
    programs: progs.size,
    sent, recv, inbound,
    inboundRemotes: inRemotes.size,
    newOrgs: newOrgs.size,
    newCountries: newCc.size,
    exposed,
    topPrograms,
    hourly,
  };
}
