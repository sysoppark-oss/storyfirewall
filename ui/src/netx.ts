// 안디옥 첫 연동: 사건 카드의 [NetX로 정밀 진단] (통합 설계 0.15판 8.1 "첫 연동").
// 화면(Tauri 코어)이 NetX 의 파이프에 직접 붙는다 — 서비스는 거치지 않는다. 확인(등록부 경로·서버 프로세스)과 전송은 코어(rack.rs)가 한다.
// 보내는 값은 접속지 주소·포트와 그 접속에 짝지어진 이름뿐이다(숫자 주소가 진단 대상, 이름은 표시로만 — 변경 제안 2판). 이 단추로는 아무것도 실행·차단되지 않는다(NetX 가 입력칸을 채우고, 실행은 사용자가 NetX 에서 누른다).
import { invoke } from "@tauri-apps/api/core";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/// `name`: 그 접속에 짝지어진 이름(도메인). 진단 대상은 늘 `ip` 이고, 이름은 표시로만 따라간다(변경 제안 2판)
export interface Endpoint { ip: string; port?: number; name?: string }

let registered: Promise<boolean> | null = null;
/// NetX 가 설치돼 등록부(HKLM\SOFTWARE\Antioch\Modules\netx)에 올라 있는가 — 단추를 보일지. 앱을 켠 동안 한 번만 묻는다
export function netxRegistered(): Promise<boolean> {
  if (!inTauri) return Promise.resolve(false);
  registered ??= invoke("netx_registered").then((v) => v === true, () => false);
  return registered;
}

/// "203.0.113.9:443" · "[2001:db8::1]:443" · "203.0.113.9" → 주소·포트. 도메인 이름이면 null(도메인은 보내지 않는다).
/// 여기서는 모양만 본다 — 코어가 주소로 다시 해석하고, 해석되지 않으면 보내지 않는다
export function parseEndpoint(label: string | undefined | null): Endpoint | null {
  const s = (label ?? "").trim();
  if (!s || s.length > 64) return null;
  const port = (p: string | undefined): number | undefined | null => {
    if (p === undefined) return undefined;
    if (!/^\d{1,5}$/.test(p)) return null;
    const n = Number(p);
    return n >= 1 && n <= 65535 ? n : null;
  };
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d+))?$/.exec(s);
  if (v4) {
    if (v4.slice(1, 5).some((o) => Number(o) > 255)) return null;
    const p = port(v4[5]);
    return p === null ? null : { ip: v4.slice(1, 5).map((o) => String(Number(o))).join("."), ...(p ? { port: p } : {}) };
  }
  const v6 = /^\[([0-9a-fA-F:.]+)\](?::(\d+))?$/.exec(s) ?? (/^[0-9a-fA-F:]+$/.test(s) && s.includes("::") ? [s, s, undefined] : null);
  if (v6 && v6[1]!.includes(":")) {
    const p = port(v6[2] ?? undefined);
    return p === null ? null : { ip: v6[1]!, ...(p ? { port: p } : {}) };
  }
  return null;
}

/// "edge.microsoft.com:443" 같은 이름 접속지 → {이름, 포트}. 숫자 주소거나 이름 모양이 아니면 null
export function parseNamed(label: string | undefined | null): { name: string; port?: number } | null {
  const s = (label ?? "").trim();
  if (!s || s.length > 270 || parseEndpoint(s)) return null;
  const m = /^([A-Za-z0-9.-]+?)\.?(?::(\d{1,5}))?$/.exec(s);
  if (!m) return null;
  const name = m[1]!.toLowerCase();
  const labels = name.split(".");
  if (name.length > 253 || labels.length < 2 || labels.some((l) => !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return null;
  const n = m[2] ? Number(m[2]) : undefined;
  if (n !== undefined && (n < 1 || n > 65535)) return null;
  return { name, ...(n ? { port: n } : {}) };
}

/// 사건 카드의 접속지에서 넘길 대상을 만든다: 접속지가 숫자면 그것, 이름이면 서비스가 준 짝 주소(`egressIp`) + 이름.
/// 이름인데 짝 주소가 없으면(낮은 판 서비스) null — 부르는 쪽이 주소 후보에서 고르게 한다. **이름만으로는 넘기지 않는다**
export function targetOf(egress: string | undefined | null, egressIp: string | undefined | null): Endpoint | null {
  const numeric = parseEndpoint(egress);
  if (numeric) return numeric;
  const named = parseNamed(egress);
  const ip = parseEndpoint(egressIp);
  if (!ip) return null;
  return named ? { ip: ip.ip, ...(named.port ? { port: named.port } : {}), name: named.name } : null;
}

/// 화면에 보일 "주소:포트"
export function endpointText(e: Endpoint): string {
  const host = e.ip.includes(":") ? `[${e.ip}]` : e.ip;
  return e.port ? `${host}:${e.port}` : host;
}

/// 같은 주소·포트는 한 번만, 최대 `max` 곳
export function uniqueEndpoints(list: Endpoint[], max = 8): Endpoint[] {
  const seen = new Set<string>();
  const out: Endpoint[] = [];
  for (const e of list) {
    const k = endpointText(e);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(e);
    if (out.length >= max) break;
  }
  return out;
}

export type DiagnoseResult = { ok: true; accepted: boolean; opened: boolean; nameSent?: boolean } | { ok: false; message: string };
/// NetX 로 인계. 실패 문장은 코어가 만든 한국어 문장(예: "NetX를 먼저 켜 주세요")
export async function netxDiagnose(e: Endpoint): Promise<DiagnoseResult> {
  if (!inTauri) return { ok: false, message: "이 화면에서는 NetX 연동을 쓸 수 없습니다" };
  try {
    const r = (await invoke("netx_diagnose", { ip: e.ip, port: e.port ?? null, name: e.name ?? null })) as { accepted?: boolean; opened?: boolean; name_sent?: boolean } | null;
    return { ok: true, accepted: r?.accepted === true, opened: r?.opened === true, nameSent: r?.name_sent === true };
  } catch (err) {
    return { ok: false, message: String(err).slice(0, 200) };
  }
}

/// 인계 결과 한 줄(사실만). 이름이 따라갔으면 "주소 (이름으로 접속한 것으로 기록된 주소)" — 짝이 틀릴 수 있어 단정하지 않는다
export function diagnoseText(e: Endpoint, r: DiagnoseResult): string {
  if (!r.ok) return r.message;
  const what = e.name && r.nameSent ? `${endpointText(e)} (${e.name} 접속으로 기록된 주소)` : endpointText(e);
  if (!r.accepted) return `${what} — NetX가 받지 않았습니다`;
  return `${what} — NetX로 넘겼습니다. 진단 실행은 NetX에서 직접 누르세요${r.opened ? "" : " (NetX 창을 직접 열어 주세요)"}`;
}
