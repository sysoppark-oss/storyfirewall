// 안디옥 첫 연동: 사건 카드의 [NetX로 정밀 진단] (통합 설계 0.15판 8.1 "첫 연동").
// 화면(Tauri 코어)이 NetX 의 파이프에 직접 붙는다 — 서비스는 거치지 않는다. 확인(등록부 경로·서버 프로세스)과 전송은 코어(rack.rs)가 한다.
// 보내는 값은 접속지 주소·포트뿐이다. 이 단추로는 아무것도 실행·차단되지 않는다(NetX 가 입력칸을 채우고, 실행은 사용자가 NetX 에서 누른다).
import { invoke } from "@tauri-apps/api/core";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export interface Endpoint { ip: string; port?: number }

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

export type DiagnoseResult = { ok: true; accepted: boolean; opened: boolean } | { ok: false; message: string };
/// NetX 로 인계. 실패 문장은 코어가 만든 한국어 문장(예: "NetX를 먼저 켜 주세요")
export async function netxDiagnose(e: Endpoint): Promise<DiagnoseResult> {
  if (!inTauri) return { ok: false, message: "이 화면에서는 NetX 연동을 쓸 수 없습니다" };
  try {
    const r = (await invoke("netx_diagnose", { ip: e.ip, port: e.port ?? null })) as { accepted?: boolean; opened?: boolean } | null;
    return { ok: true, accepted: r?.accepted === true, opened: r?.opened === true };
  } catch (err) {
    return { ok: false, message: String(err).slice(0, 200) };
  }
}

/// 인계 결과 한 줄(사실만)
export function diagnoseText(e: Endpoint, r: DiagnoseResult): string {
  if (!r.ok) return r.message;
  if (!r.accepted) return `${endpointText(e)} — NetX가 받지 않았습니다`;
  return `${endpointText(e)} — NetX로 넘겼습니다. 진단 실행은 NetX에서 직접 누르세요${r.opened ? "" : " (NetX 창을 직접 열어 주세요)"}`;
}
