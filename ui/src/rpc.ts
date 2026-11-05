// 서비스 호출: Tauri 코어의 `rpc` 명령만 쓴다 (프런트는 파이프를 모른다).
// 브라우저(vite dev, Tauri 없음)에서는 가짜로 돌아 화면을 볼 수 있다.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export interface RpcError {
  code: number;
  message: string;
  data?: unknown;
}
export type RpcResult<T = unknown> = { ok: true; result: T } | { ok: false; error: RpcError };

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export function uuid(): string {
  return crypto.randomUUID();
}

export async function connect(endpoint: string): Promise<RpcResult> {
  if (!inTauri) return { ok: false, error: { code: -1, message: "Tauri 밖(브라우저)에서는 연결할 수 없습니다" } };
  try {
    const v = (await invoke("connect", { endpoint })) as { result?: unknown; error?: RpcError };
    return v.error ? { ok: false, error: v.error } : { ok: true, result: v.result };
  } catch (e) {
    return { ok: false, error: { code: -1, message: String(e) } };
  }
}

export async function rpc<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<RpcResult<T>> {
  if (!inTauri) return { ok: false, error: { code: -1, message: "연결 없음" } };
  try {
    const v = (await invoke("rpc", { method, params })) as { result?: T; error?: RpcError };
    return v.error ? { ok: false, error: v.error } : { ok: true, result: v.result as T };
  } catch (e) {
    return { ok: false, error: { code: -1, message: String(e) } };
  }
}

/// 승격(관리자) 상태인가. 정상 사용은 늘 일반 권한(보기 모드)이고 변경은 승인 창을 거친다 (A23).
/// 사용자가 UI 자체를 관리자 권한으로 실행했으면 바로 변경한다(권장하지 않음 — 상태 표시줄 경고).
let elevatedCache: boolean | undefined;
export async function isElevated(): Promise<boolean> {
  if (elevatedCache !== undefined) return elevatedCache;
  if (!inTauri) return (elevatedCache = true); // 브라우저 미리보기
  try {
    elevatedCache = (await invoke("elevated")) as boolean;
  } catch {
    elevatedCache = false;
  }
  return elevatedCache;
}

/// -32001(관리자 아님)을 받으면 부르는 처리기 (승격된 UI 인데 계정이 관리자 그룹이 아닐 때)
let onUnauthorized: (() => void) | undefined;
export function setUnauthorizedHandler(f: () => void) {
  onUnauthorized = f;
}

/// 승인 창(도우미)을 거친 변경의 결과
export interface Approval {
  /// 도우미 종료 코드 (0 적용·유지, 4 되돌림)
  code: number;
  /// 결과에 든 정책의 지금 상태 (Confirmed / RolledBack / Applied …)
  policies: { policy_id: number; state: string | null }[];
}
export type MutationResult<T = unknown> = ({ ok: true; result: T } | { ok: false; error: RpcError }) & { approval?: Approval };

/// 승인 창 종료 코드 → 문장
export const APPROVE_TEXT: Record<number, string> = {
  1: "승인 창에서 취소했습니다. 바뀐 것은 없습니다.",
  2: "승인 창에서 오류가 났습니다. 바뀐 것은 없을 수 있습니다 — 정책 목록을 확인하세요.",
  3: "승인 창에 보인 뒤 내용이 계속 바뀌어 적용하지 않았습니다.",
  5: "승인 창이 관리자 권한을 얻지 못했습니다.",
  6: "승인 창 인자 오류",
};

/// 변경 메서드: request_id(UUID) 를 붙인다. 재시도해도 같은 id → 멱등.
/// 보기 모드면 서비스에 맡기고(change.stage) 승인 창(UAC)을 띄운 뒤 결과를 읽는다. 맡길 때의 검증 오류(needs_ack 등)는 그대로 돌려준다.
export async function mutation<T = unknown>(method: string, params: Record<string, unknown>, requestId = uuid()): Promise<MutationResult<T>> {
  const full = { request_id: requestId, ...params };
  if (await isElevated()) {
    const r = await rpc<T>(method, full);
    if (!r.ok && r.error.code === -32001) onUnauthorized?.();
    return r;
  }
  const s = await rpc<{ change_id: string }>("change.stage", { method, params: full });
  if (!s.ok) return s;
  const changeId = s.result.change_id;
  let code: number;
  try {
    code = (await invoke("approve", { changeId })) as number;
  } catch (e) {
    return { ok: false, error: { code: -1, message: `승인 창: ${String(e)}` } };
  }
  const r = await rpc<{ state: string; result?: T; error?: string; policies?: Approval["policies"] }>("change.result", { change_id: changeId });
  if (!r.ok) return r;
  if (r.result.state === "done") return { ok: true, result: r.result.result as T, approval: { code, policies: r.result.policies ?? [] } };
  const why = r.result.state === "failed" ? `서비스가 거부했습니다: ${r.result.error ?? ""}` : APPROVE_TEXT[code] ?? `승인 창 종료 코드 ${code}`;
  return { ok: false, error: { code: -32010, message: why } };
}

export interface Notification {
  method: string;
  params: Record<string, unknown>;
}

export async function onNotify(cb: (n: Notification) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const un = await listen<Notification>("svc-notify", (e) => cb(e.payload));
  return un;
}
