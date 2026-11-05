// 앱 상태: 연결·알림 구독·화면 전환. 화면은 DOM 조각을 돌려주는 함수다 (프레임워크 없음, 14차 Q3).
import { connect, onNotify, rpc, type Notification } from "./rpc";

type Screen = "dashboard" | "connections" | "story" | "policy" | "settings";

class AppState {
  connected = false;
  serverVersion = "";
  /// 27차 Gemini Q1: 엔진이 지금 한 일에 몇 ms 째 묶여 있는가(hello 가 엔진 밖에서 알려 준다). 0 = 쉬는 중
  engineBusyMs = 0;
  lastError = "";
  endpoint = import.meta.env.DEV ? "tcp:127.0.0.1:7878" : "pipe";
  private listeners = new Map<HTMLElement, (n: Notification) => void>();
  go: (s: Screen, args?: Record<string, unknown>) => void = () => {};

  async connect(): Promise<boolean> {
    const r = await connect(this.endpoint);
    if (!r.ok) {
      this.connected = false;
      this.lastError = r.error.message;
      return false;
    }
    this.connected = true;
    this.serverVersion = String((r.result as { server_version?: string })?.server_version ?? "");
    this.engineBusyMs = Number((r.result as { engine_busy_ms?: number })?.engine_busy_ms ?? 0);
    // 의심 사건·정책 알림 구독 (연결 수준·1초 갱신은 연결 화면이 따로)
    await rpc("events.subscribe", {});
    return true;
  }

  /// 엔진 묶임 확인(연결 중 hello — 엔진을 거치지 않는다). 예전 서비스면 값이 없어 0
  async pingEngine(): Promise<number> {
    if (!this.connected) return 0;
    const r = await rpc<{ engine_busy_ms?: number }>("rpc.hello", { client_version: "ui", api: [1, 0] });
    this.engineBusyMs = r.ok ? Number(r.result.engine_busy_ms ?? 0) : 0;
    return this.engineBusyMs;
  }

  /// 화면이 알림을 받는다. 화면이 떠나면 자동 해제 (screen-leave).
  /// 연결이 끊겼을 때 (main.ts 가 상태 표시줄을 바꾼다)
  onDisconnect?: (reason: string) => void;

  onNotify(owner: HTMLElement, cb: (n: Notification) => void) {
    this.listeners.set(owner, cb);
    owner.addEventListener("screen-leave", () => this.listeners.delete(owner));
  }

  async start() {
    await onNotify((n) => {
      if (n.method === "client.disconnected") {
        // 서비스 연결이 끊김 (A24 진단): 사유를 남기고 상태 표시줄을 바꾼다. 종단 시험은 콘솔 오류로 잡는다
        const reason = String(n.params?.["reason"] ?? "?");
        this.connected = false;
        this.lastError = `연결 끊김 (${reason})`;
        console.error(`service disconnected: ${reason}`);
        this.onDisconnect?.(reason);
        return;
      }
      for (const cb of this.listeners.values()) cb(n);
    });
  }
}

export const state = new AppState();

/// 27차 Gemini Q1: 엔진이 한 일에 15초 넘게 묶여 있으면 상태 줄 경고(사실만 — 원인을 단정하지 않는다)
export const ENGINE_STUCK_MS = 15_000;
export function engineStuckText(ms: number): string {
  return ms > ENGINE_STUCK_MS ? `보호 엔진이 한 가지 일에 ${Math.round(ms / 1000)}초째 묶여 있습니다 — 판정·차단 반영이 늦을 수 있습니다` : "";
}
