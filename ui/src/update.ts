// 자동 업데이트(사용자 결정 2026-11-06 "켤 때 자동 업데이트 확인 기본").
// 확인·받기·서명 검사·설치는 Rust 쪽(tauri-plugin-updater)이 한다. 화면은 묻고 보여 주기만 한다.
// 공개 빌드(SF_UPDATER=1 로 만든 것)에서만 동작한다 — 개발 빌드는 늘 "꺼짐".
// 외부 통신: GitHub Releases 의 latest.json 한 번(받는 것 없음 · 보내는 것은 요청 자체뿐). 설정에서 끌 수 있다.
import { invoke } from "@tauri-apps/api/core";
import { el, button } from "./ui";

export interface UpdateInfo {
  version: string;
  current: string;
  notes?: string | null;
  date?: string | null;
}

const KEY = "sf.update.auto";

/// 켤 때 자동 확인 — 기본 켬(저장소를 못 쓰면 기본값)
export function autoCheck(): boolean {
  try {
    return localStorage.getItem(KEY) !== "0";
  } catch {
    return true;
  }
}
export function setAutoCheck(on: boolean) {
  try {
    localStorage.setItem(KEY, on ? "1" : "0");
  } catch {
    /* 무시 */
  }
}

export async function updaterEnabled(): Promise<boolean> {
  try {
    return (await invoke("update_enabled")) as boolean;
  } catch {
    return false;
  }
}

export async function checkUpdate(): Promise<UpdateInfo | null> {
  return (await invoke("update_check")) as UpdateInfo | null;
}

/// 받고 서명을 검사한 뒤 설치 프로그램을 띄운다(관리자 설치라 UAC 승인 창이 한 번 뜬다). 성공하면 앱이 닫히고 새 판으로 다시 열린다
export async function installUpdate(): Promise<void> {
  await invoke("update_install");
}

/// 화면 맨 위 알림 띠: "새 판 X 이(가) 있습니다 [지금 설치] [나중에]"
export function updateBanner(u: UpdateInfo, onClose: () => void): HTMLElement {
  const bar = el("div", "update-banner");
  const msg = el("span", undefined, `새 판 ${u.version} 이 있습니다 (지금 ${u.current}).`);
  const note = el("span", "muted small");
  const go = button("지금 설치", async () => {
    go.disabled = true;
    note.textContent = " 받는 중… 서명을 확인한 뒤 설치 창(UAC)이 뜹니다.";
    try {
      await installUpdate();
    } catch (e) {
      go.disabled = false;
      note.textContent = ` 설치하지 못했습니다: ${String(e)}`;
    }
  }, "btn small primary");
  const later = button("나중에", onClose, "btn small");
  bar.append(msg, note, el("span", "spacer"), later, go);
  return bar;
}
