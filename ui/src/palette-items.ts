// 명령 팔레트(UI 명세 4판 3-9)의 순수 도우미. DOM 없음 — 단위 시험 대상.
// 정책을 바꾸는 명령은 "실행"이 아니라 그 기능의 대화상자·승인 창을 여는 데까지다(팔레트 안에서 바로 집행하지 않는다).

export type ItemKind = "screen" | "setting" | "incident" | "program" | "address" | "command";

export interface PaletteItem {
  kind: ItemKind;
  /// 목록에 보이는 글자(외부 문자열일 수 있음 — 화면은 텍스트 노드로만)
  label: string;
  /// 오른쪽 회색 보조 글자
  hint: string;
  /// 검색에 함께 쓰는 낱말(보이지 않음)
  keys?: string;
  /// 실행 대상 식별자(화면 키, 설정 탭, 인시던트 뿌리 번호, 프로그램 노드 번호, 주소, 명령 id)
  target: string | number;
  /// 설정 항목이면 그 탭 안에서 강조할 글자
  find?: string;
}

/// 화면 이름(main.ts SCREENS 와 같은 키)
export const SCREEN_ITEMS: PaletteItem[] = [
  { kind: "screen", label: "대시보드", hint: "화면", target: "dashboard", keys: "dashboard 홈" },
  { kind: "screen", label: "연결 · 지금 열린 연결", hint: "화면", target: "connections", keys: "connections live 연결" },
  { kind: "screen", label: "연결 · 연결 이력", hint: "화면", target: "connections:history", keys: "history 이력 지도 map" },
  { kind: "screen", label: "인시던트", hint: "화면", target: "story", keys: "story 이야기 사건" },
  { kind: "screen", label: "설치 이력", hint: "화면", target: "installs", keys: "installs 설치" },
  { kind: "screen", label: "AI 에이전트", hint: "화면", target: "agents", keys: "agents ai 에이전트 claude mcp" },
  { kind: "screen", label: "정책", hint: "화면", target: "policy", keys: "policy acl 차단 규칙" },
  { kind: "screen", label: "설정", hint: "화면", target: "settings", keys: "settings 설정" },
];

/// 설정 항목 이름 → 탭(settings.ts 4판 7-1 탭 구성과 같게)
export const SETTING_ITEMS: PaletteItem[] = [
  { kind: "setting", label: "샌드박스 관찰(첫 실행)", hint: "설정 · 보호 엔진", target: "engine", find: "샌드박스 관찰" },
  { kind: "setting", label: "관찰 기간", hint: "설정 · 보호 엔진", target: "engine", find: "관찰 기간" },
  { kind: "setting", label: "파괴 행위 자동 대응", hint: "설정 · 보호 엔진", target: "engine", find: "자동 대응", keys: "T1490 vssadmin" },
  { kind: "setting", label: "허용 서명자", hint: "설정 · 보호 엔진", target: "engine", find: "허용 서명자" },
  { kind: "setting", label: "신뢰하는 원격 제어 도구", hint: "설정 · 보호 엔진", target: "engine", find: "원격 제어 도구", keys: "rdp anydesk teamviewer" },
  { kind: "setting", label: "화면 테마", hint: "설정 · 알림·표시", target: "notify", find: "화면 테마", keys: "theme dark light 다크" },
  { kind: "setting", label: "보호 상태 표시(HUD)", hint: "설정 · 알림·표시", target: "notify", find: "HUD", keys: "hud 트레이" },
  { kind: "setting", label: "알림", hint: "설정 · 알림·표시", target: "notify", find: "알림", keys: "toast windows 알림" },
  { kind: "setting", label: "서술 형식", hint: "설정 · 알림·표시", target: "notify", find: "서술 형식", keys: "voice" },
  { kind: "setting", label: "진단", hint: "설정 · 데이터·진단", target: "diag", find: "진단", keys: "diagnostics 수집 상태" },
  { kind: "setting", label: "보관 기간", hint: "설정 · 데이터·진단", target: "diag", find: "보관", keys: "retention" },
  { kind: "setting", label: "텔레메트리 소스", hint: "설정 · 데이터·진단", target: "diag", find: "텔레메트리 소스", keys: "geoip db-ip" },
  { kind: "setting", label: "업데이트 확인", hint: "설정 · 업데이트·정보", target: "update", find: "새 판", keys: "update 판 버전" },
];

/// ">" 명령(3-9): 모두 화면 이동 또는 대화상자·승인 창 열기까지
export const COMMAND_ITEMS: PaletteItem[] = [
  { kind: "command", label: "긴급 차단…", hint: "대화상자 열기", target: "emg-start", keys: "emergency block 차단" },
  { kind: "command", label: "긴급 차단 해제…", hint: "해제 메뉴 열기", target: "emg-stop", keys: "emergency stop 해제" },
  { kind: "command", label: "지켜보는 인시던트", hint: "인시던트 목록", target: "watching", keys: "watch 지켜보기" },
  { kind: "command", label: "진단 정보 복사", hint: "설정 › 데이터·진단", target: "diag-copy", keys: "diagnostics copy" },
  { kind: "command", label: "테마 바꾸기", hint: "시스템 → 밝게 → 어둡게", target: "theme", keys: "theme dark light" },
  { kind: "command", label: "HUD 켜기/끄기", hint: "설정 › 알림·표시", target: "hud", keys: "hud" },
];

/// 비교용: 소문자 + 공백·구분 기호 제거
export function norm(s: string): string {
  return s.toLowerCase().replace(/[\s·_\-./\\:()]+/g, "");
}

/// 일치 점수(높을수록 앞). 0 이면 안 맞음. 앞부분 일치 > 낱말 안 일치 > 글자 순서 일치(퍼지)
export function score(item: PaletteItem, q: string): number {
  const nq = norm(q);
  if (!nq) return 1;
  const nl = norm(item.label);
  if (nl.startsWith(nq)) return 100 - Math.min(50, nl.length - nq.length);
  if (nl.includes(nq)) return 60;
  const nk = norm(item.keys ?? "");
  if (nk.includes(nq)) return 40;
  // 글자 순서 일치(3글자 이상만 — 짧은 입력이 아무거나 맞지 않게)
  if (nq.length >= 3) {
    let i = 0;
    for (const ch of nl) if (ch === nq[i]) i++;
    if (i === nq.length) return 20;
  }
  return 0;
}

/// 강조할 일치 범위 [시작, 끝) — 원래 글자 기준. 연속 일치만(퍼지 일치는 강조 없음). 대소문자 무시
export function matchRange(label: string, q: string): [number, number] | null {
  const t = q.trim().toLowerCase();
  if (!t) return null;
  const i = label.toLowerCase().indexOf(t);
  return i >= 0 ? [i, i + t.length] : null;
}

/// IP 주소·도메인처럼 보이나(연결 이력 거르기 대상). 외부 문자열 — 형식만 본다
export function looksLikeAddress(q: string): boolean {
  const s = q.trim();
  if (s.length < 3 || s.length > 253) return false;
  if (/^\d{1,3}(\.\d{1,3}){1,3}$/.test(s)) return true;
  if (/^[0-9a-f:]+$/i.test(s) && s.includes(":") && s.split(":").length > 2) return true;
  return /^(?=.*[a-z])[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s);
}

/// "#번호" 또는 숫자만 → 인시던트 번호
export function incidentNo(q: string): number | null {
  const m = /^#?(\d{1,12})$/.exec(q.trim());
  return m ? Number(m[1]) : null;
}

/// 입력에 맞는 결과(최대 limit). ">" 로 시작하면 명령만. 같은 점수면 원래 순서
export function search(q: string, pools: PaletteItem[][], limit = 12): PaletteItem[] {
  const isCmd = q.trimStart().startsWith(">");
  const text = isCmd ? q.trimStart().slice(1) : q;
  const all = isCmd ? COMMAND_ITEMS : pools.flat();
  const scored = all.map((it, i) => ({ it, s: score(it, text), i })).filter((x) => x.s > 0);
  scored.sort((a, b) => b.s - a.s || a.i - b.i);
  return scored.slice(0, limit).map((x) => x.it);
}

/// 최근 이동(같은 것은 앞으로 올리고 5개까지)
export function pushRecent(list: PaletteItem[], it: PaletteItem, max = 5): PaletteItem[] {
  const same = (a: PaletteItem) => a.kind === it.kind && a.target === it.target && a.find === it.find;
  return [it, ...list.filter((x) => !same(x))].slice(0, max);
}

/// 테마 순환: 시스템 → 밝게 → 어둡게 → 시스템
export function nextTheme(t: "system" | "light" | "dark"): "system" | "light" | "dark" {
  return t === "system" ? "light" : t === "light" ? "dark" : "system";
}
