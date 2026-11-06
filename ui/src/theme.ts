// 화면 테마(D011): 기본 = 어둡게(B안 그물 지도 겉모양, D049 사용자 채택 2026-11-06). 설정에서 밝게·Windows 따라가기로 바꿀 수 있다(이 브라우저에 기억).
export type Theme = "system" | "light" | "dark";

export function loadTheme(): Theme {
  try {
    const v = localStorage.getItem("sf.theme");
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch { /* 저장소 없음 */ }
  return "dark";
}

/// 문서에 적용하고, 캔버스로 그리는 화면(마인드맵)이 다시 칠하도록 알린다
export function applyTheme(t: Theme = loadTheme()) {
  const root = document.documentElement;
  if (t === "system") delete root.dataset["theme"];
  else root.dataset["theme"] = t;
  window.dispatchEvent(new Event("sf-theme"));
}

export function setTheme(t: Theme) {
  try { localStorage.setItem("sf.theme", t); } catch { /* 무시 */ }
  applyTheme(t);
}
