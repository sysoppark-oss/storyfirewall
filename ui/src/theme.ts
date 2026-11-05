// 화면 테마(D011): 기본 = Windows 설정을 따름(prefers-color-scheme). 설정 화면에서 밝게/어둡게 고정할 수 있다(이 브라우저에 기억).
export type Theme = "system" | "light" | "dark";

export function loadTheme(): Theme {
  try {
    const v = localStorage.getItem("sf.theme");
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch { /* 저장소 없음 */ }
  return "system";
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
