import { mutation, rpc } from "../rpc";
import { el, ext, button, errorBox, clear } from "../ui";
import { state } from "../state";
import { loadTheme, setTheme, type Theme } from "../theme";
import { autoCheck, setAutoCheck, checkUpdate, updateBanner, updaterEnabled } from "../update";
import { diagnostics } from "./diag";
import { FIRST_RUN_CHOICES, FIRST_RUN_MINUTES, FIRST_RUN_MINUTES_SENTENCE, firstRunSentence, firstRunSetting, umbrellaText, type FirstRunMode } from "./first-run";
import { approvalBox, countdown, type ApplyReply } from "../confirm";

/// 보관 설정 값 → "원시 기록 7일 · 연결 요약 30일". 아는 키가 없으면 빈 문자열
export function retentionText(v: Record<string, unknown>): string {
  const parts: string[] = [];
  const n = (k: string) => (typeof v[k] === "number" ? (v[k] as number) : null);
  // D033-2: 개발 말("원시") 대신 사용자 말
  if (n("raw_days") != null) parts.push(`자세한 기록 ${n("raw_days")}일`);
  if (n("summary_days") != null) parts.push(`연결 요약 ${n("summary_days")}일`);
  // 서버 필드는 suspicious_days(graph::retention::RetentionPolicy). 예전 이름 incident_days 도 읽는다
  const sus = n("suspicious_days") ?? n("incident_days");
  if (sus != null) parts.push(`의심 사건 ${sus}일`);
  return parts.length ? `보관: ${parts.join(" · ")}` : "";
}

/// 설정: 보관·화법·연결 끝점. 외부 전송 옵션(Claude 서술 등)은 켤 때 무엇이 나가는지 보여 준다 (지침 AI 요소).
export function settings(): HTMLElement {
  const root = el("section", "screen");
  root.append(el("h1", undefined, "설정"));
  // D025-B: 진단을 맨 위에(수집 상태 줄 "자세히 ›"가 여기로 온다)
  root.append(diagnostics());
  const out = el("div", "out");
  const voice = el("select");
  for (const [v, l] of [["plain", "담백하게"], ["story", "이야기처럼"]] as const) {
    const o = el("option", undefined, l);
    o.value = v;
    voice.append(o);
  }
  // 첫 실행 관찰실 (17판 23-2 ①): 끄기 / 알리기 / 알리고 막기 + 관찰 시간. 바꾸기는 관리자 승인 경로(settings.set)
  const frMode = el("select");
  for (const c of FIRST_RUN_CHOICES) {
    const o = el("option", undefined, c.label);
    o.value = c.value;
    frMode.append(o);
  }
  frMode.value = "notify";
  const frModeTip = el("p", "muted", firstRunSentence("notify"));
  frMode.addEventListener("change", () => { frModeTip.textContent = firstRunSentence(frMode.value as FirstRunMode); });
  const frMin = el("select");
  for (const m of FIRST_RUN_MINUTES) {
    const o = el("option", undefined, `${m}분`);
    o.value = String(m);
    frMin.append(o);
  }
  frMin.value = "10";
  // 31차 검수 4: settings.get 응답 전에는 기본값(알리기·10분)이 실제 설정처럼 보이고, 그때 "저장"을 누르면 실제 설정을 덮어쓴다 →
  // 응답이 올 때까지 잠그고 "불러오는 중"을 보인다
  frMode.disabled = true;
  frMin.disabled = true;
  voice.disabled = true;
  // 33차 검수 3: 잠긴 칸들(화법·첫 실행 관찰·관찰 시간) 위에 한 번만
  const loadNote = el("p", "muted", "설정을 불러오는 중…");
  // 관찰실 차단 정책(우산)의 지금 상태 — 막기 모드일 때만 한 줄
  const frUmb = el("p", "muted");
  const refreshUmbrella = async () => {
    const g = await rpc<Record<string, unknown>>("settings.get", {});
    if (g.ok) frUmb.textContent = umbrellaText(firstRunSetting(g.result).mode, g.result["first_run_umbrella"]);
  };
  const endpoint = el("input");
  endpoint.value = state.endpoint;
  const reconnect = button("다시 연결", async () => {
    state.endpoint = endpoint.value;
    const ok = await state.connect();
    out.replaceChildren(ok ? el("div", "ok", `연결됨: 서버 ${state.serverVersion}`) : errorBox(state.lastError));
  });
  const save = button("저장", async () => {
    const r = await mutation<{ ok: boolean; policies?: ApplyReply[] }>("settings.set", { voice: voice.value, first_run_watch: frMode.value, first_run_minutes: Number(frMin.value) });
    if (!r.ok) return out.replaceChildren(errorBox(r.error.message));
    out.replaceChildren(el("div", "ok", "저장됨"));
    // 막기를 고르면 관찰실 차단 정책(우산)이 생긴다: 승인 창을 거쳤으면 그 결과, 직접 실행이면 60초 확인
    if (r.approval) out.append(approvalBox(r.approval, "관찰실 "));
    else for (const pol of r.result.policies ?? []) out.append(countdown(pol, root, () => void refreshUmbrella(), "관찰실 "));
    void refreshUmbrella();
  }, "btn primary");
  save.disabled = true;
  save.title = "설정을 불러온 뒤 바꿀 수 있습니다";
  // D006-5: 끝점·다시 연결은 고급 접힘 안으로
  const adv = el("details", "advanced", el("summary", undefined, "고급"), el("label", undefined, "서비스 끝점 ", endpoint, " ", reconnect));
  const trustedBox = el("div", "form", el("p", "muted", "불러오는 중…"));
  const drawTrusted = (list: string[]) => {
    clear(trustedBox);
    if (!list.length) {
      // 사실만: 감지 근거는 송신량이지 화면이 아니다(의도·내용 단정 금지)
      trustedBox.append(el("p", "muted", "없음 — 원격 제어 프로그램이 외부로 데이터를 계속 보내기 시작하면 모두 큰 경보로 알립니다."));
      return;
    }
    for (const t of list) {
      const note = el("span", "muted small");
      // 도구 이름은 서비스 목록의 key(소문자·_ 만 — 설정 검증)
      trustedBox.append(el("p", undefined, ext("span", t), " ", button("표시 지우기", async () => {
        const r = await mutation("settings.set", { remote_trusted_tools: list.filter((x) => x !== t) });
        if (r.ok) drawTrusted(list.filter((x) => x !== t));
        else note.textContent = r.error.message;
      }), " ", note));
    }
  };
  const geoAge = el("p", "muted", "IP 데이터 정보를 불러오는 중…");
  // D007-3: DB 있음/없음에 따라 문장이 모순되지 않게 한 곳에서 정한다
  const geoSrc = el("p", "muted");
  // D011: 화면 테마 — Windows 따라가기 / 밝게 / 어둡게 (이 브라우저에 기억, 서비스 설정 아님)
  const theme = el("select");
  for (const [v, l] of [["dark", "어둡게(기본)"], ["light", "밝게"], ["system", "Windows 따라가기"]] as const) {
    const o = el("option", undefined, l);
    o.value = v;
    theme.append(o);
  }
  theme.value = loadTheme();
  theme.addEventListener("change", () => setTheme(theme.value as Theme));
  // 자동 업데이트(기본 켬). 공개 빌드에서만 동작
  const upAuto = el("input") as HTMLInputElement;
  upAuto.type = "checkbox";
  upAuto.checked = autoCheck();
  upAuto.addEventListener("change", () => setAutoCheck(upAuto.checked));
  const upNote = el("span", "muted small");
  const upBox = el("div", "update-slot");
  const upBtn = button("지금 확인", async () => {
    upNote.textContent = " 확인 중…";
    upBox.replaceChildren();
    if (!(await updaterEnabled())) { upNote.textContent = " 이 빌드(개발판)에서는 업데이트를 쓰지 않습니다."; return; }
    try {
      const u = await checkUpdate();
      upNote.textContent = u ? "" : " 지금 판이 최신입니다.";
      if (u) upBox.append(updateBanner(u, () => upBox.replaceChildren()));
    } catch (e) {
      upNote.textContent = ` 확인하지 못했습니다: ${String(e)}`;
    }
  }, "btn small");
  const upLine = el("div", "update-line", el("label", undefined, upAuto, " 켤 때 새 판이 있는지 확인(기본)"), " ", upBtn, upNote);
  root.append(
    el("div", "form",
      el("label", undefined, "화면 테마 ", theme),
      el("h3", undefined, "업데이트"),
      upLine,
      el("p", "muted small", "GitHub 공개 릴리스에서 새 판 정보(latest.json)만 받아 봅니다. 이 PC 의 기록은 보내지 않습니다. 설치 파일은 서명을 확인한 뒤에만 실행하고, 설치할 때 승인 창(UAC)이 한 번 뜹니다."),
      upBox,
      loadNote,
      el("label", undefined, "이야기 화법 ", voice),
      el("p", "muted", "Claude 서술·로컬 언어 모델은 아직 없습니다. 켜는 옵션이 생기면 무엇이 전송되는지 먼저 보여 줍니다."),
      el("label", undefined, "첫 실행 관찰 ", frMode),
      frModeTip,
      frUmb,
      el("label", undefined, "관찰 시간 ", frMin),
      el("p", "muted", FIRST_RUN_MINUTES_SENTENCE),
      el("div", "actions", save)),
    out,
    // 33차 Gemini Q4: "내가 쓰는 원격 도구"(이 도구의 원격 세션 시작은 작은 알림). 표시는 대시보드 사건 줄에서, 지우기는 여기서
    el("h2", undefined, "내가 쓰는 원격 도구"),
    trustedBox,
    el("h2", undefined, "데이터 출처"),
    geoAge,
    geoSrc,
    el("p", "muted", "국기 그림: flag-icons (MIT, Panayiotis Lipiridis). 국가 이름: i18n-iso-countries (MIT)."),
    adv,
  );
  void (async () => {
    const r = await rpc<Record<string, unknown>>("settings.get", {});
    if (r.ok && typeof r.result["voice"] === "string") voice.value = r.result["voice"];
    if (!r.ok) {
      // 설정을 못 읽었으면 잠근 채로 두고 까닭을 보인다(기본값으로 저장하지 않게)
      loadNote.textContent = "설정을 불러오지 못했습니다. 화면을 다시 열어 주세요.";
      loadNote.className = "warn";
    }
    if (r.ok) {
      frMode.disabled = false;
      frMin.disabled = false;
      voice.disabled = false;
      save.disabled = false;
      loadNote.hidden = true;
      save.title = "";
      const fr = firstRunSetting(r.result);
      frMode.value = fr.mode;
      frModeTip.textContent = firstRunSentence(fr.mode);
      frMin.value = String(fr.minutes);
      frUmb.textContent = umbrellaText(fr.mode, r.result["first_run_umbrella"]);
      const tt = r.result["remote_trusted_tools"];
      drawTrusted(Array.isArray(tt) ? tt.filter((x): x is string => typeof x === "string") : []);
    }
    // D033-3: 보관 기간은 진단 카드에만(여기 줄은 중복이라 뺐다)
    clear(out);
    // IP 데이터 기준일(제안 A5 첫 단계): 90일 넘으면 주황
    const c = await rpc<{ geo?: { built?: number | null } }>("connections.list", { since_secs: 1 });
    const built = c.ok ? c.result.geo?.built : null;
    if (!c.ok) {
      geoAge.textContent = "IP 데이터 정보를 불러오지 못했습니다.";
      geoSrc.textContent = "IP 국가·ASN 데이터: DB-IP Lite (CC BY 4.0, https://db-ip.com). 국가 표기는 정치적 입장을 뜻하지 않습니다.";
      return;
    }
    if (built) {
      const d = new Date(built * 1000);
      const days = Math.floor((Date.now() - d.getTime()) / 86400000);
      geoAge.textContent = `IP 데이터 기준일 ${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      if (days > 90) {
        geoAge.className = "warn";
        geoAge.textContent += " — 데이터가 오래되었습니다(앱을 업데이트하세요)";
      }
    } else {
      geoAge.textContent = "IP 국가·ASN 데이터가 설치되어 있지 않습니다. 주소 종류(로컬망 등)만 표시합니다.";
    }
    geoSrc.textContent = built
      ? "IP 국가·ASN 데이터: DB-IP.com (IP to Country Lite, IP to ASN Lite) — CC BY 4.0, https://db-ip.com. 조회는 이 PC 안에서만 합니다. 위치 정보와 조직 정보를 보여 줍니다. 국가 표기는 정치적 입장을 뜻하지 않습니다."
      : "사용할 데이터: DB-IP Lite (CC BY 4.0, https://db-ip.com). 국가 표기는 정치적 입장을 뜻하지 않습니다.";
  })();
  return root;
}
