import { ACT } from "../terms";
import { rpc } from "../rpc";
import { el, ext, clear, button, fmtShortSec, fmtHms, filetimeToUnix } from "../ui";
import { fileName } from "../sanitize";
import { failBox, loadingBox } from "../list-state";
import { whereCell, type Where } from "./connections";
import { levelChip } from "./story";
import { state } from "../state";

interface Related {
  node_id: number;
  kind: string;
  label: string;
  key: string;
  rel: string;
  edge_id: number;
  ts: number;
  where?: Where | null;
}
interface Detail {
  pid: number;
  create_ft: number;
  image: string;
  ended: boolean;
  core?: boolean;
  story?: { score: number; level: string; root: number } | null;
  signature: { signer?: string | null; sig_status?: string | null; issuer?: string | null } | null;
  origin: { host_url?: string | null; referrer_url?: string | null } | null;
  parents: Related[];
  children: Related[];
  connections: Related[];
  files_written: Related[];
  autoruns: Related[];
  injected: Related[];
  inbound?: Related[];
  rewind: { depth: number; node: { id: number; kind: string; label: string }; via: { rel: string; src: number; dst: number } | null }[];
}

/// 서명 상태 → 사람 말 (D025-A2)
/// D035-4: 스토어 앱 패키지 폴더 — 파일이 아니라 패키지로 서명되어 파일 서명 확인 결과가 "없음"으로 나온다
export function isPackagePath(path?: string | null): boolean {
  // 28차 Q1: 시스템 드라이브(C:) 바로 아래만 — 이동식 매체·ISO 의 같은 이름 폴더, 경로 중간의 같은 이름 폴더는 아님(판정과 같은 기준)
  return !!path && /^(\\\\\?\\)?c:\\program files\\windowsapps\\/i.test(path.replace(/\//g, "\\"));
}

/// unknown = 확인하지 못함(회색) — "없음"처럼 경고하지 않는다
export function sigText(s: Detail["signature"], path?: string | null): { text: string; ok: boolean; unknown?: boolean } {
  const st = s?.sig_status ?? "";
  if (!s || !st) return { text: "확인 전", ok: false };
  if (st === "valid") return { text: s.signer ?? "서명 유효", ok: true };
  if (st === "nosignature" && isPackagePath(path)) return { text: "확인 못 함(패키지 앱 서명 확인 미지원)", ok: false, unknown: true };
  if (st === "nosignature") return { text: "없음", ok: false };
  if (st.startsWith("untrusted:bad_digest")) return { text: "파일 내용과 서명이 맞지 않음", ok: false };
  if (st.startsWith("untrusted")) return { text: "있지만 신뢰하는 인증 기관이 아님", ok: false };
  return { text: `확인 실패 (${st})`, ok: false };
}

/// 위치 종류 (D025-A1)
export function placeKind(path: string): string {
  const p = path.toLowerCase().replace(/\//g, "\\");
  if (/^[a-z]:\\windows\\/.test(p)) return "Windows 폴더";
  if (/^[a-z]:\\program files( \(x86\))?\\/.test(p)) return "Program Files";
  if (/\\users\\[^\\]+\\(appdata|downloads|desktop|documents)\\/.test(p) || /\\temp\\/.test(p) || /^[a-z]:\\users\\public\\/.test(p)) return "사용자 쓰기 가능 경로";
  return "그 밖의 폴더";
}

/// 주소·경로 글자 + "복사". 링크로 만들지 않는다(악성 주소를 실수로 여는 일 방지, D025-A2)
function copyable(text: string, cls = "mono"): HTMLElement {
  const box = el("span", "copyable", ext("span", text, cls));
  const b = button("복사", () => { void navigator.clipboard?.writeText(text).catch(() => {}); }, "btn link small");
  box.append(" ", b);
  return box;
}

type Step = Detail["rewind"][number];
/// D025-A3: 되감기(그물)에서 한 줄 사슬을 고른다 — 자신은 실행 파일(executed_as) 먼저, 파일은 만든 프로그램(wrote) 다음 받은 곳(downloaded),
/// 그 밖의 프로세스는 실행한 부모(spawned). 오래된 쪽이 앞(왼쪽). 최대 8단계
export function mainPath(selfId: number, rewind: Step[]): Step[] {
  const out: Step[] = [];
  const seen = new Set<number>([selfId]);
  let cur = selfId;
  let kind = "self";
  for (let i = 0; i < 8; i++) {
    const cands = rewind.filter((s) => s.via && s.via.dst === cur && !seen.has(s.node.id));
    // 자신: 실행 파일의 출신(만든 프로그램·받은 곳)이 기록돼 있으면 그쪽, 아니면 실행한 부모(svchost 처럼 파일 출신이 없는 경우)
    const fileHasOrigin = (fid: number) => rewind.some((s) => s.via && s.via.dst === fid && (s.via.rel === "wrote" || s.via.rel === "downloaded"));
    const selfFirst = cands.some((s) => s.via!.rel === "executed_as" && fileHasOrigin(s.node.id)) ? ["executed_as", "spawned", "injected"] : ["spawned", "executed_as", "injected"];
    const pref = kind === "self" ? selfFirst : kind === "file" ? ["wrote", "downloaded"] : ["spawned", "injected"];
    const pick = pref.map((r) => cands.find((s) => s.via!.rel === r)).find((x) => !!x);
    if (!pick) break;
    out.unshift(pick);
    seen.add(pick.node.id);
    cur = pick.node.id;
    kind = pick.node.kind;
  }
  return out;
}

/// 기록된 뿌리로 보는 시작 프로세스(이것에서 사슬이 끝나면 "기록 없음" 칩을 달지 않는다)
const ROOT_PROCS = new Set(["explorer.exe", "services.exe", "wininit.exe", "winlogon.exe", "smss.exe", "system", "userinit.exe"]);

const REL_KO: Record<string, string> = { spawned: "실행", downloaded: "받음", wrote: "만듦", executed_as: "실행", injected: "주입" };

/// 프로그램 상세 (D025-A). 열리는 곳: 이야기 카드·마인드맵 노드·연결 표 프로그램 칸
export function processPanel(nodeId: number): HTMLElement {
  const root = el("div", "card process detail");
  root.append(loadingBox());
  const load = async () => {
    const r = await rpc<Detail>("process.detail", { node_id: nodeId, max_depth: 8 });
    clear(root);
    if (!r.ok) return root.append(failBox(r.error, () => void load(), "프로세스 정보"));
    const d = r.result;
    // 1. 머리
    const head = el("div", "pd-head");
    const title = el("div", "pd-title", ext("span", fileName(d.image), "pd-name"), el("span", "chip-n", `PID ${d.pid}`), el("span", "chip-n", d.ended ? "끝남" : "실행 중"));
    if (d.story) title.append(levelChip(d.story.level));
    const acts = el("div", "pd-acts");
    if (d.story) {
      const sr = d.story.root;
      acts.append(button("인시던트 보기", () => state.go("story", { root: sr })));
      // D027-3: 판정이 있을 때만 조치 — 이야기 카드와 같은 규칙·같은 대화상자(그 카드로 가서 연다). 승인 창 경유 그대로
      acts.append(d.core
        ? button(ACT.cutAddrOnly, () => state.go("story", { root: sr, cut: true }), "btn danger-outline")
        : button(ACT.cut, () => state.go("story", { root: sr, cut: true }), "btn danger-outline"));
    }
    head.append(title, acts);
    root.append(head);
    root.append(el("div", "pd-path", copyable(d.image)));
    root.append(el("div", "muted small", `시작 ${fmtShortSec(filetimeToUnix(d.create_ft))} · ${placeKind(d.image)}`));
    if (d.core) root.append(el("p", "muted small", "Windows 핵심 프로세스라 끝내지 않습니다. 의심 주소만 막을 수 있습니다."));
    // 2. 서명 / 출신 두 칸
    const sig = sigText(d.signature, d.image);
    const sigBox = el("div", "pd-box", el("div", "muted small", "서명"), el("div", sig.ok ? "name-wrap" : sig.unknown ? "muted name-wrap" : "warn name-wrap", ext("span", sig.text)));
    // D028-2: 서명자·발급자·조직명은 낱말 단위로 줄바꿈(숫자 중간에서 끊지 않는다). 경로·주소만 아무 데서나
    if (d.signature?.issuer) sigBox.append(el("div", "muted small", "발급자"), ext("div", d.signature.issuer, "name-wrap"));
    const orgBox = el("div", "pd-box", el("div", "muted small", "출처(MOTW)"));
    if (d.origin?.host_url || d.origin?.referrer_url) {
      orgBox.append(el("div", "warn", "인터넷 출처(MOTW Zone 3·4)"));
      if (d.origin.host_url) orgBox.append(el("div", "muted small", "다운로드 URL"), el("div", undefined, copyable(d.origin.host_url)));
      if (d.origin.referrer_url) orgBox.append(el("div", "muted small", "참조 URL(Referrer)"), el("div", undefined, copyable(d.origin.referrer_url)));
    } else {
      orgBox.append(el("div", undefined, "MOTW 없음(인터넷 출처 여부 불명)"));
    }
    root.append(el("div", "pd-two", sigBox, orgBox));
    // 3. 어디서 왔나: 오래된 쪽 → 자신
    const steps = mainPath(nodeId, d.rewind);
    const chain = el("div", "chain");
    // D027-4: 왼쪽 끝이 기록된 뿌리(explorer 등 셸·시스템 시작 프로세스)가 아니면 회색 칩 "… 기록 없음(수집 시작 전)"
    const first = steps[0];
    const realStart = !!first && first.node.kind === "process" && ROOT_PROCS.has((first.node.label || "").toLowerCase());
    if (!realStart) chain.append(el("span", "chip none", "… 기록 없음(수집 시작 전)"), el("span", "muted", " → "));
    for (const s of steps) {
      const lb = s.node.label || "미확인 프로세스";
      chain.append(ext("span", s.node.kind === "file" ? `파일 ${lb}` : lb, s.node.kind === "process" ? "chip process" : "chip file"));
      chain.append(el("span", "muted", ` → ${REL_KO[s.via?.rel ?? ""] ?? s.via?.rel ?? ""} `));
    }
    chain.append(ext("span", fileName(d.image), "chip process center"));
    root.append(el("h4", undefined, "출처(Provenance)"), chain);
    // 4. 한 일 = 탭
    const tabs: [string, Related[], boolean][] = [
      ["네트워크 연결", d.connections, true],
      ["자식 프로세스", d.children, false],
      ["생성 파일", d.files_written, false],
      ["지속성 등록", d.autoruns, false],
      ["코드 주입", d.injected, false],
      ["인바운드 연결", d.inbound ?? [], true],
    ];
    const bar = el("div", "seg pd-tabs");
    const body = el("div", "pd-tab-body");
    let cur = tabs.findIndex((t) => t[1].length > 0);
    if (cur < 0) cur = 0;
    const paint = () => {
      clear(bar);
      tabs.forEach(([name, xs], i) => {
        const b = button(`${name} ${xs.length}`, () => { cur = i; paint(); }, `btn small seg-btn${i === cur ? " on" : ""}${xs.length ? "" : " dim"}`);
        bar.append(b);
      });
      clear(body);
      const [, xs, isNet] = tabs[cur]!;
      if (!xs.length) return body.append(el("p", "muted", "없음"));
      const sorted = [...xs].sort((a, b) => a.ts - b.ts);
      let shown = 50;
      const table = el("table", "grid pd-table");
      const draw = () => {
        clear(table);
        table.append(el("tr", undefined, el("th", undefined, "시각"), el("th", undefined, isNet ? "원격지" : "대상"), ...(isNet ? [el("th", undefined, "어디")] : [])));
        for (const x of sorted.slice(0, shown)) {
          const tr = el("tr", undefined, el("td", "muted", fmtHms(filetimeToUnix(x.ts))), el("td", undefined, ext("span", x.label || x.key)));
          if (isNet) tr.append(whereCell(x.where ?? null));
          table.append(tr);
        }
        if (sorted.length > shown) {
          const more = el("tr", undefined, el("td", undefined, button(`더 보기 (${sorted.length - shown})`, () => { shown += 50; draw(); }, "btn small")));
          table.append(more);
        }
      };
      draw();
      body.append(table);
    };
    paint();
    root.append(el("h4", undefined, "행위"), bar, body);
  };
  void load();
  return root;
}

/// 오른쪽 패널(640px, 창이 1100px 미만이면 화면 전체)로 연다. Esc 로 닫는다(D025-A5)
export function openProcessDrawer(nodeId: number, note?: string): void {
  document.querySelector(".pd-drawer")?.remove();
  const drawer = el("aside", "pd-drawer");
  const close = () => { drawer.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  drawer.append(el("div", "pd-drawer-bar", note ? el("span", "muted small pd-note", note) : "", button("닫기 (Esc)", close, "btn small")), processPanel(nodeId));
  document.body.append(drawer);
}
