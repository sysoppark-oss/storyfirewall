// 통신 대상 분포 패널(막대 / 지도) — 연결 이력·지금 열린 연결·대시보드가 함께 쓴다(사용자 요청 2026-11-09).
// 같은 계산(conn-group.bars·offMapLine)과 같은 지도(worldmap)를 쓴다. 막대·나라를 누르면 onPick 으로 알린다(같은 것을 다시 누르면 해제).
import { el, ext, clear, button } from "../ui";
import { bars, offMapLine, type ConnLike } from "./conn-group";
import { worldMap } from "./worldmap";
import { flagPath } from "./connections";

export type DistFilter = { by: "country" | "org"; key: string } | null;
export type DistView = "bars" | "map";

const VIEW_KEY = "sf.dist.view";
function loadView(scope: string, dflt: DistView): DistView {
  try {
    const v = localStorage.getItem(`${VIEW_KEY}.${scope}`);
    return v === "bars" || v === "map" ? v : dflt;
  } catch {
    return dflt;
  }
}
function saveView(scope: string, v: DistView) {
  try {
    localStorage.setItem(`${VIEW_KEY}.${scope}`, v);
  } catch {
    /* 저장 못 해도 동작은 같다 */
  }
}

export interface DistPanel {
  /// 머리(막대/지도 전환)와 본문
  root: HTMLElement;
  /// 다시 그린다. sel 은 지금 거르고 있는 것(강조)
  paint(items: ConnLike[], sel: DistFilter): void;
  view(): DistView;
}

/// scope: 보기 전환 기억 칸(화면마다 따로). unit: 값 단위 글자("연결 수" 등)
export function distPanel(opts: { scope: string; unit?: string; defaultView?: DistView; initial?: DistView; onPick?: (f: DistFilter) => void; compact?: boolean }): DistPanel {
  const unit = opts.unit ?? "연결 수";
  let view: DistView = opts.initial ?? loadView(opts.scope, opts.defaultView ?? "bars");
  let last: { items: ConnLike[]; sel: DistFilter } = { items: [], sel: null };
  const body = el("div", "where-bars");
  const viewBtns = (["bars", "map"] as const).map((v) => {
    const b = button(v === "bars" ? "막대" : "지도", () => {
      view = v;
      saveView(opts.scope, v);
      viewBtns.forEach((x) => {
        x.classList.toggle("on", x === b);
        x.setAttribute("aria-pressed", String(x === b));
      });
      paint(last.items, last.sel);
    }, "btn small seg-btn");
    b.classList.toggle("on", v === view);
    b.setAttribute("aria-pressed", String(v === view));
    return b;
  });
  const root = el("div", `dist-panel${opts.compact ? " compact" : ""}`, el("div", "where-head", el("span", "seg", ...viewBtns)), body);

  const pick = (f: DistFilter) => opts.onPick?.(f);

  const paint = (items: ConnLike[], sel: DistFilter) => {
    last = { items, sel };
    clear(body);
    body.classList.toggle("map-view", view === "map");
    if (view === "map") {
      const { bars: bs } = bars(items, "country", 1000);
      const cur = sel?.by === "country" ? sel.key : null;
      body.append(
        worldMap(bs.map((b) => ({ cc: b.key, label: b.label, value: b.value, isNew: b.isNew })), cur, (cc) => pick(cur === cc ? null : { by: "country", key: cc })),
        el("div", "map-legend muted small", `${unit} `, el("i", "lg lv0"), " 0 ", el("i", "lg lv1"), " 1 ", el("i", "lg lv2"), " 2–5 ", el("i", "lg lv3"), " 6–20 ", el("i", "lg lv4"), " 21+ · ", el("i", "lg new"), " 최초 관측"),
      );
      const off = offMapLine(items);
      if (off) body.append(el("div", "muted small", off));
      return;
    }
    for (const [by, title] of [["country", `국가별 (${unit})`], ["org", `ASN(망 사업자)별 (${unit})`]] as const) {
      const { bars: bs, rest } = bars(items, by, opts.compact ? 6 : 8);
      const col = el("div", "bar-col", el("h4", undefined, title));
      const max = Math.max(1, ...bs.map((b) => b.value));
      for (const b of bs) {
        const on = sel?.by === by && sel.key === b.key;
        // 누를 수 있게 보이면 실제 단추(키보드로도)
        const row = button("", () => pick(on ? null : { by, key: b.key }), `bar-row${b.isNew ? " is-new" : ""}${on ? " on" : ""}`);
        row.setAttribute("aria-pressed", String(on));
        const name = ext("span", b.label, "bar-name");
        name.title = b.label;
        const fp = by === "country" ? flagPath(b.key) : null;
        if (fp) { const im = document.createElement("img"); im.src = fp; im.alt = ""; im.className = "flag"; im.width = 16; im.height = 12; name.prepend(im, " "); }
        const fill = el("span", "bar-fill");
        fill.style.width = `${Math.round((b.value / max) * 100)}%`;
        row.append(name, el("span", "bar-track", fill), el("span", "bar-val", String(b.value)));
        if (b.isNew) row.append(el("span", "badge-new", "최초 관측"));
        col.append(row);
      }
      if (rest) col.append(el("div", "muted small", `그 밖에 ${rest}곳`));
      if (by === "country") {
        const off = offMapLine(items, "막대");
        if (off) col.append(el("div", "muted small", off));
      }
      if (!bs.length) col.append(el("div", "muted small", "공인 주소로의 연결이 없습니다."));
      body.append(col);
    }
  };
  return { root, paint, view: () => view };
}

/// 지금 열린 연결 → 분포 재료(연결 하나 = 1). 같은 프로그램·같은 원격지 여러 소켓은 각각 센다
export function openAsConnLike(xs: { image?: string | null; raddr: string; where?: ConnLike["where"] }[]): ConnLike[] {
  return xs.map((c, i) => ({ image: c.image ?? "", count: 1, sent: 0, recv: 0, remote_id: i, where: c.where ?? null }));
}
