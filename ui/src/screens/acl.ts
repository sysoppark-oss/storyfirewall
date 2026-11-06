// ACL 정책 관리(사용자 요청 2026-11-06): acl.1, acl.2 … 순서대로 판정되는 보안 정책 표.
// 한 규칙 = 인터페이스 · 방향 · 프로토콜 · 출발지(IP·포트) · 목적지(IP·포트) · 허용/차단.
// 표 전체가 서비스의 "ACL" 정책 하나(한 판·한 WFP 트랜잭션)가 된다. 번호가 작을수록 먼저 판정된다.
//
// 출발지·목적지와 이 PC/상대의 관계는 방향이 정한다:
//   나감(out)   출발지 = 이 PC, 목적지 = 상대
//   들어옴(in)  출발지 = 상대,  목적지 = 이 PC
//   양방향(both) 출발지 = 이 PC, 목적지 = 상대 (두 방향 모두 같은 두 끝을 본다)
// 외부 문자열(인터페이스 이름 등)은 텍스트 노드로만 넣는다.
import { rpc } from "../rpc";
import { el, ext, button, clear } from "../ui";

export type AclDir = "out" | "in" | "both";
export type AclProto = "any" | "tcp" | "udp" | "icmp";
export interface AclRule {
  action: "block" | "allow";
  dir: AclDir;
  iface: string;
  proto: AclProto;
  srcIp: string;
  srcPort: string;
  dstIp: string;
  dstPort: string;
}

export const DIR_TEXT: Record<AclDir, string> = { out: "나감", in: "들어옴", both: "양방향" };
export const PROTO_TEXT: Record<AclProto, string> = { any: "TCP·UDP", tcp: "TCP", udp: "UDP", icmp: "ICMP ping(IPv4)" };

/// 쉼표·공백으로 나눈 목록(빈 칸 = 조건 없음)
export function splitList(s: string): string[] {
  return s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
}

/// 방향에 따라 출발지·목적지를 이 PC(local)·상대(remote)로
export function sides(r: AclRule): { localIp: string; localPort: string; remoteIp: string; remotePort: string } {
  return r.dir === "in"
    ? { localIp: r.dstIp, localPort: r.dstPort, remoteIp: r.srcIp, remotePort: r.srcPort }
    : { localIp: r.srcIp, localPort: r.srcPort, remoteIp: r.dstIp, remotePort: r.dstPort };
}

/// 표 → 서비스 정책 YAML. match 는 JSON 꼴(YAML flow mapping)이라 이름·주소에 어떤 글자가 있어도 따옴표로 안전하다
export function aclToYaml(rules: AclRule[]): string {
  return rules
    .map((r, i) => {
      const s = sides(r);
      const m: Record<string, unknown> = { direction: r.dir };
      if (r.iface) m["interface"] = r.iface;
      if (r.proto !== "any") m["protocol"] = r.proto;
      const li = splitList(s.localIp), ri = splitList(s.remoteIp), lp = splitList(s.localPort), rp = splitList(s.remotePort);
      if (li.length) m["local_ip"] = li;
      if (ri.length) m["remote_ip"] = ri;
      if (lp.length) m["local_port"] = lp;
      if (rp.length) m["remote_port"] = rp;
      return `- name: ${JSON.stringify(`acl.${i + 1}`)}\n  priority: ${i + 1}\n  action: ${r.action}\n  match: ${JSON.stringify(m)}\n`;
    })
    .join("");
}

/// 서비스에 걸린 ACL YAML → 표. 이 화면이 만든 꼴만 읽는다. 다른 꼴(고급에서 손으로 쓴 것)이면 null
export function yamlToAcl(yaml: string): AclRule[] | null {
  const blocks = yaml.split(/^- /m).filter((b) => b.trim());
  const out: { n: number; r: AclRule }[] = [];
  for (const b of blocks) {
    const pr = /^\s*priority:\s*(\d+)\s*$/m.exec(b);
    const ac = /^\s*action:\s*(block|allow)\s*$/m.exec(b);
    const mm = /^\s*match:\s*(\{.*\})\s*$/m.exec(b);
    if (!pr || !ac || !mm) return null;
    let m: Record<string, unknown>;
    try {
      m = JSON.parse(mm[1]!) as Record<string, unknown>;
    } catch {
      return null;
    }
    const list = (k: string) => (Array.isArray(m[k]) ? (m[k] as unknown[]).map(String).join(", ") : "");
    const dir = (["out", "in", "both"].includes(String(m["direction"])) ? m["direction"] : "out") as AclDir;
    const proto = (["tcp", "udp", "icmp"].includes(String(m["protocol"])) ? m["protocol"] : "any") as AclProto;
    const li = list("local_ip"), lp = list("local_port"), ri = list("remote_ip"), rp = list("remote_port");
    const r: AclRule =
      dir === "in"
        ? { action: ac[1] as "block" | "allow", dir, iface: typeof m["interface"] === "string" ? m["interface"] : "", proto, srcIp: ri, srcPort: rp, dstIp: li, dstPort: lp }
        : { action: ac[1] as "block" | "allow", dir, iface: typeof m["interface"] === "string" ? m["interface"] : "", proto, srcIp: li, srcPort: lp, dstIp: ri, dstPort: rp };
    out.push({ n: Number(pr[1]), r });
  }
  const rows = out.sort((a, b) => a.n - b.n).map((x) => x.r);
  // 37차 Q5: 표로 다시 만든 원문이 걸린 원문과 글자 그대로 같을 때만 표로 보인다.
  // 손으로 넣은 줄·주석·다른 키(process 등)가 있으면 표가 실제 규칙을 덜 보여 줄 수 있으므로 표로 읽지 않는다
  return aclToYaml(rows).trimEnd() === yaml.replace(/\r\n/g, "\n").trimEnd() ? rows : null;
}

/// 한 줄 요약(표 셀): "192.168.0.10:443" / "10.0.0.1, 10.0.0.2 · 포트 443" / "포트 3389"(주소 모두) / "모두"
export function endText(ip: string, port: string): string {
  const al = splitList(ip);
  const a = al.join(", ");
  const p = splitList(port).join(", ");
  if (a && p) return al.length === 1 && !p.includes(",") ? `${a}:${p}` : `${a} · 포트 ${p}`;
  if (p) return `포트 ${p}`;
  return a || "모두";
}

/// 출발지·목적지 머리글(방향에 따라 이 PC/상대를 밝힌다)
export function endLabels(dir: AclDir): [string, string] {
  return dir === "in" ? ["출발지 (상대)", "목적지 (이 PC)"] : dir === "out" ? ["출발지 (이 PC)", "목적지 (상대)"] : ["이 PC 쪽", "상대 쪽"];
}

const EMPTY: AclRule = { action: "block", dir: "out", iface: "", proto: "any", srcIp: "", srcPort: "", dstIp: "", dstPort: "" };

/// 화살표: 나감 →, 들어옴 ←, 양방향 ↔
export const DIR_ARROW: Record<AclDir, string> = { out: "→", in: "←", both: "↔" };

/// 주소 목록 칸 검사(화면에서 바로 알려 주기 — 최종 검사는 서비스): IPv4·CIDR·범위·IPv6·lan·internet
export function addrListError(s: string, local: boolean): string | null {
  for (const a of splitList(s)) {
    if (a === "lan") continue;
    if (a === "internet") {
      if (local) return "이 PC 쪽에는 internet 을 쓸 수 없습니다";
      continue;
    }
    const v4 = /^(\d{1,3})(\.\d{1,3}){3}(\/\d{1,2})?$/.test(a) && a.split("/")[0]!.split(".").every((x) => Number(x) <= 255) && (!a.includes("/") || Number(a.split("/")[1]) <= 32);
    const v4range = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/.test(a);
    const v6 = /^[0-9a-fA-F:]+(\/\d{1,3})?$/.test(a) && a.includes(":");
    if (!v4 && !v4range && !v6) return `주소 형식이 아닙니다: ${a}`;
  }
  return null;
}
export function portListError(s: string): string | null {
  for (const p of splitList(s)) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(p);
    if (!m || Number(m[1]) > 65535 || (m[2] != null && (Number(m[2]) > 65535 || Number(m[2]) < Number(m[1])))) return `포트는 1~65535 또는 범위(8000-8100): ${p}`;
  }
  return null;
}

/// 규칙 한 줄(편집 창 아래 미리보기). 조사를 붙이지 않는 화살표 꼴(조사 병기 금지 A6):
/// "이 PC → 1.1.1.1 : 443 · TCP · 나가는 통신 차단"
export function ruleSentence(r: AclRule): string {
  const s = sides(r);
  const noPort = r.proto === "icmp";
  const there = endText(s.remoteIp, noPort ? "" : s.remotePort);
  const here = endText(s.localIp, noPort ? "" : s.localPort);
  const herePart = here === "모두" ? "이 PC" : `이 PC ${here}`;
  const therePart = there === "모두" ? "모든 상대" : there;
  const proto = PROTO_TEXT[r.proto];
  const what = r.action === "block" ? "차단" : "허용";
  // 허용은 Story Firewall 차단의 예외일 뿐 — Windows 방화벽을 열지 않는다(검수: 원격 데스크톱 허용을 연다고 오해)
  const via = (r.iface ? ` · ${r.iface}에서만` : "") + (r.action === "allow" ? " (Windows 방화벽 규칙은 그대로)" : "");
  if (r.dir === "out") return `${herePart} → ${therePart} · ${proto} · 나가는 통신 ${what}${via}`;
  if (r.dir === "in") return `${therePart} → ${herePart} · ${proto} · 들어오는 통신 ${what}${via}`;
  return `${herePart} ↔ ${therePart} · ${proto} · 양방향 통신 ${what}${via}`;
}

interface NetIf {
  alias: string;
  description: string;
  up: boolean;
  addrs: string[];
}

/// 여러 선택지 중 하나(분할 단추). 키보드: 좌우 화살표
function segmented<T extends string>(opts: [T, string, string?][], value: T, on: (v: T) => void, label: string): HTMLElement {
  const g = el("div", "seg");
  g.setAttribute("role", "radiogroup");
  g.setAttribute("aria-label", label);
  const btns: HTMLButtonElement[] = [];
  const pick = (v: T, fire = true) => {
    for (const b of btns) {
      const on2 = b.dataset["v"] === v;
      b.setAttribute("aria-checked", String(on2));
      b.classList.toggle("on", on2);
      b.tabIndex = on2 ? 0 : -1;
    }
    if (fire) on(v);
  };
  opts.forEach(([v, t, cls], i) => {
    const b = el("button", `seg-opt${cls ? " " + cls : ""}`, t);
    b.type = "button";
    b.dataset["v"] = v;
    b.setAttribute("role", "radio");
    b.addEventListener("click", () => pick(v));
    b.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (!d) return;
      e.preventDefault();
      const n = opts[(i + d + opts.length) % opts.length]![0];
      pick(n);
      btns.find((x) => x.dataset["v"] === n)?.focus();
    });
    btns.push(b);
    g.append(b);
  });
  pick(value, false);
  return g;
}

/// ACL 표 편집기. onApply(yaml) 는 정책 화면의 적용 흐름(확인·승인 창·60초 유지)을 그대로 쓴다
export function aclEditor(onApply: (yaml: string) => void, onValidate: (yaml: string) => void): { root: HTMLElement; load: (yaml: string | null, active?: string | null) => void; markApplied: (yaml: string) => void; setActive: (yaml: string | null) => void } {
  const root = el("section", "card acl");
  let rules: AclRule[] = [];
  let applied = "";
  let ifaces: NetIf[] = [];
  // 지금 걸린 ACL 이 표로 읽을 수 없는 꼴(고급에서 손으로 쓴 것)인가 — 그러면 표를 적용할 때 그 ACL 을 통째로 바꾼다고 알린다
  let foreign = false;
  // 마지막으로 걸었던(또는 불러온) ACL 원문 — 되돌린 뒤 '다시 적용…'을 가르는 데 쓴다(검수 38-2)
  let lastYaml = "";
  const head = el("div", "acl-head");
  const body = el("div", "acl-body");
  const foot = el("div", "acl-foot");
  root.append(head, body, foot);

  const dirty = () => aclToYaml(rules) !== applied;

  const draw = () => {
    clear(head);
    clear(body);
    clear(foot);
    const title = el("div", "acl-title", el("h2", undefined, "보안 정책 (ACL)"), el("span", "badge count", String(rules.length)));
    head.append(title, button("+ 규칙 추가", () => openDialog(-1)));
    head.append(el("p", "muted small acl-note", "윗줄부터 판정하고 표 전체를 한 번에 적용·되돌립니다. ‘허용’은 이 표에서 그 아래 차단에 대한 예외입니다. 끊기 같은 보안 차단이나 Windows 방화벽이 막은 것은 열지 않습니다."));
    if (foreign) head.append(el("p", "warn acl-foreign", "지금 걸린 ACL 은 표로 보여 줄 수 없는 꼴(아래 ‘고급’에서 직접 쓴 것)이라 이 표에 나오지 않습니다. 이 표를 적용하면 그 ACL 을 통째로 바꿉니다. 원문은 ‘고급’에서 보세요."));
    if (!rules.length) {
      body.append(
        el(
          "div",
          "acl-empty",
          el("p", undefined, "아직 규칙이 없습니다."),
          el("p", "muted small", "예: “이 PC → 1.1.1.1:443 TCP 차단”, “상대 203.0.113.0/24 → 이 PC 원격 데스크톱(3389) 차단”"),
          button("첫 규칙 만들기", () => openDialog(-1), "btn primary"),
        ),
      );
    } else {
      const t = el("table", "acl-grid");
      const hr = el("tr");
      for (const h of ["#", "동작", "출발지", "방향", "목적지", "프로토콜", "인터페이스", ""]) hr.append(el("th", undefined, h));
      t.append(el("thead", undefined, hr));
      const tb = el("tbody");
      rules.forEach((r, i) => {
        const tr = el("tr");
        tr.addEventListener("dblclick", () => openDialog(i));
        const [sl, dl] = endLabels(r.dir);
        const end = (ip: string, port: string, label: string) => {
          const td = el("td", "acl-end");
          td.append(el("span", "acl-end-role", label), el("span", "acl-end-addr", endText(ip, r.proto === "icmp" ? "" : port)));
          return td;
        };
        tr.append(
          el("td", "acl-no", String(i + 1)),
          el("td", undefined, el("span", `acl-act ${r.action}`, r.action === "block" ? "차단" : "허용")),
          end(r.srcIp, r.srcPort, sl),
          el("td", "acl-arrow", el("span", undefined, DIR_ARROW[r.dir]), el("span", "muted small", DIR_TEXT[r.dir])),
          end(r.dstIp, r.dstPort, dl),
          el("td", undefined, PROTO_TEXT[r.proto]),
          ext("td", r.iface || "모두"),
        );
        const ops = el("td", "acl-ops");
        const icon = (t: string, tip: string, fn: () => void, dis = false, cls = "") => {
          const b = button(t, fn, `btn icon${cls}`);
          b.title = tip;
          b.setAttribute("aria-label", tip);
          b.disabled = dis;
          return b;
        };
        ops.append(
          icon("↑", "위로(먼저 판정)", () => { [rules[i - 1], rules[i]] = [rules[i]!, rules[i - 1]!]; draw(); }, i === 0),
          icon("↓", "아래로", () => { [rules[i + 1], rules[i]] = [rules[i]!, rules[i + 1]!]; draw(); }, i === rules.length - 1),
          button("수정", () => openDialog(i), "btn small"),
          button("삭제", () => { rules.splice(i, 1); draw(); }, "btn small danger-outline"),
        );
        tr.append(ops);
        tb.append(tr);
      });
      t.append(tb);
      body.append(el("div", "acl-scroll", t));
    }
    // 아래 줄: 상태(적용 안 된 변경) · 보조(검증) → 주(적용)
    // 2026-11-06 노트북 제보: 자동 되돌림 뒤에도 '같습니다'로 보이고 적용 단추가 꺼져 다시 걸 수 없었다 → 기준은 '지금 걸린' ACL
    // 검수 38-2: 상태 말을 하나로 — 걸림과 같음 / 걸린 것과 다름 / 되돌려서 안 걸림 / 아직 안 걸어 봄
    const now = aclToYaml(rules);
    const rolledBack = !applied && !!lastYaml && now === lastYaml;
    const state = !dirty()
      ? el("span", "muted small", applied ? "지금 걸린 ACL과 같습니다" : "")
      : applied
        ? el("span", "acl-dirty", "● 적용하지 않은 변경이 있습니다")
        : rolledBack
          ? el("span", "acl-dirty", "● 되돌림 — 이 표는 지금 걸려 있지 않습니다")
          : el("span", "acl-dirty", "● 아직 적용하지 않았습니다 — 이 표는 지금 걸려 있지 않습니다");
    const applyBtn = button(!dirty() ? "적용…" : applied ? "변경 적용…" : rolledBack ? "다시 적용…" : "적용…", () => onApply(now), "btn primary");
    applyBtn.disabled = !rules.length || !dirty();
    foot.append(state, el("span", "spacer"), button("검증", () => onValidate(aclToYaml(rules))), applyBtn);
  };

  const openDialog = (idx: number) => {
    const r: AclRule = { ...(idx >= 0 ? rules[idx]! : EMPTY) };
    const dlg = el("dialog", "acl-dialog");
    const n = idx >= 0 ? idx + 1 : rules.length + 1;
    dlg.append(el("div", "acl-dlg-head", el("h3", undefined, idx >= 0 ? `규칙 ${n} 수정` : `새 규칙 (${n}번째 줄)`), el("p", "muted small", "빈 칸은 ‘모두’입니다. 여러 값은 쉼표로 나눕니다.")));
    const preview = el("p", "acl-preview");
    const errs = new Map<string, string>();
    const save = button(idx >= 0 ? "저장" : "표에 추가", () => {
      if (r.proto === "icmp") { r.srcPort = ""; r.dstPort = ""; }
      if (idx >= 0) rules[idx] = r;
      else rules.push(r);
      dlg.close();
      draw();
    }, "btn primary");
    const refresh = () => {
      const bad = errs.size > 0;
      // 잘못된 입력이면 규칙 문장을 보이지 않는다(검수: 1.1.1.999 를 정상 규칙처럼 보여 줌)
      // 검수 38-10: 오류는 칸 아래 한 곳에서만 — 미리보기는 회색 안내만
      preview.textContent = bad ? "입력을 고치면 규칙 문장이 여기에 나옵니다" : ruleSentence(r);
      preview.className = `acl-preview ${bad ? "invalid" : r.action}`;
      save.disabled = bad;
    };
    const row = (label: string, ctl: HTMLElement, hint?: string) => {
      const d = el("div", "acl-row", el("div", "acl-row-label", label), el("div", "acl-row-ctl", ctl));
      if (hint) d.querySelector(".acl-row-ctl")!.append(el("div", "muted small", hint));
      return d;
    };
    const field = (key: string, value: string, ph: string, check: (v: string) => string | null, on: (v: string) => void) => {
      const wrap = el("div", "acl-input");
      const i = el("input");
      i.value = value;
      i.placeholder = ph;
      i.spellcheck = false;
      i.autocomplete = "off";
      const msg = el("div", "acl-err");
      const run = () => {
        const e = check(i.value);
        msg.textContent = e ?? "";
        i.classList.toggle("invalid", !!e);
        i.setAttribute("aria-invalid", String(!!e));
        if (e) errs.set(key, e); else errs.delete(key);
        on(i.value);
        refresh();
      };
      i.addEventListener("input", run);
      wrap.append(i, msg);
      queueMicrotask(run);
      return { wrap, input: i };
    };
    // 동작
    const act = segmented<"block" | "allow">([["block", "차단", "bad"], ["allow", "허용", "ok"]], r.action, (v) => { r.action = v; refresh(); }, "동작");
    // 방향
    const srcTitle = el("span"), dstTitle = el("span");
    let relabel = () => { const [a, b] = endLabels(r.dir); srcTitle.textContent = a; dstTitle.textContent = b; };
    const dir = segmented<AclDir>([["out", "나감  이 PC → 상대"], ["in", "들어옴  상대 → 이 PC"], ["both", "양방향"]], r.dir, (v) => {
      r.dir = v;
      relabel();
      // 방향을 바꾸면 이 PC/상대 칸이 서로 바뀌므로 주소 검사를 다시 한다
      srcIp.input.dispatchEvent(new Event("input"));
      dstIp.input.dispatchEvent(new Event("input"));
      refresh();
    }, "방향");
    // 프로토콜
    const portNote = el("div", "muted small");
    const proto = segmented<AclProto>([["any", "TCP·UDP"], ["tcp", "TCP"], ["udp", "UDP"], ["icmp", "ICMP"]], r.proto, (v) => {
      r.proto = v;
      const icmp = v === "icmp";
      for (const f of [srcPort, dstPort]) {
        if (!f) continue;
        f.input.disabled = icmp;
        if (icmp) { f.input.value = ""; f.input.dispatchEvent(new Event("input")); }
      }
      // 38차 Q1①②: echo 만 다루고, 패킷마다 판정이라 들어옴 차단은 내 ping 의 응답도 막는다
      portNote.textContent = icmp ? "ICMP 는 IPv4 ping(echo 요청·응답)만 다룹니다. 오류 메시지(경로 MTU 등)와 IPv6 ICMP 는 막지 않습니다. ‘들어옴’ 차단이면 내가 보낸 ping 의 응답도 막힙니다. 포트는 없습니다." : "";
      refresh();
    }, "프로토콜");
    // 출발지·목적지 카드
    const localIsSrc = () => r.dir !== "in";
    const srcIp = field("srcIp", r.srcIp, "모두  예: 192.168.0.10, 10.0.0.0/8, lan", (v) => addrListError(v, localIsSrc()), (v) => (r.srcIp = v));
    const srcPort = field("srcPort", r.srcPort, "모두  예: 443, 8000-8100", portListError, (v) => (r.srcPort = v));
    const dstIp = field("dstIp", r.dstIp, "모두  예: 203.0.113.9, internet", (v) => addrListError(v, !localIsSrc()), (v) => (r.dstIp = v));
    const dstPort = field("dstPort", r.dstPort, "모두", portListError, (v) => (r.dstPort = v));
    const card = (title: HTMLElement, ip: { wrap: HTMLElement }, port: { wrap: HTMLElement }) =>
      el("fieldset", "acl-end-card", el("legend", undefined, title), el("label", "acl-sub", "IP 주소"), ip.wrap, el("label", "acl-sub", "포트"), port.wrap);
    // 이 PC 쪽·상대 쪽 예시는 방향에 따라 바뀐다(이 PC 쪽에 internet 은 쓸 수 없다). 짧게 — 칸에서 잘리지 않게
    const LOCAL_PH = "모두 (예: 192.168.0.10)";
    const REMOTE_PH = "모두 (예: 203.0.113.9, 10.0.0.0/8)";
    const relabelPh = () => {
      const srcLocal = localIsSrc();
      srcIp.input.placeholder = srcLocal ? LOCAL_PH : REMOTE_PH;
      dstIp.input.placeholder = srcLocal ? REMOTE_PH : LOCAL_PH;
      // 포트: 접속하는 쪽(출발지)의 포트는 보통 임의 번호라 비워 둔다. 받는 쪽(목적지)은 서비스 포트
      srcPort.input.placeholder = "모두 (보통 비워 둠)";
      dstPort.input.placeholder = r.dir === "in" ? "모두 (예: 3389)" : "모두 (예: 443)";
    };
    const relabel0 = relabel;
    relabel = () => { relabel0(); relabelPh(); };
    relabel();
    // 인터페이스
    const ifSel = el("select");
    const opt = (v: string, t: string) => { const o = el("option", undefined, t); o.value = v; if (v === r.iface) o.selected = true; ifSel.append(o); };
    opt("", "모든 인터페이스");
    for (const f of ifaces) opt(f.alias, `${f.alias}${f.up ? "" : " (연결 안 됨)"}${f.addrs.some((a) => a.includes(".")) ? " · " + f.addrs.filter((a) => a.includes(".")).map((a) => a.split("/")[0]).join(", ") : ""}`);
    if (r.iface && !ifaces.some((f) => f.alias === r.iface)) opt(r.iface, `${r.iface} (지금 없음)`);
    ifSel.addEventListener("change", () => { r.iface = ifSel.value; refresh(); });

    dlg.append(
      el(
        "div",
        "acl-dlg-body",
        row("동작", act),
        row("방향", dir),
        row("프로토콜", proto, undefined),
        portNote,
        el("div", "acl-ends", card(srcTitle, srcIp, srcPort), el("div", "acl-ends-arrow", "→"), card(dstTitle, dstIp, dstPort)),
        row("인터페이스", ifSel, "특정 네트워크(예: Wi-Fi)에서만 적용하려면 고르세요."),
      ),
      el("div", "acl-dlg-preview", el("div", "muted small", "이 규칙은"), preview),
      el("div", "actions", button("취소", () => dlg.close()), el("span", "spacer"), save),
    );
    proto.querySelector<HTMLButtonElement>(".seg-opt.on")?.click();
    document.body.append(dlg);
    dlg.addEventListener("close", () => dlg.remove());
    dlg.showModal();
    refresh();
  };

  const load = (yaml: string | null, active: string | null = yaml) => {
    if (yaml) {
      const back = yamlToAcl(yaml);
      if (back) {
        rules = back;
        applied = active ? aclToYaml(back) : "";
        lastYaml = aclToYaml(back);
      } else {
        // 37차 Q5 검토 중 발견: 이 안내를 body 에 붙였더니 바로 아래 draw() 가 지워 보이지 않았다
        foreign = true;
      }
    }
    draw();
  };
  void rpc<{ items: NetIf[] }>("net.interfaces", {}).then((r) => {
    if (r.ok) ifaces = r.result.items;
  });
  // 적용이 받아들여지면 "적용하지 않은 변경" 표시를 지운다(검수 B3: 적용 직후에도 변경 있음으로 보였다)
  const markApplied = (yaml: string) => {
    applied = yaml;
    lastYaml = yaml;
    foreign = false;
    draw();
  };
  // 목록을 새로 받을 때마다: 지금 걸린 ACL(없으면 null) 기준으로 '적용 안 된 변경'을 다시 판단한다
  const setActive = (yaml: string | null) => {
    const back = yaml ? yamlToAcl(yaml) : null;
    const next = back ? aclToYaml(back) : "";
    if (next) lastYaml = next;
    else if (applied) lastYaml = applied;
    if (next !== applied) {
      applied = next;
      draw();
    }
  };
  return { root, load, markApplied, setActive };
}
