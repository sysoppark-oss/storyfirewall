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
export const PROTO_TEXT: Record<AclProto, string> = { any: "TCP·UDP", tcp: "TCP", udp: "UDP", icmp: "ICMP(IPv4)" };

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
  return out.sort((a, b) => a.n - b.n).map((x) => x.r);
}

/// 한 줄 요약(표 셀): "192.168.0.10:443" / "모두"
export function endText(ip: string, port: string): string {
  const a = splitList(ip).join(", ") || "모두";
  const p = splitList(port).join(", ");
  return p ? `${a} : ${p}` : a;
}

/// 출발지·목적지 머리글(방향에 따라 이 PC/상대를 밝힌다)
export function endLabels(dir: AclDir): [string, string] {
  return dir === "in" ? ["출발지 (상대)", "목적지 (이 PC)"] : dir === "out" ? ["출발지 (이 PC)", "목적지 (상대)"] : ["이 PC 쪽", "상대 쪽"];
}

const EMPTY: AclRule = { action: "block", dir: "out", iface: "", proto: "any", srcIp: "", srcPort: "", dstIp: "", dstPort: "" };

interface NetIf {
  alias: string;
  description: string;
  up: boolean;
  addrs: string[];
}

/// ACL 표 편집기. onApply(yaml) 는 정책 화면의 적용 흐름(확인·승인 창·60초 유지)을 그대로 쓴다
export function aclEditor(onApply: (yaml: string) => void, onValidate: (yaml: string) => void): { root: HTMLElement; load: (yaml: string | null) => void } {
  const root = el("div", "card acl");
  let rules: AclRule[] = [];
  let ifaces: NetIf[] = [];
  const table = el("div", "acl-table");
  const form = el("div", "acl-form");
  const note = el("p", "muted small", "번호가 작은 규칙부터 판정합니다(위 규칙이 먼저). 표 전체가 정책 'ACL' 하나로 한 번에 적용·되돌림됩니다. 허용은 이 표와 다른 Story Firewall 차단 사이의 예외일 뿐, Windows 방화벽이 막은 것을 열지는 못합니다.");
  root.append(el("h2", undefined, "보안 정책 (ACL)"), note, table, form);

  const draw = () => {
    clear(table);
    if (!rules.length) {
      table.append(el("p", "muted", "아직 규칙이 없습니다. 아래 '규칙 추가'로 acl.1 부터 만듭니다."));
    } else {
      const t = el("table", "grid acl-grid");
      const hr = el("tr");
      for (const h of ["번호", "인터페이스", "방향", "프로토콜", "출발지", "목적지", "동작", ""]) hr.append(el("th", undefined, h));
      t.append(el("thead", undefined, hr));
      const tb = el("tbody");
      rules.forEach((r, i) => {
        const tr = el("tr");
        const [sl, dl] = endLabels(r.dir);
        const src = el("td", "path", endText(r.srcIp, r.srcPort));
        src.title = sl;
        const dst = el("td", "path", endText(r.dstIp, r.dstPort));
        dst.title = dl;
        tr.append(
          el("td", undefined, `acl.${i + 1}`),
          ext("td", r.iface || "모두"),
          el("td", undefined, DIR_TEXT[r.dir]),
          el("td", undefined, PROTO_TEXT[r.proto]),
          src,
          dst,
          el("td", undefined, el("span", `chip ${r.action === "block" ? "bad" : "ok"}`, r.action === "block" ? "차단" : "허용")),
        );
        const ops = el("td", "acl-ops");
        const up = button("▲", () => { if (i > 0) { [rules[i - 1], rules[i]] = [rules[i]!, rules[i - 1]!]; draw(); } }, "btn small");
        up.title = "위로(먼저 판정)";
        up.disabled = i === 0;
        const dn = button("▼", () => { if (i < rules.length - 1) { [rules[i + 1], rules[i]] = [rules[i]!, rules[i + 1]!]; draw(); } }, "btn small");
        dn.title = "아래로";
        dn.disabled = i === rules.length - 1;
        ops.append(up, dn, button("수정", () => openForm(i), "btn small"), button("삭제", () => { rules.splice(i, 1); draw(); }, "btn small danger-outline"));
        tr.append(ops);
        tb.append(tr);
      });
      t.append(tb);
      table.append(t);
    }
    // 단추 줄: 보조(추가·검증) → 주(적용)
    table.append(
      el(
        "div",
        "actions",
        button("규칙 추가", () => openForm(-1)),
        button("검증", () => onValidate(aclToYaml(rules))),
        el("span", "spacer"),
        Object.assign(button("ACL 적용…", () => onApply(aclToYaml(rules)), "btn primary"), { disabled: !rules.length }),
      ),
    );
  };

  const openForm = (idx: number) => {
    clear(form);
    const r: AclRule = { ...(idx >= 0 ? rules[idx]! : EMPTY) };
    const sel = (opts: [string, string][], value: string, on: (v: string) => void) => {
      const s = el("select");
      for (const [v, t] of opts) {
        const o = el("option", undefined, t);
        o.value = v;
        if (v === value) o.selected = true;
        s.append(o);
      }
      s.addEventListener("change", () => on(s.value));
      return s;
    };
    const input = (value: string, ph: string, on: (v: string) => void) => {
      const i = el("input");
      i.value = value;
      i.placeholder = ph;
      i.spellcheck = false;
      i.addEventListener("input", () => on(i.value));
      return i;
    };
    const ifaceOpts: [string, string][] = [["", "모든 인터페이스"], ...ifaces.map((f): [string, string] => [f.alias, `${f.alias}${f.up ? "" : " (꺼짐)"} — ${f.addrs.filter((a) => a.includes(".")).join(", ") || f.description}`])];
    if (r.iface && !ifaces.some((f) => f.alias === r.iface)) ifaceOpts.push([r.iface, `${r.iface} (지금 없음)`]);
    const srcL = el("span"), dstL = el("span");
    const relabel = () => { const [a, b] = endLabels(r.dir); srcL.textContent = a; dstL.textContent = b; };
    relabel();
    const portNote = el("span", "muted small");
    const field = (label: Node | string, ...c: Node[]) => el("label", "acl-field", el("span", "acl-label", label), ...c);
    const srcIp = input(r.srcIp, "모두 (예: 192.168.0.10, 10.0.0.0/8, lan)", (v) => (r.srcIp = v));
    const srcPort = input(r.srcPort, "모두 (예: 443, 8000-8100)", (v) => (r.srcPort = v));
    const dstIp = input(r.dstIp, "모두 (예: 203.0.113.9, internet)", (v) => (r.dstIp = v));
    const dstPort = input(r.dstPort, "모두", (v) => (r.dstPort = v));
    const protoSel = sel(Object.entries(PROTO_TEXT) as [string, string][], r.proto, (v) => { r.proto = v as AclProto; ports(); });
    const ports = () => {
      const icmp = r.proto === "icmp";
      srcPort.disabled = dstPort.disabled = icmp;
      portNote.textContent = icmp ? "ICMP 에는 포트가 없습니다. IPv6 의 ICMP 는 이웃 탐색에 필요해 막지 않습니다." : "";
    };
    ports();
    form.append(
      el("h3", undefined, idx >= 0 ? `acl.${idx + 1} 수정` : `acl.${rules.length + 1} 추가`),
      field("인터페이스", sel(ifaceOpts, r.iface, (v) => (r.iface = v))),
      field("방향", sel([["out", "나감 (이 PC → 상대)"], ["in", "들어옴 (상대 → 이 PC)"], ["both", "양방향"]], r.dir, (v) => { r.dir = v as AclDir; relabel(); })),
      field("프로토콜", protoSel, portNote),
      el("div", "acl-pair", field(srcL, srcIp), field("포트", srcPort)),
      el("div", "acl-pair", field(dstL, dstIp), field("포트", dstPort)),
      field("동작", sel([["block", "차단"], ["allow", "허용"]], r.action, (v) => (r.action = v as "block" | "allow"))),
      el(
        "div",
        "actions",
        button("취소", () => clear(form)),
        button(idx >= 0 ? "고치기" : "표에 넣기", () => {
          if (r.proto === "icmp") { r.srcPort = ""; r.dstPort = ""; }
          if (idx >= 0) rules[idx] = r;
          else rules.push(r);
          clear(form);
          draw();
        }, "btn primary"),
      ),
      el("p", "muted small", "빈 칸은 '모두'입니다. 여러 값은 쉼표로. 표에 넣은 뒤 'ACL 적용…'을 눌러야 실제로 걸립니다."),
    );
  };

  const load = (yaml: string | null) => {
    if (yaml) {
      const back = yamlToAcl(yaml);
      if (back) rules = back;
      else table.append(el("p", "warn", "지금 걸린 ACL 을 표로 읽지 못했습니다(고급 편집에서 손으로 쓴 꼴). 아래 '고급'에서 원문을 보세요."));
    }
    draw();
  };
  void rpc<{ items: NetIf[] }>("net.interfaces", {}).then((r) => {
    if (r.ok) ifaces = r.result.items;
  });
  return { root, load };
}
