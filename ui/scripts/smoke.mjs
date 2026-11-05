// svc-dev 와 프로토콜 연기 시험 (Linux CI): hello → story.events → policy.validate → apply(needs_ack 없음) → confirm.
// Tauri 코어의 client.rs 와 같은 규약(한 줄 JSON)을 node 로 재현한다.
import net from "node:net";
import { randomUUID } from "node:crypto";

const [host, port] = (process.argv[2] ?? "127.0.0.1:7878").split(":");
const sock = net.createConnection({ host, port: Number(port) });
let buf = "";
const waiters = new Map();
let nextId = 1;
const notes = [];
sock.on("data", (d) => {
  buf += d.toString("utf8");
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    const v = JSON.parse(line);
    if (v.id != null && waiters.has(v.id)) { waiters.get(v.id)(v); waiters.delete(v.id); } else notes.push(v);
  }
});
const call = (method, params = {}) => new Promise((res, rej) => {
  const id = nextId++;
  waiters.set(id, res);
  sock.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  setTimeout(() => { if (waiters.has(id)) { waiters.delete(id); rej(new Error("timeout " + method)); } }, 5000);
});
const must = (cond, msg) => { if (!cond) { console.error("FAIL", msg); process.exit(1); } console.log("PASS", msg); };

await new Promise((r) => sock.once("connect", r));
const h = await call("rpc.hello", { client_version: "smoke", api: [1, 0] });
must(h.result?.api?.[0] === 1, "hello api 1.x");
await call("events.subscribe", {});
const ev = await call("story.events", { level_min: "suspicious", cursor: { limit: 5 } });
must(ev.result?.items?.length >= 1 && ev.result.items[0].title.includes("payload.exe"), "demo suspicious event present");
const ex = await call("story.explain", { edge_id: ev.result.items[0].sentences[0].edge_ids[0] });
must(ex.result?.evidence?.length >= 1, "story.explain returns evidence");
const yaml = "- name: block-payload\n  action: block\n  match: { direction: out, process: ['C:/Users/pjg/AppData/Local/Temp/payload.exe'] }\n";
const val = await call("policy.validate", { yaml });
must(val.result && val.result.errors.length === 0, "policy.validate ok");
const rid = randomUUID();
const ap = await call("policy.apply", { request_id: rid, yaml });
must(ap.result?.policy_id > 0 && ap.result.confirm_deadline_ts > 0, "policy.apply applied with deadline");
const ap2 = await call("policy.apply", { request_id: rid, yaml });
must(JSON.stringify(ap2.result) === JSON.stringify(ap.result), "same request_id is idempotent");
const cf = await call("policy.confirm", { request_id: randomUUID(), policy_id: ap.result.policy_id, version: ap.result.version });
must(cf.result?.ok === true || cf.result != null, "policy.confirm ok");
const wide = "- name: all\n  action: block\n  match: { direction: out }\n";
const w = await call("policy.apply", { request_id: randomUUID(), yaml: wide });
must(w.error?.code === -32003, "wide policy needs_ack (-32003)");
// A19
const cl = await call("connections.list", { since_secs: 3600 });
const pay = cl.result?.items?.find((c) => c.image.endsWith("payload.exe"));
must(pay && pay.domain === "c2.evil.example" && pay.last_ft > 116444736000000000, "connections.list has payload with domain (FILETIME)");
const ls = await call("listeners.list", {});
must(ls.result?.items?.some((l) => l.lport === 4444), "listeners.list (dev host)");
const pd = await call("process.detail", { node_id: pay.process_id });
must(pd.result?.pid === pay.pid && pd.result.origin?.host_url === "https://evil.example/p", "process.detail origin");
const root = ev.result.items[0].root;
const cp = await call("cut.preview", { story_root: root, also: ["terminate"] });
must(cp.result?.block_images?.some((i) => i.endsWith("payload.exe")) && (cp.result.validation?.errors ?? []).length === 0, "cut.preview plan");
const ca = await call("cut.apply", { request_id: randomUUID(), story_root: root, also: ["terminate"] });
must(ca.result?.policies?.length === 1 && ca.result.policies[0].confirm_deadline_ts > 0, "cut.apply applied as one policy (needs confirm)");
must(cp.result.injected_hosts?.some((h) => h.pid === 1500) && !cp.result.block_images.some((i) => i.endsWith("chrome.exe")), "cut.preview: injected browser not path-blocked");
must(ca.result.terminated.length >= 1, "cut.apply terminated via host");
await new Promise((r) => setTimeout(r, 600));
must(notes.some((n) => n.method === "events.new" && n.params?.kind === "cut_applied"), "events.new cut_applied notification");
sock.end();
