// UI 종단 시험 (Linux CI, A21): 실제 프런트 번들(dist) + 가짜 서비스(svc-dev) 를 Chromium 으로 돌린다.
// Tauri 코어 대신 window.__TAURI_INTERNALS__ 를 흉내 낸다: connect/rpc 명령은 작은 HTTP 다리로 svc-dev(TCP) 에 넘기고,
// 알림은 다리가 모아 두었다가 페이지가 가져가 Tauri 이벤트 콜백으로 흘린다. 화면마다 스크린샷을 남긴다.
// 사용: node scripts/e2e.mjs <svc-dev host:port> <out-dir>
import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { runScenario } from "./scenario.mjs";
import { captureScreens } from "./capture.mjs";
// ESM import 는 NODE_PATH 를 보지 않는다. 작업 환경의 전역 Playwright 와 CI 의 로컬 설치 둘 다 찾도록 require 로.
const { chromium } = createRequire(import.meta.url)("playwright");

const [hostport = "127.0.0.1:7878", outDir = "e2e-out", mode = "admin", adminHostport = ""] = process.argv.slice(2);
// mode=nonadmin: svc-dev --non-admin --admin-listen <adminHostport> 와 짝. 보기 모드 UI 가 변경을 맡기고(change.stage),
// 승인 도우미 흉내가 관리자 포트로 change.get → commit → confirm 한다 (A23). 실제 도우미(Windows 대화상자)는 poc5 에서.
const [host, port] = hostport.split(":");
fs.mkdirSync(outDir, { recursive: true });
const dist = path.resolve("dist");
// 실제 앱과 같은 CSP 를 건다(connect-src 만 흉내 다리 /bridge 를 위해 'self'). 인라인 스타일·스크립트 위반을 Linux 에서 먼저 잡는다
const appCsp = JSON.parse(fs.readFileSync("src-tauri/tauri.conf.json", "utf8")).app.security.csp;
const csp = appCsp.replace(/connect-src [^;]*/, "connect-src 'self'");

// --- svc-dev 연결 (한 줄 JSON-RPC)
function svcConn(h, p) {
  let buf = "";
  const waiters = new Map();
  const notes = [];
  let nextId = 1;
  let sock;
  const ready = new Promise((res, rej) => {
    sock = net.createConnection({ host: h, port: Number(p) }, res);
    sock.on("error", rej);
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const v = JSON.parse(buf.slice(0, i));
        buf = buf.slice(i + 1);
        if (v.id != null && waiters.has(v.id)) { waiters.get(v.id)(v); waiters.delete(v.id); } else notes.push(v);
      }
    });
  });
  const call = (method, params) => new Promise((res) => {
    const id = nextId++;
    waiters.set(id, res);
    sock.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
  return { ready, call, notes, end: () => sock.end() };
}
let ui;
const call = (m, p) => ui.call(m, p);
const notes = { splice: (...a) => (ui ? ui.notes.splice(...a) : []) };

// 승인 도우미 흉내: 관리자 포트로 서비스가 만든 요약을 받고 → 그 digest 로 실행 → 60초 확인. 요약 줄은 시나리오가 판정한다
const approvals = [];
async function helperEmu(changeId) {
  const [ah, ap] = adminHostport.split(":");
  const h = svcConn(ah, ap);
  await h.ready;
  await h.call("rpc.hello", { client_version: "e2e-helper", api: [1, 0] });
  const g = await h.call("change.get", { change_id: changeId });
  if (g.error) { h.end(); return 2; }
  approvals.push(g.result.lines);
  const c = await h.call("change.commit", { request_id: changeId, change_id: changeId, digest: g.result.digest });
  if (c.error) { h.end(); return 2; }
  const r = c.result.result;
  const pols = [r, ...(r.policies ?? [])].filter((x) => x && x.policy_id != null);
  for (const p of pols) await h.call("policy.confirm", { request_id: crypto.randomUUID(), policy_id: p.policy_id, version: p.version });
  h.end();
  return 0;
}

// --- HTTP: dist 정적 파일 + /bridge
const server = http.createServer(async (req, res) => {
  if (req.url === "/bridge" && req.method === "POST") {
    let body = "";
    for await (const c of req) body += c;
    const { cmd, args } = JSON.parse(body);
    let out;
    if (cmd === "connect") { if (!ui) { ui = svcConn(host, port); await ui.ready; } out = await call("rpc.hello", { client_version: "e2e", api: [1, 0] }); }
    else if (cmd === "rpc") out = await call(args.method, args.params ?? {});
    else if (cmd === "endpoint") out = "tcp:" + hostport;
    else if (cmd === "elevated") out = mode !== "nonadmin";
    else if (cmd === "approve") out = await helperEmu(args.changeId);
    else if (cmd === "notes") out = notes.splice(0);
    else out = null;
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify(out));
  }
  const f = path.join(dist, req.url === "/" ? "index.html" : decodeURIComponent(req.url.split("?")[0]));
  if (!f.startsWith(dist) || !fs.existsSync(f)) { res.writeHead(404); return res.end(); }
  const type = f.endsWith(".js") ? "text/javascript" : f.endsWith(".css") ? "text/css" : f.endsWith(".svg") ? "image/svg+xml" : f.endsWith(".png") ? "image/png" : "text/html";
  res.writeHead(200, type === "text/html" ? { "content-type": type, "content-security-policy": csp } : { "content-type": type });
  fs.createReadStream(f).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const shim = () => {
  const cbs = new Map();
  let cid = 1;
  window.__TAURI_INTERNALS__ = {
    transformCallback(cb) { const id = cid++; cbs.set(id, cb); return id; },
    unregisterCallback(id) { cbs.delete(id); },
    convertFileSrc(p) { return p; },
    async invoke(cmd, args) {
      if (cmd === "plugin:event|listen") { (window.__sfListeners ||= []).push(args.handler); return args.handler; }
      if (cmd === "plugin:event|unlisten") return null;
      const r = await fetch("/bridge", { method: "POST", body: JSON.stringify({ cmd, args }) });
      return r.json();
    },
  };
  // 알림 끌어오기 → Tauri 이벤트 콜백 형식 {event, id, payload}
  setInterval(async () => {
    const r = await fetch("/bridge", { method: "POST", body: JSON.stringify({ cmd: "notes" }) });
    for (const n of await r.json()) for (const h of window.__sfListeners || []) cbs.get(h)?.({ event: "svc-notify", id: 0, payload: n });
  }, 300);
};

const results = [];
const must = (c, m) => { results.push(`${c ? "PASS" : "FAIL"} ${m}`); console.log(results.at(-1)); };
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
const cspViolations = [];
page.on("console", (m) => {
  if (/Content Security Policy|Refused to/i.test(m.text())) cspViolations.push(m.text());
  else if (m.type() === "error") errors.push(m.text());
});
await page.addInitScript(shim);
await page.goto(base);
if (mode === "acl") {
  // ACL 정책 관리 화면(2026-11-06 개편): 빈 표 → 규칙 창 두 번(차단·허용) → 표 → 적용 → 다시 열어 표로 읽기
  await page.setViewportSize({ width: 1393, height: 997 });
  await page.waitForSelector(".status", { timeout: 20000 });
  await page.click("button.nav-btn[data-key=policy]");
  await page.waitForSelector(".acl", { timeout: 10000 });
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(outDir, "acl-0-empty.png") });
  const addRule = async (o) => {
    await page.click(".acl-head button:has-text('규칙 추가')");
    await page.waitForSelector("dialog.acl-dialog[open]");
    if (o.allow) await page.click("dialog.acl-dialog .seg-opt:has-text('허용')");
    if (o.dir) await page.click(`dialog.acl-dialog .seg-opt:has-text('${o.dir}')`);
    if (o.proto) await page.click(`dialog.acl-dialog .seg-opt:text-is('${o.proto}')`);
    const inputs = page.locator("dialog.acl-dialog .acl-input input");
    if (o.srcIp) await inputs.nth(0).fill(o.srcIp);
    if (o.dstIp) await inputs.nth(2).fill(o.dstIp);
    if (o.dstPort) await inputs.nth(3).fill(o.dstPort);
    await page.waitForTimeout(200);
    if (o.shot) await page.screenshot({ path: path.join(outDir, o.shot) });
    await page.click("dialog.acl-dialog .actions .btn.primary");
  };
  await addRule({ dstIp: "1.1.1.1", dstPort: "443", proto: "TCP", shot: "acl-1-dialog-block.png" });
  await addRule({ allow: true, dir: "들어옴", srcIp: "192.168.0.0/24", dstPort: "3389", proto: "TCP", shot: "acl-2-dialog-allow-in.png" });
  // 잘못된 주소는 저장 단추가 꺼진다
  await page.click(".acl-head button:has-text('규칙 추가')");
  await page.locator("dialog.acl-dialog .acl-input input").nth(2).fill("1.1.1.999");
  await page.waitForTimeout(200);
  const disabled = await page.locator("dialog.acl-dialog .actions .btn.primary").isDisabled();
  must(disabled, "acl: invalid address disables save");
  await page.screenshot({ path: path.join(outDir, "acl-3-dialog-invalid.png") });
  await page.click("dialog.acl-dialog .actions .btn:has-text('취소')");
  must((await page.locator(".acl-grid tbody tr").count()) === 2, "acl: two rules in table");
  await page.screenshot({ path: path.join(outDir, "acl-4-table.png") });
  await page.click(".acl-foot .btn.primary");
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(outDir, "acl-5-applied.png"), fullPage: true });
  const listed = await page.evaluate(() => document.body.innerText.includes("ACL 규칙 2개"));
  must(listed, "acl: applied policy listed as 'ACL 규칙 2개'");
  // 화면을 다시 열면 걸린 ACL 을 표로 읽는다
  await page.click("button.nav-btn[data-key=dashboard]");
  await page.waitForTimeout(500);
  await page.click("button.nav-btn[data-key=policy]");
  await page.waitForTimeout(1500);
  must((await page.locator(".acl-grid tbody tr").count()) === 2, "acl: reload reads applied ACL back");
  await page.setViewportSize({ width: 760, height: 900 });
  await page.click(".acl-grid tbody tr >> nth=1 >> button:has-text('수정')");
  await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(outDir, "acl-6-dialog-narrow.png") });
  await page.click("dialog.acl-dialog .actions .btn:has-text('취소')");
  console.log(results.join("\n"));
  if (errors.length) console.log("page errors:", errors.join(" | "));
  if (cspViolations.length) console.log("csp:", cspViolations.join(" | "));
  await browser.close();
  server.close();
  process.exit(results.some((r) => r.startsWith("FAIL")) || errors.length || cspViolations.length ? 1 : 0);
}
if (mode.startsWith("shots:")) {
  // D013 상태 캡처: svc-dev --force empty|error / --health stalled 와 짝. 화면 넷을 찍고 끝낸다(시나리오 없음)
  const label = mode.slice(6);
  await page.setViewportSize({ width: 1393, height: 997 });
  await page.waitForSelector(".status", { timeout: 20000 });
  for (const key of ["dashboard", "story", "connections", "policy"]) {
    await page.click(`button.nav-btn[data-key=${key}]`);
    if (label === "delay") {
      // D015-5: 불러오는 중 — 뼈대(2초 전)와 "불러오는 중…"(2초 뒤)
      await page.waitForTimeout(600);
      await page.screenshot({ path: path.join(outDir, `${label}-${key}-0.6s.png`) });
      await page.waitForTimeout(1700);
      await page.screenshot({ path: path.join(outDir, `${label}-${key}-2.3s.png`) });
    }
    await page.waitForTimeout(2600);
    await page.screenshot({ path: path.join(outDir, `${label}-${key}.png`), fullPage: key === "story" });
    if (key === "story" && label === "items") {
      // D020: 핵심 프로세스(svchost) 묶음 카드
      const sv = page.locator(".card.event", { hasText: "svchost.exe" }).first();
      if (await sv.count()) {
        await sv.locator("details.occurrences summary").first().click().catch(() => {});
        await page.waitForTimeout(300);
        await sv.screenshot({ path: path.join(outDir, `${label}-card-svchost.png`) });
      }
      // D012: 오늘 처음 접속지 주황 테두리 — helper.exe 마인드맵
      const btn = page.locator(".card.event", { hasText: "helper.exe" }).locator("button", { hasText: "마인드맵" }).first();
      if (await btn.count()) {
        await btn.click();
        // D018: 국기 SVG 를 다 읽은 뒤 찍는다(같은 경로를 페이지에서 미리 읽어 load/complete 확인)
        await page.waitForTimeout(800);
        await page.evaluate(async () => {
          const urls = [...document.querySelectorAll("[data-flags]")].flatMap((d) => JSON.parse(d.getAttribute("data-flags") || "[]"));
          await Promise.all(urls.map((u) => new Promise((r) => { const i = new Image(); i.onload = i.onerror = () => r(null); i.src = u; })));
        });
        await page.waitForTimeout(1400);
        await page.locator(".card.event", { hasText: "helper.exe" }).first().screenshot({ path: path.join(outDir, `${label}-mindmap-helper.png`) });
      }
    }
    const quiet = await page.evaluate(() => document.body.innerText.includes("조용합니다"));
    const fail = await page.evaluate(() => document.querySelectorAll(".fail").length);
    console.log(`shots ${label} ${key}: quiet-text=${quiet} fail-boxes=${fail}`);
  }
  if (label === "live") {
    // D030-2·3 캡처(svc-dev --live): 오늘 한 일 "×N" 접힘·펼침, 연결 표 보는 중 "새 접속 N건 — 보기" 알약
    await page.click("button.nav-btn[data-key=story]");
    await page.waitForTimeout(3000);
    const chip = page.locator(".chip-btn").first();
    if (await chip.count()) {
      await chip.scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(outDir, `${label}-today-folded.png`) });
      await chip.click();
      await page.waitForTimeout(300);
      await page.screenshot({ path: path.join(outDir, `${label}-today-open.png`) });
    }
    console.log(`shots live: chips=${await page.locator(".chip-btn").count()}`);
    await page.click("button.nav-btn[data-key=connections]");
    await page.waitForTimeout(2500);
    await page.click(".seg-btn[data-mode=none]").catch(() => {});
    await page.waitForTimeout(2500);
    await page.hover("table.conn tbody tr >> nth=2");
    await page.locator(".new-pill").waitFor({ timeout: 15000 }).catch(() => {});
    console.log(`shots live: pill=${await page.locator(".new-pill").count()}`);
    await page.screenshot({ path: path.join(outDir, `${label}-new-pill.png`) });
  }
  if (label === "items") {
    // D023-1: 대시보드 → 묶인 svchost "이야기 보기" → 그 카드로 이동·강조(이동 직후)
    await page.click("button.nav-btn[data-key=dashboard]");
    await page.waitForTimeout(2600);
    const row = page.locator(".row", { hasText: "svchost.exe" }).first();
    if (await row.count()) {
      await row.locator("button", { hasText: "이야기 보기" }).click();
      await page.locator(".card.event.flash").first().waitFor({ timeout: 15000 }).catch(() => {});
      await page.waitForTimeout(300);
      await page.screenshot({ path: path.join(outDir, `${label}-focus-svchost.png`) });
    }
  }
  if (label === "items") {
    // D025: 프로그램 상세(payload — 연결 표에서, svchost — 이야기 카드 이름에서), 진단, 다크 상세
    await page.click("button.nav-btn[data-key=connections]");
    await page.waitForTimeout(2500);
    await page.selectOption(".toolbar select", "86400").catch(() => {});
    await page.click(".seg-btn[data-mode=none]").catch(() => {});
    await page.waitForTimeout(2500);
    const pr = page.locator("tr.clickable", { hasText: "payload.exe" }).first();
    if (await pr.count()) {
      await pr.click();
      await page.locator(".pd-drawer .pd-name").waitFor({ timeout: 10000 }).catch(() => {});
      await page.waitForTimeout(800);
      await page.screenshot({ path: path.join(outDir, `${label}-detail-payload.png`) });
      await page.keyboard.press("Escape");
    }
    await page.click("button.nav-btn[data-key=story]");
    await page.waitForTimeout(3000);
    const sv = page.locator(".card.event h3.clickable", { hasText: "svchost.exe" }).first();
    if (await sv.count()) {
      await sv.click();
      await page.locator(".pd-drawer .pd-name").waitFor({ timeout: 10000 }).catch(() => {});
      await page.waitForTimeout(800);
      await page.screenshot({ path: path.join(outDir, `${label}-detail-svchost.png`) });
      await page.emulateMedia({ colorScheme: "dark" });
      await page.waitForTimeout(500);
      await page.screenshot({ path: path.join(outDir, `${label}-detail-svchost-dark.png`) });
      await page.emulateMedia({ colorScheme: "light" });
      await page.keyboard.press("Escape");
    }
    await page.click("button.nav-btn[data-key=settings]");
    await page.waitForTimeout(3000);
    await page.screenshot({ path: path.join(outDir, `${label}-diagnostics.png`) });
  }
  console.log(`shots ${label}: page-errors=${errors.length}`);
  await browser.close();
  server.close();
  process.exit(0);
}
if (mode === "nonadmin") {
  await page.waitForSelector(".status.ok", { timeout: 20000 });
  must((await page.textContent(".status")).includes("보기 모드"), "non-elevated UI shows view mode");
  // 같은 시나리오를 승인 창 경로로: 끊기 → 맡기기 → 도우미(관리자)가 요약 확인·실행·유지 → UI 는 결과만
  await runScenario(page, outDir, must, { approvals });
} else {
  await runScenario(page, outDir, must);
  // 디자인 회신용 화면 캡처(Linux CI 와 개발 세션 로컬에서도 같은 것)
  await captureScreens(page, outDir, (m) => { console.log(m); results.push(`INFO ${m}`); });
}

must(cspViolations.length === 0, `no CSP violations (${cspViolations.join(" | ").slice(0, 300)})`);
must(errors.length === 0, `no page errors (${errors.join(" | ").slice(0, 300)})`);
await browser.close();
server.close();
ui?.end();
fs.writeFileSync(`${outDir}/result.txt`, results.join("\n") + "\n");
process.exit(results.some((r) => r.startsWith("FAIL")) ? 1 : 0);
