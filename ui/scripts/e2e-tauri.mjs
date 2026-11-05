// A22: 실제 Tauri 앱(WebView2)에 붙어 같은 시나리오를 돈다 (Windows 러너).
// 앱은 WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=<port> 로 띄우고, 여기서 CDP 로 붙는다.
// 실제 파이프 → 실제 서명 검사·관리자 검사 → svc-poc(--demo) 까지 전 경로. CSP 위반·페이지 오류·Tauri 거부를 모은다.
// 사용: node scripts/e2e-tauri.mjs <cdp-port> <out-dir> [user]
// user (A27): 앱이 표준 사용자로 떠 있다 — 보기 모드여야 하고, 변경은 change.stage → 승인 도우미(관리자, UAC 대역) 경로로만 된다.
import fs from "node:fs";
import { createRequire } from "node:module";
import { runScenario } from "./scenario.mjs";
import { captureScreens } from "./capture.mjs";

const { chromium } = createRequire(import.meta.url)("playwright");
const [port = "9222", outDir = "e2e-tauri-out", mode = "admin"] = process.argv.slice(2);
const userMode = mode === "user";
fs.mkdirSync(outDir, { recursive: true });
const results = [];
const must = (c, m) => { results.push(`${c ? "PASS" : "FAIL"} ${m}`); console.log(results.at(-1)); };

let browser;
for (let i = 0; i < 60 && !browser; i++) {
  try { browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`); } catch { await new Promise((r) => setTimeout(r, 1000)); }
}
must(!!browser, "attached to WebView2 over CDP");
if (!browser) { fs.writeFileSync(`${outDir}/result.txt`, results.join("\n") + "\n"); process.exit(1); }
const ctx = browser.contexts()[0];
// 처음에는 about:blank 이다가 앱 출처(tauri.localhost)로 넘어간다. 앱 페이지가 될 때까지 기다린다.
const isApp = (u) => /tauri\.localhost|^tauri:/.test(u);
let page;
for (let i = 0; i < 60 && !page; i++) {
  page = ctx.pages().find((p) => isApp(p.url()));
  if (!page) await new Promise((r) => setTimeout(r, 500));
}
must(!!page, `found app page (${page?.url() ?? ctx.pages().map((p) => p.url()).join(",")})`);
if (!page) { fs.writeFileSync(`${outDir}/result.txt`, results.join("\n") + "\n"); process.exit(1); }

const errors = [];
const csp = [];
page.on("pageerror", (e) => errors.push(String(e)));
page.on("console", (m) => {
  const t = m.text();
  if (/Content Security Policy|Refused to/i.test(t)) csp.push(t);
  else if (m.type() === "error") errors.push(t);
});
// 붙기 전(시작 시점)에 난 CSP 위반·오류도 잡는다: CDP Log 도메인은 enable 할 때 지금까지 모인 항목을 다시 보내 준다
const cdp = await ctx.newCDPSession(page);
cdp.on("Log.entryAdded", ({ entry }) => {
  if (entry.source === "security" || /Content Security Policy|Refused to/i.test(entry.text)) csp.push(entry.text);
  else if (entry.level === "error") errors.push(`[log] ${entry.text}`);
});
await cdp.send("Log.enable");
await page.evaluate(() => document.addEventListener("securitypolicyviolation", (e) => console.error(`Refused to load (CSP ${e.violatedDirective}) ${e.blockedURI}`)));
const approveOut = process.env.STORYFW_E2E_APPROVE_OUT;
// 승인 도우미가 마지막으로 본 요약(서비스가 계산한 줄). 시나리오가 판정 시점에 읽는다
const lastApproval = () => {
  const t = approveOut && fs.existsSync(approveOut) ? fs.readFileSync(approveOut, "utf8") : "";
  const blocks = t.split("[approve]\n");
  return blocks.length > 1 ? blocks.at(-1).split("\n") : [];
};
let opts = {};
if (userMode) {
  const elevated = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke("elevated"));
  must(elevated === false, `UI runs non-elevated (view mode) as standard user (elevated=${elevated})`);
  opts = { approvals: { at: () => lastApproval() } };
}
// 시나리오가 중간에 멈춰도 그때까지 모은 콘솔 오류(끊김 사유 등)를 남긴다
try {
  await runScenario(page, outDir, must, opts);
  // 디자인 회신용 화면 캡처 (관리자 실행에서만 — 표준 사용자 실행은 보기 모드 확인용)
  if (!userMode) await captureScreens(page, outDir, (m) => console.log(m));
} catch (e) {
  must(false, `scenario threw: ${String(e).split("\n")[0]} | console: ${errors.join(" | ").slice(0, 400)}`);
  await page.screenshot({ path: `${outDir}/scenario-failed.png`, fullPage: true }).catch(() => {});
  fs.writeFileSync(`${outDir}/result.txt`, results.join("\n") + "\n");
  process.exit(1);
}

// A23: 실제 승인 도우미 — 앱 코어의 approve 명령 → ShellExecuteEx runas → 같은 서명 exe 의 --approve (웹뷰 없음)
// → 실제 파이프(SQOS 식별 수준, 서버 session 기록) → change.get → commit → confirm. 시험 빌드라 대화상자 대신 자동 응답 파일.
if (userMode) {
  // 서비스가 막는가: 표준 사용자 UI 가 맡기기를 건너뛰고 바로 변경을 부르면 -32001
  const direct = await page.evaluate(async () => {
    const yaml = "- name: direct-test\n  action: block\n  match: { direction: out, process: ['C:/x/direct.exe'] }\n";
    return window.__TAURI_INTERNALS__.invoke("rpc", { method: "policy.apply", params: { request_id: crypto.randomUUID(), yaml } });
  }).catch((e) => ({ err: String(e) }));
  must(direct?.error?.code === -32001, `direct policy.apply from standard-user UI rejected -32001 (${JSON.stringify(direct).slice(0, 200)})`);
  // 관리자 전용 조회도 막히는가: change.get 은 관리자만 (도우미 몫)
  const get = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke("rpc", { method: "change.get", params: { change_id: crypto.randomUUID() } })).catch((e) => ({ err: String(e) }));
  must(get?.error?.code === -32001, `change.get from standard-user UI rejected -32001 (${JSON.stringify(get).slice(0, 200)})`);
}
const helper = await page.evaluate(async () => {
  const inv = window.__TAURI_INTERNALS__.invoke;
  const yaml = "- name: helper-test\n  action: block\n  match: { direction: out, process: ['C:/helper/test.exe'] }\n";
  const s = await inv("rpc", { method: "change.stage", params: { method: "policy.apply", params: { request_id: crypto.randomUUID(), yaml } } });
  if (!s.result) return { stage: s };
  const id = s.result.change_id;
  const code = await Promise.race([inv("approve", { changeId: id }), new Promise((r) => setTimeout(() => r("timeout"), 90000))]);
  const res = await inv("rpc", { method: "change.result", params: { change_id: id } });
  return { code, res };
}).catch((e) => ({ err: String(e) }));
must(helper.code === 0, `approval helper exit 0 (${JSON.stringify(helper).slice(0, 300)})`);
must(helper.res?.result?.state === "done" && helper.res?.result?.policies?.[0]?.state === "Confirmed", "helper committed and confirmed (change.result)");
const log = approveOut && fs.existsSync(approveOut) ? fs.readFileSync(approveOut, "utf8") : "";
must(log.includes("[approve]") && log.includes("helper-test") && log.includes("서비스가 계산한 실행 내용"), "helper showed service-computed summary");
must(/\[exit\] 0/.test(log), "helper logged exit 0");
const srv = log.match(/\[server\] pid=(\d+) session=(\d+)/);
must(!!srv, `helper recorded pipe server session (${srv ? `pid ${srv[1]} session ${srv[2]}` : "none"})`);
if (approveOut) fs.copyFileSync(approveOut, `${outDir}/approve-out.txt`);

must(csp.length === 0, `no CSP violations (${csp.join(" | ").slice(0, 400)})`);
must(errors.length === 0, `no page errors (${errors.join(" | ").slice(0, 400)})`);
// 앱이 외부로 나가지 않는가: 로드된 자원이 전부 앱 출처인지
const origins = await page.evaluate(() => [...new Set(performance.getEntriesByType("resource").map((r) => new URL(r.name).origin))]);
must(origins.every((o) => /^(https?:\/\/tauri\.localhost|tauri:\/\/localhost|http:\/\/ipc\.localhost|ipc:)/.test(o)), `only app/ipc origins (${origins.join(", ")})`);
fs.writeFileSync(`${outDir}/result.txt`, results.join("\n") + "\n");
await browser.close().catch(() => {});
process.exit(results.some((r) => r.startsWith("FAIL")) ? 1 : 0);
