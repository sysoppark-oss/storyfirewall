// UI 종단 시나리오 (A21·A22 공용). page 는 Playwright Page. 실제 Tauri(WebView2, CDP)와 Linux 흉내 실행이 같은 판정을 쓴다.
// 화면별 스크린샷을 outDir 에 남기고 판정 줄을 돌려준다.
// opts.approvals: 승인 창 경로(보기 모드)면 도우미가 본 요약 줄 배열들 — 카운트다운 대신 승인 결과를 판정한다 (A23)
export async function runScenario(page, outDir, must, opts = {}) {
  const viaApproval = !!opts.approvals;
  await page.waitForSelector(".status.ok", { timeout: 20000 });
  must(true, "connected to service");
  await page.waitForSelector(".card.alert", { timeout: 15000 });
  must((await page.textContent(".card.alert .big"))?.trim() !== "0", "dashboard shows suspicious count");
  await page.screenshot({ path: `${outDir}/1-dashboard.png` });

  await page.click("button.nav-btn[data-key=story]");
  await page.waitForSelector(".card.event");
  // D020: 같은 판정 묶기·최신이 위 — 첫 카드가 payload 라는 가정 대신 payload 카드를 찾는다
  const pay = page.locator(".card.event", { has: page.locator("h3", { hasText: "payload.exe" }) }).first();
  must((await pay.count()) > 0, "story card for payload.exe");
  await pay.locator("button", { hasText: "마인드맵" }).click();
  await page.waitForSelector(".cy canvas", { timeout: 10000 });
  await page.waitForTimeout(800);
  must((await page.evaluate(() => document.querySelectorAll(".cy canvas").length)) > 0, "mindmap canvas rendered");
  await page.locator(".mindmap").screenshot({ path: `${outDir}/2-mindmap.png` });

  await pay.locator("button", { hasText: "여기서부터 끊기…" }).click();
  await page.waitForSelector("dialog.ack[open]");
  const dlg = await page.textContent("dialog.ack");
  must(dlg.includes("통신을 막을 프로그램") && dlg.includes("payload.exe"), "cut dialog lists payload.exe");
  must(dlg.includes("코드를 주입당한 정상 프로그램") && dlg.includes("chrome.exe (PID 1500)"), "cut dialog separates injected browser");
  must(/203\.0\.113\.9:8443\/tcp/.test(dlg) && dlg.includes("203.0.113.77:443/tcp"), "cut dialog lists precise addresses (ip:port/proto)");
  await page.screenshot({ path: `${outDir}/3-cut-dialog.png` });
  await page.click("dialog.ack >> text=끊기 적용");
  if (viaApproval) {
    await page.waitForSelector(".cut-result .card.approval", { timeout: 15000 });
    // 도우미가 본 것은 UI 가 보낸 글이 아니라 서비스가 계산한 요약이어야 한다
    const seen = (opts.approvals.at(-1) ?? []).join("\n");
    must(seen.includes("payload.exe") && /203\.0\.113\.9:8443\/tcp/.test(seen), "approval helper saw service-computed summary (targets, addresses)");
    must((await page.textContent(".cut-result")).includes("유지됨"), "cut kept via approval helper (no in-UI countdown)");
    await page.screenshot({ path: `${outDir}/4-cut-applied.png`, fullPage: true });
  } else {
    await page.waitForSelector(".cut-result .card.alert");
    const left = await page.textContent(".cut-result .big");
    const secs = Number((left ?? "").replace(/[^0-9]/g, ""));
    // 시간대 접점(A22): 확인 시한은 UTC — 로컬 시각이 섞이면 수천~수만 초로 보인다
    must(secs > 0 && secs <= 60, `cut countdown within 60s (saw "${left?.trim()}")`);
    await page.screenshot({ path: `${outDir}/4-cut-applied.png`, fullPage: true });
    await page.click(".cut-result >> text=유지 (확인)");
    await page.waitForSelector(".cut-result >> text=확인됨");
    must(true, "cut policy confirmed");
  }

  await page.click("button.nav-btn[data-key=connections]");
  await page.waitForSelector("table.grid tbody tr");
  await page.selectOption(".toolbar select", "3600");
  // A2: 기본은 망(조직) 묶음 — 행 단위 확인은 "묶지 않음"으로
  await page.click("button.seg-btn[data-mode=none]");
  await page.waitForTimeout(800);
  must((await page.textContent("table.grid")).includes("c2.evil.example"), "connections show c2 domain (UTC window)");
  await page.click("table.grid tbody tr.clickable >> nth=0");
  // D025: 프로그램 상세는 오른쪽 패널
  await page.waitForSelector(".pd-drawer .pd-name");
  must(true, "process detail opens from connection row");
  await page.screenshot({ path: `${outDir}/5-connections.png`, fullPage: true });
  await page.keyboard.press("Escape");
  must((await page.locator(".pd-drawer").count()) === 0, "process detail closes with Esc");

  await page.click("button.nav-btn[data-key=policy]");
  // D006-4: 편집기는 "고급" 접힘 안
  await page.click("details.advanced > summary");
  await page.waitForSelector("textarea.yaml");
  // needs_ack 왕복 (A23 접점 결함: 서비스가 "selfblock" 을 내보내고 "self" 만 받아 확인 뒤 적용이 늘 거부됐다)
  await page.fill("textarea.yaml", "- name: dns-test\n  action: block\n  match: { direction: out, remote_port: [53], process: ['C:/a/b.exe'] }\n");
  await page.click(".editor >> text=적용");
  await page.waitForSelector("dialog.ack[open]", { timeout: 10000 });
  await page.click("dialog.ack >> text=확인하고 적용");
  if (viaApproval) {
    await page.waitForSelector(".card.approval", { timeout: 15000 });
    must((await page.textContent(".card.approval")).includes("유지됨"), "policy needs_ack round-trip then approval helper");
  } else {
    await page.waitForSelector(".card.alert .big", { timeout: 10000 });
    must(true, "policy needs_ack round-trip then countdown");
  }
  await page.screenshot({ path: `${outDir}/6-policy.png` });
}
