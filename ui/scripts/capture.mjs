// 디자인 회신용 화면 캡처 (러너 CDP). e2e 시나리오가 끝난 뒤 같은 페이지에서 화면마다 PNG 를 남긴다.
// 디자인 세션 요청(Dxxx)을 구현하면 이 캡처(ci-logs 브랜치의 poc5 실행 폴더 captures/)를 to-design 회신에 붙인다.
export async function captureScreens(page, outDir, log) {
  const dir = `${outDir}/captures`;
  const fs = await import("node:fs");
  fs.mkdirSync(dir, { recursive: true });
  const shots = [];
  // D001·D002 완료 기준 크기: 1393x997(노트북 125%), 1280x800
  for (const [w, h] of [[1393, 997], [1280, 800]]) {
    await page.setViewportSize({ width: w, height: h }).catch(() => {});
    for (const key of ["dashboard", "story", "connections", "policy", "settings"]) {
      if (w === 1280 && key !== "connections") continue;
      try {
        await page.click(`button.nav-btn[data-key=${key}]`);
        await page.waitForTimeout(800);
        // 연결: 시연 데이터가 5분보다 오래됐을 수 있어 "오늘" 범위로
        if (key === "connections") {
          await page.selectOption(".toolbar select", "86400").catch(() => {});
          // D008 완료 기준: 망 묶음 펼침 1개 + A3 패널 펼침
          await page.click("button.seg-btn[data-mode=org]").catch(() => {});
          await page.waitForTimeout(600);
          await page.evaluate(() => { const d = document.querySelector("details.where-panel"); if (d) d.open = true; });
          await page.click("tr.group-row >> nth=0").catch(() => {});
        }
        // 지도 보기(사용자 요청): 막대 캡처 뒤 따로 한 장
        if (key === "connections" && w === 1393) {
          await page.waitForTimeout(1200);
          await page.click("details.where-panel .seg-btn >> text=지도").catch(() => {});
          await page.waitForTimeout(800);
          await page.screenshot({ path: `${dir}/connections-map-${w}x${h}.png` });
          shots.push(`${dir}/connections-map-${w}x${h}.png`);
          await page.click("details.where-panel .seg-btn >> text=막대").catch(() => {});
        }
        await page.waitForTimeout(1500);
        const p = `${dir}/${key}-${w}x${h}.png`;
        await page.screenshot({ path: p });
        shots.push(p);
        // 2026-11-07 대시보드 다듬기: 아래 칸(영역 그래프·도넛·4장 띠)까지 전체 쪽

        // D006 완료 기준: 정책 화면 영어 상태 0, 설정 "{}" 0
        if (key === "policy" || key === "settings") {
          const m = await page.evaluate(() => {
            const t = document.querySelector("section.screen")?.textContent ?? "";
            return { englishState: (t.match(/\b(Applied|Confirmed|Paused|Expired|RolledBack)\b/g) ?? []).length, braces: (t.match(/\{\}/g) ?? []).length, rows: document.querySelectorAll(".policy-row").length };
          });
          log(`capture-check ${key}: ${JSON.stringify(m)}`);
        }
        if (key === "connections") {
          // 판정 재료: 가로 스크롤 여부·머리글 한 줄·보이는 행 수
          const m = await page.evaluate(() => {
            const t = document.querySelector("table.grid.conn");
            const ths = [...(t?.querySelectorAll("th") ?? [])];
            return {
              hscroll: document.documentElement.scrollWidth > document.documentElement.clientWidth,
              headerOneLine: ths.every((th) => th.getBoundingClientRect().height <= 40),
              rows: t?.querySelectorAll("tbody tr").length ?? 0,
              rowHeight: Math.round(t?.querySelector("tbody tr")?.getBoundingClientRect().height ?? 0),
            };
          });
          log(`capture-check connections ${w}x${h}: ${JSON.stringify(m)}`);
        }
      } catch (e) {
        log(`capture ${key} failed: ${String(e).split("\n")[0]}`);
      }
    }
  }
  await page.setViewportSize({ width: 1393, height: 997 }).catch(() => {});
  // 마인드맵: 이야기 화면의 첫 사건에서 연다
  try {
    await page.click("button.nav-btn[data-key=story]");
    await page.waitForTimeout(800);
    await page.click(".card.event >> text=마인드맵");
    await page.waitForTimeout(2500);
    await page.screenshot({ path: `${dir}/mindmap.png`, fullPage: true });
    shots.push(`${dir}/mindmap.png`);
  } catch (e) {
    log(`capture mindmap failed: ${String(e).split("\n")[0]}`);
  }
  // D003·D004 완료 기준: 이야기 전체(카드 + 접힌 묶음 펼침 + 오늘 한 일 + 마인드맵), 금지 문자열·빨간 채움 단추 수
  try {
    await page.evaluate(() => document.querySelectorAll("details.stale-group").forEach((d) => (d.open = true)));
    await page.waitForTimeout(300);
    // 본문이 스크롤 칸 안에 있어 fullPage 로는 안 잡힌다 → 요소 단위로(요소가 화면보다 길어도 전부)
    // 본문은 스크롤 칸 안이라 fullPage 로 안 잡힌다 → 스크롤 칸을 내려 가며 화면 단위로 찍는다
    const pages = await page.evaluate(() => {
      const sc = [...document.querySelectorAll("*")].find((e) => e.scrollHeight > e.clientHeight + 20 && /auto|scroll/.test(getComputedStyle(e).overflowY));
      if (!sc) return 1;
      sc.setAttribute("data-capture-scroll", "1");
      return Math.min(6, Math.ceil(sc.scrollHeight / (sc.clientHeight - 80)));
    });
    for (let k = 0; k < pages; k++) {
      await page.evaluate((k) => {
        const sc = document.querySelector("[data-capture-scroll]");
        if (sc) sc.scrollTop = k * (sc.clientHeight - 80);
      }, k);
      await page.waitForTimeout(300);
      await page.screenshot({ path: `${dir}/story-scroll-${k + 1}.png` });
      shots.push(`${dir}/story-scroll-${k + 1}.png`);
    }
    const m = await page.evaluate(() => {
      const txt = document.body.innerText;
      const redFilled = [...document.querySelectorAll("button")].filter((b) => {
        const c = getComputedStyle(b).backgroundColor;
        const m = /rgba?\((\d+), (\d+), (\d+)/.exec(c);
        return m && Number(m[1]) > 150 && Number(m[2]) < 80 && Number(m[3]) < 80;
      }).length;
      return {
        particle: (txt.match(/이\(가\)|을\(를\)/g) ?? []).length,
        binguii: (txt.match(/빙의/g) ?? []).length,
        redFilledButtons: redFilled,
        staleGroups: document.querySelectorAll("details.stale-group").length,
        staleRows: document.querySelectorAll(".stale-row").length,
        sinceLines: document.querySelectorAll(".since").length,
        unrecordedSteps: document.querySelectorAll(".step.none").length,
        todayParts: document.querySelectorAll(".story-today .sentence b").length,
      };
    });
    log(`capture-check story: ${JSON.stringify(m)}`);
  } catch (e) {
    log(`capture story-full failed: ${String(e).split("\n")[0]}`);
  }
  // D011: 다크 테마(Windows 설정 따라가기) 캡처 — 대시보드·이야기(마인드맵)·연결(지도)·정책
  try {
    await page.emulateMedia({ colorScheme: "dark" });
    await page.setViewportSize({ width: 1393, height: 997 });
    for (const key of ["dashboard", "story", "connections", "policy"]) {
      await page.click(`button.nav-btn[data-key=${key}]`);
      await page.waitForTimeout(900);
      if (key === "story") {
        await page.click(".card.event >> text=마인드맵").catch(() => {});
        await page.waitForTimeout(2000);
      }
      if (key === "connections") {
        await page.selectOption(".toolbar select", "86400").catch(() => {});
        await page.evaluate(() => { const d = document.querySelector("details.where-panel"); if (d) d.open = true; });
        await page.click("details.where-panel .seg-btn >> text=지도").catch(() => {});
        await page.waitForTimeout(900);
      }
      await page.screenshot({ path: `${dir}/${key}-dark-1393x997.png` });
      shots.push(`${dir}/${key}-dark-1393x997.png`);
      if (key === "dashboard") {
        // .main 이 스크롤 상자라 fullPage 로는 아래가 안 찍힌다 — 잠시 자연 높이로 펴고 찍는다
        const h0 = await page.evaluate(() => { const m = document.querySelector(".main"); const e = document.querySelector(".main .screen"); return e && m ? (m.style.overflow = "visible", m.style.height = "auto", document.body.style.height = "auto", e.scrollHeight + 60) : 997; });
        await page.setViewportSize({ width: 1393, height: Math.min(4000, h0) });
        await page.waitForTimeout(500);
        await page.screenshot({ path: `${dir}/dashboard-dark-full.png` });
        shots.push(`${dir}/dashboard-dark-full.png`);
        await page.evaluate(() => { const m = document.querySelector(".main"); if (m) { m.style.overflow = ""; m.style.height = ""; } document.body.style.height = ""; });
        await page.setViewportSize({ width: 1393, height: 997 });
      }
    }
    await page.emulateMedia({ colorScheme: "light" });
  } catch (e) {
    log(`capture dark failed: ${String(e).split("\n")[0]}`);
  }
  log(`captures: ${shots.length} -> ${dir}`);
  return shots;
}
