// CSP 고정 시험 — 화면(webview)이 스크립트를 어디서 받아 실행할 수 있는지를 설정 파일에서 직접 읽어 못 박는다.
// 배경: CVE-2026-95626(GHSA-6vxm-x265-58qf). Tauri 가 script-src 에 nonce 를 넣어도, 같은 줄에 data: 나 blob: 이
// 있으면 CSP Level 3 규칙상 그쪽이 그대로 통해서 nonce 보호가 무력해진다. 지금 설정은 'self' 하나라 해당이 없다.
// 이 시험은 누가 나중에 편의로 data:/blob:/'unsafe-inline' 등을 넣는 순간 빌드에서 드러나게 한다.
import { describe, expect, it } from "vitest";
// @ts-ignore — node 내장 모듈(@types/node 없이 시험에서만 씀, word.test.ts 와 같은 방식)
import { readFileSync } from "node:fs";
// @ts-ignore
import { fileURLToPath } from "node:url";

const confPath = fileURLToPath(new URL("../src-tauri/tauri.conf.json", import.meta.url));
const conf = JSON.parse(readFileSync(confPath, "utf8"));

// "a b; c d" -> { a: ["b"], c: ["d"] }. 지시어 이름은 소문자로 맞춘다(CSP 는 대소문자를 가리지 않음).
function directives(csp: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const part of csp.split(";")) {
    const words = part.trim().split(/\s+/).filter(Boolean);
    if (words.length === 0) continue;
    const name = (words[0] ?? "").toLowerCase();
    // 같은 지시어가 두 번 나오면 브라우저는 첫 번째만 쓴다. 뒤엣것으로 덮어 시험을 속이지 못하게 첫 번째를 남긴다.
    if (!(name in out)) out[name] = words.slice(1).map((w) => w.toLowerCase());
  }
  return out;
}

describe("tauri.conf.json 의 CSP", () => {
  const csp = conf?.app?.security?.csp;

  it("문자열로 적혀 있다(없거나 null 이면 Tauri 가 CSP 를 아예 걸지 않는다)", () => {
    expect(typeof csp).toBe("string");
    expect(csp.length).toBeGreaterThan(0);
  });

  it("script-src 는 'self' 하나뿐이다", () => {
    const d = directives(csp);
    expect(d["script-src"]).toEqual(["'self'"]);
  });

  it("script-src-elem / script-src-attr 로 따로 풀어 주지 않는다", () => {
    // 이 둘이 있으면 script-src 보다 먼저 적용되므로, 위 시험을 통과한 채로 구멍을 낼 수 있다.
    const d = directives(csp);
    expect(d["script-src-elem"]).toBeUndefined();
    expect(d["script-src-attr"]).toBeUndefined();
  });

  it("default-src 에도 스크립트로 번질 수 있는 출처가 없다", () => {
    // script-src 가 지워졌을 때 default-src 가 대신 쓰이므로 같이 지킨다.
    const d = directives(csp);
    const bad = ["data:", "blob:", "filesystem:", "'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:"];
    expect(d["default-src"]).toBeDefined();
    for (const b of bad) expect(d["default-src"]).not.toContain(b);
  });

  it("플러그인·base 주소·폼 전송은 막혀 있다", () => {
    const d = directives(csp);
    expect(d["object-src"]).toEqual(["'none'"]);
    expect(d["base-uri"]).toEqual(["'none'"]);
    expect(d["form-action"]).toEqual(["'none'"]);
  });

  it("Tauri 의 CSP 손질(nonce·hash 주입)을 끄지 않았다", () => {
    expect(conf?.app?.security?.dangerousDisableAssetCspModification ?? false).toBe(false);
  });
});

describe("directives() 자체", () => {
  it("같은 지시어가 두 번 나오면 첫 번째를 쓴다", () => {
    expect(directives("script-src 'self' data:; script-src 'self'")["script-src"]).toEqual(["'self'", "data:"]);
  });
  it("대소문자와 여분 공백을 흡수한다", () => {
    expect(directives("  Script-Src   'SELF'  ;; ")["script-src"]).toEqual(["'self'"]);
  });
});
