// CSP 고정 시험 — 화면(webview)이 스크립트를 어디서 받아 실행할 수 있는지를 설정 파일에서 직접 읽어 못 박는다.
// 배경: CVE-2026-95626(GHSA-6vxm-x265-58qf). Tauri 가 script-src 에 nonce 를 넣어도, 같은 줄에 data: 나 blob: 이
// 있으면 CSP Level 3 규칙상 그쪽이 그대로 통해서 nonce 보호가 무력해진다. 지금 설정은 'self' 하나라 해당이 없다.
// 이 시험은 누가 나중에 편의로 출처를 넓히는 순간 빌드에서 드러나게 한다.
//
// 방식: 금지 목록이 아니라 허용 목록. CSP 전체(지시어 이름 집합과 값)가 아래 EXPECTED 와 정확히 같아야 한다.
// CSP 를 바꿔야 하면 이 표를 함께 고친다 — 그 차이가 검토 대상이다.
//
// 별도 Claude 검수(2026-11-26)에서 드러난 것을 반영:
//  - Tauri 는 CSP 문자열을 ';' 로 쪼개 HashMap 에 넣고 다시 조립한다(tauri-utils config.rs). 같은 지시어가 두 번이면
//    '마지막'이 남고, 대소문자만 다른 이름은 둘 다 남아 순서가 실행마다 달라진다. 브라우저 규칙(첫 번째)으로 읽으면 속는다
//    → 중복·대문자 이름은 그 자체로 거부한다.
//  - tauri.conf.json 말고도 병합되는 설정 파일(tauri.windows.conf.json 등)로 통째로 덮을 수 있다 → 다른 파일에 app 이 있으면 거부.
//  - 원격 주소를 띄우면 이 CSP 는 붙지 않는다 → frontendDist·창 url·capability 의 remote 를 함께 고정.
// 이 시험이 못 보는 것: CI 가 빌드 때 만들어 --config 로 넘기는 설정(tauri.release.conf.json, tauri.devbuild.conf.json)과
// TAURI_CONFIG 환경 변수. 그쪽은 작업 흐름 파일에서 app 항목을 넣지 않는 것으로 지킨다.
import { describe, expect, it } from "vitest";
// @ts-ignore — node 내장 모듈(@types/node 없이 시험에서만 씀, word.test.ts 와 같은 방식)
import { readFileSync, readdirSync } from "node:fs";
// @ts-ignore
import { fileURLToPath } from "node:url";

const dir = fileURLToPath(new URL("../src-tauri/", import.meta.url));
const read = (name: string): any => JSON.parse(readFileSync(dir + name, "utf8"));
const conf = read("tauri.conf.json");

const EXPECTED: Record<string, string[]> = {
  "default-src": ["'self'"],
  "script-src": ["'self'"],
  "style-src": ["'self'"],
  "img-src": ["'self'", "data:"],
  "connect-src": ["ipc:", "http://ipc.localhost"],
  "font-src": ["'self'"],
  "object-src": ["'none'"],
  "base-uri": ["'none'"],
  "frame-ancestors": ["'none'"],
  "form-action": ["'none'"],
};

// "a b; c d" -> [["a", ["b"]], ["c", ["d"]]]. 이름·값을 손대지 않고 그대로 돌려준다(대소문자·중복을 호출 쪽이 판단).
function parse(csp: string): [string, string[]][] {
  const out: [string, string[]][] = [];
  for (const part of csp.split(";")) {
    const words = part.trim().split(/\s+/).filter(Boolean);
    if (words.length === 0) continue;
    out.push([words[0] ?? "", words.slice(1)]);
  }
  return out;
}

// 문제를 사람이 읽을 문장으로 모아 돌려준다. 빈 배열이면 통과.
function problems(csp: unknown, expected: Record<string, string[]>): string[] {
  if (typeof csp !== "string" || csp.length === 0) return ["csp 가 문자열이 아니다(없거나 객체 형식)"];
  // 쉼표는 '정책을 하나 더 붙이는' 구분자다. 우리 값에는 쉼표가 들어갈 일이 없다.
  if (csp.includes(",")) return ["csp 에 쉼표가 있다(정책이 둘로 나뉜다)"];
  const bad: string[] = [];
  const seen = new Set<string>();
  for (const [name, values] of parse(csp)) {
    if (name !== name.toLowerCase()) bad.push(`지시어 이름에 대문자: ${name}`);
    const key = name.toLowerCase();
    if (seen.has(key)) bad.push(`같은 지시어가 두 번: ${key}`);
    seen.add(key);
    const want = expected[key];
    if (!want) { bad.push(`표에 없는 지시어: ${key}`); continue; }
    if (values.length !== want.length || values.some((v, i) => v !== want[i])) bad.push(`${key} 값이 다르다: ${values.join(" ")}`);
  }
  for (const key of Object.keys(expected)) if (!seen.has(key)) bad.push(`빠진 지시어: ${key}`);
  return bad;
}

describe("tauri.conf.json 의 CSP", () => {
  const sec = conf?.app?.security ?? {};

  it("표(EXPECTED)와 정확히 같다", () => {
    expect(problems(sec.csp, EXPECTED)).toEqual([]);
  });

  it("개발용 CSP 를 따로 두지 않는다", () => {
    expect(sec.devCsp).toBeUndefined();
  });

  it("Tauri 의 CSP 손질(nonce·hash 주입)을 끄지 않았다", () => {
    expect(sec.dangerousDisableAssetCspModification ?? false).toBe(false);
  });
});

describe("CSP 가 붙지 않는 길이 없다", () => {
  it("화면 묶음은 로컬 폴더다(원격 주소가 아니다)", () => {
    expect(conf?.build?.frontendDist).toBe("../dist");
  });

  it("설정에 적힌 창은 주소(url)를 따로 지정하지 않는다", () => {
    for (const w of conf?.app?.windows ?? []) expect(w.url).toBeUndefined();
  });

  it("권한 묶음은 default 하나이고, 원격 주소에 열어 준 것이 없다", () => {
    expect(conf?.app?.security?.capabilities).toEqual(["default"]);
    const files = (readdirSync(dir + "capabilities") as string[]).sort();
    expect(files).toEqual(["default.json"]);
    expect(read("capabilities/default.json").remote).toBeUndefined();
  });

  it("전역 Tauri 객체를 화면에 내놓지 않는다", () => {
    expect(conf?.app?.withGlobalTauri ?? false).toBe(false);
  });

  it("병합되는 다른 설정 파일이 app 항목을 덮지 않는다", () => {
    // tauri.<플랫폼>.conf.json, tauri.conf.json5, Tauri.toml 은 주 설정에 병합된다. 지금은 설치 파일용(bundle 만) 하나뿐이다.
    const names = (readdirSync(dir) as string[]).filter((n) => /^tauri\..*(json5?|toml)$/i.test(n) || /^tauri\.toml$/i.test(n)).sort();
    expect(names).toEqual(["tauri.conf.json", "tauri.installer.conf.json"]);
    const inst = read("tauri.installer.conf.json");
    expect(Object.keys(inst).filter((k) => k !== "$schema")).toEqual(["bundle"]);
  });
});

describe("problems() 가 잡아야 하는 것", () => {
  const ok = "default-src 'self'; script-src 'self'";
  const exp = { "default-src": ["'self'"], "script-src": ["'self'"] };
  const cases: [string, string][] = [
    ["뒤에 넓은 script-src 를 한 번 더(Tauri 는 마지막을 쓴다)", ok + "; script-src 'self' blob: data:"],
    ["대문자 이름으로 한 번 더", ok + "; Script-Src 'self' blob:"],
    ["script-src 에 data:", "default-src 'self'; script-src 'self' data:"],
    ["script-src 에 blob:", "default-src 'self'; script-src 'self' blob:"],
    ["script-src 에 'unsafe-inline'", "default-src 'self'; script-src 'self' 'unsafe-inline'"],
    ["script-src-elem 추가", ok + "; script-src-elem *"],
    ["worker-src 추가", ok + "; worker-src blob:"],
    ["frame-src 추가", ok + "; frame-src https:"],
    ["default-src 에 호스트 와일드카드", "default-src 'self' https://*; script-src 'self'"],
    ["script-src 삭제", "default-src 'self'"],
    ["쉼표로 정책 하나 더", ok + ", script-src *"],
    ["탭으로 붙인 출처", "default-src 'self'; script-src 'self'\tblob:"],
  ];
  for (const [name, csp] of cases) it(name, () => expect(problems(csp, exp)).not.toEqual([]));

  it("객체 형식·빈 값은 거부한다", () => {
    expect(problems({ "script-src": "'self'" }, exp)).not.toEqual([]);
    expect(problems(null, exp)).not.toEqual([]);
    expect(problems("", exp)).not.toEqual([]);
  });

  it("같은 내용은 통과한다(끝 세미콜론·여분 공백 허용)", () => {
    expect(problems("  default-src   'self' ;script-src 'self'; ", exp)).toEqual([]);
  });
});
