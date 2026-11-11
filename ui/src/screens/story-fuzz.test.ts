// 49차 답변 3(별도 과제): 서비스 응답의 필드가 비거나(null·"")·형이 틀리거나·템플릿 찌꺼기("{{x}}")여도
// 이야기 화면의 글자 만드는 함수가 던지지 않고, "undefined"·"NaN"·"[object …]" 같은 찌꺼기를 화면 글자로 내지 않는다.
import { describe, expect, it } from "vitest";
import {
  bareTitle, cardNote, chainKids, chainTitle, cmdlineText, emptyText, execRange, feedbackUnitText, isWindowsSigned,
  liveText, mergeItems, parseAutoNote, subjectName, tableOnly, triageCountsText, triageText,
} from "./story";
import { groupStories, summarizeGaps, diffShort } from "./story-group";
import { matches, parseFilter } from "./story-filter";

// 현실적인 어긋남: 판이 다른 서비스(필드 없음·null), 빈 글자, 템플릿 찌꺼기, 아주 긴 글자, 제어 문자, 셀 수 없는 수.
// 형이 통째로 다른 값(글자 자리에 객체)은 대상이 아니다 — 서비스는 서명·핀으로 확인한 우리 프로세스다.
const JUNK: unknown[] = [undefined, null, "", " ", "{{session_name}}", NaN, "x".repeat(5000), "\u0000\u202e<b>"];
/** 배열 자리: 없음·null 은 그대로, 수는 빈 배열, 글자는 한 칸짜리 배열로 */
const arr = (j: unknown) => (j == null ? j : typeof j === "number" ? [] : [j]);
const BAD = /undefined|NaN|\[object |null/;

/** 던지지 않고, 글자를 돌려주면 찌꺼기가 없어야 한다 — 어긋난 것을 모아 한 번에 보인다 */
const fails: string[] = [];
function probe(name: string, f: (j: any) => unknown): void {
  for (const j of JUNK) {
    const tag = `${name}(${typeof j === "string" ? JSON.stringify(j.slice(0, 12)) : String(j)})`;
    let out: unknown;
    try { out = f(j); } catch (e) { fails.push(`${tag} 던짐: ${String(e).slice(0, 60)}`); continue; }
    if (typeof out === "string" && !(typeof j === "string" && BAD.test(j)) && BAD.test(out)) fails.push(`${tag} → ${out.slice(0, 60)}`);
  }
}

describe("이야기 화면 — 빈 값·틀린 형 주입", () => {
  it("글자 만드는 함수", () => {
    probe("bareTitle", (j) => bareTitle(j));
    probe("subjectName", (j) => subjectName(j).text);
    probe("cmdlineText", (j) => cmdlineText(j));
    probe("feedbackUnitText", (j) => feedbackUnitText(j));
    probe("triageText", (j) => triageText(j));
    probe("triageText.state", (j) => triageText({ state: j, action: j, note: j } as never));
    probe("triageCountsText", (j) => triageCountsText(j));
    probe("triageCountsText.fields", (j) => triageCountsText({ new: j, investigated: j, acted: j, closed: j } as never));
    probe("emptyText", (j) => emptyText(j, j));
    probe("cardNote", (j) => cardNote(!!j, !!j, typeof j === "number" ? undefined : j));
    probe("chainKids", (j) => chainKids(arr(j) as never, j));
    probe("chainTitle", (j) => chainTitle(j, { parent: j, children: [], children_total: j }));
    probe("chainTitle.null", (j) => chainTitle(j, j == null ? j : ({ children: arr(j), children_total: j } as never)));
    probe("liveText", (j) => liveText({ running: j, pid: j, ended: j }));
    probe("execRange", (j) => execRange({ count: j, first_ts: j, last_ts: j }));
    probe("parseAutoNote", (j) => parseAutoNote(j));
    probe("diffShort", (j) => diffShort(j));
    expect(fails.splice(0)).toEqual([]);
  });
  it("묶기·거르기·판단 함수", () => {
    probe("tableOnly", (j) => tableOnly(j == null ? j : []));
    probe("isWindowsSigned", (j) => isWindowsSigned({ root_image: j, root_signature: j }));
    probe("isWindowsSigned.sig", (j) => isWindowsSigned({ root_image: j, root_signature: { sig_status: j } }));
    probe("mergeItems", (j) => mergeItems([{ label: j, value: j, edge_ids: [], sources: j == null ? j : [] }], !!j));
    probe("groupStories", (j) => groupStories([{ root: 1, title: j, level: j, chapter: j, last_ts: j, root_image: j } as never]));
    probe("summarizeGaps", (j) => summarizeGaps([{ from_ts: j, to_ts: j, events: j } as never]));
    probe("matches", (j) => matches({ level: j, chapter: j, last_ts: j, reached: j, triage: j } as never, parseFilter({ level: j, chapter: j, time: j }), 1_794_400_000));
    expect(fails.splice(0)).toEqual([]);
  });
});
