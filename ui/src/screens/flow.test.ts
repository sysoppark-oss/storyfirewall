import { describe, it, expect } from "vitest";
import { flowColumn, railSteps, RAIL_NAMES } from "./flow";

const b = (side: "origin" | "action", depth: number, kind: string, rel: string | null = null) => ({ side, depth, node: { kind }, via: rel ? { rel } : null });

describe("흐름 보기 열 배치(D049)", () => {
  it("주인공·조상·결과가 네 열로 나뉜다", () => {
    expect(flowColumn(b("action", 0, "process"))).toBe("process");
    expect(flowColumn(b("action", 0, "file"))).toBe("file");
    expect(flowColumn(b("origin", 1, "process", "spawned"))).toBe("origin");
    expect(flowColumn(b("origin", 1, "remote", "downloaded"))).toBe("origin");
    expect(flowColumn(b("origin", 1, "file", "executed_as"))).toBe("file");
    expect(flowColumn(b("action", 1, "process", "spawned"))).toBe("process");
    expect(flowColumn(b("action", 1, "remote", "connected"))).toBe("did");
    expect(flowColumn(b("action", 1, "autorun", "registered"))).toBe("did");
    expect(flowColumn(b("action", 2, "command", "ran"))).toBe("did");
    // 주인공이 만든 파일은 "한 일", 주인공 파일에서 실행된 것은 프로세스
    expect(flowColumn(b("action", 1, "file", "wrote"))).toBe("did");
  });
});

describe("장 레일", () => {
  it("다섯 장, 사실 문장이 없는 장은 꺼짐, 5장은 파괴 징후에서", () => {
    const steps = railSteps({
      reached: [1, 2, 4],
      sentences: [
        { text: "b 실행", ts: 20, edge_ids: [2], chapter: 2 },
        { text: "a 실행", ts: 10, edge_ids: [1], chapter: 2 },
        { text: "접속", ts: 30, edge_ids: [3], chapter: 4 },
      ],
      destroy: { sentence: "그림자 복사본 삭제", ts: 40, edge_id: 9 },
    });
    expect(steps.map((s) => s.name)).toEqual(RAIL_NAMES);
    expect(steps[0]!.on).toBe(true); // reached 에 있으나 문장 없음 → 켜짐, 글자 없음
    expect(steps[0]!.text).toBeNull();
    expect(steps[1]!.text).toBe("a 실행"); // 그 장의 가장 이른 문장
    expect(steps[1]!.edge).toBe(1);
    expect(steps[2]!.on).toBe(false);
    expect(steps[4]!.on).toBe(true);
    expect(steps[4]!.edge).toBe(9);
  });
  it("파괴 징후가 없으면 5장은 꺼짐", () => {
    expect(railSteps({ sentences: [] })[4]!.on).toBe(false);
  });
});

describe("도메인·접속지 합치기", () => {
  it("같은 호스트의 도메인 노드는 접속지 노드로", async () => {
    const { domainAliases } = await import("./flow");
    const n = (id: number, kind: string, label: string) => ({ node: { id, kind, key: label, label } });
    const m = domainAliases([n(1, "remote", "mail.google.com:443"), n(2, "domain", "Mail.Google.com"), n(3, "domain", "other.net")]);
    expect(m.get(2)).toBe(1);
    expect(m.has(3)).toBe(false);
  });
});
