import { describe, it, expect } from "vitest";
import { runEngagement } from "./run-engagement.js";
import type { AgentRunner, AgentResult } from "./orchestrator.js";

const TOK = { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } };

const noop: AgentRunner = {
  async run(): Promise<AgentResult> {
    return { costUsd: 0.001, tokens: TOK, findings: [] };
  },
};

describe("runEngagement", () => {
  it("refuses to run without authorization", async () => {
    await expect(
      runEngagement({
        scope: { inScopeUrls: ["http://x"] },
        budget: { usd: 1, turns: 1, tokens: 100 },
        impactLevel: "L2-readonly",
        authorization: { ref: "", window: { start: "", end: "" } },
        runner: noop,
      }),
    ).rejects.toThrow(/authorization/i);
  });

  it("refuses to run with an empty scope", async () => {
    await expect(
      runEngagement({
        scope: { inScopeUrls: [] },
        budget: { usd: 1, turns: 1, tokens: 100 },
        impactLevel: "L2-readonly",
        authorization: { ref: "A-1", window: { start: "2026-01-01T00:00Z", end: "2026-01-02T00:00Z" } },
        runner: noop,
      }),
    ).rejects.toThrow(/in-scope/i);
  });

  it("rejects a non-http(s) scope URL", async () => {
    await expect(
      runEngagement({
        scope: { inScopeUrls: ["ftp://x"] },
        budget: { usd: 1, turns: 1, tokens: 100 },
        impactLevel: "L2-readonly",
        authorization: { ref: "A-1", window: { start: "2026-01-01T00:00Z", end: "2026-01-02T00:00Z" } },
        runner: noop,
      }),
    ).rejects.toThrow(/http/i);
  });

  it("runs the four phases and echoes authorization", async () => {
    const result = await runEngagement({
      scope: { inScopeUrls: ["http://139.59.15.10:3000"] },
      budget: { usd: 10, turns: 10, tokens: 10_000 },
      impactLevel: "L2-readonly",
      authorization: { ref: "A-42", window: { start: "2026-01-01T00:00Z", end: "2026-01-02T00:00Z" } },
      runner: noop,
    });
    expect(result.authorization.ref).toBe("A-42");
    expect(result.run.exit).toBe("completed");
    expect(result.run.phasesRun).toEqual([1, 2, 3, 4]);
  });
});
