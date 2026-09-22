import { describe, it, expect } from "vitest";
import { runAgentLoop, type LoopPhase } from "./agent-loop.js";
import type { LlmMessage, LlmResponse, ToolDef } from "./llm.js";

const base = { content: "", promptTokens: 1, completionTokens: 1, cachedTokens: 0, cost: 0, finishReason: "stop" };

/** LLM stub: emits `toolTurns` tool-calling turns, then answers with no tools. */
function stubLlm(toolTurns: number, seen: LlmMessage[][]) {
  let n = 0;
  return {
    complete: async (o: { messages: LlmMessage[]; tools?: ToolDef[] }): Promise<LlmResponse> => {
      seen.push(o.messages.map((m) => ({ ...m })));
      n += 1;
      if (n > toolTurns || (o.tools?.length ?? 0) === 0) return { ...base, content: "report", toolCalls: [] };
      return { ...base, toolCalls: [{ id: `c${n}`, type: "function", function: { name: "t", arguments: "{}" } }] };
    },
  };
}

const phases: LoopPhase[] = [
  { id: "alpha", brief: "do alpha", skills: ["skill-a"], turnShare: 0.5 },
  { id: "beta", brief: "do beta", skills: ["skill-b"], turnShare: 0.5 },
];

const common = {
  model: "m",
  system: "s",
  objective: "o",
  tools: [{ type: "function", function: { name: "t", description: "d", parameters: {} } }] as ToolDef[],
  executeTool: async () => "ok",
  loadSkill: (n: string) => `PLAYBOOK BODY FOR ${n}`,
};

describe("phased loop", () => {
  it("injects each phase's playbooks and records per-phase turns", async () => {
    const seen: LlmMessage[][] = [];
    const res = await runAgentLoop({ ...common, llm: stubLlm(100, seen) as never, maxTurns: 8, phases });

    const all = JSON.stringify(seen.at(-1));
    expect(all).toContain("PHASE ALPHA");
    expect(all).toContain("PLAYBOOK BODY FOR skill-a");
    expect(all).toContain("PHASE BETA");
    expect(all).toContain("PLAYBOOK BODY FOR skill-b");

    // 8 turns split 50/50, and the cap is respected
    expect(res.phaseTurns.alpha).toBe(4);
    expect(res.phaseTurns.beta).toBe(4);
    expect(res.turns).toBe(8);
  });

  it("treats 'no tool calls' as end of phase, not end of engagement", async () => {
    const seen: LlmMessage[][] = [];
    // stub answers without tools on the very first turn
    const res = await runAgentLoop({ ...common, llm: stubLlm(0, seen) as never, maxTurns: 8, phases });
    // it must still have entered the second phase
    expect(JSON.stringify(seen)).toContain("PHASE BETA");
    expect(res.phaseTurns.alpha).toBe(1);
    expect(res.phaseTurns.beta).toBe(1);
  });

  it("still runs unphased when no phases are given (backward compatible)", async () => {
    const seen: LlmMessage[][] = [];
    const res = await runAgentLoop({ ...common, llm: stubLlm(0, seen) as never, maxTurns: 5 });
    expect(res.finalText).toBe("report");
    expect(res.phaseTurns).toEqual({});
    expect(JSON.stringify(seen)).not.toContain("PHASE ");
  });
});
