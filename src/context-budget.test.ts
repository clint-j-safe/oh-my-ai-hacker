import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LlmRunner } from "./llm-runner.js";
import { parseScope } from "./scope.js";
import { runAgentLoop } from "./agent-loop.js";
import type { LlmMessage, LlmResponse, ToolDef } from "./llm.js";

const scope = parseScope({ inScopeUrls: ["http://example.test"] });

function runner(workspaceRoot: string, inlineLimit: number) {
  return new LlmRunner({ apiKey: "k", model: "m", system: "s", scope, workspaceRoot, inlineLimit }) as unknown as {
    executeTool: (n: string, a: Record<string, unknown>) => Promise<string>;
  };
}

describe("output offloading", () => {
  it("spills oversized tool output to a file and keeps only a head inline", async () => {
    const ws = mkdtempSync(join(tmpdir(), "sahw-off-"));
    const out = await runner(ws, 200).executeTool("run_command", {
      command: `node -e "console.log('X'.repeat(4000))"`,
    });

    expect(out.length).toBeLessThan(1000); // context stays bounded
    const path = out.match(/^FULL OUTPUT FILE: (.+)$/m)?.[1];
    expect(path).toBeTruthy();
    // the path must not swallow surrounding punctuation
    expect(path!.endsWith(".txt")).toBe(true);
    expect(readFileSync(path!, "utf8").length).toBeGreaterThan(4000);
  });

  it("leaves small tool output untouched", async () => {
    const ws = mkdtempSync(join(tmpdir(), "sahw-off-"));
    const out = await runner(ws, 2000).executeTool("run_command", { command: "echo hi" });
    expect(out).not.toContain("FULL OUTPUT FILE");
    expect(out).toContain("hi");
  });
});

describe("history trimming", () => {
  it("collapses stale tool results to a stub that points at the spill file", async () => {
    const seen: LlmMessage[][] = [];
    let turn = 0;
    const big = `head\n…[9999 more chars offloaded]\nFULL OUTPUT FILE: /tmp/sahw-sandbox/spill-http-1.txt\n${"y".repeat(900)}`;
    const llm = {
      complete: async (o: { messages: LlmMessage[] }): Promise<LlmResponse> => {
        seen.push(o.messages.map((m) => ({ ...m })));
        turn += 1;
        const base = { content: "", promptTokens: 1, completionTokens: 1, cachedTokens: 0, cost: 0, finishReason: "stop" };
        if (turn > 4) return { ...base, content: "done", toolCalls: [] };
        return { ...base, toolCalls: [{ id: `c${turn}`, type: "function", function: { name: "t", arguments: "{}" } }] };
      },
    };
    const res = await runAgentLoop({
      llm: llm as never,
      model: "m",
      system: "s",
      objective: "o",
      tools: [] as ToolDef[],
      executeTool: async () => big,
      maxTurns: 10,
      keepFullToolResults: 1,
    });

    expect(res.finalText).toBe("done");
    const last = seen.at(-1)!;
    const toolMsgs = last.filter((m) => m.role === "tool");
    expect(toolMsgs.length).toBeGreaterThan(1);
    const stale = toolMsgs.slice(0, -1);
    for (const m of stale) {
      expect(m.content).toContain("older result trimmed from context");
      expect(m.content).toContain("/tmp/sahw-sandbox/spill-http-1.txt");
      expect(m.content!.length).toBeLessThan(big.length);
    }
    // the most recent result is kept in full
    expect(toolMsgs.at(-1)!.content).toBe(big);
  });
});
