/**
 * Agent loop — "the LLM proposes, deterministic code decides".
 *
 * Runs a bounded tool-calling loop: the model proposes tool calls; the caller's
 * `executeTool` (Tether-gated, deterministic) executes them; results are fed
 * back until the model emits a final answer (no more tool calls).
 */

import type { LlmMessage, OpenRouterLlm, ToolDef } from "./llm.js";

export interface AgentLoopOptions {
  llm: OpenRouterLlm;
  model: string;
  system: string;
  objective: string;
  tools: ToolDef[];
  executeTool: (name: string, args: Record<string, unknown>) => Promise<string>;
  maxTurns?: number;
  temperature?: number;
}

export interface AgentLoopResult {
  finalText: string;
  cost: number;
  promptTokens: number;
  completionTokens: number;
  turns: number;
  toolCalls: number;
}

export async function runAgentLoop(opts: AgentLoopOptions): Promise<AgentLoopResult> {
  const maxTurns = opts.maxTurns ?? 12;
  const messages: LlmMessage[] = [
    { role: "system", content: opts.system },
    { role: "user", content: opts.objective },
  ];

  let cost = 0;
  let promptTokens = 0;
  let completionTokens = 0;
  let toolCalls = 0;

  for (let turn = 0; turn < maxTurns; turn++) {
    const resp = await opts.llm.complete({
      model: opts.model,
      messages,
      tools: opts.tools,
      temperature: opts.temperature,
    });
    cost += resp.cost;
    promptTokens += resp.promptTokens;
    completionTokens += resp.completionTokens;

    if (resp.toolCalls.length === 0) {
      return { finalText: resp.content, cost, promptTokens, completionTokens, turns: turn + 1, toolCalls };
    }

    messages.push({ role: "assistant", content: resp.content, tool_calls: resp.toolCalls });
    for (const tc of resp.toolCalls) {
      let result: string;
      try {
        const args = JSON.parse(tc.function.arguments || "{}");
        result = await opts.executeTool(tc.function.name, args);
      } catch (e) {
        result = `ERROR: ${(e as Error).message}`;
      }
      toolCalls++;
      messages.push({ role: "tool", content: result.slice(0, 16_000), tool_call_id: tc.id, name: tc.function.name });
    }
  }

  // Turn budget exhausted — force a final synthesis without tools.
  const final = await opts.llm.complete({
    model: opts.model,
    messages: [...messages, { role: "user", content: "Turn budget exhausted. Provide your final findings now as a concise report." }],
    tools: [],
  });
  return {
    finalText: final.content,
    cost: cost + final.cost,
    promptTokens: promptTokens + final.promptTokens,
    completionTokens: completionTokens + final.completionTokens,
    turns: maxTurns,
    toolCalls,
  };
}
