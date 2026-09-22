/**
 * Agent loop — "the LLM proposes, deterministic code decides".
 *
 * Runs a bounded tool-calling loop: the model proposes tool calls; the caller's
 * `executeTool` (Tether-gated, deterministic) executes them; results are fed
 * back until the model emits a final answer (no more tool calls).
 *
 * With `phases`, the engagement is driven as a sequence of segments. Each phase
 * gets a FIXED share of the turn budget and has its operator playbooks injected
 * at phase start. Both are deliberate: leaving skill consultation to the model
 * meant it never happened, and leaving breadth to a prompt request meant the
 * agent sank its whole budget into the first interesting endpoint. Running out
 * of tool calls ends the PHASE, not the engagement.
 */

import type { LlmMessage, OpenRouterLlm, ToolDef } from "./llm.js";
import type { SpanRecorder } from "./langfuse.js";

export interface LoopPhase {
  id: string;
  /** What this phase must accomplish. */
  brief: string;
  /** Skill names whose playbooks are injected when the phase starts. */
  skills?: string[];
  /** Share of the total turn budget, 0..1. */
  turnShare: number;
}

export interface AgentLoopOptions {
  llm: OpenRouterLlm;
  model: string;
  system: string;
  objective: string;
  tools: ToolDef[];
  executeTool: (name: string, args: Record<string, unknown>) => Promise<string>;
  maxTurns?: number;
  temperature?: number;
  /** Stable key so repeated prefixes hit the same provider prompt cache. */
  cacheKey?: string;
  /** Tool results older than this many turns are collapsed to a stub. */
  keepFullToolResults?: number;
  /** Optional Langfuse recorder — emits a generation per turn and a span per tool call. */
  rec?: SpanRecorder;
  /** Drive the engagement as budgeted phases instead of one open-ended segment. */
  phases?: LoopPhase[];
  /** Loads a skill playbook for injection (usually readSkill from skills.ts). */
  loadSkill?: (name: string) => string;
  /** Max chars of each injected playbook. */
  skillCharBudget?: number;
}

export interface AgentLoopResult {
  finalText: string;
  cost: number;
  promptTokens: number;
  completionTokens: number;
  /** Prompt tokens served from cache across the run. */
  cachedTokens: number;
  turns: number;
  toolCalls: number;
  /** Turns actually spent per phase (empty when running unphased). */
  phaseTurns: Record<string, number>;
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
  let cachedTokens = 0;
  let toolCalls = 0;
  let turnsUsed = 0;
  let lastText = "";
  const phaseTurns: Record<string, number> = {};
  const keepFull = opts.keepFullToolResults ?? 6;
  const skillBudget = opts.skillCharBudget ?? 3500;

  /**
   * Collapse tool results from older turns to a one-line stub. The full text
   * already lives in a spill file (see LlmRunner.offload), so the agent can
   * re-read it on demand instead of carrying it in every request.
   */
  const trimHistory = (): void => {
    const toolIdx = messages.reduce<number[]>((acc, m, i) => (m.role === "tool" ? [...acc, i] : acc), []);
    const stale = toolIdx.slice(0, Math.max(0, toolIdx.length - keepFull));
    for (const i of stale) {
      const m = messages[i]!;
      const body = m.content ?? "";
      if (body.length <= 400) continue;
      const spill = body.match(/^FULL OUTPUT FILE: (.+)$/m)?.[1]?.trim();
      m.content =
        `${body.slice(0, 300)}\n…[older result trimmed from context` +
        (spill ? `; full text in ${spill} — re-read it with run_command before citing it as evidence]` : `]`);
    }
  };

  const complete = async (msgs: LlmMessage[], tools: ToolDef[]) =>
    opts.llm.complete({
      model: opts.model,
      messages: msgs,
      tools,
      temperature: opts.temperature,
      ...(opts.cacheKey ? { cacheKey: opts.cacheKey } : {}),
    });

  /** Run up to `budget` turns; returns why it stopped. */
  const runSegment = async (budget: number, label: string): Promise<"no_tools" | "budget"> => {
    for (let i = 0; i < budget; i++) {
      if (turnsUsed >= maxTurns) return "budget";
      const turnNo = turnsUsed;
      turnsUsed += 1;
      phaseTurns[label] = (phaseTurns[label] ?? 0) + 1;

      const promptSnapshot = messages.map((m) => ({ role: m.role, content: m.content, name: m.name, tool_calls: m.tool_calls }));
      const resp = await complete(messages, opts.tools);
      cost += resp.cost;
      promptTokens += resp.promptTokens;
      completionTokens += resp.completionTokens;
      cachedTokens += resp.cachedTokens ?? 0;
      lastText = resp.content || lastText;

      await opts.rec?.generation(`turn-${turnNo}`, {
        input: promptSnapshot,
        output: { content: resp.content, tool_calls: resp.toolCalls, finish_reason: resp.finishReason },
        model: opts.model,
        tokens: { input: resp.promptTokens, output: resp.completionTokens },
        metadata: { turn: turnNo, phase: label, toolCallCount: resp.toolCalls.length },
      });

      if (resp.toolCalls.length === 0) return "no_tools";

      messages.push({ role: "assistant", content: resp.content, tool_calls: resp.toolCalls });
      for (const tc of resp.toolCalls) {
        let result: string;
        let parsedArgs: unknown;
        try {
          const args = JSON.parse(tc.function.arguments || "{}");
          parsedArgs = args;
          result = await opts.executeTool(tc.function.name, args);
        } catch (e) {
          result = `ERROR: ${(e as Error).message}`;
          parsedArgs = tc.function.arguments;
        }
        toolCalls++;
        await opts.rec?.toolSpan(`tool:${tc.function.name}`, {
          input: parsedArgs,
          output: result.slice(0, 16_000),
          metadata: { turn: turnNo, phase: label, toolCallId: tc.id },
        });
        messages.push({ role: "tool", content: result.slice(0, 16_000), tool_call_id: tc.id, name: tc.function.name });
      }
      trimHistory();
    }
    return "budget";
  };

  if (opts.phases?.length) {
    for (const phase of opts.phases) {
      const playbooks = (phase.skills ?? [])
        .map((n) => {
          const body = opts.loadSkill?.(n) ?? "";
          return body && !body.startsWith("ERROR") ? `### PLAYBOOK: ${n}\n${body.slice(0, skillBudget)}` : "";
        })
        .filter(Boolean)
        .join("\n\n");

      messages.push({
        role: "user",
        content:
          `== PHASE ${phase.id.toUpperCase()} ==\n${phase.brief}\n\n` +
          `You have a fixed budget for this phase; when it is spent you move on whether or not you are finished, ` +
          `so prioritise breadth of coverage over depth on any single target. Record findings as you go.` +
          (playbooks ? `\n\nApply these operator playbooks:\n\n${playbooks}` : ""),
      });

      const budget = Math.max(1, Math.round(maxTurns * phase.turnShare));
      await runSegment(budget, phase.id);
      if (turnsUsed >= maxTurns) break;
    }
  } else {
    const why = await runSegment(maxTurns, "main");
    if (why === "no_tools") {
      return { finalText: lastText, cost, promptTokens, completionTokens, cachedTokens, turns: turnsUsed, toolCalls, phaseTurns: {} };
    }
  }

  // Final synthesis without tools.
  const finalMessages: LlmMessage[] = [
    ...messages,
    {
      role: "user",
      content:
        "Engagement budget spent. Produce your final report NOW as the JSON array described in your instructions. " +
        "Include every confirmed issue as its own finding, and afterwards list any endpoints from your inventory you never reached.",
    },
  ];
  const final = await complete(finalMessages, []);
  await opts.rec?.generation("final-synthesis", {
    input: finalMessages.map((m) => ({ role: m.role, content: m.content, name: m.name, tool_calls: m.tool_calls })),
    output: { content: final.content, finish_reason: final.finishReason },
    model: opts.model,
    tokens: { input: final.promptTokens, output: final.completionTokens },
    metadata: { phase: "final-synthesis" },
  });

  return {
    finalText: final.content || lastText,
    cost: cost + final.cost,
    promptTokens: promptTokens + final.promptTokens,
    completionTokens: completionTokens + final.completionTokens,
    cachedTokens: cachedTokens + (final.cachedTokens ?? 0),
    turns: turnsUsed,
    toolCalls,
    phaseTurns,
  };
}
