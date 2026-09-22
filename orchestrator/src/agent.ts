import type OpenAI from "openai";
import type { ToolRunner } from "./tools.js";

export interface MinimalClient {
  chat: { completions: { create(params: any, opts?: any): Promise<any> } };
}

export interface AgentResult {
  messages: any[];
  turns: number;
  tokens: number;
  toolCalls: Array<{ tool: string; args: string; ok: boolean }>;
  artifacts: number;
  stopReason: "done" | "max_turns" | "budget" | "aborted";
}

export async function runAgent(opts: {
  client: MinimalClient;
  model: string;
  system: string;
  user: string;
  tools: OpenAI.Chat.ChatCompletionTool[];
  runner: ToolRunner;
  maxTurns: number;
  budgetTokens: number;
  signal?: AbortSignal;
}): Promise<AgentResult> {
  const messages: any[] = [
    { role: "system", content: opts.system },
    { role: "user", content: opts.user },
  ];
  const toolCalls: AgentResult["toolCalls"] = [];
  let turns = 0;
  let tokens = 0;
  let artifacts = 0;

  while (true) {
    if (opts.signal?.aborted) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "aborted" };
    }
    if (turns >= opts.maxTurns) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "max_turns" };
    }

    const completion = await opts.client.chat.completions.create(
      {
        model: opts.model,
        messages,
        tools: opts.tools,
        parallel_tool_calls: false,
      },
      opts.signal ? { signal: opts.signal } : undefined,
    );
    turns += 1;
    tokens += completion.usage?.total_tokens ?? 0;

    const message = completion.choices?.[0]?.message;
    messages.push(message);

    const calls = message?.tool_calls ?? [];
    if (calls.length === 0) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "done" };
    }

    for (const c of calls) {
      const name = c.function.name;
      const raw = c.function.arguments ?? "{}";
      let args: Record<string, unknown> = {};
      try { args = JSON.parse(raw); } catch { /* malformed args reach the tool as {} */ }

      const out = await opts.runner.execute(name, args);
      toolCalls.push({ tool: name, args: raw, ok: out.ok });
      if (out.ok && (out.result as any)?.artifact) artifacts += 1;

      messages.push({
        role: "tool",
        tool_call_id: c.id,
        content: JSON.stringify(out.ok ? out.result : { denied: out.denied }),
      });
    }

    if (tokens >= opts.budgetTokens) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "budget" };
    }
  }
}
