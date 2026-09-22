import type OpenAI from "openai";
import { startActiveObservation } from "@langfuse/tracing";
import type { ToolRunner, ToolResult } from "./tools.js";

/**
 * THE OFFLOAD LAW. Tool results must never be fed back to the model in full.
 * One fetch of a bundled JS asset is hundreds of KB; feeding that into the message
 * array consumed a 120k-token budget inside five turns and killed a run that was
 * otherwise reasoning correctly. The artifact store already holds the verbatim,
 * hashed response, so the model gets status + headers + a bounded body preview +
 * the artifact hash, and calls read_artifact when it genuinely needs more.
 *
 * Headers are NEVER truncated: they are small, and several finding classes live
 * entirely in them. Only the body is capped.
 */
const PREVIEW_BYTES = Math.max(
  256, Number(process.env.SAHW_TOOL_PREVIEW_BYTES ?? 2000) || 2000);
const ARTIFACT_PREVIEW_BYTES = Math.max(
  512, Number(process.env.SAHW_ARTIFACT_PREVIEW_BYTES ?? 8000) || 8000);

function forModel(result: unknown): unknown {
  const r = result as any;
  // An http_request capture: keep the whole envelope, bound the body.
  if (r && r.response && r.artifact) {
    const body: string = r.response.body ?? "";
    const truncated = body.length > PREVIEW_BYTES;
    return {
      request: r.request,
      response: {
        status: r.response.status,
        headers: r.response.headers,
        body_preview: truncated ? body.slice(0, PREVIEW_BYTES) : body,
        body_bytes: body.length,
        truncated,
      },
      artifact_sha256: r.artifact.sha256,
      ms: r.ms,
      ...(truncated
        ? { note: `body truncated to ${PREVIEW_BYTES} of ${body.length} bytes — call read_artifact with artifact_sha256 for the full response` }
        : {}),
    };
  }
  // A read_artifact result: the model asked for this, so allow more, still bounded.
  if (r && typeof r.content === "string" && r.content.length > ARTIFACT_PREVIEW_BYTES) {
    return {
      content: r.content.slice(0, ARTIFACT_PREVIEW_BYTES),
      content_bytes: r.content.length,
      truncated: true,
    };
  }
  return result;
}

// Header VALUES that must never reach telemetry: they carry live credentials (bearer
// tokens, session/auth cookies). The header NAME is kept — its mere presence is
// itself useful signal, and several finding classes (missing/odd auth headers,
// cookie flags) live entirely in header names and OTHER header values.
const SECRET_HEADER_NAMES = new Set(["authorization", "cookie", "set-cookie"]);

function redactHeaders(headers: Record<string, string> | undefined | null): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) {
    out[k] = SECRET_HEADER_NAMES.has(k.toLowerCase()) ? "<redacted>" : v;
  }
  return out;
}

/**
 * What a tool-call span records as its `input`. Pure and exported so redaction can
 * be asserted directly against a span payload, without a live Langfuse exporter.
 */
export function toolSpanInput(args: Record<string, unknown>): Record<string, unknown> {
  if (!args) return {};
  if (typeof args.headers !== "object" || args.headers === null) return { ...args };
  return { ...args, headers: redactHeaders(args.headers as Record<string, string>) };
}

/**
 * What a tool-call span records as its `output`. Mirrors forModel()'s Offload Law
 * below, but for telemetry rather than the model: full response headers (small,
 * several finding classes live entirely in them, so they are kept — with secret
 * VALUES redacted), body SIZE and the artifact hash so the verbatim bytes stay
 * reachable via the artifact store, and NEVER the response body itself. A denied
 * call is recorded as a denial, with its kind, so a Tether policy denial reads as
 * the security event it is, not a silent no-op.
 */
export function toolSpanOutput(out: ToolResult): Record<string, unknown> {
  if (!out.ok) return { denied: out.denied, kind: out.kind };
  const r = out.result as any;
  if (r && r.response && r.artifact) {
    const body: string = r.response.body ?? "";
    return {
      status: r.response.status,
      headers: redactHeaders(r.response.headers),
      body_bytes: body.length,
      artifact_sha256: r.artifact.sha256,
      ms: r.ms,
    };
  }
  if (r && typeof r.content === "string") {
    return { content_bytes: r.content.length };
  }
  return {};
}

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
  /**
   * Continue an existing conversation (e.g. across multiple findings in one beat)
   * instead of starting fresh from system/user. When provided, system/user are
   * ignored — the caller is responsible for the conversation already containing a
   * system message. The array is mutated in place AND returned as
   * AgentResult.messages, so a caller can pass it straight back in for the next call.
   */
  messages?: any[];
}): Promise<AgentResult> {
  const messages: any[] = opts.messages ?? [
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

      const out = await startActiveObservation(`tool:${name}`, async (span) => {
        span.update({ input: toolSpanInput(args) });
        const result = await opts.runner.execute(name, args);
        span.update({
          output: toolSpanOutput(result),
          ...(result.ok ? {} : { level: "WARNING" as const }),
        });
        return result;
      });
      toolCalls.push({ tool: name, args: raw, ok: out.ok });
      if (out.ok && (out.result as any)?.artifact) artifacts += 1;

      messages.push({
        role: "tool",
        tool_call_id: c.id,
        content: JSON.stringify(
          out.ok ? forModel(out.result) : { denied: out.denied, kind: (out as any).kind }),
      });
    }

    if (tokens >= opts.budgetTokens) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "budget" };
    }
  }
}
