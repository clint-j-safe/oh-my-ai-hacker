import type OpenAI from "openai";
import { startActiveObservation } from "@langfuse/tracing";
import type { ToolRunner, ToolResult } from "./tools.js";
import { auditTarget } from "./tether.js";

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
// grep_artifact's own caps (GREP_LINE_MAX_CHARS / GREP_MAX_MATCHES_CEILING /
// GREP_MAX_CONTEXT_LINES in tools.ts) already bound a single result, but their
// product is still large enough (100 matches x 10 lines of context each side x 400
// chars) to be worth a second, coarser backstop here — the Offload Law applies to
// every tool result, grep_artifact included, not just http_request/read_artifact.
const GREP_RESULT_MAX_CHARS = Math.max(
  1000, Number(process.env.SAHW_GREP_RESULT_MAX_CHARS ?? 20000) || 20000);
// skill_run artifacts can be arbitrarily large (severity-calibration over hundreds of
// findings, a full crawl map, ...) for the exact reason http_request bodies can: the
// model gets a bounded preview of the validated artifact plus its sha256, and calls
// read_artifact/grep_artifact against that hash when it genuinely needs more.
const SKILL_SUMMARY_MAX_CHARS = Math.max(
  512, Number(process.env.SAHW_SKILL_SUMMARY_MAX_CHARS ?? 4000) || 4000);

function isGrepResult(r: any): boolean {
  return r && Array.isArray(r.matches) && typeof r.total_matches === "number"
    && typeof r.returned_matches === "number";
}

function isSkillArtifactResult(r: any): boolean {
  return r && r.kind === "skill_artifact" && r.artifact && typeof r.skill_name === "string";
}

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
  // A grep_artifact result: ToolRunner already bounded this (line clipping, a match
  // cap, a scan budget) — do NOT run it through a generic slice-the-JSON-string
  // truncation like the branches above; chopping a structured array mid-match would
  // just produce garbage, not a smaller useful result. It is also not EXEMPT from
  // the Offload Law: a caller near its max_matches/context ceilings can still add up
  // to a large payload, so drop trailing matches (never edit one that's kept) until
  // the result fits, preserving the real total_matches/total_lines so the model still
  // knows what it's missing and can narrow its pattern.
  if (isGrepResult(r)) {
    let matches = r.matches as unknown[];
    let dropped = false;
    while (matches.length > 0
      && JSON.stringify({ ...r, matches }).length > GREP_RESULT_MAX_CHARS) {
      matches = matches.slice(0, -1);
      dropped = true;
    }
    if (!dropped) return r;
    return {
      ...r,
      matches,
      returned_matches: matches.length,
      truncated: true,
      note: `result exceeded ${GREP_RESULT_MAX_CHARS} chars for the model — kept ${matches.length} ` +
        `of the ${r.matches.length} matches the tool returned; narrow the pattern or reduce max_matches/context`,
    };
  }
  // A skill_run success: ToolRunner already schema-validated and hashed the FULL
  // artifact into the store (r.output is the complete parsed JSON). The Offload Law
  // applies here exactly as it does to http_request: the model gets a bounded preview
  // of the artifact plus its sha256, never the whole thing, and calls
  // read_artifact/grep_artifact against artifact_sha256 when it needs more.
  if (isSkillArtifactResult(r)) {
    const full = JSON.stringify(r.output);
    const truncated = full.length > SKILL_SUMMARY_MAX_CHARS;
    return {
      skill_name: r.skill_name,
      exit_code: r.exit_code,
      ms: r.ms,
      artifact_sha256: r.artifact.sha256,
      summary: truncated ? full.slice(0, SKILL_SUMMARY_MAX_CHARS) : full,
      summary_bytes: full.length,
      truncated,
      ...(truncated
        ? { note: `artifact truncated to ${SKILL_SUMMARY_MAX_CHARS} of ${full.length} chars for the ` +
            "model — call read_artifact with artifact_sha256 for the full validated artifact" }
        : {}),
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
  // skill_run's input_json can be arbitrarily large (and, like any tool argument, is
  // caller/model-supplied) — bound it the same way response bodies are bounded, rather
  // than writing it into telemetry verbatim.
  if (typeof args.input_json === "string") {
    const truncated = args.input_json.length > PREVIEW_BYTES;
    return {
      ...args,
      input_json: truncated ? args.input_json.slice(0, PREVIEW_BYTES) : args.input_json,
      input_json_bytes: args.input_json.length,
      ...(truncated ? { input_json_truncated: true } : {}),
    };
  }
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
 *
 * `args` is optional and only consulted for a grep_artifact result, to recover the
 * search pattern for the span (the pattern is not itself part of the tool's return
 * value) — every other branch ignores it, so existing single-argument call sites are
 * unaffected.
 */
export function toolSpanOutput(out: ToolResult, args?: Record<string, unknown>): Record<string, unknown> {
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
  // A grep_artifact result: record the pattern and match counts, but NEVER the
  // matched lines themselves — they can contain recovered secrets (tokens, keys,
  // PII) pulled straight out of a target's bundle, which is exactly the class of
  // content this project's telemetry redaction already refuses to persist elsewhere
  // (see redactHeaders() above).
  if (isGrepResult(r)) {
    return {
      pattern: args?.pattern,
      total_matches: r.total_matches,
      returned_matches: r.returned_matches,
      truncated: r.truncated,
    };
  }
  if (r && typeof r.content === "string") {
    return { content_bytes: r.content.length };
  }
  // A skill_run success: skill_name, exit code, duration, the artifact hash and that
  // validation passed — NEVER the artifact body, and never a secret value (a skill
  // that discovers a credential is itself responsible for hashing/encrypting it before
  // it ever reaches an artifact; this span records only bookkeeping about the run).
  if (isSkillArtifactResult(r)) {
    return {
      skill_name: r.skill_name,
      exit_code: r.exit_code,
      ms: r.ms,
      artifact_sha256: r.artifact.sha256,
      validation: "ok",
    };
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
  stopReason: "done" | "max_turns" | "budget" | "aborted" | "model_error";
  /** Set only when stopReason is "model_error": why the model call failed. */
  modelError?: string;
  /**
   * Metadata-only record of every successful http_request this call made: method,
   * url, status, content-type — NEVER the body. This does not weaken the Offload
   * Law above; it is bookkeeping over fields toolSpanOutput already extracts for
   * telemetry, not a path for full response bodies back to the caller. Exists so a
   * caller (beat.ts) can feed what the hunter actually discovered into the Spine's
   * attack_surface, not just the endpoints involved in a claim.
   */
  httpCalls: Array<{ method: string; url: string; status: number; contentType: string | null }>;
}

function headerValue(headers: Record<string, string> | undefined | null, name: string): string | null {
  if (!headers) return null;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v;
  }
  return null;
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
  const httpCalls: AgentResult["httpCalls"] = [];
  let turns = 0;
  let tokens = 0;
  let artifacts = 0;

  while (true) {
    if (opts.signal?.aborted) {
      return { messages, turns, tokens, toolCalls, artifacts, httpCalls, stopReason: "aborted" };
    }
    if (turns >= opts.maxTurns) {
      return { messages, turns, tokens, toolCalls, artifacts, httpCalls, stopReason: "max_turns" };
    }

    // A model call can fail mid-flight for reasons that have nothing to do with the
    // engagement — a dropped HTTP/2 stream, EHOSTUNREACH, a provider hiccup. One
    // such failure previously propagated out of runBeat and killed the process,
    // discarding four CONFIRMED findings that had already been proved. Treat it as
    // the end of THIS attempt and hand back everything accumulated so far; the
    // caller decides whether to keep hunting.
    let completion: any;
    try {
      completion = await opts.client.chat.completions.create(
      {
        model: opts.model,
        messages,
        tools: opts.tools,
        parallel_tool_calls: false,
      },
      opts.signal ? { signal: opts.signal } : undefined,
      );
    } catch (err) {
      const message = String((err as Error)?.message ?? err);
      const cause = (err as { cause?: { code?: string } })?.cause?.code;
      return {
        messages, turns, tokens, toolCalls, artifacts, httpCalls,
        stopReason: "model_error",
        modelError: cause ? `${message} (${cause})` : message,
      };
    }
    turns += 1;
    tokens += completion.usage?.total_tokens ?? 0;

    const message = completion.choices?.[0]?.message;
    messages.push(message);

    const calls = message?.tool_calls ?? [];
    if (calls.length === 0) {
      return { messages, turns, tokens, toolCalls, artifacts, httpCalls, stopReason: "done" };
    }

    for (const c of calls) {
      const name = c.function.name;
      const raw = c.function.arguments ?? "{}";
      let args: Record<string, unknown> = {};
      try { args = JSON.parse(raw); } catch { /* malformed args reach the tool as {} */ }

      // THE TETHER AUDIT SPAN. gate() runs on every tool call inside
      // ToolRunner.execute(), but until now that decision left no record of its own: a
      // DENIAL surfaced only as kind:"policy" buried inside the tool result (see
      // toolSpanOutput below), and an ALLOW left NO record at all — the single most
      // security-critical decision in the system ("may this action leave the box") was
      // the one thing with no audit trail. This computes the SAME decision the
      // executor is about to enforce (ToolRunner.checkGate() delegates to the identical
      // gate() call tools.ts.execute() makes internally) and records it as its own
      // `tether` span — a SIBLING of the `tool:<name>` span below, not nested inside
      // it, so the authorization decision is auditable on its own regardless of
      // whether the call goes on to succeed. Emitted for ALLOW as well as DENY: an
      // allow-only-on-deny audit log is useless for answering "was this authorization
      // decision even made" on the other 66 calls in a 67-call trace.
      await startActiveObservation("tether", async (span) => {
        const decision = opts.runner.checkGate(name, args);
        span.update({
          input: { tool: name, target: auditTarget(name, args) },
          output: decision.allow
            ? { decision: "allow" as const }
            // The reason is the security record here — shell_exec commands and
            // http_request URLs are NEVER redacted (per toolSpanInput's own body/URL
            // handling elsewhere, only response BODIES and secret header VALUES are
            // redacted, never the requested action itself).
            : { decision: "deny" as const, reason: decision.reason },
          ...(decision.allow ? {} : { level: "WARNING" as const }),
        });
      });

      const out = await startActiveObservation(`tool:${name}`, async (span) => {
        span.update({ input: toolSpanInput(args) });
        const result = await opts.runner.execute(name, args);
        span.update({
          output: toolSpanOutput(result, args),
          ...(result.ok ? {} : { level: "WARNING" as const }),
        });
        return result;
      });
      toolCalls.push({ tool: name, args: raw, ok: out.ok });
      if (out.ok && (out.result as any)?.artifact) artifacts += 1;
      if (out.ok && name === "http_request") {
        const r = out.result as any;
        if (r?.request && r?.response) {
          httpCalls.push({
            method: r.request.method,
            url: r.request.url,
            status: r.response.status,
            contentType: headerValue(r.response.headers, "content-type"),
          });
        }
      }

      messages.push({
        role: "tool",
        tool_call_id: c.id,
        content: JSON.stringify(
          out.ok ? forModel(out.result) : { denied: out.denied, kind: (out as any).kind }),
      });
    }

    if (tokens >= opts.budgetTokens) {
      return { messages, turns, tokens, toolCalls, artifacts, httpCalls, stopReason: "budget" };
    }
  }
}
