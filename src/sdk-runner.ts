/**
 * SdkRunner — the real AgentRunner, backed by the OpenCode SDK.
 *
 * Implements the injected AgentRunner interface the Orchestrator consumes.
 * One run() = one phase/objective = one session (create → prompt → read
 * AssistantMessage.cost/.tokens → parse proposed findings from text parts).
 *
 * Targets the OpenCode v2 HTTP API via `client.v2.*`, whose routes are
 * `/api/session…` — the v1 namespace (`client.session.*`) posts to `/session…`,
 * which a v2 server answers with the SPA HTML. v2 responses are additionally
 * wrapped twice: the SDK's `{data}` holds the server's own `{data}`.
 */

import { type OpencodeClient } from "@opencode-ai/sdk/v2";
import type { AgentResult, Finding } from "./orchestrator.js";
import type { TokenUsage } from "./budget.js";
import type { LoopPhase } from "./agent-loop.js";
import type { SpanRecorder } from "./langfuse.js";

export interface SdkRunnerOptions {
  client: OpencodeClient;
  directory: string; // project directory whose .opencode/agents/*.md are used
  model?: { id: string; providerID: string };
  system?: string; // shared core preamble (docs/agents/core.md)
  pollIntervalMs?: number; // how often to poll for turn completion (tests use a small value)
}

const EMPTY_TOKENS: TokenUsage = { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } };

/** Extract finding JSON objects (those carrying finding_id + invariant) from agent text. */
export function parseFindings(parts: Array<{ type?: string; text?: string; synthetic?: boolean }>): Finding[] {
  const text = parts
    .filter((p) => p.type === "text" && !p.synthetic && typeof p.text === "string")
    .map((p) => p.text as string)
    .join("\n");

  const findings: Finding[] = [];
  // Balanced-object scan: find top-level JSON objects and keep those with finding_id.
  for (const obj of extractJsonObjects(text)) {
    if (
      obj &&
      typeof obj === "object" &&
      typeof (obj as Record<string, unknown>).finding_id === "string" &&
      (obj as Record<string, unknown>).invariant &&
      (obj as Record<string, unknown>).evidence
    ) {
      findings.push(obj as unknown as Finding);
    }
  }
  return findings;
}

function extractJsonObjects(text: string): unknown[] {
  const out: unknown[] = [];
  let i = 0;
  while (i < text.length) {
    const open = text.indexOf("{", i);
    if (open === -1) break;
    // find matching close brace with string/escape awareness
    let depth = 0;
    let inString = false;
    let esc = false;
    for (let j = open; j < text.length; j++) {
      const c = text[j];
      if (inString) {
        if (esc) esc = false;
        else if (c === "\\") esc = true;
        else if (c === '"') inString = false;
        continue;
      }
      if (c === '"') inString = true;
      else if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) {
          const slice = text.slice(open, j + 1);
          try {
            out.push(JSON.parse(slice));
          } catch {
            // not valid JSON — skip
          }
          i = j + 1;
          break;
        }
      }
    }
    if (depth !== 0) break; // unbalanced — stop scanning
    if (i <= open) break;
  }
  return out;
}

export class SdkRunner {
  private readonly client: OpencodeClient;
  private readonly directory: string;
  private readonly model?: { id: string; providerID: string };
  private readonly system?: string;
  private readonly pollIntervalMs: number;

  constructor(opts: SdkRunnerOptions) {
    this.client = opts.client;
    this.directory = opts.directory;
    this.model = opts.model;
    this.system = opts.system;
    this.pollIntervalMs = opts.pollIntervalMs ?? 3_000;
  }

  async run(agent: string, objective: string): Promise<AgentResult & { finalText: string }> {
    const api = (this.client as unknown as { v2?: { session?: Record<string, any> } }).v2;
    const session = api?.session;
    if (!session) throw new Error("OpenCode SDK client has no v2 namespace — SDK/server version mismatch");
    // The generated client is used where its schema matches this server build;
    // `prompt` and the message list go through the SDK's own HTTP client because
    // the bundled schema drifted (it sends body.prompt, the server wants body.text).
    const http = session.client;

    const created = await session.create({
      agent,
      location: { directory: this.directory },
      ...(this.model ? { model: this.model } : {}),
    });
    if (created.error) throw new Error(`session.create() failed: ${JSON.stringify(created.error).slice(0, 300)}`);
    const sessionId = unwrap<{ id?: string }>(created)?.id;
    if (!sessionId) throw new Error(`session.create() returned no id: ${JSON.stringify(created.data).slice(0, 300)}`);
    console.log(`[sdk-runner] engine session ${sessionId} (agent=${agent})`);

    // Prompting is asynchronous: the call queues the turn and returns the user message.
    const queued = await this.sendPrompt(http, sessionId, objective);
    if (queued.error) {
      console.error(`[sdk-runner] prompt failed: ${JSON.stringify(queued.error).slice(0, 300)}`);
      return { costUsd: 0, tokens: EMPTY_TOKENS, findings: [], stalled: true, finalText: "" };
    }

    const messages = await this.awaitCompletion(http, sessionId, 12 * 60 * 60_000, this.pollIntervalMs);
    if (!messages) return { costUsd: 0, tokens: EMPTY_TOKENS, findings: [], stalled: true, finalText: "" };

    // Aggregate across every assistant message in the session.
    let costUsd = 0;
    const totals: TokenUsage = { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } };
    const parts: Array<{ type?: string; text?: string; synthetic?: boolean }> = [];
    const texts: string[] = [];
    for (const m of messages) {
      if (m?.type !== "assistant") continue;
      if (typeof m.cost === "number") costUsd += m.cost;
      const t = normalizeTokens(m.tokens);
      totals.input += t.input;
      totals.output += t.output;
      totals.reasoning += t.reasoning;
      totals.cache.read += t.cache.read;
      totals.cache.write += t.cache.write;
      for (const c of (m.content ?? m.parts ?? []) as Array<Record<string, unknown>>) {
        parts.push(c as { type?: string; text?: string; synthetic?: boolean });
        if (c?.type === "text" && typeof c.text === "string") texts.push(c.text);
      }
    }

    const findings = parseFindings(parts);
    return { costUsd, tokens: totals, findings, stalled: parts.length === 0, finalText: texts.join("\n\n") };
  }

  /**
   * Drive a full engagement through ONE engine session: the objective, then one
   * prompt per phase with that phase's playbooks injected. The engine runs its
   * own tool loop for each prompt; we wait for each to go idle before the next.
   */
  async runPhases(
    agent: string,
    objective: string,
    phases: LoopPhase[],
    loadSkill: (name: string) => string,
    rec?: SpanRecorder,
    skillCharBudget = 3500,
  ): Promise<AgentResult & { finalText: string }> {
    const api = (this.client as unknown as { v2?: { session?: Record<string, any> } }).v2;
    const session = api?.session;
    if (!session) throw new Error("OpenCode SDK client has no v2 namespace — SDK/server version mismatch");
    const http = session.client;

    const created = await session.create({
      agent,
      location: { directory: this.directory },
      ...(this.model ? { model: this.model } : {}),
    });
    if (created.error) throw new Error(`session.create() failed: ${JSON.stringify(created.error).slice(0, 300)}`);
    const sessionId = unwrap<{ id?: string }>(created)?.id;
    if (!sessionId) throw new Error(`session.create() returned no id`);

    const prompts: Array<{ label: string; text: string }> = [
      { label: "objective", text: objective },
      ...phases.map((p) => {
        const books = (p.skills ?? [])
          .map((n) => {
            const b = loadSkill(n);
            return b && !b.startsWith("ERROR") ? `### PLAYBOOK: ${n}\n${b.slice(0, skillCharBudget)}` : "";
          })
          .filter(Boolean)
          .join("\n\n");
        return {
          label: p.id,
          text:
            `== PHASE ${p.id.toUpperCase()} ==\n${p.brief}\n\n` +
            `Prioritise breadth of coverage over depth on any single target; record findings as you go.` +
            (books ? `\n\nApply these operator playbooks:\n\n${books}` : ""),
        };
      }),
      {
        label: "report",
        text:
          "Engagement complete. Produce your final report NOW as the JSON array described earlier. " +
          "Include every confirmed issue as its own finding, then list any inventory endpoint you never reached.",
      },
    ];

    for (const p of prompts) {
      const before = await this.idleCount(http, sessionId);
      const queued = await this.sendPrompt(http, sessionId, p.text);
      if (queued.error) {
        console.error(`[sdk-runner] phase '${p.label}' prompt failed: ${JSON.stringify(queued.error).slice(0, 200)}`);
        continue;
      }
      const ok = await this.awaitTurn(http, sessionId, before);
      await rec?.toolSpan(`engine:${p.label}`, { input: p.text.slice(0, 2000), output: ok ? "completed" : "timed out" });
      if (!ok) console.error(`[sdk-runner] phase '${p.label}' timed out`);
    }

    const messages = (await this.fetchMessages(http, sessionId)) ?? [];
    let costUsd = 0;
    const totals: TokenUsage = { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } };
    const parts: Array<{ type?: string; text?: string; synthetic?: boolean }> = [];
    const texts: string[] = [];
    for (const m of messages) {
      if (m?.type !== "assistant") continue;
      if (typeof m.cost === "number") costUsd += m.cost;
      const t = normalizeTokens(m.tokens);
      totals.input += t.input;
      totals.output += t.output;
      totals.reasoning += t.reasoning;
      totals.cache.read += t.cache.read;
      totals.cache.write += t.cache.write;
      for (const c of (m.content ?? m.parts ?? []) as Array<Record<string, unknown>>) {
        parts.push(c as { type?: string; text?: string; synthetic?: boolean });
        if (c?.type === "text" && typeof c.text === "string") texts.push(c.text);
      }
    }
    return {
      costUsd,
      tokens: totals,
      findings: parseFindings(parts),
      stalled: parts.length === 0,
      finalText: texts.join("\n\n"),
    };
  }

  /**
   * Send a prompt, tolerating the two body shapes in the wild: opencode 1.18.x
   * expects `{prompt:{text}}` (what the SDK generates), while some 2.0.x builds
   * expect a bare `{text}`. Try the SDK-native shape, fall back on a payload
   * rejection naming the other key.
   */
  private async sendPrompt(http: any, sessionId: string, text: string): Promise<{ error?: unknown }> {
    const url = `/api/session/${sessionId}/prompt`;
    const headers = { "Content-Type": "application/json" };
    const first = await http.post({ url, body: { prompt: { text } }, headers });
    if (!first.error) return first;
    // Any payload-validation rejection means this build wants the other shape.
    const msg = JSON.stringify(first.error);
    if (/InvalidRequestError|Missing key|Expected|Payload/i.test(msg)) {
      return await http.post({ url, body: { text }, headers });
    }
    return first;
  }

  private async fetchMessages(http: any, sessionId: string): Promise<Array<Record<string, any>> | null> {
    const res = await http.get({ url: `/api/session/${sessionId}/message` });
    if (res.error) return null;
    const list = unwrap<Array<Record<string, any>>>(res as { data?: unknown });
    return Array.isArray(list) ? list : null;
  }

  private async idleCount(http: any, sessionId: string): Promise<number> {
    const list = (await this.fetchMessages(http, sessionId)) ?? [];
    return list.filter((m) => m?.type === "idle").length;
  }

  /** Wait until a NEW idle message appears (this prompt's turn finished). */
  private async awaitTurn(http: any, sessionId: string, idleBefore: number, timeoutMs = 45 * 60_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, this.pollIntervalMs));
      if ((await this.idleCount(http, sessionId)) > idleBefore) return true;
    }
    return false;
  }

  /** Poll the session until it reports an outcome; returns its messages. */
  private async awaitCompletion(
    http: { get: (o: Record<string, unknown>) => Promise<{ data?: unknown; error?: unknown }> },
    sessionId: string,
    timeoutMs = 30 * 60_000,
    intervalMs = 3_000,
  ): Promise<Array<Record<string, any>> | null> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, intervalMs));
      const res = await http.get({ url: `/api/session/${sessionId}/message` });
      if (res.error) continue;
      const list = unwrap<Array<Record<string, any>>>(res as { data?: unknown });
      if (!Array.isArray(list)) continue;
      // An `idle` message carrying an outcome marks the turn complete.
      const done = list.find((m) => m?.type === "idle" && m?.outcome);
      if (done) return list;
    }
    console.error(`[sdk-runner] timed out waiting for session ${sessionId}`);
    return null;
  }
}

/** v2 responses are double-wrapped: SDK `{data}` holds the server's `{data}`. */
function unwrap<T>(res: { data?: unknown }): T | undefined {
  const d = res?.data as Record<string, unknown> | undefined;
  if (d && !Array.isArray(d) && typeof d === "object" && "data" in d) return d.data as T;
  return d as T | undefined;
}

function normalizeTokens(t: unknown): TokenUsage {
  if (t && typeof t === "object") {
    const o = t as Record<string, unknown>;
    const cache = (o.cache && typeof o.cache === "object" ? o.cache : {}) as Record<string, unknown>;
    return {
      input: num(o.input),
      output: num(o.output),
      reasoning: num(o.reasoning),
      cache: { read: num(cache.read), write: num(cache.write) },
    };
  }
  return EMPTY_TOKENS;
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}
