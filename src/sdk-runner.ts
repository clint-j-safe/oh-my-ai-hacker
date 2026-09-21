/**
 * SdkRunner — the real AgentRunner, backed by the OpenCode SDK.
 *
 * Implements the injected AgentRunner interface the Orchestrator consumes.
 * One run() = one phase/objective = one session (create → prompt → read
 * AssistantMessage.cost/.tokens → parse proposed findings from text parts).
 */

import type { OpencodeClient } from "@opencode-ai/sdk";
import type { AgentResult, Finding } from "./orchestrator.js";
import type { TokenUsage } from "./budget.js";

export interface SdkRunnerOptions {
  client: OpencodeClient;
  directory: string; // project directory whose .opencode/agents/*.md are used
  model?: { providerID: string; modelID: string };
  system?: string; // shared core preamble (docs/agents/core.md)
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
  private readonly model?: { providerID: string; modelID: string };
  private readonly system?: string;

  constructor(opts: SdkRunnerOptions) {
    this.client = opts.client;
    this.directory = opts.directory;
    this.model = opts.model;
    this.system = opts.system;
  }

  async run(agent: string, objective: string): Promise<AgentResult> {
    const created = await this.client.session.create();
    const sessionId = created.data?.id;
    if (!sessionId) {
      throw new Error(`session.create() failed: ${JSON.stringify(created.error ?? "no session id")}`);
    }

    const resp = await this.client.session.prompt({
      path: { id: sessionId },
      query: { directory: this.directory },
      body: {
        agent,
        ...(this.model ? { model: this.model } : {}),
        ...(this.system ? { system: this.system } : {}),
        parts: [{ type: "text", text: objective }],
      },
    });

    if (resp.error) {
      return { costUsd: 0, tokens: EMPTY_TOKENS, findings: [], stalled: true };
    }

    const info = resp.data?.info;
    const costUsd = typeof info?.cost === "number" ? info.cost : 0;
    const tokens = normalizeTokens(info?.tokens);
    const findings = parseFindings(resp.data?.parts ?? []);

    return { costUsd, tokens, findings };
  }
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
