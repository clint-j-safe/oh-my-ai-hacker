/**
 * LlmRunner — the AgentRunner that drives the model directly via OpenRouter.
 *
 * Each phase's agent runs a Tether-gated tool loop: the model proposes
 * `http_request` (and `run_command`) tool calls, the Tether/scope decides
 * whether they may execute, and the Axiom later validates any findings.
 * This is the working "AI drives, deterministic code decides" path — no
 * opencode CLI/server required.
 */

import { OpenRouterLlm, type ToolDef } from "./llm.js";
import { runAgentLoop } from "./agent-loop.js";
import { Tether } from "./tether.js";
import { Scope } from "./scope.js";
import { httpRequest } from "./http.js";
import { parseFindings } from "./sdk-runner.js";
import type { AgentResult } from "./orchestrator.js";
import type { SpanRecorder } from "./langfuse.js";

export interface LlmRunnerOptions {
  apiKey: string;
  model: string;
  system: string; // core preamble + agent role
  scope: Scope;
  workspaceRoot: string;
  maxTurns?: number;
  temperature?: number;
  baseUrl?: string;
}

const HTTP_TOOL: ToolDef = {
  type: "function",
  function: {
    name: "http_request",
    description: "Send an HTTP request to an in-scope target and return status, headers and body (truncated). Use GET for reading, POST/PUT with a body when needed. The tool will DENY any out-of-scope URL.",
    parameters: {
      type: "object",
      properties: {
        method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"] },
        url: { type: "string", description: "Absolute http(s) URL within the authorized scope" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        body: { type: "string", description: "Request body (for POST/PUT)" },
      },
      required: ["method", "url"],
    },
  },
};

const RUN_TOOL: ToolDef = {
  type: "function",
  function: {
    name: "run_command",
    description: "Run a read-only shell command (e.g. curl) against an in-scope target. Destructive or out-of-scope commands are DENIED.",
    parameters: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
  },
};

export class LlmRunner {
  private readonly llm: OpenRouterLlm;
  private readonly model: string;
  private readonly system: string;
  private readonly tether: Tether;
  private readonly maxTurns: number;
  private readonly temperature?: number;

  constructor(opts: LlmRunnerOptions) {
    this.llm = new OpenRouterLlm({ apiKey: opts.apiKey, baseUrl: opts.baseUrl });
    this.model = opts.model;
    this.system = opts.system;
    this.tether = new Tether({ scope: opts.scope, workspaceRoot: opts.workspaceRoot });
    this.maxTurns = opts.maxTurns ?? 12;
    this.temperature = opts.temperature;
  }

  private async executeTool(name: string, args: Record<string, unknown>): Promise<string> {
    if (name === "http_request") {
      const url = String(args.url ?? "");
      const decision = this.tether.decide({ tool: "webfetch", url });
      if (decision.decision !== "allow") return `DENIED: ${decision.reason}`;
      try {
        const res = await httpRequest(url, {
          method: String(args.method ?? "GET").toUpperCase(),
          headers: (args.headers as Record<string, string>) ?? undefined,
          body: args.body as string | undefined,
        });
        return `STATUS ${res.status}\nHEADERS ${JSON.stringify(res.headers).slice(0, 600)}\nBODY ${res.body.slice(0, 4000)}`;
      } catch (e) {
        return `ERROR: ${(e as Error).message}`;
      }
    }
    if (name === "run_command") {
      const command = String(args.command ?? "");
      const decision = this.tether.decide({ tool: "bash", command });
      if (decision.decision !== "allow") return `DENIED: ${decision.reason}`;
      return `(command execution not yet wired in this runner: ${command.slice(0, 80)})`;
    }
    return `UNKNOWN TOOL: ${name}`;
  }

  async run(agent: string, objective: string, rec?: SpanRecorder): Promise<AgentResult & { finalText: string }> {
    const result = await runAgentLoop({
      llm: this.llm,
      model: this.model,
      system: `${this.system}\n\nYou are running as agent: ${agent}.`,
      objective,
      tools: [HTTP_TOOL, RUN_TOOL],
      executeTool: (n, a) => this.executeTool(n, a),
      maxTurns: this.maxTurns,
      temperature: this.temperature,
      ...(rec ? { rec } : {}),
    });

    const findings = parseFindings([{ type: "text", text: result.finalText }]);
    return {
      costUsd: result.cost,
      tokens: {
        input: result.promptTokens,
        output: result.completionTokens,
        reasoning: 0,
        cache: { read: 0, write: 0 },
      },
      findings,
      stalled: result.finalText.trim().length === 0,
      finalText: result.finalText,
    };
  }
}
