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
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readSkill } from "./skills.js";
import type { LoopPhase } from "./agent-loop.js";
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
  /** Chars of a tool result kept inline before the rest is offloaded to a file. */
  inlineLimit?: number;
  /** Stable per-run key for provider prompt caching. */
  cacheKey?: string;
  /** Budgeted engagement phases; each injects its playbooks and gets a turn share. */
  phases?: LoopPhase[];
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
    description: "Run a shell command in an isolated sandbox directory to COMPUTE things you cannot do over HTTP: decrypt/encrypt (e.g. `node -e` with the crypto module for AES), base64/hex encode-decode, decode or forge JWTs, craft serialized payloads (PHP/Java/pickle), hash, parse source maps, and do arithmetic on values you captured. Node.js is available. Use http_request for HTTP; use this for local computation. Destructive/DoS or out-of-scope commands are DENIED.",
    parameters: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
  },
};

const SKILL_TOOL: ToolDef = {
  type: "function",
  function: {
    name: "read_skill",
    description: "Read an operator playbook from the skill library by name (see the SKILL LIBRARY list in your instructions). Returns the full methodology plus the paths of any runnable scripts it ships, which you can execute with run_command. Consult the relevant skill BEFORE attacking a class of vulnerability.",
    parameters: {
      type: "object",
      properties: { name: { type: "string", description: "Exact skill name, e.g. sqli-database-injection" } },
      required: ["name"],
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
  private readonly workspaceRoot: string;
  private readonly inlineLimit: number;
  private readonly cacheKey?: string;
  private readonly phases?: LoopPhase[];
  private spillSeq = 0;

  constructor(opts: LlmRunnerOptions) {
    this.llm = new OpenRouterLlm({ apiKey: opts.apiKey, baseUrl: opts.baseUrl });
    this.model = opts.model;
    this.system = opts.system;
    this.tether = new Tether({ scope: opts.scope, workspaceRoot: opts.workspaceRoot });
    this.maxTurns = opts.maxTurns ?? 12;
    this.temperature = opts.temperature;
    this.workspaceRoot = opts.workspaceRoot;
    // Prompt caching (91% hit) already makes a long context cheap, so only
    // genuinely huge payloads (source maps, dumps) are worth spilling. A low
    // limit starves the engagement: the agent spends turns re-reading files
    // instead of probing the target.
    this.inlineLimit = opts.inlineLimit ?? Number(process.env.SAHW_INLINE_LIMIT ?? 6000);
    this.cacheKey = opts.cacheKey;
    this.phases = opts.phases;
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
        return this.offload(`STATUS ${res.status}\nHEADERS ${JSON.stringify(res.headers).slice(0, 600)}\nBODY ${res.body}`, "http");
      } catch (e) {
        return `ERROR: ${(e as Error).message}`;
      }
    }
    if (name === "read_skill") {
      return this.offload(readSkill(String(args.name ?? "")), "skill");
    }
    if (name === "run_command") {
      const command = String(args.command ?? "");
      const decision = this.tether.decide({ tool: "bash", command });
      if (decision.decision !== "allow") return `DENIED: ${decision.reason}`;
      try {
        mkdirSync(this.workspaceRoot, { recursive: true });
      } catch {
        /* already exists */
      }
      return this.offload(await runShell(command, this.workspaceRoot), "cmd");
    }
    return `UNKNOWN TOOL: ${name}`;
  }

  /**
   * Keep a readable head of a tool result in the conversation and spill the
   * full text to a file in the sandbox. The agent greps/reads the file with
   * run_command when it needs the rest, so context does not grow with every
   * large response.
   */
  private offload(text: string, kind: string): string {
    if (text.length <= this.inlineLimit) return text;
    this.spillSeq += 1;
    const file = join(this.workspaceRoot, `spill-${kind}-${this.spillSeq}.txt`);
    try {
      mkdirSync(this.workspaceRoot, { recursive: true });
      writeFileSync(file, text);
    } catch (e) {
      // Cannot spill — fall back to a hard truncation so context stays bounded.
      return `${text.slice(0, this.inlineLimit)}\n…[truncated ${text.length - this.inlineLimit} chars; spill failed: ${(e as Error).message}]`;
    }
    // The path is alone at the end of its line so neither the agent nor the
    // history trimmer can swallow an adjacent bracket into the filename.
    return (
      `${text.slice(0, this.inlineLimit)}\n` +
      `…[${text.length - this.inlineLimit} more chars offloaded]\n` +
      `FULL OUTPUT FILE: ${file}\n` +
      `Read the rest with run_command, e.g.  grep -n "pattern" ${file} | head -40`
    );
  }

  async run(agent: string, objective: string, rec?: SpanRecorder): Promise<AgentResult & { finalText: string }> {
    const result = await runAgentLoop({
      llm: this.llm,
      model: this.model,
      system: `${this.system}\n\nYou are running as agent: ${agent}.`,
      objective,
      tools: [HTTP_TOOL, RUN_TOOL, SKILL_TOOL],
      executeTool: (n, a) => this.executeTool(n, a),
      maxTurns: this.maxTurns,
      temperature: this.temperature,
      ...(this.cacheKey ? { cacheKey: this.cacheKey } : {}),
      ...(this.phases?.length ? { phases: this.phases, loadSkill: readSkill } : {}),
      ...(rec ? { rec } : {}),
    });

    const findings = parseFindings([{ type: "text", text: result.finalText }]);
    return {
      costUsd: result.cost,
      tokens: {
        input: result.promptTokens,
        output: result.completionTokens,
        reasoning: 0,
        cache: { read: result.cachedTokens ?? 0, write: 0 },
      },
      findings,
      stalled: result.finalText.trim().length === 0,
      finalText: result.finalText,
    };
  }
}

/** Run a command in the sandbox with a hard timeout; never throws. */
function runShell(command: string, cwd: string, timeoutMs = 20_000): Promise<string> {
  return new Promise((resolve) => {
    const child = spawn(command, { cwd, shell: "/bin/sh", env: { ...process.env, NO_COLOR: "1" } });
    let out = "";
    let err = "";
    let done = false;
    const finish = (note: string, code: number | null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
      resolve(`EXIT ${code ?? "killed"}${note}\nSTDOUT ${out.slice(0, 6000)}\nSTDERR ${err.slice(0, 1500)}`);
    };
    const timer = setTimeout(() => finish(" (timeout)", null), timeoutMs);
    child.stdout?.on("data", (c) => { if (out.length < 64_000) out += String(c); });
    child.stderr?.on("data", (c) => { if (err.length < 16_000) err += String(c); });
    child.on("error", (e) => { err += String((e as Error).message); finish(" (spawn error)", null); });
    child.on("close", (code) => finish("", code));
  });
}
