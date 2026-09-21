/**
 * runEngagement — the black-box input contract (the tool API).
 *
 * Wires Scope + Axiom + Budget + Orchestrator + the injected AgentRunner.
 * Authorization is a MANDATORY precondition. Nothing here is target-specific:
 * scope URLs come from the caller at run time. (The Tether is instantiated in
 * the execution-engine plugin from env; the control plane owns budget/axiom.)
 */

import { parseScope } from "./scope.js";
import { Axiom } from "./axiom.js";
import { Budget } from "./budget.js";
import { Orchestrator, type AgentRunner, type PhaseSpec, type RunResult } from "./orchestrator.js";

export interface EngagementInput {
  scope: {
    inScopeUrls: string[];
    inScopeCidrs?: string[];
    outOfScope?: string[];
  };
  credentials?: Array<{ role: string; userid: string; password: string }> | null;
  authFlow?: { loginUrl?: string; hints?: string } | null;
  budget: { usd: number; turns: number; tokens: number };
  impactLevel: "L2-readonly";
  authorization: { ref: string; window: { start: string; end: string } };
  runner: AgentRunner; // injected (SdkRunner in production, fake in tests)
  phases?: PhaseSpec[];
  confidenceThreshold?: number;
}

export interface EngagementResult {
  authorization: { ref: string; window: { start: string; end: string } };
  run: RunResult;
}

const DEFAULT_PHASES: PhaseSpec[] = [
  { phase: 1, name: "recon", agent: "recon", objective: "Fingerprint, crawl, and map the in-scope target to a state machine." },
  { phase: 2, name: "discovery", agent: "threat-model", objective: "Propose test strategies and payloads for discovered endpoints." },
  { phase: 3, name: "exploitation", agent: "exploit-constructor", objective: "Build safe, reversible PoCs and collect verbatim evidence." },
  { phase: 4, name: "validation", agent: "adjudicator", objective: "Replay invariants against evidence and finalize findings." },
];

export async function runEngagement(input: EngagementInput): Promise<EngagementResult> {
  // MANDATORY precondition: authorization must be present and non-empty.
  if (!input.authorization?.ref || !input.authorization?.window?.start || !input.authorization?.window?.end) {
    throw new Error("runEngagement: authorization (ref + window) is a mandatory precondition");
  }
  if (input.scope.inScopeUrls.length === 0) {
    throw new Error("runEngagement: at least one in-scope URL is required");
  }

  // Parse scope eagerly: this throws ScopeError on non-http(s) / malformed URLs.
  parseScope(input.scope);

  const axiom = new Axiom({ confidenceThreshold: input.confidenceThreshold });
  const budget = new Budget(input.budget);
  const orchestrator = new Orchestrator({
    runner: input.runner,
    budget,
    axiom,
    phases: input.phases ?? DEFAULT_PHASES,
  });

  const run = await orchestrator.run();
  return { authorization: input.authorization, run };
}
