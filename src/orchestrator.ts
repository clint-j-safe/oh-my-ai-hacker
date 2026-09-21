/**
 * Orchestrator — the deterministic Big Loop (phase state machine).
 *
 * The LLM never controls phase transitions. The orchestrator drives phases
 * 1→2→3→4, records budget from each agent run, replays findings through the
 * Axiom, and stops on one of three typed exits: success, limit, no_progress.
 * The LLM interaction is injected via AgentRunner; the real implementation
 * (src/sdk-runner.ts) wraps the OpenCode SDK.
 */

import { Budget } from "./budget.js";
import { Axiom, type AxiomVerdict, type Evidence, type Invariant } from "./axiom.js";
import type { TokenUsage } from "./budget.js";

export type Phase = 1 | 2 | 3 | 4;

export interface PhaseSpec {
  phase: Phase;
  name: string;
  agent: string;
  objective: string;
}

export interface Finding {
  finding_id: string;
  invariant: Invariant;
  evidence: Evidence;
}

export interface AgentResult {
  costUsd: number;
  tokens: TokenUsage;
  findings: Finding[];
  stalled?: boolean;
}

export interface AgentRunner {
  run(agent: string, objective: string): Promise<AgentResult>;
}

export interface VerdictedFinding {
  finding: Finding;
  verdict: AxiomVerdict;
}

export type RunExit = "success" | "limit" | "no_progress" | "completed";

export interface RunResult {
  exit: RunExit;
  phasesRun: Phase[];
  findings: VerdictedFinding[];
  budget: { usd: number; turns: number; tokens: number };
}

export interface OrchestratorOptions {
  runner: AgentRunner;
  budget: Budget;
  axiom: Axiom;
  phases: PhaseSpec[];
  isSuccess?: (state: { findings: VerdictedFinding[]; phase: Phase }) => boolean;
}

export class Orchestrator {
  readonly runner: AgentRunner;
  readonly budget: Budget;
  readonly axiom: Axiom;
  readonly phases: PhaseSpec[];
  readonly isSuccess: (state: { findings: VerdictedFinding[]; phase: Phase }) => boolean;

  constructor(opts: OrchestratorOptions) {
    this.runner = opts.runner;
    this.budget = opts.budget;
    this.axiom = opts.axiom;
    this.phases = opts.phases;
    this.isSuccess = opts.isSuccess ?? (() => false);
  }

  async run(): Promise<RunResult> {
    const phasesRun: Phase[] = [];
    const findings: VerdictedFinding[] = [];

    for (const spec of this.phases) {
      // Stop 1: limit — refuse to start a turn that would reach/exceed a limit.
      if (!this.budget.canContinue()) {
        return { exit: "limit", phasesRun, findings, budget: this.budget.usage() };
      }

      const result = await this.runner.run(spec.agent, spec.objective);
      this.budget.record({ cost: result.costUsd, tokens: result.tokens });
      phasesRun.push(spec.phase);

      // Stop 1 (post-turn): a turn may push USD/tokens past the limit.
      if (!this.budget.check().ok) {
        return { exit: "limit", phasesRun, findings, budget: this.budget.usage() };
      }

      for (const finding of result.findings) {
        findings.push({ finding, verdict: await this.axiom.verify(finding) });
      }

      // Stop 3: no-progress (stall) reported by the phase.
      if (result.stalled) {
        return { exit: "no_progress", phasesRun, findings, budget: this.budget.usage() };
      }

      // Stop 2: success (coverage predicate).
      if (this.isSuccess({ findings, phase: spec.phase })) {
        return { exit: "success", phasesRun, findings, budget: this.budget.usage() };
      }
    }

    return { exit: "completed", phasesRun, findings, budget: this.budget.usage() };
  }
}
