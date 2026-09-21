import { describe, it, expect } from "vitest";
import { Orchestrator, type AgentRunner, type AgentResult, type PhaseSpec, type Finding } from "./orchestrator.js";
import { Budget, type TokenUsage } from "./budget.js";
import { Axiom } from "./axiom.js";

const TOK: TokenUsage = { input: 10, output: 10, reasoning: 0, cache: { read: 0, write: 0 } };

const PHASES: PhaseSpec[] = [
  { phase: 1, name: "recon", agent: "recon", objective: "map the target" },
  { phase: 2, name: "discovery", agent: "threat-model", objective: "propose strategies" },
  { phase: 3, name: "exploitation", agent: "exploit-constructor", objective: "build PoCs" },
  { phase: 4, name: "validation", agent: "adjudicator", objective: "finalize findings" },
];

const F1: Finding = {
  finding_id: "SAHW-0001",
  invariant: { statement: "file contents must not be returned", type: "body_contains", expression: "root:x:0:0" },
  evidence: { exploit_response_excerpt: "root:x:0:0:root:/root:/bin/bash", control_response_excerpt: "File not found" },
};

class FakeRunner implements AgentRunner {
  calls: string[] = [];
  results: AgentResult[] = [];
  constructor(results?: AgentResult[]) {
    this.results = results ?? [];
  }
  async run(agent: string, objective: string): Promise<AgentResult> {
    this.calls.push(`${agent}:${objective}`);
    return this.results.shift() ?? { costUsd: 0.01, tokens: TOK, findings: [] };
  }
}

function makeOrch(runner: AgentRunner, budget: Budget, axiom: Axiom = new Axiom(), isSuccess?: Orchestrator["isSuccess"]) {
  return new Orchestrator({ runner, budget, axiom, phases: PHASES, isSuccess });
}

describe("Orchestrator.run — phase progression", () => {
  it("runs phases in order 1→2→3→4", async () => {
    const runner = new FakeRunner();
    const budget = new Budget({ usd: 100, turns: 100, tokens: 100_000 });
    const orch = makeOrch(runner, budget);
    const res = await orch.run();
    expect(runner.calls.map((c) => c.split(":")[0])).toEqual(["recon", "threat-model", "exploit-constructor", "adjudicator"]);
    expect(res.phasesRun).toEqual([1, 2, 3, 4]);
    expect(res.exit).toBe("completed");
  });
});

describe("Orchestrator.run — budget", () => {
  it("stops with exit=limit on budget breach and does not run further phases", async () => {
    const runner = new FakeRunner();
    const budget = new Budget({ usd: 100, turns: 2, tokens: 100_000 });
    const orch = makeOrch(runner, budget);
    const res = await orch.run();
    expect(res.exit).toBe("limit");
    expect(res.phasesRun).toEqual([1, 2]); // third turn would breach turns=2
    expect(runner.calls).toHaveLength(2);
  });
});

describe("Orchestrator.run — findings + Axiom", () => {
  it("collects CONFIRMED findings with their Axiom verdicts", async () => {
    const runner = new FakeRunner([
      { costUsd: 0.01, tokens: TOK, findings: [] },
      { costUsd: 0.01, tokens: TOK, findings: [] },
      { costUsd: 0.01, tokens: TOK, findings: [F1] },
      { costUsd: 0.01, tokens: TOK, findings: [] },
    ]);
    const budget = new Budget({ usd: 100, turns: 100, tokens: 100_000 });
    const orch = makeOrch(runner, budget);
    const res = await orch.run();
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].verdict.status).toBe("CONFIRMED");
  });

  it("returns exit=success when the success predicate fires after a phase", async () => {
    const runner = new FakeRunner([
      { costUsd: 0.01, tokens: TOK, findings: [F1] },
    ]);
    const budget = new Budget({ usd: 100, turns: 100, tokens: 100_000 });
    const orch = makeOrch(runner, budget, new Axiom(), () => true);
    const res = await orch.run();
    expect(res.exit).toBe("success");
    expect(res.phasesRun).toEqual([1]); // stopped after phase 1
  });
});

describe("Orchestrator.run — stall", () => {
  it("returns exit=no_progress when a phase reports stalled", async () => {
    const runner = new FakeRunner([
      { costUsd: 0.01, tokens: TOK, findings: [], stalled: true },
    ]);
    const budget = new Budget({ usd: 100, turns: 100, tokens: 100_000 });
    const orch = makeOrch(runner, budget);
    const res = await orch.run();
    expect(res.exit).toBe("no_progress");
  });
});
