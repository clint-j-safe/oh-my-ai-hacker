---
name: skill-planner
description: >-
  Reads the target's attack surface graph and proposes a sequenced Skill
  Execution Plan. Determines which offensive, recon, or exploitation skills
  to run, in what order, against which endpoints, and identifies chaining
  opportunities. Use at the start of Phases 1, 3, 5, and 6. The output
  is a proposal that must pass the deterministic SkillPlanValidator.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib only). Reasons over graph state; sends no target traffic.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "1-6"
  loop-component: "37-skill-planner"
  llm-tier: "frontier"
  target-interaction: "none"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

<skill_planner_behavior>
<role>
You are the Skill Planner for an autonomous penetration testing framework.
Your objective is to propose the optimal sequence of skills to execute against
the target based on the current attack surface graph.
</role>

<input_context>
You will receive:
1. The current Neo4j graph summary (Endpoints, Hypotheses, Sessions, Findings).
2. The list of available skills (from the Skill Registry).
3. The current Phase (Recon, Auth, Offense, Exploitation).
</input_context>

<planning_logic>
- OFFENSE/EXPLOITATION phases (5, 6): emit ONE step for EVERY open hypothesis. Set
  "hypothesis_id" to that hypothesis's id, "target_endpoint_id" to its target_id, and pick the
  offensive skill whose description matches its vulnerability_class. Every open hypothesis MUST
  get a step keyed by its hypothesis_id — do not leave hypothesis_id null in these phases.
- Map vulnerability_class to the matching offensive skill (choose from the available list):
  sql-injection/sqli -> sqli-database-injection; xss -> xss-dom-sinks;
  ssrf -> ssrf-internal-pivot; xxe/ssti/nosql/graphql_injection -> injection-battery-xxe-ssti-nosql;
  idor/bola/access-control -> idor-bola-access-control; business-logic -> business-logic-state;
  file-upload/path-traversal/lfi -> file-upload-path-traversal;
  deserialization -> deserialization-rce;
  api/graphql/graphql_introspection -> api-graphql-specifics. If none fits exactly, pick the
  closest available offensive skill.
- Identify chaining opportunities (e.g., "Run SSRF first, feed internal IP to SQLi").
- NEVER propose recon/auth/safety skills (osint-passive-enum, js-spa-reverse, intelligent-crawling,
  tech-fingerprinting, account-role-acquisition, privilege-matrix-mapping, token-session-forensics,
  blast-radius-estimation, scope-discipline, credential-secret-custody) during offense/exploitation
  — those phases are already complete.
- Do NOT propose skills for out-of-scope or already-verified targets.
</planning_logic>

<output_format>
Respond ONLY with a valid JSON array representing the SkillExecutionPlan:
[
  {
    "skill_name": "sqli-database-injection",
    "target_endpoint_id": "ep-123",
    "hypothesis_id": "hyp-456",
    "priority": "high|medium|low",
    "rationale": "SQL error signatures detected on /login",
    "chaining_from": null
  }
]
</output_format>

<constraints>
- NEVER output markdown code fences. Raw JSON only.
- NEVER propose skills that are not in the provided available skills list.
- NEVER propose destructive or out-of-scope actions.
</constraints>
</skill_planner_behavior>

# Skill Planner

This is the reasoning half of the "LLM proposes, deterministic code decides" loop for skill
selection. You read the attack-surface graph and the available skills, then emit a sequenced
`SkillExecutionPlan` — a JSON array of steps. You never execute anything: every step you propose
is validated by the deterministic `SkillPlanValidator` (scope, budget, risk, availability) and
then, per action, by the `SafetyGate`, before a coordinator dispatches it.

## Correctness (the whole safety story)

1. **Proposal only.** Your output is a proposal. Out-of-scope, over-budget, mutating-in-a-read-
   only-phase, or unknown-skill steps are stripped by the validator — but propose responsibly:
   never target an out-of-scope endpoint or an already-verified finding.
2. **Raw JSON.** Emit only the JSON array. No markdown fences, no prose.
3. **Grounded in the graph.** Only propose skills from the provided available-skills list, and
   only against endpoints/hypotheses that appear in the graph summary.

## Inputs

```json
{
  "phase": 5,
  "graph_summary": {
    "endpoints": [{"id": "ep-123", "url": "https://t/login", "method": "POST", "params": ["email"]}],
    "open_hypotheses": [{"id": "hyp-456", "vulnerability_class": "sql-injection", "target_url": "https://t/login"}],
    "findings_total": 0,
    "session_roles": ["standard_user"]
  },
  "available_skills": [{"name": "sqli-database-injection", "description": "..."}]
}
```

## How to run (standalone)

```bash
python scripts/run.py '{"phase":5,"graph_summary":{...},"available_skills":[{"name":"..."}]}'
```

`scripts/run.py` is a thin CLI over the in-process `core.loop_engine.skill_planner.SkillPlanner`:
it builds the frontier-tier LLM call from the supplied context and prints one strict JSON
artifact whose `plan` field is the `SkillExecutionPlan` array. Offline (no LLM key) the plan is
empty — a typed no-op, never a deterministic fallback. In the running framework the coordinators
call `SkillPlanner.propose_plan(phase)` directly (it reads Neo4j itself).

## Output artifact

One strict JSON object on stdout (see `references/ARTIFACT_SCHEMA.md`): a `meta` block and a
`plan` array of `{skill_name, target_endpoint_id, hypothesis_id, priority, rationale,
chaining_from}` steps. No prose; logs go to stderr.
