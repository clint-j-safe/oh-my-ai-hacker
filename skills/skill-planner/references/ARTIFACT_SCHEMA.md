# skill-planner — Artifact Schema

One strict JSON object on stdout. No prose; logs go to stderr. A non-parseable or
schema-invalid output is a failure to the caller. The machine-readable copy is
`references/artifact.schema.json` (JSON Schema Draft 2020-12).

## Output

```json
{
  "plan": [
    {
      "skill_name": "sqli-database-injection",
      "target_endpoint_id": "ep-123",
      "hypothesis_id": "hyp-456",
      "priority": "high",
      "rationale": "SQL error signatures detected on /login",
      "chaining_from": null
    }
  ],
  "meta": {
    "skill": "skill-planner",
    "version": "1.0",
    "phase": "1-6",
    "loop_component": "35-skill-planner",
    "status": "ok",
    "generated_at": "2026-09-18T00:00:00+00:00",
    "sends_traffic": false,
    "phase_planned": 5,
    "step_count": 1
  },
  "errors": []
}
```

## `plan` — the SkillExecutionPlan (array of steps)

Each step is an object:

| Field | Type | Meaning |
| --- | --- | --- |
| `skill_name` | string | Skill folder to run. Must exist in the Skill Registry. |
| `target_endpoint_id` | string \| null | Endpoint node id to run against. `null` = a target-level step (e.g. recon against the root); scope is then enforced by the SafetyGate at dispatch. |
| `hypothesis_id` | string \| null | Hypothesis under test, if the step is driven by one. |
| `priority` | `"high"` \| `"medium"` \| `"low"` | Ordering hint; the validator keeps `high` first when it truncates to budget. |
| `rationale` | string | Why this skill against this target (for tracing). |
| `chaining_from` | string \| null | The prior step/finding this step chains from (e.g. feed an SSRF-discovered internal IP into SQLi), or `null`. |

## Input contract

```json
{ "phase": 5,
  "graph_summary": { "endpoints": [...], "open_hypotheses": [...], "findings_total": 0,
                     "verified_findings": 0, "session_roles": ["standard_user"] },
  "available_skills": [ {"name": "sqli-database-injection", "description": "..."} ] }
```

## Safety model

| Invariant | Value |
| --- | --- |
| `meta.sends_traffic` | always `false` — the planner reasons over graph state only |
| Proposal, not execution | every step is culled by the deterministic `SkillPlanValidator` (availability, scope, risk-vs-phase, budget) and then, per action, by the `SafetyGate` |
| Offline behaviour | empty `plan` (a typed no-op) — never a deterministic class→skill fallback |

## Caller-side validation

1. Parse stdout as JSON; require `plan` (array) and `meta.status == "ok"`.
2. Pass `plan` to `SkillPlanValidator.validate_plan(plan, phase)`; only its approved steps run.
3. Each approved step is built into an `Action` and dispatched only if the `SafetyGate` allows it.
