---
name: business-logic-state
description: >-
  Tests multi-step workflows for logic flaws: race conditions (bounded
  concurrent execution), step-skipping (omitting a required step such as
  payment), negative quantities, and price manipulation. Requires the Phase 2
  crawl data to map workflow steps. Mutating by nature, so it refuses to run
  unless mutations are explicitly authorized, caps concurrency, and logs every
  state-changing request for cleanup. Use in Phase 5 on stateful workflows.
  Returns logic-flaw findings with offloaded transaction logs.
license: Apache-2.0
compatibility: Python 3.11+, httpx (playwright optional for browser-driven flows).
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(playwright:*)
---

# Business Logic & State

You are executing the **hardest Phase 5 battery**. Logic flaws don't come from
payloads — they come from doing legitimate actions in an illegitimate order, at
an illegitimate scale, or with illegitimate values. This is also the most
dangerous battery, because proving a flaw means changing the app's state. You
change nothing without explicit authorization, and you record everything you do.

## Safety model (load-bearing — do not weaken)

1. **Hard mutation gate.** Any non-GET step is refused unless
   `config.authorize_mutations` is explicitly `true`. Without it the skill
   returns a fatal artifact (`meta.authorization_required:true`) — it never
   turns mutations on by itself.
2. **Bounded.** Race concurrency = `min(race_count, race_max)`, hard-capped
   (default 50).
3. **Accountable.** Every mutating request is appended to `meta.mutations` for
   the cleanup report.
4. **Isolated + scoped.** Each test runs in a fresh session; only in-scope hosts
   are driven; transaction logs offload to the spill store. Strict JSON on
   stdout, no prose.

## Inputs

Full request-template workflows (from Phase 2 crawl). See
`references/ARTIFACT_SCHEMA.md §2` for the step shape. Key controls per workflow:
`race_step`, `skip_steps`, `tamper:{step,fields}`, `state_check_url`,
`success_indicator`.

## How to run

```bash
python scripts/run.py '{"target_base":"https://app.example.com","workflows":[...],"config":{"authorize_mutations":true}}'
```

`run.py` pipeline (`LogicTester`):

1. Mutation gate — abort unless authorized.
2. `test_race_conditions()` — prelude once, then `race_count` concurrent copies
   of `race_step` (`asyncio.gather`); a single-use action succeeding >1× or a
   negative resulting balance is a race.
3. `test_step_skipping()` — run the flow with `skip_steps` omitted; reaching the
   terminal `success_indicator` anyway is the flaw.
4. `test_parameter_tampering()` — send the `tamper` step with negative values;
   acceptance (2xx, no validation error) is the flaw (`confirmed` when the
   negative shows up in state).
5. Offload each transaction transcript → `evidence_spill_id`.

## Typed exits

- `logic_flaw_found` — ≥1 finding.
- `authorization_required` — mutating steps but no mutation budget
  (`meta.authorization_required:true`; fatal, no requests sent).
- `logic_ok` — workflows exercised, no flaws.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| httpx | Async concurrent workflow requests | https://github.com/encode/httpx |
| Playwright | Browser-driven multi-step flows (optional) | https://github.com/microsoft/playwright-python |

Install: `pip install httpx` (+ playwright for browser flows).

## Wordlists

None fixed — workflow steps come from Phase 2 crawl data. Reference ideas:
SecLists Fuzzing (https://github.com/danielmiessler/SecLists/tree/master/Fuzzing).
