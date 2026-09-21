---
name: blast-radius-estimation
description: >-
  The Proposer's impact governor. Classifies the risk of a proposed action
  (read_only / mutating / destructive / account_creating) from its HTTP method,
  vulnerability class, and payload verbs, then selects the GENTLEST probe that
  still confirms the vulnerability — a boolean/time delay for SQLi, one canary
  account instead of a hundred, an OOB DNS callback instead of running a command
  — and reports the mutation cost the budget should charge. Use in Phase 5 before
  executing any payload that could alter state. Advisory only, sends no traffic;
  never upgrades risk and never passes a destructive action through as-is.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib only — re, hashlib).
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "2-proposer"
  advisory-only: "true"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Blast-Radius & Impact Estimation

You are the Proposer's sense of **how much could break**. The loop wants a
finding confirmed; it does not need the target damaged to get there. Your job is
to look at a proposed action, grade its blast radius, and hand back the gentlest
probe that still proves the bug — so the loop confirms with a delay instead of a
dropped table, one test account instead of a hundred, a DNS ping instead of a
command. Confirm, don't exploit.

## Correctness (this is the whole safety story)

1. **Never upgrade.** The gentle probe's grade is always `<=` the proposed
   action's grade. A read-only proposal never comes back mutating.
2. **Destructive is never passed through.** A `destructive` proposal is
   downgraded to a read-only / OOB confirmation and flagged
   `meta.recommend_abort_original:true`; real exploitation, if ever needed, goes
   through the sandbox/PoC path, not this action.
3. **Probes are benign by construction.** No shell/OS weaponization, no data
   exfiltration, no mass mutation — SQLi is confirmed by a boolean/time
   differential that touches no row, RCE by a benign OOB DNS callback with no
   command output, LFI by reading `/etc/hostname` not `/etc/shadow`. Every
   generated probe is asserted free of destructive tokens before it is emitted.
4. **No traffic.** You reason only; the deterministic Safety Gate and the
   mutation budget do the enforcing.

## Inputs

```json
{ "proposed_action": {"url": "https://app.example.com/api/orders/42",
                      "method": "DELETE", "payload": "'; DROP TABLE users;-- -",
                      "vuln_class": "SQLi"},
  "config": {"oob_domain": "abc.oast.pro"} }
```

Method, payload verbs and `vuln_class` together drive the grade; `oob_domain` is
the controlled canary domain for out-of-band probes.

## How to run

```bash
python scripts/run.py '{"proposed_action":{"url":"https://app.example.com/o/42","method":"DELETE","payload":"1; DROP TABLE users","vuln_class":"SQLi"}}'
```

`run.py` pipeline (`BlastRadiusEstimator`):

1. `classify_risk()` — grade = the higher of {destructive/mutating payload verb,
   vuln-class intrinsic grade, HTTP-method baseline}; account-creation endpoints
   are graded outright.
2. `select_gentle_probe()` — pick the gentlest confirming probe for the vuln
   class, stamped with a per-run `canary` (`BR<hash8>`); assert it is benign.
3. `return_artifact()` — clamp the probe grade `<=` proposed grade, compute
   `estimated_mutation_cost` (0 for read-only), and write the justification.

## Typed exits

- `risk_grade: read_only` — confirm freely; cost 0.
- `risk_grade: account_creating` — the probe creates exactly one labelled test
  account; cost 1.
- `risk_grade: mutating` — the probe makes one reversible/aborted change; cost 1.
- `risk_grade: destructive` — do **not** run the original;
  `meta.recommend_abort_original:true` and the gentle probe confirms read-only.

## External tools

None — pure heuristic reasoning (`re`, `hashlib`).

## Wordlists

None. The vuln-class→risk and vuln-class→gentle-probe tables are built in and
easy to extend in `scripts/run.py`.
