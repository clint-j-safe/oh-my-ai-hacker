---
name: delegation-collaboration
description: >-
  The Loop Registry's delegation brain. Decides when a task is handled inline by
  the current loop vs delegated to a spawned sub-agent with its own isolated
  context and budget, using a token/budget/endpoint-count decision matrix and a
  concurrency cap. On delegate it writes a full sub-agent spec (scope, entry-state
  Cypher, budget, exit condition, mailbox id), persists and registers it. On
  completion it runs the merge protocol: read the sub-agent's mailbox, dedupe
  against the parent graph, merge only unique findings with preserved provenance.
  Use in Phase 5/6 for parallelizable, context-isolated work. Target interaction
  is indirect — it specs sub-agents but sends no traffic itself.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib). Optional neo4j driver for the registry/mailbox.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5-6"
  loop-component: "29-loop-registry"
  target-interaction: "indirect"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Delegation & Collaboration

You are the loop's decision about when to go it alone and when to send help. Some
work belongs inline — it needs the live conversation, or it is too small to be
worth spawning for. Other work — forty-five independent admin endpoints, a whole
role matrix — is better handed to a sub-agent with its own context window and its
own budget, so the parent doesn't drown. Your job is to make that call, spec the
sub-agent tightly when you delegate, and merge its findings back cleanly when it
returns. You send no traffic yourself.

## Correctness (this is the whole safety story)

1. **Indirect only.** This skill sends no requests. The sub-agents it specs do
   the probing, and only ever within the scope and budget written into their
   spec. `meta.target_interaction:"indirect"`, `meta.sends_traffic:false`.
2. **Scoped, bounded sub-agents.** Every delegate produces an explicit `scope`
   (exact endpoints/parameters/roles), a `budget` (token + time caps), and an
   `exit_condition`. A sub-agent is never spawned open-ended.
3. **Respect capacity.** If delegating would exceed `max_concurrent_sub_agents`,
   the decision falls back to `inline` — the loop is never over-subscribed.
4. **Isolate what can be isolated; keep what can't.** Tasks needing conversation
   history or that are sequential are forced inline — they cannot run correctly
   in an isolated context.
5. **Merge without duplication or lost provenance.** Sub-agent findings are
   de-duplicated against the parent graph by `(vuln_class, endpoint)` and merged
   idempotently, each tagged `discovered_by: sub-agent-<id>`.

## Decision matrix

- **INLINE** — needs history / sequential; or `estimated_tokens < 10000`; or no
  trigger fires.
- **DELEGATE** — `estimated_tokens > 20000` AND budget `< 40%`; or
  `estimated_endpoints > 20`; or flagged `parallelizable` and large.
- **Cap** — want-to-delegate but `active >= max_concurrent` → `inline`.

## Inputs

Decide:

```json
{ "action": "decide",
  "current_task": {"description": "Test all /api/admin/* for IDOR", "estimated_endpoints": 45,
                   "estimated_tokens": 80000, "parallelizable": true, "vuln_class": "IDOR",
                   "scope": {"endpoints": ["/api/admin/users"], "parameters": ["id"], "roles": ["user","admin"]}},
  "current_context_budget_remaining_pct": 30, "active_sub_agents": 2, "max_concurrent_sub_agents": 5 }
```

Merge:

```json
{ "action": "merge", "mailbox_id": "mbx-...", "sub_agent_id": "sub-agent-...",
  "sub_agent_findings": [{"vuln_class": "IDOR", "endpoint": "/api/admin/users?id=2"}],
  "parent_findings":    [{"vuln_class": "IDOR", "endpoint": "/api/admin/roles"}] }
```

`config.neo4j` enables the Loop Registry node + `SubAgentMailbox` reads and the
idempotent graph merge; without it the skill runs input-driven.

## How to run

```bash
python scripts/run.py '{"current_task":{"description":"Test /api/admin/* for IDOR","estimated_endpoints":45,"estimated_tokens":80000},"current_context_budget_remaining_pct":30,"active_sub_agents":2,"max_concurrent_sub_agents":5}'
```

`run.py` pipeline (`DelegationManager`): `should_delegate()` →
`build_sub_agent_spec()` → `register_sub_agent()` (spill + registry); or, in merge
mode, `merge_sub_agent_results()` → `deduplicate_findings()`.

## Typed exits

- `decision: inline` — return the task to the current loop; `sub_agent_spec: null`.
- `decision: delegate` (spawn) — `sub_agent_spec` with mailbox, scope, budget,
  exit condition, entry-state query; registered and spilled.
- `decision: delegate` (merge) — `merge_protocol` with merged/duplicate counts and
  the provenance tag.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| neo4j (optional) | Loop Registry node, mailbox reads, idempotent merge | https://github.com/neo4j/neo4j-python-driver |

Install: none required (stdlib); `pip install neo4j` to enable the registry paths.

## Wordlists

None — pure orchestration.
