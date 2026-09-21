---
name: cognitive-pruning
description: >-
  Triggered by the Semantic Compactor when the context budget is exceeded. Scores
  every open hypothesis by evidence strength vs cost-so-far (score = (for −
  against) / (cost_tokens/1000)), kills dead-end threads below the threshold with
  a one-line reason, folds closed investigations into dense (<50-token) memory
  paragraphs, and preserves load-bearing open hypotheses with their full claim,
  evidence, and next-step plan intact. Returns a pruned hypothesis graph and the
  token savings. Use at any phase on a context_budget_exceeded signal. Manages the
  agent's own cognitive state only — it does NOT interact with the target.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib). Optional neo4j driver, optional tiktoken.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "any"
  loop-component: "13-semantic-compactor"
  trigger: "context_budget_exceeded"
  target-interaction: "none"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Cognitive Pruning

You are the agent's pruning shears. When the context is filling up, most of what
it holds is no longer earning its keep — dead-end hypotheses that three probes
never moved, closed threads whose full transcript can collapse to a single dense
line. Your job is to decide, coldly and by the numbers, what stays and what goes
— and to protect the few load-bearing leads absolutely while you do it. You never
touch the target; you only reshape the agent's own memory.

## Correctness (this is the whole safety story)

1. **No target interaction.** No HTTP, no payloads, no network to any scope. Pure
   reasoning over the hypothesis graph. `meta.target_interaction:"none"`.
2. **Preserved is sacred.** A surviving hypothesis is never compressed — full
   `claim`, full evidence counts, `cost_tokens`, `survival_score`, and its
   `next_step` verbatim. Survivors are not compaction food; only closed/refuted
   threads and killed dead ends are ever compressed or dropped. A missing
   `next_step` is *added*, never at the expense of existing content.
3. **Transparent kills.** Every kill carries a one-sentence, auditable reason with
   the evidence counts, the score, the threshold, and the sunk cost. Nothing
   disappears silently.
4. **Honest accounting.** `context_savings_estimate` is the sum of freed kill
   footprints and closed-thread fold savings; `meta` splits and counts them.

## Scoring

```
score = (evidence_for - evidence_against) / (cost_tokens / 1000)
  cost_tokens == 0 -> 999   (cannot judge cost yet -> preserve)
  score <  threshold(0.5)   -> KILL
  score >= threshold        -> PRESERVE
```

The kill threshold is configurable per run (`config.kill_threshold`, default
0.5); fold paragraphs are clipped to `config.fold_max_tokens` (default 50).

## Inputs

```json
{ "context_budget_remaining_pct": 15,
  "open_hypotheses": [{"id":"H-3","claim":"IDOR on /api/invoices","evidence_for":3,
                       "evidence_against":1,"cost_tokens":4500,"next_step":"diff 2 accounts"}],
  "closed_threads": [{"id":"7","summary":"SQLi on /api/users?id","outcome":"confirmed",
                      "method":"time-based","tokens":6200}],
  "conversation_summary": "...",
  "config": {"kill_threshold": 0.5, "fold_max_tokens": 50} }
```

When `config.neo4j` is set and `open_hypotheses` is omitted, the graph is read
from Neo4j WorkingMemory and kills are written back (`status='killed'`).

## How to run

```bash
python scripts/run.py '{"open_hypotheses":[{"id":"H-3","claim":"IDOR","evidence_for":3,"evidence_against":1,"cost_tokens":4500}],"closed_threads":[{"id":"7","summary":"SQLi on /api/users","outcome":"confirmed","method":"time-based","tokens":6200}]}'
```

`run.py` pipeline (`CognitivePruner`):

1. `load_hypotheses()` — from input, or Neo4j when configured.
2. `score_hypothesis()` + `kill_dead_ends()` — split into preserved (verbatim) and
   killed (with reason + freed footprint).
3. `fold_closed_threads()` — dense `[THREAD-id] … → OUTCOME via method.` clipped
   to the fold limit.
4. `estimate_savings()` + `return_artifact()` — total tokens saved and the graph.

## Typed exits

- `pruned_hypotheses` — survivors, full context, sorted by score.
- `killed_hypotheses` — dead ends with `kill_reason` + `tokens_saved`.
- `folded_memory` — one dense line per closed thread, each `< fold_max_tokens`.
- `context_savings_estimate` — integer tokens reclaimed.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| neo4j (optional) | Read/write the hypothesis graph in WorkingMemory | https://github.com/neo4j/neo4j-python-driver |
| tiktoken (optional) | Accurate token counts (heuristic fallback otherwise) | https://github.com/openai/tiktoken |

Install: none required (stdlib). `pip install neo4j tiktoken` to enable the
optional paths.

## Wordlists

None — no security tooling; pure cognitive management.
