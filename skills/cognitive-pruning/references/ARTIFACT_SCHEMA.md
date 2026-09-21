# Artifact Contract — `cognitive-pruning`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Semantic
Compactor. This skill **does not touch the target** (`meta.target_interaction:
"none"`, `meta.sends_traffic:false`) — it manages the agent's own cognitive state.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "cognitive-pruning artifact",
  "type": "object",
  "required": ["pruned_hypotheses", "killed_hypotheses", "folded_memory", "context_savings_estimate"],
  "properties": {
    "pruned_hypotheses": {
      "type": "array",
      "description": "Hypotheses that survived pruning. Full context preserved.",
      "items": {
        "type": "object",
        "required": ["id", "claim", "evidence_for", "evidence_against", "next_step"],
        "properties": {
          "id": {"type": "string"}, "claim": {"type": "string"},
          "evidence_for": {"type": "integer"}, "evidence_against": {"type": "integer"},
          "cost_tokens": {"type": "integer"}, "survival_score": {"type": "number"},
          "next_step": {"type": "string"}
        }
      }
    },
    "killed_hypotheses": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "kill_reason"],
        "properties": {
          "id": {"type": "string"}, "claim": {"type": "string"},
          "kill_reason": {"type": "string"}, "tokens_saved": {"type": "integer"}
        }
      }
    },
    "folded_memory": {
      "type": "array",
      "description": "Dense paragraphs (<50 tokens each) summarizing closed threads.",
      "items": {"type": "string"}
    },
    "context_savings_estimate": {"type": "integer"}
  }
}
```

Machine copy (incl. additive `meta`/`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "context_budget_remaining_pct": 15,
  "open_hypotheses": [
    {"id": "H-3", "claim": "IDOR on /api/invoices", "evidence_for": 3,
     "evidence_against": 1, "cost_tokens": 4500, "next_step": "diff 2 accounts on /api/invoices/{id}"}
  ],
  "closed_threads": [
    {"id": "7", "summary": "SQLi on /api/users?id", "outcome": "confirmed",
     "method": "time-based", "tokens": 6200}
  ],
  "conversation_summary": "...",
  "config": {"kill_threshold": 0.5, "fold_max_tokens": 50,
             "neo4j": {"uri": "bolt://...", "user": "neo4j", "password": "...", "database": "neo4j"}}
}
```

* `open_hypotheses` — each needs `evidence_for`, `evidence_against`, `cost_tokens`;
  `id`, `claim`, `next_step` are preserved verbatim for survivors.
* `closed_threads` — `id`, `summary`, `outcome` (+ optional `method`, `tokens`).
  `tokens` is what the thread occupied (drives fold savings; estimated if absent).
* `config.kill_threshold` — default `0.5`. `config.fold_max_tokens` — default `50`.
* `config.neo4j` — optional. If present and `open_hypotheses` is omitted, hypotheses
  are read from Neo4j WorkingMemory; kills are written back (`status='killed'`).

---

## 3. Scoring & the load-bearing rule

```
score = (evidence_for - evidence_against) / (cost_tokens / 1000)
  cost_tokens == 0 -> 999   (cannot judge cost yet -> preserve)
  score <  threshold(0.5)   -> KILL   (dead end, not worth more tokens)
  score >= threshold        -> PRESERVE
```

* **Preserved hypotheses are never compressed.** They keep the full `claim`, the
  full `evidence_for`/`evidence_against`, `cost_tokens`, the computed
  `survival_score`, and their `next_step` plan verbatim. A missing `next_step` is
  *added* (never truncates existing content) and noted in `meta.notes`.
* **Killed hypotheses** get a one-sentence `kill_reason`
  (`"Killed: N probe(s) yielded evidence_for=…/against=… (score X < T). Cost: C tokens."`)
  and `tokens_saved` = the context footprint freed by dropping them.
* **Closed threads** are folded to one dense `[THREAD-<id>] <summary> → <OUTCOME>
  via <method>.` line, clipped to `< fold_max_tokens`. Only closed/refuted threads
  and killed dead ends are ever compressed — surviving hypotheses are not
  compaction food.

`context_savings_estimate` = Σ killed `tokens_saved` + Σ (thread original −
folded) tokens. `meta.counts` breaks down open-in / preserved / killed /
closed-folded, and `meta.fold_tokens_saved` / `meta.kill_tokens_saved` split the
estimate.

---

## 4. Example artifact (abridged)

```json
{
  "pruned_hypotheses": [
    {"id": "H-3", "claim": "IDOR on /api/invoices", "evidence_for": 3, "evidence_against": 1,
     "cost_tokens": 4500, "survival_score": 0.444, "next_step": "diff 2 accounts on /api/invoices/{id}"}
  ],
  "killed_hypotheses": [
    {"id": "H-9", "claim": "XXE on /upload", "kill_reason": "Killed: 3 probe(s) yielded evidence_for=1/evidence_against=2 (score -0.20 < 0.5). Cost: 5000 tokens.",
     "tokens_saved": 34, "survival_score": -0.2}
  ],
  "folded_memory": ["[THREAD-7] SQLi on /api/users?id → CONFIRMED via time-based."],
  "context_savings_estimate": 6100,
  "meta": {"skill": "cognitive-pruning", "trigger": "context_budget_exceeded",
           "target_interaction": "none", "source": "input", "kill_threshold": 0.5,
           "counts": {"open_in": 2, "preserved": 1, "killed": 1, "closed_folded": 1},
           "sends_traffic": false},
  "errors": []
}
```

(Note: with `cost_tokens=4500`, H-3 scores `2/4.5 = 0.444` — below 0.5 — so a
strict reading would kill it; tune `kill_threshold` per run. The example uses it
to show the field shape.)

---

## 5. Compactor-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. Every `pruned_hypotheses[]` item has a non-empty `next_step` and its `claim`
   matches the input verbatim (no truncation of survivors).
3. Every `folded_memory[]` string is `< fold_max_tokens`.
4. `context_savings_estimate >= 0` and equals `meta.fold_tokens_saved +
   meta.kill_tokens_saved`.
5. `meta.target_interaction == "none"` and `meta.sends_traffic == false`.
