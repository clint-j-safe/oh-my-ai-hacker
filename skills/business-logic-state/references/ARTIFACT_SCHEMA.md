# Artifact Contract — `business-logic-state`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error — including the **mutation gate** refusing to run — the skill emits a
schema-valid artifact with empty `findings` and `meta.status == "error"`
(with `meta.authorization_required == true` when it is the gate).

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "business-logic-state artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["flaw_type", "workflow", "evidence_spill_id"],
        "properties": {
          "flaw_type": { "enum": ["race_condition","step_skipping","negative_quantity","price_manipulation"] },
          "workflow": { "type": "array", "items": { "type": "string" } },
          "evidence_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `confidence`, `detail`, `meta`, `scope_summary`,
`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "target_base": "https://app.example.com",
  "workflows": [{
    "name": "checkout",
    "steps": [
      {"name": "add_to_cart", "method": "POST", "url": "/cart/add", "type": "json", "body": {"item": "x", "qty": 1}},
      {"name": "apply_discount", "method": "POST", "url": "/discount", "type": "json", "body": {"code": "SAVE10"}},
      {"name": "pay", "method": "POST", "url": "/pay", "type": "json", "body": {}},
      {"name": "checkout", "method": "POST", "url": "/checkout", "type": "json", "body": {}, "success": "\"status\":\\s*\"complete\""}
    ],
    "race_step": "apply_discount", "race_single_use": true,
    "skip_steps": ["pay"],
    "tamper": {"step": "add_to_cart", "fields": ["qty", "price"]},
    "state_check_url": "/cart",
    "success_indicator": "\"status\":\\s*\"complete\""
  }],
  "session_spill_id": "phase3_sessions_hash",
  "scope_policy_spill_id": "abc123",
  "config": {"authorize_mutations": false, "race_count": 20, "race_max": 50}
}
```

A **step** is a request template (`method`, `url`, `type` = json/form/query,
`body`, optional `success` regex). Workflow controls: `race_step` +
`race_single_use`, `skip_steps`, `tamper` (step + fields), `state_check_url`
(GET to read resulting state), `success_indicator`.

---

## 3. Safety model (the highest-blast-radius battery — read this)

| Guard | Enforcement |
| --- | --- |
| **Hard mutation gate** | If any step is non-GET and `config.authorize_mutations` is not `true`, the skill **refuses to run** and returns a fatal artifact with `meta.authorization_required:true`. It never enables mutations on its own. |
| Bounded concurrency | Race count = `min(config.race_count, config.race_max)`, hard-capped (default 50). Nothing unbounded. |
| Mutation ledger | Every mutating request is appended to `meta.mutations` (`workflow`, `step`, `method`, `url`, `body`) for the cleanup report. |
| Isolation | Each test runs in a **fresh session** (its own cookie jar) so tests don't cross-contaminate. |
| Scope + custody | Only in-scope hosts driven; full transaction logs offloaded to `evidence_spill_id`. |

`meta.safety` echoes `{mutations_authorized, race_capped_at, race_hard_max}`.

---

## 4. Detection

* **race_condition** — the prelude steps run once, then `race_count` concurrent
  copies of `race_step` fire via `asyncio.gather`. If a `race_single_use` action
  succeeds more than once, or the resulting state shows a negative
  total/balance, it is a confirmed race.
* **step_skipping** — the workflow runs with `skip_steps` omitted; if the
  terminal `success_indicator` is still reached, the required step wasn't
  enforced.
* **negative_quantity / price_manipulation** — the `tamper` step is sent with a
  negative value in each field; acceptance (2xx, no validation error) is the
  flaw, `confirmed` when the negative is reflected in state, else `suspected`.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"flaw_type": "race_condition", "workflow": ["add_to_cart","apply_discount","pay","checkout"],
     "confidence": "confirmed",
     "detail": {"race_step": "apply_discount", "concurrent": 20, "successes": 14, "single_use_expected": true},
     "evidence_spill_id": "9f2a1c7b6d4e0a53"},
    {"flaw_type": "step_skipping", "workflow": ["add_to_cart","apply_discount","pay","checkout"],
     "confidence": "confirmed", "detail": {"skipped": ["pay"], "reached_success_without_them": true},
     "evidence_spill_id": "0f1e2d3c4b5a6978"},
    {"flaw_type": "negative_quantity", "workflow": ["add_to_cart","apply_discount","pay","checkout"],
     "confidence": "confirmed", "detail": {"step": "add_to_cart", "field": "qty", "value": -1},
     "evidence_spill_id": "7c1e9a0b4d5f2318"}
  ],
  "meta": {"skill": "business-logic-state", "status": "ok", "race_count": 20,
           "safety": {"mutations_authorized": true, "race_capped_at": 20, "race_hard_max": 50},
           "mutations": [{"workflow": "checkout", "step": "add_to_cart", "method": "POST", "url": "…/cart/add"}]},
  "scope_summary": {"policy_present": true},
  "errors": []
}
```

The **gated** (unauthorized) response:

```json
{"findings": [],
 "meta": {"skill": "business-logic-state", "status": "error", "authorization_required": true,
          "safety": {"mutations_authorized": false}},
 "errors": [{"stage": "authorization", "error": "mutating workflow steps require config.authorize_mutations=true …"}]}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. if `meta.safety.mutations_authorized` is false, `findings` is empty and
   `meta.authorization_required` is true (the gate held).
3. `meta.race_count <= meta.safety.race_hard_max` (bounded).
4. every finding's `evidence_spill_id` resolves; every mutating action performed
   appears in `meta.mutations` (cleanup handle).
