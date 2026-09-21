# Artifact Contract — `stall-ambiguity-resolution`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Stall Detector.
This skill **does not touch the target** (`meta.target_interaction:"none"`,
`meta.sends_traffic:false`) — it analyses a trace that already happened. It never
restarts the loop; it always returns a plan that **differs** from the stalled one
(`meta.no_restart:true`, `meta.revised_differs_from_stalled:true`).

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "stall-ambiguity-resolution artifact",
  "type": "object",
  "required": ["root_cause", "diagnosis", "revised_plan", "lesson_learned"],
  "properties": {
    "root_cause": { "enum": ["TOOL_BROKEN", "HYPOTHESIS_WRONG", "WAF_BLOCKING", "TARGET_DOWN", "AMBIGUOUS_OUTPUT"] },
    "diagnosis": { "type": "string" },
    "revised_plan": {
      "type": "object",
      "required": ["action", "reason"],
      "properties": {
        "action": { "enum": ["quarantine_tool", "kill_hypothesis", "switch_to_waf_evasion", "pause_and_cooldown", "switch_detection_method"] },
        "reason": { "type": "string" },
        "new_hypothesis": { "type": ["object", "null"] },
        "new_tool": { "type": ["string", "null"] }
      }
    },
    "lesson_learned": { "type": "string" },
    "stall_duration_steps": { "type": "integer" },
    "tokens_wasted": { "type": "integer" }
  }
}
```

Machine copy (incl. additive `meta`/`errors` and `revised_plan.cooldown_s`):
`references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "loop_trace": [
    {"step": 1, "action": "GET /api/users?id=1", "observation": "200 OK", "info_gain": 0},
    {"step": 2, "action": "GET /api/users?id=1", "observation": "200 OK", "info_gain": 0},
    {"step": 3, "action": "GET /api/users?id=1' OR 1=1--", "observation": "403 Forbidden", "info_gain": 0}
  ],
  "current_hypothesis": {"id": "H-42", "claim": "SQLi on /api/users?id"},
  "stall_type": "stalled_repetitive",
  "config": {
    "fallback_tools": {"sqlmap": "manual-httpx-differential"},
    "next_hypotheses": [{"id": "H-43", "claim": "IDOR on /api/users"}],
    "zero_gain_epsilon": 0, "cooldown_s": 60
  }
}
```

Each `loop_trace` step is normalized: `status` and `error_type` are parsed from
the `observation` string when not given explicitly, and `response_hash` is
computed (numbers masked) when absent. Optional per-step `status`,
`response_hash`, `error_type`, `cost_tokens`, `tool` are honored. `config`
supplies fallback tools, the next hypotheses to advance to, the zero-gain
epsilon, and the cooldown.

---

## 3. Root-cause classification (precedence, most specific first)

1. **TARGET_DOWN** — every step is server-unavailable (502/503/504 or
   timeout/reset) across the trace and **not** explained by a WAF signature.
   (A single action timing out repeatedly is reclassified `TOOL_BROKEN`.)
2. **WAF_BLOCKING** — a 403/429, or a 503 carrying a WAF signature, appears:
   payloads are blocked before the app.
3. **TOOL_BROKEN** — the SAME action repeats and every attempt hits an identical
   tool/infra error (timeout, connection reset/refused, tool_error), or a
   repeated clean 500 with no payload variation.
4. **HYPOTHESIS_WRONG** — ≥2 DISTINCT payloads all yield the identical response
   (same hash) with success-ish statuses: the target is indifferent; refuted.
5. **AMBIGUOUS_OUTPUT** — responses move but give no clear signal (fallback).

The precedence matters: a signature-bearing 503 is WAF, not TARGET_DOWN; an
injection 500 is not treated as "down".

---

## 4. Root cause → revised plan (never a restart)

| root_cause | revised action | carries |
| --- | --- | --- |
| TOOL_BROKEN | `quarantine_tool` | `new_tool` (config fallback or built-in), hypothesis kept |
| HYPOTHESIS_WRONG | `kill_hypothesis` | `new_hypothesis` (next in plan) or null |
| WAF_BLOCKING | `switch_to_waf_evasion` | hand payloads to waf-evasion-mastery |
| TARGET_DOWN | `pause_and_cooldown` | `cooldown_s`, notify Budget Governor |
| AMBIGUOUS_OUTPUT | `switch_detection_method` | e.g. time-based instead of error-based |

Every `revised_plan.action` is one of the five change-actions — the skill never
emits "repeat" or "restart", and `meta.revised_differs_from_stalled` is `true`.

`lesson_learned` is a single sentence for the Provenance Ledger, e.g.
`"Stall resolved: WAF blocking payloads on /api/users; switched to waf-evasion-mastery for encoding mutations."`

`stall_duration_steps` = the trailing run of ≤-epsilon info-gain steps (or the
whole trace); `tokens_wasted` = summed cost of those zero-gain steps (per-step
`cost_tokens` when given, else estimated).

---

## 5. Example artifact (for the §2 trace)

```json
{
  "root_cause": "WAF_BLOCKING",
  "diagnosis": "WAF is actively blocking. Payloads are returning 403/429 (or a signature-bearing 503) and are not reaching the app.",
  "revised_plan": {"action": "switch_to_waf_evasion",
    "reason": "Route the payloads for /api/users?id=1 through waf-evasion-mastery to derive encodings that reach the app; keep the hypothesis open.",
    "new_hypothesis": null, "new_tool": null},
  "lesson_learned": "Stall resolved: WAF blocking payloads on /api/users?id=1; switched to waf-evasion-mastery for encoding mutations.",
  "stall_duration_steps": 3, "tokens_wasted": 24,
  "meta": {"skill": "stall-ambiguity-resolution", "root_cause": "WAF_BLOCKING",
           "target_interaction": "none", "no_restart": true,
           "revised_differs_from_stalled": true, "sends_traffic": false},
  "errors": []
}
```

---

## 6. Stall-Detector-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `revised_plan.action` is one of the five change-actions and matches
   `root_cause` per §4; it is never a repeat of `meta.stalled_action`.
3. `meta.target_interaction == "none"` and `meta.sends_traffic == false`.
4. `lesson_learned` is non-empty and gets appended to the Provenance Ledger.
5. On `TOOL_BROKEN` a `new_tool` is present; on `HYPOTHESIS_WRONG` `new_hypothesis`
   is the next lead or explicitly null (request the next from the plan).
