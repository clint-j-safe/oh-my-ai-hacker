---
name: stall-ambiguity-resolution
description: >-
  Triggered by the Stall Detector when N consecutive near-zero-gain observations
  are detected. Analyzes the loop trace to determine the root cause — tool broken,
  hypothesis wrong, WAF blocking, target down, or ambiguous output — and
  reformulates the plan into a NEW action that differs from the stalled one
  instead of blindly restarting. Returns a revised action plan and a one-sentence
  lesson for the Provenance Ledger. Use at any phase on a stalled_repetitive
  signal. Analyses a trace that already happened; it does NOT interact with the
  target.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib only).
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "any"
  loop-component: "8-stall-detector"
  trigger: "stalled_repetitive"
  target-interaction: "none"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Stall & Ambiguity Resolution

You are the loop's way out of a rut. When it has spent N steps learning nothing —
hammering the same request, getting blocked, watching noisy output — restarting
just burns the same tokens again. Your job is to read the trace, name *why* the
loop stalled, and hand back a genuinely different plan plus a lesson so the loop
never walks into the same wall twice. You never touch the target; you reason over
what already happened.

## Correctness (this is the whole safety story)

1. **No target interaction.** No HTTP, no payloads, no network. You analyse a
   trace. `meta.target_interaction:"none"`, `meta.sends_traffic:false`.
2. **Never restart.** The revised plan is always one of five *change*-actions —
   quarantine the tool, kill the hypothesis, switch to WAF evasion, pause and
   cool down, or switch detection method. It is never "repeat" or "restart", and
   never a repeat of the stalled action (`meta.revised_differs_from_stalled`).
3. **Precedence that respects signal.** A signature-bearing 503 is WAF, not
   TARGET_DOWN; an injection-triggered 500 is not treated as "down"; a single
   action timing out repeatedly is a broken tool, not a dead target. The
   classification is ordered most-specific-first so a real signal is not lost to
   a coarser bucket.
4. **Every stall teaches something.** A one-sentence `lesson_learned` goes to the
   Provenance Ledger on every pass.

## Root-cause classification (precedence)

1. `TARGET_DOWN` — every step is 502/503/504 or timeout/reset, not WAF.
2. `WAF_BLOCKING` — a 403/429 or signature-bearing 503 appears.
3. `TOOL_BROKEN` — same action, identical tool/infra error each time.
4. `HYPOTHESIS_WRONG` — ≥2 distinct payloads, identical responses → refuted.
5. `AMBIGUOUS_OUTPUT` — responses move but give no clear signal (fallback).

## Inputs

```json
{ "loop_trace": [
    {"step": 1, "action": "GET /api/users?id=1", "observation": "200 OK", "info_gain": 0},
    {"step": 2, "action": "GET /api/users?id=1' OR 1=1--", "observation": "403 Forbidden", "info_gain": 0}],
  "current_hypothesis": {"id": "H-42", "claim": "SQLi on /api/users?id"},
  "stall_type": "stalled_repetitive",
  "config": {"fallback_tools": {"sqlmap": "manual-httpx-differential"},
             "next_hypotheses": [{"id": "H-43", "claim": "IDOR"}], "cooldown_s": 60} }
```

`status`/`error_type`/`response_hash` are parsed from each `observation` when not
given explicitly. `config` supplies fallbacks, next leads, and the cooldown.

## How to run

```bash
python scripts/run.py '{"loop_trace":[{"step":1,"action":"GET /x","observation":"200 OK","info_gain":0},{"step":2,"action":"GET /x?q=1'"'"' OR 1=1--","observation":"403 Forbidden","info_gain":0}],"current_hypothesis":{"id":"H-42","claim":"SQLi"}}'
```

`run.py` pipeline (`StallResolver`):

1. `_norm()` — parse status/error/hash/attack-ness from each step.
2. `classify_root_cause()` — apply the ordered precedence.
3. `generate_diagnosis()` / `formulate_revised_plan()` — one of five change
   actions with a concrete reason, plus `new_tool` / `new_hypothesis` when apt.
4. `record_lesson()` + accounting — the Ledger lesson, `stall_duration_steps`,
   `tokens_wasted`.

## Typed exits

- `root_cause` — one of the five enums.
- `revised_plan.action` — the matching change-action, never a restart.
- `lesson_learned` — one sentence for the Provenance Ledger.
- `stall_duration_steps` / `tokens_wasted` — how much the stall cost.

## External tools

None — pure trace analysis (`re`, `hashlib`).

## Wordlists

None.
