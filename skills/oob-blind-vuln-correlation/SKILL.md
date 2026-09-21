---
name: oob-blind-vuln-correlation
description: >-
  The Observer's OOB handler: collects Interactsh/OAST callbacks and proves, by
  exact canary match, which specific request triggered a blind vulnerability
  (SSRF, XXE, RCE, deserialization), then computes request->callback latency. It
  waits with a timeout instead of assuming failure, reports non-matching
  callbacks separately (never falsely attributed), and lists canaries that never
  called back. Use in Phase 6. Listens only — sends no target traffic.
license: Apache-2.0
compatibility: Python 3.11+, httpx (for polling). Optional interactsh-client.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "6"
  loop-component: "5-observer"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(interactsh-client:*)
---

# OOB & Blind-Vuln Correlation

You are the **Observer** for out-of-band signals. Blind vulnerabilities announce
themselves by calling home; your job is to catch that callback and prove — not
guess — which request caused it, using the unique canary each request carried.
You attribute exactly, and you report what didn't come back as clearly as what
did. This is the shared component the SSRF, XXE, RCE, and deserialization skills
defer their OOB confirmation to.

## Correctness (this is the whole safety story)

1. **Observer only.** No target traffic, no mutations — you listen to the OOB
   channel and correlate.
2. **Exact attribution.** A callback maps to a `request_id` only when that
   request's unique `canary` appears in it. No fuzzy matching.
3. **No false positives.** Callbacks matching no pending canary go to
   `meta.uncorrelated_interactions`; canaries with no callback within the timeout
   go to `meta.timed_out`. Absence is reported, never guessed as success/failure.

## Inputs

```json
{ "oob_domain": "abc.oast.pro",
  "pending_tests": [{"request_id": "req-ssrf-1", "canary": "s1a2b3c4", "sent_at_ms": 1730000000000}],
  "config": {"timeout_s": 30, "poll_interval_s": 3, "poll_url": "https://oast/interactions"} }
```

Interaction source priority: `config.poll_url` (polled) > `interactions_inline`
(single pass, e.g. from a shared Interactsh session) > `interactsh-client`
output file. Interactions may be Interactsh JSON or plain host/path strings.

## How to run

```bash
python scripts/run.py '{"oob_domain":"abc.oast.pro","pending_tests":[{"request_id":"r","canary":"s1a2b3c4"}],"config":{"poll_url":"https://oast/interactions"}}'
```

`run.py` pipeline (`OOBCorrelator`):

1. `poll_interactsh()` — fetch interactions from the configured source in a wait
   loop (exits early once all canaries have called back or the timeout hits).
2. `_normalize()` — coerce each interaction to `{protocol, ident, ts_ms, raw}`.
3. `extract_canary()` / correlate — bind an interaction to a `request_id` only on
   an exact canary substring; first callback per canary wins, repeats counted.
4. compute `latency_ms = callback_ts − sent_at_ms`; offload the raw interaction
   to `raw_log_spill_id`.
5. report `timed_out` and `uncorrelated_interactions`.

## Typed exits

- `callbacks_correlated` — one or more blind vulns proven by attributed callback.
- `partial` — some canaries correlated, others in `timed_out`.
- `no_callbacks` — nothing came back within the timeout (all `timed_out`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| Interactsh | OOB/OAST callback server + client | https://github.com/projectdiscovery/interactsh |
| Interactsh Python client | Programmatic register/poll | https://pypi.org/project/interactsh/ |

Install: `pip install httpx` (+ interactsh-client from upstream). httpx is used
for the generic poll source.

## Wordlists

None — correlation is driven by the canary IDs the upstream skills embedded.
