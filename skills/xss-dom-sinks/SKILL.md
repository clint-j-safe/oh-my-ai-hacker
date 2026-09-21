---
name: xss-dom-sinks
description: >-
  Tests endpoints for Reflected, Stored, and DOM-based XSS using context-aware
  payloads (HTML body, attribute, JS string) and verifies EXECUTION by driving
  Playwright and catching the JavaScript dialog the payload fires. Stored XSS is
  verified across two Phase 3 sessions (inject as A, observe as B). Payloads are
  benign alert() canaries only — no cookie theft, no external beacons. Use in
  Phase 5 for JS-heavy apps. Returns findings with offloaded screenshot/DOM
  evidence. Do NOT use for exploitation beyond proof of execution.
license: Apache-2.0
compatibility: >-
  Python 3.11+, playwright (+ chromium), httpx. Optional: dalfox for a fast
  reflection pre-scan. Network access to the in-scope target.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(playwright:*) Bash(dalfox:*)
---

# XSS & DOM Sinks

You are executing a **Phase 5 offensive battery**. You prove cross-site
scripting by making the payload *execute* in a real browser — a dialog fires
carrying your canary — not by guessing from reflection. You prove it and stop
there: the payloads do nothing but pop a benign alert.

## Safety model (load-bearing — do not weaken)

1. **Benign proof-only payloads.** Every payload is `alert()/confirm()/prompt()`
   with a unique `XSS<hex>` canary. A finding is `confirmed` only when a dialog
   fires whose message contains that canary. No `document.cookie` exfiltration,
   no `fetch()`/beacon to any host, no defacement.
2. **Stored XSS is a tracked mutation.** Reflected/DOM are non-persistent.
   Stored testing writes a benign canary and records it in `meta.mutations`
   (canary + location) for the cleanup skill. It runs only when a `view_url` is
   given and `config.allow_stored` (default true).
3. **Scope-gated.** Only in-scope endpoint hosts are tested.
4. **Offload + Artifact Contract.** Screenshot/DOM evidence → spill store; strict
   JSON on stdout, no prose.

## Inputs

```json
{ "endpoints": [
    {"url":"https://app.example.com/search","params":["q"],"context":"html"},
    {"url":"https://app.example.com/profile","params":["bio"],"context":"attr",
     "method":"POST","store_param":"bio","view_url":"https://app.example.com/u/me"}],
  "session_pool_spill_id":"phase3_sessions_hash" }
```

## How to run

```bash
python scripts/run.py '{"endpoints":[{"url":"https://app.example.com/search","params":["q"],"context":"html"}]}'
```

`run.py` pipeline (`XSSTester`):

1. Scope-filter endpoints; launch one headless Chromium for the run.
2. `test_reflected()` — inject per param (httpx), detect unencoded reflection,
   then load in the browser and catch the dialog.
3. `test_dom()` — load with the payload in the param **and** the fragment
   (client-only sinks: `location.hash`/`document.write`/`innerHTML`); a fired
   dialog with no server reflection is DOM-based.
4. `test_stored()` — inject as session A, observe `view_url` as session B; record
   the mutation.
5. `run_dalfox()` — optional fast reflection pre-scan when present.
6. Offload screenshot + DOM snapshot per finding → `evidence_spill_id`.

Payloads are context-aware: `context:"attr"` prefers attribute break-outs
(`" autofocus onfocus=…`), `"js"` prefers string break-outs (`';…//`), `"html"`
prefers tag injection (`<img onerror=…>`).

## Typed exits

- `xss_confirmed` — ≥1 finding with `executed: true`.
- `xss_suspected` — reflection/stored writes without observed execution.
- `no_xss` — endpoints tested, nothing fired.
- `out_of_scope` / `no_browser` — fatal (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| Playwright (Python) | Browser DOM execution + dialog capture | https://github.com/microsoft/playwright-python |
| Dalfox | Fast reflection/XSS pre-scan (optional) | https://github.com/hahwul/dalfox |

Install: `pip install playwright httpx && playwright install chromium`.

## Wordlists

Payloads are generated in-process (context-aware, canary-tagged). For a broader
manual payload set: SecLists XSS
(https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS).
