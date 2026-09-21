---
name: sqli-database-injection
description: >-
  Tests specific parameters for SQL injection using error, boolean-differential,
  time-based, union, and optional OOB (DNS) methods, selecting WAF-bypass tamper
  chains from the Phase 2 tech fingerprint and confirming findings by dual-method
  agreement. Wraps ghauri and sqlmap. Detection + read-only proof only (DB
  identity metadata) — no stacked queries, no table dumps, no OS/file/RCE
  actions, risk capped at 2. Use in Phase 5 on database-driven endpoints already
  identified as in scope. Returns a JSON findings artifact with offloaded logs.
license: Apache-2.0
compatibility: >-
  Python 3.11+. External CLIs (auto-detected, degrade gracefully if absent):
  ghauri (preferred), sqlmap. Optional: interactsh-client for OOB. Network
  access to the in-scope target.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(ghauri:*) Bash(sqlmap:*) Bash(interactsh-client:*)
---

# SQLi & Database Injection

You are executing a **Phase 5 offensive battery**. You test named parameters for
SQL injection and *confirm* what you find — you do not exfiltrate data or execute
statements. Proof is that the parameter is injectable and which DBMS answers;
demonstrated impact, not damage.

## Safety model (load-bearing — do not weaken)

1. **Detection + read-only proof only.** Techniques are limited to `BEUT`
   (Boolean/Error/Union/Time) — read-only SELECT inference. Stacked queries
   (`S`) are stripped from any config. Proof is `--banner`/`--current-user`/
   `--current-db`/`--is-dba` — DB identity, never table data.
2. **Blocked, hard.** `--os-shell`, `--os-pwn`, `--sql-shell`, `--file-read/
   write`, `--dump*`, `--dbs`, `--passwords`, `--udf-inject`, `--all` and
   friends are blocklisted; a `_assert_safe()` guard refuses to launch any
   command containing them, whatever the config says. Risk capped at 2.
3. **Scope-gated.** Only the in-scope target host is tested; an out-of-scope
   target returns a fatal artifact before any tool runs.
4. **Confirm, don't over-claim.** A parameter is `confirmed` only when ≥2
   independent methods (or both tools) agree; otherwise `suspected`.
5. **Offload + Artifact Contract.** Raw tool logs → spill store; strict JSON on
   stdout, no prose.

## Inputs

```json
{ "target_url": "https://app.example.com/item?id=1",
  "parameters": ["id","category"], "waf_detected": true,
  "oob_domain": "abc.oast.pro", "dbms": "MySQL",
  "tech_fingerprint_spill_id": "def456" }
```

## How to run

```bash
python scripts/run.py '{"target_url":"https://app.example.com/item?id=1","parameters":["id"]}'
```

`run.py` pipeline (`SQLiTester`):

1. Scope check (fatal if out of scope). Load DBMS/WAF hints from the tech
   fingerprint when supplied.
2. `select_tampers()` — DBMS+WAF-aware tamper chain when `waf_detected`.
3. Per parameter: `run_ghauri()` (preferred) then `run_sqlmap()` — each argv is
   built safe-by-construction and passed through `_assert_safe()`; techniques
   `BEUT`, `--level`/`--risk` capped, read-only proof flags, `--dns-domain` when
   an OOB domain is given. A missing tool degrades gracefully.
4. `parse_tool_output()` — extract injection types (boolean/error/time/union/
   oob), back-end DBMS, and identity proof from tool stdout.
5. `verify_dual_method()` — pool methods across tools → `confirmed` / `suspected`.
6. `offload_logs()` — raw logs → `raw_log_spill_id`; emit the artifact.

## Typed exits

- `sqli_confirmed` — ≥1 finding at `confirmed`.
- `sqli_suspected` — only single-method leads.
- `no_injection` — parameters tested, nothing fired.
- `out_of_scope` / `no_tooling` — fatal / degraded (`meta.status`/`errors`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| ghauri | Fast async SQLi detection (preferred, WAF-aware) | https://github.com/r0oth3x49/ghauri |
| sqlmap | SQLi detection + read-only enumeration | https://github.com/sqlmapproject/sqlmap |
| interactsh-client | OOB/OAST callback correlation (optional) | https://github.com/projectdiscovery/interactsh |

Install: `pip install sqlmap ghauri` (or clone upstream). The skill runs with
whichever tools are present.

## Wordlists

None bundled — ghauri/sqlmap carry their own payloads and tamper scripts. For
manual payload reference: SecLists SQLi
(https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/SQLi).
