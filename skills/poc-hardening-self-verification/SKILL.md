---
name: poc-hardening-self-verification
description: >-
  A pre-flight check before the Oracle. Loads a generated PoC, independently
  re-vets its source, then runs it twice in a hardened sandbox and diffs the two
  outputs (ignoring dynamic fields like timestamps/nonces/uuids) to prove the
  exploit is deterministic — not flaky or dependent on transient state — and
  compares against the PoC's recorded expected_output_hash. Emits a verdict:
  reproduced, flaky, regressed, or error. Use in Phase 6, after
  exploit-sandbox-programming and before promoting a PoC to the Oracle. Runs
  only the already-vetted PoC, inside rlimit/Docker isolation with a scrubbed
  environment.
license: Apache-2.0
compatibility: Python 3.11+, POSIX (resource module for rlimits). Optional Docker + docker CLI.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "6"
  loop-component: "5-observer"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(docker:*) Bash(node:*)
---

# PoC Hardening (Self-Verification)

You are the **pre-flight check that stands between a freshly generated PoC and
the Oracle**. A PoC that fires once may be luck: a race, a warm cache, a token
that was still valid, a timestamp that happened to line up. Your job is to prove
the exploit is *reproducible* before the loop spends Oracle budget on it — run it
twice under identical, hardened conditions and show the meaningful output is the
same both times. You never trust the upstream source: you re-vet it yourself
before it runs, and you run it only inside a resource-limited sandbox.

## Correctness (this is the whole safety story)

1. **Re-vet, always.** Before the *first* execution the loaded PoC source is
   re-validated with the same controls the generator used — an ast import
   allow-list plus a destructive-token scan (`subprocess`, `os.system`/`popen`,
   `eval`/`exec`, `__import__`, `socket`, `ctypes`, `shutil`, write-mode `open`,
   `pty`; JS: `child_process`, `execSync`, `fs`, `process.binding`, `eval`). Any
   hit ⇒ `verdict: "error"` and **nothing runs**. You independently vet; you do
   not assume the generator was honest.
2. **Hardened sandbox, twice.** Each run is a subprocess under POSIX rlimits
   (CPU, address space, file size, open files, NPROC where allowed), a scrubbed
   environment (only `SESSION_JSON` + minimal `PATH` + the proxy/CA vars TLS
   needs), a private temp cwd, and a hard timeout. Docker mode
   (`--read-only --cap-drop=ALL --pids-limit --memory --cpus`, and
   `--network=none` on request) is preferred when the daemon is present.
3. **Deterministic diff.** Outputs are canonicalized before comparison —
   well-known dynamic fields stripped (timestamps, csrf/xsrf, nonces, uuids),
   ISO timestamps → `<TS>`, UUIDs → `<UUID>` — so ordinary churn is never
   mistaken for flakiness, and genuine instability is never hidden.

## Inputs

```json
{ "poc_script_spill_id": "a1b2c3d4e5f60718",
  "expected_output_hash": "9f2a1c7b...",
  "config": {"timeout_s": 30, "use_docker": false, "network_none": false,
             "session_json": {"cookies": {"session": "..."}},
             "mem_mb": 256, "cpu_s": 20, "fsize_mb": 100} }
```

`poc_script_spill_id` points at the generator's spill record
(`{"source": ..., "language": "python"|"javascript"}`). `expected_output_hash`
is the proof hash the generator recorded — supply it to distinguish `reproduced`
from `regressed`. Session context, if any, reaches the PoC only as the scrubbed
`SESSION_JSON` env var.

## How to run

```bash
python scripts/run.py '{"poc_script_spill_id":"a1b2c3d4e5f60718","expected_output_hash":"9f2a1c7b","config":{"timeout_s":30}}'
```

`run.py` pipeline (`PoCHardener`):

1. `_load()` — read the PoC source + language from the spill.
2. `vet_python()` / `vet_javascript()` — re-vet; refuse (→ `error`) on any
   disallowed import or destructive token before anything executes.
3. `run_in_sandbox()` ×2 — `_run_subprocess()` (rlimits + scrubbed env + timeout)
   or `_run_docker()` when `use_docker` and the daemon exist.
4. `canonicalize()` + `_hash()` — strip dynamic fields, sha256 each run.
5. verdict: outputs differ ⇒ `flaky`; equal but hash ≠ `expected_output_hash`
   ⇒ `regressed`; equal (and matching, or no expected) ⇒ `reproduced`; unsafe /
   empty ⇒ `error`. Raw stdout/stderr of both runs → `logs_spill_id`.

## Typed exits

- `reproduced` — deterministic across both runs (and matches the recorded proof
  when one was supplied). Safe to promote to the Oracle.
- `flaky` — the two runs disagree after stripping dynamic fields. Do **not**
  promote; send back to exploit-sandbox-programming for determinism work.
- `regressed` — stable but no longer matches `expected_output_hash`; the target
  or proof drifted. Re-run the exploiting skill rather than trusting the PoC.
- `error` — unsafe source, missing spill, or no output in either run.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| Docker | Preferred container isolation (`--network=none`, cgroup limits) | https://docs.docker.com/ |
| Docker SDK for Python | Optional programmatic container control | https://pypi.org/project/docker/ |
| Node.js | Runs JavaScript PoCs in the sandbox | https://nodejs.org/ |

Install: none required for the default path — POSIX `resource` rlimits and
`subprocess` are stdlib. Docker and `node` are used only when present.

## Wordlists

None — this skill re-executes an existing PoC; it generates no payloads.
