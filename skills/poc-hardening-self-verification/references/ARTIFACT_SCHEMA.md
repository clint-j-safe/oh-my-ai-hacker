# Artifact Contract — `poc-hardening-self-verification`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On any
fatal condition (missing spill, unsafe source, no output) the skill still emits
a schema-valid artifact with `verdict == "error"` and a populated `errors` array.

This skill **re-runs** a PoC that a prior skill generated; it does not craft new
target traffic of its own. Whatever traffic occurs is whatever the vetted PoC
already contained, run inside a hardened, resource-limited sandbox.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "poc-hardening-self-verification artifact",
  "type": "object",
  "required": ["verdict", "run1_hash", "run2_hash"],
  "properties": {
    "verdict": { "enum": ["reproduced", "flaky", "regressed", "error"] },
    "run1_hash": { "type": "string" },
    "run2_hash": { "type": "string" },
    "diff_summary": { "type": "string" },
    "logs_spill_id": { "type": "string" }
  }
}
```

Machine copy (incl. additive `meta`/`errors`): `references/artifact.schema.json`.

**Verdict enum note.** The base spec listed `[reproduced, flaky, error]`. This
skill adds **`regressed`** — a PoC that is *stable across both runs* (not flaky)
but whose hash **no longer matches** the `expected_output_hash` recorded by the
generator (exploit-sandbox-programming). That is a distinct, actionable state
(the target changed, or the recorded proof drifted) that neither `reproduced`
nor `flaky` captures, so it is reported separately rather than collapsed into
`flaky`.

---

## 2. Input contract

```json
{
  "poc_script_spill_id": "a1b2c3d4e5f60718",
  "expected_output_hash": "9f2a1c7b6d4e0a53...",
  "config": {
    "timeout_s": 30,
    "session_json": { "cookies": {"session": "..."}, "headers": {} },
    "session_spill_id": "0f1e2d3c4b5a6978",
    "use_docker": false,
    "network_none": false,
    "mem_mb": 256,
    "cpu_s": 20,
    "fsize_mb": 100,
    "docker_image": "python:3.11-slim"
  }
}
```

* `poc_script_spill_id` — **required.** Spill record written by
  exploit-sandbox-programming: `{"source": "...", "language": "python"|"javascript"}`.
* `expected_output_hash` — optional. The `expected_output_hash` the generator
  computed. When present, drives the `reproduced` vs `regressed` distinction.
* `config.session_json` / `config.session_spill_id` — optional session context,
  passed to the PoC **only** as the scrubbed `SESSION_JSON` env var. Inline wins;
  a spill is read and its first pool entry used.
* `config.use_docker` — prefer Docker isolation when the daemon is present.
* `config.network_none` — Docker `--network=none` (subprocess mode inherits the
  host network; use Docker for a hard network cut).
* `mem_mb` / `cpu_s` / `fsize_mb` — rlimit / cgroup budgets (defaults 256 / 20 / 100).
* `timeout_s` — per-run wall-clock kill (default 30).

---

## 3. Safety model (the property this skill enforces)

* **Independent re-vetting.** Before the first execution the loaded PoC source is
  re-validated with the same controls as the generator: an ast import
  allow-list (`json, os, re, sys, hashlib, base64, urllib, httpx, asyncio, html,
  playwright`) and a destructive-token scan (`subprocess`, `os.system`/`popen`,
  `eval`/`exec`, `__import__`, `socket`, `ctypes`, `shutil`, write-mode `open`,
  `pty`; JS: `child_process`, `execSync`, `fs`, `process.binding`, `eval`). Any
  hit ⇒ `verdict: "error"`, **nothing runs**. This skill trusts nothing upstream.
* **Hardened sandbox.** Subprocess execution applies POSIX rlimits (CPU, address
  space, file size, open files, and NPROC where permitted) via `preexec_fn`, a
  scrubbed environment (only `SESSION_JSON` + minimal `PATH` + the proxy/CA vars
  outbound TLS needs), a private temp cwd, and a hard timeout. Docker mode adds
  `--read-only --cap-drop=ALL --pids-limit --memory --cpus` and optional
  `--network=none`.
* **Deterministic diff.** Both runs' stdout are canonicalized — JSON parsed and
  well-known dynamic keys dropped (`timestamp, time, date, ts, generated_at,
  csrf/xsrf, nonce, uuid, requestid, trace_id`), ISO timestamps → `<TS>`, UUIDs
  → `<UUID>` — so transient churn is never mistaken for flakiness.

---

## 4. Verdict logic

| Condition | Verdict |
| --- | --- |
| stripped(run1) ≠ stripped(run2) | `flaky` |
| stripped runs equal, `expected_output_hash` given, run1_hash ≠ it | `regressed` |
| stripped runs equal, and (no expected hash, or it matches) | `reproduced` |
| unsafe source / missing spill / no output in either run | `error` |

`run1_hash` / `run2_hash` = sha256 of the canonicalized stdout of each run.
Equal hashes ⇔ stable. Raw stdout/stderr of both runs (truncated) go to
`logs_spill_id` for the Observer.

---

## 5. Example artifact (abridged)

```json
{
  "verdict": "reproduced",
  "run1_hash": "3b0f...c1",
  "run2_hash": "3b0f...c1",
  "diff_summary": "identical after stripping dynamic fields",
  "logs_spill_id": "7d4e2a1c0b9f8e6d",
  "meta": {
    "skill": "poc-hardening-self-verification", "version": "1.0", "phase": "6",
    "status": "ok", "language": "python",
    "expected_output_hash": "3b0f...c1", "matches_expected": true, "stable": true,
    "sandbox": "subprocess+rlimits",
    "safety": {"revetted_before_run": true, "rlimits_applied": true,
               "env_scrubbed": true, "network_none": false}
  },
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `verdict == "reproduced"` requires `run1_hash == run2_hash` **and**
   `meta.stable == true`; if `expected_output_hash` was supplied it must equal
   both. Otherwise the Observer downgrades to not-verified.
3. `verdict == "flaky"` ⇒ do not promote to the Oracle; the PoC needs
   determinism work in exploit-sandbox-programming.
4. `verdict == "regressed"` ⇒ the proof no longer holds against the live target;
   re-run the exploiting skill rather than trusting the stored PoC.
5. `meta.safety.revetted_before_run` is `true` on every non-init artifact — the
   source was independently vetted before any execution.
