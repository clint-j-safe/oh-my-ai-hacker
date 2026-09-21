---
name: idor-bola-access-control
description: >-
  Executes differential access-control testing using the Phase 3 privilege
  matrix and session pool. Confirms Broken Object Level Authorization (BOLA/IDOR)
  by requesting one identity's protected object with another identity's session
  and comparing normalized response hashes, and re-verifies vertical privilege
  denials. Read-only by default; a horizontal BOLA is confirmed only for
  genuinely access-controlled objects (unauthenticated baseline denied). Use in
  Phase 5 after privilege-matrix-mapping. Returns confirmed access-control
  findings with offloaded evidence.
license: Apache-2.0
compatibility: Python 3.11+, httpx. Read access to the Phase 3 matrix + session pool spills.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  depends_on: privilege-matrix-mapping
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# IDOR / BOLA / Access Control

You are executing a **Phase 5 offensive battery**. The privilege matrix told you
where the same URL behaves differently per identity; now you *prove* the
authorization break by having one identity read another's object. You read to
prove ownership crosses a boundary — you do not modify anything.

## Safety model

1. **Read-only by default.** Cross-session access uses GET/HEAD/OPTIONS. Mutating
   IDOR (PUT/PATCH/DELETE on another user's object) runs only under
   `config.allow_mutating` (an explicit mutation budget).
2. **Real-vuln discriminator.** A horizontal BOLA is confirmed only when the
   endpoint is access-controlled — the matrix's `unauthenticated` verdict is
   `denied`. Genuinely public objects never produce findings.
3. **Scope-gated. Custody.** Only in-scope hosts; response bodies (another test
   identity's data) are offloaded to `evidence_spill_id`, never inlined.
4. **Artifact Contract.** Strict JSON on stdout, no prose.

## Inputs

```json
{ "privilege_matrix_spill_id": "phase3_matrix_hash",
  "session_pool_spill_id": "phase3_sessions_hash" }
```

## How to run

```bash
python scripts/run.py '{"privilege_matrix_spill_id":"abc","session_pool_spill_id":"def"}'
```

`run.py` pipeline (`IDORTester`):

1. `load_matrix()` — accepts a row list, `{matrix_inline|matrix_spill_id}`, or the
   full artifact. `load_sessions()` — per-role cookie/auth headers.
2. `test_horizontal()` — for each id-bearing, access-controlled endpoint: the
   owner (a `2xx` role) fetches it fresh; every other session requests the **same
   object URL**; a `2xx` with a matching normalized hash = confirmed BOLA
   (`attacker_role` read `victim_role`'s object).
3. `test_vertical()` — for endpoints allowed to one role and `denied` to another,
   the denied role re-requests; a `2xx` is a confirmed vertical break.
4. Offload each cross-access response → `evidence_spill_id`.

Response hashing normalizes away timestamps/CSRF/nonces so a hash match means the
attacker got the victim's actual data, not incidental churn.

## Typed exits

- `bola_confirmed` — ≥1 horizontal finding (object-level authz break).
- `vertical_break` — ≥1 vertical finding (privilege escalation).
- `access_control_ok` — matrix exercised, no breaks confirmed.
- `no_matrix` / `no_sessions` — fatal (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| httpx | Async differential requests | https://github.com/encode/httpx |

Install: `pip install httpx`.

## Wordlists

None — this skill uses live application IDs from the matrix and session pool.
