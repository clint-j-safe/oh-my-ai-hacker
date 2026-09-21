---
name: privilege-matrix-mapping
description: >-
  Builds a strict Role x Resource x Verb authorization matrix by replaying the
  Phase 2 sitemap endpoints with each Phase 3 role session plus an
  unauthenticated baseline, and comparing the differential responses (status +
  normalized body hash) to determine exact access boundaries. Read-only by
  default (safe verbs only). Use in Phase 3 right after Account Acquisition;
  this matrix is the required substrate for the Phase 5 IDOR/BOLA skill. Returns
  a JSON privilege matrix. Do NOT use for exploitation.
license: Apache-2.0
compatibility: >-
  Python 3.11+, httpx, and read access to the spill store holding the Phase 2
  sitemap and Phase 3 session pool. Network access to the in-scope target.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "3"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(httpx:*)
---

# Privilege Matrix Mapping

You are executing **Phase 3 authorization mapping**. You take what recon found
(the sitemap) and who Phase 3 became (the session pool) and produce the one
artifact every access-control test depends on: for each endpoint, exactly which
identity can reach it, and where the same URL leaks different data to different
identities. You are read-only — you measure the boundary, you don't cross it.

## Laws

1. **Read-only by default.** Replay only safe idempotent verbs (GET/HEAD/
   OPTIONS). Mutating verbs are recorded `skipped` and never sent unless
   `config.allow_mutating` is explicitly true (opt-in mutation budget).
2. **Differential truth.** Every verdict comes from an actual response — status
   code and a normalized body hash — including an `unauthenticated` baseline.
   Broken access control is proven, not assumed.
3. **Gentle.** Concurrency capped (default 20) to avoid WAF/rate-limit trips.
4. **Offload + Artifact Contract.** Matrix > 100 endpoints → spill; strict JSON
   on stdout, no prose.

## Inputs

```json
{ "sitemap_spill_id": "phase2_sitemap_hash",
  "session_pool_spill_id": "phase3_sessions_hash",
  "config": {"allow_mutating": false, "concurrency": 20, "api_only": true} }
```

## How to run

```bash
python scripts/run.py '{"sitemap_spill_id":"abc","session_pool_spill_id":"def"}'
```

`run.py` pipeline (`PrivilegeMapper`):

1. `load_sitemap()` — read the Phase 2 sitemap; filter to API endpoints
   (`api_only`), dedup by `(method, url)`, pull each request template.
2. `load_sessions()` — read the Phase 3 pool; build per-role cookie + auth
   headers; add the `unauthenticated` baseline.
3. `replay_endpoint()` — for each endpoint, fire one request per identity
   concurrently (semaphore-bounded); record `status`, `verdict`, and a
   `response_hash` of the **normalized** body (timestamps/CSRF/nonce/UUID/JWT/
   hex stripped so diffs are real).
4. `analyze_differential_response()` — allowed vs denied per role; ≥2 identities
   getting in with differing content/size at the same URL → `idorsuspect`.
5. `offload_matrix()` — assemble summary, inline (≤100) or spill (>100), emit.

## Verdicts

`allowed` (2xx) · `denied` (401/403/404/3xx) · `idorsuspect` (differential lead
for Phase 5) · `skipped` (mutating verb, not sent) · `error` (5xx/429/network).

## Artifact Contract (strict)

One JSON object on stdout per `references/ARTIFACT_SCHEMA.md` (machine copy:
`references/artifact.schema.json`). Keys: `matrix_inline`, `matrix_spill_id`
(exactly one non-null), `summary` (+ additive `meta`/`errors`). On fatal error,
emit an empty-but-valid artifact with `meta.status: "error"`.

## Typed exits

- `matrix_built` — endpoints tested; verdicts assigned.
- `idor_leads_found` — `summary.idor_suspects_count > 0`; hand to Phase 5 IDOR.
- `broken_authn` — `summary.unauthorized_access_count > 0` (unauth reached data).
- `no_endpoints` — sitemap yielded nothing to test (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| httpx | Async HTTP client for endpoint replay | https://github.com/encode/httpx |

Install: `pip install httpx`.

## Wordlists

None. This skill is purely analytical — it consumes Phase 2 (Intelligent
Crawling) and Phase 3 (Account Acquisition) outputs and sends no payloads.
