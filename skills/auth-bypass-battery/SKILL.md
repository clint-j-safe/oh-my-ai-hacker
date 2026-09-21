---
name: auth-bypass-battery
description: >-
  Exhaustively fires every HTTP-level authentication-bypass class against every
  endpoint that denied access with 401/403, and keeps going until each endpoint's
  finite vector set is exhausted. Covers header path override (X-Original-URL /
  X-Rewrite-URL), loopback IP allowlist spoofing, path normalization and
  semicolon traversal, verb tampering with method-override headers, trusted-proxy
  identity header injection, malformed/null credentials, origin-referer trust and
  content-negotiation debug flags. Read-only by default; a bypass is confirmed
  only when the baseline genuinely denied, the variant returns 2xx, and its
  normalized body differs from both the denial body and a freshly probed soft-404
  control. Use in Phase 5 on any endpoint the crawl or privilege matrix found
  protected. Returns per-endpoint exhaustion bookkeeping plus confirmed findings
  with offloaded evidence.
license: Apache-2.0
compatibility: Python 3.11+, httpx. No session pool required — this is the unauthenticated battery.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  depends_on: intelligent-crawling
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Authentication Bypass Battery

You are executing a **Phase 5 offensive battery** against the *unauthenticated*
access-control surface. A `401`/`403` is not a dead end — it is a hypothesis that
the route's authorization check can be confused. This skill enumerates every way
an HTTP layer can be confused, fires all of them at every protected endpoint, and
reports which (if any) got through.

This fills a real gap: `waf-evasion-mastery` answers *"a WAF blocked my payload"*
(`403/406/429` with a block page), `idor-bola-access-control` and
`privilege-matrix-mapping` both need an **identity** to compare against, and
`account-role-acquisition` only bypasses CAPTCHAs. Nothing else enumerated the
no-credential bypass surface.

## Safety model

1. **Read-only by default.** Every vector uses `GET`/`HEAD`/`OPTIONS` or a
   nonstandard verb (`FOO`, `JEFF`) the server has no handler for and therefore
   cannot act on. Mutating verbs (`POST`/`PUT`/`PATCH`/`DELETE`) are generated
   **only** under `config.allow_mutating` (an explicit mutation budget) and are
   tagged `"mutating": true` in the artifact.
2. **Bounded, never a flood.** The vector set is finite and enumerated
   (`BYPASS_CLASSES`), so exhaustion terminates by construction.
   `max_requests_per_endpoint` caps it further, and hitting the cap is reported as
   `"vectors_exhausted": false` rather than silently trimmed — a truncated run
   never claims exhaustion.
3. **Baseline denial required.** Nothing is called a bypass unless the unmodified
   request really returned `401`/`403`. A `200`/`302`/`404` baseline marks the
   endpoint `not_protected` and it is skipped.
4. **Soft-404 discriminator.** Each host's not-found body is probed first. A
   variant returning `200` with that body is classified `absent`, not a bypass —
   stacks that answer unknown routes with `200` + a not-found page cannot inflate
   the finding count.
5. **Scope-gated. Custody.** Both the base URL and every variant URL are host-
   checked against the locked scope policy. Response bodies are offloaded to
   `evidence_spill_id`; only hashes and byte counts are inlined.
6. **Artifact Contract.** Strict JSON on stdout, no prose.

## Inputs

```json
{ "endpoints": [{"url": "https://app.example.com/api/admin", "method": "GET"}],
  "scope_policy_spill_id": "abc123",
  "base_headers": {},
  "config": {"allow_mutating": false, "max_requests_per_endpoint": 200} }
```

`endpoints` may also arrive as `endpoints_spill_id`, or be derived from a
`privilege_matrix_spill_id` (rows whose `access_map.unauthenticated.verdict` is
`denied`). A supplied `status` is advisory — the baseline is always re-measured.

## How to run

```bash
python scripts/run.py '{"endpoints":[{"url":"http://t.test/api/admin","method":"GET"}]}'
```

`run.py` pipeline (`AuthBypassBattery`):

1. `build_vectors()` — enumerate all eight classes for the endpoint, drop
   mutating verbs unless allowed, de-duplicate by wire identity
   `(method, url, headers)` so equivalent vectors are never sent twice.
2. `test_endpoint()` — measure the baseline; skip unless `401`/`403`; probe the
   soft-404 control; fire every vector under a concurrency semaphore.
3. `classify_variant()` — `confirmed` (2xx, body distinct from denial **and**
   control) · `likely` (2xx empty body, or 3xx redirect) · `denied` · `absent`
   (404/405/501 or soft-404) · `other` · `error`.
4. Offload each `confirmed`/`likely` response → `evidence_spill_id`.

## Bypass classes

| Class | What it confuses |
| --- | --- |
| `header_path_override` | Routers that honour `X-Original-URL` / `X-Rewrite-URL` over the request line |
| `ip_allowlist_spoof` | IP-restricted admin panels trusting `X-Forwarded-For` / `X-Real-IP` |
| `path_normalization` | Filter/route mismatch: `//p`, `/p/.`, `/p/..;/`, `/.;/p`, `%2f`, case-flip, `.json` |
| `verb_tampering` | Method-scoped authorization: `HEAD`, `TRACE`, unknown verbs, `X-HTTP-Method-Override` |
| `identity_header_injection` | Trusted-proxy headers the app reads as authentication (`X-Remote-User`, `X-Role`) |
| `malformed_auth_header` | Authenticators that treat an empty/null credential as present |
| `origin_referer_trust` | Same-origin/CSRF-style allowlists satisfied by a self-referential header |
| `content_negotiation` | Framework debug/format switches (`?debug=true`, `?format=json`, `Accept`) |

## Typed exits

- `bypass_confirmed` — ≥1 vector reached content past the auth wall.
- `exhausted_no_bypass` — every protected endpoint's full vector set ran, nothing got through.
- `no_protected_endpoints` — no supplied endpoint returned 401/403.
- `error` — fatal (`meta.status: "error"`), schema-valid with empty `findings`.

`meta.all_vectors_exhausted` is the honest exhaustion flag: true only when every
protected endpoint ran its complete enumerated set without hitting the cap.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| httpx | Async variant dispatch | https://github.com/encode/httpx |

Install: `pip install httpx`.

## Wordlists

None — the vector set is enumerated in code (`BYPASS_CLASSES`) so that exhaustion
is a checkable property rather than a list that can silently run out.
