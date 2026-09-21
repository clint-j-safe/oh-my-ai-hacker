# Artifact Contract — `privilege-matrix-mapping`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error the skill emits a schema-valid artifact with `matrix_inline: null`,
`matrix_spill_id: null`, a zeroed `summary`, and `meta.status: "error"`.

> **Contract reconciliation.** The original brief listed `required: ["matrix",
> "summary"]` while defining `matrix_spill_id` + `matrix_inline` (no `matrix`
> key). This is resolved here: the matrix is realized as the two fields
> `matrix_inline` (small apps) and `matrix_spill_id` (offloaded) — exactly one
> is non-null — and both keys are always present. `required` is therefore
> `["matrix_inline", "matrix_spill_id", "summary"]`. The `verdict` enum also
> gains `"skipped"` for the read-only-by-default safety behavior (see §4).

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "privilege-matrix-mapping artifact",
  "type": "object",
  "required": ["matrix_inline", "matrix_spill_id", "summary"],
  "properties": {
    "matrix_spill_id": { "type": ["string","null"] },
    "matrix_inline": {
      "type": ["array","null"],
      "items": {
        "type": "object",
        "required": ["endpoint","method","access_map"],
        "properties": {
          "endpoint": { "type": "string" },
          "method": { "type": "string" },
          "access_map": {
            "type": "object",
            "additionalProperties": {
              "type": "object",
              "properties": {
                "status": { "type": "integer" },
                "verdict": { "enum": ["allowed","denied","idorsuspect","skipped","error"] },
                "response_hash": { "type": "string" }
              }
            }
          }
        }
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "total_endpoints_tested": { "type": "integer" },
        "roles_tested": { "type": "array", "items": { "type": "string" } },
        "idor_suspects_count": { "type": "integer" },
        "unauthorized_access_count": { "type": "integer" }
      }
    }
  }
}
```

`access_map` is keyed by role name plus the literal `"unauthenticated"`
baseline.

---

## 2. Input contract

```json
{
  "sitemap_spill_id": "phase2_sitemap_hash",
  "session_pool_spill_id": "phase3_sessions_hash",
  "config": {"allow_mutating": false, "concurrency": 20, "api_only": true,
             "idor_size_delta": 0.25}
}
```

* `sitemap_spill_id` — the `intelligent-crawling` sitemap (or `{sitemap:[...]}`).
  Each item's `captured_request_spill_id` supplies the request body/content-type.
* `session_pool_spill_id` — the `account-role-acquisition` session pool (or
  `{session_pool:[...]}`); each role's cookies + `auth_headers` are injected.
* `config.allow_mutating` — opt-in to also replay POST/PUT/PATCH/DELETE (see §4).
* `config.api_only` — default true; filters the sitemap to API endpoints
  (`/api`, `/v<n>`, `/graphql`, `/rest`, xhr/fetch/form_action, JSON responses).

---

## 3. Verdict semantics

For each endpoint × role (and the unauthenticated baseline):

| Verdict | Condition |
| --- | --- |
| `allowed` | HTTP `2xx`. |
| `denied` | `401`, `403`, `404` (hidden/absent), or a `3xx` redirect (login wall). |
| `idorsuspect` | ≥2 identities got in (`allowed`) at the same URL but the **normalized** response hashes differ, or sizes differ by ≥ `idor_size_delta`. A lead for the Phase 5 IDOR/BOLA skill to verify — not a confirmed finding. |
| `skipped` | A mutating verb not sent (read-only default). |
| `error` | `5xx`, `429`, or a network/transport failure. |

**Smart comparison.** `response_hash` is `SHA-256` of the body *after*
normalizing away dynamic noise — timestamps, CSRF/XSRF/authenticity tokens,
nonces, UUIDs, JWTs, and long hex signatures — so a diff reflects real
authorization differences, not per-request churn. Record ids and values are
**kept**, so genuinely different objects still hash differently.

---

## 4. Safety: read-only by default (blast radius)

Only **safe, idempotent** verbs (`GET`/`HEAD`/`OPTIONS`) are replayed. Mutating
verbs (`POST`/`PUT`/`PATCH`/`DELETE`) are recorded as `skipped` with `status: 0`
and **not sent**, unless `config.allow_mutating` is explicitly `true` (an opt-in
mutation budget). Concurrency is capped (`config.concurrency`, default 20) to
avoid WAF/rate-limit trips. This keeps building the authz matrix from having any
side effects on the target.

---

## 5. Offload Law

The full matrix is always assembled; when it exceeds **100 endpoints** it is
written to `matrix_spill_id` and `matrix_inline` is `null`. At or below 100 it
is returned inline and `matrix_spill_id` is `null`. Retrieve with
`spill_store.read_spill(matrix_spill_id)`.

---

## 6. Example artifact (abridged)

```json
{
  "matrix_inline": [
    {"endpoint": "https://app.example.com/api/v1/orders/42", "method": "GET",
     "access_map": {
        "tenant_admin": {"status": 200, "verdict": "idorsuspect", "response_hash": "9f2a1c7b6d4e0a53"},
        "standard_user": {"status": 200, "verdict": "idorsuspect", "response_hash": "0f1e2d3c4b5a6978"},
        "unauthenticated": {"status": 302, "verdict": "denied", "response_hash": "…"}}},
    {"endpoint": "https://app.example.com/api/v1/admin/users", "method": "GET",
     "access_map": {
        "tenant_admin": {"status": 200, "verdict": "allowed", "response_hash": "…"},
        "standard_user": {"status": 403, "verdict": "denied", "response_hash": "…"},
        "unauthenticated": {"status": 401, "verdict": "denied", "response_hash": "…"}}},
    {"endpoint": "https://app.example.com/api/v1/orders", "method": "DELETE",
     "access_map": {
        "tenant_admin": {"status": 0, "verdict": "skipped", "response_hash": ""},
        "standard_user": {"status": 0, "verdict": "skipped", "response_hash": ""},
        "unauthenticated": {"status": 0, "verdict": "skipped", "response_hash": ""}}}
  ],
  "matrix_spill_id": null,
  "summary": {"total_endpoints_tested": 3,
              "roles_tested": ["tenant_admin","standard_user","unauthenticated"],
              "idor_suspects_count": 1, "unauthorized_access_count": 0},
  "meta": {"skill": "privilege-matrix-mapping", "status": "ok",
           "endpoints_loaded": 3, "mutating_allowed": false, "api_only": true},
  "errors": []
}
```

---

## 7. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. exactly one of `matrix_inline` / `matrix_spill_id` is non-null.
3. every `access_map` contains the `"unauthenticated"` baseline key.
4. when `meta.mutating_allowed` is false, every mutating-method row is entirely
   `skipped` (no side effects were possible).
5. `summary.total_endpoints_tested` equals the matrix length (inline or spilled).
