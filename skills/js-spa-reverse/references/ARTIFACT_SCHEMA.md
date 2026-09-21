# Artifact Contract — `js-spa-reverse`

The skill **MUST** emit exactly one JSON object on stdout matching the schema
below. No conversational text; logs go to stderr. If a valid artifact cannot be
produced the Observer (component 5) treats the invocation as a **failure**. On
setup errors the skill still emits a schema-valid artifact with empty arrays and
`meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "js-spa-reverse artifact",
  "type": "object",
  "required": ["endpoints", "secrets", "framework"],
  "additionalProperties": true,
  "properties": {
    "endpoints": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["path", "source_js", "confidence"],
        "properties": {
          "path": { "type": "string" },
          "method": { "enum": ["GET","POST","PUT","DELETE","PATCH","WS","unknown"] },
          "params": { "type": "array", "items": { "type": "string" } },
          "source_js": { "type": "string" },
          "confidence": { "enum": ["high","medium","low"] },
          "is_api": { "type": "boolean" }
        }
      }
    },
    "secrets": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["type", "value_hash", "context"],
        "properties": {
          "type": { "enum": ["AWS","GCP","Azure","JWT","Firebase","Slack","GitHub","Generic"] },
          "value_hash": { "type": "string", "description": "SHA-256 of the secret value, never raw" },
          "context": { "type": "string", "description": "Surrounding chars, secret redacted" },
          "source_js": { "type": "string" },
          "detector": { "type": "string" }
        }
      }
    },
    "framework": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "version": { "type": "string" },
        "routing_type": { "enum": ["client","server","hybrid","unknown"] },
        "graphql_detected": { "type": "boolean" }
      }
    },
    "raw_bundles_spill_id": { "type": ["string","null"] }
  }
}
```

The full machine-readable schema (including the additive `meta`,
`scope_summary`, and `errors` blocks) is `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "js_urls": ["https://cdn.example.com/static/app.4f2a.js", "https://example.com/main.js"],
  "target": "example.com",
  "scope_policy_spill_id": "abc123def4567890"
}
```

* `js_urls` (**required**) — non-empty list of bundle URLs (typically produced
  by `osint-passive-enum` / intelligent-crawling upstream).
* `target` (recommended) — apex domain; used as the default scope when no
  policy is supplied.
* `scope_policy_spill_id` (optional) — same scope-policy shape as
  `osint-passive-enum`. **Only in-scope hosts are fetched.** Out-of-scope or
  off-policy URLs are recorded in `meta.bundles_skipped`, never downloaded.

---

## 3. Secret custody (hard rule)

Raw secret values are **never** emitted. Each finding carries:

* `value_hash` — `SHA-256(secret)`, so the same secret dedupes and can be
  correlated across the engagement without ever storing the plaintext.
* `context` — a short window around the match with the secret substring
  replaced by `<REDACTED:<type>:<len>>`, so an analyst sees *where* it lives
  without the artifact leaking the credential.

The raw bundles themselves are spilled (`raw_bundles_spill_id`) for evidence;
the Credential-custody skill (component 25) governs anything sensitive there.

---

## 4. Offload Law binding

| Corpus | Rule |
| --- | --- |
| raw JS bundles | **Always** spilled to `raw_bundles_spill_id` (`{url: {sha256, bytes, content}}`). |
| `endpoints` | Inlined; if `> 200` matches or `> 50 KB`, full set spills to `meta.endpoints_overflow_spill_id` and the inline array is capped at 200. |
| `secrets` | Same rule → `meta.secrets_overflow_spill_id`. |
| param inventory | `meta.param_inventory` = `{spill_id, count, preview[≤10]}` (spilled when large). |

Retrieve with `spill_store.read_spill(<id>)`.

---

## 5. Confidence model

* **high** — matched an `/api/**`, `/v<n>/**`, `/graphql`, or `/rest/**`
  pattern (`is_api: true`), an absolute API URL, or corroborated by ≥2
  independent extractors (regex + AST).
* **medium** — a declared client route (`path:`/`<Route path=>`), a non-API
  absolute URL, or a WebSocket URL.
* **low** — a path-like string literal recovered only from the AST.

`method` is `unknown` for most statically-recovered endpoints (HTTP verbs are
rarely co-located with the path in minified code) and `WS` for WebSocket URLs —
this is deliberately honest rather than guessed.

---

## 6. Example artifact (abridged)

```json
{
  "endpoints": [
    {"path": "/api/v2/users", "method": "unknown", "params": ["id","expand"],
     "source_js": "https://example.com/main.js", "confidence": "high", "is_api": true},
    {"path": "/dashboard/:tenant", "method": "unknown", "params": [],
     "source_js": "https://example.com/main.js", "confidence": "medium", "is_api": false},
    {"path": "wss://rt.example.com/socket", "method": "WS", "params": [],
     "source_js": "https://example.com/main.js", "confidence": "medium", "is_api": false}
  ],
  "secrets": [
    {"type": "Firebase", "value_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
     "context": "apiKey:\"<REDACTED:Firebase:39>\",authDomain:", "source_js": "https://example.com/main.js",
     "detector": "Google/Firebase API Key"}
  ],
  "framework": {"name": "React", "version": "18.2.0", "routing_type": "client", "graphql_detected": true},
  "raw_bundles_spill_id": "7c1e9a0b4d5f2318",
  "meta": {
    "skill": "js-spa-reverse", "status": "ok", "bundles_analyzed": 1,
    "endpoint_count": 3, "secret_count": 1,
    "endpoints_overflow_spill_id": null, "secrets_overflow_spill_id": null,
    "param_inventory": {"spill_id": null, "count": 2, "preview": ["id","expand"]},
    "ast_parsed": 1, "ast_skipped": 0, "esprima_available": true
  },
  "scope_summary": {"policy_present": true, "urls_requested": 1, "urls_analyzed": 1, "urls_skipped": 0},
  "errors": []
}
```

---

## 7. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. **No raw secrets**: every `secrets[].value_hash` matches `^[0-9a-f]{64}$`,
   and no `secrets[].context` contains a substring that hashes to that value.
3. `raw_bundles_spill_id` is non-null whenever `meta.bundles_analyzed > 0`.
4. every fetched host in `scope_summary` was in scope (out-of-scope URLs appear
   only under `meta.bundles_skipped`).
