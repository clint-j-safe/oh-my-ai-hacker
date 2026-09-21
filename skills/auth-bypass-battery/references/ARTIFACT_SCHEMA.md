# Artifact Contract — `auth-bypass-battery`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On fatal
error (no endpoints, httpx missing) the skill emits a schema-valid artifact with
empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "auth-bypass-battery artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["endpoint", "vector", "bypass_class", "status", "confidence"],
        "properties": {
          "endpoint": { "type": "string" },
          "vector": { "type": "string" },
          "bypass_class": { "type": "string" },
          "status": { "type": "integer" },
          "confidence": { "enum": ["confirmed", "suspected"] },
          "evidence_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `endpoints[]` exhaustion bookkeeping, `meta`,
`scope_summary`, `errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "endpoints": [{"url": "https://app.example.com/api/admin", "method": "GET", "status": 403}],
  "endpoints_spill_id": "crawl_endpoints_hash",
  "privilege_matrix_spill_id": "phase3_matrix_hash",
  "scope_policy_spill_id": "abc123",
  "base_headers": {"User-Agent": "…"},
  "config": {"allow_mutating": false, "max_requests_per_endpoint": 200}
}
```

* `endpoints` — inline list, or `endpoints_spill_id` pointing at one. A supplied
  `status` is advisory: the baseline is always re-measured live.
* `privilege_matrix_spill_id` — alternate source; rows whose
  `access_map.unauthenticated.verdict == "denied"` become the protected set.
* `config.allow_mutating` — opt-in to also generate mutating verbs (default false).
* `config.max_requests_per_endpoint` — hard per-endpoint vector cap.

---

## 3. Safety model

| Guard | Enforcement |
| --- | --- |
| Read-only | Only `GET`/`HEAD`/`OPTIONS` and nonstandard verbs are emitted unless `config.allow_mutating`; mutating vectors carry `"mutating": true`. `meta.safety.read_only`. |
| Bounded, not a flood | The vector set is enumerated in `BYPASS_CLASSES` and de-duplicated by wire identity; `max_requests_per_endpoint` caps it. Hitting the cap sets `vectors_exhausted: false` — exhaustion is never claimed for a truncated run. |
| Baseline denial required | A bypass is only possible where the unmodified request returned `401`/`403`; otherwise the endpoint is recorded `skipped: "not_protected"`. |
| Soft-404 discriminator | Each host's not-found body is probed first; a `200` serving that body is `absent`, not a bypass. `meta.safety.soft_404_discriminator: true`. |
| Scope | Base URL **and** every variant URL are host-checked; out-of-scope variants are counted, not sent. |
| Custody | Response bodies are offloaded to `evidence_spill_id`, never inlined. |

---

## 4. Detection

For each protected endpoint, every vector in all eight classes is dispatched and
classified by `classify_variant(status, body, baseline_hash, control_hash)`:

| Verdict | Meaning |
| --- | --- |
| `confirmed` | `2xx`, non-empty body whose normalized hash differs from **both** the denial body and the soft-404 control → content was reached past the auth wall. Emitted as a finding with `confidence: "confirmed"`. |
| `likely` | `2xx` with an empty body, or a `3xx` redirect. Status changed but content did not prove access. Emitted with `confidence: "suspected"`. |
| `denied` | `401`/`403`, or a `2xx` whose body hash equals the baseline denial body. |
| `absent` | `404`/`405`/`501`, or a `2xx` serving the soft-404 control body — the variant does not route. |
| `other` / `error` | Unclassified status / transport failure. |

Bodies are normalized (timestamps, CSRF/XSRF tokens, nonces replaced) before
hashing, so a match means the same *content*, not the same instant.

`endpoints[].class_results` gives the per-verdict tally, so "all vectors were
exhausted and every one was denied" is auditable rather than asserted.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"endpoint": "https://app.example.com/api/admin",
     "vector": "header_path_override:X-Original-URL",
     "bypass_class": "header_path_override", "method": "GET",
     "url_requested": "https://app.example.com/",
     "sent_headers": {"X-Original-URL": "/api/admin"}, "mutating": false,
     "status": 200, "verdict": "confirmed", "confidence": "confirmed",
     "body_hash": "9f2a1c7b6d4e0a53", "body_bytes": 4211,
     "baseline_status": 403, "evidence_spill_id": "0f1e2d3c4b5a6978"}
  ],
  "endpoints": [
    {"endpoint": "https://app.example.com/api/admin", "method": "GET",
     "baseline_status": 403, "vectors_total": 96, "vectors_attempted": 96,
     "vectors_exhausted": true, "confirmed": 1, "likely": 0, "skipped": null,
     "class_results": {"confirmed": 1, "denied": 88, "absent": 7}}
  ],
  "meta": {"skill": "auth-bypass-battery", "version": "1.0", "phase": "5",
           "status": "bypass_confirmed", "endpoints_supplied": 1,
           "endpoints_protected": 1, "vectors_total": 96, "vectors_attempted": 96,
           "all_vectors_exhausted": true, "confirmed_findings": 1,
           "bypass_classes": ["content_negotiation", "header_path_override",
                              "identity_header_injection", "ip_allowlist_spoof",
                              "malformed_auth_header", "origin_referer_trust",
                              "path_normalization", "verb_tampering"],
           "safety": {"read_only": true, "mutating_allowed": false,
                      "bounded_vectors": true, "max_requests_per_endpoint": 200,
                      "scope_gated": true, "soft_404_discriminator": true,
                      "baseline_denial_required": true}},
  "scope_summary": {"policy_present": true,
                    "hosts_in_scope": ["app.example.com"]},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `meta.safety.read_only` is `true` unless `mutating_allowed`; no finding carries
   `"mutating": true` otherwise.
3. every finding's endpoint has `baseline_status` in `{401, 403}`.
4. every finding's `body_hash` differs from both the endpoint's baseline denial
   hash and the host's soft-404 control hash.
5. `meta.all_vectors_exhausted` is `true` only if every protected endpoint has
   `vectors_exhausted: true` (i.e. `vectors_attempted == vectors_total`).
6. every finding's `evidence_spill_id` resolves in the spill store.
