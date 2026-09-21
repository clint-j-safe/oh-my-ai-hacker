# Artifact Contract — `api-graphql-specifics`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (no endpoints, no httpx) the skill emits a schema-valid artifact
with empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "api-graphql-specifics artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["vuln_class", "endpoint"],
        "properties": {
          "vuln_class": { "enum": ["graphql_introspection","mass_assignment","batching_abuse","id_enumeration"] },
          "endpoint": { "type": "string" },
          "schema_spill_id": { "type": ["string","null"] },
          "evidence_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `detail`, `meta`, `scope_summary`, `errors`):
`references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "graphql_endpoints": ["https://app.example.com/graphql"],
  "api_endpoints": [
    {"url": "https://app.example.com/api/users", "method": "POST", "body": {"email": "x@y.z"}},
    {"url": "https://app.example.com/api/docs/1000"}
  ],
  "scope_policy_spill_id": "abc123",
  "config": {"authorize_mutations": false, "batch_size": 10, "id_enum_count": 20}
}
```

* `graphql_endpoints` — introspection + batching are tested here.
* `api_endpoints` — each `{url, method, body}`; ID enumeration runs on any URL
  with a numeric id in the path/query; mass assignment uses `method`+`body`.
* `config.authorize_mutations` — required for mass assignment (writes).

---

## 3. Safety model

| Test | Mutating? | Guard |
| --- | --- | --- |
| `graphql_introspection` | No | Benign introspection query; schema offloaded to `schema_spill_id`. |
| `batching_abuse` | No | A **capped** batch (`config.batch_size`, hard max 25) of harmless `__typename` queries — detects that batching is processed (rate-limit-bypass vector), never used to brute-force. |
| `id_enumeration` | No (GET) | **Bounded** sweep (`config.id_enum_count`, hard max 50) around the observed id; GET-only. |
| `mass_assignment` | **Yes** | Runs only under `config.authorize_mutations` (mutation budget). Every probe is recorded in `meta.mutations` for cleanup. Confirmed only when the over-posted field is reflected back with our value **and** absent from the baseline response. |

`meta.mass_assignment_authorization_required` flags when mass assignment was
skipped for lack of authorization (read-only tests still ran). Scope-gated;
schemas/responses offloaded.

---

## 4. Detection

* **graphql_introspection** — `__schema` present in the introspection response ⇒
  enabled; the full schema is dumped to `schema_spill_id` (Clairvoyance can
  extend this when introspection is disabled).
* **batching_abuse** — an array batch or an aliased query returns ≥ batch_size
  results processed in one request.
* **mass_assignment** — an injected privileged field (`role=admin`,
  `is_admin=true`, …) is echoed back with our value and was not in the baseline.
* **id_enumeration** — a bounded sweep of sequential ids returns many distinct
  accessible objects.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"vuln_class": "graphql_introspection", "endpoint": "https://app.example.com/graphql",
     "schema_spill_id": "9f2a…", "detail": {"types": 42}, "evidence_spill_id": "0f1e…"},
    {"vuln_class": "batching_abuse", "endpoint": "https://app.example.com/graphql",
     "schema_spill_id": null, "detail": {"array_batch_processed": 10, "batch_size": 10},
     "evidence_spill_id": "7c1e…"},
    {"vuln_class": "mass_assignment", "endpoint": "https://app.example.com/api/users",
     "schema_spill_id": null, "detail": {"field": "role", "value": "admin", "method": "POST"},
     "evidence_spill_id": "1a2b…"},
    {"vuln_class": "id_enumeration", "endpoint": "https://app.example.com/api/docs/1000",
     "schema_spill_id": null, "detail": {"ids_probed": 20, "accessible": 20},
     "evidence_spill_id": "3c4d…"}
  ],
  "meta": {"skill": "api-graphql-specifics", "status": "ok",
           "counts": {"graphql_introspection": 1, "batching_abuse": 1, "mass_assignment": 1, "id_enumeration": 1},
           "safety": {"mass_assignment_authorized": true, "batch_capped_at": 10, "id_enum_capped_at": 20},
           "mutations": [{"action": "mass_assignment_probe", "endpoint": "…/api/users", "injected_field": "role"}]},
  "scope_summary": {"policy_present": true},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. if `meta.safety.mass_assignment_authorized` is false there are no
   `mass_assignment` findings and `meta.mutations` is empty.
3. `meta.safety.batch_capped_at <= 25` and `id_enum_capped_at <= 50`.
4. every finding's `evidence_spill_id` resolves; introspection findings have a
   resolving `schema_spill_id`.
