# Artifact Contract — `idor-bola-access-control`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (empty matrix, no sessions) the skill emits a schema-valid artifact
with empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "idor-bola-access-control artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["endpoint", "resource_id", "attacker_role", "victim_role"],
        "properties": {
          "endpoint": { "type": "string" },
          "resource_id": { "type": "string" },
          "attacker_role": { "type": "string" },
          "victim_role": { "type": "string" },
          "evidence_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `access_type`, `method`, `attacker_status`,
`confidence`, `meta`, `scope_summary`, `errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "privilege_matrix_spill_id": "phase3_matrix_hash",
  "session_pool_spill_id": "phase3_sessions_hash",
  "scope_policy_spill_id": "abc123",
  "config": {"allow_mutating": false}
}
```

* `privilege_matrix_spill_id` — the `privilege-matrix-mapping` output. Accepts a
  list of rows, `{matrix_inline|matrix_spill_id}`, or the full artifact. Each row
  is `{endpoint, method, access_map: {role: {status, verdict, hash}}}`, including
  the `"unauthenticated"` baseline.
* `session_pool_spill_id` — the `account-role-acquisition` pool (cookies +
  `auth_headers` per role).
* `config.allow_mutating` — opt-in to also test mutating verbs (default false).

---

## 3. Safety model

| Guard | Enforcement |
| --- | --- |
| Read-only | Cross-session access uses `GET`/`HEAD`/`OPTIONS` only. Mutating rows are skipped unless `config.allow_mutating` (mutation budget). `meta.safety.read_only`. |
| Protected-resource discriminator | A **horizontal** BOLA is confirmed only when the matrix's `unauthenticated` verdict for that endpoint is `denied` — the object is access-controlled, so cross-identity access is a real break. Public objects (unauth allowed) never produce findings. `meta.safety.protected_resource_discriminator:true`. |
| Scope | Only in-scope endpoint hosts are requested. |
| Custody | Response bodies (another test identity's data) are offloaded to `evidence_spill_id`, never inlined. |

---

## 4. Detection

* **Horizontal (BOLA/IDOR)** — for each id-bearing, access-controlled endpoint,
  one identity (`victim_role`) that gets `2xx` is the object owner; every other
  session (`attacker_role`) requests the **same object URL**. If the attacker
  gets `2xx` and the **normalized** response hash equals the owner's fresh
  response, the attacker read the owner's object → **confirmed**. Hashing strips
  timestamps/CSRF/nonces so a match means the same data.
* **Vertical (privilege escalation)** — for endpoints allowed to one role and
  `denied` to another, the denied role re-requests; a `2xx` is a confirmed
  vertical access-control break (catches method/param bypass the mapper's first
  probe missed).

`resource_id` is the object identifier(s) extracted from the URL path/query.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"endpoint": "https://app.example.com/api/orders/1", "resource_id": "1",
     "attacker_role": "standard_user", "victim_role": "tenant_admin",
     "access_type": "horizontal", "method": "GET", "attacker_status": 200,
     "confidence": "confirmed", "evidence_spill_id": "9f2a1c7b6d4e0a53"},
    {"endpoint": "https://app.example.com/api/admin/stats", "resource_id": "-",
     "attacker_role": "standard_user", "victim_role": "tenant_admin",
     "access_type": "vertical", "method": "GET", "attacker_status": 200,
     "confidence": "confirmed", "evidence_spill_id": "0f1e2d3c4b5a6978"}
  ],
  "meta": {"skill": "idor-bola-access-control", "status": "ok", "matrix_rows": 12,
           "roles_available": ["tenant_admin","standard_user"],
           "horizontal_findings": 1, "vertical_findings": 1,
           "safety": {"read_only": true, "mutating_allowed": false,
                      "protected_resource_discriminator": true}},
  "scope_summary": {"policy_present": true},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `meta.safety.read_only` is `true` unless `mutating_allowed`; no mutating
   request was sent otherwise.
3. every horizontal finding's endpoint had `access_map.unauthenticated.verdict
   == "denied"` in the source matrix (protected-resource discriminator).
4. every finding's `evidence_spill_id` resolves in the spill store.
