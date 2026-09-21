# Artifact Contract — `chain-construction`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (no findings) the skill emits a schema-valid artifact with empty
`chains` and `meta.status == "error"`.

This skill is **analytical only** — it sends no traffic and changes no state
(`meta.sends_traffic:false`, `meta.mutates:false`).

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "chain-construction artifact",
  "type": "object",
  "required": ["chains"],
  "properties": {
    "chains": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["chain_id", "steps", "impact_score"],
        "properties": {
          "chain_id": { "type": "string" },
          "steps": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "vuln_class": { "type": "string" },
                "action": { "type": "string" },
                "yields": { "type": "string" }
              }
            }
          },
          "impact_score": { "type": "integer" },
          "rationale": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `endpoint` per step, `targets`, `links`, `meta`,
`errors`): `references/artifact.schema.json`. Chains are sorted by
`impact_score` (then link count), highest first.

---

## 2. Input contract

```json
{
  "confirmed_findings": [
    {"vuln_class": "LFI", "output": "readable /etc/passwd and app config with jwt_secret", "target": "app.example.com", "endpoint": "/view"},
    {"vuln_class": "weak_secret_cracked", "output": "HS256 secret cracked", "target": "app.example.com", "endpoint": "/api"},
    {"vuln_class": "horizontal", "output": "cross-tenant orders", "target": "app.example.com", "endpoint": "/api/orders/{id}"}
  ],
  "config": {"max_depth": 5}
}
```

* `confirmed_findings` — the confirmed outputs of Phase 5 skills. Each carries a
  `vuln_class`, an `output` (free text describing what it yielded), and a
  `target`/`endpoint`.
* `output` refines the data-type handoff: text mentioning a secret/token/cookie/
  source/schema/metadata adds that data type to what the finding yields.

---

## 3. How chains are built (the model)

Each vulnerability class has an **impact weight** (0–10), a set of data types it
**yields**, a set it **consumes**, and a canonical multi-step **expansion**. A
directed edge `A → B` exists when `yields(A) ∩ consumes(B) ≠ ∅` **and A and B
share a target**. Chains are the simple paths through this graph (plus notable
standalone findings), flattened into `steps`.

| Class | yields | consumes |
| --- | --- | --- |
| RCE (rfi/upload/deser/ssti) | rce, admin_session | — |
| cloud_metadata | cloud_token, admin_session | internal_reach |
| SQLi | db_creds, user_data, secret | — |
| LFI / XXE | source_code, secret | — |
| XSS | session | — |
| weak_secret (JWT) | forged_token, admin_session | **secret, source_code** |
| mass_assignment | admin_session, privilege | schema |
| IDOR/BOLA | user_data | **session, admin_session, forged_token** |
| introspection | schema | — |

So canonical chains fall out automatically, e.g.:
`LFI → weak_secret → IDOR`, `XSS → IDOR`,
`introspection → mass_assignment → IDOR`, `cloud_metadata` (high standalone).

**Impact score** = `min(100, max_step_weight × 10 + 6 × links)` — the peak tier
scaled to 100, plus a synergy bonus per additional linked finding (multiplicative
synergy per the Loop Engineering doc). `rationale` names the handoffs and the
peak impact tier.

---

## 4. Faithfulness

* Chains are grounded in the supplied confirmed findings. The `expansion`
  describes the standard steps a class implies; it does **not** invent a
  capability a finding didn't establish.
* Findings are linked only when they share a target — no cross-host handoff is
  asserted.

---

## 5. Example artifact (abridged)

```json
{
  "chains": [
    {"chain_id": "chain-1a2b3c4d",
     "steps": [
       {"vuln_class": "LFI", "action": "read local files via traversal", "yields": "source code & secrets"},
       {"vuln_class": "weak_secret_cracked", "action": "forge a JWT with the cracked/leaked secret", "yields": "arbitrary/admin session"},
       {"vuln_class": "horizontal", "action": "access others' objects with the acquired identity", "yields": "cross-tenant data"}],
     "impact_score": 92,
     "rationale": "Chain: lfi then weak_secret then idor. Handoffs: lfi → weak_secret via secret/source_code; weak_secret → idor via admin_session/forged_token. Peak impact: privilege escalation; 2 linked finding(s) compound the severity.",
     "targets": ["app.example.com"], "links": 2}
  ],
  "meta": {"skill": "chain-construction", "status": "ok", "findings_ingested": 3,
           "chains_total": 4, "multi_step_chains": 1, "top_impact": 92,
           "analytical_only": true, "sends_traffic": false, "mutates": false},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `meta.sends_traffic` and `meta.mutates` are both `false`.
3. chains are sorted by `impact_score` descending.
4. every chain step's `vuln_class` traces to a supplied finding (no invented
   nodes); a chain's `targets` are a subset of the input targets.
