# Artifact Contract — `technique-combinator`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the consumer. This
skill is **planning only** (`meta.planning_only:true`, `meta.sends_traffic:false`):
it composes findings the loop already confirmed and executes nothing. Every step
of a returned plan is still subject to scope-discipline, blast-radius-estimation,
and the deterministic Safety Gate before it runs.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "technique-combinator artifact",
  "type": "object",
  "required": ["combinations"],
  "properties": {
    "combinations": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["chain_id", "techniques", "impact_score", "action_plan"],
        "properties": {
          "chain_id": { "type": "string" },
          "techniques": { "type": "array", "items": { "type": "string" } },
          "data_flow": { "type": "string" },
          "impact_score": { "type": "integer" },
          "action_plan": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "step": { "type": "integer" },
                "technique": { "type": "string" },
                "input": { "type": "string" },
                "expected_output": { "type": "string" }
              }
            }
          }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `impact_category`, `meta`/`errors`):
`references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "confirmed_findings": [
    {"vuln_class": "SSRF", "output": "reached internal service http://10.0.0.5:8080", "target": "/proxy", "finding_id": "F1"},
    {"vuln_class": "SQLi", "output": "dumped password hashes", "target": "internal admin db"},
    {"vuln_class": "XSS",  "output": "captured admin session cookie", "target": "/dashboard"},
    {"vuln_class": "IDOR", "output": "read admin-only records", "target": "/api/admin/users"}
  ],
  "capabilities": [
    {"name": "hashcat", "yields": "plaintext_cred"},
    {"name": "privilege_escalation", "yields": "admin_access"}
  ],
  "config": {"max_len": 4, "max_chains": 25}
}
```

* `confirmed_findings` — each with `vuln_class`, `output` (what it yielded),
  `target`. Only confirmed findings are chained. `finding_id` optional.
* `capabilities` — extra transformers (`name`, `yields`, optional `consumes`),
  e.g. `hashcat` turns a `db_hash` into a `plaintext_cred`.
* `config.max_len` (default 4) — max techniques per chain; `config.max_chains`
  (default 25) — top-N returned.

---

## 3. Model: produces → consumes

Each vuln class and capability is modeled by the artifact tokens it **produces**
and **consumes**; a producer links to a consumer when a produced token satisfies a
consumed one. Examples (the compatibility matrix):

| producer (output) | → consumer (needs) |
| --- | --- |
| SSRF `internal_service` | → SQLi (internal service) |
| XSS `session_cookie` | → IDOR / CSRF (valid session) |
| File Upload `file_path` | → Path Traversal / RCE |
| XXE `file_read` | → credential theft → auth bypass |
| SQLi `db_hash` | → hashcat `plaintext_cred` → auth bypass → privesc |

A finding's `output` string is scanned for tokens (internal url/service, cookie,
file path, hash, file read, cred, admin, shell) that augment its class's produces
set. Chains must **start at a real finding** (a confirmed foothold), never at a
bare transformer capability.

---

## 4. Scoring & ranking

Terminal impact of the chain's last node sets the base score:

```
RCE (shell) = 100 > PrivEsc (admin_access/elevated) = 80
            > DataExfil (creds/hashes/data) = 60 > InfoDisclosure (file/internal) = 40
```

`+5` per extra hop (novelty bonus for a longer composite), capped at 100.
Combinations are de-duplicated (by technique+link sequence) and ranked by
`impact_score` desc, then fewer hops, then `chain_id`; the top `max_chains` are
returned. Each carries `impact_category`.

---

## 5. Action plan & data flow

Each combination has an explicit `action_plan`: one step per technique with
`step`, `technique`, `input` (the artifact fed in — `initial access @ <target>`
for the first), and `expected_output` (the artifact handed to the next step),
plus a final `verification` step. `data_flow` is the compact
`A(link) → B(link) → …` string.

---

## 6. Example artifact (abridged)

```json
{
  "combinations": [
    {"chain_id": "chain-9f2a1c7b6d",
     "techniques": ["sqli", "hashcat", "privilege_escalation"],
     "data_flow": "sqli(db_hash) → hashcat(plaintext_cred) → privilege_escalation(admin_access)",
     "impact_score": 90, "impact_category": "PrivEsc",
     "action_plan": [
       {"step": 1, "technique": "sqli", "input": "initial access @ internal admin db", "expected_output": "db_hash"},
       {"step": 2, "technique": "hashcat", "input": "db_hash", "expected_output": "plaintext_cred"},
       {"step": 3, "technique": "privilege_escalation", "input": "plaintext_cred", "expected_output": "admin_access"},
       {"step": 4, "technique": "verification", "input": "combined artifacts", "expected_output": "composite result confirmed"}]}
  ],
  "meta": {"skill": "technique-combinator", "findings_in": 4, "capabilities_in": 2,
           "chains_found": 7, "planning_only": true, "sends_traffic": false},
  "errors": []
}
```

---

## 7. Consumer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. Each combination has ≥2 `techniques`, a matching `action_plan` (one step per
   technique + a verification step), and an `impact_score` in [40, 100].
3. Combinations are ranked by `impact_score` descending.
4. Each chain's first technique corresponds to a confirmed finding.
5. `meta.sends_traffic == false`; plans are advisory and re-gated per step.
