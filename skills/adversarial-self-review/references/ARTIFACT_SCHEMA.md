# Artifact Contract — `adversarial-self-review`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the consumer. This
skill **does not touch the target** (`meta.target_interaction:"none"`,
`meta.sends_traffic:false`) — it reasons over evidence already collected. Its
posture is `skeptical-by-default`: a finding survives only because the evidence
forces it to.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "adversarial-self-review artifact",
  "type": "object",
  "required": ["reviews"],
  "properties": {
    "reviews": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["finding_id", "verdict", "challenges"],
        "properties": {
          "finding_id": { "type": "string" },
          "verdict": { "enum": ["survives", "downgraded", "rejected"] },
          "challenges": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "challenge": { "type": "string" },
                "resolution": { "enum": ["ruled_out", "unresolved"] },
                "evidence_cited": { "type": "string" }
              }
            }
          },
          "severity_adjustment": { "type": ["string", "null"] },
          "rejection_reason": { "type": ["string", "null"] }
        }
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "total_reviewed": { "type": "integer" }, "survived": { "type": "integer" },
        "downgraded": { "type": "integer" }, "rejected": { "type": "integer" }
      }
    }
  }
}
```

Machine copy (incl. additive `vuln_class`, `meta`/`errors`):
`references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "verified_findings": [
    {"finding_id": "F-12", "vuln_class": "SQLi", "evidence_spill_id": "a1b2c3d4",
     "poc_spill_id": "e5f6a7b8", "cvss_score": 7.5, "confidence": "confirmed",
     "oracle_verifications": 2, "oracle_verdict": "reproduced", "poc_verdict": "reproduced",
     "methods": ["boolean", "time-based"], "data_accessed": "read one boolean via differential"}
  ]
}
```

Each finding's evidence fields feed the challenge evaluation.
`evidence_spill_id` / `poc_spill_id` are hydrated from the spill store (inline
fields win). Signals read: `oracle_verifications`, `oracle_verdict`/`poc_verdict`
(flaky/reproduced), `methods`, `data_accessed`, `commands_executed`,
`session_hijacked`, `internal_pivot`, plus keyword evidence (OOB/canary,
boolean/time differential, command output, cross-account, execution).

---

## 3. Three adversarial challenges per finding

1. **Class-specific false positive** (critical) — the most likely way this
   *specific* class is a mirage:
   - SQLi/NoSQLi → "a WAF error page / 500 misread as a SQL error?"
   - XSS → "self-XSS needing a paste, or reflection without execution?"
   - SSRF → "a DNS-rebinding artifact or unrelated outbound request?"
   - RCE/deser → "a benign echo rather than real execution?"
   - XXE → "a parser error rather than entity resolution?"
   - SSTI → "reflected braces rather than `7*7`→`49` evaluation?"
   - IDOR/BOLA → "same-tenant/public data or a decoy?"
   - LFI → "an app error containing the path, not file content?"
   - CSRF → "blocked by SameSite / an unverified token?"
   - file upload → "stored but never executed?" … (generic FP otherwise).
2. **Symptom vs proof** (critical) — "does the evidence prove the bug, or just a
   symptom (a 500, latency, a reflected string)?"
3. **Manual-reviewer** (rigor, non-critical) — "would this survive a source-code
   reviewer with no benefit of the doubt?"

Each challenge resolves to `ruled_out` (with the evidence that rules it out) or
`unresolved` (with what is missing). A **flaky** Oracle/PoC verdict leaves the
false-positive/symptom challenges `unresolved` by definition.

---

## 4. Verdict

* **rejected** — any *critical* challenge is `unresolved`; `rejection_reason`
  names the challenge and the missing evidence. Removed from the report.
* **downgraded** — all critical challenges ruled out, but the rigor challenge is
  `unresolved`; `severity_adjustment` says to reduce one band.
* **survives** — every challenge ruled out.

`summary` totals the four counts. The default is doubt: a bare status/500 with no
reproduced, bug-specific signal is rejected, not reported.

---

## 5. Example artifact (abridged)

```json
{
  "reviews": [
    {"finding_id": "F-12", "vuln_class": "sqli", "verdict": "survives",
     "challenges": [
       {"challenge": "Could this SQLi be a WAF error page ... misread as a SQL error?",
        "resolution": "ruled_out",
        "evidence_cited": "A boolean/time differential (or OOB/data extraction), reproduced, distinguishes true injection from a WAF/error page."},
       {"challenge": "Does the evidence prove the vulnerability itself, or just a symptom ...?",
        "resolution": "ruled_out", "evidence_cited": "Evidence goes beyond a status code ..."},
       {"challenge": "Would this finding survive a manual reviewer ...?",
        "resolution": "ruled_out", "evidence_cited": "Reproduced with high/confirmed confidence ..."}],
     "severity_adjustment": null, "rejection_reason": null}
  ],
  "summary": {"total_reviewed": 1, "survived": 1, "downgraded": 0, "rejected": 0},
  "meta": {"skill": "adversarial-self-review", "posture": "skeptical-by-default",
           "target_interaction": "none", "sends_traffic": false},
  "errors": []
}
```

---

## 6. Report-gate validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `verdict == "rejected"` ⇒ `rejection_reason` non-null and at least one critical
   challenge `unresolved`; the finding is excluded from the report.
3. `verdict == "downgraded"` ⇒ `severity_adjustment` non-null; reduce the finding's
   severity one band before reporting.
4. `verdict == "survives"` ⇒ every `challenges[].resolution == "ruled_out"`.
5. `summary.survived + downgraded + rejected == total_reviewed`.
