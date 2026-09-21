# Artifact Contract — `severity-calibration`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the consumer. This
skill **does not touch the target** (`meta.target_interaction:"none"`,
`meta.sends_traffic:false`) — it scores evidence already collected.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "severity-calibration artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["finding_id", "cvss_score", "severity", "confidence", "reproducibility"],
        "properties": {
          "finding_id": { "type": "string" },
          "cvss_score": { "type": "number", "minimum": 0, "maximum": 10 },
          "severity": { "enum": ["critical", "high", "medium", "low", "info"] },
          "confidence": { "enum": ["confirmed", "high", "medium", "low"] },
          "reproducibility": { "enum": ["deterministic", "conditional", "unstable"] },
          "demonstrated_impact": { "type": "string" },
          "theoretical_max_impact": { "type": "string" },
          "gap_explanation": { "type": "string", "description": "Why demonstrated < theoretical, if applicable" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `cvss_vector`, `vuln_class`, `existence_only`, and
`meta`/`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "verified_findings": [
    {
      "vuln_class": "SQLi", "id": "F-12", "chain_id": "chain-3",
      "evidence_spill_id": "a1b2c3d4",
      "assets_affected": ["/api/users"],
      "data_accessed": "dumped users table incl. password hashes",
      "rows_read": 5000,
      "commands_executed": ["id", "cat /etc/passwd -> root"],
      "session_hijacked": "admin",
      "internal_pivot": 2,
      "service_impact": "",
      "oracle_verifications": 2, "oracle_verdict": "reproduced",
      "methods": ["boolean", "time-based"],
      "poc_verdict": "reproduced"
    }
  ]
}
```

Fields are the **evidence of what was actually demonstrated**. Any may be omitted;
`evidence_spill_id` is hydrated from the spill store and inline fields override
it. Impact-bearing fields: `data_accessed` / `rows_read`, `commands_executed`,
`session_hijacked`, `internal_pivot`, `service_impact`. Grading fields:
`oracle_verifications`, `oracle_verdict`, `methods`, `poc_verdict` (the
poc-hardening verdict), `reproducibility`.

---

## 3. Scoring — demonstrated, not theoretical

Each finding starts from a per-class **theoretical** CVSS 3.1 vector (e.g. SQLi
`C:H/I:H/A:H`, RCE `S:C/C:H/I:H/A:H`). The score reported is computed from a
**demonstrated** vector where C/I/A (and Scope) are overridden by actual evidence:

* **Confidentiality** — from data actually read: sensitive/PII/creds or >100 rows
  ⇒ `H`; limited data ⇒ `L`; none ⇒ `N`.
* **Integrity** — from commands that actually ran (real output/modification) or
  data actually modified ⇒ `H`; a benign OOB/existence probe (`nslookup` canary,
  `7*7`) does **not** count. Scope flips to `C` on real command exec or an
  internal pivot.
* **Availability** — from service actually impacted (down/crash ⇒ `H`).
* **Session hijack** — privileged/admin ⇒ `C:H`+`I:H`; other role ⇒ `L`.

**Existence-only cap.** If nothing beyond existence was demonstrated (all real
C/I/A evidence absent), the finding is capped at **Medium** (score ≤ 6.9), the
primary impact dimension is set to `L`, and `existence_only:true`.

Both the demonstrated `cvss_score`/`cvss_vector` and the
`theoretical_max_impact` (its own CVSS + vector) are reported, and
`gap_explanation` states why demonstrated < theoretical when it does. The CVSS
3.1 base engine matches the official calculator (verified against reference
vectors: 9.8, 6.1, 7.5, 10.0, 8.1, 5.3, 0.0).

Qualitative `severity`: 0.0 `info`, 0.1–3.9 `low`, 4.0–6.9 `medium`, 7.0–8.9
`high`, 9.0–10.0 `critical`.

---

## 4. Confidence & reproducibility

**confidence** — `confirmed`: Oracle verified ≥2×; `high`: verified 1× with
dual-method agreement (≥2 methods); `medium`: single method, verified ≥1×;
`low`: Oracle flaky, or unverified.

**reproducibility** — `deterministic`: `poc_verdict == reproduced` / explicitly
deterministic; `unstable`: flaky Oracle/PoC verdict or race/timing signals;
`conditional`: `regressed`, or requires specific state/timing (default).

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"finding_id": "F3", "vuln_class": "rce", "cvss_score": 5.3,
     "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "severity": "medium", "confidence": "medium", "reproducibility": "deterministic",
     "demonstrated_impact": "triggered a benign OOB/existence probe (no real command output); existence proven (benign probe); impact not demonstrated",
     "theoretical_max_impact": "Arbitrary code execution, full host compromise (CVSS 10.0, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
     "gap_explanation": "Demonstrated CVSS 5.3 < theoretical 10.0: only triggered a benign OOB/existence probe ... — capped at Medium (existence only).",
     "existence_only": true}
  ],
  "meta": {"skill": "severity-calibration", "phase": "9", "target_interaction": "none", "sends_traffic": false},
  "errors": []
}
```

---

## 6. Consumer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `existence_only:true` ⇒ `severity` is `medium` or lower and `gap_explanation`
   is non-empty.
3. `cvss_score` is consistent with `severity` per the §3 bands, and the reported
   `cvss_score <= theoretical`.
4. `confidence`/`reproducibility` are within their enums; a `flaky` Oracle verdict
   never yields `confirmed`/`deterministic`.
