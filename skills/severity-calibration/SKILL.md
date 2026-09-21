---
name: severity-calibration
description: >-
  Scores verified findings from DEMONSTRATED impact, not theoretical maximum.
  Uses actual evidence — data actually read, commands actually executed, sessions
  actually hijacked, pivots actually made, and how many times the Oracle
  reproduced the PoC — to assign a calibrated CVSS 3.1 score, confidence, and
  reproducibility. Overrides CVSS Confidentiality/Integrity/Availability from real
  evidence and caps existence-only proofs at Medium, reporting the gap to the
  theoretical max. Use in Phase 9 after Oracle verification. Pure scoring over
  evidence already collected — it does not interact with the target.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib). Optional neo4j driver.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "9"
  loop-component: "2-proposer"
  target-interaction: "none"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Severity Calibration

You are the difference between "this could be catastrophic" and "here is exactly
what we proved". A finding's theoretical ceiling is easy to name; your job is to
score what the loop *actually demonstrated* — the rows it really read, the command
whose output really came back, the admin session it really rode — and to say
plainly where that falls short of the ceiling. A vuln that was confirmed but never
exploited is graded on the proof, not the fantasy.

## Correctness (this is the whole safety story)

1. **Demonstrated over theoretical.** CVSS Confidentiality/Integrity/Availability
   are set from actual evidence, never the class's maximum. A benign OOB probe, an
   `nslookup` canary, or `7*7=49` proves existence, not impact.
2. **Existence-only caps at Medium.** If nothing beyond existence was shown, the
   score is capped at ≤6.9, `existence_only:true`, and `gap_explanation` states
   why demonstrated < theoretical. No inflating an unexploited bug to Critical.
3. **Standards-correct CVSS.** The 3.1 base engine matches the official
   calculator (verified against reference vectors 9.8 / 6.1 / 7.5 / 10.0 / 8.1 /
   5.3 / 0.0), including scope-change math and roundup.
4. **Honest grades.** `confidence` follows Oracle verification count and method
   agreement; `reproducibility` follows the PoC-hardening verdict — a `flaky`
   verdict never becomes `confirmed`/`deterministic`.
5. **No target interaction.** Scoring only. `meta.sends_traffic:false`.

## Scoring model

Start from a per-class theoretical vector → override C/I/A (and Scope) from
evidence → compute CVSS 3.1 base → map to severity band. Report both the
demonstrated score/vector and the theoretical max, plus the gap.

- **Confidentiality**: sensitive/PII/creds or >100 rows → H; limited → L; none → N.
- **Integrity**: real command exec / data modified → H (Scope→C); benign probe → not counted.
- **Availability**: service down/crash → H; partial → L.
- **Session hijack**: admin/root → C:H+I:H; other role → L. **Internal pivot** → Scope C.

## Inputs

```json
{ "verified_findings": [
    {"vuln_class": "SQLi", "id": "F-12", "evidence_spill_id": "a1b2c3d4",
     "data_accessed": "dumped users incl. password hashes", "rows_read": 5000,
     "commands_executed": ["id -> root"], "session_hijacked": "admin", "internal_pivot": 2,
     "oracle_verifications": 2, "oracle_verdict": "reproduced", "methods": ["boolean","time-based"],
     "poc_verdict": "reproduced"}] }
```

`evidence_spill_id` is hydrated from the spill store; inline fields override it.

## How to run

```bash
python scripts/run.py '{"verified_findings":[{"vuln_class":"rce","id":"F3","oracle_verifications":1,"commands_executed":"nslookup canary.oob (benign)"}]}'
```

`run.py` pipeline (`SeverityCalibrator`), per finding:

1. `assess_demonstrated_impact()` — derive demonstrated C/I/A/Scope from evidence;
   flag `existence_only`.
2. `cvss_base()` — score the demonstrated vector (and the theoretical vector).
3. `assign_confidence()` / `assign_reproducibility()`.
4. cap existence-only at Medium; write `gap_explanation`.

## Typed exits

Per finding: `cvss_score` + `cvss_vector`, `severity`
(critical/high/medium/low/info), `confidence`
(confirmed/high/medium/low), `reproducibility`
(deterministic/conditional/unstable), `demonstrated_impact`,
`theoretical_max_impact`, `gap_explanation`.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| CVSS 3.1 | Base-score standard (implemented in-skill) | https://www.first.org/cvss/v3.1/specification-document |
| OWASP Risk Rating | Cross-check methodology | https://owasp.org/www-community/OWASP_Risk_Rating_Methodology |
| neo4j (optional) | Persist calibrated scores to Finding nodes | https://github.com/neo4j/neo4j-python-driver |

Install: none required (stdlib).

## Wordlists

None — pure reasoning; sensitivity/benign-probe detection uses built-in regexes.
