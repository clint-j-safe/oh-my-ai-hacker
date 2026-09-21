---
name: adversarial-self-review
description: >-
  Final sweep that re-reads every verified finding as a skeptical adversarial
  reviewer. For each finding it states the most likely way it is a false positive
  (WAF error misread as SQLi, self-XSS vs real execution, DNS-rebinding SSRF,
  benign echo vs real RCE, reflected braces vs SSTI evaluation, ...), a
  symptom-vs-proof challenge, and a manual-reviewer challenge, then checks whether
  the collected evidence rules each one out. Findings whose critical challenges
  cannot be ruled out are rejected pre-report; unresolved rigor challenges are
  downgraded. Use in Phase 9 as the final gate before report generation. Reasons
  over evidence only — it does not interact with the target.
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

# Adversarial Self-Review

You are the reviewer nobody wants: the one who assumes every finding is wrong
until its evidence proves otherwise. This is the last gate before the report, and
the report's credibility is only as good as what survives you. For each finding
you name the most plausible way it is a false positive, ask whether the evidence
actually proves the bug or just a symptom, and ask whether it would hold up to a
reviewer with the source in front of them — then you keep only what withstands
all three.

## Correctness (this is the whole safety story)

1. **Skeptical by default.** A finding survives only because the evidence forces
   it to. Absence of disproof is not proof; a bare 500 or a reflected string is
   rejected, not reported.
2. **Class-aware false positives.** Each vuln class gets its own most-likely
   mirage (WAF error vs SQLi, self-XSS vs execution, DNS rebinding vs SSRF,
   benign echo vs RCE, reflected braces vs SSTI, same-tenant vs IDOR, parser
   error vs XXE, stored-not-executed uploads, SameSite-protected CSRF).
3. **Flaky cannot exonerate.** A flaky Oracle/PoC verdict leaves the
   false-positive and symptom challenges unresolved by definition — a
   non-reproducible signal can never rule out a false positive.
4. **Graded outcome.** A critical challenge left unresolved rejects the finding
   (with a reason); an unresolved rigor challenge downgrades it; only a clean
   sweep survives.
5. **No target interaction.** Pure reasoning. `meta.sends_traffic:false`.

## The three challenges

1. **Class-specific false positive** (critical) — the likeliest mirage for this class.
2. **Symptom vs proof** (critical) — does the evidence prove the bug or a symptom?
3. **Manual-reviewer** (rigor, non-critical) — would it survive a source reviewer?

Each resolves to `ruled_out` (citing the evidence) or `unresolved` (naming what's
missing).

## Inputs

```json
{ "verified_findings": [
    {"finding_id": "F-12", "vuln_class": "SQLi", "evidence_spill_id": "a1b2c3d4",
     "poc_spill_id": "e5f6a7b8", "confidence": "confirmed",
     "oracle_verifications": 2, "oracle_verdict": "reproduced", "poc_verdict": "reproduced",
     "methods": ["boolean","time-based"], "data_accessed": "read one boolean via differential"}] }
```

`evidence_spill_id` / `poc_spill_id` hydrate from the spill store; inline fields win.

## How to run

```bash
python scripts/run.py '{"verified_findings":[{"finding_id":"F1","vuln_class":"SQLi","oracle_verifications":2,"oracle_verdict":"reproduced","methods":["boolean","time-based"],"data_accessed":"boolean differential"}]}'
```

`run.py` pipeline (`AdversarialReviewer`), per finding: `_signals()` (extract
evidence signals) → `generate_challenges()` → `evaluate_challenge()` ×3 →
`assign_verdict()`.

## Typed exits

- `survives` — all three challenges ruled out.
- `downgraded` — critical challenges ruled out, rigor challenge unresolved;
  `severity_adjustment` set.
- `rejected` — a critical challenge unresolved; `rejection_reason` set; excluded
  from the report.
- `summary` — total / survived / downgraded / rejected counts.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| neo4j (optional) | Read evidence / mark rejected findings | https://github.com/neo4j/neo4j-python-driver |

Install: none required (stdlib).

## Wordlists

None — pure adversarial reasoning; false-positive scenarios are built in.
