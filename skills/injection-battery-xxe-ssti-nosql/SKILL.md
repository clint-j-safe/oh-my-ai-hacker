---
name: injection-battery-xxe-ssti-nosql
description: >-
  Tests for SSTI, XXE, and NoSQL injection, prioritized by the Phase 2 tech
  fingerprint (e.g. Jinja2 SSTI when Python/Flask is detected). SSTI is proven by
  arithmetic evaluation and engine identification, with the RCE payload emitted
  as a PoC for human escalation but never executed. XXE uses OOB canaries and a
  benign file probe (no DoS entities). NoSQL uses read-only operator inference.
  Use in Phase 5 when specific backend technologies are identified. Returns a
  JSON findings artifact with offloaded responses.
license: Apache-2.0
compatibility: >-
  Python 3.11+, httpx. Optional: tplmap (detection-only) for SSTI engine
  corroboration, interactsh/OAST for blind XXE. Network access to the in-scope
  target.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(tplmap:*) Bash(interactsh-client:*)
---

# Injection Battery — XXE / SSTI / NoSQL

You are executing a **Phase 5 offensive battery**. You test the secondary
injection classes that the tech fingerprint makes likely, and you prove them
with the least forceful evidence: a template that does arithmetic, an entity
that pings back, an operator that flips an auth check. You prove; you do not
detonate.

## Safety model (load-bearing — do not weaken)

1. **SSTI proves eval, not RCE.** Confirmation is arithmetic (`{{a*b}}` → the
   product, random canary). The RCE payload for the identified engine is
   **emitted as `rce_poc` for human-gated escalation and never executed**
   (`rce_executed:false`). tplmap runs detection-only; exploitation flags
   (`--os-cmd`, `--os-shell`, `--reverse-shell`, upload/download) are blocklisted.
2. **XXE without DoS or secrets.** Blind detection via OOB canary; in-band via a
   **benign** file (`/etc/hostname`). No billion-laughs/entity-expansion,
   no credential/secret file paths.
3. **NoSQL is read-only inference.** Operator injection (`$ne`/`$gt`/`$regex`/
   `$exists`) via a baseline differential — no `$where` arbitrary-JS execution.
4. **Scope-gated. Offload + Artifact Contract.** Raw responses → spill store;
   strict JSON on stdout, no prose.

## Inputs

```json
{ "target_url": "https://app.example.com/greet", "parameters": ["name"],
  "tech_stack": ["python","flask"], "content_type": "query",
  "oob_domain": "abc.oast.pro" }
```

`content_type` selects delivery and which classes run: `xml`→XXE; `json`/`form`
→NoSQL(+SSTI); `query`→SSTI(+NoSQL bracket form).

## How to run

```bash
python scripts/run.py '{"target_url":"https://app.example.com/greet","parameters":["name"],"tech_stack":["python"]}'
```

`run.py` pipeline (`SecondaryInjectionTester`):

1. Scope check; `_plan()` picks classes from `content_type` + `tech_stack`.
2. `test_ssti()` — arithmetic wrappers → product check → `_identify_engine()`
   distinctive probes → emit `rce_poc` (not executed). Optional `run_tplmap()`.
3. `test_xxe()` — OOB entity canary (poll to correlate), else benign in-band
   file entity vs an entity-free control.
4. `test_nosql()` — baseline vs operator injection differential (JSON body or
   `param[$ne]=` bracket form).
5. Offload each raw response → `evidence_spill_id`.

## Typed exits

- `injection_confirmed` — ≥1 finding.
- `ssti_rce_capable` — an SSTI finding with `rce_capable:true` (PoC provided, not
  run) → escalate under human gate.
- `no_injection` — classes tested, nothing fired.
- `out_of_scope` — fatal (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| tplmap | SSTI engine corroboration (detection-only) | https://github.com/epinna/tplmap |
| interactsh | Blind XXE OOB correlation | https://github.com/projectdiscovery/interactsh |
| httpx | Async HTTP | https://github.com/encode/httpx |

Install: `pip install httpx` (tplmap/interactsh from upstream).

## Wordlists

`assets/injection-payloads.json` — SSTI engine table (distinctive probes +
non-executed RCE PoCs), arithmetic wrappers, XXE OOB/file templates, NoSQL
operators. Broader manual sets: SecLists Fuzzing
(https://github.com/danielmiessler/SecLists/tree/master/Fuzzing).
