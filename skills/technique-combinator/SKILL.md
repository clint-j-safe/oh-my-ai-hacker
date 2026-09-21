---
name: technique-combinator
description: >-
  Combines techniques from different confirmed findings into novel composite
  attack vectors no single skill would produce. Models each vuln class and extra
  capability by what artifact it produces and consumes, links a producer to a
  consumer when a produced artifact satisfies a consumed one, enumerates the
  resulting chains, scores them by terminal impact (RCE > PrivEsc > DataExfil >
  InfoDisclosure), and emits an explicit step-by-step action plan with data flow.
  Use in Phase 6 when multiple confirmed findings exist. Planning only — it
  composes confirmed findings, sends no traffic, and every step is re-gated before
  execution.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib). Optional neo4j driver.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "6"
  loop-component: "33-technique-combinator"
  target-interaction: "none"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Technique Combinator

You are the strategist that sees what the individual skills cannot: that an SSRF
foothold plus a SQLi plus a hash-cracking capability is not three findings, it is
one path to admin. You take the loop's confirmed findings, work out which one's
output feeds another's input, and lay out the composite chains — ranked by how
much they actually get you. You plan; you never fire.

## Loop-native chaining (Milestone 16)

Chaining is expressed **within the loop-engineering framework — never as a DAG or a
separate executor.** A confirmed finding writes its reusable output to the graph as a
property (e.g. SSRF → `yields: internal_ip`). To chain, you propose the **next
follow-on step** as a new `open` hypothesis whose target reads that yielded value from
the graph, tagged `chaining_from: <finding id>`. The Streaming Planner appends it, the
`SkillPlanValidator` + Safety Gate re-gate it, and the normal pull loop runs it. Data
flows step→step through the graph (Law 2 stigmergy); each step is a bounded loop cycle,
executed in sequence. There is no in-memory chain object and no cycle to detect —
just a sequence of re-gated loop steps.

## Correctness (this is the whole safety story)

1. **Planning only.** You compose findings the loop already CONFIRMED. You send
   no traffic and execute nothing. Every step of every plan is still subject to
   scope-discipline, blast-radius-estimation, and the Safety Gate before it runs.
   `meta.sends_traffic:false`.
2. **Chains start at real footholds.** A chain must begin at a confirmed finding,
   never at a bare transformer capability — you don't invent access you don't have.
3. **Grounded links.** A producer links to a consumer only when a produced
   artifact token actually satisfies a consumed one — no hand-waving "and then
   somehow".
4. **Honest scoring.** Impact is the chain's terminal effect
   (RCE > PrivEsc > DataExfil > InfoDisclosure), with a small novelty bonus per
   extra hop; combinations are de-duplicated and ranked.

## The produces→consumes model

Each vuln class / capability is tagged with the artifacts it **produces** and
**consumes**. A finding's `output` string is scanned to augment its produces set.
Sample compatibility edges:

- SSRF `internal_service` → SQLi (internal service)
- XSS `session_cookie` → IDOR / CSRF (valid session)
- File Upload `file_path` → Path Traversal / RCE
- XXE `file_read` → credential theft → auth bypass
- SQLi `db_hash` → hashcat `plaintext_cred` → auth bypass → privesc

## Inputs

```json
{ "confirmed_findings": [
    {"vuln_class": "SSRF", "output": "reached internal service http://10.0.0.5", "target": "/proxy"},
    {"vuln_class": "SQLi", "output": "dumped password hashes", "target": "internal admin db"}],
  "capabilities": [{"name": "hashcat", "yields": "plaintext_cred"},
                   {"name": "privilege_escalation", "yields": "admin_access"}],
  "config": {"max_len": 4, "max_chains": 25} }
```

## How to run

```bash
python scripts/run.py '{"confirmed_findings":[{"vuln_class":"SQLi","output":"dumped password hashes","target":"db"}],"capabilities":[{"name":"hashcat","yields":"plaintext_cred"},{"name":"privilege_escalation","yields":"admin_access"}]}'
```

`run.py` pipeline (`TechniqueCombinator`): `_build_nodes()` →
`build_compatibility_matrix()` → `identify_chains()` (DFS from finding nodes,
bounded by `max_len`) → `score_chain()` + `generate_action_plan()` → rank.

## Typed exits

- `combinations` — ranked composite chains, each with `chain_id`, `techniques`,
  `data_flow`, `impact_score` (+ `impact_category`), and a step-by-step
  `action_plan`.
- empty `combinations` — no chainable techniques among the confirmed findings.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| neo4j (optional) | Read confirmed findings/capabilities, persist chains | https://github.com/neo4j/neo4j-python-driver |
| MITRE ATT&CK | Technique mapping reference | https://attack.mitre.org/ |

Install: none required (stdlib).

## Wordlists

None — pure graph reasoning; the produces/consumes model is built in and
extensible in `scripts/run.py`.
