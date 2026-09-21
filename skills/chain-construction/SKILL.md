---
name: chain-construction
description: >-
  Reads confirmed Phase 5 vulnerabilities and maps them into ranked multi-step
  exploit chains (e.g., LFI leaks a JWT secret -> forge admin token -> IDOR reads
  cross-tenant data; SSRF -> cloud metadata -> role token -> admin). Models each
  vuln class by the data it yields and consumes, builds a per-target exploit
  graph, and scores chains by compounded business impact. Analytical only — sends
  no traffic and changes nothing. Use in Phase 6 over confirmed findings.
license: Apache-2.0
compatibility: Python 3.11+ (standard library only).
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "6"
  loop-component: "2-proposer"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Chain Construction

You are the **Proposer** in Phase 6. Individual findings are flat; real impact
comes from the paths between them. Your job is to see that one finding's output
is another's input, map those handoffs into a graph, and rank the resulting
chains by how much damage they compound to. You reason — you do not attack.

## Faithfulness (this is the whole safety story here)

1. **Analytical only.** No network, no payloads, no state change
   (`meta.sends_traffic:false`, `meta.mutates:false`).
2. **Grounded in confirmed findings.** Chains are built strictly from the
   findings supplied. Canonical `expansion` steps describe what a vuln class
   standardly implies; they never assert a capability a finding didn't establish.
3. **Scope-faithful.** Two findings are chained only when they share a target.

## Inputs

```json
{ "confirmed_findings": [
    {"vuln_class": "LFI", "output": "app config leaks jwt_secret", "target": "app.example.com", "endpoint": "/view"},
    {"vuln_class": "weak_secret_cracked", "output": "HS256 secret cracked", "target": "app.example.com"},
    {"vuln_class": "horizontal", "output": "cross-tenant orders", "target": "app.example.com"}],
  "config": {"max_depth": 5} }
```

## How to run

```bash
python scripts/run.py '{"confirmed_findings":[{"vuln_class":"xss","output":"session cookie","target":"a"},{"vuln_class":"idor","target":"a"}]}'
```

`run.py` pipeline (`ChainConstructor`):

1. Normalize each finding's `vuln_class` to the ontology and union its yields
   with data types inferred from the `output` text (secret / token / cookie /
   source / schema / metadata).
2. `build_graph()` — directed edges where `yields(A) ∩ consumes(B)` and A, B
   share a target.
3. `_paths()` — enumerate simple paths (≤ `max_depth`), prune prefixes, keep
   notable standalone findings.
4. `rank_chains()` — flatten each path's canonical expansions into `steps`,
   score `min(100, max_weight×10 + 6×links)`, and write a handoff `rationale`.

## Impact model

Weights by tier: RCE 10 · SSTI/cloud-metadata 9 · weak-secret/mass-assignment 8
· SQLi 7 · LFI/XSS/IDOR/logic 6 · SSRF 5 · id-enum 4 · batching 3 ·
introspection 2. Linked findings add a synergy bonus, so a chain always
out-scores its parts.

## Typed exits

- `chains_ranked` — chains produced (multi-step ones surfaced first).
- `no_chains` — findings ingested but no viable path (each stands alone).
- `no_findings` — empty input (`meta.status: "error"`).

## External tools

None — pure reasoning and graph-mapping (standard library only).

## Wordlists

None.
