---
name: skill-variant-generator
description: >-
  Takes an existing SKILL.md and generates a variant adapted for a new context
  the base skill does not cover (SQLi via WebSocket, XSS via GraphQL, SSRF via
  file upload, ...). It rewrites the delivery/detection/evidence/tools guidance
  for the new transport, PRESERVES the base skill's artifact contract byte-for-byte
  (SHA-256 verified) so the Oracle verifies the variant with the identical schema,
  writes skills/<base>-via-<context>/, and registers it in the Dynamic Skill
  Registry. Use when the agent hits a context the base skill cannot handle. A code
  generator — it reads and writes skill files and sends no target traffic.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib only).
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5-6"
  loop-component: "34-skill-variant-generator"
  target-interaction: "none"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Skill Variant Generator

You are how the toolkit grows without losing its rigor. When the loop meets a
context no skill covers — a SQLi that lives behind a WebSocket, an injection that
only reaches the app through a GraphQL variable — you take the closest base skill
and re-dress it for the new transport. What you must never change is the artifact
contract: the variant has to prove itself to the Oracle with the exact same schema
the base uses, or the loop can't trust it. So you adapt the delivery and keep the
proof identical.

## Correctness (this is the whole safety story)

1. **Contract preserved, verified.** The variant's `references/ARTIFACT_SCHEMA.md`
   and `references/artifact.schema.json` are copied from the base unchanged and
   SHA-256-checked equal. `artifact_contract_preserved` is `true` only when every
   present contract file hashes equal — same schema in, same schema out.
2. **Only the transport changes.** Delivery, detection signal, evidence source and
   client library are remapped for the context; the base engine
   (`scripts/run.py`) and its schema are reused as-is, so the Oracle verifies the
   variant identically.
3. **Grounded generation.** The generated `scripts/delivery_adapter.py` is a
   complete, runnable module (`wrap_payload`, `detect`) — no placeholders, no
   TODOs. Every adaptation is recorded in `changes_made` for audit.
4. **No target interaction.** It reads and writes skill files only.
   `meta.sends_traffic:false`.

## Known contexts

`websocket`, `graphql`, `file_upload`, `grpc`, `xml_soap`, `http_header`. An
unknown context still yields a variant with a generic adaptation section and a
generic adapter, flagged for manual mapping.

## Inputs

```json
{ "base_skill": "sqli-database-injection", "new_context": "websocket",
  "observed_behavior": "WS endpoint at /ws/api accepts JSON",
  "constraints": ["must use WS frames", "no HTTP fallback"],
  "config": {"skills_dir": "skills"} }
```

`skills_dir` (or the `SKILLS_DIR` env var) is the skills root; the base skill's
folder must contain `SKILL.md` and its `references/` contract.

## How to run

```bash
SKILLS_DIR=skills python scripts/run.py '{"base_skill":"sqli-database-injection","new_context":"websocket","observed_behavior":"/ws/api accepts JSON","constraints":["WS frames only"]}'
```

`run.py` pipeline (`SkillVariantGenerator`): `load_base_skill()` →
`adapt_delivery()` / `adapt_detection()` → `save_variant()` (writes adapted
SKILL.md + copied engine + generated `delivery_adapter.py`) → `preserve_contract()`
(copy + hash-verify) → `register_variant()`.

## Typed exits

- `variant_name` / `variant_path` — the written variant.
- `artifact_contract_preserved` — true iff the base contract copied hash-equal.
- `registered` — true iff added to `.variant_registry.json`.
- `changes_made` — the ordered list of adaptations and files written.
- error artifact — missing base skill, no frontmatter, or no base contract files.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| agentskills.io spec | Skill packaging format | https://agentskills.io/specification |
| MCP spec | Tool/registry interop reference | https://modelcontextprotocol.io/ |

Install: none required (stdlib only).

## Wordlists

None — pure code generation. Context adaptation maps are built in and extensible
in `scripts/run.py`.
