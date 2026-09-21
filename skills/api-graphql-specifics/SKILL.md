---
name: api-graphql-specifics
description: >-
  Tests REST and GraphQL APIs for introspection leaks (with schema dump), mass
  assignment (over-posting privileged fields), batch/aliased-query abuse
  (rate-limit bypass), and ID enumeration. Read-only by default; mass assignment
  writes and runs only with mutation authorization; batching and ID enumeration
  are capped. Use in Phase 5 on API and GraphQL endpoints. Returns findings with
  offloaded schemas and responses.
license: Apache-2.0
compatibility: Python 3.11+, httpx. Optional clairvoyance for GraphQL schema inference when introspection is disabled.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(clairvoyance:*)
---

# API & GraphQL Specifics

You are executing a **Phase 5 offensive battery** for the API layer. You dump
what the schema will tell you, prove where the server binds fields it shouldn't,
and show where batching and sequential ids open doors — with capped, mostly
read-only probes.

## Safety model

1. **Read-only by default.** Introspection is a benign query; batching sends a
   **capped** batch (`config.batch_size`, hard max 25) of harmless `__typename`
   queries to *detect* rate-limit bypass, never to brute-force; ID enumeration
   is a **bounded** GET-only sweep (`config.id_enum_count`, hard max 50).
2. **Mass assignment is a mutation** — it writes privileged fields, so it runs
   only under `config.authorize_mutations` (mutation budget) and every probe is
   recorded in `meta.mutations` for cleanup. Confirmed only when the over-posted
   field is reflected with our value and was absent from the baseline.
3. **Scope-gated. Offload + Artifact Contract.** GraphQL schemas and responses →
   spill store; strict JSON on stdout, no prose.

## Inputs

```json
{ "graphql_endpoints": ["https://app.example.com/graphql"],
  "api_endpoints": [{"url":"https://app.example.com/api/users","method":"POST","body":{"email":"x@y.z"}},
                    {"url":"https://app.example.com/api/docs/1000"}],
  "config": {"authorize_mutations": false} }
```

## How to run

```bash
python scripts/run.py '{"graphql_endpoints":["https://app/graphql"],"api_endpoints":[{"url":"https://app/api/docs/1000"}]}'
```

`run.py` pipeline (`APITester`):

1. `test_graphql_introspection()` — POST the introspection query; if `__schema`
   is present, dump it to `schema_spill_id` and run `test_batching()`.
2. `test_batching()` — a capped array batch + an aliased query; ≥ batch_size
   processed ⇒ batching abuse (rate-limit bypass vector).
3. `test_id_enumeration()` — bounded sweep of sequential ids in the URL; many
   distinct accessible objects ⇒ enumeration.
4. `test_mass_assignment()` (gated) — inject each `assets/mass-assignment-
   fields.txt` field into the body; reflection-vs-baseline confirms binding.
5. Offload schemas/responses → `schema_spill_id` / `evidence_spill_id`.

## Typed exits

- `introspection_enabled` — schema dumped.
- `mass_assignment` — a privileged field was bound.
- `batching_abuse` / `id_enumeration` — rate-limit-bypass / object-enumeration.
- `mass_assignment_authorization_required` — writes skipped for lack of budget
  (read-only tests still ran).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| Clairvoyance | GraphQL schema inference when introspection is off | https://github.com/nikitastupin/clairvoyance |
| GraphQLmap | GraphQL testing reference | https://github.com/swisskyrepo/GraphQLmap |
| httpx | Async HTTP | https://github.com/encode/httpx |

Install: `pip install httpx` (+ clairvoyance for blind schema inference).

## Wordlists

`assets/mass-assignment-fields.txt` — privileged fields to over-post. Reference:
SecLists GraphQL
(https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/GraphQL).
