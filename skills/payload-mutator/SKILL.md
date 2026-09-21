---
name: payload-mutator
description: >-
  Takes a base payload and generates bounded, deterministic mutations across four
  levels — encoding (URL/double-URL/%u/hex/base64/HTML entities), syntax
  (comments/case-swap/whitespace/concat/null-byte/newline), context
  (JSON/XML/header/chunked/multipart), and composition (nested encoding, param
  split, polyglot, buffer padding). Every mutation is seeded and reproducible:
  same seed + same payload = identical set, so the Oracle can reproduce it. The
  LLM selects which levels to apply; deterministic code does the transform. Use
  in Phase 5 when a payload is blocked by a WAF or input filter. Pure generator —
  sends no traffic and never dresses up a destructive command.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib only).
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "32-payload-mutator"
  mutation-budget: "8 per level, 4 levels max"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Payload Mutator

You are the deterministic hands that reshape a blocked payload. The loop decides
*which* kinds of mutation to try; you do the transforming — the same way, every
time, for a given seed. That reproducibility is the point: a mutation that gets
through can be handed to the Oracle and reproduced exactly. You re-encode an
existing probe; you never invent a new attack, and you never obfuscate a
destructive command.

## Correctness (this is the whole safety story)

1. **Deterministic and seeded.** Each level orders its candidates with
   `random.Random(f"{seed}:{level}:{payload}")` and caps at the budget. Same seed
   + same payload ⇒ byte-identical mutation set — the Oracle can reproduce any
   winner. A level's output is independent of which other levels run.
2. **Bounded.** ≤ `max_mutations_per_level` (default 8) per level, ≤ 4 levels.
   Over 32 total, the full set offloads to the spill store and only 32 are inlined
   (Offload Law); `total_count` is always the true number.
3. **Re-encode, never re-arm.** A `base_payload` carrying a destructive OS/shell
   token (`rm -rf`, `mkfs`, `dd if=`, `curl … | sh`, fork bomb) is refused. This
   transforms the representation of a probe, not the intent of a command.
4. **No traffic.** Pure generation. `meta.sends_traffic:false`.

## The four levels

1. **Encoding** — url, double-url, `%u00XX`, `0x` hex, base64, `&#NN;` entities.
2. **Syntax** — `/**/` comments, case swap, space→`/**/`, string concat, `%00`,
   `%0a`.
3. **Context** — JSON body, XML entities, CRLF header injection, chunked transfer,
   multipart form.
4. **Composition** — nested `url(unicode(payload))`, split across params (HPP),
   multi-context polyglot, junk buffer padding.

## Inputs

```json
{ "base_payload": "1' OR '1'='1", "seed": 42, "blocked_by": "cloudflare_waf",
  "levels_to_apply": [1, 2, 3, 4], "max_mutations_per_level": 8 }
```

## How to run

```bash
python scripts/run.py '{"base_payload":"1'"'"' OR '"'"'1'"'"'='"'"'1","seed":42,"levels_to_apply":[1,2,3,4],"max_mutations_per_level":8}'
```

`run.py` pipeline (`PayloadMutator`): `level1_encoding()` / `level2_syntax()` /
`level3_context()` / `level4_composition()` each build candidates →
`apply_all()` seeds the ordering, caps per level → offload if `total_count > 32`.
Each `Mutation` carries `base_payload`, `mutated_payload`, `level`,
`mutation_type`, `seed`, `encoding_chain`.

## Typed exits

- `mutations` — the (possibly preview-capped) mutation list.
- `total_count` — the full number generated.
- `spill_id` — set (non-null) when `total_count > 32`; the full set lives there.
- error artifact — empty or destructive `base_payload`.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| PayloadsAllTheThings | Payload/bypass reference corpus | https://github.com/swisskyrepo/PayloadsAllTheThings |
| HackTricks — WAF Bypass | Bypass technique reference | https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/waf-bypass |

Install: none required (stdlib only).

## Wordlists

Optional external corpora (not bundled; mutations are generated in code):

- SecLists Fuzzing — https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
- SecLists Payloads — https://github.com/danielmiessler/SecLists/tree/master/Payloads
- WAF Bypass Payloads — https://github.com/waf-bypass-maker/waf-community-bypasses
