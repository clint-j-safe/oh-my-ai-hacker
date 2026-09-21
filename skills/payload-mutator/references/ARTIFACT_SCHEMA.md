# Artifact Contract — `payload-mutator`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the consumer. This
skill is a pure generator — it **sends no traffic** (`meta.sends_traffic:false`)
and re-encodes an existing probe payload; it never dresses up a destructive
command.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "payload-mutator artifact",
  "type": "object",
  "required": ["mutations", "total_count"],
  "properties": {
    "mutations": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["base_payload", "mutated_payload", "level", "mutation_type", "seed"],
        "properties": {
          "base_payload": { "type": "string" },
          "mutated_payload": { "type": "string" },
          "level": { "type": "integer" },
          "mutation_type": { "type": "string" },
          "seed": { "type": "integer" },
          "encoding_chain": { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "total_count": { "type": "integer" },
    "spill_id": { "type": ["string", "null"] }
  }
}
```

Machine copy (incl. additive `meta`/`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "base_payload": "1' OR '1'='1",
  "seed": 42,
  "blocked_by": "cloudflare_waf",
  "levels_to_apply": [1, 2, 3, 4],
  "max_mutations_per_level": 8
}
```

* `base_payload` — **required.** The probe payload to mutate.
* `seed` — integer (default 42). Same seed + same payload ⇒ identical set.
* `levels_to_apply` — subset of `[1,2,3,4]` (default all).
* `max_mutations_per_level` — budget per level (default 8; ≤ the candidates a
  level can generate).

---

## 3. The four levels

* **Level 1 — Encoding:** `url_encode`, `double_url_encode`, `unicode_percent_u`
  (`%u00XX`), `hex_0x` (`0x…`), `base64`, `html_entities` (`&#NN;`).
* **Level 2 — Syntax:** `comment_injection` (`/*!50000…*/` / `/**/`), `case_swap`,
  `whitespace_to_comment` (space→`/**/`), `string_concatenation` (split quoted
  literals), `null_byte_insertion` (`%00`), `newline_injection` (`%0a`).
* **Level 3 — Context:** `json_body_wrap`, `xml_entity` (`&#x27;`…),
  `header_injection` (CRLF), `chunked_transfer` (hex-length chunks),
  `multipart_form` (boundary body).
* **Level 4 — Composition:** `nested_encoding` (`url(unicode(payload))`),
  `split_across_params` (HTTP parameter pollution), `polyglot_multicontext`
  (valid across SQL/JS/HTML comment contexts), `buffer_padding` (seeded junk
  prefix to exceed a WAF inspection buffer).

Each `Mutation` records `base_payload`, `mutated_payload`, `level`,
`mutation_type`, `seed`, and an `encoding_chain` naming the transforms applied.

---

## 4. Determinism & budget (the guarantees)

* **Deterministic.** Each level draws from `random.Random(f"{seed}:{level}:{payload}")`
  to order its candidates, then caps at `max_mutations_per_level`. Same seed +
  same payload ⇒ byte-identical mutation set every run, so the Oracle can
  reproduce it. A level's selection is independent of which other levels run.
* **Bounded.** ≤ `max_mutations_per_level` per level, ≤ 4 levels.
* **Offload (Offload Law).** If `total_count > 32`, the full set is written to the
  spill store (`spill_id`) and only the first 32 mutations are inlined in
  `mutations`; `total_count` is always the full number.
* **Non-weaponizing.** A `base_payload` carrying a destructive OS/shell token
  (`rm -rf`, `mkfs`, `dd if=`, `curl … | sh`, fork bomb, `> /dev/sd…`) is refused
  with an error artifact — the mutator re-encodes probes, it does not obfuscate
  destructive commands.

---

## 5. Example artifact (abridged)

```json
{
  "mutations": [
    {"base_payload": "1' OR '1'='1", "mutated_payload": "1%27%20OR%20%271%27%3D%271",
     "level": 1, "mutation_type": "url_encode", "seed": 42, "encoding_chain": ["url"]},
    {"base_payload": "1' OR '1'='1", "mutated_payload": "1' Or/**/'1'='1",
     "level": 2, "mutation_type": "comment_injection", "seed": 42, "encoding_chain": ["comment_/**/"]}
  ],
  "total_count": 21,
  "spill_id": null,
  "meta": {"skill": "payload-mutator", "seed": 42, "levels_applied": [1,2,3,4],
           "max_mutations_per_level": 8, "inlined": 21, "offloaded": false,
           "deterministic": true, "sends_traffic": false},
  "errors": []
}
```

---

## 6. Consumer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. Re-running with the same `seed` + `base_payload` reproduces the identical
   `mutations` (order and content).
3. Per level, the count is ≤ `max_mutations_per_level`; at most 4 levels.
4. `total_count > 32` ⇒ `spill_id` non-null and `len(mutations) == 32`; otherwise
   `spill_id == null` and `len(mutations) == total_count`.
5. Every mutation's `level` is in the requested `levels_to_apply` and its
   `seed` equals the input seed.
