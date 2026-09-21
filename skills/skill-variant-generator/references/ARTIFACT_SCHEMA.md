# Artifact Contract — `skill-variant-generator`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the consumer. This
skill reads and writes skill files and **sends no target traffic**
(`meta.sends_traffic:false`).

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "skill-variant-generator artifact",
  "type": "object",
  "required": ["variant_name", "variant_path", "base_skill", "context"],
  "properties": {
    "variant_name": { "type": "string" },
    "variant_path": { "type": "string" },
    "base_skill": { "type": "string" },
    "context": { "type": "string" },
    "artifact_contract_preserved": { "type": "boolean" },
    "registered": { "type": "boolean" },
    "changes_made": { "type": "array", "items": { "type": "string" } }
  }
}
```

Machine copy (incl. additive `meta`/`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "base_skill": "sqli-database-injection",
  "new_context": "websocket",
  "observed_behavior": "WS endpoint at /ws/api accepts JSON",
  "constraints": ["must use WS frames", "no HTTP fallback"],
  "config": {"skills_dir": "skills"}
}
```

* `base_skill` — **required.** Folder name under `skills_dir` holding the base
  `SKILL.md` and its `references/` contract.
* `new_context` — **required.** The target context; known contexts:
  `websocket`, `graphql`, `file_upload`, `grpc`, `xml_soap`, `http_header`
  (any other string still produces a variant with a generic adaptation section).
* `observed_behavior` / `constraints` — recorded in the variant's adaptation
  section.
* `config.skills_dir` (or `SKILLS_DIR` env) — the skills root (default `skills`).

---

## 3. What it does

1. **load_base_skill** — read `skills/<base>/SKILL.md`, split frontmatter/body.
2. **adapt_delivery / adapt_detection** — apply the context's substitution map to
   the body (delivery, tooling, detection signal, evidence source) and append a
   `## Context adaptation — <context>` section with the observed behavior,
   constraints, and the delivery/detection/evidence mapping.
3. **preserve_contract** — copy `references/ARTIFACT_SCHEMA.md` and
   `references/artifact.schema.json` from the base **unchanged** and verify each
   with a SHA-256 equality check. `artifact_contract_preserved` is `true` only if
   every present contract file hashes equal.
4. **save_variant** — write `skills/<base>-via-<context>/` with the adapted
   `SKILL.md`, the copied contract, the base's `scripts/run.py` + `spill_store.py`
   (engine and schema unchanged), and a generated `scripts/delivery_adapter.py`.
5. **register_variant** — upsert an entry into the Dynamic Skill Registry
   (`skills/.variant_registry.json`).

The generated `delivery_adapter.py` is a complete, runnable module exposing
`wrap_payload(payload, endpoint)` (the transport envelope for the context) and
`detect(before, after)` (context-appropriate difference check). The base engine's
detection/evidence logic and artifact schema are reused as-is, which is exactly
what keeps the Oracle able to verify the variant identically.

---

## 4. Contract preservation (the guarantee)

The variant emits the **same artifact schema** as the base — only the transport
changes. This is enforced by copying the base contract files byte-for-byte and
hash-verifying them; if the base lacks contract files, or a copy does not hash
equal, `artifact_contract_preserved` is `false` (and `errors` says why).

---

## 5. Example artifact (abridged)

```json
{
  "variant_name": "sqli-database-injection-via-websocket",
  "variant_path": "skills/sqli-database-injection-via-websocket/SKILL.md",
  "base_skill": "sqli-database-injection",
  "context": "websocket",
  "artifact_contract_preserved": true,
  "registered": true,
  "changes_made": [
    "delivery/tooling: 'httpx' → 'websockets'",
    "detection: HTTP status codes → inbound-frame diffing / close codes",
    "evidence: HTTP response body → inbound WS frame log",
    "preserved contract file references/ARTIFACT_SCHEMA.md (sha256 verified equal)",
    "preserved contract file references/artifact.schema.json (sha256 verified equal)",
    "wrote scripts/delivery_adapter.py (wrap_payload/detect for the context)",
    "registered in Dynamic Skill Registry (.variant_registry.json)"
  ],
  "meta": {"skill": "skill-variant-generator", "client_lib": "websockets", "sends_traffic": false},
  "errors": []
}
```

---

## 6. Consumer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `variant_name == "<base_skill>-via-<slug(context)>"` and `variant_path` ends in
   `<variant_name>/SKILL.md`.
3. `artifact_contract_preserved == true` ⇒ the variant's `references/` contract
   files hash-equal the base's (the Oracle verifies with the identical schema).
4. `registered == true` ⇒ the variant appears in `.variant_registry.json`.
5. `meta.sends_traffic == false`.
