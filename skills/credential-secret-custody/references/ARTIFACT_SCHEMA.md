# Artifact Contract — `credential-secret-custody`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer.

**The one rule:** the raw secret leaves this process only as ciphertext on disk
and a SHA-256 hash. It never appears in stdout, stderr, logs, or this artifact.
Every artifact carries `meta.raw_secret_in_output:false`; a final leak guard
scans the outgoing JSON for the raw bytes and suppresses them if any survived.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "credential-secret-custody artifact",
  "type": "object",
  "required": ["secret_hash", "encrypted_spill_id", "custody_log"],
  "properties": {
    "secret_hash":        { "type": "string", "description": "SHA-256 of the secret. Safe for LLM context." },
    "encrypted_spill_id": { "type": "string", "description": "Path to the encrypted .enc file under spill_store/secrets/" },
    "secret_type":        { "enum": ["AWS", "GCP", "Azure", "JWT_Private_Key", "DB_Password", "API_Key", "Generic"] },
    "custody_log": {
      "type": "object",
      "properties": {
        "discovered_at":  { "type": "string", "format": "date-time" },
        "discovered_by":  { "type": "string" },
        "cleanup_status": { "enum": ["pending", "rotated", "revoked"] }
      }
    }
  }
}
```

Machine copy (incl. additive `meta`/`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "raw_secret": "AKIAIOSFODNN7EXAMPLE",
  "secret_type": "AWS",
  "context": "found in /static/app.bundle.js line 4021",
  "discovered_by": "js-spa-reverse",
  "action": "custody"
}
```

**Input channels**, most to least safe — the secret should arrive by the safest
available:

* **stdin JSON** (preferred) — no process-table exposure.
* `{"raw_secret_env": "VARNAME"}` — read from an environment variable.
* `{"raw_secret_file": "/path"}` — read from a file.
* `{"raw_secret": "..."}` — inline; via **argv** it is visible in `ps`, so
  `meta.input_channel:"argv"` is flagged as discouraged.

`secret_type` is optional (auto-detected when absent/`Generic`); `context` and
`discovered_by` feed the custody log. `action` defaults to `custody`.

**Status-update mode** (for the final cleanup report):

```json
{"action": "update_status", "secret_hash": "<sha256>", "cleanup_status": "rotated"}
```

---

## 3. What the skill does

1. **Hash** — SHA-256 of the raw bytes; this is the only representation returned
   to context and the key for de-duplication.
2. **Classify** — honor a declared `secret_type`, else auto-detect (AWS `AKIA…`,
   GCP `AIza…`/service-account JSON, Azure `AccountKey=`, PEM `PRIVATE KEY`, DB
   URIs `postgres://user:pass@…`, `sk-…`/`ghp_…`/`xox…` API keys).
3. **Encrypt at rest** — Fernet-encrypt an envelope `{secret, type, context,
   discovered_at, discovered_by}` to `spill_store/secrets/<hash>.enc` (mode 0600,
   dir 0700). The key comes from `SECRET_CUSTODY_KEY` (env), else a keyfile, else
   a freshly generated key written 0600 (`meta.key_source`). The key is never
   emitted — only a `key_fingerprint`.
4. **Custody log** — append/update `spill_store/secrets/custody_log.json` with
   hash, type, timestamps, discoverer, encrypted path, key + context
   fingerprints, occurrence count, and `cleanup_status` (starts `pending`). The
   artifact-facing `custody_log` view carries no raw bytes and no absolute paths.
5. **Scrub** — the plaintext is held in a `bytearray`, zeroed immediately after
   encryption; `raw_secret` is deleted from the payload; a leak guard re-checks
   the artifact before printing.

---

## 4. Safety / custody properties

* **No plaintext egress.** `secret_hash` + ciphertext only. `meta.raw_secret_in_output`
  is always `false` on a successful artifact.
* **Best-effort memory hygiene.** The raw bytes live in a `bytearray` that is
  zeroed post-encryption (Python `str` immutability means the original decode
  cannot be guaranteed-wiped; this is stated honestly, not hidden).
* **At-rest encryption.** AES128-CBC + HMAC via Fernet, files `0600`, dir `0700`.
  If `cryptography` is unavailable the skill degrades to **hash-only** custody
  (`meta.encryption:"unavailable"`, `encrypted_spill_id:""`) — it still never
  leaks the secret, it simply stores no ciphertext.
* **Deterministic dedup.** Re-submitting the same secret updates the same log
  entry (occurrence counter) rather than duplicating it.

---

## 5. Example artifact (abridged)

```json
{
  "secret_hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "encrypted_spill_id": "secrets/b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9.enc",
  "secret_type": "AWS",
  "custody_log": {"discovered_at": "2026-09-18T03:40:00Z", "discovered_by": "js-spa-reverse",
                  "cleanup_status": "pending"},
  "meta": {"skill": "credential-secret-custody", "status": "ok", "action": "custody",
           "encryption": "fernet", "key_source": "generated", "key_fingerprint": "9f2a1c7b6d4e0a53",
           "input_channel": "stdin", "secret_length": 20, "raw_secret_in_output": false},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `meta.raw_secret_in_output == false` and no substring of any known secret
   appears in the artifact.
3. `secret_hash` is 64 lowercase hex chars; `encrypted_spill_id` is
   `secrets/<hash>.enc` (or empty only when `meta.encryption == "unavailable"`).
4. `custody_log.cleanup_status` starts `pending`; the final report drives it to
   `rotated`/`revoked` via `action:"update_status"`. Every `pending` secret is an
   open cleanup item.
