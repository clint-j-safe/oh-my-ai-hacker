---
name: credential-secret-custody
description: >-
  The Observer's secret handler. When the loop discovers a credential (API key,
  DB password, JWT/PEM private key, cloud key) in JS, responses, or files, it
  mathematically secures it before the LLM sees the next turn: SHA-256-hashes it
  (the only form allowed back into context), Fernet-encrypts the raw value at
  rest in spill_store/secrets/<hash>.enc, and appends a custody-log entry for the
  final cleanup/rotation report. Use in Phase 5/6 on any secret discovery. The
  raw secret NEVER reaches stdout, stderr, logs, or the artifact — hash and
  ciphertext only, with the plaintext buffer zeroed after encryption.
license: Apache-2.0
compatibility: Python 3.11+, cryptography (Fernet), hashlib.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5-6"
  loop-component: "5-observer"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Credential & Secret Custody

You are the vault the loop drops secrets into. The moment any other skill finds a
credential, it hands the raw value to you and forgets it — because from here on
the only safe form of that secret is a hash and a blob of ciphertext. Your job is
to make that true before the next turn: hash it, encrypt it at rest, log it for
cleanup, and let nothing else out.

## Correctness (this is the whole safety story)

1. **No plaintext egress.** The raw secret leaves this process only as (a)
   ciphertext on disk and (b) a SHA-256 hash. It is never printed, never logged,
   never placed in the artifact. Every artifact carries
   `meta.raw_secret_in_output:false`, and a final leak guard scans the outgoing
   JSON for the raw bytes and suppresses them if any survived.
2. **Encrypt at rest.** The value is Fernet-encrypted (AES128-CBC + HMAC) into
   `spill_store/secrets/<hash>.enc` at mode `0600` in a `0700` dir. The key comes
   from `SECRET_CUSTODY_KEY`, a `0600` keyfile, or a freshly generated key — never
   emitted, only fingerprinted. No `cryptography`? Degrade to **hash-only**
   custody; still no leak, just no ciphertext.
3. **Memory hygiene.** The plaintext lives in a `bytearray` that is zeroed
   immediately after encryption, and `raw_secret` is deleted from the payload.
   (Python `str` immutability makes a guaranteed wipe of the original impossible;
   this is stated honestly, not papered over.)
4. **Safe intake.** Prefer stdin (no `ps` exposure); `raw_secret_env` /
   `raw_secret_file` avoid putting the secret in the command line at all. An argv
   secret is accepted but flagged `input_channel:"argv"` as discouraged.

## Inputs

```json
{ "raw_secret": "AKIAIOSFODNN7EXAMPLE", "secret_type": "AWS",
  "context": "found in /static/app.bundle.js:4021", "discovered_by": "js-spa-reverse",
  "action": "custody" }
```

`secret_type` is optional (auto-detected when absent/`Generic`). Safer intakes:
`{"raw_secret_env": "VAR"}` or `{"raw_secret_file": "/path"}`. Cleanup-report
mode: `{"action": "update_status", "secret_hash": "...", "cleanup_status": "rotated"}`.

## How to run

```bash
echo '{"raw_secret":"AKIAIOSFODNN7EXAMPLE","secret_type":"AWS","discovered_by":"js-spa-reverse"}' \
  | python scripts/run.py
```

Prefer piping on stdin. `run.py` pipeline (`SecretCustodian`):

1. `_read_secret()` — intake into a zeroable `bytearray` from the safest channel.
2. `hash_secret()` — SHA-256 (the context-safe reference + dedup key).
3. `classify_type()` — declared type or auto-detect (AWS/GCP/Azure/PEM/DB-URI/API).
4. `encrypt_secret()` — Fernet-encrypt the envelope to `secrets/<hash>.enc`, then
   zero the plaintext.
5. `write_custody_log()` — append/update `secrets/custody_log.json`
   (`cleanup_status:"pending"`); leak-guard the artifact; print hash + path only.

## Typed exits

- `status: ok` — hashed, encrypted at rest, logged; `encrypted_spill_id` set.
- `status: degraded` — hash-only custody (no `cryptography`); still no leak,
  `encrypted_spill_id:""`.
- `action: update_status` — an existing entry moved to `rotated`/`revoked`.
- error artifact — no secret provided, or (never printed) a leak-guard trip.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| cryptography (Fernet) | AES128-CBC+HMAC encryption at rest | https://cryptography.io/en/latest/fernet/ |
| SecLists — Regex | Secret-detection patterns (context) | https://github.com/danielmiessler/SecLists/tree/master/Regex |

Install: `pip install cryptography`.

## Wordlists

None bundled — detection uses built-in structural regexes (AWS `AKIA…`, GCP
`AIza…`, Azure `AccountKey=`, PEM private keys, DB URIs, `sk-`/`ghp_`/`xox…`),
extensible in `scripts/run.py`.
