---
name: token-session-forensics
description: >-
  Offline cryptographic and architectural analysis of the authentication
  mechanisms captured in Phase 3. Decodes JWTs, tests for algorithm confusion
  (alg:none, RS256->HS256), cracks weak HS256 secrets against a wordlist, checks
  cookie flags (HttpOnly, Secure, SameSite, domain scope), and identifies
  session-fixation vectors. Use in Phase 3 to understand what can be minted,
  stolen, or replayed. Makes no network requests — it produces forged-token
  PoCs for the Phase 5 HTTP Tool to test. Returns an auth-model artifact.
license: Apache-2.0
compatibility: >-
  Python 3.11+. JWT crypto is implemented in the standard library, so there are
  no required dependencies; PyJWT and cryptography are optional. Needs read
  access to the Phase 3 session-pool spill.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "3"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Token & Session Forensics

You are executing **Phase 3 auth-model analysis**. You take the sessions Phase 3
captured and work out, offline, what an attacker could do to them: forge, crack,
steal, or replay. You never touch the network — you hand Phase 5 the exact
forged tokens to submit, and it confirms them.

## Laws

1. **Offline only.** No requests. Every determination is made from the captured
   tokens/cookies. Network-dependent claims (does the server accept `alg:none`?)
   are emitted as *candidates* with a ready-to-submit forged token, not as
   confirmed findings.
2. **Custody.** A cracked secret's raw value never enters the artifact — only
   its `SHA-256` hash. The raw secret and the derived PoC tokens (re-signed +
   privilege-escalated) go to the spill store (`cracked_secret_spill_id`).
3. **Artifact Contract.** One strict JSON object on stdout, no prose.

## Inputs

```json
{ "session_pool_spill_id": "phase3_sessions_hash",
  "config": {"wordlist": null, "domain_apex_broad": true} }
```

## How to run

```bash
python scripts/run.py '{"session_pool_spill_id":"abc123"}'
```

`run.py` pipeline (`TokenForensics`):

1. `load_sessions()` — read the Phase 3 pool.
2. `analyze_cookies()` — per unique cookie: `missing_httponly`, `missing_secure`,
   `samesite_value`, `domain_too_broad` (leading-dot / apex scope).
3. `_collect_tokens()` — extract JWTs from `auth_headers`, cookie values, and
   localStorage (via each session's `state_spill_id`).
4. `decode_jwt()` — base64url-decode header + payload; read `alg` and claims.
5. `test_jwt_none_alg()` — build the `alg:none` empty-signature token
   (`forged_token_none_alg`) for Phase 5; flag `none_alg_possible`.
6. `crack_jwt_weak_secrets()` — HMAC-verify the signature against
   `assets/jwt_secrets.txt` (stdlib, fast, offline). On a hit → `weak_secret_
   cracked`, hash + spilled PoC tokens.
7. Header/expiry flags — `alg_confusion_possible` (RS/ES/PS), `jku_injection`,
   `kid_injection`, `expired_but_accepted`.
8. `check_session_fixation()` — compare pre-login vs post-login session id when a
   paired `pre_login_cookies` capture is present; else `insufficient_data`.

## Artifact Contract (strict)

One JSON object on stdout per `references/ARTIFACT_SCHEMA.md` (machine copy:
`references/artifact.schema.json`). Required keys: `cookies`, `jwts`,
`session_fixation` (+ additive `meta`/`errors`). On fatal error, emit an
empty-but-valid artifact with `meta.status: "error"`.

## Typed exits

- `auth_modeled` — analysis complete.
- `weak_secret` — an HS* secret cracked (`weak_secret_cracked`); the highest-
  value offline finding — hand the spilled forged tokens to Phase 5.
- `forgeable` — `none_alg_possible`/`alg_confusion_possible`/`jku`/`kid` leads.
- `no_sessions` — pool empty/unreadable (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| PyJWT | JWT decode/encode (optional; stdlib used by default) | https://github.com/jpadilla/pyjwt |
| cryptography | Asymmetric verification for RS/ES confirmation (optional) | https://github.com/pyca/cryptography |

Install (optional): `pip install pyjwt cryptography`.

## Wordlists

`assets/jwt_secrets.txt` — curated high-signal weak HS* secrets for fast offline
cracking. For a fuller list set `config.wordlist` (or env `JWT_WORDLIST`) to
SecLists JWT secrets:
https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/JWT-Secrets.txt
