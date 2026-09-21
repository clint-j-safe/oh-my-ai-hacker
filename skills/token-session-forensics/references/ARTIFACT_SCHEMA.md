# Artifact Contract — `token-session-forensics`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error the skill emits a schema-valid artifact with empty `cookies`/`jwts`,
`session_fixation.vulnerable == false`, and `meta.status == "error"`.

This skill is **offline** — it makes no network requests. It produces the auth
model (what can be minted, stolen, replayed) and the forged-token PoCs; the
Phase 5 HTTP Tool is what actually submits those tokens to the server.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "token-session-forensics artifact",
  "type": "object",
  "required": ["cookies", "jwts", "session_fixation"],
  "properties": {
    "cookies": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "missing_httponly": { "type": "boolean" },
          "missing_secure": { "type": "boolean" },
          "samesite_value": { "type": "string" },
          "domain_too_broad": { "type": "boolean" }
        }
      }
    },
    "jwts": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "header": { "type": "object" },
          "payload": { "type": "object" },
          "algorithm": { "type": "string" },
          "vulnerabilities": {
            "type": "array",
            "items": { "enum": ["none_alg_possible","weak_secret_cracked","jku_injection",
                                "kid_injection","alg_confusion_possible","expired_but_accepted"] }
          },
          "forged_token_none_alg": { "type": ["string","null"] },
          "cracked_secret_hash": { "type": ["string","null"] }
        }
      }
    },
    "session_fixation": {
      "type": "object",
      "properties": {
        "vulnerable": { "type": "boolean" },
        "evidence": { "type": "string" }
      }
    }
  }
}
```

> **Note.** The `vulnerabilities` enum is extended beyond the original brief with
> `kid_injection` and `alg_confusion_possible` (RS/ES→HS confusion candidate).
> `jwts[]` also carries `cracked_secret_spill_id` (see §3). Machine copy:
> `references/artifact.schema.json`.

---

## 2. Input contract

```json
{ "session_pool_spill_id": "phase3_sessions_hash",
  "config": {"wordlist": null, "domain_apex_broad": true} }
```

* `session_pool_spill_id` (**required**) — the `account-role-acquisition`
  session pool (or `{session_pool:[...]}`). JWTs are pulled from `auth_headers`,
  cookie values, and (via each session's `state_spill_id`) localStorage.
* `config.wordlist` — override the bundled `assets/jwt_secrets.txt`.
* Optional per-session `pre_login_cookies` enables the session-fixation test.

---

## 3. Credential custody (hard rule)

A cracked HS* secret's **raw value never appears in the artifact**. The JWT entry
carries only `cracked_secret_hash` (`SHA-256` of the secret). The raw secret and
the derived PoC tokens — a re-signed copy and a **privilege-escalated** copy
(role claims bumped to admin) — are written to the spill store and referenced by
`cracked_secret_spill_id`, for the Phase 5 HTTP Tool to load and test. This keeps
the live secret out of the LLM context while remaining actionable.

`forged_token_none_alg` is safe to inline (it carries no secret): it is the
`alg:none`, empty-signature rewrite of the token, ready for Phase 5 to submit —
a *candidate*, proven only if the server accepts it.

---

## 4. JWT vulnerability flags

| Flag | Meaning (offline determination) |
| --- | --- |
| `none_alg_possible` | Structural — an `alg:none` token is always constructible; provided in `forged_token_none_alg` for Phase 5 to confirm. |
| `weak_secret_cracked` | An HS256/384/512 signature verified against a wordlist secret — **confirmed offline**. |
| `alg_confusion_possible` | Token uses RS/ES/PS; an RS→HS confusion attack is a candidate (needs the public key at Phase 5). |
| `jku_injection` | Header carries `jku`/`x5u` (attacker-controlled key URL candidate). |
| `kid_injection` | Header carries `kid` (path-traversal / SQLi-in-kid candidate). |
| `expired_but_accepted` | `exp` is in the past yet the token is in an active session — expiry likely unenforced (confirm at Phase 5). |

Only `weak_secret_cracked` is a *confirmed* finding offline; the rest are leads.

---

## 5. Cookie flags

Per unique cookie: `missing_httponly`, `missing_secure`,
`samesite_value` (`Strict`/`Lax`/`None`), and `domain_too_broad` (leading-dot or
apex-scoped domain — sharable across subdomains).

## 6. Session fixation

`vulnerable: true` only when a paired `pre_login_cookies` vs post-login capture
shows the same session-id cookie with an **unchanged value** across
authentication. Without a paired capture the evidence is `insufficient_data:…`
(honest — not a guess).

---

## 7. Example artifact (abridged)

```json
{
  "cookies": [
    {"name": "session", "missing_httponly": false, "missing_secure": true,
     "samesite_value": "None", "domain_too_broad": true}
  ],
  "jwts": [
    {"header": {"alg": "HS256", "typ": "JWT"},
     "payload": {"sub": "1", "role": "user", "exp": 1700000000},
     "algorithm": "HS256",
     "vulnerabilities": ["expired_but_accepted", "none_alg_possible", "weak_secret_cracked"],
     "forged_token_none_alg": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.",
     "cracked_secret_hash": "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b",
     "cracked_secret_spill_id": "a1b2c3d4e5f60718"}
  ],
  "session_fixation": {"vulnerable": false,
    "evidence": "insufficient_data: no paired pre-auth/post-auth session capture supplied"},
  "meta": {"skill": "token-session-forensics", "status": "ok", "sessions_analyzed": 2,
           "jwts_found": 1, "wordlist_size": 150, "offline_only": true},
  "errors": []
}
```

---

## 8. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. **No raw secret**: every `cracked_secret_hash` matches `^[0-9a-f]{64}$`; no
   raw secret string appears anywhere in the artifact.
3. `weak_secret_cracked` present ⇒ `cracked_secret_hash` non-null and
   `cracked_secret_spill_id` resolves in the spill store.
4. `forged_token_none_alg`, when non-null, ends with `.` (empty signature).
