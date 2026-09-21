# Artifact Contract — `account-role-acquisition`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error the skill emits a schema-valid artifact with empty `session_pool`
and `registration_status.success == false`.

The `session_pool` is the substrate for Phase 3+ access-control testing
(privilege mapping, IDOR/BOLA, differential-session tests): one authenticated
session per role.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "account-role-acquisition artifact",
  "type": "object",
  "required": ["session_pool", "registration_status"],
  "properties": {
    "session_pool": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["role", "cookies", "auth_headers", "state_spill_id"],
        "properties": {
          "role": { "type": "string" },
          "username": { "type": "string" },
          "cookies": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "name": { "type": "string" }, "value": { "type": "string" },
                "domain": { "type": "string" }, "httpOnly": { "type": "boolean" },
                "secure": { "type": "boolean" }, "sameSite": { "type": "string" }
              }
            }
          },
          "auth_headers": { "type": "object", "additionalProperties": { "type": "string" } },
          "state_spill_id": { "type": "string" }
        }
      }
    },
    "registration_status": {
      "type": "object",
      "properties": {
        "success": { "type": "boolean" },
        "failed_roles": { "type": "array", "items": { "type": "string" } },
        "captcha_bypass_used": { "type": "boolean" }
      }
    }
  }
}
```

Machine copy (incl. additive `meta`/`scope_summary`/`errors` and `mfa_enrolled`):
`references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "target": "https://app.example.com",
  "roles_to_create": ["standard_user", "tenant_admin"],
  "captcha_api_key": "env:CAPTCHA_API_KEY",
  "signup_path": "/register",
  "scope_policy_spill_id": "abc123",
  "config": {"captcha_provider": "2captcha", "verify_timeout": 120, "max_retries": 2}
}
```

* `target` (**required**) — http(s) root of the in-scope app.
* `roles_to_create` — one session is created per role name.
* `captcha_api_key` — a literal key, an `env:VAR` reference, or a bare env-var
  name. Omit to skip CAPTCHA solving (flows behind a CAPTCHA then fail cleanly).
* `signup_path` — optional hint; otherwise common signup paths are probed.
* `scope_policy_spill_id` — same policy shape as the other skills.

There is deliberately **no** `credentials`/`username`/`password` input: this
skill cannot be pointed at an existing account.

---

## 3. Hard boundaries (enforced in code)

| Boundary | Enforcement |
| --- | --- |
| New identities only | No credential input exists; each role gets a freshly-registered throwaway account. `meta.credential_reuse` is always `false`. |
| In scope only | Signup/verification/link navigation is gated to the scope policy (default: target apex + subdomains). |
| MFA = self-enrollment | TOTP is handled only by reading the seed the app shows the account owner during **our** enrollment (`otpauth://…secret=`), then computing our own RFC 6238 code. No attempt to defeat another user's MFA. |
| Custody | Full state (cookies, localStorage, sessionStorage, Playwright `storage_state`) is spilled to `state_spill_id`. Registration passwords are used once and discarded — never emitted. |

`captcha_bypass_used` records whether a third-party solver token was injected —
this is an authorized-engagement anti-automation test signal, surfaced for the
audit log, not hidden.

---

## 4. External services

* **Mail.tm** (`api.mail.tm`, free, no key) — temp inbox per identity; the
  verification link is polled from `/messages` within `verify_timeout`.
* **2Captcha** (`in.php`/`res.php`, key required) — reCAPTCHA v2 / hCaptcha /
  Turnstile sitekey → token, injected into the matching `*-response` field.

Both degrade gracefully: unavailable service ⇒ that role fails and is listed in
`failed_roles`, never a crash.

---

## 5. Example artifact (abridged)

```json
{
  "session_pool": [
    {"role": "standard_user", "username": "qa.4f2a1c@…", 
     "cookies": [{"name": "session", "value": "…", "domain": "app.example.com",
                  "httpOnly": true, "secure": true, "sameSite": "Lax"}],
     "auth_headers": {"Authorization": "Bearer eyJ…"},
     "state_spill_id": "a1b2c3d4e5f60718", "mfa_enrolled": false}
  ],
  "registration_status": {"success": true, "failed_roles": ["tenant_admin"],
                          "captcha_bypass_used": true},
  "meta": {"skill": "account-role-acquisition", "status": "ok",
           "roles_requested": ["standard_user","tenant_admin"],
           "roles_acquired": ["standard_user"],
           "new_identities_only": true, "credential_reuse": false},
  "scope_summary": {"policy_present": true, "target_host": "app.example.com"},
  "errors": [{"stage": "register:tenant_admin", "error": "email verification timeout"}]
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. every `session_pool[].cookies[].domain` is in scope for the target.
3. every `session_pool[].state_spill_id` resolves in the spill store.
4. `meta.credential_reuse === false` (invariant; a `true` here quarantines the run).
5. `registration_status.success` ⇒ `session_pool` non-empty.
