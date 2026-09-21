---
name: account-role-acquisition
description: >-
  Autonomously registers throwaway TEST identities on an in-scope target, walks
  signup / email-verification / MFA-enrollment flows, solves CAPTCHAs via a
  third-party solver when a key is supplied, and captures one fresh
  authenticated session per requested role. Use in Phase 3 (Auth & Identity) to
  build the session pool that privilege-mapping and access-control tests need.
  NEVER uses real or supplied credentials and never touches existing accounts —
  it only creates new ones. Returns a JSON session pool plus an offloaded
  browser-state dump for replay. Do NOT use for login brute-force or credential
  stuffing.
license: Apache-2.0
compatibility: >-
  Python 3.11+, playwright (+ chromium), httpx. Optional keys: a CAPTCHA solver
  (2Captcha) via captcha_api_key, and Mail.tm (free, no key) for temp inboxes.
  TOTP is computed in-process (RFC 6238) — no extra dependency.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "3"
  # Two registrations, each driving a browser with a model in the loop at roughly
  # fifteen seconds per call. The shared 300s sandbox ceiling killed this mid-run.
  timeout-seconds: 1200
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(playwright:*)
---

# Account & Role Acquisition

You are executing **Phase 3 identity bootstrap**. Every access-control test that
follows — privilege mapping, IDOR/BOLA, cross-tenant, differential-session —
needs one live authenticated session per role. Your job is to *create* those
identities and capture their sessions. You are a builder of test accounts, not
an attacker of existing ones.

## Hard boundaries (never cross these)

1. **New identities only.** There is no credentials input. You register fresh
   throwaway accounts and log into those. No credential stuffing, no brute
   force, no customer/admin accounts you did not create.
2. **In scope only.** Signup, verification-link, and MFA navigation stay on the
   in-scope target host. Off-scope redirects are not followed for registration.
3. **MFA = self-enrollment.** If the flow enrolls TOTP for the account you just
   made, read the seed the app shows *you* (the `otpauth://…secret=` it renders
   to the account owner) and compute your own code. Never try to defeat another
   user's MFA.
4. **Custody.** Full browser state (cookies, localStorage, sessionStorage,
   `storage_state`) is offloaded to `state_spill_id`. Registration passwords are
   used once and discarded — never emitted in the artifact.
5. **Artifact Contract.** One strict JSON object on stdout, no prose.

## Inputs

```json
{ "target": "https://app.example.com",
  "roles_to_create": ["standard_user", "tenant_admin"],
  "captcha_api_key": "env:CAPTCHA_API_KEY",
  "signup_path": "/register" }
```

## How to run

```bash
python scripts/run.py '{"target":"https://app.example.com","roles_to_create":["standard_user"]}'
```

`run.py` pipeline (`AccountAcquisition`), per role:

1. `generate_temp_email()` — Mail.tm creates a disposable inbox + auth token.
2. `_find_signup()` — use `signup_path` or probe common signup routes for a form
   with a password field (in scope only).
3. `_fill_form()` — heuristic field mapping (email/password/confirm/first/last/
   username/full-name/company) with realistic names + a strong random password;
   consent checkboxes ticked.
4. `_detect_and_solve_captcha()` — extract reCAPTCHA/hCaptcha/Turnstile sitekey
   → `solve_captcha()` (2Captcha) → inject the token into the `*-response` field.
5. `verify_email()` — poll Mail.tm for the verification link, click it (in scope).
6. `_maybe_totp()` — if TOTP is enrolled for this account, capture the seed and
   submit a valid RFC-6238 code.
7. `login_and_extract_session()` / `offload_state()` — confirm a target-scoped
   session cookie, dump `storage_state` + sessionStorage to the spill store,
   derive `auth_headers` from a JWT in localStorage if present.

Edge cases handled: "account already exists" → new temp email + retry
(`max_retries`); verification timeout → role reported in `failed_roles`, not a
crash; missing CAPTCHA key or Mail.tm outage → clean per-role failure.

## Artifact Contract (strict)

One JSON object on stdout per `references/ARTIFACT_SCHEMA.md` (machine copy:
`references/artifact.schema.json`). Required keys: `session_pool`,
`registration_status`. On fatal error, emit an empty-but-valid artifact with
`registration_status.success: false`.

## Typed exits

- `sessions_acquired` — at least one role session captured.
- `partial` — some roles in `failed_roles` (verification/CAPTCHA/no-signup).
- `no_signup` — no registration form found on the target.
- `out_of_scope` / `launch_failed` — fatal; `registration_status.success:false`.

## External tools

| Tool / Service | Purpose | URL |
| --- | --- | --- |
| Playwright (Python) | Browser automation of signup flows | https://github.com/microsoft/playwright-python |
| Mail.tm API | Free, no-auth temp email + verification polling | https://docs.mail.tm/ |
| 2Captcha API | reCAPTCHA/hCaptcha/Turnstile solving (key required) | https://2captcha.com/2captcha-api |

Install: `pip install playwright httpx && playwright install chromium`.

## Assets

`assets/names-fallback.txt` — first-name pool for realistic identities. For a
larger pool set `config.names_wordlist` (or env `ACCT_NAMES`) to SecLists names:
https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/names.txt
Passwords are generated strong-random in-process (complexity-meeting); the
SecLists top-100k list is referenced only for environments that must draw the
password from a list. No brute-force wordlists are used — this skill never
guesses credentials.
