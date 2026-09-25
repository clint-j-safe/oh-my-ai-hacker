# SAHW authenticated scanning — auth-sequence recorder + TOTP — design spec

Date: 2026-09-25
Status: Approved (design). Implementation via a separate plan (writing-plans).
Branch: feat/dns-vhost-recon (pre-AWS; migrates to the AWS control plane later).

## Context

SAHW is a black-box web pentest engine: one Docker container = one "beat", all config from
env, an LLM "hunter" proposes probes and the deterministic Axiom decides verdicts. Sessions
live in an in-process `SessionStore`; secrets (passwords, tokens/cookies) never reach the spine
— only non-secret metadata does (label, username, `auth_header_name`, `has_auth_material`).

Today the engine can only **self-register synthetic accounts** through a target's signup flow.
It cannot use operator-provided real credentials, has no way to discover a target's login
mechanism, and has no MFA/TOTP support. That makes enterprise, auth-gated apps (which rarely
allow open signup and often enforce TOTP) effectively unreachable — the whole authenticated and
post-2FA attack surface is invisible to the engine.

This spec adds a reusable capability, modeled on how Acunetix/Burp scan MFA apps: the operator
supplies a URL + real credentials and requests an **auth scan**; an agent discovers and records
the **login sequence**; for MFA apps the operator supplies the **TOTP shared secret** (or
`otpauth://` URI) so the engine generates valid RFC-6238 codes to complete login. Two run modes
are supported: a **bypass** run (password only, hunt for a 2FA/auth bypass) and an
**authenticated** run (complete TOTP, scan the authenticated surface).

First target: the operator's own `demo.safeone.io`. Intended sequence: run the bypass mode
first; if no bypass is found, run the authenticated mode with the TOTP secret.

Design invariants preserved: "LLM proposes; deterministic code decides"; the Axiom is the sole
verdict authority; secrets never persist to the spine; every request passes the Tether scope
gate; findings are control-differential and evidence-backed.

## Decisions (jev-assisted; escalated forks reasoned out)

- **Discovery = hybrid.** A deterministic recorder handles the common case; the LLM hunter is a
  fallback only when rules cannot classify the flow. (jev prior 0.61, escalated — chosen for fit
  with both the operator's "agent records the sequence" ask and the engine's determinism.)
- **Record once at auth-scan request, cache, replay** during the scan (jev 0.94).
- **Represent the login as a replayable ordered *sequence*** of HTTP steps with extraction rules
  and a TOTP slot — not a single login shape (jev 1.0).
- **TOTP input accepts both** an `otpauth://` URI and a raw base32 secret, with optional
  algorithm/digits/period overrides (jev 0.99).
- **Reuse guard: yes** — track the consumed (window, code) and wait for the next 30s window
  rather than resubmit a one-time code (jev 0.69, escalated — concur; this is why Burp throttles).
- **Two run modes** (`bypass` then `authenticated`), operator-selected; TOTP secret required
  only for `authenticated` (jev split, escalated — chosen because the operator stated this flow
  explicitly).
- **Persistence: spine stores the sequence *shape* only** (endpoints, field names, token/cookie
  location, header name, 2FA type); creds + TOTP secret stay in env/in-process (jev 0.99).
- **Session refresh: reuse until 401/redirect-to-login, then re-login** with a fresh code
  (jev 0.83).

## Components

### 1. TOTP generator — `orchestrator/src/totp.ts` (pure)
- Accepts either an `otpauth://totp/...?secret=...&algorithm=&digits=&period=` URI **or** a raw
  base32 secret plus optional `{ algorithm: SHA1|SHA256|SHA512 (default SHA1), digits: default 6,
  period: default 30 }`.
- `parseTotpConfig(input, overrides?) -> TotpConfig` (base32-decodes the secret; validates).
- `generateTotp(config, atUnixSeconds) -> { code, window }` — RFC 6238 (HMAC-based, big-endian
  counter = floor(t/period)).
- **Reuse guard:** a small stateful `TotpEmitter` wraps a config and remembers the last emitted
  `window`. `next(nowFn, sleepFn)` returns a code for a window not yet consumed; if the current
  window is already consumed it waits (bounded, injectable `sleepFn`) until the next window. Pure
  logic, time/sleep injected for tests.
- No secret is logged; the emitter holds the decoded secret in memory only.

### 2. Auth-sequence recorder — `orchestrator/src/auth-recon.ts` (pure helpers) + a recorder in `beat.ts`
- Pure helpers (unit-tested):
  - `LOGIN_PATH_CANDIDATES` and `candidateLoginRequests(url, creds, fieldHints?)` — ordered
    attempts (JSON `{email,password}`, `{username,password}`, form-encoded equivalents, etc.),
    cheap-first.
  - `classifyLoginResponse({status, headers, body}) -> { outcome, authMaterial?, twoFactor? }`
    where `outcome ∈ authed | 2fa_pending_with_material | 2fa_required_no_material | invalid | blocked | unknown`.
  - `extractAuthMaterial(headers, body) -> { headerName, value } | null` — prefers a bearer
    token from the JSON body (keys: token/access_token/accessToken/jwt/id_token/authToken/…) →
    `Authorization`; else a `Set-Cookie` session cookie → `Cookie`.
  - `detectTwoFactor(status, body) -> { present: boolean, type?: "totp"|"otp"|"sms"|"unknown" }`
    (signals: otp/totp/2fa/mfa/authenticator/verification-code/challenge).
- Recorder (in `beat.ts`, runs on beat 1 when an auth scan is requested): uses the Tether-gated
  `fetchImpl` to (a) locate the login endpoint (candidate paths + the app's own login form/links),
  (b) submit creds, (c) classify, (d) if a TOTP step is present and mode is `authenticated`,
  submit a generated code, and (e) emit a **`LoginSequence`**: an ordered list of steps
  `{ method, url, contentType, bodyTemplate (with {{email}}/{{password}}/{{totp}} placeholders),
  extract: { from: "body-json-path"|"set-cookie", as: "authMaterial"|"login_id", headerName } }`.
- **Hybrid fallback:** if the deterministic recorder cannot classify the flow (SPA/multi-redirect/
  unusual envelope), it records what it learned and hands the login-envelope discovery to the LLM
  hunter, which records the working sequence; seeding then resumes.
- The recorded `LoginSequence` **shape** (no secret values) persists to the spine under
  `recovered_intel`; the creds/TOTP secret are injected at replay from env/in-process only.

### 3. Session lifecycle — `beat.ts` + `session.ts`
- Replaying the `LoginSequence` (with placeholders filled from env/in-process, TOTP from the
  emitter) establishes a `SessionStore` session labeled "A". For `bypass` mode the replay stops
  **before** the TOTP step, seeding the pre-2FA session (with whatever material the pre-OTP state
  yields).
- The session is **reused across beats** (its non-secret meta is on the spine; the material is
  re-established in-process each run by replaying the sequence). On a `401`/redirect-to-login
  during the hunt, the executor signals expiry and the sequence is re-replayed with a **fresh**
  TOTP code (respecting the reuse guard).
- Reuse `SessionStore.create({ credentials, authMaterial, authHeaderName })`; the http executor's
  existing label-based injection (send vs record headers) is unchanged.

### 4. Run modes — config in `config.ts`
- `SAHW_AUTH_MODE ∈ { off (default), bypass, authenticated }`.
- `SAHW_AUTH_LOGIN` (JSON): `{ email|username, password, login_url?, field_hints? }` — the real
  credentials + optional hints. Secret; env/in-process only.
- `SAHW_TOTP` (JSON or string): an `otpauth://` URI or `{ secret, algorithm?, digits?, period? }`.
  Required when `SAHW_AUTH_MODE=authenticated` and the flow has a TOTP step; ignored in `bypass`.
- Fail-closed: `authenticated` mode with a TOTP-gated flow and no `SAHW_TOTP` throws a
  `ConfigError`; `bypass` mode never consumes a TOTP secret even if present.

### 5. Axiom proofs — `axiom.ts`
- **2FA/auth bypass (bypass mode):** a new `derived` invariant `auth_bypass_pre_2fa` — CONFIRMED
  when a **password-only (pre-2FA) session** reaches a protected resource that (a) an anonymous
  session cannot reach (control differential: anon → 401/redirect vs pre-2FA session → 200 with
  protected content) and (b) is gated behind completed 2FA. Missing either differential →
  NEEDS_REVIEW, never a pass.
- **Authenticated-surface findings (authenticated mode):** the existing invariants
  (`body_contains`, `status_in`, `state_changed`, `derived`, …) apply unchanged; the only
  difference is the hunter now has an authenticated session "A" to reach the surface.

## Data flow
- **Record (beat 1 / auth-scan request):** recorder → `LoginSequence` (shape) → spine
  `recovered_intel`; establish session "A" (pre-2FA in bypass mode, full in authenticated mode).
- **Each beat:** load `LoginSequence` from spine; ensure session "A" valid (reuse; re-replay on
  401 with a fresh TOTP code); the hunter probes; the Axiom verifies.

## Config model (env now, safe later)
Provided per engagement as env on the runner today (`SAHW_AUTH_MODE`, `SAHW_AUTH_LOGIN`,
`SAHW_TOTP`), and later sourced from the per-user "safe" (SSM SecureString) in the AWS control
plane — no engine change needed for that migration, only where the env values originate.

## Testing
- `totp.ts`: RFC 6238 published test vectors (SHA1/SHA256/SHA512); base32 + `otpauth://` parsing;
  reuse guard (injected clock/sleep) never re-emits a consumed window's code.
- `auth-recon.ts`: `classifyLoginResponse` over token-body / Set-Cookie / 2FA-signal / invalid /
  403-blocked fixtures; `extractAuthMaterial` token-vs-cookie; `detectTwoFactor` signals;
  `candidateLoginRequests` envelope ordering.
- Recorder + replay: injected `fetchImpl` fixtures drive a full record → seed cycle in both modes;
  a 401 mid-hunt triggers exactly one re-replay with a fresh code.
- `axiom.ts`: `auth_bypass_pre_2fa` → CONFIRMED on the full control differential, NEEDS_REVIEW
  when either side of the differential is missing.
- Beat integration: with an injected fetch, `SAHW_AUTH_MODE=bypass` seeds a pre-2FA session and
  `authenticated` seeds a full session; default (`off`) path is byte-identical to today.

## Non-goals / later
- Non-TOTP MFA (SMS, push, WebAuthn, character-select passwords, CAPTCHA) — out of scope, same as
  Burp's recorded-login limitations.
- The AWS "safe" sourcing of these secrets — separate (AWS control-plane) work; this spec keeps
  the values env-provided.
- A UI for recording sequences — the recorder is headless/deterministic with an LLM fallback.

## Critical files
- New: `orchestrator/src/totp.ts`, `orchestrator/src/auth-recon.ts`.
- Modified: `orchestrator/src/config.ts` (parse `SAHW_AUTH_MODE`/`SAHW_AUTH_LOGIN`/`SAHW_TOTP`,
  fail-closed rules), `orchestrator/src/beat.ts` (recorder + session lifecycle + mode wiring),
  `orchestrator/src/axiom.ts` (`auth_bypass_pre_2fa` deriver), `orchestrator/src/spine.ts`
  (persist `LoginSequence` shape under recovered_intel), and reuse of `orchestrator/src/session.ts`
  and the `tools.ts` http executor unchanged.
- Tests: `orchestrator/test/totp.test.ts`, `test/auth-recon.test.ts`, plus additions to
  `test/axiom*.test.ts`, `test/config*.test.ts`, and a beat integration test.
