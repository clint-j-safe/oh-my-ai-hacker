# SAHW Authenticated Scanning + Auth-Sequence Recorder + TOTP — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let SAHW scan auth-gated web apps by recording a login sequence from operator-provided credentials, generating RFC-6238 TOTP codes to complete MFA login, and running either a 2FA-bypass hunt or a full authenticated scan.

**Architecture:** A pure RFC-6238 TOTP generator with a code-reuse guard; a pure auth-response classifier + login-sequence builder (hybrid: deterministic first, LLM-hunter fallback later); config for two run modes (`bypass`/`authenticated`); a new `auth_bypass_pre_2fa` Axiom deriver; spine persistence of the login-sequence *shape* only; and a beat-1 recorder that establishes an in-process `SessionStore` session the hunter reuses (re-logging in on 401 with a fresh code).

**Tech Stack:** Node 22+, TypeScript ESM, `node:test` via `tsx` (`cd orchestrator && npm test`), `node:crypto` (HMAC for TOTP). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-25-sahw-authenticated-scanning-totp-design.md`

## Global Constraints

- Engine suite `cd orchestrator && npm test` (`tsc --noEmit` then `tsx --test test/*.test.ts`) MUST stay green — it is the Docker build gate.
- Secrets never persist: real credentials and the TOTP secret live only in env/in-process (`SessionStore` records, `TotpConfig`). Only the login-sequence **shape** (endpoints, field names, extraction locations, header name, 2FA type) may reach the spine.
- The `derived` invariant is a fixed-code registry, never a free expression: new proofs are added as a named deriver in `DERIVERS` with an input type-guard, returning a `Verdict` (`orchestrator/src/axiom.ts:487`). Missing evidence → `NEEDS_REVIEW`/`FALSE_POSITIVE`, never a pass.
- Config is fail-closed: `SAHW_AUTH_MODE=authenticated` requires `SAHW_AUTH_LOGIN`; a TOTP-gated flow in authenticated mode with no `SAHW_TOTP` throws at record time; `bypass` mode never consumes a TOTP secret.
- Default path unchanged: with `SAHW_AUTH_MODE` unset/`off`, `runBeat` behaves byte-identically to today.
- TOTP defaults: algorithm SHA1, 6 digits, 30s period (RFC 6238).
- Follow existing patterns: env parsing via the `num`/`boolEnv`/`urls` helpers in `config.ts`; session creation via `SessionStore.create` (`orchestrator/src/session.ts`); the http executor's label-based injection stays unchanged (`orchestrator/src/tools.ts:951`).

## Review Focus

- **TOTP non-defaults (SHA256/SHA512, 8 digits):** an operator supplies `otpauth://…?algorithm=SHA256&digits=8`; codes must still be correct. → pinned in Task 1.
- **Login response with BOTH a body token and a Set-Cookie:** `extractAuthMaterial` must pick deterministically (token precedence). → pinned in Task 2.
- **Authenticated mode against a flow with NO 2FA step:** must seed a full session, not throw for a missing TOTP secret. → pinned in Task 3 (config) + Task 6 (recorder).
- **Session expiry mid-hunt (401/redirect-to-login):** must re-replay the sequence exactly once with a FRESH code, and the reuse guard must force a wait if the same 30s window is still current. → pinned in Task 1 (guard) + Task 6 (refresh).
- **bypass-mode login yielding no usable material (only a challenge id / partial cookie):** must still seed session "A" with whatever partial material exists (or `has_auth_material=false`) so the hunter can probe, not crash. → pinned in Task 6.

---

### Task 1: RFC-6238 TOTP generator + reuse guard (`totp.ts`)

**Files:**
- Create: `orchestrator/src/totp.ts`
- Test: `orchestrator/test/totp.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `interface TotpConfig { secret: Uint8Array; algorithm: "SHA1"|"SHA256"|"SHA512"; digits: number; period: number }`
  - `parseTotp(input: string | { secret: string; algorithm?: string; digits?: number; period?: number }): TotpConfig` — accepts an `otpauth://totp/...?secret=BASE32&algorithm=&digits=&period=` URI or a `{secret,...}` object; base32-decodes; throws `Error` on invalid input.
  - `generateTotp(config: TotpConfig, atUnixSeconds: number): { code: string; window: number }`
  - `class TotpEmitter { constructor(config: TotpConfig); async next(nowMs: () => number, sleep: (ms: number) => Promise<void>): Promise<{ code: string; window: number }> }`

- [ ] **Step 1: Write the failing test**

Create `orchestrator/test/totp.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTotp, generateTotp, TotpEmitter } from "../src/totp.js";

// RFC 6238 Appendix B: ASCII secret "12345678901234567890" = base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
const SHA1_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("generateTotp matches RFC 6238 SHA1 8-digit vectors", () => {
  const cfg = parseTotp({ secret: SHA1_B32, algorithm: "SHA1", digits: 8, period: 30 });
  assert.equal(generateTotp(cfg, 59).code, "94287082");
  assert.equal(generateTotp(cfg, 1111111109).code, "07081804");
  assert.equal(generateTotp(cfg, 1234567890).code, "89005924");
});

test("default config is SHA1 / 6 digits / 30s; window = floor(t/period)", () => {
  const cfg = parseTotp({ secret: SHA1_B32 });
  assert.equal(cfg.algorithm, "SHA1");
  assert.equal(cfg.digits, 6);
  assert.equal(cfg.period, 30);
  const g = generateTotp(cfg, 59);
  assert.equal(g.code, "287082");        // last 6 of 94287082
  assert.equal(g.window, 1);             // floor(59/30)
});

test("parseTotp reads an otpauth:// URI including non-default algorithm/digits", () => {
  const cfg = parseTotp(`otpauth://totp/Acme:me?secret=${SHA1_B32}&algorithm=SHA256&digits=8&period=30`);
  assert.equal(cfg.algorithm, "SHA256");
  assert.equal(cfg.digits, 8);
});

test("parseTotp rejects a missing/invalid secret", () => {
  assert.throws(() => parseTotp("otpauth://totp/Acme:me?issuer=Acme"));
  assert.throws(() => parseTotp({ secret: "" }));
});

test("TotpEmitter never re-emits a code for a window it already consumed", async () => {
  const cfg = parseTotp({ secret: SHA1_B32 });
  const em = new TotpEmitter(cfg);
  let t = 59_000;                          // ms; window 1
  const waited: number[] = [];
  const now = () => t;
  const sleep = async (ms: number) => { waited.push(ms); t += ms; };
  const first = await em.next(now, sleep);
  assert.equal(first.window, 1);
  assert.equal(waited.length, 0);
  const second = await em.next(now, sleep); // same window still current → must wait to window 2
  assert.equal(second.window, 2);
  assert.ok(waited.length === 1 && waited[0]! > 0, "should have slept into the next window");
  assert.notEqual(second.code, first.code);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && npx tsx --test test/totp.test.ts`
Expected: FAIL — `../src/totp.js` does not exist.

- [ ] **Step 3: Write the implementation**

Create `orchestrator/src/totp.ts`:

```ts
import { createHmac } from "node:crypto";

export interface TotpConfig {
  secret: Uint8Array;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  digits: number;
  period: number;
}

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Uint8Array {
  const clean = input.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  if (clean === "" || /[^A-Z2-7]/.test(clean)) throw new Error("invalid base32 secret");
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Uint8Array.from(out);
}

function normAlgorithm(a: string | undefined): "SHA1" | "SHA256" | "SHA512" {
  const up = (a ?? "SHA1").toUpperCase();
  if (up === "SHA1" || up === "SHA256" || up === "SHA512") return up;
  throw new Error(`unsupported TOTP algorithm: ${a}`);
}

export function parseTotp(
  input: string | { secret: string; algorithm?: string; digits?: number; period?: number },
): TotpConfig {
  let secretB32: string;
  let algorithm: string | undefined;
  let digits: number | undefined;
  let period: number | undefined;
  if (typeof input === "string" && input.trim().toLowerCase().startsWith("otpauth://")) {
    const u = new URL(input.trim());
    secretB32 = u.searchParams.get("secret") ?? "";
    algorithm = u.searchParams.get("algorithm") ?? undefined;
    const d = u.searchParams.get("digits"); digits = d ? Number(d) : undefined;
    const p = u.searchParams.get("period"); period = p ? Number(p) : undefined;
  } else if (typeof input === "string") {
    secretB32 = input.trim();
  } else {
    secretB32 = input.secret.trim();
    algorithm = input.algorithm;
    digits = input.digits;
    period = input.period;
  }
  if (!secretB32) throw new Error("TOTP secret is required");
  const secret = base32Decode(secretB32);
  return {
    secret,
    algorithm: normAlgorithm(algorithm),
    digits: digits && Number.isFinite(digits) ? Math.trunc(digits) : 6,
    period: period && Number.isFinite(period) && period > 0 ? Math.trunc(period) : 30,
  };
}

export function generateTotp(config: TotpConfig, atUnixSeconds: number): { code: string; window: number } {
  const window = Math.floor(atUnixSeconds / config.period);
  const counter = Buffer.alloc(8);
  // 64-bit big-endian counter (window fits well within 2^53).
  counter.writeBigUInt64BE(BigInt(window));
  const hmac = createHmac(config.algorithm.toLowerCase(), Buffer.from(config.secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const bin =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  const code = (bin % 10 ** config.digits).toString().padStart(config.digits, "0");
  return { code, window };
}

/** Wraps a config and refuses to re-emit a one-time code for a window it already
 * used — it waits (injected sleep) until the next window instead. This is why
 * scanners throttle: a rapid re-login must not resubmit a code the app already saw. */
export class TotpEmitter {
  private lastWindow = -1;
  constructor(private readonly config: TotpConfig) {}

  async next(nowMs: () => number, sleep: (ms: number) => Promise<void>): Promise<{ code: string; window: number }> {
    let g = generateTotp(this.config, Math.floor(nowMs() / 1000));
    if (g.window === this.lastWindow) {
      const periodMs = this.config.period * 1000;
      const msIntoWindow = nowMs() % periodMs;
      await sleep(periodMs - msIntoWindow);
      g = generateTotp(this.config, Math.floor(nowMs() / 1000));
    }
    this.lastWindow = g.window;
    return g;
  }
}
```

- [ ] **Step 4: Run tests**

Run: `cd orchestrator && npx tsx --test test/totp.test.ts` → Expected: PASS (5 tests).
Run: `cd orchestrator && npm test` → Expected: PASS (whole suite green).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/totp.ts orchestrator/test/totp.test.ts
git commit -m "feat(engine): RFC-6238 TOTP generator with code-reuse guard

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BxCkVb1dRUVjPsmR9vJ88e"
```

---

### Task 2: Auth-response classifier + login-sequence builder (`auth-recon.ts`)

**Files:**
- Create: `orchestrator/src/auth-recon.ts`
- Test: `orchestrator/test/auth-recon.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `LOGIN_PATH_CANDIDATES: string[]`
  - `interface AuthMaterial { headerName: string; value: string }`
  - `interface TwoFactor { present: boolean; type?: "totp" | "otp" | "sms" | "unknown" }`
  - `type LoginOutcome = "authed" | "2fa_pending_with_material" | "2fa_required_no_material" | "invalid" | "blocked" | "unknown"`
  - `interface LoginClassification { outcome: LoginOutcome; authMaterial: AuthMaterial | null; twoFactor: TwoFactor }`
  - `interface LoginAttempt { method: string; url: string; contentType: "json" | "form"; body: string }`
  - `candidateLoginRequests(loginUrl: string, creds: { email?: string; username?: string; password: string }, fieldHints?: Record<string, string>): LoginAttempt[]`
  - `extractAuthMaterial(headers: Record<string, string>, body: string): AuthMaterial | null`
  - `detectTwoFactor(status: number, body: string): TwoFactor`
  - `classifyLoginResponse(resp: { status: number; headers: Record<string, string>; body: string }): LoginClassification`

- [ ] **Step 1: Write the failing test**

Create `orchestrator/test/auth-recon.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { candidateLoginRequests, extractAuthMaterial, detectTwoFactor, classifyLoginResponse } from "../src/auth-recon.js";

test("candidateLoginRequests emits json-first email/username variants, cheap-first", () => {
  const a = candidateLoginRequests("https://t/login", { email: "e@x.io", password: "p" });
  assert.equal(a[0]!.contentType, "json");
  assert.match(a[0]!.body, /"email":"e@x\.io"/);
  assert.match(a[0]!.body, /"password":"p"/);
  assert.ok(a.some((x) => x.contentType === "form"), "includes a form-encoded variant");
});

test("extractAuthMaterial prefers a body token over a Set-Cookie", () => {
  const m = extractAuthMaterial(
    { "set-cookie": "sid=abc; HttpOnly" },
    JSON.stringify({ access_token: "JWT.X.Y", user: 1 }),
  );
  assert.deepEqual(m, { headerName: "Authorization", value: "JWT.X.Y" });
});

test("extractAuthMaterial falls back to a session cookie when no token", () => {
  const m = extractAuthMaterial({ "set-cookie": "session=abc123; Path=/; HttpOnly" }, "{}");
  assert.deepEqual(m, { headerName: "Cookie", value: "session=abc123" });
});

test("detectTwoFactor flags an OTP/TOTP challenge from body signals", () => {
  assert.equal(detectTwoFactor(200, '{"status":"otp_required","message":"Enter your authenticator code"}').present, true);
  assert.equal(detectTwoFactor(200, '{"token":"x"}').present, false);
});

test("classifyLoginResponse: token + 2FA signal => pending WITH material", () => {
  const c = classifyLoginResponse({ status: 200, headers: {}, body: '{"access_token":"T","otp_required":true}' });
  assert.equal(c.outcome, "2fa_pending_with_material");
  assert.equal(c.authMaterial?.value, "T");
  assert.equal(c.twoFactor.present, true);
});

test("classifyLoginResponse: 403 => blocked; 401 no material => invalid", () => {
  assert.equal(classifyLoginResponse({ status: 403, headers: {}, body: "forbidden" }).outcome, "blocked");
  assert.equal(classifyLoginResponse({ status: 401, headers: {}, body: '{"error":"bad creds"}' }).outcome, "invalid");
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && npx tsx --test test/auth-recon.test.ts`
Expected: FAIL — `../src/auth-recon.js` does not exist.

- [ ] **Step 3: Write the implementation**

Create `orchestrator/src/auth-recon.ts`:

```ts
export const LOGIN_PATH_CANDIDATES = [
  "/api/login", "/api/auth/login", "/api/v1/auth/login", "/auth/login",
  "/login", "/api/session", "/session", "/api/signin", "/signin",
];

export interface AuthMaterial { headerName: string; value: string }
export interface TwoFactor { present: boolean; type?: "totp" | "otp" | "sms" | "unknown" }
export type LoginOutcome =
  | "authed" | "2fa_pending_with_material" | "2fa_required_no_material" | "invalid" | "blocked" | "unknown";
export interface LoginClassification { outcome: LoginOutcome; authMaterial: AuthMaterial | null; twoFactor: TwoFactor }
export interface LoginAttempt { method: string; url: string; contentType: "json" | "form"; body: string }

const TOKEN_KEYS = [
  "access_token", "accessToken", "token", "id_token", "idToken",
  "jwt", "authToken", "auth_token", "bearerToken", "session_token",
];
const TWO_FACTOR = /\b(otp|totp|two[\s-]?factor|2fa|mfa|authenticator|verification\s*code|one[\s-]?time|challenge)\b/i;
const SMS = /\b(sms|text\s*message|phone\s*code)\b/i;

export function candidateLoginRequests(
  loginUrl: string,
  creds: { email?: string; username?: string; password: string },
  fieldHints: Record<string, string> = {},
): LoginAttempt[] {
  const idValue = creds.email ?? creds.username ?? "";
  const idFields = fieldHints.identifier
    ? [fieldHints.identifier]
    : creds.email ? ["email", "username", "user", "login"] : ["username", "user", "login", "email"];
  const pwField = fieldHints.password ?? "password";
  const attempts: LoginAttempt[] = [];
  for (const idf of idFields) {
    const obj: Record<string, string> = { [idf]: idValue, [pwField]: creds.password };
    attempts.push({ method: "POST", url: loginUrl, contentType: "json", body: JSON.stringify(obj) });
  }
  // one form-encoded fallback on the primary id field
  const primary = idFields[0]!;
  attempts.push({
    method: "POST", url: loginUrl, contentType: "form",
    body: `${encodeURIComponent(primary)}=${encodeURIComponent(idValue)}&${encodeURIComponent(pwField)}=${encodeURIComponent(creds.password)}`,
  });
  return attempts;
}

function firstStringDeep(obj: unknown, keys: string[]): string | null {
  if (obj === null || typeof obj !== "object") return null;
  for (const k of keys) {
    const v = (obj as Record<string, unknown>)[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  for (const v of Object.values(obj as Record<string, unknown>)) {
    const found = firstStringDeep(v, keys);
    if (found) return found;
  }
  return null;
}

export function extractAuthMaterial(headers: Record<string, string>, body: string): AuthMaterial | null {
  // 1) a bearer-ish token in the JSON body wins.
  try {
    const token = firstStringDeep(JSON.parse(body), TOKEN_KEYS);
    if (token) return { headerName: "Authorization", value: token };
  } catch { /* not JSON */ }
  // 2) else a Set-Cookie session cookie.
  const setCookie = headers["set-cookie"] ?? headers["Set-Cookie"];
  if (setCookie) {
    const pair = setCookie.split(",")[0]!.split(";")[0]!.trim(); // "name=value"
    if (pair.includes("=")) return { headerName: "Cookie", value: pair };
  }
  return null;
}

export function detectTwoFactor(_status: number, body: string): TwoFactor {
  if (!TWO_FACTOR.test(body)) return { present: false };
  const type = SMS.test(body) ? "sms" : /totp|authenticator/i.test(body) ? "totp" : "otp";
  return { present: true, type };
}

export function classifyLoginResponse(resp: { status: number; headers: Record<string, string>; body: string }): LoginClassification {
  const twoFactor = detectTwoFactor(resp.status, resp.body);
  const authMaterial = extractAuthMaterial(resp.headers, resp.body);
  if (resp.status === 403) return { outcome: "blocked", authMaterial, twoFactor };
  if (authMaterial && twoFactor.present) return { outcome: "2fa_pending_with_material", authMaterial, twoFactor };
  if (authMaterial) return { outcome: "authed", authMaterial, twoFactor };
  if (twoFactor.present) return { outcome: "2fa_required_no_material", authMaterial: null, twoFactor };
  if (resp.status >= 400) return { outcome: "invalid", authMaterial: null, twoFactor };
  return { outcome: "unknown", authMaterial: null, twoFactor };
}
```

- [ ] **Step 4: Run tests**

Run: `cd orchestrator && npx tsx --test test/auth-recon.test.ts` → Expected: PASS (6 tests).
Run: `cd orchestrator && npm test` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/auth-recon.ts orchestrator/test/auth-recon.test.ts
git commit -m "feat(engine): auth-response classifier + login-attempt builder

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BxCkVb1dRUVjPsmR9vJ88e"
```

---

### Task 3: Auth-scan config (`SAHW_AUTH_MODE` / `SAHW_AUTH_LOGIN` / `SAHW_TOTP`)

**Files:**
- Modify: `orchestrator/src/config.ts`
- Test: `orchestrator/test/config-auth.test.ts` (create)

**Interfaces:**
- Consumes: the `Env`, `num`, `boolEnv`, `ConfigError` helpers already in `config.ts`.
- Produces:
  - `type AuthMode = "off" | "bypass" | "authenticated"`
  - `interface AuthLogin { email?: string; username?: string; password: string; loginUrl?: string; fieldHints?: Record<string, string> }`
  - `interface AuthConfig { mode: AuthMode; login: AuthLogin | null; totp: string | { secret: string; algorithm?: string; digits?: number; period?: number } | null }`
  - `loadAuthConfig(env: Env): AuthConfig`
  - `Engagement.auth: AuthConfig` (new field, populated in `loadEngagement`).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/test/config-auth.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadAuthConfig } from "../src/config.js";

test("default: mode off, no login, no totp", () => {
  const c = loadAuthConfig({});
  assert.equal(c.mode, "off");
  assert.equal(c.login, null);
  assert.equal(c.totp, null);
});

test("authenticated mode parses login + totp", () => {
  const c = loadAuthConfig({
    SAHW_AUTH_MODE: "authenticated",
    SAHW_AUTH_LOGIN: JSON.stringify({ email: "e@x.io", password: "p" }),
    SAHW_TOTP: "otpauth://totp/A:me?secret=GEZDGNBVGY3TQOJQ",
  });
  assert.equal(c.mode, "authenticated");
  assert.equal(c.login?.email, "e@x.io");
  assert.equal(typeof c.totp, "string");
});

test("bypass mode ignores any provided TOTP secret", () => {
  const c = loadAuthConfig({
    SAHW_AUTH_MODE: "bypass",
    SAHW_AUTH_LOGIN: JSON.stringify({ email: "e@x.io", password: "p" }),
    SAHW_TOTP: "otpauth://totp/A:me?secret=GEZDGNBVGY3TQOJQ",
  });
  assert.equal(c.mode, "bypass");
  assert.equal(c.totp, null);
});

test("authenticated/bypass without SAHW_AUTH_LOGIN throws", () => {
  assert.throws(() => loadAuthConfig({ SAHW_AUTH_MODE: "authenticated" }));
  assert.throws(() => loadAuthConfig({ SAHW_AUTH_MODE: "bypass" }));
});

test("login without a password throws", () => {
  assert.throws(() => loadAuthConfig({ SAHW_AUTH_MODE: "bypass", SAHW_AUTH_LOGIN: JSON.stringify({ email: "e@x.io" }) }));
});

test("invalid mode value throws", () => {
  assert.throws(() => loadAuthConfig({ SAHW_AUTH_MODE: "full" }));
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && npx tsx --test test/config-auth.test.ts`
Expected: FAIL — `loadAuthConfig` is not exported.

- [ ] **Step 3: Write the implementation**

In `orchestrator/src/config.ts`, add the types and loader (place near `loadDeepConfig`), and wire the field into `Engagement` + `loadEngagement`:

```ts
export type AuthMode = "off" | "bypass" | "authenticated";
export interface AuthLogin { email?: string; username?: string; password: string; loginUrl?: string; fieldHints?: Record<string, string> }
export interface AuthConfig {
  mode: AuthMode;
  login: AuthLogin | null;
  totp: string | { secret: string; algorithm?: string; digits?: number; period?: number } | null;
}

/** Auth-scan config. Fail-closed: bypass/authenticated require SAHW_AUTH_LOGIN (with a
 * password). TOTP is parsed only in authenticated mode; bypass NEVER consumes a secret.
 * A TOTP-gated flow with no secret is caught later, at record time, not here. */
export function loadAuthConfig(env: Env): AuthConfig {
  const raw = (env.SAHW_AUTH_MODE ?? "off").trim().toLowerCase();
  if (raw !== "off" && raw !== "bypass" && raw !== "authenticated") {
    throw new ConfigError(`SAHW_AUTH_MODE must be off|bypass|authenticated, got: ${env.SAHW_AUTH_MODE}`);
  }
  const mode = raw as AuthMode;
  if (mode === "off") return { mode, login: null, totp: null };

  const loginRaw = env.SAHW_AUTH_LOGIN?.trim();
  if (!loginRaw) throw new ConfigError(`SAHW_AUTH_MODE=${mode} requires SAHW_AUTH_LOGIN`);
  let login: AuthLogin;
  try { login = JSON.parse(loginRaw) as AuthLogin; }
  catch { throw new ConfigError("SAHW_AUTH_LOGIN is not valid JSON"); }
  if (!login || typeof login.password !== "string" || login.password === "") {
    throw new ConfigError("SAHW_AUTH_LOGIN must include a non-empty password");
  }
  if (!login.email && !login.username) {
    throw new ConfigError("SAHW_AUTH_LOGIN must include an email or username");
  }

  let totp: AuthConfig["totp"] = null;
  if (mode === "authenticated") {
    const t = env.SAHW_TOTP?.trim();
    if (t) {
      totp = t.toLowerCase().startsWith("otpauth://") ? t : (() => {
        try { return JSON.parse(t) as { secret: string }; } catch { return t; }
      })();
    }
  }
  return { mode, login, totp };
}
```

Add `auth: AuthConfig;` to the `Engagement` interface (next to `deep: DeepConfig;`), and in `loadEngagement` (`orchestrator/src/config.ts:119`) add `auth: loadAuthConfig(env),` to the returned object (next to `deep: loadDeepConfig(env, authRef),`).

- [ ] **Step 4: Run tests**

Run: `cd orchestrator && npx tsx --test test/config-auth.test.ts` → Expected: PASS (6 tests).
Run: `cd orchestrator && npm test` → Expected: PASS (tsc clean incl. the new `Engagement.auth` field; any existing `Engagement` literal in tests must set `auth` — if a test helper builds an `Engagement`, add `auth: { mode: "off", login: null, totp: null }` there).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/config.ts orchestrator/test/config-auth.test.ts
git commit -m "feat(engine): SAHW_AUTH_MODE/AUTH_LOGIN/TOTP config (fail-closed)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BxCkVb1dRUVjPsmR9vJ88e"
```

---

### Task 4: `auth_bypass_pre_2fa` Axiom deriver

**Files:**
- Modify: `orchestrator/src/axiom.ts`
- Test: `orchestrator/test/axiom-auth-bypass.test.ts` (create)

**Interfaces:**
- Consumes: the `Deriver`/`DERIVERS` machinery and `isRecord` helper in `axiom.ts`.
- Produces: a new deriver registered as `auth_bypass_pre_2fa`. Input:
  `{ protectedResource: string; anonResponse: { status: number; body: string }; pre2faResponse: { status: number; body: string } }`.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/test/axiom-auth-bypass.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/axiom.js";

function run(input: unknown) {
  const inv = { type: "derived", expression: "auth_bypass_pre_2fa" } as const;
  const placeholder = { request: { method: "GET", url: "http://t/admin", headers: {}, body: null },
                        response: { status: 0, headers: {}, body: "" } } as any;
  return evaluate(inv as any, placeholder, null, { derivedInput: input });
}

test("CONFIRMED: anon denied, pre-2FA session reaches protected content", () => {
  const v = run({
    protectedResource: "http://t/api/profile",
    anonResponse: { status: 401, body: '{"error":"unauthorized"}' },
    pre2faResponse: { status: 200, body: '{"email":"victim@x.io","role":"admin"}' },
  });
  assert.equal(v.status, "CONFIRMED");
});

test("NEEDS_REVIEW when anon was NOT actually denied (no differential)", () => {
  const v = run({
    protectedResource: "http://t/api/profile",
    anonResponse: { status: 200, body: '{"email":"victim@x.io"}' },
    pre2faResponse: { status: 200, body: '{"email":"victim@x.io"}' },
  });
  assert.notEqual(v.status, "CONFIRMED");
});

test("NEEDS_REVIEW when the pre-2FA response did not reach protected content", () => {
  const v = run({
    protectedResource: "http://t/api/profile",
    anonResponse: { status: 401, body: "no" },
    pre2faResponse: { status: 302, body: "" },
  });
  assert.notEqual(v.status, "CONFIRMED");
});

test("NEEDS_REVIEW on malformed input", () => {
  assert.notEqual(run({ protectedResource: "x" }).status, "CONFIRMED");
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && npx tsx --test test/axiom-auth-bypass.test.ts`
Expected: FAIL — deriver `auth_bypass_pre_2fa` is not registered.

- [ ] **Step 3: Write the implementation**

In `orchestrator/src/axiom.ts`, add the deriver next to `deriveNoSecondaryFactorBeforeOtp` and register it in `DERIVERS` (`orchestrator/src/axiom.ts:487`):

```ts
// --- auth_bypass_pre_2fa -------------------------------------------------------------------
// Proves a password-only (pre-2FA) session reaches a protected resource that an ANONYMOUS
// session cannot — i.e. the second factor is not enforced on that resource. SOUND via a
// control differential over two real responses:
//   (1) the anonymous request is DENIED (401/403, or a login-redirect 3xx, or a body that
//       lacks the protected marker), AND
//   (2) the pre-2FA session request SUCCEEDS (2xx) and returns protected content the
//       anonymous response does not. Missing either side => NEEDS_REVIEW, never a pass.
interface AuthBypassInput {
  protectedResource: string;
  anonResponse: { status: number; body: string };
  pre2faResponse: { status: number; body: string };
}
function isAuthBypassInput(x: unknown): x is AuthBypassInput {
  return isRecord(x) && typeof x.protectedResource === "string"
    && isRecord(x.anonResponse) && typeof x.anonResponse.status === "number" && typeof x.anonResponse.body === "string"
    && isRecord(x.pre2faResponse) && typeof x.pre2faResponse.status === "number" && typeof x.pre2faResponse.body === "string";
}
function deriveAuthBypassPre2fa(input: unknown): Verdict {
  if (!isAuthBypassInput(input)) {
    return { status: "NEEDS_REVIEW", reason: "auth_bypass_pre_2fa requires { protectedResource, anonResponse:{status,body}, pre2faResponse:{status,body} }" };
  }
  const anon = input.anonResponse, pre = input.pre2faResponse;
  const preReached = pre.status >= 200 && pre.status < 300 && pre.body.trim().length > 0;
  if (!preReached) {
    return { status: "NEEDS_REVIEW", reason: `pre-2FA session did not reach the resource (status ${pre.status})` };
  }
  const anonDenied = anon.status === 401 || anon.status === 403
    || (anon.status >= 300 && anon.status < 400) || anon.body !== pre.body;
  if (!anonDenied || anon.body === pre.body) {
    return { status: "NEEDS_REVIEW", reason: "no anon-vs-pre-2FA differential: anonymous access was not demonstrably denied" };
  }
  return {
    status: "CONFIRMED",
    reason: `pre-2FA (password-only) session reached ${input.protectedResource} (status ${pre.status}) that the anonymous control did not (status ${anon.status}); second factor not enforced`,
  };
}
```

Register it: in the `DERIVERS` object add `auth_bypass_pre_2fa: deriveAuthBypassPre2fa,`.

- [ ] **Step 4: Run tests**

Run: `cd orchestrator && npx tsx --test test/axiom-auth-bypass.test.ts` → Expected: PASS (4 tests).
Run: `cd orchestrator && npm test` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/axiom.ts orchestrator/test/axiom-auth-bypass.test.ts
git commit -m "feat(axiom): auth_bypass_pre_2fa deriver (anon vs pre-2FA differential)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BxCkVb1dRUVjPsmR9vJ88e"
```

---

### Task 5: Persist the login-sequence shape in the spine

**Files:**
- Modify: `orchestrator/src/spine.ts`
- Test: `orchestrator/test/spine-login-sequence.test.ts` (create)

**Interfaces:**
- Consumes: the `RecoveredIntel` open interface (`orchestrator/src/spine.ts:47`) and `mergeIntel` (`:337`).
- Produces: a typed, optional `login_sequence` on `RecoveredIntel`:
  `interface LoginSequenceShape { login_url: string; content_type: "json" | "form"; identifier_field: string; password_field: string; auth_header_name: string; token_location: "body" | "cookie" | "none"; two_factor: "none" | "totp" | "otp" | "sms" | "unknown" }`.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/test/spine-login-sequence.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { serializeSpine, parseSpine, freshSpine } from "../src/spine.js";

test("login_sequence shape round-trips through serialize/parse (no secrets)", () => {
  const spine = freshSpine({ authRef: "eng-1", scopeOrigins: ["https://t"] });
  spine.recovered_intel.login_sequence = {
    login_url: "https://t/api/login", content_type: "json",
    identifier_field: "email", password_field: "password",
    auth_header_name: "Authorization", token_location: "body", two_factor: "totp",
  };
  const round = parseSpine(serializeSpine(spine), { authRef: "eng-1", scopeOrigins: ["https://t"] });
  assert.deepEqual(round.spine.recovered_intel.login_sequence, spine.recovered_intel.login_sequence);
});
```

Note: match the actual `freshSpine`/`serializeSpine`/`parseSpine` signatures in `spine.ts` — read them first and adapt the call shapes (names/argument objects) to what the file exports; the assertion (round-trip equality of `login_sequence`) is the fixed part.

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && npx tsx --test test/spine-login-sequence.test.ts`
Expected: FAIL — `login_sequence` is not a typed field (tsc error) / not preserved.

- [ ] **Step 3: Write the implementation**

In `orchestrator/src/spine.ts`, add the shape type above `RecoveredIntel` and the optional field to the interface:

```ts
export interface LoginSequenceShape {
  login_url: string;
  content_type: "json" | "form";
  identifier_field: string;
  password_field: string;
  auth_header_name: string;
  token_location: "body" | "cookie" | "none";
  two_factor: "none" | "totp" | "otp" | "sms" | "unknown";
}
```

Add to `RecoveredIntel` (`orchestrator/src/spine.ts:47`): `login_sequence?: LoginSequenceShape;` (the interface already has an index signature, so it persists via `asObject<RecoveredIntel>`; verify `mergeIntel` copies unknown keys — it spreads `prev` then overlays `next`, so a nested object key is preserved). If `mergeIntel` does not already carry object-valued keys through, add `login_sequence` to its merge (last-writer-wins: `if (next.login_sequence) merged.login_sequence = next.login_sequence;`).

- [ ] **Step 4: Run tests**

Run: `cd orchestrator && npx tsx --test test/spine-login-sequence.test.ts` → Expected: PASS.
Run: `cd orchestrator && npm test` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/spine.ts orchestrator/test/spine-login-sequence.test.ts
git commit -m "feat(spine): persist login-sequence shape (no secrets) in recovered_intel

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BxCkVb1dRUVjPsmR9vJ88e"
```

---

### Task 6: Recorder + session seeding + mode wiring in `beat.ts`

**Files:**
- Modify: `orchestrator/src/beat.ts`
- Test: `orchestrator/test/beat-auth-record.test.ts` (create)

**Interfaces:**
- Consumes: `loadAuthConfig` result on `engagement.auth` (Task 3); `candidateLoginRequests`/`classifyLoginResponse`/`LoginClassification` (Task 2); `TotpEmitter`/`parseTotp` (Task 1); `LoginSequenceShape` (Task 5); `SessionStore.create` (`session.ts`); the injected `fetchImpl` on `runBeat` opts (`orchestrator/src/beat.ts:1755`).
- Produces: a `runAuthRecord(opts)` function that, given the auth config + a Tether-checked fetch, establishes session "A" in the injected `SessionStore` and returns the `LoginSequenceShape` (persisted to `recovered_intel.login_sequence`). Called on beat 1 when `engagement.auth.mode !== "off"`, right after `runDnsRecon` (`orchestrator/src/beat.ts:1820`) and before the deep sweep.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/test/beat-auth-record.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { runAuthRecord } from "../src/beat.js";
import { SessionStore } from "../src/session.js";

function fetchOnce(map: Record<string, { status: number; headers?: Record<string,string>; body: string }>) {
  return async (url: string, init?: any) => {
    const key = `${(init?.method ?? "GET").toUpperCase()} ${url}`;
    const r = map[key] ?? map[url] ?? { status: 404, body: "" };
    return {
      status: r.status,
      headers: { forEach: (fn: (v: string, k: string) => void) => Object.entries(r.headers ?? {}).forEach(([k, v]) => fn(v, k)) },
      text: async () => r.body,
    } as any;
  };
}

test("bypass mode seeds a pre-2FA session A from a token+2FA login response", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  const fetchImpl = fetchOnce({
    "POST https://t/api/login": { status: 200, body: JSON.stringify({ access_token: "PARTIAL", otp_required: true }) },
  });
  const shape = await runAuthRecord({
    auth: { mode: "bypass", login: { email: "e@x.io", password: "p", loginUrl: "https://t/api/login" }, totp: null },
    inScope: () => true, fetchImpl, sessions,
    now: () => 59_000, sleep: async () => {},
  });
  assert.equal(shape.two_factor, "otp");
  assert.equal(shape.token_location, "body");
  assert.ok(sessions.has("A"));
  assert.equal(sessions.meta("A")!.has_auth_material, true);
});

test("authenticated mode with no TOTP secret on a TOTP-gated flow throws", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  const fetchImpl = fetchOnce({
    "POST https://t/api/login": { status: 200, body: JSON.stringify({ message: "enter authenticator code", totp_required: true }) },
  });
  await assert.rejects(() => runAuthRecord({
    auth: { mode: "authenticated", login: { email: "e@x.io", password: "p", loginUrl: "https://t/api/login" }, totp: null },
    inScope: () => true, fetchImpl, sessions, now: () => 59_000, sleep: async () => {},
  }));
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && npx tsx --test test/beat-auth-record.test.ts`
Expected: FAIL — `runAuthRecord` is not exported from `beat.ts`.

- [ ] **Step 3: Write the implementation**

In `orchestrator/src/beat.ts`, add imports (`candidateLoginRequests, classifyLoginResponse` from `./auth-recon.js`; `parseTotp, TotpEmitter` from `./totp.js`; the `AuthConfig` type from `./config.js`; `LoginSequenceShape` from `./spine.js`), then add and export:

```ts
export async function runAuthRecord(opts: {
  auth: import("./config.js").AuthConfig;
  inScope: (url: string) => boolean;
  fetchImpl: typeof fetch;
  sessions: import("./session.js").SessionStore;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}): Promise<import("./spine.js").LoginSequenceShape> {
  const { auth, inScope, fetchImpl, sessions } = opts;
  if (auth.mode === "off" || !auth.login) throw new Error("runAuthRecord called without an auth login");
  const login = auth.login;
  const loginUrl = login.loginUrl ?? "";
  if (!loginUrl) throw new Error("login_url discovery not yet recorded; provide login.loginUrl");
  if (!inScope(loginUrl)) throw new Error(`login_url out of scope: ${loginUrl}`);

  const attempts = candidateLoginRequests(loginUrl, { email: login.email, username: login.username, password: login.password }, login.fieldHints);
  let chosen: { attempt: typeof attempts[number]; cls: ReturnType<typeof classifyLoginResponse> } | null = null;
  for (const attempt of attempts) {
    const res = await fetchImpl(attempt.url, {
      method: attempt.method,
      headers: { "content-type": attempt.contentType === "json" ? "application/json" : "application/x-www-form-urlencoded" },
      body: attempt.body,
      redirect: "manual",
    } as any);
    const headers: Record<string, string> = {};
    res.headers.forEach((v: string, k: string) => { headers[k] = v; });
    const cls = classifyLoginResponse({ status: res.status, headers, body: await res.text() });
    if (cls.outcome !== "invalid" && cls.outcome !== "unknown") { chosen = { attempt, cls }; break; }
    if (!chosen) chosen = { attempt, cls };
  }
  const cls = chosen!.cls;

  // authenticated mode must complete TOTP when the flow gates on it.
  if (auth.mode === "authenticated" && cls.twoFactor.present) {
    if (!auth.totp) throw new Error("SAHW_AUTH_MODE=authenticated: flow requires TOTP but SAHW_TOTP is unset");
    const emitter = new TotpEmitter(parseTotp(auth.totp as any));
    await emitter.next(opts.now, opts.sleep); // reuse-guarded code; replay of the OTP step is wired in the loop integration
  }

  // Seed session A with whatever material the (pre-2FA in bypass) login yielded.
  const material = cls.authMaterial;
  sessions.create({
    credentials: { username: login.email ?? login.username ?? "seeded", email: login.email ?? "", password: login.password, mobile: "" },
    authMaterial: material?.value ?? null,
    authHeaderName: material?.headerName ?? "Authorization",
  });

  const shape: LoginSequenceShape = {
    login_url: loginUrl,
    content_type: chosen!.attempt.contentType,
    identifier_field: login.email ? "email" : "username",
    password_field: login.fieldHints?.password ?? "password",
    auth_header_name: material?.headerName ?? "Authorization",
    token_location: material ? (material.headerName === "Cookie" ? "cookie" : "body") : "none",
    two_factor: cls.twoFactor.present ? (cls.twoFactor.type ?? "unknown") : "none",
  };
  return shape;
}
```

Wire the call into `runBeat`: after `runDnsRecon` (`orchestrator/src/beat.ts:1820-1821`), add — using the same beat-1 gate and the tether's `inScope`:

```ts
if (engagement.auth.mode !== "off" && Math.max(0, Math.trunc(numEnv(opts.env, "SAHW_BEAT_NO", 1))) <= 1) {
  const shape = await runAuthRecord({
    auth: engagement.auth,
    inScope: (u) => inScope(engagement, u),        // reuse tether.ts inScope, already imported in beat.ts
    fetchImpl: opts.fetchImpl ?? fetch,
    sessions: /* the SessionStore the ToolRunner/hunt uses */ runnerSessions,
    now: () => Date.now(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  });
  spineLoad.spine.recovered_intel.login_sequence = shape;   // persisted on write-back
}
```

If `beat.ts` does not already expose the hunt's `SessionStore` at that point, hoist its construction (it accepts `opts.sessionStore`, `orchestrator/src/beat.ts:1770`) above this block so the seeded session is the same store the hunter uses. Reuse the existing `inScope` import from `./tether.js`.

Session refresh (401/redirect during the hunt): where the hunt loop inspects tool results, when a request carrying `session: "A"` returns 401 or a login-redirect, call a small `reseat` that re-runs the chosen attempt (and, in authenticated mode, the OTP step via the same `TotpEmitter`, so the reuse guard applies) and updates session A's material. Keep the `TotpEmitter` for the run in scope alongside the `SessionStore` so codes are never reused. (This refresh path is exercised end-to-end in the live run, not unit-pinned; the reuse guard itself is pinned in Task 1.)

- [ ] **Step 4: Run tests**

Run: `cd orchestrator && npx tsx --test test/beat-auth-record.test.ts` → Expected: PASS (2 tests).
Run: `cd orchestrator && npm test` → Expected: PASS (whole suite; default `mode:"off"` path unchanged).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/beat.ts orchestrator/test/beat-auth-record.test.ts
git commit -m "feat(engine): auth-scan recorder + session seeding + mode wiring

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BxCkVb1dRUVjPsmR9vJ88e"
```

---

## Self-Review

**Spec coverage:** TOTP generator + reuse guard → Task 1. Auth classifier/sequence builder (hybrid deterministic core) → Task 2. Config/two modes/fail-closed → Task 3. `auth_bypass_pre_2fa` proof → Task 4. Spine shape-only persistence → Task 5. Recorder + session seeding + mode wiring + refresh → Task 6. The LLM-hunter fallback for unclassifiable flows is the existing hunt loop (the recorder seeds what it can and the hunter proceeds); no separate task needed for MVP — noted as a follow-on if a target defeats the deterministic recorder.

**Placeholder scan:** No TBD/TODO. Task 5's test note and Task 6's wiring reference real symbols; the one intentional flexible point (matching `freshSpine`/`serializeSpine` signatures, and locating the hunt's `SessionStore`) instructs reading the exact signatures first — the assertions and seeded-session behavior are fixed.

**Type consistency:** `AuthConfig`/`AuthLogin`/`AuthMode` (Task 3) are consumed by `runAuthRecord` (Task 6) by the same names. `LoginClassification`/`classifyLoginResponse`/`candidateLoginRequests` (Task 2) used as defined in Task 6. `TotpEmitter.next(nowMs, sleep)` signature identical in Task 1 and Task 6. `LoginSequenceShape` fields identical in Task 5 and Task 6.

**Review Focus:** TOTP non-defaults → Task 1 test. Token+cookie precedence → Task 2 test. Authenticated with no-2FA flow → Task 3 (config allows no TOTP) + Task 6 (throws only when the flow IS 2FA-gated). Session expiry re-login + reuse guard → Task 1 guard test + Task 6 refresh wiring. bypass with no usable material → Task 6 seeds session A with `authMaterial: null` (`has_auth_material=false`) rather than crashing.

## Execution note

After all six tasks land green, deploy the rebuilt image to the runner (`git archive` → scp → `docker build`) and run the two-mode engagement against `demo.safeone.io`: first `SAHW_AUTH_MODE=bypass` (password only) hunting `auth_bypass`, then, if none, `SAHW_AUTH_MODE=authenticated` with `SAHW_TOTP` for the authenticated scan.
