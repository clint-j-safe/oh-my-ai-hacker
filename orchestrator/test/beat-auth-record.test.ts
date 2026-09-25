import { test } from "node:test";
import assert from "node:assert/strict";
import { runAuthRecord } from "../src/beat.js";
import { SessionStore } from "../src/session.js";

function fetchOnce(map: Record<string, { status: number; headers?: Record<string,string>; body: string }>): typeof fetch {
  return (async (url: string, init?: any) => {
    const key = `${(init?.method ?? "GET").toUpperCase()} ${url}`;
    const r = map[key] ?? map[url] ?? { status: 404, body: "" };
    return {
      status: r.status,
      headers: { forEach: (fn: (v: string, k: string) => void) => Object.entries(r.headers ?? {}).forEach(([k, v]) => fn(v, k)) },
      text: async () => r.body,
    } as any;
  }) as unknown as typeof fetch;
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

// --- Cognito provider wiring ---------------------------------------------------

// RFC 6238 Appendix B vector, same seed as test/totp.test.ts and test/auth-cognito.test.ts.
const COGNITO_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/** A router fake keyed on "<METHOD> <url>" (target-app fetches) or
 * "<METHOD> <url> <x-amz-target>" (Cognito calls), so a single fetchImpl can serve
 * both the target app's bundle(s) AND the Cognito IDP in one test. */
function routerFetch(
  handlers: Record<string, (init?: any) => { status: number; headers?: Record<string, string>; body: string }>,
): typeof fetch {
  return (async (url: string, init?: any) => {
    const method = (init?.method ?? "GET").toUpperCase();
    const target = (init?.headers as Record<string, string> | undefined)?.["x-amz-target"];
    const key = target ? `${method} ${url} ${target}` : `${method} ${url}`;
    const h = handlers[key];
    if (!h) throw new Error(`routerFetch: no handler for ${key}`);
    const r = h(init);
    return {
      status: r.status,
      headers: { forEach: (fn: (v: string, k: string) => void) => Object.entries(r.headers ?? {}).forEach(([k, v]) => fn(v, k)) },
      text: async () => r.body,
    } as any;
  }) as unknown as typeof fetch;
}

test("cognito provider (explicit config + custom header): seeds session A with the IdToken, bypassing inScope for the IDP host entirely", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  const IDP = "https://cognito-idp.us-east-1.amazonaws.com/";
  const fetchImpl = routerFetch({
    [`POST ${IDP} AWSCognitoIdentityProviderService.InitiateAuth`]: () => ({
      status: 200, body: JSON.stringify({ ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "sess-1" }),
    }),
    [`POST ${IDP} AWSCognitoIdentityProviderService.RespondToAuthChallenge`]: () => ({
      status: 200, body: JSON.stringify({ AuthenticationResult: { IdToken: "id-tok", AccessToken: "acc-tok" } }),
    }),
  });
  const shape = await runAuthRecord({
    auth: {
      mode: "authenticated",
      provider: "cognito",
      login: { email: "user@x.io", password: "pw" },
      totp: COGNITO_SEED,
      cognito: { region: "us-east-1", clientId: "cid" },
      authHeader: "x-custom-token",
    },
    // inScope DENIES EVERYTHING — proves the Cognito IDP calls never go through the
    // tether gate (they're an explicit auth-provider egress; see beat.ts's EGRESS
    // comment on runAuthRecord). If the implementation mistakenly routed the IDP
    // calls through inScope, this test would throw instead of succeeding.
    inScope: () => false,
    fetchImpl, sessions, now: () => 59_000, sleep: async () => {},
  });
  assert.equal(shape.auth_header_name, "x-custom-token");
  assert.equal(shape.two_factor, "totp");
  assert.ok(sessions.has("A"));
  assert.equal(sessions.meta("A")!.auth_header_name, "x-custom-token");
  assert.equal(sessions.meta("A")!.has_auth_material, true);
  assert.equal(sessions.authMaterialFor("A"), "id-tok");
});

test("cognito provider auto-fingerprinted from the target's own bundle; bundle fetches stay inScope, IDP calls bypass it", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  const IDP = "https://cognito-idp.us-east-1.amazonaws.com/";
  const fetchImpl = routerFetch({
    "GET https://t/": () => ({ status: 200, body: '<html><script src="/app.js"></script></html>' }),
    "GET https://t/app.js": () => ({
      status: 200,
      body: "var c={userPoolId:`us-east-1_Y4lomyxe9`,userPoolWebClientId:`4e4np8b76ra8uvf8ou2t6fmm9t`,region:`us-east-1`};",
    }),
    [`POST ${IDP} AWSCognitoIdentityProviderService.InitiateAuth`]: () => ({
      status: 200, body: JSON.stringify({ AuthenticationResult: { IdToken: "id-direct", AccessToken: "acc-direct" } }),
    }),
  });
  const shape = await runAuthRecord({
    auth: { mode: "bypass", login: { email: "user@x.io", password: "pw" }, totp: null }, // provider defaults to "auto"
    // Only the target origin is in scope — the Cognito IDP host is deliberately
    // excluded, proving the fingerprint's bundle fetches (target-app requests) go
    // through inScope while the subsequent Cognito calls do not.
    inScope: (u) => u.startsWith("https://t"),
    fetchImpl, sessions, now: () => 59_000, sleep: async () => {},
    scopeOrigin: "https://t",
  });
  assert.match(shape.login_url, /^cognito:\/\/us-east-1\/4e4np8b76ra8uvf8ou2t6fmm9t$/);
  assert.equal(shape.auth_header_name, "x-safe-id-token"); // default header
  assert.ok(sessions.has("A"));
  assert.equal(sessions.authMaterialFor("A"), "id-direct");
});

test("cognito provider: a runtime auth failure (wrong credentials) fails SOFT — no session seeded, beat proceeds, does not throw", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  const IDP = "https://cognito-idp.us-east-1.amazonaws.com/";
  const fetchImpl = routerFetch({
    [`POST ${IDP} AWSCognitoIdentityProviderService.InitiateAuth`]: () => ({
      status: 400, body: JSON.stringify({ __type: "NotAuthorizedException", message: "Incorrect username or password." }),
    }),
  });
  const shape = await runAuthRecord({
    auth: {
      mode: "authenticated",
      provider: "cognito",
      login: { email: "user@x.io", password: "wrong-password" },
      totp: null,
      cognito: { region: "us-east-1", clientId: "cid" },
    },
    inScope: () => false,
    fetchImpl, sessions, now: () => 59_000, sleep: async () => {},
  });
  assert.equal(shape.token_location, "none");
  assert.equal(shape.two_factor, "none");
  assert.equal(sessions.has("A"), false);
});

test("cognito provider: SOFTWARE_TOKEN_MFA with no totpSecret configured fails SOFT (a challenge this beat can't answer), not a throw", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  const IDP = "https://cognito-idp.us-east-1.amazonaws.com/";
  const fetchImpl = routerFetch({
    [`POST ${IDP} AWSCognitoIdentityProviderService.InitiateAuth`]: () => ({
      status: 200, body: JSON.stringify({ ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "sess-1" }),
    }),
  });
  const shape = await runAuthRecord({
    auth: { mode: "bypass", provider: "cognito", login: { email: "user@x.io", password: "pw" }, totp: null, cognito: { region: "us-east-1", clientId: "cid" } },
    inScope: () => true, fetchImpl, sessions, now: () => 59_000, sleep: async () => {},
  });
  assert.equal(shape.token_location, "none");
  assert.equal(sessions.has("A"), false);
});

test("cognito provider: an invalid (host-injection-shaped) region in an explicit SAHW_COGNITO throws — a genuine config error, NOT fail-soft", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  let fetchCalled = false;
  const fetchImpl = (async () => { fetchCalled = true; return { status: 200, headers: { forEach: () => {} }, text: async () => "{}" } as any; }) as unknown as typeof fetch;
  await assert.rejects(
    () => runAuthRecord({
      auth: { mode: "bypass", provider: "cognito", login: { email: "user@x.io", password: "pw" }, totp: null, cognito: { region: "evil.com/x", clientId: "cid" } },
      inScope: () => true, fetchImpl, sessions, now: () => 59_000, sleep: async () => {},
    }),
    /region/i,
  );
  assert.equal(fetchCalled, false, "an invalid region must be rejected before ANY network call, including to the (legitimate) target");
  assert.equal(sessions.has("A"), false);
});

test("cognito provider explicit with no config anywhere throws a clear error", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  await assert.rejects(
    () => runAuthRecord({
      auth: { mode: "bypass", provider: "cognito", login: { email: "user@x.io", password: "pw" }, totp: null },
      inScope: () => true, fetchImpl: fetchOnce({}), sessions, now: () => 59_000, sleep: async () => {},
    }),
    /SAHW_COGNITO|fingerprint/,
  );
});
