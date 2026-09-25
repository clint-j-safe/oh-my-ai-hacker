import { test } from "node:test";
import assert from "node:assert/strict";
import {
  cognitoCall, initiateAuth, respondSoftwareTokenMfa, associateSoftwareToken,
  verifySoftwareToken, respondMfaSetup, cognitoAuthenticate, type CognitoConfig,
} from "../src/auth-cognito.js";

// RFC 6238 Appendix B vector (also used by test/totp.test.ts): ASCII secret
// "12345678901234567890" = base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ. At t=59s,
// default (SHA1/6-digit/30s) generateTotp yields "287082" — deterministic, so
// the fakes below can assert the exact SOFTWARE_TOKEN_MFA_CODE/UserCode sent.
const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const CODE_AT_59 = "287082";
const CONFIG: CognitoConfig = { region: "us-east-1", clientId: "4e4np8b76ra8uvf8ou2t6fmm9t" };
const now = () => 59_000; // ms -> 59s, matching CODE_AT_59
const sleep = async () => {};

interface CapturedRequest { url: string; action: string; headers: Record<string, string>; body: any }

/** Injected-fetch fake keyed on the X-Amz-Target action, per the brief (Part D). Records
 * every request it sees so tests can assert on exactly what left the process. */
function fakeCognitoFetch(
  handlers: Record<string, (body: any) => { status: number; body: unknown }>,
  captured: CapturedRequest[] = [],
): typeof fetch {
  return (async (url: string, init?: any) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const target = headers["x-amz-target"] ?? "";
    const action = target.split(".")[1] ?? "";
    const body = init?.body ? JSON.parse(init.body as string) : {};
    captured.push({ url, action, headers, body });
    const handler = handlers[action];
    if (!handler) throw new Error(`fakeCognitoFetch: no handler registered for action ${action}`);
    const r = handler(body);
    return { status: r.status, text: async () => JSON.stringify(r.body) } as any;
  }) as unknown as typeof fetch;
}

test("cognitoCall sets x-amz-target + content-type application/x-amz-json-1.1, no SECRET_HASH", async () => {
  const captured: CapturedRequest[] = [];
  const fetchImpl = fakeCognitoFetch(
    { InitiateAuth: () => ({ status: 200, body: { ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "s1" } }) },
    captured,
  );
  await cognitoCall(CONFIG, "InitiateAuth", {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: CONFIG.clientId,
    AuthParameters: { USERNAME: "user@x.io", PASSWORD: "pw" },
  }, fetchImpl);
  assert.equal(captured.length, 1);
  const req = captured[0]!;
  assert.equal(req.url, "https://cognito-idp.us-east-1.amazonaws.com/");
  assert.equal(req.headers["x-amz-target"], "AWSCognitoIdentityProviderService.InitiateAuth");
  assert.equal(req.headers["content-type"], "application/x-amz-json-1.1");
  assert.equal(req.body.AuthParameters.SECRET_HASH, undefined);
  assert.ok(!("SECRET_HASH" in req.body.AuthParameters));
});

test("cognitoCall throws on a non-2xx response, carrying the error body", async () => {
  const fetchImpl = fakeCognitoFetch({
    InitiateAuth: () => ({ status: 400, body: { __type: "NotAuthorizedException", message: "Incorrect username or password." } }),
  });
  await assert.rejects(
    () => cognitoCall(CONFIG, "InitiateAuth", { AuthFlow: "USER_PASSWORD_AUTH", ClientId: CONFIG.clientId, AuthParameters: { USERNAME: "u", PASSWORD: "p" } }, fetchImpl),
    /NotAuthorizedException|400/,
  );
});

test("initiateAuth surfaces a SOFTWARE_TOKEN_MFA challenge; respondSoftwareTokenMfa with a known seed completes it (idToken extracted)", async () => {
  const captured: CapturedRequest[] = [];
  const fetchImpl = fakeCognitoFetch({
    InitiateAuth: (body) => {
      assert.equal(body.AuthFlow, "USER_PASSWORD_AUTH");
      assert.equal(body.AuthParameters.USERNAME, "user@x.io");
      assert.equal(body.AuthParameters.PASSWORD, "correct-horse");
      return { status: 200, body: { ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "sess-1", ChallengeParameters: { USER_ID_FOR_SRP: "user@x.io" } } };
    },
    RespondToAuthChallenge: (body) => {
      assert.equal(body.ChallengeName, "SOFTWARE_TOKEN_MFA");
      assert.equal(body.Session, "sess-1");
      assert.equal(body.ChallengeResponses.USERNAME, "user@x.io");
      assert.match(body.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE, /^\d{6}$/);
      assert.equal(body.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE, CODE_AT_59);
      return { status: 200, body: { AuthenticationResult: { IdToken: "id-tok", AccessToken: "acc-tok", RefreshToken: "ref-tok", ExpiresIn: 3600, TokenType: "Bearer" } } };
    },
  }, captured);

  const init = await initiateAuth(CONFIG, "user@x.io", "correct-horse", fetchImpl);
  assert.equal(init.challengeName, "SOFTWARE_TOKEN_MFA");
  assert.equal(init.session, "sess-1");
  assert.equal(init.tokens, undefined);

  const tokens = await respondSoftwareTokenMfa(CONFIG, "user@x.io", init.session!, CODE_AT_59, fetchImpl);
  assert.equal(tokens.idToken, "id-tok");
  assert.equal(tokens.accessToken, "acc-tok");
  assert.equal(tokens.refreshToken, "ref-tok");

  // Full high-level flow through cognitoAuthenticate, same fixture.
  const result = await cognitoAuthenticate({
    config: CONFIG, username: "user@x.io", password: "correct-horse", totpSecret: SEED,
    fetchImpl, now, sleep,
  });
  assert.equal(result.tokens.idToken, "id-tok");
  assert.equal(result.fetchedSeed, undefined);
});

test("MFA_SETUP challenge with enroll:true fetches+owns a new seed via AssociateSoftwareToken, verifies it, completes setup", async () => {
  const captured: CapturedRequest[] = [];
  const fetchImpl = fakeCognitoFetch({
    InitiateAuth: () => ({ status: 200, body: { ChallengeName: "MFA_SETUP", Session: "sess-setup" } }),
    AssociateSoftwareToken: (body) => {
      assert.equal(body.Session, "sess-setup");
      return { status: 200, body: { SecretCode: SEED, Session: "sess-assoc" } };
    },
    VerifySoftwareToken: (body) => {
      assert.equal(body.Session, "sess-assoc");
      assert.match(body.UserCode, /^\d{6}$/);
      assert.equal(body.UserCode, CODE_AT_59);
      return { status: 200, body: { Status: "SUCCESS", Session: "sess-verified" } };
    },
    RespondToAuthChallenge: (body) => {
      assert.equal(body.ChallengeName, "MFA_SETUP");
      assert.equal(body.Session, "sess-verified");
      assert.equal(body.ChallengeResponses.USERNAME, "user@x.io");
      return { status: 200, body: { AuthenticationResult: { IdToken: "id-tok-2", AccessToken: "acc-tok-2" } } };
    },
  }, captured);

  const result = await cognitoAuthenticate({
    config: CONFIG, username: "user@x.io", password: "correct-horse", enroll: true,
    fetchImpl, now, sleep,
  });
  assert.equal(result.tokens.idToken, "id-tok-2");
  assert.equal(result.fetchedSeed, SEED);

  // low-level building blocks individually, per the brief's exported surface
  const assoc = await associateSoftwareToken(CONFIG, "sess-setup", fetchImpl);
  assert.equal(assoc.secretCode, SEED);
  assert.equal(assoc.session, "sess-assoc");
  const verified = await verifySoftwareToken(CONFIG, "sess-assoc", CODE_AT_59, fetchImpl);
  assert.equal(verified.status, "SUCCESS");
  assert.equal(verified.session, "sess-verified");
  const tokens = await respondMfaSetup(CONFIG, "user@x.io", "sess-verified", fetchImpl);
  assert.equal(tokens.idToken, "id-tok-2");
});

test("SOFTWARE_TOKEN_MFA challenge with no known seed and no enroll throws a clear error", async () => {
  const fetchImpl = fakeCognitoFetch({
    InitiateAuth: () => ({ status: 200, body: { ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "sess-1" } }),
  });
  await assert.rejects(
    () => cognitoAuthenticate({ config: CONFIG, username: "user@x.io", password: "pw", fetchImpl, now, sleep }),
    /totpSecret|SOFTWARE_TOKEN_MFA/,
  );
});

test("MFA_SETUP challenge without enroll:true throws a clear error (never silently fetches a seed)", async () => {
  const fetchImpl = fakeCognitoFetch({
    InitiateAuth: () => ({ status: 200, body: { ChallengeName: "MFA_SETUP", Session: "sess-setup" } }),
  });
  await assert.rejects(
    () => cognitoAuthenticate({ config: CONFIG, username: "user@x.io", password: "pw", fetchImpl, now, sleep }),
    /enroll|MFA_SETUP/,
  );
});

test("no-MFA InitiateAuth returns tokens directly", async () => {
  const fetchImpl = fakeCognitoFetch({
    InitiateAuth: () => ({ status: 200, body: { AuthenticationResult: { IdToken: "id-direct", AccessToken: "acc-direct" } } }),
  });
  const init = await initiateAuth(CONFIG, "user@x.io", "pw", fetchImpl);
  assert.equal(init.tokens?.idToken, "id-direct");
  assert.equal(init.challengeName, undefined);

  const result = await cognitoAuthenticate({ config: CONFIG, username: "user@x.io", password: "pw", fetchImpl, now, sleep });
  assert.equal(result.tokens.idToken, "id-direct");
});

test("secret hygiene: password/totpSecret/fetched seed never appear in console output, and reach Cognito only via the request body", async () => {
  const captured: CapturedRequest[] = [];
  const SECRET_PASSWORD = "sUp3r-Secret-PW-9f2c";
  const fetchImpl = fakeCognitoFetch({
    InitiateAuth: () => ({ status: 200, body: { ChallengeName: "MFA_SETUP", Session: "sess-setup" } }),
    AssociateSoftwareToken: () => ({ status: 200, body: { SecretCode: SEED, Session: "sess-assoc" } }),
    VerifySoftwareToken: () => ({ status: 200, body: { Status: "SUCCESS", Session: "sess-verified" } }),
    RespondToAuthChallenge: () => ({ status: 200, body: { AuthenticationResult: { IdToken: "id-tok-3", AccessToken: "acc-tok-3" } } }),
  }, captured);

  const originalLog = console.log, originalError = console.error, originalWarn = console.warn;
  const logged: string[] = [];
  console.log = ((...args: unknown[]) => { logged.push(args.map(String).join(" ")); }) as any;
  console.error = ((...args: unknown[]) => { logged.push(args.map(String).join(" ")); }) as any;
  console.warn = ((...args: unknown[]) => { logged.push(args.map(String).join(" ")); }) as any;
  let result;
  try {
    result = await cognitoAuthenticate({
      config: CONFIG, username: "user@x.io", password: SECRET_PASSWORD, enroll: true, fetchImpl, now, sleep,
    });
  } finally {
    console.log = originalLog; console.error = originalError; console.warn = originalWarn;
  }

  for (const line of logged) {
    assert.ok(!line.includes(SECRET_PASSWORD), `password leaked into console output: ${line}`);
    assert.ok(!line.includes(SEED), `fetched seed leaked into console output: ${line}`);
  }
  // the password DID have to leave the process exactly once, in the InitiateAuth request
  // body to Cognito — that is the only legitimate egress for it.
  const initReq = captured.find((c) => c.action === "InitiateAuth")!;
  assert.equal(initReq.body.AuthParameters.PASSWORD, SECRET_PASSWORD);
  // fetchedSeed IS returned to the caller (by design — the caller now OWNS the seed and
  // must persist it in-process); it must never have been logged, asserted above.
  assert.equal(result.fetchedSeed, SEED);
});
