import { test } from "node:test";
import assert from "node:assert/strict";
import { candidateLoginRequests, extractAuthMaterial, detectTwoFactor, classifyLoginResponse, detectCognito, detectTokenHeaders } from "../src/auth-recon.js";

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

test("detectTwoFactor does not false-positive on ordinary words containing 'otp' etc.", () => {
  for (const w of ["footpath", "hotpot", "rootPath", "hotpatch"]) {
    assert.equal(detectTwoFactor(200, JSON.stringify({ note: w })).present, false);
  }
});

test("detectTwoFactor detects camelCase 2FA keys", () => {
  for (const k of ["otpRequired", "mfaEnabled", "twoFactorRequired", "totpEnabled", "2faRequired", "challengeRequired"]) {
    assert.equal(detectTwoFactor(200, JSON.stringify({ [k]: true })).present, true);
  }
});

test("detectTwoFactor detects all-caps and mixed-case 2FA keywords", () => {
  const testCases = [
    { body: '{"msg":"2FA required"}', expected: true },
    { body: '{"msg":"2Fa"}', expected: true },
    { body: '{"msg":"ONE-TIME password"}', expected: true },
    { body: '{"msg":"AUTHENTICATOR"}', expected: true },
    { body: '{"msg":"VERIFICATION CODE"}', expected: true },
    { body: '{"msg":"TWO-FACTOR"}', expected: true },
    { body: '{"msg":"CHALLENGE"}', expected: true },
    { body: '{"msg":"TEXT MESSAGE"}', expected: true },
  ];
  for (const { body, expected } of testCases) {
    assert.equal(detectTwoFactor(200, body).present, expected, `Failed for: ${body}`);
  }
});

test("detectTwoFactor detects snake_case and space-separated variants", () => {
  const testCases = [
    { body: '{"otp_required":true}', expected: true },
    { body: '{"msg":"Enter your authenticator code"}', expected: true },
    { body: '{"msg":"verification code"}', expected: true },
  ];
  for (const { body, expected } of testCases) {
    assert.equal(detectTwoFactor(200, body).present, expected, `Failed for: ${body}`);
  }
});

test("detectTwoFactor rejects challenge variants that are part of longer words", () => {
  const testCases = [
    { body: '{"msg":"challenges"}', expected: false },
    { body: '{"msg":"challenger"}', expected: false },
  ];
  for (const { body, expected } of testCases) {
    const result = detectTwoFactor(200, body).present;
    assert.equal(result, expected, `Failed for: ${body} - got ${result}, expected ${expected}`);
  }
});

test("detectCognito extracts {region, clientId} from an Amplify-style bundle snippet", () => {
  const snippet = "const c={userPoolId:`us-east-1_Y4lomyxe9`,userPoolWebClientId:`4e4np8b76ra8uvf8ou2t6fmm9t`,region:`us-east-1`};";
  const cfg = detectCognito(snippet);
  assert.deepEqual(cfg, { region: "us-east-1", clientId: "4e4np8b76ra8uvf8ou2t6fmm9t" });
});

test("detectCognito derives region from the pool id's own prefix when region is not spelled out separately", () => {
  const snippet = "userPoolId:'us-east-1_Y4lomyxe9',userPoolWebClientId:'4e4np8b76ra8uvf8ou2t6fmm9t'";
  const cfg = detectCognito(snippet);
  assert.deepEqual(cfg, { region: "us-east-1", clientId: "4e4np8b76ra8uvf8ou2t6fmm9t" });
});

test("detectTokenHeaders extracts the SPA's id/access/refresh token header mapping from its bundle", () => {
  const snippet = "var s={accessTokenHeader:`authorization`,idTokenHeader:`x-safe-id-token`,refreshTokenHeader:`x-safe-refresh-token`};";
  assert.deepEqual(detectTokenHeaders(snippet), {
    idTokenHeader: "x-safe-id-token",
    accessTokenHeader: "authorization",
    refreshTokenHeader: "x-safe-refresh-token",
  });
});

test("detectTokenHeaders omits keys that are absent or not header-name-shaped (never guesses)", () => {
  assert.deepEqual(detectTokenHeaders("const x = 1;"), {});
  // present key but a non-header-name value (spaces/quotes) is rejected
  assert.deepEqual(detectTokenHeaders("idTokenHeader:`not a header name`"), {});
  // partial mapping: only what's present and valid
  assert.deepEqual(detectTokenHeaders("idTokenHeader:'x-id'"), { idTokenHeader: "x-id" });
});

test("detectCognito returns null when the bundle has no Cognito config", () => {
  assert.equal(detectCognito("const x = 1; // nothing here"), null);
  assert.equal(detectCognito("userPoolId:'us-east-1_abc'"), null); // no paired client id
});

// --- fix round 1: scope-bypass / credential-exfiltration hole -----------------
// detectCognito's output flows, unvalidated in the original implementation, into
// cognitoCall's request URL on a code path that deliberately bypasses inScope()
// (see beat.ts's EGRESS comment on runAuthRecord). A malicious/malformed region or
// clientId string embedded in the TARGET's own served bundle must never be trusted
// enough to steer that URL's host — detectCognito must refuse (return null) rather
// than pass through an unvalidated value.

test("detectCognito returns null for a bundle-supplied region that isn't a real AWS region shape (host-injection attempt)", () => {
  const snippet = "userPoolId:'us-east-1_Y4lomyxe9',userPoolWebClientId:'4e4np8b76ra8uvf8ou2t6fmm9t',region:'evil.com/x'";
  assert.equal(detectCognito(snippet), null);
});

test("detectCognito returns null for a bundle-supplied clientId containing characters outside the expected alphanumeric shape", () => {
  const snippet = "userPoolId:'us-east-1_Y4lomyxe9',userPoolWebClientId:'evil.com/x',region:'us-east-1'";
  assert.equal(detectCognito(snippet), null);
});

test("detectCognito still returns the valid config for the real (well-formed) snippet — the validation doesn't over-reject", () => {
  const snippet = "userPoolId:`us-east-1_Y4lomyxe9`,userPoolWebClientId:`4e4np8b76ra8uvf8ou2t6fmm9t`,region:`us-east-1`";
  assert.deepEqual(detectCognito(snippet), { region: "us-east-1", clientId: "4e4np8b76ra8uvf8ou2t6fmm9t" });
});
