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

test("detectTwoFactor does not false-positive on ordinary words containing 'otp' etc.", () => {
  for (const w of ["footpath", "hotpot", "rootPath", "hotpatch"]) {
    assert.equal(detectTwoFactor(200, JSON.stringify({ note: w })).present, false);
  }
});
