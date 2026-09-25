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

test("cognito provider defaults: provider auto, cognito null, cognitoEnroll false, authHeader x-safe-id-token", () => {
  const c = loadAuthConfig({});
  assert.equal(c.provider, "auto");
  assert.equal(c.cognito, null);
  assert.equal(c.cognitoEnroll, false);
  assert.equal(c.authHeader, "x-safe-id-token");
});

test("SAHW_AUTH_PROVIDER=cognito + SAHW_COGNITO parses region/clientId", () => {
  const c = loadAuthConfig({
    SAHW_AUTH_MODE: "authenticated",
    SAHW_AUTH_PROVIDER: "cognito",
    SAHW_AUTH_LOGIN: JSON.stringify({ email: "e@x.io", password: "p" }),
    SAHW_COGNITO: JSON.stringify({ region: "us-east-1", clientId: "4e4np8b76ra8uvf8ou2t6fmm9t" }),
    SAHW_COGNITO_ENROLL: "true",
    SAHW_AUTH_HEADER: "x-custom-token",
  });
  assert.equal(c.provider, "cognito");
  assert.deepEqual(c.cognito, { region: "us-east-1", clientId: "4e4np8b76ra8uvf8ou2t6fmm9t" });
  assert.equal(c.cognitoEnroll, true);
  assert.equal(c.authHeader, "x-custom-token");
});

test("invalid SAHW_AUTH_PROVIDER throws", () => {
  assert.throws(() => loadAuthConfig({ SAHW_AUTH_PROVIDER: "saml" }));
});

test("SAHW_COGNITO must be JSON with region+clientId", () => {
  assert.throws(() => loadAuthConfig({ SAHW_COGNITO: "not json" }));
  assert.throws(() => loadAuthConfig({ SAHW_COGNITO: JSON.stringify({ region: "us-east-1" }) }));
  assert.throws(() => loadAuthConfig({ SAHW_COGNITO: JSON.stringify({ clientId: "abc" }) }));
});

test("provider/cognito config is parsed even in mode:off (no secret to gate)", () => {
  const c = loadAuthConfig({
    SAHW_AUTH_PROVIDER: "cognito",
    SAHW_COGNITO: JSON.stringify({ region: "us-east-1", clientId: "abc" }),
  });
  assert.equal(c.mode, "off");
  assert.equal(c.provider, "cognito");
  assert.deepEqual(c.cognito, { region: "us-east-1", clientId: "abc" });
});
