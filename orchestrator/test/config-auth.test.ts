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
