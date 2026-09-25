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

test("NEEDS_REVIEW when anon ALSO succeeded (200) even if bodies differ", () => {
  const v = run({
    protectedResource: "http://t/api/profile",
    anonResponse: { status: 200, body: '{"ok":true,"requestId":"abc"}' },
    pre2faResponse: { status: 200, body: '{"ok":true,"requestId":"xyz"}' },
  });
  assert.notEqual(v.status, "CONFIRMED");
});
