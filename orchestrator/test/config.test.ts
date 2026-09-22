import { test } from "node:test";
import assert from "node:assert/strict";
import { loadEngagement, ConfigError } from "../src/config.js";

const NOW = new Date("2026-09-22T12:00:00Z");
const base = {
  SAHW_SCOPE: "http://10.0.0.1:3000,http://10.0.0.1/api/",
  SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z",
  SAHW_AUTH_END: "2026-09-25T00:00:00Z",
};

test("parses scope into URLs", () => {
  const e = loadEngagement(base, NOW);
  assert.equal(e.scope.length, 2);
  assert.equal(e.scope[0].port, "3000");
});

test("applies documented defaults", () => {
  const e = loadEngagement(base, NOW);
  assert.equal(e.maxTurns, 40);
  assert.equal(e.budgetTurns, 200);
  assert.equal(e.requestTimeoutMs, 3_600_000);
  assert.equal(e.phaseTimeoutMs, 3_000_000);
  assert.ok(e.phaseTimeoutMs < e.requestTimeoutMs, "defaults must satisfy the validator");
  assert.equal(e.maxRetries, 0);
  assert.equal(e.profile, "test");
});

test("refuses an empty scope — scope IS the allowlist", () => {
  assert.throws(() => loadEngagement({ ...base, SAHW_SCOPE: "" }, NOW), ConfigError);
});

test("refuses a run outside the authorization window", () => {
  assert.throws(
    () => loadEngagement(base, new Date("2026-09-26T00:00:00Z")), ConfigError);
  assert.throws(
    () => loadEngagement(base, new Date("2026-09-19T00:00:00Z")), ConfigError);
});

test("refuses a missing authorization reference", () => {
  const { SAHW_AUTH_REF, ...noRef } = base;
  assert.throws(() => loadEngagement(noRef, NOW), ConfigError);
});

test("refuses a phase timeout that does not trip before the transport", () => {
  assert.throws(() => loadEngagement(
    { ...base, SAHW_PHASE_TIMEOUT_MS: "9000000", SAHW_REQUEST_TIMEOUT_MS: "3600000" }, NOW),
    ConfigError);
});

test("rejects a non-http scheme in scope", () => {
  assert.throws(() => loadEngagement({ ...base, SAHW_SCOPE: "ftp://10.0.0.1" }, NOW), ConfigError);
});
