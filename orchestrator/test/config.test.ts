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

test("budgetUsd is null when unset — it means \"not priced per token\", not zero", () => {
  const e = loadEngagement(base, NOW);
  assert.equal(e.budgetUsd, null);
});

test("budgetUsd parses a valid value", () => {
  const e = loadEngagement({ ...base, SAHW_BUDGET_USD: "25" }, NOW);
  assert.equal(e.budgetUsd, 25);
});

test("refuses a malformed budgetUsd instead of silently disabling the spend cap", () => {
  assert.throws(() => loadEngagement({ ...base, SAHW_BUDGET_USD: "abc" }, NOW), ConfigError);
});

test("budgetTokens applies its default and parses an override", () => {
  const withDefault = loadEngagement(base, NOW);
  assert.equal(withDefault.budgetTokens, 2_000_000);
  const withOverride = loadEngagement({ ...base, SAHW_BUDGET_TOKENS: "500000" }, NOW);
  assert.equal(withOverride.budgetTokens, 500_000);
});

test("outOfScope is empty by default and parses a provided list", () => {
  const withDefault = loadEngagement(base, NOW);
  assert.deepEqual(withDefault.outOfScope, []);
  const e = loadEngagement({ ...base, SAHW_OUT_OF_SCOPE: "http://10.0.0.1/admin" }, NOW);
  assert.equal(e.outOfScope.length, 1);
  assert.equal(e.outOfScope[0].pathname, "/admin");
});

test("treats a whitespace-only numeric field as unset instead of silently coercing it to zero", () => {
  const e = loadEngagement({ ...base, SAHW_MAX_TURNS: "  " }, NOW);
  assert.equal(e.maxTurns, 40, "must fall back to the default, not Number(\" \") === 0");
});

// ---- deep mode -----------------------------------------------------------------

test("deep mode is OFF by default and every sub-flag is disabled", () => {
  const e = loadEngagement(base, NOW);
  assert.equal(e.deep.enabled, false);
  assert.equal(e.deep.sweep, false);
  assert.equal(e.deep.fuzz, false);
  assert.equal(e.deep.escalate, false);
  assert.equal(e.deep.weaponize, "off");
  assert.equal(e.deep.weaponizeAuthRef, null);
});

test("enabling deep mode turns on sweep/fuzz/escalate by default, weaponize stays off", () => {
  const e = loadEngagement({ ...base, SAHW_DEEP_MODE: "true" }, NOW);
  assert.equal(e.deep.enabled, true);
  assert.equal(e.deep.sweep, true);
  assert.equal(e.deep.fuzz, true);
  assert.equal(e.deep.escalate, true);
  assert.equal(e.deep.weaponize, "off");
});

test("a sub-flag set WITHOUT deep mode enabled is forced off (fail-closed)", () => {
  const e = loadEngagement({ ...base, SAHW_DEEP_SWEEP: "true", SAHW_DEEP_WEAPONIZE: "impact" }, NOW);
  assert.equal(e.deep.enabled, false);
  assert.equal(e.deep.sweep, false);
  assert.equal(e.deep.weaponize, "off");
});

test("weaponize is REFUSED unless the signed auth ref is named a second time (double-confirm)", () => {
  // deep on + weaponize impact but no matching auth ref -> ConfigError
  assert.throws(
    () => loadEngagement({ ...base, SAHW_DEEP_MODE: "1", SAHW_DEEP_WEAPONIZE: "impact" }, NOW),
    ConfigError);
  // wrong auth ref -> still refused
  assert.throws(
    () => loadEngagement({ ...base, SAHW_DEEP_MODE: "1", SAHW_DEEP_WEAPONIZE: "impact", SAHW_DEEP_WEAPONIZE_AUTH_REF: "WRONG" }, NOW),
    ConfigError);
});

test("weaponize is permitted only when SAHW_DEEP_WEAPONIZE_AUTH_REF exactly matches SAHW_AUTH_REF", () => {
  const e = loadEngagement(
    { ...base, SAHW_DEEP_MODE: "1", SAHW_DEEP_WEAPONIZE: "impact", SAHW_DEEP_WEAPONIZE_AUTH_REF: "ENG-1" }, NOW);
  assert.equal(e.deep.weaponize, "impact");
  assert.equal(e.deep.weaponizeAuthRef, "ENG-1");
});

test("deep caps default sensibly and accept overrides", () => {
  const d = loadEngagement({ ...base, SAHW_DEEP_MODE: "1" }, NOW).deep;
  assert.equal(d.maxSweepRequests, 500);
  assert.equal(d.maxEscalationDepth, 2);
  const o = loadEngagement({ ...base, SAHW_DEEP_MODE: "1", SAHW_DEEP_SWEEP_BUDGET: "1200", SAHW_DEEP_ESCALATION_DEPTH: "4" }, NOW).deep;
  assert.equal(o.maxSweepRequests, 1200);
  assert.equal(o.maxEscalationDepth, 4);
});

test("a malformed deep boolean throws rather than silently defaulting", () => {
  assert.throws(() => loadEngagement({ ...base, SAHW_DEEP_MODE: "maybe" }, NOW), ConfigError);
});
