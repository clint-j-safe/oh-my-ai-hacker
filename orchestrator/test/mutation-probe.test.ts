import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildMutationPlan, parseEntity, noopRoundTripRestorable, massAssignmentAccepted, restoreVerified,
  MASS_ASSIGNMENT_PROBE,
} from "../src/mutation-probe.js";

test("parseEntity accepts a bare object, rejects arrays/primitives/collections/non-JSON", () => {
  assert.deepEqual(parseEntity('{"id":1,"name":"x"}'), { id: 1, name: "x" });
  assert.equal(parseEntity('[1,2,3]'), null);
  assert.equal(parseEntity('"str"'), null);
  assert.equal(parseEntity('not json'), null);
  assert.equal(parseEntity('null'), null);
});

test("buildMutationPlan injects only probe keys NOT already present, and keeps the exact original as restore", () => {
  const original = '{"id":42,"name":"widget","role":"user"}';
  const plan = buildMutationPlan(original)!;
  assert.ok(plan, "plan built");
  // role already present -> NOT injected (so restore can revert everything we added)
  assert.ok(!plan.injectedKeys.includes("role"), "must not clobber an existing field");
  assert.ok(plan.injectedKeys.includes("isAdmin") && plan.injectedKeys.includes("sahw_probe_marker"));
  const probe = JSON.parse(plan.probeBody);
  assert.equal(probe.id, 42); assert.equal(probe.name, "widget");
  assert.equal(probe.role, "user", "existing field untouched");
  assert.equal(probe.isAdmin, true, "injected privileged field present");
  assert.equal(plan.restoreBody, original, "restore is the verbatim original bytes");
});

test("buildMutationPlan returns null when nothing is safe to probe (all probe keys already exist, or not an object)", () => {
  const allPresent = JSON.stringify(Object.fromEntries(Object.keys(MASS_ASSIGNMENT_PROBE).map((k) => [k, "x"])));
  assert.equal(buildMutationPlan(allPresent), null);
  assert.equal(buildMutationPlan('[1,2]'), null);
  assert.equal(buildMutationPlan('nope'), null);
});

test("noopRoundTripRestorable is true only when the post-noop entity equals the original (order-independent)", () => {
  assert.equal(noopRoundTripRestorable('{"a":1,"b":2}', '{"b":2,"a":1}'), true, "key order must not matter");
  assert.equal(noopRoundTripRestorable('{"a":1}', '{"a":1,"server_added":true}'), false, "server mutated it -> not cleanly restorable");
  assert.equal(noopRoundTripRestorable('{"a":1}', 'not json'), false);
});

test("massAssignmentAccepted is true when an injected key is reflected back on the entity", () => {
  assert.equal(massAssignmentAccepted('{"id":1,"isAdmin":true}', ["isAdmin", "role"]), true);
  assert.equal(massAssignmentAccepted('{"id":1}', ["isAdmin", "role"]), false, "probe fields ignored -> not accepted");
});

test("restoreVerified requires equality to original AND no lingering probe keys", () => {
  const original = '{"id":1,"name":"x"}';
  assert.equal(restoreVerified(original, '{"id":1,"name":"x"}', ["isAdmin"]), true);
  assert.equal(restoreVerified(original, '{"id":1,"name":"x","isAdmin":true}', ["isAdmin"]), false, "probe key lingered -> NOT restored");
  assert.equal(restoreVerified(original, '{"id":1,"name":"CHANGED"}', ["isAdmin"]), false, "value changed -> NOT restored");
});
