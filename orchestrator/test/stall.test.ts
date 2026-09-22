import { test } from "node:test";
import assert from "node:assert/strict";
import { isStalled, loadStallConfig } from "../src/stall.js";

const CFG = loadStallConfig({});

test("documented defaults", () => {
  assert.equal(CFG.minToolCalls, 1);
  assert.equal(CFG.minArtifacts, 1);
  assert.equal(CFG.maxRepeatCalls, 3);
  assert.equal(CFG.maxBarrenBeats, 2);
  assert.equal(CFG.exitCode, 3);
});

test("a beat that executed nothing is stalled, however much the model talked", () => {
  const r = isStalled({ succeededToolCalls: 0, newArtifacts: 0, calls: [] }, CFG);
  assert.equal(r.stalled, true);
  assert.match(r.reason!, /tool call/i);
});

test("tool calls without artifacts is still a stall", () => {
  const r = isStalled(
    { succeededToolCalls: 5, newArtifacts: 0, calls: [{ tool: "http_request", args: "{}" }] }, CFG);
  assert.equal(r.stalled, true);
  assert.match(r.reason!, /artifact/i);
});

test("the same call repeated past the cap is a stall", () => {
  const calls = Array.from({ length: 4 }, () => ({ tool: "http_request", args: '{"url":"u"}' }));
  const r = isStalled({ succeededToolCalls: 4, newArtifacts: 1, calls }, CFG);
  assert.equal(r.stalled, true);
  assert.match(r.reason!, /repeat/i);
});

test("distinct productive calls are not a stall", () => {
  const calls = [
    { tool: "http_request", args: '{"url":"a"}' },
    { tool: "http_request", args: '{"url":"b"}' },
  ];
  const r = isStalled({ succeededToolCalls: 2, newArtifacts: 2, calls }, CFG);
  assert.equal(r.stalled, false);
  assert.equal(r.reason, null);
});

test("failed tool calls do not count as executed work", () => {
  // succeededToolCalls counts only successes; a beat of pure denials is barren.
  const r = isStalled({ succeededToolCalls: 0, newArtifacts: 0, calls:
    [{ tool: "http_request", args: '{"url":"denied"}' }] }, CFG);
  assert.equal(r.stalled, true);
});
