import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyGenuineFinding } from "../src/judge.js";

function clientReturning(json: string) {
  return { chat: { completions: { create: async () => ({ choices: [{ message: { content: json } }] }) } } } as any;
}
const inv = { type: "status_in", statement: "burst kept returning 502", expression: "502" } as any;
const cap = { request: { method: "GET", url: "http://t/api/v2/auth", headers: {}, body: null },
              response: { status: 502, headers: {}, body: '{"message":"Internal server error"}' } } as any;

test("returns ok:false (fail open) when no model configured", async () => {
  const r = await verifyGenuineFinding({ client: undefined, model: undefined, vulnClass: "rate_limit_absence", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, false);
});

test("parses a confident not-genuine verdict", async () => {
  const r = await verifyGenuineFinding({
    client: clientReturning('{"is_genuine":false,"confidence":0.95,"rationale":"502 is a server error, not absent rate limiting"}'),
    model: "m", vulnClass: "rate_limit_absence", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, true); assert.equal(r.isGenuine, false); assert.ok(r.confidence >= 0.9);
});

test("parses a genuine verdict", async () => {
  const r = await verifyGenuineFinding({
    client: clientReturning('{"is_genuine":true,"confidence":0.8,"rationale":"real disclosure"}'),
    model: "m", vulnClass: "info_disclosure", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, true); assert.equal(r.isGenuine, true);
});

test("fails open (ok:false) when the client throws", async () => {
  const client = { chat: { completions: { create: async () => { throw new Error("boom"); } } } } as any;
  const r = await verifyGenuineFinding({ client, model: "m", vulnClass: "info_disclosure", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, false);
});

test("fails open on unparseable output", async () => {
  const r = await verifyGenuineFinding({ client: clientReturning("not json"), model: "m", vulnClass: "info_disclosure", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, false);
});
