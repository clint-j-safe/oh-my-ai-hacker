import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runBeat } from "../src/beat.js";

const ENV = async () => ({
  SAHW_SCOPE: "http://10.0.0.1:3000", SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z", SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
  SAHW_WORKSPACE: await mkdtemp(join(tmpdir(), "sahw-")),
});
const NOW = new Date("2026-09-22T12:00:00Z");

/** Exploit sees the marker, control does not — the shape M0 must confirm. */
const differentialFetch = (async (url: string | URL) => {
  const u = String(url);
  return u.includes("exploit")
    ? new Response("root:x:0:0:root:/root:/bin/bash")
    : new Response("404 not found", { status: 404 });
}) as unknown as typeof fetch;

function scriptedClient() {
  const script = [
    { choices: [{ message: { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "http_request", arguments: JSON.stringify({ method: "GET", url: "http://10.0.0.1:3000/exploit" }) } }] } }], usage: { total_tokens: 10 } },
    { choices: [{ message: { role: "assistant", content: JSON.stringify({
        vuln_class: "path_traversal",
        endpoint: "http://10.0.0.1:3000/exploit",
        control_url: "http://10.0.0.1:3000/control",
        invariant: { statement: "file contents returned", type: "body_contains", expression: "root:x:0:0" },
      }) } }], usage: { total_tokens: 10 } },
  ];
  let i = 0;
  return { chat: { completions: { create: async () => script[Math.min(i++, script.length - 1)] } } };
}

test("a beat with a real differential produces a CONFIRMED finding and exits 0", async () => {
  const out = await runBeat({ env: await ENV(), client: scriptedClient(), fetchImpl: differentialFetch, now: NOW });
  assert.equal(out.stalled, false);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED");
  assert.equal(out.exitCode, 0);
});

test("a beat that executes nothing is stalled and exits non-zero", async () => {
  const silent = { chat: { completions: { create: async () => ({ choices: [{ message: { role: "assistant", content: "I will think about it." } }], usage: { total_tokens: 5 } }) } } };
  const out = await runBeat({ env: await ENV(), client: silent, fetchImpl: differentialFetch, now: NOW });
  assert.equal(out.stalled, true);
  assert.equal(out.exitCode, 3);
  assert.equal(out.findings.length, 0);
});

test("no control differential means no CONFIRMED", async () => {
  const sameFetch = (async () => new Response("root:x:0:0")) as unknown as typeof fetch;
  const out = await runBeat({ env: await ENV(), client: scriptedClient(), fetchImpl: sameFetch, now: NOW });
  assert.notEqual(out.findings[0]?.verdict, "CONFIRMED");
});

test("an out-of-window engagement refuses to run at all", async () => {
  const env = await ENV();
  await assert.rejects(() => runBeat({
    env, client: scriptedClient(), fetchImpl: differentialFetch,
    now: new Date("2026-10-01T00:00:00Z"),
  }));
});
