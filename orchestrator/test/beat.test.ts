import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NodeSDK, tracing as otelTracing } from "@opentelemetry/sdk-node";
import { runBeat } from "../src/beat.js";

// Registers a REAL (but export-free) OpenTelemetry tracer provider once, before any
// test runs. OpenTelemetry's "first registered provider wins" rule means this
// NoopSpanProcessor-backed provider is the one that ends up minting trace ids for
// every span in this process; a later, real LangfuseTracing.start() call (triggered
// by TRACED_ENV below, when LANGFUSE_PUBLIC_KEY/SECRET_KEY are set) still runs its
// full real code path — constructing a genuine LangfuseSpanProcessor — but loses
// that registration race and stays inert, so it never attempts a network export.
// This makes the CONFIRMED-with-a-real-trace-id test fast (~ms, not ~500ms) and
// fully deterministic instead of depending on how quickly some environment refuses
// a connection to an unreachable port. Both packages used here (@opentelemetry/sdk-node,
// @langfuse/otel via LangfuseTracing itself) are already direct dependencies.
new NodeSDK({ spanProcessors: [new otelTracing.NoopSpanProcessor()] }).start();

const ENV = async () => ({
  SAHW_SCOPE: "http://10.0.0.1:3000", SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z", SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
  SAHW_WORKSPACE: await mkdtemp(join(tmpdir(), "sahw-")),
});
// A Langfuse-configured env, used only by the test that exercises the full CONFIRMED
// path with a real trace id present. LANGFUSE_BASE_URL is set to a port nothing
// listens on purely as defense-in-depth (in case the no-op-provider trick above ever
// stops winning the registration race in a future @langfuse/otel version) — it is not
// what makes this test fast or safe; the module-level NodeSDK registration above is.
const TRACED_ENV = async () => ({
  ...(await ENV()),
  LANGFUSE_PUBLIC_KEY: "pk-test", LANGFUSE_SECRET_KEY: "sk-test",
  LANGFUSE_BASE_URL: "http://127.0.0.1:1",
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

test("a beat with a real differential and real tracing produces a CONFIRMED finding and exits 0", async () => {
  const out = await runBeat({ env: await TRACED_ENV(), client: scriptedClient(), fetchImpl: differentialFetch, now: NOW });
  assert.equal(out.stalled, false);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED");
  assert.equal(out.exitCode, 0);
  // The trace id that reached provenance must be a REAL id minted by the active
  // OpenTelemetry span, never a placeholder — a 32-lowercase-hex OTel trace id.
  assert.match(out.findings[0].langfuse_trace_id ?? "", /^[0-9a-f]{32}$/);
});

// THE BEHAVIOUR CHANGE THAT MATTERS MOST: without Langfuse configured, obs.traceId()
// returns null (never a placeholder like the old "local"). gateProvenance treats a
// missing langfuseTraceId as missing provenance, so an otherwise-CONFIRMED finding
// is capped at NEEDS_REVIEW. This is the Provenance Gate doing its job — see
// src/provenance.ts and src/obs/langfuse.ts.
test("with no Langfuse configured, a real differential is capped at NEEDS_REVIEW — never a placeholder trace id", async () => {
  const out = await runBeat({ env: await ENV(), client: scriptedClient(), fetchImpl: differentialFetch, now: NOW });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "NEEDS_REVIEW");
  assert.equal(out.findings[0].langfuse_trace_id, null);
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
