import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NodeSDK, tracing as otelTracing } from "@opentelemetry/sdk-node";
import { runBeat, VULN_CLASSES, isVulnClass } from "../src/beat.js";

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

// ---- Multi-finding beats -------------------------------------------------------

/** A response with no headers at all: any "!header:x" response_asserted clause holds. */
const bareFetch = (async () => new Response("OK")) as unknown as typeof fetch;

const say = (content: string) => ({ choices: [{ message: { role: "assistant", content } }], usage: { total_tokens: 10 } });
const call = (name: string, args: object) => ({
  choices: [{ message: { role: "assistant", content: null, tool_calls: [
    { id: "c1", type: "function", function: { name, arguments: JSON.stringify(args) } }] } }],
  usage: { total_tokens: 10 },
});

function claim(vuln_class: string, endpoint: string) {
  return {
    vuln_class, endpoint,
    invariant: { statement: "no framing protection", type: "response_asserted", expression: "!header:x-frame-options" },
  };
}

/** Records every params object the client was called with, so a test can inspect what the hunter was told. */
function recordingScriptedClient(script: any[]) {
  const seen: any[] = [];
  let i = 0;
  return {
    seen,
    chat: { completions: { create: async (params: any) => {
      seen.push(params);
      return script[Math.min(i++, script.length - 1)];
    } } },
  };
}

test("three different valid claims in one beat produce three findings", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify(claim("clickjacking", url("a")))),
    call("http_request", { method: "GET", url: url("b") }),
    say(JSON.stringify(claim("cors_misconfig", url("b")))),
    call("http_request", { method: "GET", url: url("c") }),
    say(JSON.stringify(claim("info_disclosure", url("c")))),
    say("No further hypotheses. I am done."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 3);
  assert.deepEqual(out.findings.map((f) => f.vuln_class), ["clickjacking", "cors_misconfig", "info_disclosure"]);
  assert.equal(out.stalled, false);
  assert.equal(out.exitCode, 0);
});

test("the same claim reported twice produces one finding and increments duplicates_suppressed", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.duplicates_suppressed, 1);
  assert.equal(out.stalled, false);
});

test("a prose vuln_class is rejected, counted in rejected_claims, and the hunter is re-prompted with the allowed values", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("Missing framing protection (clickjacking)", url))),
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const client = recordingScriptedClient(script);
  const out = await runBeat({ env: await ENV(), client, fetchImpl: bareFetch, now: NOW });

  assert.equal(out.rejected_claims.length, 1);
  assert.match(out.rejected_claims[0].reason, /not in the allowed vocabulary/);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].vuln_class, "clickjacking");

  // The re-prompt actually reached the model: some later request's messages contain
  // the exact allowed-values list.
  const allowedList = VULN_CLASSES.join(", ");
  const sawFeedback = client.seen.some((params: any) =>
    params.messages.some((m: any) => typeof m.content === "string" && m.content.includes(allowedList)));
  assert.ok(sawFeedback, "hunter must be re-prompted with the exact allowed vuln_class values");
});

test("SAHW_MAX_FINDINGS caps the loop", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify(claim("clickjacking", url("a")))),
    call("http_request", { method: "GET", url: url("b") }),
    say(JSON.stringify(claim("cors_misconfig", url("b")))),
    call("http_request", { method: "GET", url: url("c") }),
    say(JSON.stringify(claim("info_disclosure", url("c")))),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_MAX_FINDINGS: "2" },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 2);
  assert.equal(out.stalled, false);
  assert.equal(out.exitCode, 0);
});

test("a beat that banks one finding then fails to parse a later claim is NOT reported as stalled and exits 0", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    call("http_request", { method: "GET", url }),
    say("I probed further but found nothing conclusive worth claiming."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.stalled, false);
  assert.equal(out.exitCode, 0);
});

test("SAHW_MAX_TURNS_PER_FINDING cuts off a greedy attempt without ending the beat", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }), // attempt 1, turn 1 of 2 — no claim yet
    call("http_request", { method: "GET", url }), // attempt 1, turn 2 of 2 — cap hit, still no claim
    call("http_request", { method: "GET", url }), // attempt 2, turn 1 — bank the claim
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_MAX_TURNS_PER_FINDING: "2" },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1, "the abandoned first attempt must not have killed the beat");
  assert.equal(out.findings[0].vuln_class, "clickjacking");
  assert.equal(out.stalled, false);
  assert.equal(out.exitCode, 0);
});

test("a beat that never produces a parseable claim (zero findings) IS stalled and exits non-zero", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say("I probed but found nothing conclusive."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 0);
  assert.equal(out.stalled, true);
  assert.equal(out.exitCode, 3);
});

// ---- the Spine -------------------------------------------------------------------

test("the spine is written even when the beat stalls, and records the stalled beat", async () => {
  const env = await ENV();
  const silent = { chat: { completions: { create: async () => ({ choices: [{ message: { role: "assistant", content: "I will think about it." } }], usage: { total_tokens: 5 } }) } } };
  const out = await runBeat({ env, client: silent, fetchImpl: differentialFetch, now: NOW });
  assert.equal(out.stalled, true);

  const raw = await readFile(join(env.SAHW_WORKSPACE!, "spine", "progress.json"), "utf8");
  const spine = JSON.parse(raw);
  assert.equal(spine.beats.length, 1);
  assert.equal(spine.beats[0].stalled, true);
  assert.equal(spine.beats[0].findings_banked, 0);
  assert.ok(spine.beats[0].reason, "a stalled beat must record why");
});

test("a fresh workspace produces spine_fresh: true on the result, with a null reason", async () => {
  const out = await runBeat({ env: await ENV(), client: scriptedClient(), fetchImpl: differentialFetch, now: NOW });
  assert.equal(out.spine_fresh, true);
  assert.equal(out.spine_fresh_reason, null);
});

test("the generated hunter brief (not a static string) reaches the model as the system message", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const client = recordingScriptedClient(script);
  await runBeat({ env: await ENV(), client, fetchImpl: bareFetch, now: NOW });
  const firstCallMessages = client.seen[0].messages;
  const system = firstCallMessages.find((m: any) => m.role === "system");
  assert.match(system.content, /<safe_ai_hacker_hunter>/);
  assert.match(system.content, /<attack_surface>/);
  assert.match(system.content, /<already_proved>/);
  assert.match(system.content, /map the attack surface/i);
});

test("a second beat against the SAME engagement/scope inherits the first beat's proved findings into <already_proved>", async () => {
  const env = await ENV();
  const url = "http://10.0.0.1:3000/a";
  const script1 = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const first = await runBeat({ env, client: recordingScriptedClient(script1), fetchImpl: bareFetch, now: NOW });
  assert.equal(first.findings.length, 1);

  const script2 = [say("Nothing to report.")];
  const client2 = recordingScriptedClient(script2);
  await runBeat({ env, client: client2, fetchImpl: bareFetch, now: NOW });
  const system = client2.seen[0].messages.find((m: any) => m.role === "system");
  assert.match(system.content, /vuln_class="clickjacking"/);
  assert.match(system.content, new RegExp(`endpoint="${url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
});

test("every VULN_CLASSES value is accepted by isVulnClass, and a prose value is rejected", () => {
  for (const v of VULN_CLASSES) {
    assert.equal(isVulnClass(v), true, `expected ${v} to be accepted`);
  }
  assert.equal(isVulnClass("Missing framing protection (clickjacking)"), false);
  assert.equal(isVulnClass("Clickjacking"), false);
  assert.equal(isVulnClass(""), false);
  assert.equal(isVulnClass(undefined), false);
});

test("a beat that did real work is NOT stalled because one later attempt ran dry", async () => {
  // Regression. Stall was evaluated per ATTEMPT, so a beat whose first attempt made
  // five successful requests — mapping the API root among them — was aborted and
  // discarded the moment a later hypothesis produced no tool calls. Stall is a
  // BEAT-level rule: the beat plainly executed work.
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),                 // attempt 1: real work
    say(JSON.stringify(claim("clickjacking", url))),              // -> banks a finding
    say("I have no further hypothesis worth testing."),           // attempt 2: zero tool calls
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.stalled, false, "a beat with executed work must not report stalled");
  assert.equal(out.exitCode, 0);
  assert.equal(out.findings.length, 1, "the finding proved in attempt 1 must survive");
  assert.doesNotMatch(String(out.reason ?? ""), /0 succeeded tool call/);
});
