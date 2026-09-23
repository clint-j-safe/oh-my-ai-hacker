import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { spawn as realSpawn } from "node:child_process";
import { NodeSDK, tracing as otelTracing } from "@opentelemetry/sdk-node";
import { runBeat, VULN_CLASSES, isVulnClass } from "../src/beat.js";
import { buildHunterBrief, type HunterBriefState } from "../src/brief.js";
import { SessionStore, generateDisposableCredentials } from "../src/session.js";

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

test("a claim whose exploit request cannot be captured (null) is handled per-claim (NEEDS_REVIEW) and NEVER aborts the beat — a later valid claim still banks", async () => {
  const failUrl = "http://10.0.0.1:3000/faily";   // fetch throws here -> capture() returns null
  const goodUrl = "http://10.0.0.1:3000/ok";
  // A fetch that THROWS for the failing endpoint (network failure) — http_request maps
  // this to ok:false, so capture() returns null and exploit is null for that claim.
  const throwOnFaily = (async (url: string | URL) => {
    if (String(url).includes("faily")) throw new TypeError("terminated");
    return new Response("OK");   // bare response -> a "!header:x-frame-options" claim holds
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: goodUrl }),        // execute work (not stalled)
    say(JSON.stringify(claim("clickjacking", failUrl))),           // response_asserted on the null-exploit endpoint
    say(JSON.stringify(claim("clickjacking", goodUrl))),           // a valid claim AFTER the would-be crash
    say("Nothing else to report."),
  ];
  // Before the guard, the null exploit hit `exploit!.response` and threw, aborting the
  // whole beat (discarding the later valid finding). This must resolve, not reject.
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: throwOnFaily, now: NOW,
  });
  assert.equal(out.stalled, false);
  assert.equal(out.exitCode, 0);
  const faily = out.findings.find((f) => f.endpoint === failUrl);
  assert.ok(faily, "the un-capturable claim must still produce a recorded finding, not a crash");
  assert.equal(faily!.verdict, "NEEDS_REVIEW", "a null exploit cannot be confirmed; it is surfaced for review");
  assert.ok(
    out.findings.some((f) => f.endpoint === goodUrl),
    "the beat must CONTINUE past the un-capturable claim and bank the later valid one",
  );
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

// ---- Claim review: a mandatory pre-Axiom stage ------------------------------------
//
// The real adversarial-self-review skill runs end to end in these tests (default
// skillsRoot resolution — see tools.ts's defaultSkillsRoot — finds the repo's real
// skills/ dir, exactly as skill-run.test.ts's "real severity-calibration" test
// does), never a fixture, EXCEPT where a test needs to simulate the skill being
// unavailable/erroring/hanging, where a temporary skillsRoot is substituted via
// SAHW_SKILLS_ROOT.

/** Writes a minimal fixture skill directory at <root>/adversarial-self-review, so a
 * test can simulate the review skill erroring or hanging without touching the real
 * skill. Mirrors skill-run.test.ts's writeFixtureSkill. */
async function writeFixtureReviewSkill(root: string, pySource: string): Promise<void> {
  const dir = join(root, "adversarial-self-review");
  await mkdir(join(dir, "scripts"), { recursive: true });
  await writeFile(join(dir, "scripts", "run.py"), pySource, "utf8");
  await mkdir(join(dir, "references"), { recursive: true });
  await writeFile(
    join(dir, "references", "artifact.schema.json"),
    JSON.stringify({ type: "object", required: ["reviews"], properties: { reviews: { type: "array" } } }),
    "utf8",
  );
}

test("claim review runs before the Axiom replay on every claim when enabled (ordering, via a spawn/fetch call-order spy)", async () => {
  const calls: string[] = [];
  const spyFetch = (async (u: string | URL) => {
    calls.push(`fetch:${String(u)}`);
    return new Response("OK");
  }) as unknown as typeof fetch;
  const spySpawn = ((...args: Parameters<typeof realSpawn>) => {
    calls.push("spawn:skill_run");
    return realSpawn(...args);
  }) as typeof realSpawn;

  // The stall rule needs at least one succeeded tool call + artifact before ANY
  // claim can be parsed (beat-level, see stall.ts) — the hunter's own recon probe
  // supplies that, deliberately against a DIFFERENT url than the claim's endpoint so
  // the ordering assertion below is unambiguous about which fetch is the Axiom's.
  const reconUrl = "http://10.0.0.1:3000/recon";
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url: reconUrl }),
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script),
    fetchImpl: spyFetch, spawnImpl: spySpawn, now: NOW,
  });
  const spawnIdx = calls.findIndex((c) => c === "spawn:skill_run");
  const exploitFetchIdx = calls.findIndex((c) => c === `fetch:${url}`);
  assert.ok(spawnIdx >= 0, "the claim-review skill must actually have run (real, network-free skill)");
  assert.ok(exploitFetchIdx >= 0, "the Axiom must actually have replayed the exploit");
  assert.ok(spawnIdx < exploitFetchIdx, "claim review must run before the Axiom replay");
  assert.equal(out.exitCode, 0);
});

test("a claim rejected by adversarial-self-review skips the Axiom replay entirely (target fetch never called) and records review_rejected", async () => {
  const fetchedUrls: string[] = [];
  const spyFetch = (async (u: string | URL) => {
    fetchedUrls.push(String(u));
    return new Response("OK");
  }) as unknown as typeof fetch;
  const reconUrl = "http://10.0.0.1:3000/recon";
  const url = "http://10.0.0.1:3000/ssrf";
  const controlUrl = "http://10.0.0.1:3000/control";
  // ssrf's only class-specific false-positive challenge (dns_rebinding) resolves
  // ONLY on out-of-band evidence, which M0's control-differential model can never
  // produce pre-Axiom — so an ssrf claim is deterministically rejected by the
  // reviewer regardless of any other field. See src/beat.ts's claim-review doc
  // comment and skills/adversarial-self-review/scripts/run.py's generate_challenges().
  const ssrfClaim = {
    vuln_class: "ssrf", endpoint: url, control_url: controlUrl,
    invariant: {
      statement: "internal service reached via attacker-controlled URL",
      type: "body_contains", expression: "internal-marker-xyz",
    },
  };
  const script = [
    call("http_request", { method: "GET", url: reconUrl }),
    say(JSON.stringify(ssrfClaim)),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: spyFetch, now: NOW,
  });
  assert.ok(!fetchedUrls.includes(url), "the claimed exploit endpoint must never be contacted");
  assert.ok(!fetchedUrls.includes(controlUrl), "the claimed control endpoint must never be contacted");
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].vuln_class, "ssrf");
  assert.notEqual(out.findings[0].verdict, "CONFIRMED");
  assert.equal((out.findings[0] as any).failure_cause, "review_rejected");
  assert.equal(out.failure_causes.review_rejected, 1);
  assert.equal(out.exitCode, 0);
  // The hunter is told WHY, not just "rejected".
  assert.ok(out.rejected_claims.length === 0, "a review rejection is a finding (dead end), not a malformed-claim rejection");
});

test("SAHW_CLAIM_REVIEW=off skips the claim-review stage entirely (no skill process spawned)", async () => {
  let spawnCalls = 0;
  const spySpawn = ((...args: Parameters<typeof realSpawn>) => {
    spawnCalls++;
    return realSpawn(...args);
  }) as typeof realSpawn;
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, spawnImpl: spySpawn, now: NOW,
  });
  assert.equal(spawnCalls, 0, "no skill process may be spawned when claim review is disabled");
  assert.equal(out.findings.length, 1);
  assert.equal(out.failure_causes.review_rejected, 0);
});

test("claim review that is UNAVAILABLE (no adversarial-self-review under the configured skills root) still reaches the Axiom and produces a verdict", async () => {
  const emptyRoot = await mkdtemp(join(tmpdir(), "sahw-noreview-"));
  const url = "http://10.0.0.1:3000/exploit";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "path_traversal", endpoint: url, control_url: "http://10.0.0.1:3000/control",
      invariant: { statement: "file contents returned", type: "body_contains", expression: "root:x:0:0" },
    })),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_SKILLS_ROOT: emptyRoot },
    client: recordingScriptedClient(script), fetchImpl: differentialFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1, "the Axiom must still have produced a finding");
  assert.equal(out.findings[0].verdict, "NEEDS_REVIEW"); // untraced env caps CONFIRMED, per the earlier test
  assert.equal((out.findings[0] as any).failure_cause, undefined,
    "the underlying mechanism WAS confirmed by the Axiom — an unavailable reviewer must not fabricate a cause");
  assert.equal(out.failure_causes.review_rejected, 0);
});

test("claim review that ERRORS (skill exits non-zero) still reaches the Axiom and produces a verdict", async () => {
  const root = await mkdtemp(join(tmpdir(), "sahw-badreview-"));
  await writeFixtureReviewSkill(root, [
    "import sys",
    "sys.stdin.read()",
    "sys.stderr.write('simulated crash')",
    "sys.exit(1)",
    "",
  ].join("\n"));

  const url = "http://10.0.0.1:3000/a";
  const script = [call("http_request", { method: "GET", url }), say(JSON.stringify(claim("cors_misconfig", url)))];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_SKILLS_ROOT: root },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1, "the Axiom must still have produced a finding");
  assert.equal(out.findings[0].verdict, "NEEDS_REVIEW"); // untraced env caps CONFIRMED
  assert.equal(out.failure_causes.review_rejected, 0);
});

test("claim review that TIMES OUT still reaches the Axiom and produces a verdict, without waiting for the full hang", async () => {
  const root = await mkdtemp(join(tmpdir(), "sahw-hangreview-"));
  await writeFixtureReviewSkill(root, ["import sys, time", "sys.stdin.read()", "time.sleep(30)", ""].join("\n"));

  const url = "http://10.0.0.1:3000/a";
  const script = [call("http_request", { method: "GET", url }), say(JSON.stringify(claim("cors_misconfig", url)))];
  const started = Date.now();
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_SKILLS_ROOT: root, SAHW_SKILL_TIMEOUT_MS: "300" },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 5000, `must not wait for the full hang, took ${elapsed}ms`);
  assert.equal(out.findings.length, 1, "the Axiom must still have produced a finding");
  assert.equal(out.failure_causes.review_rejected, 0);
});

// ---- Failure-cause taxonomy --------------------------------------------------------

test("wrong_invariant_type: a differential invariant against a class that needs a self-contained assertion", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "cors_misconfig", endpoint: url, control_url: "http://10.0.0.1:3000/control",
      invariant: { statement: "arbitrary origin reflected", type: "body_contains", expression: "wrong-marker-abc" },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.notEqual(out.findings[0].verdict, "CONFIRMED");
  assert.equal((out.findings[0] as any).failure_cause, "wrong_invariant_type");
  assert.equal(out.failure_causes.wrong_invariant_type, 1);
});

test("no_control: a differential claim whose control cannot be captured is attributed no_control", async () => {
  const url = "http://10.0.0.1:3000/a";
  const badControl = "http://evil.example.com:9999/control"; // out of scope: gate() denies, capture() returns null
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "auth_bypass", endpoint: url, control_url: badControl,
      invariant: { statement: "authorization bypassed", type: "body_contains", expression: "admin-marker" },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.notEqual(out.findings[0].verdict, "CONFIRMED");
  assert.equal((out.findings[0] as any).failure_cause, "no_control");
  assert.equal(out.failure_causes.no_control, 1);
});

test("marker_absent: the exploit response itself lacks the expected differential marker", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "xss_reflected", endpoint: url, control_url: "http://10.0.0.1:3000/control",
      invariant: { statement: "payload reflected unescaped", type: "body_contains", expression: "xss-marker-zzz" },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.notEqual(out.findings[0].verdict, "CONFIRMED");
  assert.equal((out.findings[0] as any).failure_cause, "marker_absent");
  assert.equal(out.failure_causes.marker_absent, 1);
});

test("control_shared_marker: exploit AND control both exhibit the differential signal", async () => {
  const url = "http://10.0.0.1:3000/a";
  const sharedFetch = (async () => new Response("root:x:0:0:root:/root:/bin/bash")) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "deserialization_rce", endpoint: url, control_url: "http://10.0.0.1:3000/control",
      invariant: { statement: "gadget chain executed", type: "body_contains", expression: "root:x:0:0" },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: sharedFetch, now: NOW,
  });
  assert.notEqual(out.findings[0].verdict, "CONFIRMED");
  assert.equal((out.findings[0] as any).failure_cause, "control_shared_marker");
  assert.equal(out.failure_causes.control_shared_marker, 1);
});

test("endpoint_implausible: a BEHAVIOUR claim against a response whose content-type is a static asset", async () => {
  const url = "http://10.0.0.1:3000/bundle.js";
  const jsAssetFetch = (async () =>
    new Response("var x = 1;", { headers: { "content-type": "application/javascript" } })) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "sqli", endpoint: url, control_url: "http://10.0.0.1:3000/control.js",
      invariant: { statement: "boolean differential observed", type: "body_contains", expression: "sql-marker-xyz" },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: jsAssetFetch, now: NOW,
  });
  assert.notEqual(out.findings[0].verdict, "CONFIRMED");
  assert.equal((out.findings[0] as any).failure_cause, "endpoint_implausible");
  assert.equal(out.failure_causes.endpoint_implausible, 1);
});

test("failure_causes counts each distinct cause across a beat, every FailureCause defaulting to 0", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const badControl = "http://evil.example.com:9999/control";
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify({
      vuln_class: "auth_bypass", endpoint: url("a"), control_url: badControl,
      invariant: { statement: "authz bypassed", type: "body_contains", expression: "admin-marker" },
    })),
    call("http_request", { method: "GET", url: url("b") }),
    say(JSON.stringify({
      vuln_class: "xss_reflected", endpoint: url("b"), control_url: url("c"),
      invariant: { statement: "payload reflected", type: "body_contains", expression: "xss-marker-zzz" },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: await ENV(), client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 2);
  assert.equal(out.failure_causes.no_control, 1);
  assert.equal(out.failure_causes.marker_absent, 1);
  assert.equal(out.failure_causes.wrong_invariant_type, 0);
  assert.equal(out.failure_causes.control_shared_marker, 0);
  assert.equal(out.failure_causes.endpoint_implausible, 0);
  assert.equal(out.failure_causes.review_rejected, 0);
  assert.equal(out.failure_causes.unknown, 0);
});

test("the hunter's feedback for a non-CONFIRMED finding contains the SPECIFIC cause, not a generic verdict-only string", async () => {
  const url = "http://10.0.0.1:3000/a";
  const sharedFetch = (async () => new Response("shared-marker-1234")) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "idor", endpoint: url, control_url: "http://10.0.0.1:3000/control",
      invariant: { statement: "other user's record returned", type: "body_contains", expression: "shared-marker-1234" },
    })),
    say("Nothing else to report."),
  ];
  const client = recordingScriptedClient(script);
  const out = await runBeat({ env: await ENV(), client, fetchImpl: sharedFetch, now: NOW });
  assert.equal((out.findings[0] as any).failure_cause, "control_shared_marker");

  const sawSpecificCause = client.seen.some((params: any) =>
    params.messages.some((m: any) =>
      typeof m.content === "string" && m.content.includes("Cause: control_shared_marker")
      && /shared the same marker/i.test(m.content)));
  assert.ok(sawSpecificCause, "feedback must name the SPECIFIC cause and actionable reasoning, not just the verdict");
});

// ---- Multi-capture / derived evidence wiring (Axiom's four new invariant types) --
//
// All of these disable claim review (SAHW_CLAIM_REVIEW=off) purely to keep the test
// deterministic and hermetic — the claim-review stage is exercised elsewhere; here
// the point is what beat.ts assembles as evidence.captures / evidence.derivedInput
// before calling axiom.evaluate().

test("state_changed: re-observing the SAME resource before/after a mutating action (marker appears) is CONFIRMED", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const marker = "sc-marker-77";
  // A genuine state change: the SAME observation (GET /observe) yields the marker only
  // AFTER the mutating POST /action ran — proving the action changed server state, not
  // that two different requests happen to differ (which would be a read differential).
  let mutated = false;
  const stepFetch = (async (u: string | URL, init?: RequestInit) => {
    const s = String(u);
    if (s.endsWith("/action")) { mutated = true; return new Response("done"); }
    if (s.endsWith("/observe")) return new Response(mutated ? `ok ${marker}` : "ok plain");
    return new Response("ok plain");
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify({
      vuln_class: "business_logic", endpoint: url("observe"),
      invariant: { statement: "resource mutated by the action", type: "state_changed", expression: `appeared:${marker}` },
      steps: [
        { method: "GET", url: url("observe") },   // pre: same resource, no marker yet
        { method: "POST", url: url("action") },   // the mutating action
        { method: "GET", url: url("observe") },   // post: SAME resource, marker now present
      ],
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await TRACED_ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: stepFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].vuln_class, "business_logic");
  assert.equal(out.findings[0].verdict, "CONFIRMED");
});

test("invariant relabel: a state_changed proved on the SAME endpoint with a DIFFERENT body (an input differential, e.g. read id=A then id=B) is recorded as body_contains", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const marker = "victim-pii-42";
  // A read IDOR: same endpoint /account, the marker (victim data) comes back only for
  // the id=B request. The hunter framed it as state_changed appeared:, but pre and
  // post are the SAME url with DIFFERENT bodies — that is a body_contains differential
  // (marker in the exploit body's response, absent in the control's), so it is
  // recorded as body_contains, the invariant the finding actually is.
  const stepFetch = (async (u: string | URL, init?: RequestInit) => {
    const body = String(init?.body ?? "");
    return body.includes("id=B") ? new Response(`data ${marker}`) : new Response("ok plain");
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify({
      vuln_class: "idor", endpoint: url("account"),
      invariant: { statement: "read another user's record", type: "state_changed", expression: `appeared:${marker}` },
      steps: [
        { method: "POST", url: url("account"), body: "id=A" },   // pre/control: own record, same url
        { method: "GET", url: url("noop") },                      // filler middle step (>=3 captures)
        { method: "POST", url: url("account"), body: "id=B" },   // post/exploit: victim record, same url, different body
      ],
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await TRACED_ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: stepFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED", "the input differential still confirms — throughput preserved");
  assert.equal(out.findings[0].invariant_type, "body_contains", "recorded as the body_contains differential it actually is, not state_changed");
});

test("state_violated single_use: a marker reused across 2 steps is CONFIRMED", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const marker = "otp-777";
  const reuseFetch = (async () => new Response(`accepted ${marker}`)) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify({
      vuln_class: "business_logic", endpoint: url("a"),
      invariant: { statement: "one-time code accepted twice", type: "state_violated", expression: `single_use:${marker}` },
      steps: [
        { method: "POST", url: url("verify1") },
        { method: "POST", url: url("verify2") },
      ],
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await TRACED_ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: reuseFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED");
});

test("state_violated single_use: only 1 step is too few and NEEDS_REVIEW, never a guess", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const marker = "otp-778";
  const reuseFetch = (async () => new Response(`accepted ${marker}`)) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify({
      vuln_class: "business_logic", endpoint: url("a"),
      invariant: { statement: "one-time code accepted twice", type: "state_violated", expression: `single_use:${marker}` },
      steps: [{ method: "POST", url: url("verify1") }],
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: reuseFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "NEEDS_REVIEW");
});

test("file_created_then_deleted: absent->present->absent across 3 steps is CONFIRMED", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const marker = "temp-file-99";
  const cycleFetch = (async (u: string | URL) => {
    const s = String(u);
    return s.endsWith("/during") ? new Response(`has ${marker}`) : new Response("clean");
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify({
      vuln_class: "path_traversal", endpoint: url("a"),
      invariant: { statement: "PoC file created then cleaned up", type: "file_created_then_deleted", expression: marker },
      steps: [
        { method: "GET", url: url("before") },
        { method: "GET", url: url("during") },
        { method: "GET", url: url("after") },
      ],
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await TRACED_ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: cycleFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED");
});

test("file_created_then_deleted: still present at the end is a FALSE_POSITIVE, not a pass", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const marker = "temp-file-100";
  const stillThereFetch = (async (u: string | URL) => {
    const s = String(u);
    return s.endsWith("/before") ? new Response("clean") : new Response(`has ${marker}`);
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify({
      vuln_class: "path_traversal", endpoint: url("a"),
      invariant: { statement: "PoC file created then cleaned up", type: "file_created_then_deleted", expression: marker },
      steps: [
        { method: "GET", url: url("before") },
        { method: "GET", url: url("during") },
        { method: "GET", url: url("after") },
      ],
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: stillThereFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "FALSE_POSITIVE");
});

test("derived hs256_weak_key: a candidate key that verifies the JWT is CONFIRMED", async () => {
  const url = "http://10.0.0.1:3000/a";
  const key = "weak-secret-123";
  const b64url = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const signingInput = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user1" })}`;
  const sig = createHmac("sha256", key).update(signingInput).digest("base64url");
  const jwt = `${signingInput}.${sig}`;
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "jwt_weak_key", endpoint: url,
      invariant: { statement: "HS256 token signed with a guessable key", type: "derived", expression: "hs256_weak_key" },
      derived_input: { jwt, candidates: ["wrong-1", key, "wrong-2"] },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await TRACED_ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED");
});

test("derived tls_unavailable: an injected prober reporting no HTTPS is CONFIRMED, and the prober is actually consulted", async () => {
  const url = "http://10.0.0.1:3000/a";
  const consulted: string[] = [];
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "insecure_transport", endpoint: url,
      invariant: { statement: "no HTTPS service reachable", type: "derived", expression: "tls_unavailable" },
      derived_input: { origins: ["https://10.0.0.1:3000"] },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await TRACED_ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
    tlsProber: async (origin: string) => { consulted.push(origin); return false; },
  });
  assert.deepEqual(consulted, ["https://10.0.0.1:3000"]);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED");
});

test("derived tls_unavailable: an injected prober reporting HTTPS reachable is a FALSE_POSITIVE", async () => {
  const url = "http://10.0.0.1:3000/a";
  const consulted: string[] = [];
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({
      vuln_class: "insecure_transport", endpoint: url,
      invariant: { statement: "no HTTPS service reachable", type: "derived", expression: "tls_unavailable" },
      derived_input: { origins: ["https://10.0.0.1:3000"] },
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
    tlsProber: async (origin: string) => { consulted.push(origin); return true; },
  });
  assert.deepEqual(consulted, ["https://10.0.0.1:3000"]);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "FALSE_POSITIVE");
});

test("a denied step in `steps` is refused by the Tether and never reaches fetch", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const outOfScope = "http://evil.example.com:9999/x";
  const fetchedUrls: string[] = [];
  const spyFetch = (async (u: string | URL) => {
    fetchedUrls.push(String(u));
    return new Response("ok");
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: url("a") }),
    say(JSON.stringify({
      vuln_class: "business_logic", endpoint: url("a"),
      invariant: { statement: "state changed", type: "state_changed", expression: "appeared:whatever-marker" },
      steps: [
        { method: "GET", url: url("pre") },
        { method: "GET", url: outOfScope },
        { method: "GET", url: url("post") },
      ],
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: spyFetch, now: NOW,
  });
  assert.ok(!fetchedUrls.includes(outOfScope), "a denied step must never reach fetch");
  assert.equal(out.findings.length, 1);
  assert.notEqual(out.findings[0].verdict, "CONFIRMED");
  assert.equal(out.findings[0].verdict, "NEEDS_REVIEW", "too few captures after the denied step stops the sequence");
});

// ---- Session threading through proof-capture (capture()/runSteps()) --------------
//
// register_account + http_request's `session` arg were already live for the hunter's
// own exploration, but beat.ts's own re-request path — capture() (differential
// exploit/control) and runSteps() (the `steps` evidence-bundle types) — did not
// thread a claim's `session` label, so proof-capture always replayed anonymously
// even for a claim the hunter proved authenticated during exploration. These tests
// exercise the fix: claim.session / step.session reach http_request's own `session`
// arg, which is the ONLY path from a label to real auth material (see
// test/tools.test.ts for that mechanism's own coverage).

test("a claim with session:\"A\" injects A's auth material into the exploit proof-capture request", async () => {
  const url = "http://10.0.0.1:3000/a";
  const sessions = new SessionStore({ maxAccounts: 2 });
  sessions.create({
    credentials: generateDisposableCredentials("A"), authMaterial: "TOKEN-A", authHeaderName: "Authorization",
  });
  let sentAuth: string | undefined;
  const spyFetch = (async (_u: unknown, init?: RequestInit) => {
    sentAuth = (init?.headers as Record<string, string> | undefined)?.["Authorization"];
    return new Response("OK");
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({ ...claim("clickjacking", url), session: "A" })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: spyFetch, now: NOW, sessionStore: sessions,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(sentAuth, "TOKEN-A", "the proof-capture request (not just exploration) must carry session A's token");
});

test("cross-user claim: a setup step under session A and an exploit step under session B each carry their OWN token (the IDOR mechanism)", async () => {
  const url = (p: string) => `http://10.0.0.1:3000/${p}`;
  const marker = "idor-marker-1";
  const sessions = new SessionStore({ maxAccounts: 2 });
  sessions.create({
    credentials: generateDisposableCredentials("A"), authMaterial: "TOKEN-A", authHeaderName: "Authorization",
  });
  sessions.create({
    credentials: generateDisposableCredentials("B"), authMaterial: "TOKEN-B", authHeaderName: "Authorization",
  });
  const authByUrl: Record<string, string | undefined> = {};
  const spyFetch = (async (u: string | URL, init?: RequestInit) => {
    const s = String(u);
    authByUrl[s] = (init?.headers as Record<string, string> | undefined)?.["Authorization"];
    return s.endsWith("/access-as-b") ? new Response(`ok ${marker}`) : new Response("ok plain");
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: url("recon") }),
    say(JSON.stringify({
      vuln_class: "idor", endpoint: url("recon"),
      invariant: { statement: "resource created by A is readable by B", type: "state_changed", expression: `appeared:${marker}` },
      steps: [
        { method: "POST", url: url("create-as-a"), session: "A" },     // setup, under A
        { method: "GET", url: url("baseline") },                       // context, anonymous
        { method: "GET", url: url("access-as-b"), session: "B" },      // exploit, under B
      ],
    })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: spyFetch, now: NOW, sessionStore: sessions,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(authByUrl[url("create-as-a")], "TOKEN-A", "the setup step must carry A's token");
  assert.equal(authByUrl[url("access-as-b")], "TOKEN-B", "the exploit step must carry B's token, never A's");
  assert.notEqual(authByUrl[url("access-as-b")], "TOKEN-A");
});

test("an anonymous claim (no session label) still sends no Authorization header — regression", async () => {
  const url = "http://10.0.0.1:3000/a";
  let sawAuthHeader = false;
  const spyFetch = (async (_u: unknown, init?: RequestInit) => {
    if ((init?.headers as Record<string, string> | undefined)?.["Authorization"]) sawAuthHeader = true;
    return new Response("OK");
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: spyFetch, now: NOW,
  });
  assert.equal(out.findings.length, 1);
  assert.equal(sawAuthHeader, false, "a claim with no session label must never inject auth material");
});

test("a session-threaded claim's auth token never appears in the spine's persisted progress.json", async () => {
  const env = await ENV();
  const url = "http://10.0.0.1:3000/a";
  const sessions = new SessionStore({ maxAccounts: 2 });
  sessions.create({
    credentials: generateDisposableCredentials("A"), authMaterial: "TOP-SECRET-CAPTURE-TOKEN", authHeaderName: "Authorization",
  });
  const okFetch = (async () => new Response("OK")) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({ ...claim("clickjacking", url), session: "A" })),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: okFetch, now: NOW, sessionStore: sessions,
  });
  assert.equal(out.findings.length, 1);
  const raw = await readFile(join(env.SAHW_WORKSPACE!, "spine", "progress.json"), "utf8");
  assert.ok(!raw.includes("TOP-SECRET-CAPTURE-TOKEN"), "the real auth token must never reach the spine's serialized JSON");
});

// ---- Already-proved short-circuit (Gap 2: beats re-proving already-CONFIRMED classes) --
//
// The deterministic backstop is keyed on (class, endpoint): re-claiming the EXACT
// same pair already banked is short-circuited, but the SAME class on a DIFFERENT
// endpoint is a distinct finding (the benchmark scores per class+endpoint) and must
// be allowed through to the Axiom — the loop must not stop at one-per-class.

test("only the EXACT (class, endpoint) re-proof is short-circuited; the same class on a NEW endpoint reaches the Axiom", async () => {
  const env = await TRACED_ENV();
  const urlA = "http://10.0.0.1:3000/a";
  const urlRecon = "http://10.0.0.1:3000/recon";
  const urlB = "http://10.0.0.1:3000/b";

  // Beat 1: bank a real CONFIRMED clickjacking finding on /a, into the spine.
  const script1 = [
    call("http_request", { method: "GET", url: urlA }),
    say(JSON.stringify(claim("clickjacking", urlA))),
    say("Nothing else to report."),
  ];
  const first = await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script1), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].verdict, "CONFIRMED");

  // Beat 2, SAME engagement/workspace: re-claim clickjacking on the ALREADY-PROVED
  // endpoint /a (must be suppressed), and ALSO claim clickjacking on a NEW endpoint
  // /b (must NOT be suppressed — a distinct finding that reaches the target/Axiom).
  const fetchedUrls: string[] = [];
  const spyFetch = (async (u: string | URL) => {
    fetchedUrls.push(String(u));
    return new Response("OK");   // bare response -> a "!header:x-frame-options" claim holds
  }) as unknown as typeof fetch;
  const script2 = [
    call("http_request", { method: "GET", url: urlRecon }),
    say(JSON.stringify(claim("clickjacking", urlA))),   // exact re-proof -> suppressed
    say(JSON.stringify(claim("clickjacking", urlB))),   // new endpoint -> allowed
    say("Nothing else to report."),
  ];
  const client2 = recordingScriptedClient(script2);
  const second = await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: client2, fetchImpl: spyFetch, now: NOW,
  });

  assert.equal(second.already_proved_suppressed, 1, "the exact (clickjacking, /a) re-proof is suppressed");
  assert.ok(!fetchedUrls.includes(urlA), "the already-proved exact pair must never reach the target");
  assert.ok(fetchedUrls.includes(urlB), "the same class on a NEW endpoint MUST reach the Axiom/target");
  assert.ok(
    second.findings.some((f) => f.endpoint === urlB && f.vuln_class === "clickjacking"),
    "the same class on a new endpoint is banked as a distinct finding, not suppressed",
  );

  // Fed back as already-covered, distinct wording from the plain duplicate-in-beat path.
  const sawFeedback = client2.seen.some((params: any) =>
    params.messages.some((m: any) => typeof m.content === "string" && /already CONFIRMED/i.test(m.content)));
  assert.ok(sawFeedback, "the hunter must be told this class is already covered, not silently dropped");
});

test("a claim whose vuln_class is NOT yet proved still reaches the Axiom normally", async () => {
  const url = "http://10.0.0.1:3000/a";
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify(claim("clickjacking", url))),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await TRACED_ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(out.already_proved_suppressed, 0);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED");
});

test("within one beat, the same class on a NEW endpoint is a distinct finding (both banked) — coverage is per (class, endpoint), not per class", async () => {
  const urlA = "http://10.0.0.1:3000/a";
  const urlB = "http://10.0.0.1:3000/b";
  const fetchedUrls: string[] = [];
  const spyFetch = (async (u: string | URL) => {
    fetchedUrls.push(String(u));
    return new Response("OK");   // bare -> "!header:x-frame-options" holds on both
  }) as unknown as typeof fetch;
  const script = [
    call("http_request", { method: "GET", url: urlA }),
    say(JSON.stringify(claim("clickjacking", urlA))),
    say(JSON.stringify(claim("clickjacking", urlB))),
    say("Nothing else to report."),
  ];
  const out = await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script), fetchImpl: spyFetch, now: NOW,
  });
  assert.equal(out.findings.length, 2, "same class on two distinct endpoints = two findings");
  assert.equal(out.already_proved_suppressed, 0, "a different endpoint is not an already-proved re-proof");
  assert.ok(fetchedUrls.includes(urlA) && fetchedUrls.includes(urlB), "both distinct endpoints reach the target");
  const endpoints = out.findings.map((f) => f.endpoint).sort();
  assert.deepEqual(endpoints, [urlA, urlB]);
});

// ---- Brief coverage-breadth discipline (src/brief.ts) -----------------------------
//
// Regression coverage for a real 4-beat run: beats 3-4 spent their whole budget
// RE-PROVING findings already in the spine's `proved` list (a different endpoint,
// same vuln_class), because the old <already_proved> rendering was descriptive
// ("here is what was proved") rather than imperative ("do not do this again,
// here is what to do instead"). These tests assert on the STRENGTHENED brief text
// directly via buildHunterBrief — not through a full runBeat/spine round trip —
// so a regression here fails fast and names exactly which rule regressed.

function briefSection(xml: string, name: string): string {
  const m = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(xml);
  assert.ok(m, `expected a <${name}> section in the brief`);
  return m![1];
}

const BRIEF_EMPTY_STATE: HunterBriefState = {
  attackSurface: [], recoveredIntel: {}, proved: [], attempted: [],
  turnsRemaining: 40, findingsRemaining: 12,
};

test("brief: a spine with proved classes [clickjacking, cors_misconfig] names both as PROVED and presents an OPEN class as the target, in <already_proved>/<coverage_goal>", () => {
  const state: HunterBriefState = {
    ...BRIEF_EMPTY_STATE,
    proved: [
      { vuln_class: "clickjacking", endpoint: "http://10.0.0.1:3000/a", invariant_type: "response_asserted", verdict: "CONFIRMED", finding_id: "SAHW-aaaa1111" },
      { vuln_class: "cors_misconfig", endpoint: "http://10.0.0.1:3000/b", invariant_type: "response_asserted", verdict: "CONFIRMED", finding_id: "SAHW-bbbb2222" },
    ],
  };
  const xml = buildHunterBrief(state);

  const alreadyProved = briefSection(xml, "already_proved");
  assert.match(alreadyProved, /vuln_class="clickjacking"/);
  assert.match(alreadyProved, /vuln_class="cors_misconfig"/);

  const coverageGoal = briefSection(xml, "coverage_goal");
  const openLine = coverageGoal.split("\n").find((l) => /^\s*OPEN classes/.test(l));
  const bankedLine = coverageGoal.split("\n").find((l) => /ALREADY BANKED/.test(l));
  assert.ok(openLine, "coverage_goal must contain an OPEN classes line");
  assert.ok(bankedLine, "coverage_goal must list already-banked (class @ endpoint) pairs");
  // sqli was not proved — it is an OPEN class to prove at least once.
  assert.match(openLine!, /\bsqli\b/);
  assert.doesNotMatch(openLine!, /clickjacking/, "a proved class is not in the OPEN-classes list");
  assert.doesNotMatch(openLine!, /cors_misconfig/, "a proved class is not in the OPEN-classes list");
  // The banked line shows the exact proved pairs (class @ endpoint), which the hunter
  // must not repeat — but the SAME classes on other endpoints remain fair game.
  assert.match(bankedLine!, /clickjacking @ /);
  assert.match(bankedLine!, /cors_misconfig @ /);
  // framing: coverage is per-finding and must invite pursuing other endpoints.
  assert.match(coverageGoal, /other endpoints/i);
});

test("brief: <already_proved> forbids re-proving the EXACT (class, endpoint) pair but invites the same class on OTHER endpoints", () => {
  const state: HunterBriefState = {
    ...BRIEF_EMPTY_STATE,
    proved: [
      { vuln_class: "idor", endpoint: "http://10.0.0.1:3000/api/x", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-cccc3333" },
    ],
  };
  const xml = buildHunterBrief(state);
  const alreadyProved = briefSection(xml, "already_proved");
  // The new per-(class,endpoint) policy: the exact pair is off-limits, but the same
  // class on a DIFFERENT endpoint is a separate finding to pursue.
  assert.match(alreadyProved, /same class on a different endpoint is a new/i);
  assert.match(alreadyProved, /scored per \(class, endpoint\)/i);
  assert.match(alreadyProved, /only the exact\s+pairs listed above are off-limits/i);
});

test("brief: <evidence_discipline> forbids a behaviour claim on a static asset, and <output_contract> forbids a prose/parenthetical vuln_class", () => {
  const xml = buildHunterBrief(BRIEF_EMPTY_STATE);

  const evidenceDiscipline = briefSection(xml, "evidence_discipline");
  assert.match(evidenceDiscipline, /invalid by construction/i);
  assert.match(evidenceDiscipline, /\.js,\s*\.css,\s*\.map,\s*\.png/, "must enumerate static-asset extensions, not just say 'a script'");
  assert.match(evidenceDiscipline, /no server-side logic to violate/i);
  assert.match(evidenceDiscipline, /forbidden/i);

  const outputContract = briefSection(xml, "output_contract");
  assert.match(outputContract, /vuln_class must be exactly one of these snake_case strings/i);
  assert.match(outputContract, /no prose, no\s+parentheses/i);
});

test("a session created during a beat is persisted to the spine as label-only metadata (no token), so a later beat's hunter knows the account exists", async () => {
  const url = "http://10.0.0.1:3000/a";
  const sessions = new SessionStore({ maxAccounts: 2 });
  sessions.create({
    credentials: generateDisposableCredentials("A"), authMaterial: "TOKEN-A", authHeaderName: "Authorization",
  });
  const env = await ENV();  // fresh temp workspace
  const script = [
    call("http_request", { method: "GET", url }),
    say(JSON.stringify({ ...claim("clickjacking", url), session: "A" })),
    say("Nothing else to report."),
  ];
  await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script),
    fetchImpl: (async () => new Response("OK")) as unknown as typeof fetch,
    now: NOW, sessionStore: sessions,
  });
  const raw = await readFile(join(env.SAHW_WORKSPACE!, "spine", "progress.json"), "utf8");
  const spine = JSON.parse(raw);
  // The label and non-secret metadata must be there...
  assert.ok(spine.sessions?.some((s: any) => s.label === "A" && s.has_auth_material === true),
    "session A must be recorded in the spine so the next beat does not re-register it");
  // ...and the token must NOT be anywhere in the written file.
  assert.ok(!/TOKEN-A/.test(raw), "the auth token must never be written to the spine");
});

// ---- Registration phase (Task: "registration is a beat PHASE, not an optional tool") --
//
// OBSERVED PROBLEM: register_account was never called across real beats — accounts=0
// every time — so every authenticated finding (idor, business_logic, jwt, ...) was
// unreachable, even though register_account itself worked and the brief described it.
// The fix has two halves, both exercised here:
//   (a) buildHunterBrief's <account_objective> imperatively names registration THIS
//       BEAT'S FIRST PRIORITY whenever fewer than 2 accounts are known and an
//       AUTHENTICATED_VULN_CLASSES member is still open — and drops that directive
//       once 2 accounts exist.
//   (b) beat.ts's runRegistrationPhase calls register_account ITSELF, through the
//       same Tether-gated ToolRunner path, BEFORE the hunter's first turn, whenever a
//       prior beat's recovered_intel already carries a discovered signup flow.

const SIGNUP_INTEL = {
  signup_url: "http://10.0.0.1:3000/api/signup",
  signup_method: "POST",
  signup_body_template: '{"user":{"username":"{{username}}","email":"{{email}}","password":"{{password}}"}}',
  signup_response_token_path: "token",
  login_url: "",
  login_method: "POST",
  login_body_template: "",
  login_response_token_path: "",
  auth_header_name: "Authorization",
};

test("brief: 0 sessions + open authenticated classes -> <account_objective> imperatively names registration this beat's FIRST PRIORITY", () => {
  const state: HunterBriefState = { ...BRIEF_EMPTY_STATE, sessionsCount: 0, proved: [] };
  const xml = buildHunterBrief(state);
  const section = briefSection(xml, "account_objective");
  assert.match(section, /FIRST PRIORITY/, "must be imperative, not merely descriptive");
  assert.match(section, /register(ing)?\s+TWO\s+disposable\s+accounts/i);
  assert.match(section, /register_account/);
  // Names at least the classes this module judges to require a session.
  assert.match(section, /idor/);
  // And gives a concrete signup-discovery tactic: a login route alone is not "no signup".
  // (Without this, the hunter finds /login and never probes for /signup — observed live.)
  assert.match(section, /sibling/i, "must tell the hunter signup is a sibling of the login route");
  assert.match(section, /grep_artifact/, "must point at searching the bundle for the signup route");
});

test("brief: 2 sessions already known -> <account_objective> DROPS the registration directive and pushes authenticated-class coverage instead", () => {
  const state: HunterBriefState = { ...BRIEF_EMPTY_STATE, sessionsCount: 2, proved: [] };
  const xml = buildHunterBrief(state);
  const section = briefSection(xml, "account_objective");
  assert.doesNotMatch(section, /FIRST PRIORITY/i, "the directive must be gone once 2 accounts exist");
  assert.doesNotMatch(section, /register_account/i);
  assert.match(section, /existing session labels/i, "must push the hunter toward using the sessions already on hand");
});

test("brief: no open authenticated class -> <account_objective> drops the directive even at 0 sessions", () => {
  const state: HunterBriefState = {
    ...BRIEF_EMPTY_STATE, sessionsCount: 0,
    proved: [
      { vuln_class: "idor", endpoint: "x", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-1" },
      { vuln_class: "business_logic", endpoint: "x", invariant_type: "state_changed", verdict: "CONFIRMED", finding_id: "SAHW-2" },
      { vuln_class: "auth_bypass", endpoint: "x", invariant_type: "status_in", verdict: "CONFIRMED", finding_id: "SAHW-3" },
      { vuln_class: "jwt_weak_key", endpoint: "x", invariant_type: "derived", verdict: "CONFIRMED", finding_id: "SAHW-4" },
      { vuln_class: "improper_session_invalidation", endpoint: "x", invariant_type: "response_asserted", verdict: "CONFIRMED", finding_id: "SAHW-5" },
      { vuln_class: "deserialization_rce", endpoint: "x", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-6" },
    ],
  };
  const xml = buildHunterBrief(state);
  const section = briefSection(xml, "account_objective");
  assert.doesNotMatch(section, /FIRST PRIORITY/i, "every authenticated class is already proved — nothing left to gate registration on");
});

test("registration phase: when the signup flow is already known from a prior beat's recovered_intel, the orchestrator calls register_account deterministically, twice, before the hunter's own turn", async () => {
  const env = await ENV();
  const reconUrl = "http://10.0.0.1:3000/recon";

  // Beat 1: the hunter recovers the signup flow and attaches it under "intel"
  // using EXACTLY the generic key names discoveredSignupFlow() (beat.ts) reads
  // back out — mirroring register_account's own tool-schema field names.
  const script1 = [
    call("http_request", { method: "GET", url: reconUrl }),
    say(JSON.stringify({ ...claim("clickjacking", reconUrl), intel: SIGNUP_INTEL })),
    say("Nothing else to report."),
  ];
  const first = await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script1), fetchImpl: bareFetch, now: NOW,
  });
  assert.equal(first.findings.length, 1, "sanity: beat 1 banked the intel-carrying claim");

  // Beat 2, SAME engagement/workspace: the model's own script here NEVER calls
  // register_account or even mentions it — the ONLY way a request can reach
  // SIGNUP_INTEL.signup_url is the orchestrator's own deterministic phase.
  const fetchedUrls: string[] = [];
  const spyFetch = (async (u: string | URL) => {
    const s = String(u);
    fetchedUrls.push(s);
    if (s === SIGNUP_INTEL.signup_url) {
      return new Response(JSON.stringify({ token: "DETERMINISTIC-TOKEN" }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }
    return new Response("OK");
  }) as unknown as typeof fetch;
  const sessions = new SessionStore({ maxAccounts: 2 });
  const script2 = [
    call("http_request", { method: "GET", url: reconUrl }),
    say("Nothing else to report."),
  ];
  await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script2), fetchImpl: spyFetch, now: NOW, sessionStore: sessions,
  });

  const signupCalls = fetchedUrls.filter((u) => u === SIGNUP_INTEL.signup_url).length;
  assert.equal(signupCalls, 2, "the orchestrator itself must call register_account twice (A then B) via the discovered flow");
  assert.equal(sessions.allMeta().length, 2);
  assert.ok(sessions.allMeta().every((m) => m.has_auth_material), "both deterministically-created sessions must have obtained auth material");
  assert.deepEqual(sessions.labels(), ["A", "B"]);
});

test("registration phase: when the signup flow is NOT yet known, no blind registration is attempted, and the brief carries the discovery directive instead", async () => {
  const url = "http://10.0.0.1:3000/recon";
  const fetchedUrls: string[] = [];
  const spyFetch = (async (u: string | URL) => {
    fetchedUrls.push(String(u));
    return new Response("OK");
  }) as unknown as typeof fetch;
  const sessions = new SessionStore({ maxAccounts: 2 });
  const script = [
    call("http_request", { method: "GET", url }),
    say("Nothing else to report."),
  ];
  const client = recordingScriptedClient(script);
  await runBeat({
    env: { ...(await ENV()), SAHW_CLAIM_REVIEW: "off" },
    client, fetchImpl: spyFetch, now: NOW, sessionStore: sessions,
  });
  assert.equal(sessions.allMeta().length, 0, "no account may be created without a discovered signup flow — blind registration is impossible by construction");
  assert.deepEqual(fetchedUrls, [url], "only the hunter's own recon call may reach fetch — no forced/blind signup attempt");
  const systemPrompt = client.seen[0]?.messages?.[0]?.content as string;
  assert.match(systemPrompt, /FIRST PRIORITY/, "the brief must carry the discovery+registration directive instead");
  assert.match(systemPrompt, /register_account/);
});

test("registration phase: a later beat RE-REGISTERS from the persisted recipe because live tokens never persist across beats (only metadata does)", async () => {
  const env = await ENV();
  const reconUrl = "http://10.0.0.1:3000/recon";

  // Beat 0: seed recovered_intel with the discovered signup flow (no registration
  // yet — the flow was not known at the START of this beat).
  const script0 = [
    call("http_request", { method: "GET", url: reconUrl }),
    say(JSON.stringify({ ...claim("clickjacking", reconUrl), intel: SIGNUP_INTEL })),
    say("Nothing else to report."),
  ];
  await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script0), fetchImpl: bareFetch, now: NOW,
  });

  const signupFetch = (async (u: string | URL) => {
    const s = String(u);
    if (s === SIGNUP_INTEL.signup_url) {
      return new Response(JSON.stringify({ token: "TOK" }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("OK");
  }) as unknown as typeof fetch;

  // Beat 1: the flow is now known -> the deterministic phase registers A and B.
  const script1 = [call("http_request", { method: "GET", url: reconUrl }), say("Nothing else to report.")];
  await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script1), fetchImpl: signupFetch, now: NOW,
    sessionStore: new SessionStore({ maxAccounts: 2 }),
  });
  const raw = await readFile(join(env.SAHW_WORKSPACE!, "spine", "progress.json"), "utf8");
  const spineAfterBeat1 = JSON.parse(raw);
  assert.equal(spineAfterBeat1.sessions.length, 2, "sanity: beat 1 must have registered both accounts into the spine");

  // Beat 2: the spine records 2 "usable" sessions from beat 1, but those are
  // METADATA only — the tokens lived in beat 1's in-process store and are gone. So
  // beat 2, starting with a FRESH live session store, MUST re-register from the
  // persisted recipe to obtain live tokens for THIS beat. Gating on the stale spine
  // metadata (the old behavior) left the beat with session labels and no tokens.
  const fetchedUrls: string[] = [];
  const spyFetch = (async (u: string | URL) => {
    const s = String(u);
    fetchedUrls.push(s);
    if (s === SIGNUP_INTEL.signup_url) {
      return new Response(JSON.stringify({ token: "TOK-3" }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("OK");
  }) as unknown as typeof fetch;
  const script2 = [call("http_request", { method: "GET", url: reconUrl }), say("Nothing else to report.")];
  const sessions2 = new SessionStore({ maxAccounts: 2 });
  await runBeat({
    env: { ...env, SAHW_CLAIM_REVIEW: "off" },
    client: recordingScriptedClient(script2), fetchImpl: spyFetch, now: NOW, sessionStore: sessions2,
  });
  assert.ok(fetchedUrls.includes(SIGNUP_INTEL.signup_url), "beat 2 MUST re-register from the recipe — stale spine metadata carries no live token");
  assert.ok(sessions2.allMeta().length >= 1, "beat 2's own live session store must gain live account(s) this beat");
  assert.ok(sessions2.allMeta().some((m) => m.has_auth_material), "the re-registered session must carry a live token this beat");
});
