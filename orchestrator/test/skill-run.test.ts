// orchestrator/test/skill-run.test.ts
//
// skill_run: the OpenAI-SDK-compatible dispatcher tool for the pre-built skills, and
// the Tether's egress gate around it. See tether.ts (gate(), SKILL_EGRESS) and
// tools.ts (buildSkillRunTool, ToolRunner.skillRun) for the mechanism under test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn as realSpawn } from "node:child_process";
import { loadEngagement } from "../src/config.js";
import { ArtifactStore } from "../src/artifacts.js";
import { ToolRunner, buildSkillRunTool } from "../src/tools.js";
import { gate, SKILL_EGRESS, type SkillEgress } from "../src/tether.js";
import { runAgent, toolSpanOutput } from "../src/agent.js";

const E = loadEngagement({
  SAHW_SCOPE: "http://10.0.0.1:3000",
  SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z",
  SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
}, new Date("2026-09-22T12:00:00Z"));

const REPO_SKILLS_ROOT = join(process.cwd(), "..", "skills");

/** Writes a self-contained fixture skill directory: scripts/run.py + (optionally)
 * references/artifact.schema.json. `pySource` is the full contents of run.py. */
async function writeFixtureSkill(
  root: string, name: string, pySource: string, schema?: object,
): Promise<string> {
  const dir = join(root, name);
  await mkdir(join(dir, "scripts"), { recursive: true });
  await writeFile(join(dir, "scripts", "run.py"), pySource, "utf8");
  if (schema) {
    await mkdir(join(dir, "references"), { recursive: true });
    await writeFile(join(dir, "references", "artifact.schema.json"), JSON.stringify(schema), "utf8");
  }
  return dir;
}

const OK_SCHEMA = {
  type: "object",
  required: ["items", "status"],
  properties: {
    items: { type: "array" },
    status: { type: "string", enum: ["ok", "error"] },
  },
};

// A large-enough payload (well past agent.ts's SKILL_SUMMARY_MAX_CHARS default of
// 4000) that the Offload-Law bounded-summary assertion below is meaningful — a small
// fixture output could satisfy "sha256 is present" trivially without ever exercising
// truncation.
const OK_PY = `
import json, sys
sys.stdin.read()
items = ["x" * 200 for _ in range(60)]
print(json.dumps({"items": items, "status": "ok"}))
`;

const BAD_SCHEMA_PY = `
import json, sys
sys.stdin.read()
print(json.dumps({"status": "ok"}))
`;  // missing required "items"

const MALFORMED_JSON_PY = `
import sys
sys.stdin.read()
print("not json at all {{{")
`;

const NONZERO_PY = `
import sys
sys.stdin.read()
sys.stderr.write("simulated crash\\n")
sys.exit(3)
`;

const HANG_PY = `
import sys, time
sys.stdin.read()
time.sleep(30)
`;

async function mkStore(): Promise<ArtifactStore> {
  return new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-skillrun-")));
}

// --- Schema shape ----------------------------------------------------------------

test("skill_run schema is strict-mode valid: additionalProperties false, every property required, skill_name carries an enum", () => {
  const tool = buildSkillRunTool(["a-skill", "b-skill"]);
  assert.equal(tool.type, "function");
  const fn = (tool as any).function;
  assert.equal(fn.strict, true);
  const params = fn.parameters;
  assert.equal(params.additionalProperties, false);
  assert.deepEqual([...params.required].sort(), ["input_json", "skill_name"]);
  assert.deepEqual(Object.keys(params.properties).sort(), ["input_json", "skill_name"]);
  assert.equal(params.properties.skill_name.type, "string");
  assert.deepEqual(params.properties.skill_name.enum, ["a-skill", "b-skill"]);
  assert.equal(params.properties.input_json.type, "string");
});

test("the skill_name enum reflects the allowlist and omits skills not on it", () => {
  const tool = buildSkillRunTool(["severity-calibration"]);
  const enumValues = (tool as any).function.parameters.properties.skill_name.enum;
  assert.deepEqual(enumValues, ["severity-calibration"]);
  assert.ok(!enumValues.includes("osv-cve-correlation"));
  assert.ok(!enumValues.includes("adversarial-self-review"));
});

// --- gate(): allowlist, egress, known-tool default-deny ---------------------------

test("gate allows skill_run for a permitted skill and still default-denies an unknown tool name", () => {
  const allowed = gate(E, "skill_run", { skill_name: "severity-calibration" }, ["severity-calibration"]);
  assert.equal(allowed.allow, true);
  const unknownTool = gate(E, "exfiltrate", {}, ["severity-calibration"]);
  assert.equal(unknownTool.allow, false);
});

test("a network-free skill NOT in the caller's required allowlist is denied naming the allowlist, distinct from an egress denial", () => {
  // blast-radius-estimation is genuinely egress:"none" in the production registry (see
  // tether.ts SKILL_EGRESS) but is not part of the REQUIRED phase-1 set
  // (adversarial-self-review, severity-calibration) — this must fail on the ALLOWLIST
  // check, not the egress check, and the reason text must say so.
  assert.equal(SKILL_EGRESS["blast-radius-estimation"], "none");
  const d = gate(E, "skill_run", { skill_name: "blast-radius-estimation" },
    ["adversarial-self-review", "severity-calibration"]);
  assert.equal(d.allow, false);
  if (d.allow) throw new Error("unreachable");
  assert.match(d.reason, /allowlist/i);
  assert.ok(!/egress/i.test(d.reason), "must not read like an egress denial");
});

test("a network-touching skill ON the allowlist is now PERMITTED — egress classification alone no longer denies it", () => {
  // Policy change: an allowlisted skill may run regardless of its egress class; the
  // controls are the allowlist, the input-URL scope gate below, the skill's own
  // scope-gating, and the sandbox. A "target"/"external" skill with no out-of-scope
  // URL in its input_json is allowed.
  assert.equal(SKILL_EGRESS["sqli-database-injection"], "target");
  const d = gate(E, "skill_run",
    { skill_name: "sqli-database-injection", input_json: JSON.stringify({ target_url: "http://10.0.0.1:3000/api/x", parameters: ["id"] }) },
    ["sqli-database-injection"]);
  assert.equal(d.allow, true, "an allowlisted target skill targeting an in-scope URL must run");
});

test("a skill whose input_json names an OUT-OF-SCOPE url is denied by the Tether before it runs (declared-egress scope gate)", () => {
  const d = gate(E, "skill_run",
    { skill_name: "sqli-database-injection", input_json: JSON.stringify({ target_url: "http://evil.example.com/steal", parameters: ["id"] }) },
    ["sqli-database-injection"]);
  assert.equal(d.allow, false, "an out-of-scope target URL in the skill input must be refused");
  if (d.allow) throw new Error("unreachable");
  assert.match(d.reason, /scope/i);
});

test("an ALLOWED network skill still requires the allowlist — egress permission does not bypass it", () => {
  // osv-cve-correlation is "external" and permitted by egress now, but NOT on this
  // caller's allowlist -> still denied, naming the allowlist.
  assert.equal(SKILL_EGRESS["osv-cve-correlation"], "external");
  const d = gate(E, "skill_run", { skill_name: "osv-cve-correlation", input_json: "{}" },
    ["adversarial-self-review", "severity-calibration"]);
  assert.equal(d.allow, false);
  if (d.allow) throw new Error("unreachable");
  assert.match(d.reason, /allowlist/i);
});

test("an unclassified (unknown) skill is denied even if named in the allowlist", () => {
  const d = gate(E, "skill_run", { skill_name: "totally-made-up-skill" }, ["totally-made-up-skill"]);
  assert.equal(d.allow, false);
  if (d.allow) throw new Error("unreachable");
  assert.match(d.reason, /unknown skill/i);
});

// --- Path traversal: rejected before any process is spawned ------------------------

test("a skill_name containing a path separator is rejected as invalid_argument and no process is spawned", async () => {
  let spawnCalled = false;
  const spy = ((...a: Parameters<typeof realSpawn>) => {
    spawnCalled = true;
    return realSpawn(...a);
  }) as typeof realSpawn;

  const r = new ToolRunner({
    engagement: E, store: await mkStore(), spawnImpl: spy,
    skillsRoot: REPO_SKILLS_ROOT,
    skillAllowlist: ["severity-calibration"],
  });
  const out = await r.execute("skill_run", { skill_name: "../severity-calibration", input_json: "{}" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "invalid_argument");
  assert.match(out.denied, /path separator|parent directory/i);
  assert.equal(spawnCalled, false, "no process may be spawned for a malformed skill_name");
});

test("a skill_name containing '..' is rejected as invalid_argument and no process is spawned", async () => {
  let spawnCalled = false;
  const spy = (() => { spawnCalled = true; throw new Error("must not be called"); }) as unknown as typeof realSpawn;

  const r = new ToolRunner({
    engagement: E, store: await mkStore(), spawnImpl: spy,
    skillsRoot: REPO_SKILLS_ROOT,
    skillEgress: { "fixture..skill": "none" },
    skillAllowlist: ["fixture..skill"],
  });
  const out = await r.execute("skill_run", { skill_name: "fixture..skill", input_json: "{}" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "invalid_argument");
  assert.match(out.denied, /parent directory/i);
  assert.equal(spawnCalled, false);
});

// --- Allowlist / egress denials via the executor (not just gate() in isolation) ----

test("ToolRunner.execute denies a skill not on the allowlist with kind policy", async () => {
  const r = new ToolRunner({
    engagement: E, store: await mkStore(), skillsRoot: REPO_SKILLS_ROOT,
    skillAllowlist: ["severity-calibration"],
  });
  const out = await r.execute("skill_run", { skill_name: "adversarial-self-review", input_json: "{}" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "policy");
  assert.match(out.denied, /allowlist/i);
});

test("ToolRunner.execute denies a skill whose input_json names an OUT-OF-SCOPE url (input-URL scope gate), kind policy, and never spawns a process", async () => {
  // New egress policy: an allowlisted network skill runs, but any URL in its
  // input_json is scope-gated exactly like http_request. An out-of-scope target URL
  // must be refused as a policy denial BEFORE any process is spawned — never a real
  // network call, and never the skill's own subprocess.
  let spawned = false;
  const spy = ((...a: Parameters<typeof realSpawn>) => {
    spawned = true;
    return realSpawn(...a);
  }) as typeof realSpawn;
  const r = new ToolRunner({
    engagement: E, store: await mkStore(), skillsRoot: REPO_SKILLS_ROOT,
    skillAllowlist: ["sqli-database-injection"], spawnImpl: spy,
  });
  const out = await r.execute("skill_run", {
    skill_name: "sqli-database-injection",
    input_json: JSON.stringify({ target_url: "http://evil.example.com/steal", parameters: ["id"] }),
  });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "policy");
  assert.match(out.denied, /scope/i);
  assert.equal(spawned, false, "a scope-denied skill must never spawn its subprocess");
});

// --- Fixture skill: success path, Offload Law -----------------------------------

test("a fixture skill that emits valid JSON succeeds, is hashed into the artifact store, and the model-facing result is a bounded summary plus sha256", async () => {
  const skillsRoot = await mkdtemp(join(tmpdir(), "sahw-fixtures-"));
  await writeFixtureSkill(skillsRoot, "fixture-ok", OK_PY, OK_SCHEMA);
  const store = await mkStore();
  const r = new ToolRunner({
    engagement: E, store, skillsRoot,
    skillEgress: { "fixture-ok": "none" },
    skillAllowlist: ["fixture-ok"],
  });

  const out = await r.execute("skill_run", { skill_name: "fixture-ok", input_json: "{}" });
  assert.equal(out.ok, true);
  if (!out.ok) throw new Error(`unreachable: ${JSON.stringify(out)}`);
  const result = out.result as any;
  assert.equal(result.kind, "skill_artifact");
  assert.equal(result.skill_name, "fixture-ok");
  assert.equal(result.exit_code, 0);
  assert.match(result.artifact.sha256, /^[0-9a-f]{64}$/);
  assert.equal(result.output.status, "ok");
  assert.equal(result.output.items.length, 60);

  // The artifact is actually retrievable from the store by its hash.
  const stored = await store.get(result.artifact.sha256);
  const parsedStored = JSON.parse(stored.toString("utf8"));
  assert.equal(parsedStored.status, "ok");

  // Full round-trip through runAgent's forModel() Offload Law: the model only ever
  // sees the tool message content, never ToolRunner's raw result object.
  const script = [
    { choices: [{ message: { role: "assistant", content: null, tool_calls: [
      { id: "c1", type: "function", function: { name: "skill_run", arguments: JSON.stringify({ skill_name: "fixture-ok", input_json: "{}" }) } },
    ] } }], usage: { total_tokens: 5 } },
    { choices: [{ message: { role: "assistant", content: "done" } }], usage: { total_tokens: 5 } },
  ];
  let i = 0;
  const client = { chat: { completions: { create: async () => script[Math.min(i++, script.length - 1)] } } };
  const agentResult = await runAgent({
    client, model: "m", system: "sys", user: "go",
    tools: [buildSkillRunTool(["fixture-ok"])], runner: r, maxTurns: 5, budgetTokens: 1000,
  });
  const toolMsg = agentResult.messages.find((m: any) => m.role === "tool");
  const modelFacing = JSON.parse(toolMsg.content);
  assert.equal(modelFacing.artifact_sha256, result.artifact.sha256);
  assert.equal(modelFacing.truncated, true, "the fixture output is deliberately larger than the summary bound");
  assert.ok(!modelFacing.summary.includes(parsedStored.items[0]) || modelFacing.summary.length < JSON.stringify(parsedStored).length,
    "sanity: the bounded summary must be shorter than the full artifact");
  assert.ok(
    JSON.stringify(modelFacing).length < JSON.stringify(parsedStored).length,
    "the model-facing payload must be smaller than the full artifact",
  );
  // The strongest form of the assertion: the full artifact JSON string must not appear
  // verbatim in what the model was sent.
  assert.ok(
    !JSON.stringify(modelFacing).includes(JSON.stringify(parsedStored)),
    "the full artifact body must not appear in the model-facing result",
  );

  // toolSpanOutput (telemetry) also never carries the artifact body, only bookkeeping.
  const spanOut = toolSpanOutput(out);
  assert.equal(spanOut.skill_name, "fixture-ok");
  assert.equal(spanOut.artifact_sha256, result.artifact.sha256);
  assert.equal(spanOut.validation, "ok");
  assert.ok(!JSON.stringify(spanOut).includes("x".repeat(200)), "the artifact body must never reach telemetry");
});

test("the real severity-calibration skill runs end to end (genuinely network-free)", async () => {
  const store = await mkStore();
  const r = new ToolRunner({
    engagement: E, store, skillsRoot: REPO_SKILLS_ROOT,
    skillAllowlist: ["severity-calibration"],
  });
  const input = {
    verified_findings: [
      { vuln_class: "sqli", id: "F-1", oracle_verifications: 2, data_accessed: "dumped users incl. password hashes", rows_read: 5000 },
    ],
  };
  const out = await r.execute("skill_run", { skill_name: "severity-calibration", input_json: JSON.stringify(input) });
  assert.equal(out.ok, true);
  if (!out.ok) throw new Error(`unreachable: ${JSON.stringify(out)}`);
  const result = out.result as any;
  assert.equal(result.exit_code, 0);
  assert.equal(result.output.findings.length, 1);
  assert.equal(result.output.findings[0].finding_id, "F-1");
  assert.ok(result.output.findings[0].cvss_score > 0);
  assert.match(result.artifact.sha256, /^[0-9a-f]{64}$/);
});

// --- Fixture skill: schema validation failure -------------------------------------

test("a fixture skill whose output fails schema validation returns ONLY the validation error, stores the raw output for forensics, and never surfaces the unvalidated content", async () => {
  const skillsRoot = await mkdtemp(join(tmpdir(), "sahw-fixtures-"));
  await writeFixtureSkill(skillsRoot, "fixture-bad-schema", BAD_SCHEMA_PY, OK_SCHEMA);
  const store = await mkStore();
  const r = new ToolRunner({
    engagement: E, store, skillsRoot,
    skillEgress: { "fixture-bad-schema": "none" },
    skillAllowlist: ["fixture-bad-schema"],
  });

  const out = await r.execute("skill_run", { skill_name: "fixture-bad-schema", input_json: "{}" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "execution_error");
  assert.match(out.denied, /schema validation/i);
  assert.match(out.denied, /missing required property "items"/i);
  // The raw (invalid) stdout must never appear in the failure text itself...
  assert.ok(!out.denied.includes('{"status": "ok"}'), "raw unvalidated content must not surface in the denial");
  // ...but it MUST have been preserved as an artifact for forensics: the denial names
  // a sha256, and that hash is actually retrievable from the store.
  const shaMatch = out.denied.match(/[0-9a-f]{64}/);
  assert.ok(shaMatch, "the denial must name the forensic artifact's sha256");
  const forensic = await store.get(shaMatch![0]);
  assert.match(forensic.toString("utf8"), /"status": "ok"/);
});

test("a fixture skill emitting malformed JSON is execution_error and preserves the raw stdout for forensics", async () => {
  const skillsRoot = await mkdtemp(join(tmpdir(), "sahw-fixtures-"));
  await writeFixtureSkill(skillsRoot, "fixture-malformed", MALFORMED_JSON_PY, OK_SCHEMA);
  const store = await mkStore();
  const r = new ToolRunner({
    engagement: E, store, skillsRoot,
    skillEgress: { "fixture-malformed": "none" },
    skillAllowlist: ["fixture-malformed"],
  });
  const out = await r.execute("skill_run", { skill_name: "fixture-malformed", input_json: "{}" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "execution_error");
  assert.match(out.denied, /malformed json/i);
});

// --- Fixture skill: non-zero exit --------------------------------------------------

test("a fixture skill that exits non-zero is reported as execution_error", async () => {
  const skillsRoot = await mkdtemp(join(tmpdir(), "sahw-fixtures-"));
  await writeFixtureSkill(skillsRoot, "fixture-nonzero", NONZERO_PY, OK_SCHEMA);
  const r = new ToolRunner({
    engagement: E, store: await mkStore(), skillsRoot,
    skillEgress: { "fixture-nonzero": "none" },
    skillAllowlist: ["fixture-nonzero"],
  });
  const out = await r.execute("skill_run", { skill_name: "fixture-nonzero", input_json: "{}" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "execution_error");
  assert.match(out.denied, /exited 3/);
});

// --- Fixture skill: timeout ---------------------------------------------------------

test("a fixture skill that hangs is killed at the timeout and reported as execution_error", async () => {
  const skillsRoot = await mkdtemp(join(tmpdir(), "sahw-fixtures-"));
  await writeFixtureSkill(skillsRoot, "fixture-hang", HANG_PY, OK_SCHEMA);
  const r = new ToolRunner({
    engagement: E, store: await mkStore(), skillsRoot,
    skillEgress: { "fixture-hang": "none" },
    skillAllowlist: ["fixture-hang"],
    skillTimeoutMs: 300,
  });
  const started = Date.now();
  const out = await r.execute("skill_run", { skill_name: "fixture-hang", input_json: "{}" });
  const elapsed = Date.now() - started;
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "execution_error");
  assert.match(out.denied, /timed out/i);
  assert.ok(elapsed < 5000, `must return well within the suite's patience, took ${elapsed}ms`);
});

// --- Malformed input_json / missing skill -------------------------------------------

test("input_json that is not valid JSON is rejected as invalid_argument before any process is spawned", async () => {
  let spawnCalled = false;
  const spy = (() => { spawnCalled = true; throw new Error("must not be called"); }) as unknown as typeof realSpawn;
  const r = new ToolRunner({
    engagement: E, store: await mkStore(), spawnImpl: spy, skillsRoot: REPO_SKILLS_ROOT,
    skillAllowlist: ["severity-calibration"],
  });
  const out = await r.execute("skill_run", { skill_name: "severity-calibration", input_json: "{not json" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "invalid_argument");
  assert.equal(spawnCalled, false);
});

test("a known-in-registry skill missing from the skills root on disk is invalid_argument, not execution_error", async () => {
  const skillsRoot = await mkdtemp(join(tmpdir(), "sahw-empty-"));
  const r = new ToolRunner({
    engagement: E, store: await mkStore(), skillsRoot,
    skillEgress: { "phantom-skill": "none" },
    skillAllowlist: ["phantom-skill"],
  });
  const out = await r.execute("skill_run", { skill_name: "phantom-skill", input_json: "{}" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "invalid_argument");
  assert.match(out.denied, /unknown skill/i);
});

// --- Tether audit span ---------------------------------------------------------------

test("a tether span is emitted for an ALLOW as well as a DENY (via runAgent's tool-call loop)", async () => {
  // startActiveObservation is a no-op without a configured Langfuse exporter in this
  // test environment, so this test cannot inspect exported span data directly (there is
  // no exporter to inspect). What it CAN and does prove: runAgent's loop calls
  // runner.checkGate() for every tool call — allowed or denied — via the same code path
  // that feeds the `tether` span, and that call does not throw or alter tool_calls
  // bookkeeping for either outcome. The pure decision logic itself (allow vs deny,
  // reason content) is exercised directly by the gate() tests above.
  const store = await mkStore();
  const r = new ToolRunner({
    engagement: E, store, skillsRoot: REPO_SKILLS_ROOT,
    skillAllowlist: ["severity-calibration"],
  });

  // checkGate() must reflect ALLOW for a permitted call...
  const allowDecision = r.checkGate("skill_run", { skill_name: "severity-calibration" });
  assert.equal(allowDecision.allow, true);
  // ...and DENY for a call outside the allowlist, with a reason available for the span.
  const denyDecision = r.checkGate("skill_run", { skill_name: "osv-cve-correlation" });
  assert.equal(denyDecision.allow, false);
  if (denyDecision.allow) throw new Error("unreachable");
  assert.ok(denyDecision.reason.length > 0);

  // And the full loop (which emits the `tether` span before the `tool:<name>` span for
  // EVERY call) still produces correct toolCalls/messages bookkeeping for both an
  // allowed and a denied skill_run call in the same run.
  const script = [
    { choices: [{ message: { role: "assistant", content: null, tool_calls: [
      { id: "c1", type: "function", function: { name: "skill_run", arguments: JSON.stringify({ skill_name: "osv-cve-correlation", input_json: "{}" }) } },
    ] } }], usage: { total_tokens: 5 } },
    { choices: [{ message: { role: "assistant", content: "done" } }], usage: { total_tokens: 5 } },
  ];
  let i = 0;
  const client = { chat: { completions: { create: async () => script[Math.min(i++, script.length - 1)] } } };
  const result = await runAgent({
    client, model: "m", system: "sys", user: "go",
    tools: [buildSkillRunTool(["osv-cve-correlation"])], runner: r, maxTurns: 5, budgetTokens: 1000,
  });
  assert.equal(result.toolCalls.length, 1);
  assert.equal(result.toolCalls[0].ok, false, "osv-cve-correlation must still be denied end to end (external egress)");
});
