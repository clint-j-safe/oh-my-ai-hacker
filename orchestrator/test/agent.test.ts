import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadEngagement } from "../src/config.js";
import { ArtifactStore } from "../src/artifacts.js";
import { ToolRunner, TOOL_SCHEMAS } from "../src/tools.js";
import { runAgent, toolSpanInput, toolSpanOutput } from "../src/agent.js";

const E = loadEngagement({
  SAHW_SCOPE: "http://10.0.0.1:3000", SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z", SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
}, new Date("2026-09-22T12:00:00Z"));

const okFetch = (async () => new Response("OK")) as unknown as typeof fetch;

async function mkRunner() {
  return new ToolRunner({
    engagement: E, fetchImpl: okFetch,
    store: new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-"))),
  });
}

/** Stub client: returns scripted completions, records what it was sent. */
function stub(script: any[]) {
  const seen: any[] = [];
  let i = 0;
  return {
    seen,
    client: { chat: { completions: { create: async (p: any) => { seen.push(p); return script[i++] ?? script[script.length - 1]; } } } },
  };
}

const say = (content: string) => ({ choices: [{ message: { role: "assistant", content } }], usage: { total_tokens: 10 } });
const call = (name: string, args: object) => ({
  choices: [{ message: { role: "assistant", content: null, tool_calls: [
    { id: "c1", type: "function", function: { name, arguments: JSON.stringify(args) } }] } }],
  usage: { total_tokens: 10 },
});

const OPTS = async (client: any, script?: any) => ({
  client, model: "m", system: "sys", user: "go",
  tools: TOOL_SCHEMAS, runner: await mkRunner(), maxTurns: 5, budgetTokens: 1000,
});

test("returns on a terminal assistant message", async () => {
  const { client } = stub([say("done")]);
  const r = await runAgent(await OPTS(client));
  assert.equal(r.stopReason, "done");
  assert.equal(r.turns, 1);
});

test("executes a tool call and feeds the result back", async () => {
  const { client, seen } = stub([call("http_request", { method: "GET", url: "http://10.0.0.1:3000/" }), say("ok")]);
  const r = await runAgent(await OPTS(client));
  assert.equal(r.toolCalls.length, 1);
  assert.equal(r.toolCalls[0].ok, true);
  assert.equal(r.artifacts, 1);
  const last = seen[seen.length - 1];
  assert.ok(last.messages.some((m: any) => m.role === "tool"));
});

test("a denied tool call is fed back as a tool message, not thrown", async () => {
  const { client } = stub([call("http_request", { method: "GET", url: "http://evil.test/" }), say("ok")]);
  const r = await runAgent(await OPTS(client));
  assert.equal(r.toolCalls[0].ok, false);
  assert.equal(r.stopReason, "done");
});

test("stops at maxTurns", async () => {
  const { client } = stub([call("http_request", { method: "GET", url: "http://10.0.0.1:3000/" })]);
  const o = await OPTS(client);
  const r = await runAgent({ ...o, maxTurns: 3 });
  assert.equal(r.stopReason, "max_turns");
  assert.equal(r.turns, 3);
});

test("stops when the token budget is exhausted", async () => {
  const { client } = stub([call("http_request", { method: "GET", url: "http://10.0.0.1:3000/" })]);
  const o = await OPTS(client);
  const r = await runAgent({ ...o, budgetTokens: 15 });
  assert.equal(r.stopReason, "budget");
});

test("passes the tools array and parallel_tool_calls false on every request", async () => {
  const { client, seen } = stub([say("done")]);
  await runAgent(await OPTS(client));
  assert.equal(seen[0].parallel_tool_calls, false);
  assert.equal(seen[0].tools.length, TOOL_SCHEMAS.length);
});

test("a tool call's span output records the offload law: no full body, just body_bytes and artifact_sha256", () => {
  const bigBody = "x".repeat(50_000);
  const out = toolSpanOutput({
    ok: true,
    result: {
      request: { method: "GET", url: "http://10.0.0.1:3000/", headers: {}, body: null },
      response: { status: 200, headers: { "content-type": "text/plain" }, body: bigBody },
      artifact: { sha256: "a".repeat(64) },
      ms: 12,
    },
  });
  assert.equal(out.body_bytes, bigBody.length);
  assert.equal(out.artifact_sha256, "a".repeat(64));
  assert.equal(out.ms, 12);
  const serialized = JSON.stringify(out);
  assert.ok(!serialized.includes(bigBody), "the full body string must never appear in span output");
  assert.ok(!("body" in out), "no raw body field in span output");
  assert.ok(!("body_preview" in out), "no body preview field either — telemetry gets none of the body");
});

test("a read_artifact tool call's span output caps content to content_bytes — no full content string either", () => {
  const bigContent = "y".repeat(50_000);
  const out = toolSpanOutput({ ok: true, result: { content: bigContent } });
  assert.equal(out.content_bytes, bigContent.length);
  assert.ok(!JSON.stringify(out).includes(bigContent), "the full artifact content must never appear in span output");
  assert.ok(!("content" in out), "no raw content field in span output");
});

test("a denied tool call's span output carries its kind and denial reason", () => {
  const out = toolSpanOutput({ ok: false, kind: "policy", denied: "out of scope: http://evil.test/" });
  assert.equal(out.kind, "policy");
  assert.equal(out.denied, "out of scope: http://evil.test/");
});

test("Authorization, Cookie and Set-Cookie header VALUES are redacted but the NAMES survive", () => {
  const input = toolSpanInput({
    method: "GET", url: "http://10.0.0.1:3000/",
    headers: { Authorization: "Bearer super-secret-token", Cookie: "session=abc123", "X-Trace": "keep-me" },
  });
  const headers = (input as any).headers;
  assert.equal(headers.Authorization, "<redacted>");
  assert.equal(headers.Cookie, "<redacted>");
  assert.equal(headers["X-Trace"], "keep-me");
  assert.ok(Object.prototype.hasOwnProperty.call(headers, "Authorization"), "header NAME must survive redaction");
  assert.ok(Object.prototype.hasOwnProperty.call(headers, "Cookie"), "header NAME must survive redaction");
  assert.ok(!JSON.stringify(headers).includes("super-secret-token"), "the secret VALUE must never appear");
  assert.ok(!JSON.stringify(headers).includes("abc123"), "the cookie VALUE must never appear");

  const output = toolSpanOutput({
    ok: true,
    result: {
      request: { method: "GET", url: "http://10.0.0.1:3000/", headers: {}, body: null },
      response: {
        status: 200,
        headers: { "set-cookie": "session=abc123; HttpOnly", "content-type": "text/plain" },
        body: "ok",
      },
      artifact: { sha256: "b".repeat(64) },
      ms: 1,
    },
  });
  const respHeaders = (output as any).headers;
  assert.equal(respHeaders["set-cookie"], "<redacted>");
  assert.equal(respHeaders["content-type"], "text/plain");
  assert.ok(Object.prototype.hasOwnProperty.call(respHeaders, "set-cookie"), "header NAME must survive redaction");
  assert.ok(!JSON.stringify(respHeaders).includes("abc123"), "the cookie VALUE must never appear");
});

// --- grep_artifact wiring ------------------------------------------------------------

test("a grep_artifact tool call's span output records the pattern and match counts but never the matched lines", () => {
  const out = toolSpanOutput(
    {
      ok: true,
      result: {
        matches: [{ line_number: 7, line: "authToken=super-secret-recovered-value", before: [], after: [] }],
        total_matches: 5,
        returned_matches: 1,
        truncated: true,
        total_lines: 900,
      },
    },
    { sha256: "a".repeat(64), pattern: "authToken=\\S+", context: 0, max_matches: 1 },
  );
  assert.equal(out.pattern, "authToken=\\S+");
  assert.equal(out.total_matches, 5);
  assert.equal(out.returned_matches, 1);
  assert.equal(out.truncated, true);
  const serialized = JSON.stringify(out);
  assert.ok(!serialized.includes("super-secret-recovered-value"), "a matched (possibly secret) line must never appear in span output");
  assert.ok(!("matches" in out), "no raw matches array in span output");
});

test("a grep_artifact result reaches the model with its matches intact, unmolested by the generic body-preview truncation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sahw-"));
  const store = new ArtifactStore(dir);
  const grepRunner = new ToolRunner({ engagement: E, store, fetchImpl: okFetch });
  const artifact = await store.put("alpha\nneedle-hit\nomega");

  const { client } = stub([
    call("grep_artifact", { sha256: artifact.sha256, pattern: "needle" }),
    say("ok"),
  ]);
  const o = await OPTS(client);
  const r = await runAgent({ ...o, runner: grepRunner });

  const toolMsg = r.messages.find((m: any) => m.role === "tool");
  const content = JSON.parse(toolMsg.content);
  assert.equal(content.total_matches, 1);
  assert.equal(content.returned_matches, 1);
  assert.equal(content.matches[0].line, "needle-hit");
  assert.equal(content.matches[0].line_number, 2);
});

test("an oversized grep_artifact result (many matches with context) is trimmed by forModel's second bound, keeping accurate totals", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sahw-"));
  const store = new ArtifactStore(dir);
  const grepRunner = new ToolRunner({ engagement: E, store, fetchImpl: okFetch });
  // Near the tool's own GREP_LINE_MAX_CHARS cap (400), repeated many times with wide
  // context — big enough that even after the tool's own bounds, forModel's coarser
  // GREP_RESULT_MAX_CHARS backstop still has to trim it further.
  const longLine = `needle ${"z".repeat(390)}`;
  const lines = Array.from({ length: 200 }, () => longLine);
  const artifact = await store.put(lines.join("\n"));

  const { client } = stub([
    call("grep_artifact", { sha256: artifact.sha256, pattern: "needle", max_matches: 100, context: 10 }),
    say("ok"),
  ]);
  const o = await OPTS(client);
  const r = await runAgent({ ...o, runner: grepRunner });

  const toolMsg = r.messages.find((m: any) => m.role === "tool");
  const content = JSON.parse(toolMsg.content);
  assert.ok(content.matches.length < 100, "forModel must have dropped trailing matches to fit its bound");
  assert.equal(content.truncated, true);
  assert.ok(typeof content.note === "string" && content.note.length > 0, "must explain the extra truncation");
  // The tool itself found a match on every one of the 200 lines, even though far
  // fewer are actually handed to the model — the real total must survive forModel's
  // second trim, not just the tool's own max_matches cap.
  assert.equal(content.total_matches, 200);
});
