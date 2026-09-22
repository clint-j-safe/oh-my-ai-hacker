import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type OpenAI from "openai";
import { loadEngagement } from "../src/config.js";
import { ArtifactStore } from "../src/artifacts.js";
import { ToolRunner, TOOL_SCHEMAS } from "../src/tools.js";

const E = loadEngagement({
  SAHW_SCOPE: "http://10.0.0.1:3000",
  SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z",
  SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
}, new Date("2026-09-22T12:00:00Z"));

async function runner(fetchImpl?: typeof fetch) {
  return new ToolRunner({
    engagement: E,
    store: new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-"))),
    fetchImpl,
  });
}

const okFetch = (async () => new Response("BODY-OK", {
  status: 200, headers: { "content-type": "text/plain" },
})) as unknown as typeof fetch;

test("tool schemas are in chat.completions shape with required fields", () => {
  assert.ok(TOOL_SCHEMAS.length >= 2);
  for (const t of TOOL_SCHEMAS) {
    assert.equal(t.type, "function");
    assert.ok(t.function.name && t.function.description && t.function.parameters);
  }
  // Note: the installed `openai` SDK's ChatCompletionTool is a union of function-tool and
  // custom-tool shapes (a newer shape than the brief's snippet assumed), so `.find()`
  // needs a type predicate to narrow back to the function-tool member before `.function`
  // is accessible. This is a type-level fix only; the runtime assertions are unchanged.
  const http = TOOL_SCHEMAS.find(
    (t): t is OpenAI.Chat.ChatCompletionFunctionTool =>
      t.type === "function" && t.function.name === "http_request",
  );
  assert.deepEqual((http!.function.parameters as any).required, ["method", "url"]);
});

test("http_request captures request and response and stores an artifact", async () => {
  const r = await runner(okFetch);
  const sentHeaders = { "x-test-header": "abc123" };
  const sentBody = "hello-body";
  const out = await r.execute("http_request", {
    method: "POST",
    url: "http://10.0.0.1:3000/x",
    headers: sentHeaders,
    body: sentBody,
  });
  assert.equal(out.ok, true);
  if (!out.ok) throw new Error("unreachable");
  const cap = out.result as any;
  // Request half — asserted explicitly. Previously this test only checked the response
  // half and the artifact hash format, so `capture.request` could have been `{}` (or
  // otherwise wrong) and every assertion here would still have passed; "captures request
  // AND response" was met in code but unverified. A dropped/mangled request half would
  // be an evidence-integrity defect (the artifact is supposed to be the verbatim
  // exchange), so pin it directly.
  assert.equal(cap.request.method, "POST");
  assert.equal(cap.request.url, "http://10.0.0.1:3000/x");
  assert.equal(cap.request.headers["x-test-header"], "abc123");
  assert.equal(cap.request.body, sentBody);
  // Response half.
  assert.equal(cap.response.status, 200);
  assert.equal(cap.response.body, "BODY-OK");
  assert.match(cap.artifact.sha256, /^[0-9a-f]{64}$/);
});

test("a 3xx response is captured verbatim and NOT auto-followed", async () => {
  // What this test can and cannot prove, honestly stated:
  // - `lastOptions?.redirect === "manual"` is the load-bearing assertion. It pins that
  //   ToolRunner actually asks the transport for manual redirect handling instead of
  //   relying on the WHATWG default ("follow"). Delete `redirect: "manual"` from
  //   tools.ts and THIS assertion fails.
  // - `status === 302` / `headers["location"] === ...` prove a 3xx is captured usefully
  //   (status + Location visible), not silently discarded or swallowed.
  // - `callCount === 1` is shape-only here: `redirectFetch` is a hand-written mock that
  //   never follows anything regardless of what `options.redirect` says, so this
  //   assertion cannot fail no matter what ToolRunner passes. It does NOT demonstrate
  //   "the redirect target was never contacted" — that property depends on undici's
  //   real behaviour under `redirect: "manual"`, which cannot be exercised here without
  //   a real network call (forbidden by this project's test constraints). That real
  //   no-follow behaviour was verified empirically against a local 302 server by the
  //   reviewer who requested this fix (see the fix-round report addendum), not by this
  //   test suite.
  let callCount = 0;
  let lastOptions: RequestInit | undefined;
  const redirectFetch = (async (_url: unknown, options?: RequestInit) => {
    callCount++;
    lastOptions = options;
    return new Response("moved", {
      status: 302,
      headers: { Location: "http://evil.test/reached" },
    });
  }) as unknown as typeof fetch;

  const r = await runner(redirectFetch);
  const out = await r.execute("http_request", { method: "GET", url: "http://10.0.0.1:3000/redirect" });
  assert.equal(out.ok, true);
  if (!out.ok) throw new Error("unreachable");
  const cap = out.result as any;
  assert.equal(cap.response.status, 302);
  // The Headers API lower-cases header names on iteration.
  assert.equal(cap.response.headers["location"], "http://evil.test/reached");
  assert.equal(callCount, 1, "the redirect target must not be auto-followed");
  assert.equal(lastOptions?.redirect, "manual", "ToolRunner must request manual redirect handling");
});

test("http_request is denied out of scope and never calls fetch", async () => {
  let called = false;
  const spy = (async () => { called = true; return new Response(""); }) as unknown as typeof fetch;
  const r = await runner(spy);
  const out = await r.execute("http_request", { method: "GET", url: "http://evil.test/" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "policy");
  assert.match(out.denied, /not in SAHW_SCOPE/);
  assert.equal(called, false, "fetch must not run when the Tether denies");
});

test("shell_exec is denied for destructive commands without executing", async () => {
  const r = await runner(okFetch);
  const out = await r.execute("shell_exec", { command: "rm -rf /" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "policy");
  assert.match(out.denied, /destructive/);
});

test("an unknown tool is denied by policy, not silently ignored via the no-executor fallback", async () => {
  const r = await runner(okFetch);
  const out = await r.execute("exfiltrate", {});
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  // Must be "policy" (gate()'s own default-deny for an unrecognized tool name), not
  // "no_executor" (ToolRunner's fallback for a tool gate() ALLOWED but has no dispatch
  // branch for). If gate()'s unknown-tool default-deny were ever deleted, execute()'s
  // own "no executor" fallback would still produce ok:false with SOME message — so
  // `assert.equal(out.ok, false)` alone cannot tell "the Tether denied it" apart from
  // "the Tether waved it through and ToolRunner happened to have nothing to run".
  // Pinning kind === "policy" is what actually proves the Tether's default-deny ran.
  assert.equal(out.kind, "policy");
});

test("a tool the Tether allows but ToolRunner has no executor for reports kind: no_executor", async () => {
  // Complements the unknown-tool test above: this exercises the OTHER branch that can
  // also return ok:false — a tool name gate() recognizes and allows (shell_exec with a
  // non-destructive command passes checkCommand()) but for which ToolRunner has no
  // dispatch branch. Without this test, "no_executor" was a type-level literal with no
  // test ever actually reaching it.
  const r = await runner(okFetch);
  const out = await r.execute("shell_exec", { command: "echo hello" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "no_executor");
  assert.match(out.denied, /no executor/);
});

test("identical responses collapse to one artifact", async () => {
  const r = await runner(okFetch);
  const a = await r.execute("http_request", { method: "GET", url: "http://10.0.0.1:3000/a" });
  const b = await r.execute("http_request", { method: "GET", url: "http://10.0.0.1:3000/a" });
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  if (!a.ok || !b.ok) throw new Error("unreachable");
  assert.equal((a.result as any).artifact.sha256, (b.result as any).artifact.sha256);
});

test("exchanges differing only in a request header produce different artifact hashes", async () => {
  // The dangerous direction of content-addressing to get wrong: two DISTINCT exchanges
  // sharing one artifact would let a finding cite evidence that is not its own. The
  // collapsing test above only proves identical requests collapse; it says nothing about
  // whether a near-identical-but-different request would wrongly collapse too.
  const r = await runner(okFetch);
  const a = await r.execute("http_request", {
    method: "GET", url: "http://10.0.0.1:3000/same-path", headers: { "x-tag": "one" },
  });
  const b = await r.execute("http_request", {
    method: "GET", url: "http://10.0.0.1:3000/same-path", headers: { "x-tag": "two" },
  });
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  if (!a.ok || !b.ok) throw new Error("unreachable");
  assert.notEqual((a.result as any).artifact.sha256, (b.result as any).artifact.sha256);
});

test("exchanges differing only in request body produce different artifact hashes", async () => {
  const r = await runner(okFetch);
  const a = await r.execute("http_request", {
    method: "POST", url: "http://10.0.0.1:3000/same-path", body: "one",
  });
  const b = await r.execute("http_request", {
    method: "POST", url: "http://10.0.0.1:3000/same-path", body: "two",
  });
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  if (!a.ok || !b.ok) throw new Error("unreachable");
  assert.notEqual((a.result as any).artifact.sha256, (b.result as any).artifact.sha256);
});

// --- Strengthened / additional coverage beyond the brief's baseline ---

test("http_request never calls fetch for an out-of-scope request (network-touch assertion, not just ok flag)", async () => {
  // Distinct from the baseline out-of-scope test: this drives multiple distinct denied
  // shapes (bad host, out-of-scope path) through the same spy so the "fetch never runs"
  // property can't pass by accident of one particular denial reason.
  for (const url of ["http://evil.test/", "https://10.0.0.1:9999/nope"]) {
    let called = false;
    const spy = (async () => { called = true; return new Response(""); }) as unknown as typeof fetch;
    const r = await runner(spy);
    const out = await r.execute("http_request", { method: "GET", url });
    assert.equal(out.ok, false, `expected denial for ${url}`);
    if (out.ok) throw new Error("unreachable");
    assert.equal(out.kind, "policy", `expected a policy denial for ${url}`);
    assert.equal(called, false, `fetch must not run for ${url}`);
  }
});

test("denied http_request writes no artifact to the store", async () => {
  // A denial that still left an artifact behind would be a silent capture of
  // out-of-scope traffic. Assert the store stays empty, not just that ok is false.
  let called = false;
  const spy = (async () => { called = true; return new Response("x"); }) as unknown as typeof fetch;
  const dir = await mkdtemp(join(tmpdir(), "sahw-"));
  const store = new ArtifactStore(dir);
  const r = new ToolRunner({ engagement: E, store, fetchImpl: spy });
  const out = await r.execute("http_request", { method: "GET", url: "http://evil.test/" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "policy");
  assert.equal(called, false);
  // No artifact directory should have been created by this call.
  const { readdir } = await import("node:fs/promises");
  const entries = await readdir(dir);
  assert.equal(entries.length, 0, "no fan-out directory should exist after a denied request");
});

test("shell_exec destructive commands are denied with a destructive reason across several command shapes", async () => {
  // Note: ToolRunner has no shell executor implemented at all (only http_request and
  // read_artifact have branches in execute()), so this test cannot and does not claim to
  // verify "no shell hook ran" — there is no hook to run. What it verifies is that
  // gate()'s destructive-command denial reaches the caller through ToolRunner's own
  // { ok:false, denied } shape, consistently, across several distinct destructive
  // command patterns (not just one regex match).
  const r = await runner(okFetch);
  for (const command of ["rm -rf /", "rm --recursive --force /", "dd if=/dev/zero of=/dev/sda"]) {
    const out = await r.execute("shell_exec", { command });
    assert.equal(out.ok, false, `expected denial for: ${command}`);
    if (out.ok) throw new Error("unreachable");
    assert.equal(out.kind, "policy", `expected a policy denial for: ${command}`);
    assert.match(out.denied, /destructive/, `expected destructive reason for: ${command}`);
  }
});

test("read_artifact denies a malformed sha256 via the upfront format check, not just the store's throw", async () => {
  const r = await runner(okFetch);
  // Not 64 hex chars — must not be handed raw to ArtifactStore.get(), which throws on
  // a non-canonical hash. Assert the SPECIFIC message from ToolRunner's own upfront
  // CANONICAL_SHA256 check ("invalid sha256: ..."), which is distinct from
  // ArtifactStore's own message ("Invalid SHA-256 hash: ..."). This pins the upfront
  // validation itself — deleting it and relying solely on the catch-all try/catch
  // around store.get() would still pass a weaker assertion that only checked
  // `out.denied` was truthy, but would fail this one.
  const out = await r.execute("read_artifact", { sha256: "not-a-hash" });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "execution_error");
  assert.match(out.denied, /invalid sha256/i);
});

test("read_artifact denies a well-formed but unknown sha256 via the store's not-found error", async () => {
  const r = await runner(okFetch);
  const fakeButCanonical = "a".repeat(64);
  const out = await r.execute("read_artifact", { sha256: fakeButCanonical });
  assert.equal(out.ok, false);
  if (out.ok) throw new Error("unreachable");
  assert.equal(out.kind, "execution_error");
  // This is the ArtifactStore.get() -> readFile ENOENT path, caught by ToolRunner's
  // try/catch and reported as "tool execution error: ...ENOENT...". Distinguishing this
  // from the malformed-hash case (asserted above) proves the two failure paths are both
  // actually exercised, not just that one of them happens to satisfy a loose assertion.
  assert.match(out.denied, /ENOENT|no such file/i);
});

test("read_artifact round-trips content actually written by http_request", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sahw-"));
  const store = new ArtifactStore(dir);
  const r = new ToolRunner({ engagement: E, store, fetchImpl: okFetch });
  const put = await r.execute("http_request", { method: "GET", url: "http://10.0.0.1:3000/y" });
  assert.equal(put.ok, true);
  if (!put.ok) throw new Error("unreachable");
  const sha256 = (put.result as any).artifact.sha256 as string;
  const out = await r.execute("read_artifact", { sha256 });
  assert.equal(out.ok, true);
  if (!out.ok) throw new Error("unreachable");
  const content = (out.result as any).content as string;
  assert.match(content, /BODY-OK/);
});
