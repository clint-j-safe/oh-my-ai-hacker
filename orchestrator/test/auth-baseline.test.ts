import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { authenticatedBaselinePass } from "../src/beat.js";

// Minimal fake ToolRunner: records every http_request it is asked to execute.
function fakeRunner() {
  const calls: Array<Record<string, unknown>> = [];
  const runner = {
    execute: async (_tool: string, args: Record<string, unknown>) => { calls.push(args); return { ok: true, result: {} }; },
  } as any;
  return { runner, calls };
}

async function workspaceWithSurface(surface: unknown[]): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sahw-base-"));
  await mkdir(join(dir, "spine"), { recursive: true });
  await writeFile(join(dir, "spine", "progress.json"), JSON.stringify({ attack_surface: surface }));
  return dir;
}

const canon = (u: string) => u;
const inScope = (u: string) => u.startsWith("https://t");

test("authenticatedBaselinePass fires an authenticated GET for each in-scope, uncaptured GET endpoint — with the session attached", async () => {
  const { runner, calls } = fakeRunner();
  const ws = await workspaceWithSurface([
    { url: "https://t/api/v3/assets", method: "GET" },
    { url: "https://t/api/v3/groups/1/trend", method: "GET" },
  ]);
  const fired = await authenticatedBaselinePass({ runner, workspace: ws, inScope, sessionLabel: "A", canon, alreadyCaptured: new Set(), cap: 150 });
  assert.equal(fired, 2);
  assert.deepEqual(calls.map((c) => c.url).sort(), ["https://t/api/v3/assets", "https://t/api/v3/groups/1/trend"]);
  for (const c of calls) { assert.equal(c.method, "GET"); assert.equal(c.session, "A"); }
});

test("authenticatedBaselinePass is GET-only (no state change), skips out-of-scope and already-captured endpoints, and respects the cap", async () => {
  const { runner, calls } = fakeRunner();
  const ws = await workspaceWithSurface([
    { url: "https://t/api/v3/assets", method: "GET" },        // fire
    { url: "https://t/api/v3/assets/1", method: "DELETE" },   // skip: mutating verb
    { url: "https://t/api/v3/assets/1", method: "POST" },     // skip: mutating verb
    { url: "https://evil/api/v3/x", method: "GET" },          // skip: out of scope
    { url: "https://t/api/v3/already", method: "GET" },        // skip: already captured
  ]);
  const fired = await authenticatedBaselinePass({
    runner, workspace: ws, inScope, sessionLabel: "A", canon,
    alreadyCaptured: new Set(["GET https://t/api/v3/already"]), cap: 150,
  });
  assert.equal(fired, 1);
  assert.deepEqual(calls.map((c) => c.url), ["https://t/api/v3/assets"]);
});

test("authenticatedBaselinePass honors the cap", async () => {
  const { runner, calls } = fakeRunner();
  const surface = Array.from({ length: 10 }, (_, i) => ({ url: `https://t/api/v3/e${i}`, method: "GET" }));
  const ws = await workspaceWithSurface(surface);
  const fired = await authenticatedBaselinePass({ runner, workspace: ws, inScope, sessionLabel: "A", canon, alreadyCaptured: new Set(), cap: 3 });
  assert.equal(fired, 3);
  assert.equal(calls.length, 3);
});

test("authenticatedBaselinePass returns 0 and fires nothing when the spine is missing/empty", async () => {
  const { runner, calls } = fakeRunner();
  const ws = await workspaceWithSurface([]);
  assert.equal(await authenticatedBaselinePass({ runner, workspace: ws, inScope, sessionLabel: "A", canon, alreadyCaptured: new Set(), cap: 150 }), 0);
  assert.equal(await authenticatedBaselinePass({ runner, workspace: join(tmpdir(), "sahw-nonexistent-xyz"), inScope, sessionLabel: "A", canon, alreadyCaptured: new Set(), cap: 150 }), 0);
  assert.equal(calls.length, 0);
});
