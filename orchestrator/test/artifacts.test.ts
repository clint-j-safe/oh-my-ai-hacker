import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { ArtifactStore } from "../src/artifacts.js";

async function store() {
  return new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-")));
}

test("put returns the sha256 of the content", async () => {
  const s = await store();
  const a = await s.put("hello");
  assert.equal(a.sha256, createHash("sha256").update("hello").digest("hex"));
  assert.equal(a.bytes, 5);
});

test("put is idempotent — identical content collapses to one path", async () => {
  const s = await store();
  const a = await s.put("same");
  const b = await s.put("same");
  assert.equal(a.path, b.path);
  assert.equal(a.sha256, b.sha256);
});

test("get round-trips the exact bytes", async () => {
  const s = await store();
  const a = await s.put("verbatim \u0000 bytes");
  assert.equal((await s.get(a.sha256)).toString(), "verbatim \u0000 bytes");
});

test("has reports presence without reading", async () => {
  const s = await store();
  const a = await s.put("x");
  assert.equal(await s.has(a.sha256), true);
  assert.equal(await s.has("0".repeat(64)), false);
});

test("get on an unknown hash rejects rather than returning empty", async () => {
  const s = await store();
  await assert.rejects(() => s.get("0".repeat(64)));
});
