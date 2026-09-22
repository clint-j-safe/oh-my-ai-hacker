import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, stat, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { ArtifactStore } from "../src/artifacts.js";

async function store() {
  return new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-")));
}

async function storeWithRoot() {
  const root = await mkdtemp(join(tmpdir(), "sahw-"));
  return { store: new ArtifactStore(root), root };
}

test("put returns the sha256 of the content", async () => {
  const s = await store();
  const a = await s.put("hello");
  assert.equal(a.sha256, createHash("sha256").update("hello").digest("hex"));
  // Test with multi-byte string to distinguish byte count from character count.
  const b = await s.put("héllo");
  assert.equal(b.bytes, 6, "multi-byte character should be 6 bytes in UTF-8");
});

test("put is idempotent — file is not rewritten", async () => {
  const s = await store();
  const a = await s.put("same");
  const stat1 = await stat(a.path);
  // Sleep briefly to ensure mtime would differ if file were rewritten.
  await new Promise(resolve => setTimeout(resolve, 1));
  const b = await s.put("same");
  const stat2 = await stat(b.path);
  assert.equal(a.path, b.path, "paths should be identical");
  assert.equal(a.sha256, b.sha256, "hashes should be identical");
  // Compare inode (ino) instead of mtime to avoid platform-specific granularity issues.
  // On POSIX systems, inode is invariant if the file is not replaced.
  assert.equal(stat1.ino, stat2.ino, "inode should be unchanged (file not rewritten)");
});

test("get round-trips the exact bytes", async () => {
  const s = await store();
  const a = await s.put("verbatim \u0000 bytes");
  assert.equal((await s.get(a.sha256)).toString(), "verbatim \u0000 bytes");
});

test("put accepts Uint8Array input", async () => {
  const s = await store();
  const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
  const a = await s.put(data);
  const expected = createHash("sha256").update(data).digest("hex");
  assert.equal(a.sha256, expected);
  assert.equal(a.bytes, 5);
});

test("get round-trips non-ASCII content exactly", async () => {
  const s = await store();
  const nonAscii = "café ☕ 日本語";
  const a = await s.put(nonAscii);
  const retrieved = (await s.get(a.sha256)).toString("utf8");
  assert.equal(retrieved, nonAscii);
});

test("has reports presence without reading", async () => {
  const s = await store();
  const a = await s.put("x");
  assert.equal(await s.has(a.sha256), true);
  assert.equal(await s.has("0".repeat(64)), false);
});

test("has and get agree: invalid hash input is rejected", async () => {
  const s = await store();
  const invalidHash = "not-a-valid-hash";
  // Both should reject invalid hash format.
  await assert.rejects(() => s.has(invalidHash), "has() should reject invalid hash");
  await assert.rejects(() => s.get(invalidHash), "get() should reject invalid hash");
});

test("has rejects empty string (spec failure protection)", async () => {
  const s = await store();
  await assert.rejects(() => s.has(""), "has() should not accept empty string");
});

test("has rejects path traversal attempts", async () => {
  const s = await store();
  await assert.rejects(() => s.has(".."), "has() should reject '..'");
  await assert.rejects(() => s.has("."), "has() should reject '.'");
});

test("get on an unknown hash rejects rather than returning empty", async () => {
  const s = await store();
  await assert.rejects(() => s.get("0".repeat(64)));
});

test("get rejects corrupt artifacts: hash mismatch fails closed", async () => {
  // This test simulates a truncated write from a crash under the previous non-atomic version.
  // A file is planted at the correct content-addressed path with wrong content,
  // and get() must reject it rather than trust it as valid.
  const { store: s, root } = await storeWithRoot();
  const realContent = "the-real-evidence-bytes";
  const realHash = createHash("sha256").update(realContent).digest("hex");
  const corruptContent = "TRUNCATED";

  // Plant the corrupt file directly at the correct content-addressed path.
  const path = join(root, realHash.slice(0, 2), realHash);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, corruptContent);

  // Verify that has() reports it present (it's a cheap existence check).
  assert.equal(await s.has(realHash), true);

  // But get() must reject the corrupt artifact with a hash mismatch error.
  await assert.rejects(
    () => s.get(realHash),
    (err: unknown) => {
      assert(err instanceof Error);
      const msg = err.message;
      // Error message should name both the requested hash and the actual hash.
      assert(msg.includes(realHash), "error should include requested hash");
      assert(msg.includes("Hash mismatch"), "error should mention mismatch");
      return true;
    },
    "get() should reject the corrupt artifact"
  );
});
