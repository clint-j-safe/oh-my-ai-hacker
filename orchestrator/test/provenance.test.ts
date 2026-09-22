import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArtifactStore } from "../src/artifacts.js";
import { gateProvenance, type Provenance } from "../src/provenance.js";

async function fixture() {
  const store = new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-")));
  const a = await store.put("verbatim stdout");
  const full: Provenance = {
    utc: "2026-09-22T12:00:00Z",
    langfuseTraceId: "trace-1",
    exploitRequestHash: "b".repeat(64),
    stdoutSha256: a.sha256,
    sandboxId: "sbx-1",
    exitCode: 0,
  };
  return { store, full };
}

test("a complete chain with a CONFIRMED axiom verdict stays CONFIRMED", async () => {
  const { store, full } = await fixture();
  const out = await gateProvenance(full, "CONFIRMED", store);
  assert.equal(out.status, "CONFIRMED");
  assert.deepEqual(out.missing, []);
});

test("any missing field downgrades to NEEDS_REVIEW and names it", async () => {
  const { store, full } = await fixture();
  for (const k of ["langfuseTraceId", "exploitRequestHash", "sandboxId", "exitCode"] as const) {
    const out = await gateProvenance({ ...full, [k]: null }, "CONFIRMED", store);
    assert.equal(out.status, "NEEDS_REVIEW", k);
    assert.ok(out.missing.includes(k), `${k} should be named`);
  }
});

test("a stdout hash absent from the store downgrades — the artifact must exist", async () => {
  const { store, full } = await fixture();
  const out = await gateProvenance({ ...full, stdoutSha256: "c".repeat(64) }, "CONFIRMED", store);
  assert.equal(out.status, "NEEDS_REVIEW");
  assert.ok(out.missing.some((m) => m.includes("stdoutSha256")));
});

test("the gate never upgrades a non-CONFIRMED axiom verdict", async () => {
  const { store, full } = await fixture();
  assert.equal((await gateProvenance(full, "FALSE_POSITIVE", store)).status, "FALSE_POSITIVE");
  assert.equal((await gateProvenance(full, "NEEDS_REVIEW", store)).status, "NEEDS_REVIEW");
});
