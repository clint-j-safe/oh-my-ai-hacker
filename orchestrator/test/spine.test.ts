import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadSpine, saveSpine, updateSpine, SPINE_SCHEMA_VERSION, SpineVersionError,
  type Spine, type SpineBeatRecord,
} from "../src/spine.js";

async function tmpWorkspace(): Promise<string> {
  return mkdtemp(join(tmpdir(), "sahw-spine-"));
}

const AUTH_REF = "ENG-1";
const SCOPE = ["http://10.0.0.1:3000"];

const beat = (over: Partial<SpineBeatRecord> = {}): SpineBeatRecord => ({
  beat_id: "b1", started_utc: "2026-09-22T00:00:00Z", ended_utc: "2026-09-22T00:05:00Z",
  findings_banked: 0, stalled: false, reason: null, codename: "quiet-ledger",
  ...over,
});

test("no existing spine yields a fresh spine with schema_version set", async () => {
  const workspace = await tmpWorkspace();
  const out = await loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: SCOPE });
  assert.equal(out.fresh, true);
  assert.equal(out.spine.schema_version, SPINE_SCHEMA_VERSION);
  assert.equal(out.spine.engagement.auth_ref, AUTH_REF);
  assert.deepEqual(out.spine.beats, []);
});

test("a spine for a DIFFERENT engagement is not merged — a fresh one starts and the mismatch is recorded", async () => {
  const workspace = await tmpWorkspace();
  const first = await loadSpine({ workspace, authRef: "ENG-1", scopeOrigins: SCOPE });
  const withBeat = updateSpine(first.spine, { beat: beat({ findings_banked: 2 }) });
  await saveSpine(workspace, withBeat);

  const out = await loadSpine({ workspace, authRef: "ENG-2", scopeOrigins: SCOPE });
  assert.equal(out.fresh, true);
  assert.match(out.freshReason ?? "", /ENG-1/);
  assert.match(out.freshReason ?? "", /ENG-2/);
  // The mismatch must NOT silently inherit ENG-1's prior beats/findings.
  assert.deepEqual(out.spine.beats, []);
  assert.equal(out.spine.counters.total_findings, 0);
  // And the fact is durable, not just logged to stderr: it lands in the returned spine.
  assert.match(out.spine.fresh_reason ?? "", /ENG-1/);
});

test("a spine for a DIFFERENT scope is not merged — a fresh one starts and the mismatch is recorded", async () => {
  const workspace = await tmpWorkspace();
  const first = await loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: ["http://10.0.0.1:3000"] });
  await saveSpine(workspace, updateSpine(first.spine, { beat: beat() }));

  const out = await loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: ["http://10.0.0.2:9000"] });
  assert.equal(out.fresh, true);
  assert.match(out.freshReason ?? "", /10\.0\.0\.1/);
  assert.deepEqual(out.spine.beats, []);
});

test("a corrupt progress.json does not throw — the run continues on a fresh spine", async () => {
  const workspace = await tmpWorkspace();
  await mkdir(join(workspace, "spine"), { recursive: true });
  await writeFile(join(workspace, "spine", "progress.json"), "{ not valid json !!", "utf8");

  const out = await loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: SCOPE });
  assert.equal(out.fresh, true);
  assert.match(out.freshReason ?? "", /corrupt/i);
  assert.equal(out.spine.schema_version, SPINE_SCHEMA_VERSION);
});

test("a structurally malformed but valid-JSON progress.json does not throw and normalizes to safe defaults", async () => {
  const workspace = await tmpWorkspace();
  await mkdir(join(workspace, "spine"), { recursive: true });
  await writeFile(
    join(workspace, "spine", "progress.json"),
    JSON.stringify({
      schema_version: SPINE_SCHEMA_VERSION,
      engagement: { auth_ref: AUTH_REF, scope_origins: SCOPE },
      beats: "nope",              // should have been an array
      attack_surface: null,       // should have been an array
      recovered_intel: "nope",    // should have been an object
    }),
    "utf8",
  );

  const out = await loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: SCOPE });
  assert.equal(out.fresh, false);
  assert.deepEqual(out.spine.beats, []);
  assert.deepEqual(out.spine.attack_surface, []);
  assert.deepEqual(out.spine.recovered_intel, {});
  // Must not throw when a beat is appended afterwards either.
  const next = updateSpine(out.spine, { beat: beat() });
  assert.equal(next.beats.length, 1);
});

test("a newer schema_version is refused rather than misread", async () => {
  const workspace = await tmpWorkspace();
  await mkdir(join(workspace, "spine"), { recursive: true });
  await writeFile(
    join(workspace, "spine", "progress.json"),
    JSON.stringify({
      schema_version: SPINE_SCHEMA_VERSION + 1,
      engagement: { auth_ref: AUTH_REF, scope_origins: SCOPE },
    }),
    "utf8",
  );
  await assert.rejects(
    () => loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: SCOPE }),
    SpineVersionError,
  );
});

test("round trip: save -> load -> the state matches", async () => {
  const workspace = await tmpWorkspace();
  const first = await loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: SCOPE });
  const updated = updateSpine(first.spine, {
    beat: beat({ findings_banked: 1 }),
    discoveredEndpoints: [{ url: "http://10.0.0.1:3000/a", method: "GET", status: 200, content_type: "text/html" }],
    proved: [{ vuln_class: "clickjacking", endpoint: "http://10.0.0.1:3000/a", invariant_type: "response_asserted", verdict: "CONFIRMED", finding_id: "SAHW-1" }],
    attempted: [{ vuln_class: "sqli", endpoint: "http://10.0.0.1:3000/b", invariant_type: "body_contains", outcome: "FALSE_POSITIVE", why: "control matched exploit" }],
  });
  await saveSpine(workspace, updated);

  const reloaded = await loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: SCOPE });
  assert.equal(reloaded.fresh, false);
  assert.deepEqual(reloaded.spine, updated);
});

test("updateSpine merges beats/counters/proved/attempted/attack_surface across calls", () => {
  const base: Spine = {
    schema_version: SPINE_SCHEMA_VERSION,
    engagement: { auth_ref: AUTH_REF, scope_origins: SCOPE },
    beats: [], attack_surface: [], recovered_intel: {}, proved: [], attempted: [],
    counters: { total_beats: 0, total_findings: 0, total_proved: 0, total_attempted: 0 },
    fresh_reason: null,
  };
  const afterBeat1 = updateSpine(base, {
    beat: beat({ beat_id: "b1", findings_banked: 2 }),
    proved: [{ vuln_class: "idor", endpoint: "http://x/a", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-1" }],
  });
  const afterBeat2 = updateSpine(afterBeat1, {
    beat: beat({ beat_id: "b2", findings_banked: 1 }),
    proved: [{ vuln_class: "sqli", endpoint: "http://x/b", invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: "SAHW-2" }],
  });
  assert.equal(afterBeat2.beats.length, 2);
  assert.equal(afterBeat2.counters.total_findings, 3);
  assert.equal(afterBeat2.proved.length, 2);
  assert.equal(afterBeat2.counters.total_proved, 2);
});

// ---- secret redaction -----------------------------------------------------------

test("a secret-looking value handed to recovered_intel is not persisted verbatim", async () => {
  const workspace = await tmpWorkspace();
  const first = await loadSpine({ workspace, authRef: AUTH_REF, scopeOrigins: SCOPE });
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
  const updated = updateSpine(first.spine, {
    beat: beat(),
    recoveredIntel: { auth_header_style: `Bearer ${jwt}` },
  });

  // Not persisted verbatim in the in-memory result either...
  assert.ok(!JSON.stringify(updated).includes(jwt), "sanitized value must not survive in the merged spine object");

  // ...and, more importantly, not in the actual bytes written to disk.
  await saveSpine(workspace, updated);
  const raw = await readFile(join(workspace, "spine", "progress.json"), "utf8");
  assert.ok(!raw.includes(jwt), "the JWT must not appear verbatim in progress.json");
  assert.match(raw, /redacted/);
});

test("secret redaction does not touch attack_surface URLs, which can legitimately contain long opaque segments", () => {
  const base: Spine = {
    schema_version: SPINE_SCHEMA_VERSION,
    engagement: { auth_ref: AUTH_REF, scope_origins: SCOPE },
    beats: [], attack_surface: [], recovered_intel: {}, proved: [], attempted: [],
    counters: { total_beats: 0, total_findings: 0, total_proved: 0, total_attempted: 0 },
    fresh_reason: null,
  };
  const longId = "a".repeat(40);
  const updated = updateSpine(base, {
    beat: beat(),
    discoveredEndpoints: [{ url: `http://10.0.0.1:3000/items/${longId}`, method: "GET", status: 200, content_type: null }],
  });
  assert.equal(updated.attack_surface[0].url, `http://10.0.0.1:3000/items/${longId}`);
});

test("loadRules returns null when rules.md does not exist, and its content when it does", async () => {
  const { loadRules, rulesPath } = await import("../src/spine.js");
  const workspace = await tmpWorkspace();
  assert.equal(await loadRules(workspace), null);
  await mkdir(join(workspace, "spine"), { recursive: true });
  await writeFile(rulesPath(workspace), "- lesson one", "utf8");
  assert.equal(await loadRules(workspace), "- lesson one");
});
