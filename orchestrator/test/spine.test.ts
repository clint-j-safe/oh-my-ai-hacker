import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadSpine, saveSpine, updateSpine, collapseRepeatedRuns, SPINE_SCHEMA_VERSION, SpineVersionError,
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
    beats: [], attack_surface: [], recovered_intel: {}, sessions: [], proved: [], attempted: [],
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

// ---- degenerate-URL collapse (prompt-efficiency) --------------------------------

test("collapseRepeatedRuns clips a giant repeated-char run but leaves it legible", () => {
  const url = `http://10.0.0.1:3000/?unix=${"A".repeat(219608)}`;
  const out = collapseRepeatedRuns(url);
  assert.ok(out.length < 100, `expected a compact marker, got ${out.length} chars`);
  assert.ok(out.startsWith("http://10.0.0.1:3000/?unix=AAAAAAAA"), "base + param name + run head preserved");
  assert.ok(out.includes("⟨×219608⟩"), "marker records the true run length");
});

test("collapseRepeatedRuns does NOT touch legitimate high-entropy URLs", () => {
  // A JWT in a query param — long, but no 24x single-char run.
  const jwt = "http://h/cb?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwabcdefghij.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
  assert.equal(collapseRepeatedRuns(jwt), jwt);
  // A run just under threshold (23) is left alone.
  const short = `http://h/?p=${"A".repeat(23)}`;
  assert.equal(collapseRepeatedRuns(short), short);
  // An ordinary route is untouched.
  assert.equal(collapseRepeatedRuns("http://h/api/v1/users/42?sort=name"), "http://h/api/v1/users/42?sort=name");
});

const baseSpine = (): Spine => ({
  schema_version: SPINE_SCHEMA_VERSION,
  engagement: { auth_ref: AUTH_REF, scope_origins: SCOPE },
  beats: [], attack_surface: [], recovered_intel: {}, sessions: [], proved: [], attempted: [],
  counters: { total_beats: 0, total_findings: 0, total_proved: 0, total_attempted: 0 },
  fresh_reason: null,
});

test("collapseRepeatedRuns leaves a broad corpus of REAL-WORLD URLs untouched", () => {
  // Each of these is a legitimate URL a black-box scan genuinely encounters. None
  // contains a run of >=24 identical characters, so every one must pass through
  // byte-for-byte. If any future change to the collapse rule breaks one of these,
  // this test fails loudly — that is the guardrail the user asked for.
  const legit = [
    // JWT (three high-entropy base64url segments)
    "http://h/api?auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    // UUID v4 path segment
    "http://h/users/550e8400-e29b-41d4-a716-446655440000/profile",
    // SHA-256 hex artifact id (64 hex chars)
    "http://h/artifact/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    // AWS S3 presigned URL (signature + credential query params)
    "https://bkt.s3.amazonaws.com/k.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260924%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260924T110000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
    // OAuth-style access token
    "http://h/cb?access_token=ya29.a0AfH6SMBx3n_Qk2vPqLmZ9wTgUvWxYz1234567890abcdefGHIJKLMNOP&token_type=Bearer&expires_in=3599",
    // A long opaque API credential in a query (high-entropy, provider-neutral so it
    // does not trip secret scanners; the point is only that it survives the collapse)
    "http://h/pay?api_key=k7Qm2Rv9Xw4Tz1Bn6Yc8Ld3Fp5Hs0Jg2We4Ru6Ty8Ui0Op",
    // npm integrity (sha512, base64)
    "http://h/pkg?integrity=sha512-bY6fFH6iC9Zs2C2Kr8m1n3oP4qR5sT6uV7wX8yZ0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH7iJ8kL9",
    // Nested / URL-encoded redirect param
    "http://h/login?next=https%3A%2F%2Fapp.example.com%2Fdashboard%3Ftab%3Dsettings%26id%3D42",
    // Cache-busting asset hash + real source map path
    "http://h/static/vendor/bootstrap/dist/css/bootstrap.min.css.map?v=3f9a1c7e2b",
    // A long but ordinary query string (many distinct params)
    "http://h/search?q=black+box+scan&page=3&sort=relevance&filter=open&lang=en&region=us&ref=nav",
    // Base64 image blob passed as a param (high-entropy, no single-char run)
    "http://h/preview?data=iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg",
    // Plain routes
    "http://10.0.0.1:3000/login",
    "http://10.0.0.1:3000/api/v1/orders/42?expand=items",
  ];
  for (const u of legit) {
    assert.equal(collapseRepeatedRuns(u), u, `legitimate URL was altered: ${u.slice(0, 60)}…`);
  }
});

test("updateSpine collapses a fuzzed endpoint URL on write, keeps a normal one intact", () => {
  const base = baseSpine();
  const junk = `http://10.0.0.1:3000/?unix=${"A".repeat(200000)}`;
  const out = updateSpine(base, {
    beat: beat(),
    discoveredEndpoints: [
      { url: junk, method: "GET", status: 200, content_type: "text/html" },
      { url: "http://10.0.0.1:3000/login", method: "POST", status: 200, content_type: "application/json" },
    ],
  });
  const stored = out.attack_surface.map((e) => e.url);
  assert.ok(!JSON.stringify(out).includes("A".repeat(100)), "no giant run survives anywhere in the spine");
  assert.ok(stored.some((u) => u.includes("⟨×200000⟩")), "the fuzzed URL is stored collapsed");
  assert.ok(stored.includes("http://10.0.0.1:3000/login"), "the legitimate URL is stored verbatim");
});

test("updateSpine retroactively cleans an already-bloated attack_surface on next merge", () => {
  const base: Spine = {
    ...baseSpine(),
    attack_surface: [{ url: `http://h/?x=${"B".repeat(150000)}`, method: "GET", status: 200, content_type: null }],
  };
  const out = updateSpine(base, { beat: beat() });
  assert.ok(!JSON.stringify(out).includes("B".repeat(100)), "the pre-existing bloat is clipped on the next write");
  assert.ok(out.attack_surface[0].url.includes("⟨×150000⟩"));
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
    beats: [], attack_surface: [], recovered_intel: {}, sessions: [], proved: [], attempted: [],
    counters: { total_beats: 0, total_findings: 0, total_proved: 0, total_attempted: 0 },
    fresh_reason: null,
  };
  // A realistic long opaque segment is HIGH-ENTROPY (a base64/hex id, a signed
  // token), never 40 identical characters — so it carries no >=24 repeated-char run
  // and the degenerate-run collapse leaves it fully intact. (Using "a".repeat(40) as
  // the placeholder here would have been indistinguishable from a fuzz payload, which
  // is precisely the signature the collapse targets.)
  const longId = "aGVsbG8td29ybGQtb3BhcXVlLT9fLXRva2VuLT1hMmIzYzRkNWU2Zjc";
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
