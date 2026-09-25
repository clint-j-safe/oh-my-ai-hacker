import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSpine, saveSpine, updateSpine, type LoginSequenceShape } from "../src/spine.js";

// Real spine API (no exported serializeSpine/parseSpine or freshSpine): loadSpine
// reads <workspace>/spine/progress.json (returning a fresh in-memory spine when no
// file exists yet), updateSpine is the pure merge step a beat runs before saving,
// and saveSpine/loadSpine is the actual serialize/parse round trip (JSON on disk).
test("login_sequence shape round-trips through save/load (no secrets)", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sahw-spine-login-seq-"));
  try {
    const authRef = "eng-1";
    const scopeOrigins = ["https://t"];

    const { spine } = await loadSpine({ workspace, authRef, scopeOrigins });

    const loginSequence: LoginSequenceShape = {
      login_url: "https://t/api/login",
      content_type: "json",
      identifier_field: "email",
      password_field: "password",
      auth_header_name: "Authorization",
      token_location: "body",
      two_factor: "totp",
    };

    const updated = updateSpine(spine, {
      beat: {
        beat_id: "beat-1",
        started_utc: "2026-09-25T00:00:00.000Z",
        ended_utc: "2026-09-25T00:01:00.000Z",
        findings_banked: 0,
        stalled: false,
        reason: null,
        codename: "test-beat",
      },
      recoveredIntel: { login_sequence: loginSequence },
    });

    await saveSpine(workspace, updated);
    const round = await loadSpine({ workspace, authRef, scopeOrigins });

    assert.deepEqual(round.spine.recovered_intel.login_sequence, loginSequence);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
