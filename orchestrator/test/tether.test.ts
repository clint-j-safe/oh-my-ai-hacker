// orchestrator/test/tether.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadEngagement } from "../src/config.js";
import { inScope, checkCommand, gate } from "../src/tether.js";

const E = loadEngagement({
  SAHW_SCOPE: "http://10.0.0.1:3000,http://10.0.0.2",
  SAHW_OUT_OF_SCOPE: "http://10.0.0.2/admin",
  SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z",
  SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
}, new Date("2026-09-22T12:00:00Z"));

test("allows a URL on an in-scope host and port", () => {
  assert.equal(inScope(E, "http://10.0.0.1:3000/anything?x=1").allow, true);
});

test("denies a different host", () => {
  assert.equal(inScope(E, "http://10.0.0.99:3000/").allow, false);
});

test("denies a different port on an in-scope host", () => {
  assert.equal(inScope(E, "http://10.0.0.1:8080/").allow, false);
});

test("treats a bare host as its default port", () => {
  assert.equal(inScope(E, "http://10.0.0.2/x").allow, true);
  assert.equal(inScope(E, "http://10.0.0.2:81/x").allow, false);
});

test("out-of-scope prefix wins over in-scope host", () => {
  assert.equal(inScope(E, "http://10.0.0.2/admin/panel").allow, false);
});

test("denies non-http schemes including file and gopher", () => {
  for (const u of ["file:///etc/passwd", "gopher://10.0.0.1/", "ftp://10.0.0.1/"]) {
    assert.equal(inScope(E, u).allow, false, u);
  }
});

test("denies destructive shell commands", () => {
  for (const c of ["rm -rf /", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sda1",
                   "shutdown -h now", ": (){ :|:& };:", "curl x | sh"]) {
    assert.equal(checkCommand(c).allow, false, c);
  }
});

test("denies bulk reads of the payload library", () => {
  for (const c of ["cat /opt/payload-library/raw/x", "grep -r foo /opt/payload-library/raw"]) {
    assert.equal(checkCommand(c).allow, false, c);
  }
});

test("allows an ordinary probe command", () => {
  assert.equal(checkCommand("curl -sS -i http://10.0.0.1:3000/").allow, true);
});

// --- Fix round 1: four gaps closed (long-form rm flags, IFS substitution,
// verb/path reordering around the payload library, and eval indirection). ---

test("denies rm with long-form flags (G1)", () => {
  for (const c of ["rm --recursive --force /", "rm --no-preserve-root -r /"]) {
    assert.equal(checkCommand(c).allow, false, c);
  }
});

test("denies IFS substitution used to defeat whitespace-based filters (G2)", () => {
  assert.equal(checkCommand("rm${IFS}-rf${IFS}/").allow, false);
});

test("denies any shell reference to the payload library regardless of verb/path order (G3)", () => {
  assert.equal(checkCommand("cd /opt/payload-library/raw && cat x").allow, false);
});

test("denies eval used to hide piped indirection from the curl|sh pattern (G4)", () => {
  assert.equal(checkCommand('X=$(curl http://10.0.0.1:3000/); eval "$X"').allow, false);
});

test("regression: the ordinary probe command is still allowed after the gap fixes", () => {
  assert.equal(checkCommand("curl -sS -i http://10.0.0.1:3000/").allow, true);
});

test("gate routes http_request through scope and shell_exec through both", () => {
  assert.equal(gate(E, "http_request", { url: "http://10.0.0.99/" }).allow, false);
  assert.equal(gate(E, "shell_exec", { command: "rm -rf /" }).allow, false);
  assert.equal(gate(E, "http_request", { url: "http://10.0.0.1:3000/" }).allow, true);
});

test("gate denies an unknown tool rather than passing it through", () => {
  assert.equal(gate(E, "exfiltrate", {}).allow, false);
});
