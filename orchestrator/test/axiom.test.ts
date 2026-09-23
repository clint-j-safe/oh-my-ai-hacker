import { test } from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createHmac, randomBytes } from "node:crypto";
import { evaluate } from "../src/axiom.js";
import type { HttpCapture } from "../src/tools.js";

const cap = (status: number, body: string, headers: Record<string, string> = {}): HttpCapture => ({
  request: { method: "GET", url: "http://10.0.0.1:3000/x", headers: {}, body: null },
  response: { status, headers, body },
  artifact: { sha256: "a".repeat(64), path: "/tmp/a", bytes: body.length },
  ms: 1,
});

test("body_contains CONFIRMED only when the control lacks the marker", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "root:x:0:0" },
    cap(200, "root:x:0:0:root:/root"), cap(200, "not found"));
  assert.equal(v.status, "CONFIRMED");
});

test("body_contains is FALSE_POSITIVE when the control also contains the marker", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "error" },
    cap(200, "error here"), cap(200, "error here too"));
  assert.equal(v.status, "FALSE_POSITIVE");
  assert.match(v.reason, /control/i);
});

test("body_contains is FALSE_POSITIVE when the exploit lacks the marker", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "root:x:0:0" },
    cap(200, "nothing"), cap(200, "nothing"));
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("a missing control is NEEDS_REVIEW, never CONFIRMED", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "x" },
    cap(200, "x"), null);
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /control/i);
});

test("status_in CONFIRMED when exploit status is listed and control differs", () => {
  const v = evaluate({ statement: "s", type: "status_in", expression: "200,206" },
    cap(200, ""), cap(404, ""));
  assert.equal(v.status, "CONFIRMED");
});

test("status_in FALSE_POSITIVE when the control shares the status", () => {
  const v = evaluate({ statement: "s", type: "status_in", expression: "200" },
    cap(200, ""), cap(200, ""));
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("an unsupported invariant type escalates rather than guessing", () => {
  const v = evaluate({ statement: "s", type: "derived", expression: "?" }, cap(200, "x"), cap(200, "y"));
  assert.equal(v.status, "NEEDS_REVIEW");
});

test("an empty expression never confirms", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "" },
    cap(200, "anything"), cap(404, ""));
  assert.notEqual(v.status, "CONFIRMED");
});

// --- Gap 1: header visibility ---------------------------------------------------------

test("body_contains CONFIRMED when the marker exists only in a response header", () => {
  // body_contains matches with a plain, case-sensitive substring search against the
  // serialized exchange, and tools.ts stores response header names lower-cased (the
  // WHATWG Headers API does this), so the marker here matches the serialized casing.
  const v = evaluate(
    { statement: "s", type: "body_contains", expression: "x-debug-internal-ip: 10.55.0.7" },
    cap(200, "nothing interesting", { "x-debug-internal-ip": "10.55.0.7" }),
    cap(200, "nothing interesting", {}),
  );
  assert.equal(v.status, "CONFIRMED");
});

test("body_contains FALSE_POSITIVE when the header marker is present in both exploit and control", () => {
  const v = evaluate(
    { statement: "s", type: "body_contains", expression: "x-powered-by: PHP" },
    cap(200, "ok", { "x-powered-by": "PHP" }),
    cap(200, "ok", { "x-powered-by": "PHP" }),
  );
  assert.equal(v.status, "FALSE_POSITIVE");
  assert.match(v.reason, /control/i);
});

test("body_contains still FALSE_POSITIVE for a pure body marker absent from the exploit (unchanged behaviour)", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "root:x:0:0" },
    cap(200, "nothing"), cap(200, "nothing"));
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("header serialization is deterministic regardless of header insertion order", () => {
  // Two captures whose headers carry the exact same logical content, inserted in opposite
  // orders. If serialization were not sorted, these could hash/compare differently and a
  // marker spanning multiple header lines could match one ordering and not the other.
  const headersA: Record<string, string> = {};
  headersA["x-frame-options"] = "DENY";
  headersA["content-type"] = "text/html";

  const headersB: Record<string, string> = {};
  headersB["content-type"] = "text/html";
  headersB["x-frame-options"] = "DENY";

  const exploit = cap(200, "body", headersA);
  const controlOppositeOrder = cap(200, "body", headersB);

  // A marker that only matches when both header lines appear in the expected sorted order
  // (content-type before x-frame-options).
  const v = evaluate(
    { statement: "s", type: "body_contains", expression: "content-type: text/html\nx-frame-options: DENY" },
    exploit,
    cap(200, "body", {}),
  );
  assert.equal(v.status, "CONFIRMED");

  // The "control" here is built with headers inserted in the opposite order but is
  // otherwise identical; serialization must treat it as the same content, so it must also
  // be found (proving determinism), which in turn makes this a FALSE_POSITIVE since the
  // marker would now be in both sides.
  const v2 = evaluate(
    { statement: "s", type: "body_contains", expression: "content-type: text/html\nx-frame-options: DENY" },
    exploit,
    controlOppositeOrder,
  );
  assert.equal(v2.status, "FALSE_POSITIVE");
});

// --- Gap 2: response_asserted -----------------------------------------------------------

test("response_asserted CONFIRMED when the asserted header is present", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "header:x-frame-options" },
    cap(200, "", { "x-frame-options": "DENY" }),
    null,
  );
  assert.equal(v.status, "CONFIRMED");
});

test("response_asserted FALSE_POSITIVE when the asserted-present header is absent", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "header:x-frame-options" },
    cap(200, "", {}),
    null,
  );
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("response_asserted CONFIRMED for !header: when the header is genuinely absent (clickjacking)", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "!header:x-frame-options;!header:content-security-policy" },
    cap(200, "<html></html>", { "content-type": "text/html" }),
    null,
  );
  assert.equal(v.status, "CONFIRMED");
});

test("response_asserted FALSE_POSITIVE for !header: when the header is present", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "!header:x-frame-options" },
    cap(200, "", { "x-frame-options": "SAMEORIGIN" }),
    null,
  );
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("response_asserted CONFIRMED for header:name=substring on a matching value", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "header:access-control-allow-origin=*" },
    cap(200, "", { "access-control-allow-origin": "*" }),
    null,
  );
  assert.equal(v.status, "CONFIRMED");
});

test("response_asserted FALSE_POSITIVE for header:name=substring on a mismatching value", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "header:access-control-allow-origin=*" },
    cap(200, "", { "access-control-allow-origin": "https://trusted.example" }),
    null,
  );
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("response_asserted CONFIRMED for a realistic dangerous CORS combination", () => {
  const v = evaluate(
    {
      statement: "s",
      type: "response_asserted",
      expression: "header:access-control-allow-origin=*;header:access-control-allow-credentials=true",
    },
    cap(200, "", {
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
    }),
    null,
  );
  assert.equal(v.status, "CONFIRMED");
});

test("response_asserted works with control === null (no control needed)", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "header:x-frame-options" },
    cap(200, "", { "x-frame-options": "DENY" }),
    null,
  );
  assert.notEqual(v.status, "NEEDS_REVIEW");
  assert.notEqual(v.status, "BLOCKED");
});

test("response_asserted with an unparseable clause is NEEDS_REVIEW and names the clause", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "header:x-frame-options;bogus-clause-form" },
    cap(200, "", { "x-frame-options": "DENY" }),
    null,
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /bogus-clause-form/);
});

test("response_asserted !header:name=substring is not one of the three grammar forms and is NEEDS_REVIEW, not CONFIRMED", () => {
  // Only three forms are specified: header:name, !header:name, header:name=substring.
  // "!header:name=substring" is none of them, so it must escalate rather than being
  // silently accepted as a negated-equality check (which would make asserting "CORS is
  // not wildcard" via the obvious syntax a guaranteed, unfalsifiable CONFIRMED).
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "!header:x-frame-options=DENY" },
    cap(200, "", { "x-frame-options": "DENY" }),
    null,
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /!header:x-frame-options=DENY/);
});

test("response_asserted FALSE_POSITIVE when one clause of a conjunction fails (ALL must hold)", () => {
  const v = evaluate(
    { statement: "s", type: "response_asserted", expression: "header:content-type;header:x-frame-options" },
    cap(200, "", { "content-type": "text/html" }),
    null,
  );
  assert.equal(v.status, "FALSE_POSITIVE");
  assert.match(v.reason, /x-frame-options/);
});

// =========================================================================================
// derived — the model may only SELECT a registered deriver; it never gets to assert the
// answer itself. inv.expression is exactly the deriver name; typed inputs travel through
// the fourth `evidence` argument (evidence.derivedInput).
// =========================================================================================

function b64u(s: string): string {
  return Buffer.from(s).toString("base64url");
}

// Builds a real compact JWT (header.payload.signature) signed with node:crypto — never a
// pasted token literal — so the deriver is exercised against a genuine HMAC-SHA256
// signature it must actually verify.
function makeHs256Jwt(payload: Record<string, unknown>, key: string): string {
  const header = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64u(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const sig = createHmac("sha256", key).update(signingInput).digest("base64url");
  return `${signingInput}.${sig}`;
}

test("derived hs256_weak_key CONFIRMED when a candidate key verifies the JWT signature", () => {
  const jwt = makeHs256Jwt({ sub: "alice" }, "changeit");
  const v = evaluate(
    { statement: "s", type: "derived", expression: "hs256_weak_key" },
    cap(200, ""), null,
    { derivedInput: { jwt, candidates: ["password", "changeit", "secret"] } },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("derived hs256_weak_key FALSE_POSITIVE when the JWT is signed with a strong key not in the candidate list", () => {
  const strongKey = randomBytes(32).toString("hex");
  const jwt = makeHs256Jwt({ sub: "alice" }, strongKey);
  const v = evaluate(
    { statement: "s", type: "derived", expression: "hs256_weak_key" },
    cap(200, ""), null,
    { derivedInput: { jwt, candidates: ["password", "changeit", "secret"] } },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("derived hs256_weak_key NEEDS_REVIEW when derivedInput is missing", () => {
  const v = evaluate(
    { statement: "s", type: "derived", expression: "hs256_weak_key" },
    cap(200, ""), null,
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /derivedInput/);
});

test("derived aes_cbc_decrypt_matches CONFIRMED when it decrypts to the expected shape", () => {
  const key = randomBytes(16);
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  const ciphertext = Buffer.concat([cipher.update("account_number:9988776655"), cipher.final()]);
  const v = evaluate(
    { statement: "s", type: "derived", expression: "aes_cbc_decrypt_matches" },
    cap(200, ""), null,
    {
      derivedInput: {
        ciphertext: ciphertext.toString("base64"),
        key: key.toString("base64"),
        iv: iv.toString("base64"),
        expectedPattern: "^account_number:\\d+$",
      },
    },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("derived aes_cbc_decrypt_matches FALSE_POSITIVE with the wrong key", () => {
  const key = randomBytes(16);
  const wrongKey = randomBytes(16);
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  const ciphertext = Buffer.concat([cipher.update("account_number:9988776655"), cipher.final()]);
  const v = evaluate(
    { statement: "s", type: "derived", expression: "aes_cbc_decrypt_matches" },
    cap(200, ""), null,
    {
      derivedInput: {
        ciphertext: ciphertext.toString("base64"),
        key: wrongKey.toString("base64"),
        iv: iv.toString("base64"),
        expectedPattern: "^account_number:\\d+$",
      },
    },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("derived jwt_payload_contains CONFIRMED when the named claims are present", () => {
  const jwt = makeHs256Jwt({ sub: "alice", ssn: "078-05-1120", email: "alice@example.com" }, "k");
  const v = evaluate(
    { statement: "s", type: "derived", expression: "jwt_payload_contains" },
    cap(200, ""), null,
    { derivedInput: { jwt, claims: ["ssn", "email"] } },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("derived jwt_payload_contains FALSE_POSITIVE when a named claim is missing", () => {
  const jwt = makeHs256Jwt({ sub: "alice" }, "k");
  const v = evaluate(
    { statement: "s", type: "derived", expression: "jwt_payload_contains" },
    cap(200, ""), null,
    { derivedInput: { jwt, claims: ["ssn"] } },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
  assert.match(v.reason, /ssn/);
});

test("derived tls_unavailable CONFIRMED when the injected prober reports no HTTPS reachable", () => {
  const v = evaluate(
    { statement: "s", type: "derived", expression: "tls_unavailable" },
    cap(200, ""), null,
    { derivedInput: { origins: ["https://a.example", "https://b.example"], prober: () => false } },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("derived tls_unavailable FALSE_POSITIVE when the injected prober reports HTTPS reachable", () => {
  const v = evaluate(
    { statement: "s", type: "derived", expression: "tls_unavailable" },
    cap(200, ""), null,
    {
      derivedInput: {
        origins: ["https://a.example"],
        prober: (origin: string) => origin === "https://a.example",
      },
    },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
  assert.match(v.reason, /a\.example/);
});

test("derived with an unknown deriver name is NEEDS_REVIEW naming it, never a guess", () => {
  const v = evaluate(
    { statement: "s", type: "derived", expression: "made_up_deriver" },
    cap(200, ""), null,
    { derivedInput: { anything: true } },
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /made_up_deriver/);
});

// =========================================================================================
// state_changed — pre/action/post captures plus an expression naming the delta.
// =========================================================================================

test("state_changed CONFIRMED when an appeared: marker shows up between pre and post", () => {
  const v = evaluate(
    { statement: "s", type: "state_changed", expression: "appeared:role=admin" },
    cap(200, ""), null,
    {
      captures: [
        cap(200, "role=user"),
        cap(200, "ok=true"),
        cap(200, "role=admin"),
      ],
    },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("state_changed FALSE_POSITIVE when there is no delta", () => {
  const v = evaluate(
    { statement: "s", type: "state_changed", expression: "appeared:role=admin" },
    cap(200, ""), null,
    {
      captures: [
        cap(200, "role=user"),
        cap(200, "ok=true"),
        cap(200, "role=user"),
      ],
    },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("state_changed NEEDS_REVIEW when restoration is required but no restoration evidence was supplied", () => {
  const v = evaluate(
    { statement: "s", type: "state_changed", expression: "appeared:role=admin" },
    cap(200, ""), null,
    {
      captures: [
        cap(200, "role=user"),
        cap(200, "ok=true"),
        cap(200, "role=admin"),
      ],
      restoration: { required: true, performed: false },
    },
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /restoration/i);
});

test("state_changed CONFIRMED when restoration is required and proof was supplied", () => {
  const v = evaluate(
    { statement: "s", type: "state_changed", expression: "appeared:role=admin" },
    cap(200, ""), null,
    {
      captures: [
        cap(200, "role=user"),
        cap(200, "ok=true"),
        cap(200, "role=admin"),
      ],
      restoration: { required: true, performed: true, proof: cap(200, "role=user") },
    },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("state_changed NEEDS_REVIEW when fewer than 3 captures are supplied", () => {
  const v = evaluate(
    { statement: "s", type: "state_changed", expression: "appeared:role=admin" },
    cap(200, ""), null,
    { captures: [cap(200, "a"), cap(200, "b")] },
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /3 ordered captures/);
});

// =========================================================================================
// state_violated — a rule that must hold across a sequence is broken.
// =========================================================================================

test("state_violated single_use CONFIRMED when the marker is accepted more than once", () => {
  const v = evaluate(
    { statement: "s", type: "state_violated", expression: "single_use:otp-229104-accepted" },
    cap(200, ""), null,
    {
      captures: [
        cap(200, "otp-229104-accepted"),
        cap(200, "otp-229104-accepted"),
      ],
    },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("state_violated single_use FALSE_POSITIVE when the marker is accepted at most once", () => {
  const v = evaluate(
    { statement: "s", type: "state_violated", expression: "single_use:otp-229104-accepted" },
    cap(200, ""), null,
    {
      captures: [
        cap(200, "otp-229104-accepted"),
        cap(400, "otp already used"),
      ],
    },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("state_violated single_use NEEDS_REVIEW when fewer than 2 captures are supplied", () => {
  const v = evaluate(
    { statement: "s", type: "state_violated", expression: "single_use:otp-229104-accepted" },
    cap(200, ""), null,
    { captures: [cap(200, "otp-229104-accepted")] },
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /at least 2/);
});

test("state_violated lockout_absent CONFIRMED when 5 attempts never produce the lockout status", () => {
  const v = evaluate(
    { statement: "s", type: "state_violated", expression: "lockout_absent:429" },
    cap(200, ""), null,
    { captures: Array.from({ length: 5 }, () => cap(401, "bad credentials")) },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("state_violated lockout_absent FALSE_POSITIVE when the lockout status appears", () => {
  const v = evaluate(
    { statement: "s", type: "state_violated", expression: "lockout_absent:429" },
    cap(200, ""), null,
    {
      captures: [
        cap(401, "bad credentials"),
        cap(401, "bad credentials"),
        cap(401, "bad credentials"),
        cap(401, "bad credentials"),
        cap(429, "locked out"),
      ],
    },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("state_violated lockout_absent NEEDS_REVIEW when fewer than 5 attempts are supplied", () => {
  const v = evaluate(
    { statement: "s", type: "state_violated", expression: "lockout_absent:429" },
    cap(200, ""), null,
    { captures: [cap(401, "bad credentials"), cap(401, "bad credentials")] },
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /at least 5/);
});

// =========================================================================================
// file_created_then_deleted — absent -> present -> absent.
// =========================================================================================

test("file_created_then_deleted CONFIRMED for absent -> present -> absent", () => {
  const v = evaluate(
    { statement: "s", type: "file_created_then_deleted", expression: "poc-marker-7f3a" },
    cap(200, ""), null,
    {
      captures: [
        cap(404, "not found"),
        cap(200, "poc-marker-7f3a"),
        cap(404, "not found"),
      ],
    },
  );
  assert.equal(v.status, "CONFIRMED");
});

test("file_created_then_deleted FALSE_POSITIVE naming 'still present at the end' when cleanup did not happen", () => {
  const v = evaluate(
    { statement: "s", type: "file_created_then_deleted", expression: "poc-marker-7f3a" },
    cap(200, ""), null,
    {
      captures: [
        cap(404, "not found"),
        cap(200, "poc-marker-7f3a"),
        cap(200, "poc-marker-7f3a"),
      ],
    },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
  assert.match(v.reason, /still present at the end/);
});

test("file_created_then_deleted FALSE_POSITIVE naming 'present throughout' when the marker always existed", () => {
  const v = evaluate(
    { statement: "s", type: "file_created_then_deleted", expression: "poc-marker-7f3a" },
    cap(200, ""), null,
    {
      captures: [
        cap(200, "poc-marker-7f3a"),
        cap(200, "poc-marker-7f3a"),
        cap(200, "poc-marker-7f3a"),
      ],
    },
  );
  assert.equal(v.status, "FALSE_POSITIVE");
  assert.match(v.reason, /present throughout/);
});

test("file_created_then_deleted NEEDS_REVIEW when captures are missing or not exactly 3", () => {
  const v = evaluate(
    { statement: "s", type: "file_created_then_deleted", expression: "poc-marker-7f3a" },
    cap(200, ""), null,
    { captures: [cap(404, "not found"), cap(200, "poc-marker-7f3a")] },
  );
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /exactly 3/);
});
