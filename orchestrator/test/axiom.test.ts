import { test } from "node:test";
import assert from "node:assert/strict";
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
