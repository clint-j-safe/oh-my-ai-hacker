import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/axiom.js";
import type { HttpCapture } from "../src/tools.js";

const cap = (status: number, body: string): HttpCapture => ({
  request: { method: "GET", url: "http://10.0.0.1:3000/x", headers: {}, body: null },
  response: { status, headers: {}, body },
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
