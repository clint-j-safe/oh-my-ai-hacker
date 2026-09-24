import { test } from "node:test";
import assert from "node:assert/strict";
import { judgeClaim, INVARIANT_RUBRIC } from "../src/judge.js";
import type { HttpCapture } from "../src/tools.js";

const cap = (status: number, body: string, url = "http://h/x", method = "POST"): HttpCapture => ({
  request: { method, url, headers: {}, body: null },
  response: { status, headers: { "content-type": "text/html" }, body },
  artifact: { sha256: "d".repeat(64) } as any, ms: 1,
});
const inv = (type: any, expression: string) => ({ statement: "s", type, expression });

// stub client returning a scripted judge JSON
function stub(content: string) {
  const seen: any[] = [];
  return { seen, client: { chat: { completions: { create: async (p: any) => { seen.push(p); return { choices: [{ message: { role: "assistant", content } }] }; } } } } };
}

test("judgeClaim is DISABLED (fails open) when no model is configured", async () => {
  const r = await judgeClaim({ client: undefined, model: undefined, vulnClass: "sqli", invariant: inv("body_contains", "root:x"), exploit: cap(200, "root:x:0:0"), control: cap(200, "nope") });
  assert.equal(r.ok, false);
  assert.equal(r.model, "disabled");
});

test("judgeClaim parses a scored verdict, clamps to 0-100, sends the deterministic rubric", async () => {
  const { client, seen } = stub('{"score": 92, "lean": "confirm", "rationale": "marker in exploit, absent in control"}');
  const r = await judgeClaim({ client, model: "judge-m", vulnClass: "path_traversal", invariant: inv("body_contains", "root:x:0:0"), exploit: cap(200, "root:x:0:0:root:/root"), control: cap(200, "File not found") });
  assert.equal(r.ok, true);
  assert.equal(r.score, 92);
  assert.equal(r.lean, "confirm");
  // the exact deterministic rule for the type is put in the prompt (anchored scoring)
  const userMsg = seen[0].messages.find((m: any) => m.role === "user").content;
  assert.ok(userMsg.includes(INVARIANT_RUBRIC.body_contains.slice(0, 30)), "prompt must carry the deterministic rubric");
  assert.ok(userMsg.includes("CONTROL"), "body_contains evidence must include the control");
});

test("judgeClaim tolerates prose-wrapped JSON (reasoning models) and out-of-range scores", async () => {
  const { client } = stub('Here is my assessment.\n{"score": 140, "lean":"weird", "rationale":"x"}\nDone.');
  const r = await judgeClaim({ client, model: "judge-m", vulnClass: "xxe", invariant: inv("body_contains", "PASSWD"), exploit: cap(200, "PASSWD leaked"), control: cap(200, "ok") });
  assert.equal(r.ok, true);
  assert.equal(r.score, 100, "clamped to 100");
  assert.equal(r.lean, "unsure", "unknown lean normalised");
});

test("judgeClaim fails OPEN (ok:false) on an unparseable judge reply", async () => {
  const { client } = stub("no json here at all");
  const r = await judgeClaim({ client, model: "judge-m", vulnClass: "sqli", invariant: inv("body_contains", "m"), exploit: cap(200, "m"), control: cap(200, "n") });
  assert.equal(r.ok, false);
});
