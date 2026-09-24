import { test } from "node:test";
import assert from "node:assert/strict";
import { runSweep, renderSweepLeads, type SweepTarget, type SweepPayload, type SendProbe } from "../src/sweep.js";

const targets: SweepTarget[] = [{ endpoint: "http://h/api/contactUs", method: "POST", params: ["name"] }];

const payloads: Record<string, SweepPayload[]> = {
  xss_reflected: [{ payloadClass: "xss_reflected", payload: "<script>sahwX</script>", marker: "sahwX", note: "reflected xss" }],
  ssti: [{ payloadClass: "ssti", payload: "{{7*7}}", computedMarker: "49", note: "ssti eval" }],
  sqli: [{ payloadClass: "sqli", payload: "'", note: "sqli error" }],
  html_injection: [], command_injection: [], path_traversal: [], xxe: [],
};

test("sweep finds a reflected-XSS hit on the canonical endpoint via the injected send", async () => {
  // baseline is benign; the xss payload reflects the canary verbatim.
  const send: SendProbe = async (_t, _p, value) => {
    if (value === null) return { status: 200, body: "thanks for contacting us friend" };
    if (value.includes("sahwX")) return { status: 200, body: "thanks for contacting us <script>sahwX</script>" };
    return { status: 200, body: "thanks for contacting us friend" };
  };
  const hits = await runSweep({ targets, payloadsFor: (c) => payloads[c] ?? [], send, budget: 50 });
  const xss = hits.find((h) => h.vuln_class === "xss_reflected");
  assert.ok(xss && xss.strength === "strong", "reflected xss found as strong");
  assert.equal(xss!.endpoint, "http://h/api/contactUs");
  assert.equal(xss!.observed, "sahwX");
});

test("sweep finds SSTI only when the COMPUTED value returns, and SQLi on an error signature", async () => {
  const send: SendProbe = async (_t, _p, value) => {
    if (value === null) return { status: 200, body: "x" };
    if (value === "{{7*7}}") return { status: 200, body: "result is 49" };
    if (value === "'") return { status: 500, body: "You have an error in your SQL syntax" };
    return { status: 200, body: "x" };
  };
  const hits = await runSweep({ targets, payloadsFor: (c) => payloads[c] ?? [], send, budget: 50 });
  assert.ok(hits.some((h) => h.vuln_class === "ssti" && h.strength === "strong"));
  assert.ok(hits.some((h) => h.vuln_class === "sqli" && h.strength === "strong"));
});

test("sweep respects the probe budget", async () => {
  let calls = 0;
  const send: SendProbe = async () => { calls++; return { status: 200, body: "x" }; };
  await runSweep({ targets, payloadsFor: (c) => payloads[c] ?? [], send, budget: 3 });
  assert.ok(calls <= 3, `budget honored, got ${calls}`);
});

test("renderSweepLeads emits a directive only for strong hits, naming the canonical endpoint", async () => {
  const send: SendProbe = async (_t, _p, value) =>
    value && value.includes("sahwX") ? { status: 200, body: "hi <script>sahwX</script>" } : { status: 200, body: "hi" };
  const hits = await runSweep({ targets, payloadsFor: (c) => payloads[c] ?? [], send, budget: 50 });
  const rendered = renderSweepLeads(hits);
  assert.match(rendered, /sweep_leads/);
  assert.match(rendered, /xss_reflected @ http:\/\/h\/api\/contactUs/);
  assert.equal(renderSweepLeads([]), "");
});
