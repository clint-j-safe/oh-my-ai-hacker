import { test } from "node:test";
import assert from "node:assert/strict";
import { diffResponses, classifySignal, classifySqlSignal, type FuzzProbe } from "../src/fuzz.js";

const R = (status: number, body: string, ms = 0) => ({ status, body, ms });

test("diffResponses reports a new reflection when the canary appears only in the candidate", () => {
  const probe: FuzzProbe = { payloadClass: "xss_reflected", payload: "<script>sahwXR1</script>", marker: "sahwXR1" };
  const s = diffResponses(R(200, "hello world"), R(200, "hello <script>sahwXR1</script>"), probe);
  assert.deepEqual(s.newReflections, ["sahwXR1"]);
  assert.ok(s.bodySimilarity < 1);
});

test("classifySignal: reflected canary -> strong for xss/html-injection/dom", () => {
  for (const cls of ["xss_reflected", "xss_stored", "html_injection", "dom_xss"]) {
    const probe: FuzzProbe = { payloadClass: cls, payload: "X", marker: "sahwM" };
    const strong = diffResponses(R(200, "base"), R(200, "base sahwM"), probe);
    assert.equal(classifySignal(strong, probe), "strong", cls);
    const none = diffResponses(R(200, "base"), R(200, "base &lt;escaped&gt;"), probe);
    assert.equal(classifySignal(none, probe), "none", cls);
  }
});

test("classifySignal: ssti/command need the COMPUTED value, not the literal payload", () => {
  const ssti: FuzzProbe = { payloadClass: "ssti", payload: "{{7*7}}", computedMarker: "49" };
  // literal reflected but NOT computed -> none (that would be reflection, not evaluation)
  assert.equal(classifySignal(diffResponses(R(200, "x"), R(200, "x {{7*7}}"), ssti), ssti), "none");
  // computed value present -> strong (evaluation proven)
  assert.equal(classifySignal(diffResponses(R(200, "x"), R(200, "x 49"), ssti), ssti), "strong");
  const cmd: FuzzProbe = { payloadClass: "command_injection", payload: "; echo sahw42", computedMarker: "sahw42" };
  assert.equal(classifySignal(diffResponses(R(200, "x"), R(200, "out: sahw42"), cmd), cmd), "strong");
});

test("classifySqlSignal detects DB error signatures", () => {
  assert.equal(classifySqlSignal("You have an error in your SQL syntax near '''"), "strong");
  assert.equal(classifySqlSignal("XPATH syntax error: '~root'"), "strong");
  assert.equal(classifySqlSignal("just a normal 200 body"), "none");
});

test("generic divergence is at most a weak lead, never a strong auto-claim", () => {
  const probe: FuzzProbe = { payloadClass: "idor", payload: "2" };
  const big = diffResponses(R(200, "aaaa"), R(500, "totally different error stack trace here x".repeat(20)), probe);
  assert.equal(classifySignal(big, probe), "weak");
  const same = diffResponses(R(200, "same body here friend"), R(200, "same body here friend"), probe);
  assert.equal(classifySignal(same, probe), "none");
});
