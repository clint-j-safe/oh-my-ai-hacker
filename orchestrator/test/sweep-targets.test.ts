import { test } from "node:test";
import assert from "node:assert/strict";
import { jsonStringLeafPaths, setAtPath, deriveTargets } from "../src/sweep-targets.js";

test("jsonStringLeafPaths finds nested string leaves and skips plumbing fields", () => {
  const body = { requestBody: { timestamp: "1", device: { deviceid: "X", os: "android" }, data: { name: "n", userid: "u", amount: "5" } } };
  const paths = jsonStringLeafPaths(body);
  assert.ok(paths.includes("requestBody.data.name"));
  assert.ok(paths.includes("requestBody.data.userid"));
  assert.ok(paths.includes("requestBody.data.amount"));
  assert.ok(!paths.includes("requestBody.timestamp"), "timestamp skipped");
  assert.ok(!paths.some((p) => p.endsWith("deviceid") || p.endsWith("os")), "device plumbing skipped");
});

test("setAtPath injects at a nested path on a deep clone (original untouched)", () => {
  const body = { requestBody: { data: { name: "orig" } } };
  const out = setAtPath(body, "requestBody.data.name", "<script>x</script>") as any;
  assert.equal(out.requestBody.data.name, "<script>x</script>");
  assert.equal(body.requestBody.data.name, "orig", "original not mutated");
});

test("deriveTargets extracts JSON-body fuzz params from a captured POST (envelope-aware)", () => {
  const records = [{
    request: {
      method: "POST",
      url: "http://h/api/contactUs/index",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ requestBody: { timestamp: "1", data: { name: "hi", email: "a@b.c" } } }),
    },
  }];
  const canon = (u: string) => u.replace(/\/index$/, "");
  const targets = deriveTargets(records, () => true, canon);
  assert.equal(targets.length, 1);
  assert.equal(targets[0].endpoint, "http://h/api/contactUs", "canonicalized off /index");
  assert.ok(targets[0].params.includes("requestBody.data.name"));
  assert.equal(targets[0].paramKind["requestBody.data.name"], "json");
  assert.ok(targets[0].bodyTemplate, "carries a body template to inject into");
});

test("deriveTargets falls back to query params when there is no JSON body", () => {
  const records = [{ request: { method: "GET", url: "http://h/search?q=x&page=1" } }];
  const targets = deriveTargets(records, () => true, (u) => u);
  assert.equal(targets.length, 1);
  assert.deepEqual(targets[0].params.sort(), ["page", "q"]);
  assert.equal(targets[0].paramKind["q"], "query");
  assert.equal(targets[0].bodyTemplate, null);
});

test("deriveTargets drops out-of-scope requests", () => {
  const records = [{ request: { method: "GET", url: "http://evil/x?a=1" } }];
  assert.equal(deriveTargets(records, (u) => u.includes("h.internal"), (u) => u).length, 0);
});

test("deriveTargets: form-urlencoded POST body yields form params (Cronos welcome.php shape)", () => {
  const recs = [{ request: { method: "POST", url: "http://admin.cronos.htb/welcome.php", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "command=ping+-c+1&host=8.8.8.8" } }];
  const t = deriveTargets(recs as any, () => true, (u) => u);
  const wp = t.find((x) => x.endpoint.endsWith("/welcome.php"));
  assert.ok(wp, "welcome.php target derived");
  assert.deepEqual(wp!.params.sort(), ["command", "host"]);
  assert.equal(wp!.paramKind["host"], "form");
  assert.equal(wp!.bodyTemplate, "command=ping+-c+1&host=8.8.8.8");
});
