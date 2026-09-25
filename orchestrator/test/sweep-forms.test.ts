import { test } from "node:test";
import assert from "node:assert/strict";
import { parseFormBody, setFormParam, authBypassMarker, LOGIN_BYPASS_PAYLOADS } from "../src/sweep-forms.js";

test("parseFormBody: form-urlencoded -> param names; null for JSON/XML/empty", () => {
  assert.deepEqual(parseFormBody("command=ping+-c+1&host=8.8.8.8"), ["command", "host"]);
  assert.deepEqual(parseFormBody("username=admin&password=x"), ["username", "password"]);
  assert.equal(parseFormBody('{"a":1}'), null);
  assert.equal(parseFormBody("<?xml?>"), null);
  assert.equal(parseFormBody(""), null);
  assert.equal(parseFormBody("just text no equals"), null);
});

test("setFormParam: injects into one param (URL-encoded), preserves others", () => {
  const out = setFormParam("command=ping&host=8.8.8.8", "host", "8.8.8.8;echo sahwCMD1787");
  assert.equal(out, "command=ping&host=8.8.8.8%3Becho%20sahwCMD1787");
  assert.ok(setFormParam("a=1", "b", "2").includes("b=2"));  // appends missing param
});

test("authBypassMarker: 302 redirect to a post-login page only on the exploit => marker", () => {
  const control = { status: 200, headers: { "content-type": "text/html" }, body: "<title>Login</title>" };
  const exploit = { status: 302, headers: { location: "welcome.php" }, body: "" };
  assert.equal(authBypassMarker(control, exploit), "welcome.php");
});

test("authBypassMarker: fresh session cookie only on the exploit => marker", () => {
  const control = { status: 200, headers: {}, body: "bad login" };
  const exploit = { status: 200, headers: { "set-cookie": "PHPSESSID=abc123def456; path=/" }, body: "ok" };
  assert.equal(authBypassMarker(control, exploit), "abc123def456");
});

test("authBypassMarker: no differential (both 200, no redirect/cookie diff) => null", () => {
  const same = { status: 200, headers: {}, body: "<title>Login</title>" };
  assert.equal(authBypassMarker(same, same), null);
  // control ALSO redirects to the same place => not a bypass
  const c = { status: 302, headers: { location: "welcome.php" }, body: "" };
  const e = { status: 302, headers: { location: "welcome.php" }, body: "" };
  assert.equal(authBypassMarker(c, e), null);
});

test("LOGIN_BYPASS_PAYLOADS: small generic set incl. the classic comment-out", () => {
  assert.ok(LOGIN_BYPASS_PAYLOADS.includes("admin'-- -"));
  assert.ok(LOGIN_BYPASS_PAYLOADS.length <= 8);
});
