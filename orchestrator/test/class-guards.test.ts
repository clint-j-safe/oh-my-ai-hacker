import { test } from "node:test";
import assert from "node:assert/strict";
import { guardConfirmedVerdict } from "../src/axiom.js";

function cap(url: string, status: number) {
  return { request: { method: "GET", url, headers: {}, body: null },
           response: { status, headers: {}, body: "" } } as any;
}

// Capture with an explicit body + content-type, for the disclosure guards (G1 2xx, G2 HTML).
function capB(url: string, status: number, body: string, contentType = "application/json") {
  return { request: { method: "GET", url, headers: {}, body: null },
           response: { status, headers: { "content-type": contentType }, body } } as any;
}

test("rate_limit_absence: a non-2xx burst status is demoted to NEEDS_REVIEW", () => {
  for (const s of [502, 500, 403, 401, 404]) {
    const g = guardConfirmedVerdict("rate_limit_absence", "CONFIRMED", cap("http://t/api/v2/auth", s));
    assert.equal(g.status, "NEEDS_REVIEW", `status ${s} should demote`);
    assert.match(g.reason ?? "", /2xx/);
  }
});

test("rate_limit_absence: a 2xx burst status stays CONFIRMED", () => {
  const g = guardConfirmedVerdict("rate_limit_absence", "CONFIRMED", cap("http://t/api/login", 200));
  assert.equal(g.status, "CONFIRMED");
});

test("forced_browsing/info_disclosure on a static asset is demoted to NEEDS_REVIEW", () => {
  for (const u of ["http://t/assets/index-x.js", "http://t/service-worker.js", "http://t/a.css", "http://t/x.js.map", "http://t/logo.png"]) {
    for (const cls of ["forced_browsing", "info_disclosure"]) {
      const g = guardConfirmedVerdict(cls, "CONFIRMED", cap(u, 200));
      assert.equal(g.status, "NEEDS_REVIEW", `${cls} ${u} should demote`);
    }
  }
});

test("forced_browsing on a genuinely sensitive non-asset file is NOT demoted (no TP loss)", () => {
  for (const u of ["http://t/.env", "http://t/backup.sql", "http://t/.git/config"]) {
    const g = guardConfirmedVerdict("forced_browsing", "CONFIRMED", cap(u, 200));
    assert.equal(g.status, "CONFIRMED", `${u} must stay CONFIRMED`);
  }
});

// --- G1: a disclosure is data returned in a SUCCESS response; a 4xx/5xx denial or error
// (403 explicit-deny, 400 validation, 404) cannot be a confirmed disclosure. This closes the
// demo.safeone.io FPs where body_contains fired on markers inside denial/error bodies.
test("info/crypto_disclosure off a non-2xx response is demoted to NEEDS_REVIEW", () => {
  for (const s of [403, 400, 404, 401, 500, 502]) {
    for (const cls of ["info_disclosure", "crypto_disclosure"]) {
      const g = guardConfirmedVerdict(cls, "CONFIRMED", capB("http://t/api/v3/groups", s, `{"Message":"explicit deny"}`));
      assert.equal(g.status, "NEEDS_REVIEW", `${cls} @ ${s} should demote`);
      assert.match(g.reason ?? "", /2xx|success/);
    }
  }
});

test("info/crypto_disclosure at 2xx with a real (non-HTML) data body stays CONFIRMED (no TP loss)", () => {
  for (const cls of ["info_disclosure", "crypto_disclosure"]) {
    const g = guardConfirmedVerdict(cls, "CONFIRMED", capB("http://t/api/v3/users", 200, `{"ssn":"123-45-6789","apiKey":"sk_live_x"}`));
    assert.equal(g.status, "CONFIRMED", `${cls} genuine 2xx JSON disclosure must stay CONFIRMED`);
  }
});

// --- G2: a public-by-design HTML document / SPA shell is not a data disclosure. This closes
// the crypto_disclosure-@-/ FP (200 SPA index HTML).
test("info/crypto_disclosure on an HTML document / SPA shell (2xx) is demoted to NEEDS_REVIEW", () => {
  const htmlBodies = ["<!doctype html><html><head></head><body>app</body></html>", "<html lang=\"en\"><body></body></html>"];
  for (const body of htmlBodies) {
    for (const cls of ["info_disclosure", "crypto_disclosure"]) {
      // by body sniff (no/blank content-type)
      const g1 = guardConfirmedVerdict(cls, "CONFIRMED", capB("http://t/", 200, body, ""));
      assert.equal(g1.status, "NEEDS_REVIEW", `${cls} HTML-body should demote`);
      assert.match(g1.reason ?? "", /HTML|public-by-design/);
      // by content-type
      const g2 = guardConfirmedVerdict(cls, "CONFIRMED", capB("http://t/dashboard", 200, "irrelevant", "text/html; charset=utf-8"));
      assert.equal(g2.status, "NEEDS_REVIEW", `${cls} text/html should demote`);
    }
  }
});

test("info/crypto_disclosure at 2xx with JSON data (not HTML) is NOT demoted by G2", () => {
  const g = guardConfirmedVerdict("info_disclosure", "CONFIRMED", capB("http://t/api/v3/config", 200, `{"secret":"abc"}`, "application/json"));
  assert.equal(g.status, "CONFIRMED");
});

// --- 5xx guard: a status-differential class cannot confirm on a server error / gateway
// timeout (observed FP: business_logic CONFIRMED on a 504-vs-400 differential).
test("status-differential classes are demoted when the exploit response is 5xx", () => {
  for (const s of [500, 502, 503, 504]) {
    for (const cls of ["business_logic", "forced_browsing", "auth_bypass", "idor", "open_redirect", "cors_misconfig"]) {
      const g = guardConfirmedVerdict(cls, "CONFIRMED", cap("http://t/api/v3/users?token=x", s));
      assert.equal(g.status, "NEEDS_REVIEW", `${cls} @ ${s} should demote`);
      assert.match(g.reason ?? "", /5xx|server error|timeout/);
    }
  }
});

test("a status-differential class with a 2xx exploit is NOT demoted by the 5xx guard", () => {
  assert.equal(guardConfirmedVerdict("business_logic", "CONFIRMED", cap("http://t/api/v3/x", 200)).status, "CONFIRMED");
  assert.equal(guardConfirmedVerdict("auth_bypass", "CONFIRMED", cap("http://t/api/v3/x", 302)).status, "CONFIRMED");
});

test("injection classes are NOT demoted on 5xx (a 5xx can be error-based evidence)", () => {
  for (const cls of ["sqli", "cmdi"]) {
    assert.equal(guardConfirmedVerdict(cls, "CONFIRMED", cap("http://t/api/v3/x", 500)).status, "CONFIRMED", `${cls} 5xx must stay CONFIRMED`);
  }
});

test("guard is authoritative over CONFIRMED_BY_ADJUDICATION too, and never yields FALSE_POSITIVE", () => {
  const g = guardConfirmedVerdict("rate_limit_absence", "CONFIRMED_BY_ADJUDICATION", cap("http://t/x", 502));
  assert.equal(g.status, "NEEDS_REVIEW");
  // non-confirmed verdicts pass through untouched
  assert.equal(guardConfirmedVerdict("rate_limit_absence", "NEEDS_REVIEW", cap("http://t/x", 502)).status, "NEEDS_REVIEW");
  assert.equal(guardConfirmedVerdict("sqli", "CONFIRMED", cap("http://t/x", 200)).status, "CONFIRMED");
});
