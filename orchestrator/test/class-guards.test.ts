import { test } from "node:test";
import assert from "node:assert/strict";
import { guardConfirmedVerdict } from "../src/axiom.js";

function cap(url: string, status: number) {
  return { request: { method: "GET", url, headers: {}, body: null },
           response: { status, headers: {}, body: "" } } as any;
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

test("guard is authoritative over CONFIRMED_BY_ADJUDICATION too, and never yields FALSE_POSITIVE", () => {
  const g = guardConfirmedVerdict("rate_limit_absence", "CONFIRMED_BY_ADJUDICATION", cap("http://t/x", 502));
  assert.equal(g.status, "NEEDS_REVIEW");
  // non-confirmed verdicts pass through untouched
  assert.equal(guardConfirmedVerdict("rate_limit_absence", "NEEDS_REVIEW", cap("http://t/x", 502)).status, "NEEDS_REVIEW");
  assert.equal(guardConfirmedVerdict("sqli", "CONFIRMED", cap("http://t/x", 200)).status, "CONFIRMED");
});
