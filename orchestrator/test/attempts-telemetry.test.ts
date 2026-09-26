import { test } from "node:test";
import assert from "node:assert/strict";
import { attemptsFromRecords } from "../src/obs/clickhouse.js";

type Rec = { request?: { method?: string; url?: string; headers?: Record<string, string> }; response?: { status?: number } };
const canon = (u: string) => u.replace(/\/\d+/g, "/{id}").split("?")[0];
const base = { engagementId: "ENG-x", runId: "run-1", source: "sweep", canon, utc: "2026-09-26T10:00:00.000Z" };

test("attemptsFromRecords builds one deduped row per (method, canonical endpoint, authenticated)", () => {
  const recs: Rec[] = [
    { request: { method: "GET", url: "https://t/api/v3/assets/1", headers: { "x-safe-id-token": "<redacted:session-A>" } }, response: { status: 200 } },
    { request: { method: "GET", url: "https://t/api/v3/assets/2", headers: { "x-safe-id-token": "<redacted:session-A>" } }, response: { status: 200 } }, // same canon+auth -> dedupe
    { request: { method: "GET", url: "https://t/api/v3/assets/1", headers: {} }, response: { status: 403 } }, // unauth variant -> separate row
    { request: { method: "POST", url: "https://t/api/v3/assets", headers: { authorization: "<redacted:session-A>" } }, response: { status: 201 } },
  ];
  const rows = attemptsFromRecords(recs, base);
  const keys = rows.map((r) => `${r.method} ${r.endpoint} auth=${r.authenticated} ${r.status}`).sort();
  assert.deepEqual(keys, [
    "GET https://t/api/v3/assets/{id} auth=0 403",
    "GET https://t/api/v3/assets/{id} auth=1 200",
    "POST https://t/api/v3/assets auth=1 201",
  ]);
  for (const r of rows) { assert.equal(r.engagement_id, "ENG-x"); assert.equal(r.run_id, "run-1"); assert.equal(r.source, "sweep"); }
});

test("attemptsFromRecords detects authentication via the redacted-session marker in any header", () => {
  const rows = attemptsFromRecords(
    [{ request: { method: "GET", url: "https://t/api/v3/x", headers: { authorization: "<redacted:session-B>" } }, response: { status: 200 } }],
    base,
  );
  assert.equal(rows[0].authenticated, 1);
});

test("attemptsFromRecords prefers a real status over 0 for the same probe, and skips records without a url", () => {
  const rows = attemptsFromRecords(([
    { request: { method: "GET", url: "https://t/api/v3/x", headers: {} } },                 // no response -> status 0
    { request: { method: "GET", url: "https://t/api/v3/x", headers: {} }, response: { status: 200 } }, // real status wins
    { request: { method: "GET", headers: {} } } as any,                                     // no url -> skipped
  ] as Rec[]), base);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].status, 200);
});

test("attemptsFromRecords returns [] for no records", () => {
  assert.deepEqual(attemptsFromRecords([], base), []);
});
