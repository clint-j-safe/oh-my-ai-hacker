import { test } from "node:test";
import assert from "node:assert/strict";
import { initObservability } from "../src/obs/index.js";
import { ClickHouseWriter } from "../src/obs/clickhouse.js";
import { Neo4jWriter } from "../src/obs/neo4j.js";

const ROW = {
  engagement_id: "ENG-1", finding_id: "SAHW-0001", vuln_class: "path_traversal",
  endpoint: "http://10.0.0.1:3000/x", verdict: "CONFIRMED",
  invariant_type: "body_contains", langfuse_trace_id: "t-1", utc: "2026-09-22T12:00:00Z",
};

test("unconfigured env yields a working no-op observability", async () => {
  const obs = await initObservability({});
  await obs.recordFinding(ROW);      // must not throw
  await obs.mergeFinding(ROW);
  await obs.mergeEndpoint("http://10.0.0.1:3000/x", "GET");
  assert.equal(obs.traceId(), null);
  await obs.shutdown();
});

test("ClickHouse writer sends JSONEachRow to the findings table", async () => {
  const calls: any[] = [];
  const w = new ClickHouseWriter({
    insert: async (p: any) => { calls.push(p); },
    command: async () => {},
    close: async () => {},
  } as any);
  await w.ensureSchema();
  await w.recordFinding(ROW);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].format, "JSONEachRow");
  assert.equal(calls[0].table, "sahw_findings");
  // utc is normalised from ISO-8601 to ClickHouse DateTime64 format at the boundary:
  // the real DB rejects the trailing T/Z (this stub never would, which is how the bug
  // shipped — so assert the WIRE format explicitly, not just that a row was sent).
  const sent = calls[0].values[0];
  assert.equal(sent.utc, "2026-09-22 12:00:00", "ISO T/Z stripped to DateTime64 form (ms preserved when present)");
  assert.ok(!/[TZ]/.test(sent.utc), `utc must carry no T/Z for DateTime64: got ${sent.utc}`);
  assert.equal(sent.finding_id, ROW.finding_id);   // the rest of the row is unchanged
});

test("Neo4j writer MERGEs so repeated beats do not duplicate", async () => {
  const queries: string[] = [];
  const session = { executeWrite: async (fn: any) => fn({ run: async (q: string) => { queries.push(q); return { records: [] }; } }), close: async () => {} };
  const w = new Neo4jWriter({ session: () => session, close: async () => {} } as any, "engagement");
  await w.mergeEndpoint("http://10.0.0.1:3000/x", "GET");
  await w.mergeFinding(ROW);
  assert.equal(queries.length, 2);
  for (const q of queries) assert.match(q, /MERGE/);
  assert.ok(queries.some((q) => /:Finding/.test(q)));
});

test("one store failing does not take down the others", async () => {
  const obs = await initObservability({});
  obs.clickhouse = { recordFinding: async () => { throw new Error("CH down"); } } as any;
  await obs.recordFinding(ROW);  // must swallow and continue
});
