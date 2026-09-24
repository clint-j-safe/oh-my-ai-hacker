import { createClient, type ClickHouseClient } from "@clickhouse/client";

export interface FindingRow {
  engagement_id: string; finding_id: string; vuln_class: string; endpoint: string;
  verdict: string; invariant_type: string;
  // The deterministic RATIONALE for `verdict` — the Axiom's own reason string (or the
  // pre-verifier's) explaining WHY this finding was CONFIRMED, FALSE_POSITIVE, or
  // NEEDS_REVIEW (e.g. "marker present in exploit, absent in control", "control response
  // also contains X", "no control request captured; cannot differentiate"). Carried on
  // the record so an analyst can see the verdict's basis without digging into the trace.
  verdict_reason: string;
  // null, never a placeholder, when no real Langfuse trace was active — see
  // src/obs/langfuse.ts and the Provenance Gate, which downgrades a finding to
  // NEEDS_REVIEW rather than accept a fabricated id here.
  langfuse_trace_id: string | null;
  utc: string;
}

export class ClickHouseWriter {
  constructor(private readonly client: ClickHouseClient) {}

  static fromEnv(env: Record<string, string | undefined>): ClickHouseWriter | null {
    if (!env.CLICKHOUSE_DSN) return null;
    return new ClickHouseWriter(createClient({
      url: env.CLICKHOUSE_DSN,
      username: env.CLICKHOUSE_USER,
      password: env.CLICKHOUSE_PASSWORD,
      database: env.CLICKHOUSE_DATABASE ?? "sahw",
    }));
  }

  async ensureSchema(): Promise<void> {
    await this.client.command({
      query: `CREATE TABLE IF NOT EXISTS sahw_findings (
        engagement_id String, finding_id String, vuln_class String, endpoint String,
        verdict String, invariant_type String, verdict_reason String DEFAULT '',
        langfuse_trace_id Nullable(String), utc DateTime64(3)
      ) ENGINE = MergeTree ORDER BY (engagement_id, utc)`,
    });
    // Migrate an already-existing table that predates verdict_reason. Idempotent.
    await this.client.command({
      query: `ALTER TABLE sahw_findings ADD COLUMN IF NOT EXISTS verdict_reason String DEFAULT ''`,
    });
  }

  async recordFinding(row: FindingRow): Promise<void> {
    // ClickHouse DateTime64(3) parses "YYYY-MM-DD HH:MM:SS.sss", NOT the ISO-8601
    // "…THH:MM:SS.sssZ" our FindingRow.utc carries — the trailing T/Z make it reject
    // every row (CANNOT_PARSE_INPUT_ASSERTION_FAILED). Normalise at the boundary so
    // callers keep emitting plain ISO. UTC only (the source is always Z).
    const utc = row.utc.replace("T", " ").replace(/Z$/, "");
    await this.client.insert({ table: "sahw_findings", format: "JSONEachRow", values: [{ ...row, utc }] });
  }

  async close(): Promise<void> { await this.client.close(); }
}
