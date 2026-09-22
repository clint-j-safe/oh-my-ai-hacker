import { createClient, type ClickHouseClient } from "@clickhouse/client";

export interface FindingRow {
  engagement_id: string; finding_id: string; vuln_class: string; endpoint: string;
  verdict: string; invariant_type: string; langfuse_trace_id: string; utc: string;
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
        verdict String, invariant_type String, langfuse_trace_id String, utc DateTime64(3)
      ) ENGINE = MergeTree ORDER BY (engagement_id, utc)`,
    });
  }

  async recordFinding(row: FindingRow): Promise<void> {
    await this.client.insert({ table: "sahw_findings", format: "JSONEachRow", values: [row] });
  }

  async close(): Promise<void> { await this.client.close(); }
}
