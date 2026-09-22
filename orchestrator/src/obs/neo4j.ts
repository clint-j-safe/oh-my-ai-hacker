import neo4j, { type Driver } from "neo4j-driver";
import type { FindingRow } from "./clickhouse.js";

export class Neo4jWriter {
  constructor(private readonly driver: Driver, private readonly database: string) {}

  static fromEnv(env: Record<string, string | undefined>): Neo4jWriter | null {
    if (!env.NEO4J_URI) return null;
    const driver = neo4j.driver(
      env.NEO4J_URI,
      neo4j.auth.basic(env.NEO4J_USER ?? "neo4j", env.NEO4J_PASSWORD ?? ""));
    return new Neo4jWriter(driver, env.NEO4J_DATABASE ?? "engagement");
  }

  private async write(query: string, params: Record<string, unknown>) {
    const session = this.driver.session({ database: this.database } as any);
    try {
      await session.executeWrite(async (tx: any) => tx.run(query, params));
    } finally {
      await session.close();
    }
  }

  async mergeEndpoint(url: string, method: string): Promise<void> {
    await this.write(
      `MERGE (e:Endpoint {url: $url, method: $method})
       ON CREATE SET e.first_seen = datetime()`,
      { url, method });
  }

  async mergeFinding(row: FindingRow): Promise<void> {
    await this.write(
      `MERGE (f:Finding {finding_id: $finding_id})
       SET f.vuln_class = $vuln_class, f.verdict = $verdict,
           f.invariant_type = $invariant_type, f.langfuse_trace_id = $langfuse_trace_id
       MERGE (e:Endpoint {url: $endpoint})
       MERGE (f)-[:AFFECTS]->(e)`,
      row as unknown as Record<string, unknown>);
  }

  async close(): Promise<void> { await this.driver.close(); }
}
