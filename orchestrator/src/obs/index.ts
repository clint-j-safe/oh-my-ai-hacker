import { randomUUID } from "node:crypto";
import { ClickHouseWriter, type FindingRow } from "./clickhouse.js";
import { Neo4jWriter } from "./neo4j.js";
import { LangfuseTracing } from "./langfuse.js";

export type { ClickHouseWriter, Neo4jWriter };

export type { FindingRow };

export interface Observability {
  /** Exposed so a caller (and a test) can substitute a writer without casting. */
  clickhouse: ClickHouseWriter | null;
  graph: Neo4jWriter | null;
  traceId(): string | null;
  recordFinding(r: FindingRow): Promise<void>;
  mergeEndpoint(url: string, method: string): Promise<void>;
  mergeFinding(r: FindingRow): Promise<void>;
  shutdown(): Promise<void>;
}

/** One store being down must never take the run with it. */
async function safe(label: string, fn: () => Promise<void>): Promise<void> {
  try { await fn(); } catch (err) {
    console.error(`[obs] ${label} failed (continuing):`, (err as Error).message);
  }
}

export async function initObservability(
  env: Record<string, string | undefined>,
): Promise<Observability> {
  const clickhouse = ClickHouseWriter.fromEnv(env);
  const graph = Neo4jWriter.fromEnv(env);
  const tracing = LangfuseTracing.fromEnv(env);

  if (tracing) tracing.start(randomUUID());
  if (clickhouse) await safe("clickhouse.ensureSchema", () => clickhouse.ensureSchema());

  const obs: Observability = {
    clickhouse,
    graph,
    traceId: () => tracing?.traceId() ?? null,
    recordFinding: async (r) => {
      if (obs.clickhouse) await safe("clickhouse.recordFinding", () => obs.clickhouse!.recordFinding(r));
    },
    mergeEndpoint: async (url, method) => {
      if (obs.graph) await safe("neo4j.mergeEndpoint", () => obs.graph!.mergeEndpoint(url, method));
    },
    mergeFinding: async (r) => {
      if (obs.graph) await safe("neo4j.mergeFinding", () => obs.graph!.mergeFinding(r));
    },
    shutdown: async () => {
      await safe("langfuse.shutdown", () => tracing?.shutdown() ?? Promise.resolve());
      await safe("clickhouse.close", () => clickhouse?.close() ?? Promise.resolve());
      await safe("neo4j.close", () => graph?.close() ?? Promise.resolve());
    },
  };
  return obs;
}
