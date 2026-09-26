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

/** One probe the engine actually made — coverage telemetry parsed from the artifacts and
 * embedded into the Neo4j graph (the coverage source of truth), so "was this endpoint
 * tested, and authenticated?" is a graph query rather than an artifact reconstruction.
 * One row per distinct (method, endpoint, authenticated). */
export interface AttemptRow {
  engagement_id: string;
  run_id: string;
  method: string;
  endpoint: string;      // canonicalized (path params normalized) so coverage dedupes cleanly
  authenticated: number; // 0 | 1 — whether the probe carried a session/auth material
  status: number;        // observed HTTP status (0 if the request never completed)
  source: string;        // "baseline" | "sweep" | "hunter" | "discovery" | ...
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

/** Build deduped attempt rows from captured request/response records. One row per distinct
 * (method, canonical endpoint, authenticated) — the authenticated flag is set when the
 * recorded request carried a session/auth header (the http() injector redacts these as
 * "<redacted:session-…>", which is exactly the marker we detect). Pure + unit-testable. */
export function attemptsFromRecords(
  records: Array<{ request?: { method?: string; url?: string; headers?: Record<string, string> }; response?: { status?: number } }>,
  opts: { engagementId: string; runId: string; source: string; canon: (u: string) => string; utc: string },
): AttemptRow[] {
  const byKey = new Map<string, AttemptRow>();
  for (const rec of records) {
    const url = rec.request?.url;
    if (!url) continue;
    const method = (rec.request?.method || "GET").toUpperCase();
    const endpoint = opts.canon(url);
    const authenticated = Object.values(rec.request?.headers ?? {}).some((v) => String(v).includes("redacted:session")) ? 1 : 0;
    const status = typeof rec.response?.status === "number" ? rec.response.status : 0;
    const key = `${method} ${endpoint} ${authenticated}`;
    // Prefer the row with a real (non-zero) status if we see the same probe twice.
    const existing = byKey.get(key);
    if (!existing || (existing.status === 0 && status !== 0)) {
      byKey.set(key, { engagement_id: opts.engagementId, run_id: opts.runId, method, endpoint, authenticated, status, source: opts.source, utc: opts.utc });
    }
  }
  return [...byKey.values()];
}
