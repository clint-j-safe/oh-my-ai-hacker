/**
 * Langfuse tracer — sends traces + generation observations to a running
 * Langfuse instance (legacy /api/public/ingestion endpoint, HTTP Basic auth).
 * This is "The Ledger" observability plane: every agent run becomes a trace
 * with cost/tokens, linking provenance back to the finding.
 */

export interface LangfuseOptions {
  host: string; // e.g. http://143.244.130.163:3000
  publicKey: string;
  secretKey: string;
}

export interface TraceInput {
  name: string;
  input?: unknown;
  output?: unknown;
  model?: string;
  cost?: number;
  tokens?: { input: number; output: number; reasoning?: number };
  metadata?: Record<string, unknown>;
}

function uid(): string {
  return (globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`) as string;
}

export class LangfuseTracer {
  private readonly host: string;
  private readonly auth: string;

  constructor(opts: LangfuseOptions) {
    this.host = opts.host.replace(/\/$/, "");
    this.auth = `Basic ${Buffer.from(`${opts.publicKey}:${opts.secretKey}`).toString("base64")}`;
  }

  async trace(input: TraceInput): Promise<void> {
    const traceId = uid();
    const obsId = uid();
    const now = new Date().toISOString();

    const batch = [
      {
        id: traceId,
        type: "trace-create",
        timestamp: now,
        body: {
          name: input.name,
          input: input.input,
          output: input.output,
          metadata: input.metadata,
        },
      },
      {
        id: obsId,
        type: "observation-create",
        timestamp: now,
        body: {
          traceId,
          name: `${input.name} (generation)`,
          type: "GENERATION",
          model: input.model,
          input: input.input,
          output: input.output,
          usage: input.tokens
            ? { input: input.tokens.input, output: input.tokens.output, ...(input.tokens.reasoning ? { reasoning: input.tokens.reasoning } : {}) }
            : undefined,
          metadata: { ...(input.metadata ?? {}), cost: input.cost },
        },
      },
    ];

    try {
      const res = await fetch(`${this.host}/api/public/ingestion`, {
        method: "POST",
        headers: { "authorization": this.auth, "content-type": "application/json" },
        body: JSON.stringify({ batch }),
      });
      if (!res.ok) {
        console.error(`[langfuse] ingest ${res.status}: ${(await res.text()).slice(0, 200)}`);
        return;
      }
      const body = (await res.json().catch(() => null)) as { errors?: unknown[] } | null;
      if (body?.errors?.length) {
        console.error(`[langfuse] ingest batch errors: ${JSON.stringify(body.errors).slice(0, 400)}`);
      }
    } catch (e) {
      console.error(`[langfuse] ingest failed: ${(e as Error).message}`);
    }
  }
}
