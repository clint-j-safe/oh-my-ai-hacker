/**
 * Langfuse tracer — sends traces as OpenTelemetry (OTLP/HTTP) to Langfuse v4.
 *
 * The legacy /api/public/ingestion endpoint is deprecated under the v4
 * data model. The updated method is the OTel endpoint with the
 * `x-langfuse-ingestion-version: 4` header (writes directly, no dual-write
 * staging delay). Langfuse maps `langfuse.*` and `gen_ai.*` attributes to
 * traces/observations/generations.
 */

import { randomBytes } from "node:crypto";

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
  sessionId?: string; // groups traces into a Langfuse session
  userId?: string;
}

interface OtlpAttribute {
  key: string;
  value: { stringValue?: string; intValue?: number };
}

function hexBytes(n: number): string {
  return randomBytes(n).toString("hex");
}

function toJson(v: unknown): string {
  return typeof v === "string" ? v : JSON.stringify(v);
}

export class LangfuseTracer {
  private readonly host: string;
  private readonly auth: string;

  constructor(opts: LangfuseOptions) {
    this.host = opts.host.replace(/\/$/, "");
    this.auth = `Basic ${Buffer.from(`${opts.publicKey}:${opts.secretKey}`).toString("base64")}`;
  }

  async trace(input: TraceInput): Promise<void> {
    const traceId = hexBytes(16);
    const spanId = hexBytes(8);
    const start = Date.now() * 1_000_000;

    const attributes: OtlpAttribute[] = [
      { key: "langfuse.trace.name", value: { stringValue: input.name } },
      { key: "langfuse.observation.type", value: { stringValue: "generation" } },
    ];
    if (input.sessionId) attributes.push({ key: "langfuse.session.id", value: { stringValue: input.sessionId } });
    if (input.userId) attributes.push({ key: "langfuse.user.id", value: { stringValue: input.userId } });
    if (input.input !== undefined) attributes.push({ key: "langfuse.observation.input", value: { stringValue: toJson(input.input) } });
    if (input.output !== undefined) attributes.push({ key: "langfuse.observation.output", value: { stringValue: toJson(input.output) } });
    if (input.model) attributes.push({ key: "gen_ai.response.model", value: { stringValue: input.model } });
    if (input.tokens) {
      attributes.push({ key: "gen_ai.usage.input_tokens", value: { intValue: input.tokens.input } });
      attributes.push({ key: "gen_ai.usage.output_tokens", value: { intValue: input.tokens.output } });
    }
    if (input.cost !== undefined) attributes.push({ key: "langfuse.trace.metadata.cost", value: { stringValue: String(input.cost) } });
    for (const [k, v] of Object.entries(input.metadata ?? {})) {
      attributes.push({ key: `langfuse.trace.metadata.${k}`, value: { stringValue: toJson(v) } });
    }

    const body = {
      resourceSpans: [
        {
          scopeSpans: [
            {
              spans: [
                {
                  traceId,
                  spanId,
                  name: input.name,
                  startTimeUnixNano: start,
                  endTimeUnixNano: start + 1_000_000,
                  attributes,
                },
              ],
            },
          ],
        },
      ],
    };

    try {
      const res = await fetch(`${this.host}/api/public/otel/v1/traces`, {
        method: "POST",
        headers: {
          authorization: this.auth,
          "content-type": "application/json",
          "x-langfuse-ingestion-version": "4",
        },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        console.error(`[langfuse] otel ingest ${res.status}: ${(await res.text()).slice(0, 300)}`);
      }
    } catch (e) {
      console.error(`[langfuse] otel ingest failed: ${(e as Error).message}`);
    }
  }
}
