import { NodeSDK } from "@opentelemetry/sdk-node";
import { LangfuseSpanProcessor } from "@langfuse/otel";
import { getActiveTraceId } from "@langfuse/tracing";

// OpenTelemetry's well-known invalid trace id: what a no-op span reports when no
// tracer provider is registered. It is a syntactically valid 32-hex string, so it
// must be rejected explicitly — otherwise it is indistinguishable from a real id
// and reintroduces exactly the "placeholder mistaken for real provenance" defect
// this rewrite exists to remove.
const INVALID_TRACE_ID = "0".repeat(32);
const VALID_TRACE_ID = /^[0-9a-f]{32}$/;

export class LangfuseTracing {
  private sdk: NodeSDK | null = null;

  static fromEnv(env: Record<string, string | undefined>): LangfuseTracing | null {
    if (!env.LANGFUSE_PUBLIC_KEY || !env.LANGFUSE_SECRET_KEY) return null;
    return new LangfuseTracing();
  }

  /**
   * Registers the OpenTelemetry tracer provider. MUST run before any
   * startActiveObservation/startObservation call in this process, or that call opens
   * against a no-op provider and traceId() below reports no id even though Langfuse
   * is configured. beat.ts relies on this ordering: initObservability() (which calls
   * this) always runs before the "beat" span is opened.
   */
  start(): void {
    this.sdk = new NodeSDK({ spanProcessors: [new LangfuseSpanProcessor()] });
    this.sdk.start();
  }

  /**
   * The REAL trace id of the currently active OpenTelemetry span, read live —
   * never a value captured once and cached. Returns null when there is no active
   * span (no beat currently running, or tracing unconfigured) or when the id is
   * OTel's invalid all-zero sentinel. Callers (beat.ts) must pass this value, or
   * null, straight through to provenance — never substitute a placeholder for it.
   */
  traceId(): string | null {
    const id = getActiveTraceId();
    if (!id || id === INVALID_TRACE_ID || !VALID_TRACE_ID.test(id)) return null;
    return id;
  }

  /** Required: batched spans are lost at exit otherwise. */
  async shutdown(): Promise<void> { await this.sdk?.shutdown(); }
}
