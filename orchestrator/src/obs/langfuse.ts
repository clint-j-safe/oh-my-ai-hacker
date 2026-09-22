import { NodeSDK } from "@opentelemetry/sdk-node";
import { LangfuseSpanProcessor } from "@langfuse/otel";

export class LangfuseTracing {
  private sdk: NodeSDK | null = null;
  private id: string | null = null;

  static fromEnv(env: Record<string, string | undefined>): LangfuseTracing | null {
    if (!env.LANGFUSE_PUBLIC_KEY || !env.LANGFUSE_SECRET_KEY) return null;
    return new LangfuseTracing();
  }

  start(traceId: string): void {
    this.id = traceId;
    this.sdk = new NodeSDK({ spanProcessors: [new LangfuseSpanProcessor()] });
    this.sdk.start();
  }

  traceId(): string | null { return this.id; }

  /** Required: batched spans are lost at exit otherwise. */
  async shutdown(): Promise<void> { await this.sdk?.shutdown(); }
}
