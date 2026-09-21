/**
 * Langfuse tracer — official Langfuse JS/TS SDK v5 (OTel-based).
 *
 * Uses LangfuseSpanProcessor + NodeSDK + startActiveObservation. v5 is
 * observations-first: correlating attributes (sessionId/userId/metadata/tags)
 * and the trace name are propagated to child observations via
 * propagateAttributes (traceName, not name), and trace-level input/output is
 * set explicitly with setActiveTraceIO — the root observation's I/O is no
 * longer copied onto the trace automatically.
 */

import { NodeSDK } from "@opentelemetry/sdk-node";
import { LangfuseSpanProcessor } from "@langfuse/otel";
import {
  startActiveObservation,
  propagateAttributes,
  setActiveTraceIO,
} from "@langfuse/tracing";

export interface LangfuseOptions {
  host: string; // e.g. http://143.244.130.163:3000
  publicKey: string;
  secretKey: string;
  environment?: string;
}

export interface TraceInput {
  name: string;
  input?: unknown;
  output?: unknown;
  model?: string;
  cost?: number;
  tokens?: { input: number; output: number; reasoning?: number };
  metadata?: Record<string, unknown>;
  sessionId?: string;
  userId?: string;
  tags?: string[];
}

/**
 * Recorder handed to the agent loop so it can emit one child observation per
 * LLM turn (generation) and per tool call (span) under the engagement's root
 * trace — giving a full end-to-end tree instead of a single summary span.
 */
export interface SpanRecorder {
  generation(
    name: string,
    d: {
      input?: unknown;
      output?: unknown;
      model?: string;
      tokens?: { input: number; output: number; reasoning?: number };
      metadata?: Record<string, unknown>;
    },
  ): Promise<void>;
  toolSpan(
    name: string,
    d: { input?: unknown; output?: unknown; metadata?: Record<string, unknown> },
  ): Promise<void>;
  setOutput(output: unknown): void;
}

let sdk: NodeSDK | null = null;
let processor: LangfuseSpanProcessor | null = null;
let sdkKey = "";

function ensureSdk(opts: LangfuseOptions): void {
  const key = `${opts.host}|${opts.publicKey}|${opts.secretKey}|${opts.environment ?? ""}`;
  if (sdk && sdkKey === key) return;
  // Credential/host changed within a long-lived process: flush and tear down
  // the old provider before registering a new one (NodeSDK.start registers a
  // global provider; starting twice without shutdown is a no-op + warning).
  if (sdk) {
    void sdk.shutdown();
    sdk = null;
    processor = null;
  }
  processor = new LangfuseSpanProcessor({
    baseUrl: opts.host,
    publicKey: opts.publicKey,
    secretKey: opts.secretKey,
    ...(opts.environment ? { environment: opts.environment } : {}),
  });
  sdk = new NodeSDK({ spanProcessors: [processor] });
  sdk.start();
  sdkKey = key;
}

export class LangfuseTracer {
  private readonly opts: LangfuseOptions;

  constructor(opts: LangfuseOptions) {
    this.opts = opts;
    ensureSdk(opts);
  }

  async trace(input: TraceInput): Promise<void> {
    const metadata: Record<string, unknown> = { ...(input.metadata ?? {}) };
    if (input.cost !== undefined) metadata.cost = input.cost;

    // propagateAttributes requires string-valued metadata; the observation
    // itself keeps the richer typed object below.
    const metaStrings: Record<string, string> = {};
    for (const [k, v] of Object.entries(metadata)) {
      metaStrings[k] = typeof v === "string" ? v : JSON.stringify(v);
    }

    await propagateAttributes(
      {
        traceName: input.name,
        sessionId: input.sessionId,
        userId: input.userId,
        tags: input.tags,
        metadata: metaStrings,
      },
      async () => {
        await startActiveObservation(
          input.name,
          async (generation) => {
            generation.update({
              input: input.input,
              output: input.output,
              metadata,
              model: input.model,
              ...(input.tokens
                ? {
                    usageDetails: {
                      input: input.tokens.input,
                      output: input.tokens.output,
                      ...(input.tokens.reasoning !== undefined
                        ? { reasoning: input.tokens.reasoning }
                        : {}),
                    },
                  }
                : {}),
              ...(input.cost !== undefined ? { costDetails: { total: input.cost } } : {}),
            });
            // Observations-first: set trace-level I/O explicitly so the trace
            // row (not just the observation) shows input/output.
            setActiveTraceIO({ input: input.input, output: input.output });
          },
          { asType: "generation" },
        );
      },
    );
  }

  /**
   * Run `fn` inside a root engagement observation and hand it a recorder that
   * emits nested child observations (one generation per LLM turn, one span per
   * tool call). The whole tree is grouped into the given Langfuse session.
   */
  async traceTree<T>(
    root: {
      name: string;
      input?: unknown;
      model?: string;
      sessionId?: string;
      userId?: string;
      tags?: string[];
      metadata?: Record<string, unknown>;
    },
    fn: (rec: SpanRecorder) => Promise<T>,
  ): Promise<T> {
    const metaStrings: Record<string, string> = {};
    for (const [k, v] of Object.entries(root.metadata ?? {})) {
      metaStrings[k] = typeof v === "string" ? v : JSON.stringify(v);
    }

    // Run `fn` exactly once. A tracing-scaffolding failure must never lose the
    // work (fn) nor run it twice; a failure inside fn itself is a real error and
    // is rethrown.
    let result!: T;
    let ran = false;
    let fnError: unknown;
    const runOnce = async (rec: SpanRecorder): Promise<void> => {
      if (ran) return;
      ran = true;
      try {
        result = await fn(rec);
      } catch (e) {
        fnError = e;
        throw e;
      }
    };
    const noop: SpanRecorder = { async generation() {}, async toolSpan() {}, setOutput() {} };

    try {
      await propagateAttributes(
        {
          traceName: root.name,
          sessionId: root.sessionId,
          userId: root.userId,
          tags: root.tags,
          metadata: metaStrings,
        },
        async () => {
          await startActiveObservation(
            root.name,
            async (rootObs) => {
              try {
                rootObs.update({ input: root.input, metadata: root.metadata, ...(root.model ? { model: root.model } : {}) });
                setActiveTraceIO({ input: root.input });
              } catch {
                /* tracing-only */
              }

              const rec: SpanRecorder = {
                async generation(name, d) {
                  try {
                    await startActiveObservation(
                      name,
                      async (g) => {
                        g.update({
                          input: d.input,
                          output: d.output,
                          model: d.model,
                          metadata: d.metadata,
                          ...(d.tokens
                            ? {
                                usageDetails: {
                                  input: d.tokens.input,
                                  output: d.tokens.output,
                                  ...(d.tokens.reasoning !== undefined ? { reasoning: d.tokens.reasoning } : {}),
                                },
                              }
                            : {}),
                        });
                      },
                      { asType: "generation" },
                    );
                  } catch (e) {
                    console.error(`[langfuse] span '${name}' failed (non-fatal): ${(e as Error).message}`);
                  }
                },
                async toolSpan(name, d) {
                  try {
                    await startActiveObservation(
                      name,
                      async (s) => {
                        s.update({ input: d.input, output: d.output, metadata: d.metadata });
                      },
                      { asType: "span" },
                    );
                  } catch (e) {
                    console.error(`[langfuse] span '${name}' failed (non-fatal): ${(e as Error).message}`);
                  }
                },
                setOutput(output) {
                  try {
                    rootObs.update({ output });
                    setActiveTraceIO({ output });
                  } catch {
                    /* tracing-only */
                  }
                },
              };

              await runOnce(rec);
            },
            { asType: "span" },
          );
        },
      );
    } catch (e) {
      if (fnError) throw fnError; // real failure inside fn (e.g. the scan) — propagate
      console.error(`[langfuse] traceTree scaffolding failed (non-fatal): ${(e as Error).message}`);
      await runOnce(noop); // scaffolding failed before fn ran — run it untraced
    }
    return result;
  }

  /**
   * Flush pending spans without tearing down the SDK — safe to call between
   * traces and before a short-lived process exits (the tracer stays usable).
   */
  async flush(): Promise<void> {
    try {
      await processor?.forceFlush();
    } catch (e) {
      // Export failure (e.g. Langfuse unreachable) must never break the caller.
      console.error(`[langfuse] flush failed (non-fatal): ${(e as Error).message}`);
    }
  }

  /** Full teardown; call once at process exit if you need to release the SDK. */
  async shutdown(): Promise<void> {
    await sdk?.shutdown();
    sdk = null;
    processor = null;
    sdkKey = "";
  }
}
