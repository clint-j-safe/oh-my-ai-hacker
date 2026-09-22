import type OpenAI from "openai";
import type { Engagement } from "./config.js";
import { gate } from "./tether.js";
import { ArtifactStore, type Artifact } from "./artifacts.js";

export interface HttpCapture {
  request: { method: string; url: string; headers: Record<string, string>; body: string | null };
  response: { status: number; headers: Record<string, string>; body: string };
  artifact: Artifact;
  ms: number;
}

export const TOOL_SCHEMAS: OpenAI.Chat.ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "http_request",
      description:
        "Send ONE HTTP request to an in-scope host. Returns status, headers and body, " +
        "and stores the verbatim exchange as a hashed artifact.",
      parameters: {
        type: "object",
        properties: {
          method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] },
          url: { type: "string" },
          headers: { type: "object" },
          body: { type: "string" },
        },
        required: ["method", "url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "read_artifact",
      description: "Read a stored artifact by its sha256.",
      parameters: {
        type: "object",
        properties: { sha256: { type: "string" } },
        required: ["sha256"],
      },
    },
  },
];

// Mirrors ArtifactStore's own canonical-hash check (src/artifacts.ts). ArtifactStore.get()
// now throws on a non-canonical sha256 argument (fail-closed on corrupt/junk input) rather
// than returning false/empty. A model-supplied sha256 is untrusted input, so it is
// validated HERE, before it ever reaches the store, and turned into an ordinary
// { ok: false, denied } tool result the model can react to — instead of a raw exception
// escaping execute() and aborting the whole agent loop.
const CANONICAL_SHA256 = /^[0-9a-f]{64}$/;

export class ToolRunner {
  private readonly engagement: Engagement;
  private readonly store: ArtifactStore;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: { engagement: Engagement; store: ArtifactStore; fetchImpl?: typeof fetch }) {
    this.engagement = opts.engagement;
    this.store = opts.store;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  async execute(tool: string, args: Record<string, unknown>) {
    const decision = gate(this.engagement, tool, args);
    if (!decision.allow) return { ok: false as const, denied: decision.reason };

    try {
      if (tool === "http_request") return { ok: true as const, result: await this.http(args) };
      if (tool === "read_artifact") return { ok: true as const, result: await this.readArtifact(args) };
      return { ok: false as const, denied: `no executor for tool: ${tool}` };
    } catch (err) {
      // Belt-and-braces: even with the upfront hash validation below, ArtifactStore.get()
      // can still throw (e.g. a corrupt on-disk artifact whose content no longer matches
      // its filename hash). Convert ANY executor exception into a structured denial rather
      // than letting it propagate out of execute() and abort the agent loop.
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false as const, denied: `tool execution error: ${message}` };
    }
  }

  private async readArtifact(args: Record<string, unknown>): Promise<{ content: string }> {
    const sha256 = String(args.sha256 ?? "");
    if (!CANONICAL_SHA256.test(sha256)) {
      throw new Error(
        `invalid sha256: expected 64 lowercase hex characters, got ${JSON.stringify(args.sha256)}`);
    }
    const buf = await this.store.get(sha256);
    return { content: buf.toString("utf8") };
  }

  private async http(args: Record<string, unknown>): Promise<HttpCapture> {
    const method = String(args.method ?? "GET").toUpperCase();
    const url = String(args.url);
    const headers = (args.headers as Record<string, string>) ?? {};
    const body = args.body === undefined ? null : String(args.body);

    const started = Date.now();
    const res = await this.fetchImpl(url, { method, headers, body: body ?? undefined });
    const text = await res.text();
    const ms = Date.now() - started;

    const respHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => { respHeaders[k] = v; });

    const capture = {
      request: { method, url, headers, body },
      response: { status: res.status, headers: respHeaders, body: text },
    };
    const artifact = await this.store.put(JSON.stringify(capture, null, 2));
    return { ...capture, artifact, ms };
  }
}
