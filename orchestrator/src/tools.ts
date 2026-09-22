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

// A discriminated reason for a failed tool call, so a caller (the Task 9 agent loop) can
// branch on WHY a call failed without parsing the human-readable message. Retry guidance
// for each kind (so Task 9's author does not have to infer it):
//   "policy"            - the Tether denied it. NEVER retry; count it as a security event.
//   "no_executor"        - gate() allowed the tool, but ToolRunner has no dispatch branch
//                          for it. NEVER retry — this is a bug to surface (the call can
//                          never succeed no matter how many times it's repeated), not a
//                          transient condition.
//   "invalid_argument"   - the caller/model supplied something structurally wrong (e.g. a
//                          malformed sha256) that is decidable WITHOUT touching the
//                          executor's I/O. NEVER retry the same arguments — they will
//                          fail identically every time. A caller may retry with DIFFERENT,
//                          corrected arguments, but that is a new call, not a retry.
//   "execution_error"    - the executor's own logic threw while actually running (a
//                          network failure, an artifact store I/O error, etc). Retry MAY
//                          be reasonable depending on the specific failure — this is the
//                          one kind where "try again" can plausibly help.
export type ToolFailureKind = "policy" | "no_executor" | "invalid_argument" | "execution_error";

export type ToolResult<T = unknown> =
  | { ok: true; result: T }
  | { ok: false; kind: ToolFailureKind; denied: string };

// Thrown by an executor (e.g. readArtifact) for a caller-supplied argument that is
// structurally invalid — decidable purely from the argument's shape, before any I/O is
// attempted. execute()'s catch block maps this specifically to kind: "invalid_argument"
// (never retryable with the same arguments), as opposed to any other thrown error, which
// maps to kind: "execution_error" (an executor-level failure, possibly retryable).
class InvalidToolArgumentError extends Error {}

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

  async execute(tool: string, args: Record<string, unknown>): Promise<ToolResult> {
    const decision = gate(this.engagement, tool, args);
    if (!decision.allow) return { ok: false, kind: "policy", denied: decision.reason };

    try {
      if (tool === "http_request") return { ok: true, result: await this.http(args) };
      if (tool === "read_artifact") return { ok: true, result: await this.readArtifact(args) };
      return { ok: false, kind: "no_executor", denied: `no executor for tool: ${tool}` };
    } catch (err) {
      // Belt-and-braces: even with the upfront hash validation below, ArtifactStore.get()
      // can still throw (e.g. a corrupt on-disk artifact whose content no longer matches
      // its filename hash). Convert ANY executor exception into a structured denial rather
      // than letting it propagate out of execute() and abort the agent loop.
      const message = err instanceof Error ? err.message : String(err);
      if (err instanceof InvalidToolArgumentError) {
        return { ok: false, kind: "invalid_argument", denied: message };
      }
      return { ok: false, kind: "execution_error", denied: `tool execution error: ${message}` };
    }
  }

  private async readArtifact(args: Record<string, unknown>): Promise<{ content: string }> {
    const sha256 = String(args.sha256 ?? "");
    if (!CANONICAL_SHA256.test(sha256)) {
      // Decidable purely from the string's shape, no I/O involved — kind: "invalid_argument".
      // Distinct from a well-formed-but-unknown sha256 below, which requires actually
      // asking the store and only fails once that I/O comes back not-found; that path is
      // deliberately left under kind: "execution_error" (see the report's judgement-call
      // note on this split).
      throw new InvalidToolArgumentError(
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
    // redirect: "manual" is load-bearing for scope integrity. The Tether (gate()/
    // inScope()) only sees the URL passed to THIS call — it never re-checks a URL the
    // underlying transport decides to follow on its own. With the WHATWG default
    // ("follow"), an in-scope target answering 3xx could cause this module to silently
    // contact a host the engagement never approved, and the stored artifact would then
    // record the ORIGINAL (in-scope) url while the bytes actually came from wherever the
    // redirect landed — a scope violation AND an evidence-integrity defect, since the
    // whole point of hashing the exchange is that the artifact is what was truly
    // contacted. A 3xx is instead captured verbatim (status + Location header + body)
    // like any other response; the model must issue a fresh http_request for the
    // Location if it wants to follow, which sends that URL through gate() on its own
    // merits.
    const res = await this.fetchImpl(url, { method, headers, body: body ?? undefined, redirect: "manual" });
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
