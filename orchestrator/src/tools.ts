import type OpenAI from "openai";
import { Worker } from "node:worker_threads";
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
  {
    type: "function",
    function: {
      name: "grep_artifact",
      description:
        "SEARCH a stored artifact for lines matching a regular expression and return " +
        "only the matching lines plus surrounding context — it does NOT return the " +
        "whole artifact. Prefer this over read_artifact whenever a response body is " +
        "large (e.g. a minified JS bundle): read_artifact pulls content back through a " +
        "small bounded preview, so retrieving a 100KB+ file that way takes many calls " +
        "and never gets you the whole thing anyway. grep_artifact instead searches the " +
        "artifact in place with a targeted pattern (e.g. an API route or endpoint " +
        "shape) and returns a bounded set of matches in one call.",
      parameters: {
        type: "object",
        properties: {
          sha256: { type: "string", description: "The artifact to search." },
          pattern: { type: "string", description: "A regular expression (JS RegExp syntax)." },
          ignore_case: {
            type: "boolean",
            description: "Case-insensitive matching. Defaults to true.",
          },
          context: {
            type: "integer",
            description: "Lines of context to include before and after each match. Defaults to 0.",
          },
          max_matches: {
            type: "integer",
            description: "Cap on the number of matches returned. Defaults to 40; always clamped to an upper ceiling.",
          },
        },
        required: ["sha256", "pattern"],
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

// --- grep_artifact ---------------------------------------------------------------
//
// The Offload Law (see agent.ts) exists because a bounded PREVIEW of a 100KB+ artifact
// is useless — the model burns its whole turn budget retrieving fragments of a bundle
// through read_artifact and never reaches a claim. grep_artifact searches the artifact
// in place instead, so the model gets exactly the lines it asked for.
//
// That means this tool executes a caller-SUPPLIED regular expression against
// caller-supplied (i.e. target-controlled) text. A pattern like `^(a+)+$` against a
// non-matching string of 'a's is catastrophic backtracking: RegExp#test() can block
// the calling thread for an effectively unbounded time on ONE call. Nothing inside
// that same thread — no loop counter, no Date.now() check between iterations — can
// interrupt a single .test()/.exec() call already in progress, because JS is
// single-threaded; a check between lines only helps if the hang happens BETWEEN
// lines, not inside one. The only thing that can actually interrupt it is something
// OUTSIDE that thread. So the scan runs inside a node:worker_threads Worker, and the
// parent races it against a wall-clock deadline (GREP_SCAN_BUDGET_MS): if the worker
// hasn't reported back in time, Worker#terminate() forcibly kills its V8 isolate —
// including a call stuck mid-backtrack — and the caller gets `truncated: true` back
// instead of the whole agent loop hanging.
const GREP_LINE_MAX_CHARS = 400;
const GREP_DEFAULT_MAX_MATCHES = 40;
// Deliberately modest: this bound (together with GREP_MAX_CONTEXT_LINES and
// GREP_LINE_MAX_CHARS) is what keeps a maximally-greedy caller from turning
// grep_artifact into a new way to dump hundreds of KB back at the model.
// forModel() in agent.ts applies a second, coarser bound on top of this — a backstop,
// not the primary control.
const GREP_MAX_MATCHES_CEILING = 100;
const GREP_MAX_CONTEXT_LINES = 10;
const GREP_SCAN_BUDGET_MS = Math.max(
  200, Number(process.env.SAHW_GREP_SCAN_BUDGET_MS ?? 1500) || 1500);

export interface GrepMatch {
  line_number: number;
  line: string;
  before: string[];
  after: string[];
  /** Present (true) only when `line` was clipped to GREP_LINE_MAX_CHARS. */
  clipped?: boolean;
}

export interface GrepArtifactResult {
  matches: GrepMatch[];
  total_matches: number;
  returned_matches: number;
  truncated: boolean;
  total_lines: number;
  note?: string;
}

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const n = Number(value);
  const truncated = Number.isFinite(n) ? Math.trunc(n) : fallback;
  return Math.min(max, Math.max(min, truncated));
}

// Runs entirely inside the worker via `eval: true` — a plain CommonJS-style script,
// deliberately NOT an import of this module. An eval'd worker has no file path to
// resolve "type": "module" from, so it runs as a script; `require` is the form that
// works regardless of the host package's module type. Nothing here reaches back into
// this process — content, pattern and flags all arrive via workerData, and the only
// way out is postMessage.
const GREP_WORKER_SOURCE = `
const { parentPort, workerData } = require("node:worker_threads");
try {
  const { lines, pattern, flags, context, maxMatches, lineMaxChars } = workerData;
  const re = new RegExp(pattern, flags);
  const clip = (s) => (
    s.length <= lineMaxChars
      ? { text: s, clipped: false }
      : { text: s.slice(0, lineMaxChars), clipped: true }
  );
  const matches = [];
  let totalMatches = 0;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) {
      totalMatches++;
      if (matches.length < maxMatches) {
        const main = clip(lines[i]);
        matches.push({
          line_number: i + 1,
          line: main.text,
          before: lines.slice(Math.max(0, i - context), i).map((l) => clip(l).text),
          after: lines.slice(i + 1, i + 1 + context).map((l) => clip(l).text),
          clipped: main.clipped || undefined,
        });
      }
    }
  }
  parentPort.postMessage({ ok: true, matches, totalMatches, totalLines: lines.length });
} catch (err) {
  parentPort.postMessage({ ok: false, error: String((err && err.message) || err) });
}
`;

type GrepWorkerOutcome =
  | { ok: true; matches: GrepMatch[]; totalMatches: number; totalLines: number }
  | { ok: false; error: string }
  | { ok: "timeout" };

function runGrepWorker(workerData: {
  lines: string[]; pattern: string; flags: string; context: number; maxMatches: number; lineMaxChars: number;
}): Promise<GrepWorkerOutcome> {
  return new Promise((resolve) => {
    let settled = false;
    const worker = new Worker(GREP_WORKER_SOURCE, { eval: true, workerData });

    const finish = (outcome: GrepWorkerOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // Fire-and-forget: the caller does not wait on shutdown, only on the outcome.
      // Guards against an unhandled rejection if terminate() itself ever throws.
      worker.terminate().catch(() => {});
      resolve(outcome);
    };

    const timer = setTimeout(() => finish({ ok: "timeout" }), GREP_SCAN_BUDGET_MS);
    worker.once("message", (msg: GrepWorkerOutcome) => finish(msg));
    worker.once("error", (err: Error) => finish({ ok: false, error: err.message }));
  });
}

async function grepArtifactContent(
  content: string, pattern: string, flags: string, context: number, maxMatches: number,
): Promise<GrepArtifactResult> {
  const lines = content.split(/\r?\n/);
  const outcome = await runGrepWorker({
    lines, pattern, flags, context, maxMatches, lineMaxChars: GREP_LINE_MAX_CHARS,
  });

  if (outcome.ok === "timeout") {
    return {
      matches: [],
      total_matches: 0,
      returned_matches: 0,
      truncated: true,
      total_lines: lines.length,
      note: `scan budget of ${GREP_SCAN_BUDGET_MS}ms exceeded before the pattern finished — ` +
        "it may be pathological (catastrophic backtracking); try a simpler or more specific pattern",
    };
  }
  if (!outcome.ok) {
    // Not a caller-argument problem (the pattern already compiled successfully in
    // grepArtifact() below, before the worker ever started) — an executor-level
    // failure, so it propagates as a thrown Error and execute()'s catch maps it to
    // kind: "execution_error", not "invalid_argument".
    throw new Error(`grep_artifact worker failed: ${outcome.error}`);
  }

  return {
    matches: outcome.matches,
    total_matches: outcome.totalMatches,
    returned_matches: outcome.matches.length,
    truncated: outcome.totalMatches > outcome.matches.length,
    total_lines: outcome.totalLines,
  };
}

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
      if (tool === "grep_artifact") return { ok: true, result: await this.grepArtifact(args) };
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

  private async grepArtifact(args: Record<string, unknown>): Promise<GrepArtifactResult> {
    const sha256 = String(args.sha256 ?? "");
    if (!CANONICAL_SHA256.test(sha256)) {
      // Same convention as readArtifact() above: decidable purely from the string's
      // shape, before any I/O — kind: "invalid_argument", delegating to (mirroring)
      // the store's own canonical-hash check.
      throw new InvalidToolArgumentError(
        `invalid sha256: expected 64 lowercase hex characters, got ${JSON.stringify(args.sha256)}`);
    }

    const pattern = args.pattern;
    if (typeof pattern !== "string" || pattern.length === 0) {
      throw new InvalidToolArgumentError(
        `invalid pattern: expected a non-empty regular expression string, got ${JSON.stringify(pattern)}`);
    }
    const ignoreCase = args.ignore_case === undefined ? true : Boolean(args.ignore_case);
    const flags = ignoreCase ? "i" : "";
    // Compiling the pattern is decidable purely from the pattern's own text, with no
    // I/O and before the worker ever starts — a malformed regex is a caller error
    // (kind: "invalid_argument"), NOT an executor failure, and must not throw out of
    // execute(). This is the same convention the malformed-sha256 check above follows.
    try {
      // eslint-disable-next-line no-new -- compiled only to validate; discarded here,
      // and recompiled inside the worker where it is actually used.
      new RegExp(pattern, flags);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new InvalidToolArgumentError(`invalid regular expression ${JSON.stringify(pattern)}: ${message}`);
    }

    const context = clampInt(args.context, 0, 0, GREP_MAX_CONTEXT_LINES);
    const maxMatches = clampInt(args.max_matches, GREP_DEFAULT_MAX_MATCHES, 1, GREP_MAX_MATCHES_CEILING);

    const buf = await this.store.get(sha256);
    return grepArtifactContent(buf.toString("utf8"), pattern, flags, context, maxMatches);
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
