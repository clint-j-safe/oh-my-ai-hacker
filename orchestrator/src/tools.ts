import type OpenAI from "openai";
import { Worker } from "node:worker_threads";
import { spawn } from "node:child_process";
import { stat, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import type { Engagement } from "./config.js";
import { gate, SKILL_EGRESS, type SkillEgress, type Decision } from "./tether.js";
import { ArtifactStore, type Artifact } from "./artifacts.js";

export interface HttpCapture {
  request: { method: string; url: string; headers: Record<string, string>; body: string | null };
  response: { status: number; headers: Record<string, string>; body: string };
  artifact: Artifact;
  ms: number;
}

/**
 * The full (unbounded) result of a successful skill_run call. `output` is the skill's
 * complete, schema-validated JSON artifact — ToolRunner returns it in full so telemetry
 * and forModel() (agent.ts) each apply their OWN bound; ToolRunner itself does not
 * truncate. `kind: "skill_artifact"` is a discriminant forModel()/toolSpanOutput() use
 * to recognize this shape among the other tool result shapes they already handle.
 */
export interface SkillRunOutcome {
  kind: "skill_artifact";
  skill_name: string;
  exit_code: number;
  ms: number;
  artifact: Artifact;
  output: unknown;
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

// --- skill_run: one dispatcher tool for every pre-built skill, not 37 separate ones --
//
// Chat Completions strict-mode function schema: `strict: true` requires
// `additionalProperties: false` AND every declared property to appear in `required`
// (no "optional" properties under strict mode — a property either exists or the model
// must be told not to rely on it existing).
//
// `input_json` is a JSON-encoded STRING, not a nested object, and that is deliberate:
// each of the 37 skills has a completely different input shape (severity-calibration
// wants `{"verified_findings":[...]}`, osv-cve-correlation wants `{"components":[...]}`,
// ...), and JSON Schema strict mode cannot express "the shape of this property depends
// on the value of a sibling property" — there is no variable/polymorphic object type
// under strict mode. Encoding the skill's input as a JSON string keeps the TOP-LEVEL
// arguments (`skill_name`, `input_json`) strictly well-formed regardless of what's
// inside the string, which is exactly what strict mode is for. ToolRunner parses and
// validates `input_json` itself before ever touching the filesystem or a subprocess
// (see skillRun() below). Do NOT "simplify" this back into a nested `input: object` —
// that silently drops strict mode's guarantee for every call site that uses it.
//
// The `skill_name` enum is narrowed to the CALLING AGENT's allowlist, passed in
// explicitly — never a module-level global — so the model literally cannot see, let
// alone request, a skill it has no authorization to run. gate() in tether.ts enforces
// the same allowlist independently and deterministically at call time; this enum is a
// prompting nicety (fewer wasted turns proposing a skill that will just be denied), not
// the security boundary.
export function buildSkillRunTool(allowlist: readonly string[]): OpenAI.Chat.ChatCompletionTool {
  return {
    type: "function",
    function: {
      name: "skill_run",
      description:
        "Run one pre-built skill (a scripts/run.py that takes JSON on stdin and emits " +
        "one strict JSON artifact on stdout) against evidence already collected. Only " +
        "skills this agent is authorized to run appear in skill_name's enum. Returns a " +
        "bounded summary of the artifact plus its sha256 — call read_artifact/" +
        "grep_artifact against the sha256 for the full result.",
      strict: true,
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          skill_name: {
            type: "string",
            description: "Which skill to run. Must be one of the enum values.",
            enum: [...allowlist],
          },
          input_json: {
            type: "string",
            description:
              "The skill's input object, JSON-encoded as a string (e.g. " +
              '\'{"verified_findings":[...]}\'). A string, not an object, so this ' +
              "schema stays strict-mode valid across skills with different input shapes.",
          },
        },
        required: ["skill_name", "input_json"],
      },
    },
  };
}

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

// --- skill_run: skills root resolution ------------------------------------------------
//
// Configurable via env SAHW_SKILLS_ROOT; default is the repo's top-level skills/. This
// module can run either directly from src/ (tsx, as the test suite does) or from a
// compiled dist/src/ (the built artifact), so the default probes both possible
// relative locations and picks whichever actually exists on disk, rather than assuming
// one fixed depth.
function defaultSkillsRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "..", "..", "skills"),        // .../orchestrator/src/tools.ts -> repo/skills
    join(here, "..", "..", "..", "skills"),  // .../orchestrator/dist/src/tools.js -> repo/skills
  ];
  return candidates.find((c) => existsSync(c)) ?? candidates[0];
}

const SKILLS_ROOT = process.env.SAHW_SKILLS_ROOT?.trim() || defaultSkillsRoot();
const SKILL_TIMEOUT_MS = Math.max(
  1000, Number(process.env.SAHW_SKILL_TIMEOUT_MS ?? 120_000) || 120_000);

// A skill_name must be a single, plain directory-name segment: no path separators, no
// parent-directory reference. This is checked BEFORE gate()/policy is even consulted —
// it is not a scope judgement, it is a structural precondition on the argument's shape
// (identical in spirit to the sha256/regex shape checks above for read_artifact/
// grep_artifact), decidable with zero I/O and independent of what the registry knows.
function validateSkillNameShape(name: unknown): { ok: true; name: string } | { ok: false; reason: string } {
  if (typeof name !== "string" || name.length === 0) {
    return { ok: false, reason: `skill_name must be a non-empty string, got ${JSON.stringify(name)}` };
  }
  if (name.includes("/") || name.includes("\\")) {
    return {
      ok: false,
      reason: `skill_name must be a plain directory name — no path separators: ${JSON.stringify(name)}`,
    };
  }
  if (name.includes("..")) {
    return {
      ok: false,
      reason: `skill_name must not reference a parent directory: ${JSON.stringify(name)}`,
    };
  }
  return { ok: true, name };
}

// --- skill_run: a minimal JSON Schema validator, on purpose not a full one -----------
//
// WHAT THIS DOES check, at the top level of the document AND one level into any
// property schema has its own `properties`/`type`/`enum`/`required`:
//   - `required`: every named key is present on the object being checked.
//   - `type`: matches "object" | "array" | "string" | "number" | "integer" | "boolean" |
//     "null" (an unrecognized type keyword is treated as unconstrained, not a failure).
//   - `enum`: the value is one of the listed literals.
//
// WHAT THIS DOES NOT check (by design — writing a real JSON Schema engine is out of
// scope, and a skill artifact schema in this repo never needs more than the above):
//   array `items` shapes (only the array's OWN type, one level deep, is checked — the
//   elements inside it are not walked), `additionalProperties`, `pattern`/`format`,
//   numeric bounds (`minimum`/`maximum`), `oneOf`/`anyOf`/`allOf`/`not`, and anything
//   nested more than one property deep. A schema that relies on any of those will not
//   be fully enforced — see references/artifact.schema.json in each skill for what a
//   fuller validator would need to check.
function schemaTypeMatches(value: unknown, type: string): boolean {
  switch (type) {
    case "object": return typeof value === "object" && value !== null && !Array.isArray(value);
    case "array": return Array.isArray(value);
    case "string": return typeof value === "string";
    case "number": return typeof value === "number";
    case "integer": return typeof value === "number" && Number.isInteger(value);
    case "boolean": return typeof value === "boolean";
    case "null": return value === null;
    default: return true; // unrecognized type keyword: not our job to enforce it
  }
}

function validateNode(value: unknown, schema: any, path: string, errors: string[], depth: number): void {
  if (!schema || typeof schema !== "object") return;
  if (typeof schema.type === "string" && !schemaTypeMatches(value, schema.type)) {
    const actual = value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
    errors.push(`${path}: expected type "${schema.type}", got ${actual}`);
    return; // a wrongly-typed node's own required/enum/properties are meaningless to check further
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((e: unknown) => Object.is(e, value) || e === value)) {
    errors.push(`${path}: value ${JSON.stringify(value)} is not one of the schema's enum values`);
  }
  if (Array.isArray(schema.required) && value && typeof value === "object" && !Array.isArray(value)) {
    for (const key of schema.required) {
      if (!(key in (value as Record<string, unknown>))) {
        errors.push(`${path}: missing required property "${key}"`);
      }
    }
  }
  // One level deep only: descend into declared `properties` exactly once.
  if (depth === 0 && schema.properties && value && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, subSchema] of Object.entries<any>(schema.properties)) {
      if (key in (value as Record<string, unknown>)) {
        validateNode((value as Record<string, unknown>)[key], subSchema, `${path}.${key}`, errors, depth + 1);
      }
    }
  }
}

export function validateAgainstSchema(
  data: unknown, schema: unknown,
): { ok: true } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  validateNode(data, schema, "$", errors, 0);
  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

// --- skill_run: subprocess execution --------------------------------------------------

interface SkillProcessOutcome {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
}

/** Bounds an error message that may embed raw script stderr — never dump an unbounded
 * amount of target-derived or script-derived text into a thrown Error's message. */
function boundedForError(s: string, max = 2000): string {
  return s.length > max ? `${s.slice(0, max)}… (${s.length} bytes total)` : s;
}

function runSkillProcess(
  spawnImpl: typeof spawn,
  runPyPath: string, cwd: string, stdinPayload: string, timeoutMs: number,
): Promise<SkillProcessOutcome> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timedOut = false;
    const child = spawnImpl("python3", [runPyPath], { cwd, stdio: ["pipe", "pipe", "pipe"] });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdoutChunks.push(c));
    child.stderr.on("data", (c: Buffer) => stderrChunks.push(c));

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.once("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });

    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
        exitCode: code,
        timedOut,
      });
    });

    child.stdin.write(stdinPayload);
    child.stdin.end();
  });
}

export class ToolRunner {
  private readonly engagement: Engagement;
  private readonly store: ArtifactStore;
  private readonly fetchImpl: typeof fetch;
  private readonly skillAllowlist: readonly string[];
  private readonly skillEgress: Readonly<Record<string, SkillEgress>>;
  private readonly skillsRoot: string;
  private readonly skillTimeoutMs: number;
  private readonly spawnImpl: typeof spawn;

  constructor(opts: {
    engagement: Engagement;
    store: ArtifactStore;
    fetchImpl?: typeof fetch;
    /** The calling agent's skill_run allowlist. Defaults to none (fail closed) — a
     * caller that wants skill_run to do anything must say so explicitly, mirroring the
     * "capability is the tools array" rule: no skill is ambiently available. */
    skillAllowlist?: readonly string[];
    /** Overrides the built-in skill -> egress classification registry. Tests use this
     * to register a fixture skill's classification without touching the production
     * registry in tether.ts; production code omits it and gets SKILL_EGRESS. */
    skillEgress?: Readonly<Record<string, SkillEgress>>;
    /** Overrides SAHW_SKILLS_ROOT / the default repo skills/ dir — used by tests to
     * point at a temporary fixture skill directory. */
    skillsRoot?: string;
    /** Overrides SAHW_SKILL_TIMEOUT_MS / the 120s default. */
    skillTimeoutMs?: number;
    /** Overrides node:child_process's real `spawn` — tests use this to spy on/replace
     * process creation (e.g. to prove a denied call never spawns anything), mirroring
     * how `fetchImpl` above lets tests intercept http_request without a real network
     * call. Production code omits it and gets the real `spawn`. */
    spawnImpl?: typeof spawn;
  }) {
    this.engagement = opts.engagement;
    this.store = opts.store;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.skillAllowlist = opts.skillAllowlist ?? [];
    this.skillEgress = opts.skillEgress ?? SKILL_EGRESS;
    this.skillsRoot = opts.skillsRoot ?? SKILLS_ROOT;
    this.skillTimeoutMs = opts.skillTimeoutMs ?? SKILL_TIMEOUT_MS;
    this.spawnImpl = opts.spawnImpl ?? spawn;
  }

  /** Computes the Tether's decision for a call WITHOUT executing it. Exists so
   * agent.ts can record the decision as its own `tether` audit span (Part 1) — a
   * sibling of the `tool:<name>` span, not nested inside it — independent of whether
   * the call goes on to succeed. execute() below calls gate() itself too (defense in
   * depth: execute() must never trust that some caller already checked); both calls
   * are deterministic and pure, so there is no risk of the audit record and the real
   * enforcement decision diverging. */
  checkGate(tool: string, args: Record<string, unknown>): Decision {
    return gate(this.engagement, tool, args, this.skillAllowlist, this.skillEgress);
  }

  async execute(tool: string, args: Record<string, unknown>): Promise<ToolResult> {
    if (tool === "skill_run") {
      // Structural shape check happens BEFORE gate()/policy: a path-separator or ".."
      // skill_name is a caller-argument defect decidable with zero I/O, not a policy
      // judgement — see validateSkillNameShape() above. Denying it here also guarantees
      // no process is ever spawned for a malformed name, regardless of what the
      // registry/allowlist would otherwise have said about it.
      const shape = validateSkillNameShape(args.skill_name);
      if (!shape.ok) return { ok: false, kind: "invalid_argument", denied: shape.reason };
    }

    const decision = gate(this.engagement, tool, args, this.skillAllowlist, this.skillEgress);
    if (!decision.allow) return { ok: false, kind: "policy", denied: decision.reason };

    try {
      if (tool === "http_request") return { ok: true, result: await this.http(args) };
      if (tool === "read_artifact") return { ok: true, result: await this.readArtifact(args) };
      if (tool === "grep_artifact") return { ok: true, result: await this.grepArtifact(args) };
      if (tool === "skill_run") return { ok: true, result: await this.skillRun(args) };
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

  private async skillRun(args: Record<string, unknown>): Promise<SkillRunOutcome> {
    // Shape already validated by execute() before gate() ran; re-derive the narrowed
    // string rather than trust a stale outer variable.
    const skillName = String(args.skill_name ?? "");

    const inputJson = args.input_json;
    if (typeof inputJson !== "string" || inputJson.trim() === "") {
      throw new InvalidToolArgumentError(
        `input_json must be a non-empty JSON-encoded string, got ${JSON.stringify(inputJson)}`);
    }
    try {
      JSON.parse(inputJson);
    } catch (err) {
      // Decidable purely from the string's own content, no I/O — invalid_argument, same
      // convention as the sha256/regex checks elsewhere in this file.
      throw new InvalidToolArgumentError(
        `input_json is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
    }

    const skillDir = join(this.skillsRoot, skillName);
    const runPyPath = join(skillDir, "scripts", "run.py");
    const schemaPath = join(skillDir, "references", "artifact.schema.json");

    // A skill gate() already recognized as KNOWN (it's in the egress registry and the
    // caller's allowlist) can still be missing on disk — a skillsRoot misconfiguration,
    // or a registry entry with no matching fixture in a test. That is decidable without
    // ever spawning a process, so it is invalid_argument, not execution_error: retrying
    // the identical call cannot succeed until the caller's configuration changes.
    try {
      const st = await stat(skillDir);
      if (!st.isDirectory()) throw new Error("not a directory");
    } catch {
      throw new InvalidToolArgumentError(`unknown skill (no directory under skills root): ${skillName}`);
    }
    try {
      await stat(runPyPath);
    } catch {
      throw new InvalidToolArgumentError(`skill is missing scripts/run.py: ${skillName}`);
    }

    let schema: unknown;
    try {
      schema = JSON.parse(await readFile(schemaPath, "utf8"));
    } catch (err) {
      // The skill's OWN schema file being unreadable/corrupt is an infra defect of the
      // skill/registry, not something the caller's arguments could have avoided —
      // execution_error (a plain Error; not InvalidToolArgumentError).
      throw new Error(
        `skill is missing a readable references/artifact.schema.json: ${skillName}: ` +
        `${err instanceof Error ? err.message : String(err)}`);
    }

    const started = Date.now();
    const proc = await runSkillProcess(this.spawnImpl, runPyPath, skillDir, inputJson, this.skillTimeoutMs);
    const ms = Date.now() - started;

    if (proc.timedOut) {
      throw new Error(
        `skill_run timed out after ${this.skillTimeoutMs}ms and was killed: ${skillName} ` +
        `(stderr: ${boundedForError(proc.stderr)})`);
    }
    if (proc.exitCode !== 0) {
      throw new Error(
        `skill exited ${proc.exitCode}: ${skillName} (stderr: ${boundedForError(proc.stderr)})`);
    }
    // Narrowed to exactly 0 by the check above (a null exitCode only occurs when the
    // process was killed by a signal, which the timedOut branch already handled).
    const exitCode: number = proc.exitCode ?? 0;

    let parsedOutput: unknown;
    try {
      parsedOutput = JSON.parse(proc.stdout);
    } catch (err) {
      // Fail closed but keep the evidence: the raw (malformed) stdout is hashed into
      // the artifact store for forensics BEFORE the failure is thrown, but the message
      // carries only the parse error and the artifact's sha256 — never the raw text.
      const forensic = await this.store.put(proc.stdout);
      throw new Error(
        `skill produced malformed JSON on stdout: ${skillName}: ` +
        `${err instanceof Error ? err.message : String(err)} ` +
        `(raw output preserved as artifact ${forensic.sha256} for forensics)`);
    }

    const validation = validateAgainstSchema(parsedOutput, schema);
    if (!validation.ok) {
      // Same fail-closed-but-keep-the-evidence posture as the malformed-JSON branch
      // above: store the raw stdout, surface ONLY the validation error — never the
      // unvalidated content itself, which is exactly what schema validation exists to
      // not vouch for.
      const forensic = await this.store.put(proc.stdout);
      throw new Error(
        `skill output failed artifact schema validation: ${skillName}: ${validation.errors.join("; ")} ` +
        `(raw output preserved as artifact ${forensic.sha256} for forensics)`);
    }

    const artifact = await this.store.put(proc.stdout);
    return { kind: "skill_artifact", skill_name: skillName, exit_code: exitCode, ms, artifact, output: parsedOutput };
  }
}
