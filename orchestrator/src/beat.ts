import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { startActiveObservation, propagateAttributes } from "@langfuse/tracing";
import { loadEngagement } from "./config.js";
import { ArtifactStore } from "./artifacts.js";
import { ToolRunner, TOOL_SCHEMAS, type HttpCapture } from "./tools.js";
import { runAgent, type MinimalClient } from "./agent.js";
import { evaluate, type Invariant } from "./axiom.js";
import { gateProvenance } from "./provenance.js";
import { isStalled, loadStallConfig } from "./stall.js";
import { initObservability, type FindingRow } from "./obs/index.js";

/**
 * The exact snake_case vocabulary the benchmark harness scores `vuln_class` against.
 * Single source of truth: the hunter's system prompt is built from it, claim parsing
 * validates against it, and a test asserts every member is accepted. Free prose (e.g.
 * "Missing framing protection (clickjacking)") is a vocabulary violation, not a vuln —
 * the harness matches on this exact string, so a correct finding with the wrong
 * spelling scores as `missed`.
 *
 * This is a VOCABULARY, not target knowledge: it names classes of vulnerability in
 * the abstract, never an endpoint, a payload, or anything specific to the engagement
 * target. The black-box rule (no target hostname/path/payload in src/) still holds.
 */
export const VULN_CLASSES = [
  "auth_bypass", "business_logic", "clickjacking", "cors_misconfig", "crypto_disclosure",
  "deserialization_rce", "disposable_email_accepted", "forced_browsing", "idor",
  "improper_session_invalidation", "info_disclosure", "insecure_transport", "jwt_weak_key",
  "path_traversal", "rate_limit_absence", "sqli", "ssrf", "user_enumeration",
  "weak_password_policy", "xss_reflected", "xss_stored", "xxe",
] as const;

export type VulnClass = (typeof VULN_CLASSES)[number];

export function isVulnClass(v: unknown): v is VulnClass {
  return typeof v === "string" && (VULN_CLASSES as readonly string[]).includes(v);
}

const HUNTER_SYSTEM = [
  "You are the SAFE AI Hacker methodical hunter. You probe ONE hypothesis at a time",
  "against the in-scope target and read the FULL response before concluding.",
  "This beat hunts for MANY findings, one at a time: after each claim is verified you",
  "will be told the verdict and asked to continue hunting for the NEXT, DIFFERENT",
  "finding. Bank each cheap win and move on rather than perfecting any single",
  "hypothesis.",
  "",
  "Use the http_request tool to probe. When a response body is large or truncated,",
  "use grep_artifact with a targeted pattern to SEARCH the stored artifact instead of",
  "read_artifact to retrieve it — read_artifact only gives you a small bounded",
  "preview, so pulling a large body back through it takes many calls and still never",
  "gets you the whole thing. grep_artifact returns just the matching lines in one call.",
  "",
  "When you can state a concrete violated invariant, end your turn with a JSON",
  "object of this shape:",
  '{"vuln_class","endpoint","control_url","invariant":{"statement","type","expression"}}',
  "",
  "vuln_class MUST be exactly one of these snake_case strings — no prose, no",
  "parentheses, no extra words, no capitalisation, nothing outside this list:",
  VULN_CLASSES.join(", "),
  "",
  "invariant.type must be one of:",
  '  "body_contains"     - expression is a marker string. REQUIRES control_url.',
  "                        Matched against the whole exchange: status line, response",
  "                        headers, then body. CONFIRMED only if the marker is present",
  "                        for the exploit and ABSENT for the control.",
  '  "status_in"         - expression is a comma-separated status list. REQUIRES control_url.',
  '  "response_asserted" - a self-contained claim about the server\'s OWN configuration.',
  "                        NO control_url needed; omit it or set it to null.",
  "                        expression clauses, semicolon-separated, ALL must hold:",
  '                          header:name            header is present',
  '                          !header:name           header is absent',
  '                          header:name=substring  header present and value contains substring',
  '                        e.g. missing framing protection: "!header:x-frame-options;!header:content-security-policy"',
  '                        e.g. permissive CORS: "header:access-control-allow-origin=*;header:access-control-allow-credentials=true"',
  "",
  "Use response_asserted ONLY for the server's own configuration (header present/absent/value).",
  "",
  "SUGGESTED ORDER — cheapest checks first, as STRATEGY, not as answers. You must",
  "still find the real endpoints and evidence yourself; nothing below names one:",
  "  1. response_asserted claims from response headers alone, no control needed:",
  "     missing framing protection, permissive CORS where a wildcard allow-origin",
  "     coexists with allow-credentials, or a version/technology banner disclosed",
  "     in a header.",
  "  2. status_in claims with a control: an undocumented debug route, a shipped",
  "     source map, or a directory index returning 200 where a bogus sibling path",
  "     returns 404.",
  "  3. body_contains claims with a control: a file-serving parameter returning",
  "     file contents where a bogus filename does not; an error page leaking an",
  "     absolute path or a stack trace; or distinct responses for a registered vs",
  "     unregistered identifier.",
  "Your very first probe returns response headers — inspect them immediately and",
  "emit a cheap response_asserted claim right away if one holds. Do not spend turns",
  "exploring before you have banked a provable finding.",
  "",
  "For anything caused by YOUR input, use a differential type and give a control_url",
  "that SHOULD NOT exhibit the issue.",
  "",
  "You have a limited turn budget for EACH finding attempt: emit a claim well before",
  "you run out. A claim you emitted beats a better one you never stated. After a",
  "claim is verified you will be told the verdict — do NOT re-report the same",
  "vuln_class/endpoint pair; move on to a different one. If you are told a",
  "vuln_class was rejected, re-emit using one of the exact allowed values above.",
  "",
  "When you have exhausted profitable avenues and have no further hypothesis to",
  "try, say so in plain text (no JSON) and stop.",
].join("\n");

export interface RejectedClaim {
  raw: unknown;
  reason: string;
}

type BeatResult = {
  exitCode: number;
  findings: FindingRow[];
  stalled: boolean;
  reason: string | null;
  duplicates_suppressed: number;
  rejected_claims: RejectedClaim[];
};

type Env = Record<string, string | undefined>;
function numEnv(env: Env, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function feedbackForVerdict(vuln_class: string, endpoint: string, verdict: string, reason: string): string {
  return [
    `Verdict for ${vuln_class} @ ${endpoint}: ${verdict} (${reason}).`,
    "That pair is now banked — do not report it again this beat.",
    "Continue hunting: find a DIFFERENT vulnerability class or endpoint.",
  ].join(" ");
}

function feedbackForDuplicate(vuln_class: string, endpoint: string): string {
  return [
    `You already reported ${vuln_class} @ ${endpoint} in this beat — that is a`,
    "duplicate, so it was not re-verified. Pick a different vuln_class/endpoint pair.",
  ].join(" ");
}

function feedbackForMaxTurnsPerFinding(cap: number): string {
  return [
    `You used up this attempt's turn cap (${cap}) without stating a claim.`,
    "Drop that hypothesis and try a different, cheaper vuln_class/endpoint — you",
    "still have budget left in this beat.",
  ].join(" ");
}

function feedbackForInvalidVulnClass(got: unknown): string {
  return [
    `"${String(got)}" is not a valid vuln_class.`,
    `vuln_class MUST be exactly one of: ${VULN_CLASSES.join(", ")}.`,
    "No prose, no parentheses, no capitalisation — re-emit your claim with one of",
    "those exact values.",
  ].join(" ");
}

export async function runBeat(opts: {
  env: Record<string, string | undefined>;
  client: MinimalClient;
  fetchImpl?: typeof fetch;
  now?: Date;
}): Promise<BeatResult> {
  const engagement = loadEngagement(opts.env, opts.now);   // throws outside the window — MUST run
                                                            // before any span opens (see below)
  const stallCfg = loadStallConfig(opts.env);
  // initObservability() registers the Langfuse OpenTelemetry tracer provider (when
  // configured) BEFORE the "beat" span below is opened. That ordering is load-bearing:
  // opening a span before a provider is registered gets a no-op span, and
  // obs.traceId() (which reads getActiveTraceId() live) would then report no id even
  // though Langfuse IS configured.
  const obs = await initObservability(opts.env);
  const sandboxId = randomUUID();

  const store = new ArtifactStore(join(opts.env.SAHW_WORKSPACE ?? ".", "artifacts"));
  const runner = new ToolRunner({ engagement, store, fetchImpl: opts.fetchImpl });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), engagement.phaseTimeoutMs);
  const scopeUrls = engagement.scope.map((u) => u.toString());

  const maxFindings = Math.max(1, numEnv(opts.env, "SAHW_MAX_FINDINGS", 12));
  const maxTurnsPerFinding = Math.max(1, numEnv(opts.env, "SAHW_MAX_TURNS_PER_FINDING", 8));

  try {
    // One Langfuse trace per beat. Beats for the SAME engagement share sessionId
    // (the authRef), so repeated beats group into one Langfuse session.
    return await startActiveObservation("beat", async (span) => {
      return await propagateAttributes({
        traceName: "sahw-beat",
        sessionId: engagement.authRef,
        userId: opts.env.LANGFUSE_USER_ID ?? "sahw",
        tags: [engagement.profile, "m0"],
        metadata: { scope: scopeUrls.join(","), sandboxId },
      }, async () => {
        const result = await hunt();
        // setTraceIO is deprecated in @langfuse/tracing v5 but remains the only
        // trace-level input/output path; trace-level userId/sessionId/tags/metadata
        // go through propagateAttributes above instead.
        span.setTraceIO({
          input: scopeUrls,
          output: {
            findingsCount: result.findings.length,
            verdicts: result.findings.map((f) => f.verdict),
            stalled: result.stalled,
            reason: result.reason,
            duplicatesSuppressed: result.duplicates_suppressed,
            rejectedClaims: result.rejected_claims.length,
          },
        });
        return result;
      });

      /**
       * The multi-finding loop. Each iteration is ONE finding attempt: continue (or
       * start) the hunter conversation, get at most one claim out of it, verify it
       * (unless it's rejected or a duplicate), bank it immediately, then feed the
       * outcome back as the next user turn and loop. Budgets are SHARED across the
       * whole beat (engagement.maxTurns / engagement.budgetTokens), tracked
       * cumulatively here; maxTurnsPerFinding caps any single attempt so one greedy
       * hypothesis cannot consume the whole beat's turn budget.
       */
      async function hunt(): Promise<BeatResult> {
        const findings: FindingRow[] = [];
        const seen = new Set<string>();               // `${vuln_class}::${endpoint}`
        let duplicatesSuppressed = 0;
        const rejectedClaims: RejectedClaim[] = [];

        let messages: any[] | undefined = undefined;  // undefined until the first runAgent call
        let totalTurns = 0;
        let totalTokens = 0;

        const bail = (exitCode: number, stalled: boolean, reason: string | null): BeatResult => ({
          exitCode, findings, stalled, reason,
          duplicates_suppressed: duplicatesSuppressed,
          rejected_claims: rejectedClaims,
        });

        while (true) {
          if (findings.length >= maxFindings) {
            return bail(0, false, `max findings cap (${maxFindings}) reached`);
          }
          if (controller.signal.aborted) {
            return bail(0, false, findings.length ? null : "aborted before any finding was banked");
          }
          const remainingTurns = engagement.maxTurns - totalTurns;
          if (remainingTurns <= 0) {
            return bail(0, false, findings.length ? null : "turn budget exhausted before any finding was banked");
          }
          const remainingTokens = engagement.budgetTokens - totalTokens;
          if (remainingTokens <= 0) {
            return bail(0, false, findings.length ? null : "token budget exhausted before any finding was banked");
          }

          // Everything in `messages` before this call is prior conversation, not new
          // this attempt. First call builds system+user internally (length 2).
          const priorLen = messages ? messages.length : 2;
          const perCallMaxTurns = Math.min(maxTurnsPerFinding, remainingTurns);

          const run = await runAgent({
            client: opts.client,
            model: opts.env.SAHW_MODEL ?? "model",
            system: HUNTER_SYSTEM,
            user: `In-scope: ${scopeUrls.join(", ")}`,
            tools: TOOL_SCHEMAS,
            runner,
            maxTurns: perCallMaxTurns,
            budgetTokens: remainingTokens,
            signal: controller.signal,
            messages,
          });

          totalTurns += run.turns;
          totalTokens += run.tokens;
          messages = run.messages;

          const succeededToolCalls = run.toolCalls.filter((c) => c.ok).length;
          const repeatCounts = new Map<string, number>();
          for (const c of run.toolCalls) {
            const key = `${c.tool}:${c.args}`;
            repeatCounts.set(key, (repeatCounts.get(key) ?? 0) + 1);
          }

          const stall = await startActiveObservation("stall-check", async (stallSpan) => {
            stallSpan.update({
              input: {
                succeededToolCalls, newArtifacts: run.artifacts,
                repeatCounts: Object.fromEntries(repeatCounts),
              },
            });
            const r = isStalled(
              { succeededToolCalls, newArtifacts: run.artifacts,
                calls: run.toolCalls.map((c) => ({ tool: c.tool, args: c.args })) },
              stallCfg);
            stallSpan.update({ output: { stalled: r.stalled, reason: r.reason } });
            return r;
          });

          if (stall.stalled) {
            // A beat that has already banked at least one finding is NOT stalled just
            // because a later attempt did no work — that's the hunter running dry,
            // which ends the loop gracefully, not a failure of the whole beat.
            if (findings.length === 0) {
              return bail(stallCfg.exitCode, true, stall.reason);
            }
            return bail(0, false, stall.reason);
          }

          // Only the messages produced DURING this attempt can contain its claim —
          // scanning the whole history back would risk re-parsing an earlier, already
          // banked claim as if it were new.
          const newMessages = run.messages.slice(priorLen);
          const claim = parseClaim(newMessages);
          if (!claim) {
            if (run.stopReason === "max_turns") {
              // SAHW_MAX_TURNS_PER_FINDING cut this attempt off mid-hypothesis — it did
              // NOT finish (unlike "done"/"budget"/"aborted"). Ending the whole beat here
              // would let exactly the greedy-hypothesis failure mode the per-finding cap
              // exists to prevent take down the run instead of just this one attempt: the
              // shared turn/token budget still has plenty left. Abandon the hypothesis and
              // keep hunting.
              messages.push({ role: "user", content: feedbackForMaxTurnsPerFinding(maxTurnsPerFinding) });
              continue;
            }
            // The attempt actually finished (stopReason "done"/"budget"/"aborted") without
            // a parseable claim — either the hunter explicitly declared itself done, or it
            // just didn't produce one. Per the stall rule, this is a stall ONLY when NOTHING
            // has been banked yet; once ≥1 finding is banked, the hunter running dry ends the
            // loop gracefully rather than failing the whole beat.
            if (findings.length === 0) {
              return bail(stallCfg.exitCode, true, "hunter produced no parseable claim");
            }
            return bail(0, false, null);
          }

          if (!isVulnClass(claim.vuln_class)) {
            rejectedClaims.push({
              raw: claim.vuln_class,
              reason: `vuln_class ${JSON.stringify(claim.vuln_class)} is not in the allowed vocabulary`,
            });
            messages.push({ role: "user", content: feedbackForInvalidVulnClass(claim.vuln_class) });
            continue;
          }

          const dedupeKey = `${claim.vuln_class}::${claim.endpoint}`;
          if (seen.has(dedupeKey)) {
            duplicatesSuppressed += 1;
            messages.push({ role: "user", content: feedbackForDuplicate(claim.vuln_class, claim.endpoint) });
            continue;
          }

          // Axiom: replay the exploit AND a control, then evaluate the typed invariant.
          const exploit = await capture(runner, claim.endpoint);
          const control = claim.invariant.type === "response_asserted"
            ? null                                   // self-contained: no control exists
            : await capture(runner, claim.control_url);

          const axiom = await startActiveObservation("axiom-eval", async (axSpan) => {
            axSpan.update({
              input: {
                invariant: claim.invariant,
                exploitStatus: exploit?.response.status ?? null,
                controlStatus: control?.response.status ?? null,
              },
            });
            const r = evaluate(claim.invariant as Invariant, exploit!, control);
            axSpan.update({ output: { status: r.status, reason: r.reason } });
            return r;
          });

          // The REAL trace id, read live from the active span — or null. Never a
          // placeholder: when tracing is unavailable this flows into gateProvenance as
          // null, which is the one field that then legitimately downgrades an otherwise
          // CONFIRMED finding to NEEDS_REVIEW. That is the Provenance Gate doing its
          // job, not a regression — see gateProvenance's own doc comment.
          const langfuseTraceId = obs.traceId();

          const gated = await startActiveObservation("provenance-gate", async (pgSpan) => {
            const provenance = {
              utc: new Date().toISOString(),
              langfuseTraceId,
              exploitRequestHash: exploit?.artifact.sha256 ?? null,
              stdoutSha256: exploit?.artifact.sha256 ?? null,
              sandboxId,
              exitCode: 0,
            };
            pgSpan.update({
              input: {
                fieldsPresent: {
                  utc: Boolean(provenance.utc),
                  langfuseTraceId: provenance.langfuseTraceId !== null,
                  exploitRequestHash: provenance.exploitRequestHash !== null,
                  stdoutSha256: provenance.stdoutSha256 !== null,
                  sandboxId: provenance.sandboxId !== null,
                  exitCode: provenance.exitCode !== null,
                },
              },
            });
            const r = await gateProvenance(provenance, axiom.status, store);
            pgSpan.update({ output: { status: r.status, missing: r.missing } });
            return r;
          });

          const row: FindingRow = {
            engagement_id: engagement.authRef,
            finding_id: `SAHW-${randomUUID().slice(0, 8)}`,
            vuln_class: claim.vuln_class,
            endpoint: claim.endpoint,
            verdict: gated.status,
            invariant_type: claim.invariant.type,
            langfuse_trace_id: langfuseTraceId,
            utc: new Date().toISOString(),
          };

          // Bank it as soon as it's confirmed, not at the end of the beat — a run
          // that dies mid-way must still have what it already proved.
          findings.push(row);
          seen.add(dedupeKey);
          await obs.mergeEndpoint(claim.endpoint, "GET");
          await obs.mergeFinding(row);
          await obs.recordFinding(row);

          messages.push({
            role: "user",
            content: feedbackForVerdict(row.vuln_class, row.endpoint, row.verdict, axiom.reason),
          });
        }
      }
    });
  } finally {
    clearTimeout(timer);
    // Runs AFTER the "beat" span (and every child span opened inside it) has
    // already ended, so shutdown flushes a complete trace rather than racing it.
    await obs.shutdown();
  }
}

/**
 * Extract every balanced {...} region from a string. Models routinely wrap the
 * claim in ```json fences or wrap prose around it, so parsing the WHOLE message
 * as JSON (the original approach) failed on well-formed claims and the beat
 * reported a stall it had not actually suffered.
 */
function jsonCandidates(text: string): string[] {
  const out: string[] = [];
  let depth = 0, start = -1, inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "{") { if (depth === 0) start = i; depth++; }
    else if (ch === "}") {
      depth--;
      if (depth === 0 && start >= 0) { out.push(text.slice(start, i + 1)); start = -1; }
      if (depth < 0) depth = 0;
    }
  }
  return out;
}

function parseClaim(messages: any[]): any | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const c = messages[i]?.content;
    if (typeof c !== "string") continue;
    // Longest first: a fenced claim is usually the largest balanced object present.
    for (const cand of jsonCandidates(c).sort((a, b) => b.length - a.length)) {
      let o: any;
      try { o = JSON.parse(cand); } catch { continue; }
      if (!o?.endpoint || !o?.invariant?.type) continue;
      // A differential type is worthless without a control; a self-contained one
      // must not have its verdict decided by an unrelated second request.
      if (o.invariant.type === "response_asserted") return o;
      if (o.control_url) return o;
    }
  }
  return null;
}

async function capture(runner: ToolRunner, url: string): Promise<HttpCapture | null> {
  const out = await runner.execute("http_request", { method: "GET", url });
  return out.ok ? (out.result as HttpCapture) : null;
}
