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
import { VULN_CLASSES, isVulnClass, type VulnClass } from "./vuln-classes.js";
import {
  loadSpine, saveSpine, updateSpine,
  type SpineEndpoint, type ProvedEntry, type AttemptedEntry, type RecoveredIntel,
  type SpineBeatRecord,
} from "./spine.js";
import { buildHunterBrief } from "./brief.js";

// Re-exported for backward compatibility: existing callers (and test/beat.test.ts)
// import these from beat.js. The vocabulary itself now lives in vuln-classes.ts so
// src/brief.ts can use it without a beat.ts <-> brief.ts import cycle.
export { VULN_CLASSES, isVulnClass };
export type { VulnClass };

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
  /** true if this beat started from a brand-new Spine (no prior file, a corrupt
   * one, or one for a different engagement/scope) rather than continuing a prior
   * one. See src/spine.ts loadSpine. */
  spine_fresh: boolean;
  /** Why spine_fresh is true — e.g. an engagement/scope mismatch or a corrupt
   * progress.json — or null when the spine continued normally. */
  spine_fresh_reason: string | null;
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

/**
 * A run needs its own session, not the engagement's.
 *
 * sessionId was engagement.authRef, so every beat ever executed against a target
 * collapsed into ONE Langfuse session and runs could not be compared. A session
 * should be "this run", which may contain several beats.
 *
 * Shape: sahw-<host>-<YYYYMMDD-HHMMSSZ>-<codename>
 *   e.g. sahw-10.0.0.1-20260922-080715Z-quiet-ledger
 *
 * The codename is deterministic from the run id, so the same run always yields the
 * same memorable label — greppable in logs, and easy to say out loud when two runs
 * are being compared. The engagement is preserved as a tag and in metadata, so
 * filtering by engagement still works.
 */
const CODENAME_LEFT = [
  "quiet", "amber", "hollow", "narrow", "brittle", "candid", "crimson", "still",
  "patient", "sudden", "civil", "blunt", "clear", "gilded", "sparse", "wary",
] as const;
const CODENAME_RIGHT = [
  "ledger", "vault", "teller", "transit", "mandate", "escrow", "cipher", "tally",
  "custody", "clearing", "docket", "remit", "bourse", "warrant", "assay", "drawer",
] as const;

function codenameFor(runId: string): string {
  // FNV-1a: tiny, stable, and dependency-free. Only needs to be well-spread, not secure.
  let h = 0x811c9dc5;
  for (let i = 0; i < runId.length; i++) {
    h ^= runId.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  const left = CODENAME_LEFT[h % CODENAME_LEFT.length];
  const right = CODENAME_RIGHT[(h >>> 8) % CODENAME_RIGHT.length];
  return `${left}-${right}`;
}

export function buildRunSession(opts: {
  scope: URL[]; runId: string; now: Date; override?: string;
}): { sessionId: string; runId: string; codename: string; startedUtc: string } {
  const t = opts.now.toISOString();                       // 2026-09-22T08:07:15.123Z
  const stamp = `${t.slice(0, 10).replace(/-/g, "")}-${t.slice(11, 19).replace(/:/g, "")}Z`;
  const host = opts.scope[0]?.hostname ?? "unknown-target";
  const codename = codenameFor(opts.runId);
  // A 4-char tail from the run id keeps sessions unique even when two runs start
  // in the same second and their codenames collide (the wordlists give 256 pairs,
  // so collisions are ordinary birthday behaviour and purely cosmetic).
  const tail = opts.runId.replace(/[^a-z0-9]/gi, "").slice(0, 4).toLowerCase() || "0000";
  return {
    sessionId: opts.override?.trim() || `sahw-${host}-${stamp}-${codename}-${tail}`,
    runId: opts.runId,
    codename,
    startedUtc: t,
  };
}

// ---- Spine-facing helpers --------------------------------------------------------

/** A captured exchange (an exploit or control probe), reduced to what the Spine's
 * attack_surface records — status and content-type, never the body. */
function toSpineEndpoint(capture: HttpCapture): SpineEndpoint {
  return {
    url: capture.request.url,
    method: capture.request.method,
    status: capture.response.status,
    content_type: headerValueCI(capture.response.headers, "content-type"),
  };
}

function headerValueCI(headers: Record<string, string> | undefined | null, name: string): string | null {
  if (!headers) return null;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v;
  }
  return null;
}

/**
 * A model claim may attach an optional "intel" object of durable recon facts (see
 * <output_contract> in src/brief.ts) — deterministic code decides whether to keep
 * it: only string/boolean VALUES are accepted, nothing nested, so a malformed or
 * hostile shape simply drops rather than corrupting the spine. Secret-looking
 * values are still stripped later, in spine.ts's updateSpine — this is not the only
 * guard.
 */
function extractIntel(claim: unknown): RecoveredIntel | null {
  const raw = (claim as { intel?: unknown } | null)?.intel;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const out: RecoveredIntel = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === "string" || typeof v === "boolean") out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * A cheap, generic fallback signal for recovered_intel, derived purely from
 * endpoints actually observed this run — never a literal. A model-reported
 * "intel" object (see extractIntel) is more specific and always wins on conflict;
 * this only fills gaps a claim never mentioned.
 */
function inferRecoveredIntel(scopeOrigins: string[], endpoints: SpineEndpoint[]): RecoveredIntel {
  const intel: RecoveredIntel = {};
  const foreignOrigins = new Set<string>();
  let sourceMapsSeen = false;
  for (const ep of endpoints) {
    try {
      const origin = new URL(ep.url).origin;
      if (!scopeOrigins.includes(origin)) foreignOrigins.add(origin);
    } catch {
      // Unparseable URL — nothing to infer from it.
    }
    if (/\.map(\?|$)/.test(ep.url)) sourceMapsSeen = true;
  }
  if (foreignOrigins.size > 0) intel.api_base = [...foreignOrigins].sort().join(", ");
  if (sourceMapsSeen) intel.source_maps_seen = true;
  return intel;
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

  const workspace = opts.env.SAHW_WORKSPACE ?? ".";
  const store = new ArtifactStore(join(workspace, "artifacts"));
  const runner = new ToolRunner({ engagement, store, fetchImpl: opts.fetchImpl });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), engagement.phaseTimeoutMs);
  const scopeUrls = engagement.scope.map((u) => u.toString());
  const scopeOrigins = engagement.scope.map((u) => u.origin);

  const maxFindings = Math.max(1, numEnv(opts.env, "SAHW_MAX_FINDINGS", 12));
  const maxTurnsPerFinding = Math.max(1, numEnv(opts.env, "SAHW_MAX_TURNS_PER_FINDING", 8));

  // THE SPINE. Read first, written last, every beat — see src/spine.ts. A missing,
  // corrupt, or engagement/scope-mismatched spine degrades to a fresh one (logged
  // and recorded, never thrown); a schema_version newer than this build understands
  // is refused outright and legitimately throws here, before any span opens — the
  // same posture as loadEngagement above.
  const spineLoad = await loadSpine({ workspace, authRef: engagement.authRef, scopeOrigins });

  // GENERATED FROM STATE, AS XML. Built once, from the spine as loaded — the
  // conversation's system message is only set on the FIRST runAgent call of the
  // beat (see agent.ts: system/user are ignored once `messages` is supplied), so
  // regenerating it mid-beat would never reach the model anyway. What THIS beat
  // itself discovers is folded into the spine at the end, for the NEXT beat.
  const hunterBrief = buildHunterBrief({
    attackSurface: spineLoad.spine.attack_surface,
    recoveredIntel: spineLoad.spine.recovered_intel,
    proved: spineLoad.spine.proved,
    attempted: spineLoad.spine.attempted,
    turnsRemaining: engagement.maxTurns,
    findingsRemaining: maxFindings,
  });

  try {
    // One Langfuse trace per beat; one SESSION per run, so runs are comparable.
    // The engagement stays discoverable via the tag and metadata below.
    const session = buildRunSession({
      scope: engagement.scope,
      // SAHW_RUN_ID groups several beats of one run into a single session.
      // Unset, each beat is its own run — which is the case for a single CLI call.
      runId: opts.env.SAHW_RUN_ID?.trim() || sandboxId,
      now: opts.now ?? new Date(),
      override: opts.env.SAHW_SESSION_ID,
    });
    return await startActiveObservation("beat", async (span) => {
      return await propagateAttributes({
        traceName: `sahw-beat · ${session.codename}`,
        sessionId: session.sessionId,
        userId: opts.env.LANGFUSE_USER_ID ?? "sahw",
        tags: [engagement.profile, "m0", `engagement:${engagement.authRef}`],
        metadata: {
          scope: scopeUrls.join(","),
          sandboxId,
          engagement: engagement.authRef,
          run_codename: session.codename,
          run_started_utc: session.startedUtc,
          spine_fresh: String(spineLoad.fresh),
        },
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

        // What THIS beat learns, folded into the spine at every exit — including a
        // stall or a failure. This is the whole point: a beat that learned "this
        // endpoint answers uniformly to every probe" is a beat whose lesson must
        // survive.
        const discoveredEndpoints: SpineEndpoint[] = [];
        const provedEntries: ProvedEntry[] = [];
        const attemptedEntries: AttemptedEntry[] = [];
        let recoveredIntelFromClaims: RecoveredIntel = {};
        const beatStartedUtc = new Date().toISOString();

        let messages: any[] | undefined = undefined;  // undefined until the first runAgent call
        let totalTurns = 0;
        let totalTokens = 0;
        // Stall is a BEAT-level rule, not an attempt-level one. A beat that already
        // executed real work is not stalled just because one later hypothesis ran dry —
        // that attempt simply ends, as it does for max_turns. Scoping the check to a
        // single attempt aborted a beat that had already mapped 5 endpoints including
        // the API root, discarding every bit of it.
        let beatSucceededToolCalls = 0;
        let beatArtifacts = 0;
        const beatCalls: Array<{ tool: string; args: string }> = [];

        /** Builds this beat's contribution to the spine and saves it. Never throws —
         * a save failure is logged and swallowed, exactly like a corrupt read: the
         * beat's own result must not be lost because the workspace disk hiccuped. */
        async function persistSpine(stalled: boolean, reason: string | null): Promise<void> {
          const beatRecord: SpineBeatRecord = {
            beat_id: sandboxId,
            started_utc: beatStartedUtc,
            ended_utc: new Date().toISOString(),
            findings_banked: findings.length,
            stalled,
            reason,
            codename: session.codename,
          };
          const inferred = inferRecoveredIntel(
            scopeOrigins, [...spineLoad.spine.attack_surface, ...discoveredEndpoints]);
          const nextSpine = updateSpine(spineLoad.spine, {
            beat: beatRecord,
            discoveredEndpoints,
            recoveredIntel: { ...inferred, ...recoveredIntelFromClaims },
            proved: provedEntries,
            attempted: attemptedEntries,
          });
          try {
            await saveSpine(workspace, nextSpine);
          } catch (err) {
            console.error(`[spine] failed to save progress.json (continuing): ${(err as Error).message}`);
          }
        }

        const bail = async (exitCode: number, stalled: boolean, reason: string | null): Promise<BeatResult> => {
          await persistSpine(stalled, reason);
          return {
            exitCode, findings, stalled, reason,
            duplicates_suppressed: duplicatesSuppressed,
            rejected_claims: rejectedClaims,
            spine_fresh: spineLoad.fresh,
            spine_fresh_reason: spineLoad.freshReason,
          };
        };

        try {
          return await loop();
        } catch (err) {
          // An unexpected throw (not one of the documented stop conditions below,
          // which all go through `bail`) must still leave a trace in the spine —
          // "write the spine even when the beat stalls or FAILS". Save, then
          // rethrow: this does not swallow the failure, it just makes sure the
          // failure itself is not silently lossy.
          await persistSpine(true, `beat failed: ${(err as Error)?.message ?? String(err)}`);
          throw err;
        }

        async function loop(): Promise<BeatResult> {
        while (true) {
          if (findings.length >= maxFindings) {
            return await bail(0, false, `max findings cap (${maxFindings}) reached`);
          }
          if (controller.signal.aborted) {
            return await bail(0, false, findings.length ? null : "aborted before any finding was banked");
          }
          const remainingTurns = engagement.maxTurns - totalTurns;
          if (remainingTurns <= 0) {
            return await bail(0, false, findings.length ? null : "turn budget exhausted before any finding was banked");
          }
          const remainingTokens = engagement.budgetTokens - totalTokens;
          if (remainingTokens <= 0) {
            return await bail(0, false, findings.length ? null : "token budget exhausted before any finding was banked");
          }

          // Everything in `messages` before this call is prior conversation, not new
          // this attempt. First call builds system+user internally (length 2).
          const priorLen = messages ? messages.length : 2;
          const perCallMaxTurns = Math.min(maxTurnsPerFinding, remainingTurns);

          const run = await runAgent({
            client: opts.client,
            model: opts.env.SAHW_MODEL ?? "model",
            system: hunterBrief,
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

          // Every endpoint the hunter actually touched this attempt, metadata-only
          // (status + content-type, never a body) — feeds the Spine's attack_surface
          // so a LATER beat inherits the map instead of re-deriving it.
          for (const hc of run.httpCalls) {
            discoveredEndpoints.push({
              url: hc.url, method: hc.method, status: hc.status, content_type: hc.contentType,
            });
          }

          beatSucceededToolCalls += run.toolCalls.filter((c) => c.ok).length;
          beatArtifacts += run.artifacts;
          for (const c of run.toolCalls) beatCalls.push({ tool: c.tool, args: c.args });

          const succeededToolCalls = beatSucceededToolCalls;
          const repeatCounts = new Map<string, number>();
          for (const c of beatCalls) {
            const key = `${c.tool}:${c.args}`;
            repeatCounts.set(key, (repeatCounts.get(key) ?? 0) + 1);
          }

          const stall = await startActiveObservation("stall-check", async (stallSpan) => {
            stallSpan.update({
              input: {
                scope: "beat", succeededToolCalls, newArtifacts: beatArtifacts,
                repeatCounts: Object.fromEntries(repeatCounts),
              },
            });
            const r = isStalled(
              { succeededToolCalls, newArtifacts: beatArtifacts, calls: beatCalls },
              stallCfg);
            stallSpan.update({ output: { stalled: r.stalled, reason: r.reason } });
            return r;
          });

          if (stall.stalled) {
            // A beat that has already banked at least one finding is NOT stalled just
            // because a later attempt did no work — that's the hunter running dry,
            // which ends the loop gracefully, not a failure of the whole beat.
            if (findings.length === 0) {
              return await bail(stallCfg.exitCode, true, stall.reason);
            }
            return await bail(0, false, stall.reason);
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
            if (run.stopReason === "model_error") {
              // A transport/provider failure, NOT the hunter failing to produce a claim.
              // Reporting this as "no parseable claim" would blame the model for a network
              // fault and send a reader debugging the wrong layer. End the beat, keep every
              // finding already banked, and name the real cause.
              const why = `model call failed: ${run.modelError ?? "unknown"}`;
              if (findings.length === 0) return await bail(stallCfg.exitCode, true, why);
              return await bail(0, false, why);
            }
            // The attempt actually finished (stopReason "done"/"budget"/"aborted") without
            // a parseable claim — either the hunter explicitly declared itself done, or it
            // just didn't produce one. Per the stall rule, this is a stall ONLY when NOTHING
            // has been banked yet; once ≥1 finding is banked, the hunter running dry ends the
            // loop gracefully rather than failing the whole beat.
            if (findings.length === 0) {
              return await bail(stallCfg.exitCode, true, "hunter produced no parseable claim");
            }
            return await bail(0, false, null);
          }

          // A claim may carry durable recon facts under "intel" independent of its own
          // vuln_class/verdict — captured here, before the vuln_class/dedupe checks
          // below, so it survives even a rejected or duplicate claim.
          const claimIntel = extractIntel(claim);
          if (claimIntel) recoveredIntelFromClaims = { ...recoveredIntelFromClaims, ...claimIntel };

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
          if (exploit) discoveredEndpoints.push(toSpineEndpoint(exploit));
          if (control) discoveredEndpoints.push(toSpineEndpoint(control));

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

          // Route into the spine on the RAW axiom verdict, not the provenance-gated
          // one: a hypothesis whose invariant genuinely passed (axiom.status ===
          // "CONFIRMED") belongs in `proved` even if gateProvenance downgraded the
          // reported verdict to NEEDS_REVIEW for missing tracing — that downgrade is
          // an infra/provenance concern, not evidence the hunter should re-derive
          // this pair next beat. Anything the invariant itself did not pass
          // (FALSE_POSITIVE / NEEDS_REVIEW / BLOCKED from axiom) is a real dead end.
          if (axiom.status === "CONFIRMED") {
            provedEntries.push({
              vuln_class: claim.vuln_class, endpoint: claim.endpoint,
              invariant_type: claim.invariant.type, verdict: gated.status, finding_id: row.finding_id,
            });
          } else {
            attemptedEntries.push({
              vuln_class: claim.vuln_class, endpoint: claim.endpoint,
              invariant_type: claim.invariant.type, outcome: axiom.status, why: axiom.reason,
            });
          }

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
