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

const HUNTER_SYSTEM = [
  "You are the SAFE AI Hacker methodical hunter. You probe ONE hypothesis at a time",
  "against the in-scope target and read the FULL response before concluding.",
  "Use the http_request tool to probe. When you can state a concrete violated",
  "invariant, end your turn with a JSON object of this shape:",
  '{"vuln_class","endpoint","control_url","invariant":{"statement","type","expression"}}',
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
  "STRATEGY — bank a cheap win FIRST, then go deeper:",
  "Your very first probe returns response headers. Inspect them immediately. If framing",
  "protection (x-frame-options / content-security-policy) is missing, or CORS is permissive,",
  "or a server version is disclosed, emit THAT claim right away as response_asserted — it costs",
  "one request and needs no control. Do not spend turns exploring before you have banked a",
  "provable finding. Only after emitting a claim should you pursue deeper input-driven issues.",
  "You have a limited turn budget: emit a claim well before you run out. A claim you emitted",
  "beats a better one you never stated.",
  "For anything caused by YOUR input, use a differential type and give a control_url that",
  "SHOULD NOT exhibit the issue. Report one finding per beat, the clearest one you proved.",
].join("\n");

type BeatResult = { exitCode: number; findings: FindingRow[]; stalled: boolean; reason: string | null };

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
          },
        });
        return result;
      });

      async function hunt(): Promise<BeatResult> {
        const run = await runAgent({
          client: opts.client,
          model: opts.env.SAHW_MODEL ?? "model",
          system: HUNTER_SYSTEM,
          user: `In-scope: ${scopeUrls.join(", ")}`,
          tools: TOOL_SCHEMAS,
          runner,
          maxTurns: engagement.maxTurns,
          budgetTokens: engagement.budgetTokens,
          signal: controller.signal,
        });

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
          return { exitCode: stallCfg.exitCode, findings: [], stalled: true, reason: stall.reason };
        }

        const claim = parseClaim(run.messages);
        if (!claim) {
          return { exitCode: stallCfg.exitCode, findings: [], stalled: true,
                   reason: "hunter produced no parseable claim" };
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
        const findings = [row];
        await obs.mergeEndpoint(claim.endpoint, "GET");
        await obs.mergeFinding(row);
        await obs.recordFinding(row);

        return { exitCode: 0, findings, stalled: false, reason: null };
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
