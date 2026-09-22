import { randomUUID } from "node:crypto";
import { join } from "node:path";
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
  "When you can state a concrete violated invariant, reply with ONLY a JSON object:",
  '{"vuln_class","endpoint","control_url","invariant":{"statement","type","expression"}}',
  'where invariant.type is one of: body_contains, status_in.',
  "control_url must be a benign request that SHOULD NOT exhibit the issue.",
].join(" ");

export async function runBeat(opts: {
  env: Record<string, string | undefined>;
  client: MinimalClient;
  fetchImpl?: typeof fetch;
  now?: Date;
}): Promise<{ exitCode: number; findings: FindingRow[]; stalled: boolean; reason: string | null }> {
  const engagement = loadEngagement(opts.env, opts.now);   // throws outside the window
  const stallCfg = loadStallConfig(opts.env);
  const obs = await initObservability(opts.env);
  const sandboxId = randomUUID();

  const store = new ArtifactStore(join(opts.env.SAHW_WORKSPACE ?? ".", "artifacts"));
  const runner = new ToolRunner({ engagement, store, fetchImpl: opts.fetchImpl });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), engagement.phaseTimeoutMs);

  const findings: FindingRow[] = [];
  try {
    const hunt = await runAgent({
      client: opts.client,
      model: opts.env.SAHW_MODEL ?? "model",
      system: HUNTER_SYSTEM,
      user: `In-scope: ${engagement.scope.map((u) => u.toString()).join(", ")}`,
      tools: TOOL_SCHEMAS,
      runner,
      maxTurns: engagement.maxTurns,
      budgetTokens: engagement.budgetTokens,
      signal: controller.signal,
    });

    const stall = isStalled(
      { succeededToolCalls: hunt.toolCalls.filter((c) => c.ok).length,
        newArtifacts: hunt.artifacts,
        calls: hunt.toolCalls.map((c) => ({ tool: c.tool, args: c.args })) },
      stallCfg);

    if (stall.stalled) {
      return { exitCode: stallCfg.exitCode, findings: [], stalled: true, reason: stall.reason };
    }

    const claim = parseClaim(hunt.messages);
    if (!claim) {
      return { exitCode: stallCfg.exitCode, findings: [], stalled: true,
               reason: "hunter produced no parseable claim" };
    }

    // Axiom: replay the exploit AND a control, then evaluate the typed invariant.
    const exploit = await capture(runner, claim.endpoint);
    const control = await capture(runner, claim.control_url);
    const axiom = evaluate(claim.invariant as Invariant, exploit!, control);

    const gated = await gateProvenance({
      utc: new Date().toISOString(),
      langfuseTraceId: obs.traceId() ?? "local",
      exploitRequestHash: exploit?.artifact.sha256 ?? null,
      stdoutSha256: exploit?.artifact.sha256 ?? null,
      sandboxId,
      exitCode: 0,
    }, axiom.status, store);

    const row: FindingRow = {
      engagement_id: engagement.authRef,
      finding_id: `SAHW-${randomUUID().slice(0, 8)}`,
      vuln_class: claim.vuln_class,
      endpoint: claim.endpoint,
      verdict: gated.status,
      invariant_type: claim.invariant.type,
      langfuse_trace_id: obs.traceId() ?? "local",
      utc: new Date().toISOString(),
    };
    findings.push(row);
    await obs.mergeEndpoint(claim.endpoint, "GET");
    await obs.mergeFinding(row);
    await obs.recordFinding(row);

    return { exitCode: 0, findings, stalled: false, reason: null };
  } finally {
    clearTimeout(timer);
    await obs.shutdown();
  }
}

function parseClaim(messages: any[]): any | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const c = messages[i]?.content;
    if (typeof c !== "string") continue;
    try {
      const o = JSON.parse(c);
      if (o?.invariant?.type && o?.endpoint && o?.control_url) return o;
    } catch { /* not a claim */ }
  }
  return null;
}

async function capture(runner: ToolRunner, url: string): Promise<HttpCapture | null> {
  const out = await runner.execute("http_request", { method: "GET", url });
  return out.ok ? (out.result as HttpCapture) : null;
}
