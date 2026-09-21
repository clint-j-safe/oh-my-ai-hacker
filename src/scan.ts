/**
 * scan — the autonomous black-box scan entry. The model (LlmRunner) drives
 * discovery + probing through Tether-gated tools; findings are validated by the
 * Axiom (deterministic invariant replay); every run is traced to Langfuse.
 */

import { parseScope } from "./scope.js";
import { Axiom } from "./axiom.js";
import { LlmRunner } from "./llm-runner.js";
import { LangfuseTracer } from "./langfuse.js";
import { LlmJudge } from "./judge.js";
import { OpenRouterLlm } from "./llm.js";
import { SecurityFabric } from "./graph.js";

export const SYSTEM_PROMPT = `You are SAFE AI Hacker — an autonomous black-box web application penetration-testing agent running under EXPLICIT authorization.

HARD RULES (deterministic enforcement backs these):
1. Authorized scope ONLY — the in-scope URLs you are given. Never probe anything else. Out-of-scope requests are automatically DENIED.
2. Read-only / reversible (L2). No destructive writes, no DoS, no resource exhaustion, no persistence, no real-PII exfiltration.
3. You have NO prior knowledge of the application. Discover everything from the target's own responses and its served client-side JavaScript. Never assume an endpoint exists — observe it.
4. Use the http_request tool to probe. Keep requests conservative and minimal.
5. For every suspected finding, collect BOTH the exploit evidence (the response that proves the flaw) AND a control (a benign/malformed request that should NOT trigger it), so the flaw can be verified differentially.
6. When done, emit your findings as a JSON array. Each finding: {"finding_id": "...", "title": "...", "vuln_class": "...", "affected": {"method": "GET", "url": "..."}, "invariant": {"statement": "...", "type": "body_contains|status_in|derived|state_changed|state_violated|file_created_then_deleted", "expression": "..."}, "evidence": {"exploit_response_excerpt": "...", "control_response_excerpt": "...", "status": <int>}}.
Be concise and evidence-first.`;

export interface ScanOptions {
  apiKey: string;
  model: string;
  judgeModel?: string;
  inScopeUrls: string[];
  sessionId?: string; // Langfuse session grouping (engagement id)
  langfuse?: { host: string; publicKey: string; secretKey: string };
  maxTurns?: number;
  temperature?: number;
  workspaceRoot?: string;
  baseUrl?: string;
  judgeThreshold?: number;
  neo4j?: { uri: string; user: string; password: string };
}

export interface ScanResult {
  objective: string;
  finalText: string;
  cost: number;
  tokens: { input: number; output: number };
  findings: Array<{ finding: unknown; verdict: Awaited<ReturnType<Axiom["verify"]>> }>;
}

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const scope = parseScope({ inScopeUrls: opts.inScopeUrls });
  const llm = new OpenRouterLlm({ apiKey: opts.apiKey, baseUrl: opts.baseUrl });
  const axiom = new Axiom({ judge: new LlmJudge(llm, opts.judgeModel ?? opts.model), ...(opts.judgeThreshold !== undefined ? { judgeThreshold: opts.judgeThreshold } : {}) });
  const runner = new LlmRunner({
    apiKey: opts.apiKey,
    model: opts.model,
    system: SYSTEM_PROMPT,
    scope,
    workspaceRoot: opts.workspaceRoot ?? "/tmp/sahw-sandbox",
    maxTurns: opts.maxTurns,
    temperature: opts.temperature,
    baseUrl: opts.baseUrl,
  });

  const objective = `AUTHORIZED black-box penetration test. In-scope targets: ${opts.inScopeUrls.join(", ")}.\n` +
    `Discover the application surface (pages, JS bundles, API endpoints, parameters) and identify UNAUTHENTICATED vulnerabilities first. ` +
    `Probe with http_request. Then report findings as the JSON array described in your instructions.`;

  const result = await runner.run("recon", objective);
  const findings = [];
  for (const finding of result.findings) {
    findings.push({ finding, verdict: await axiom.verify(finding as never) });
  }

  // Persist findings + endpoints to the Neo4j security fabric (canonical state).
  if (opts.neo4j) {
    const fabric = new SecurityFabric(opts.neo4j);
    for (const { finding, verdict } of findings) {
      const f = finding as { finding_id?: string; title?: string; vuln_class?: string; affected?: { url?: string } };
      const fid = f.finding_id ?? `sahw-${Math.random().toString(36).slice(2, 8)}`;
      const url = f.affected?.url ?? "";
      await fabric.upsertVuln({
        vuln_id: fid,
        vuln_class: f.vuln_class ?? "",
        title: f.title ?? "",
        verdict: verdict.status,
        confidence: verdict.confidence,
        decided_by: verdict.decided_by,
      });
      if (url) {
        await fabric.upsertAsset({ asset_key: url, type: "endpoint", url });
        await fabric.linkAssetHasVuln(url, fid);
      }
    }
    await fabric.close();
  }

  if (opts.langfuse) {
    const tracer = new LangfuseTracer(opts.langfuse);
    await tracer.trace({
      name: "sahw-recon",
      input: objective,
      output: result.finalText,
      model: opts.model,
      cost: result.costUsd,
      tokens: { input: result.tokens.input, output: result.tokens.output },
      metadata: { inScopeUrls: opts.inScopeUrls, findingsCount: findings.length },
      sessionId: opts.sessionId,
    });
  }

  return {
    objective,
    finalText: result.finalText,
    cost: result.costUsd,
    tokens: { input: result.tokens.input, output: result.tokens.output },
    findings,
  };
}
