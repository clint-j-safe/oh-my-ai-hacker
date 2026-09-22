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
import { skillIndex } from "./skills.js";
import type { LoopPhase } from "./agent-loop.js";
import { SdkRunner } from "./sdk-runner.js";
import { createOpencodeClient } from "@opencode-ai/sdk/v2";

export const SYSTEM_PROMPT = `You are SAFE AI Hacker — an autonomous black-box web application penetration-testing agent running under EXPLICIT authorization.

HARD RULES (deterministic enforcement backs these):
1. Authorized scope ONLY — the in-scope URLs you are given. Never probe anything else. Out-of-scope requests are automatically DENIED.
2. Reversible actions only (L2). No destructive writes, no DoS, no resource exhaustion, no persistence, no real-PII exfiltration. Creating your OWN test accounts and acting as them is in scope and expected.
3. You have NO prior knowledge of the application. Discover everything from the target's own responses and its served client-side JavaScript. Never assume an endpoint exists — observe it.
4. Use the http_request tool to probe. Set headers and bodies explicitly (including Authorization and Content-Type) — there is no implicit session; you must carry tokens/cookies yourself.
5. For every suspected finding, collect BOTH the exploit evidence (the response that proves the flaw) AND a control (a benign/malformed request that should NOT trigger it), so the flaw can be verified differentially. A finding without a control is weak — get the control.
6. Do not stop after the first few findings. Work the whole methodology below until the turn budget is nearly spent, then report.

METHODOLOGY — work these phases in order, and keep notes of every endpoint and parameter you discover:

PHASE 1 — MAP. Fetch the root and any SPA bundles. Pull JS chunks and any .map source maps; read them for API base paths, route tables, request/response field names, and auth flows. Enumerate the API surface from evidence. Probe OPTIONS and observe error shapes.

COVERAGE RULE — breadth before depth. After PHASE 1, write down the COMPLETE inventory of endpoints and parameters you discovered (the source maps usually list every route the client can call). Probe EVERY endpoint in that inventory at least once before you go deep on any single one, and keep a running list of which remain untouched. Most missed vulnerabilities are on endpoints that were never requested, not on endpoints that were tested shallowly. Before you report, state which inventory entries you never reached.

PHASE 2 — UNAUTHENTICATED. For every discovered endpoint/parameter test, as applicable: path traversal / arbitrary file read; injection (SQL, XML/XXE with a Content-Type the parser accepts, template, command, NoSQL); authentication bypass; user/account enumeration via differential responses; unauthenticated access to privileged actions; information disclosure (stack traces, versions, config, source, debug); CORS policy (send an Origin header and inspect whether it is reflected together with credentials); security headers.

PHASE 3 — IDENTITY. Register your own test accounts through the application's own signup/registration flow. Create at least TWO independent accounts so you can test one identity against the other. Log in and capture whatever the app issues (token, cookie, session id). If the app exposes any out-of-band verification step (one-time codes, reference ids, reset links), examine whether its values are disclosed in responses or are guessable/reusable, and whether a reference issued for one account is accepted for another.

PHASE 3b — CHAIN TO A SESSION. Do not treat authentication as a wall you can only pass by signing up. Chain what Phase 2 gave you: if a file-read or source-disclosure flaw exists, read the application's own configuration/source for secrets (keys, salts, database credentials); if the client bundle or a leaked config contains a hard-coded key, it is usable. If any flow returns a credential, one-time code, reset reference or token to the client — even encoded or ENCRYPTED — recover the plaintext with run_command (decrypt with the recovered key, decode base64/hex) and replay it. Then complete the flow (verify -> reference -> reset/login) to obtain a session for an account you did not previously control. Confirm the takeover by performing an authenticated read as that identity. Record each step as its own finding.

PHASE 4 — TOKEN ANALYSIS. Inspect any issued token. If it is structured (e.g. dot-separated base64), decode and read the header and payload: note the algorithm, any sensitive data carried in it, and whether the signature can be trivially forged or the secret guessed. Test whether the server accepts a modified/unsigned token.

PHASE 5 — AUTHENTICATED. Re-test every endpoint as an authenticated user: broken object-level authorization (request another identity's records by changing an id/account/reference — use your second account's identifiers as the cross-user probe); injection in authenticated parameters; mass assignment; privilege escalation.

PHASE 6 — BUSINESS LOGIC & RATE LIMITS. Test value and state manipulation: negative, zero, oversized, or differently-typed amounts/quantities; skipping or reordering steps in a multi-step flow; replaying a one-time value; changing a sensitive setting without presenting the current credential. Test whether repeated attempts on any verification/auth step are ever throttled or locked out.

REPORTING — when done, emit your findings as a JSON array. Each finding: {"finding_id": "...", "title": "...", "vuln_class": "...", "affected": {"method": "GET", "url": "..."}, "invariant": {"statement": "...", "type": "body_contains|status_in|derived|state_changed|state_violated|file_created_then_deleted", "expression": "..."}, "evidence": {"exploit_response_excerpt": "...", "control_response_excerpt": "...", "status": <int>}}.
Report EVERY distinct confirmed issue as its own finding. Be concise and evidence-first.`;


/**
 * Budgeted engagement phases. Each gets a fixed share of the turn budget and
 * has its playbooks injected on entry — breadth and skill use are enforced by
 * the loop rather than requested in the prompt (the agent ignored both when
 * they were optional).
 */
export const ENGAGEMENT_PHASES: LoopPhase[] = [
  {
    id: "map",
    turnShare: 0.12,
    skills: ["intelligent-crawling", "js-spa-reverse", "tech-fingerprinting"],
    brief:
      "Map the application. Fetch the root, every JS bundle and any .map source maps, and read them for API base paths, route tables, request/response field names and auth flows. " +
      "Output an explicit INVENTORY: every endpoint path and its parameters. You will be held to this inventory in later phases, so make it complete.",
  },
  {
    id: "unauth",
    turnShare: 0.18,
    skills: ["auth-bypass-battery", "file-upload-path-traversal", "injection-battery-xxe-ssti-nosql", "sqli-database-injection"],
    brief:
      "Test EVERY endpoint in your inventory without authentication — one probe each before any second probe. Cover: path traversal / arbitrary file read; SQL, XML/XXE (send an XML content-type), template and NoSQL injection; auth bypass; " +
      "user enumeration via differential responses; unauthenticated access to privileged actions; information disclosure; CORS with an Origin header. Note which endpoints reject you — those are the authenticated surface for later.",
  },
  {
    id: "identity",
    turnShare: 0.12,
    skills: ["account-role-acquisition", "token-session-forensics"],
    brief:
      "Obtain identities. Register at least TWO independent accounts through the app's own signup flow and log in to each, capturing whatever it issues. " +
      "Keep both identities' ids/accounts/tokens — the second exists so you can request the first's objects later.",
  },
  {
    id: "chain",
    turnShare: 0.15,
    skills: ["chain-construction", "credential-secret-custody", "exploit-sandbox-programming"],
    brief:
      "Chain what you have into privilege you were not given. If any read primitive exists, read the app's own config/source for secrets. If any flow returns a credential, one-time code or reference to the client — even encoded or encrypted — " +
      "recover the plaintext with run_command using recovered or client-side keys, then replay it to complete the flow. Decode any token and test whether it can be forged or its secret guessed. Confirm each takeover with an authenticated read.",
  },
  {
    id: "authed",
    turnShare: 0.23,
    skills: ["idor-bola-access-control", "privilege-matrix-mapping", "sqli-database-injection", "deserialization-rce"],
    brief:
      "Re-test EVERY inventory endpoint as an authenticated user, one probe each before going deep. Focus on: broken object-level authorization (ask for your SECOND account's objects using the FIRST account's token, and vice versa); " +
      "injection in authenticated parameters; mass assignment; unsafe deserialization / object injection in any field that looks like a serialized structure or type selector; privilege escalation.",
  },
  {
    id: "logic",
    turnShare: 0.20,
    skills: ["business-logic-state"],
    brief:
      "Abuse business logic and limits on every state-changing endpoint: negative, zero, oversized and wrong-typed amounts or quantities; skipping or reordering steps in multi-step flows; replaying a one-time value; " +
      "changing a sensitive setting without presenting the current credential; and whether ANY verification or auth step is ever rate-limited or locked out. Then close out any inventory endpoint still untested.",
  },
];

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
  /**
   * When set, the engagement runs through an OpenCode engine over the SDK
   * (its own agents/skills/tools) instead of the built-in direct-LLM loop.
   */
  opencode?: { url: string; password?: string; agent?: string; directory?: string; model?: { id: string; providerID: string } };
}

export interface ScanResult {
  objective: string;
  finalText: string;
  cost: number;
  tokens: { input: number; output: number; cached: number };
  findings: Array<{ finding: unknown; verdict: Awaited<ReturnType<Axiom["verify"]>> }>;
}

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const scope = parseScope({ inScopeUrls: opts.inScopeUrls });
  const llm = new OpenRouterLlm({ apiKey: opts.apiKey, baseUrl: opts.baseUrl });
  const axiom = new Axiom({ judge: new LlmJudge(llm, opts.judgeModel ?? opts.model), ...(opts.judgeThreshold !== undefined ? { judgeThreshold: opts.judgeThreshold } : {}) });
  const skills = skillIndex();
  const system = skills
    ? `${SYSTEM_PROMPT}\n\nSKILL LIBRARY — operator playbooks available via the read_skill tool. Consult the relevant one before attacking a vulnerability class, and run the scripts it ships with run_command:\n${skills}`
    : SYSTEM_PROMPT;
  const runner = new LlmRunner({
    apiKey: opts.apiKey,
    model: opts.model,
    system,
    scope,
    workspaceRoot: opts.workspaceRoot ?? "/tmp/sahw-sandbox",
    maxTurns: opts.maxTurns,
    temperature: opts.temperature,
    baseUrl: opts.baseUrl,
    ...(opts.sessionId ? { cacheKey: opts.sessionId } : {}),
    phases: ENGAGEMENT_PHASES,
  });

  const objective = `AUTHORIZED black-box penetration test. In-scope targets: ${opts.inScopeUrls.join(", ")}.\n` +
    `Work the full methodology end to end: map the surface from the app's own pages/JS/source maps, test unauthenticated flaws, ` +
    `then register your own test accounts (at least two), log in, analyse the issued token, and re-test everything authenticated — ` +
    `including cross-user object access, injection in authenticated parameters, business-logic/value manipulation, and missing rate limits. ` +
    `Use http_request for everything. Keep going until the turn budget is nearly exhausted, then report every confirmed issue as its own finding in the JSON array described in your instructions.`;

  // Run the agent loop and finding-verification INSIDE a Langfuse root trace so
  // every LLM turn (generation), tool call (span) and Axiom verdict (span) is
  // captured as a child observation — the full end-to-end tree, one per run.
  const tracer = opts.langfuse ? new LangfuseTracer(opts.langfuse) : null;
  const findings: Array<{ finding: unknown; verdict: Awaited<ReturnType<Axiom["verify"]>> }> = [];

  // Engine mode: same methodology, driven through the OpenCode SDK.
  const sdkRunner = opts.opencode
    ? new SdkRunner({
        client: createOpencodeClient({
          baseUrl: opts.opencode.url,
          ...(opts.opencode.password
            ? { headers: { Authorization: `Basic ${Buffer.from(`opencode:${opts.opencode.password}`).toString("base64")}` } }
            : {}),
        } as never),
        // The engine resolves this path inside ITS OWN container, so it must be
        // the engine's project dir — not the scan container's sandbox.
        directory: opts.opencode.directory ?? "/app",
        ...(opts.opencode.model ? { model: opts.opencode.model } : {}),
      })
    : null;

  const doRun = async (rec?: import("./langfuse.js").SpanRecorder) => {
    // Engine mode mirrors the v4 engagement exactly: one objective carrying the
    // full methodology, and the engine runs its own tool loop. (runPhases() is
    // the v5 phased variant — deliberately not used here.)
    const result = sdkRunner
      ? await sdkRunner.run(opts.opencode?.agent ?? "recon", `${SYSTEM_PROMPT}\n\n${objective}`)
      : await runner.run("recon", objective, rec);
    for (const finding of result.findings) {
      // Verification must never discard a finding: a transient judge/LLM
      // failure downgrades that one finding, it does not abort the report.
      let verdict: Awaited<ReturnType<Axiom["verify"]>>;
      try {
        verdict = await axiom.verify(finding as never);
      } catch (e) {
        console.error(`[axiom] verify failed (non-fatal): ${(e as Error).message.slice(0, 200)}`);
        verdict = {
          status: "NEEDS_REVIEW",
          decided_by: "adjudicator_escalation",
          invariant_violated: false,
          confidence: 0.5,
          reason: `verification error: ${(e as Error).message.slice(0, 160)}`,
        } as Awaited<ReturnType<Axiom["verify"]>>;
      }
      findings.push({ finding, verdict });
      await rec?.toolSpan("axiom:verify", {
        input: finding,
        output: { status: verdict.status, confidence: verdict.confidence, decided_by: verdict.decided_by, reason: verdict.reason },
      });
    }
    rec?.setOutput({ finalText: result.finalText, findingsCount: findings.length });
    return result;
  };

  const result = tracer
    ? await tracer.traceTree(
        {
          name: "sahw-recon",
          input: objective,
          model: opts.model,
          sessionId: opts.sessionId,
          metadata: { inScopeUrls: opts.inScopeUrls },
        },
        (rec) => doRun(rec),
      )
    : await doRun();

  // Persist findings + endpoints to the Neo4j security fabric (canonical state).
  // Non-fatal: a graph write failure must not lose findings or tracing.
  if (opts.neo4j) {
    try {
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
    } catch (e) {
      console.error(`[neo4j] write failed (non-fatal): ${(e as Error).message}`);
    }
  }

  // Flush the trace tree (non-fatal — export failure must not lose findings).
  if (tracer) await tracer.flush();

  return {
    objective,
    finalText: result.finalText,
    cost: result.costUsd,
    tokens: { input: result.tokens.input, output: result.tokens.output, cached: result.tokens.cache.read },
    findings,
  };
}
