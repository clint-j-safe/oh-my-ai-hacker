/**
 * scan-cli — run the autonomous black-box scan against a live target.
 * Loads `.env` (see .env.example) and runs the scan with Langfuse tracing.
 * Usage: node dist/scan-cli.js
 */

import { scan } from "./scan.js";
import { loadConfig } from "./config.js";

async function main(): Promise<void> {
  try {
    process.loadEnvFile?.(".env");
  } catch {
    // no .env — env vars may be set directly
  }

  const cfg = loadConfig();

  if (!cfg.scope.inScopeUrls.length || !cfg.model.apiKey) {
    console.error("usage: set SAHW_SCOPE and SAHW_OPENROUTER_KEY (in .env or env)");
    process.exit(2);
  }

  const res = await scan({
    apiKey: cfg.model.apiKey,
    model: cfg.model.model,
    judgeModel: cfg.model.judgeModel,
    inScopeUrls: cfg.scope.inScopeUrls,
    langfuse: cfg.langfuse,
    neo4j: cfg.neo4j,
    maxTurns: cfg.model.maxTurns,
    temperature: cfg.model.temperature,
    baseUrl: cfg.model.baseUrl,
    workspaceRoot: cfg.tether.workspaceRoot,
    judgeThreshold: cfg.axiom.judgeThreshold,
    sessionId: cfg.authorization.ref || undefined,
  });

  console.log("\n=== FINAL REPORT ===\n" + res.finalText);
  console.log(`\n=== FINDINGS (${res.findings.length}) ===`);
  for (const f of res.findings) {
    const fid = (f.finding as { finding_id?: string }).finding_id ?? "(no id)";
    console.log(`- ${fid}: ${f.verdict.status} [${f.verdict.decided_by}] (conf ${f.verdict.confidence})`);
    console.log(`    ${f.verdict.reason.slice(0, 180)}`);
  }
  console.log(`\n=== COST === $${res.cost.toFixed(6)} tokens=${JSON.stringify(res.tokens)}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
