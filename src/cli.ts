/**
 * CLI entry — reads engagement config from env and runs the Big Loop.
 *
 *   SAHW_SCOPE          comma-separated in-scope URLs (required)
 *   SAHW_AUTH_REF       authorization reference (required)
 *   SAHW_BUDGET_USD     / TURNS / TOKENS   (defaults 1 / 100 / 1_000_000)
 *   OPENCODE_URL        optional: engine base URL (http://engine:4096)
 *   OPENCODE_PASSWORD   optional: engine basic-auth password (username=opencode)
 *
 * Without OPENCODE_URL the runner is a no-op (dry-run) — the deterministic
 * loop, budget, and Axiom still run.
 */

import { runEngagement } from "./run-engagement.js";
import { SdkRunner } from "./sdk-runner.js";
import { createOpencodeClient } from "@opencode-ai/sdk/v2";
import type { AgentRunner } from "./orchestrator.js";
import type { TokenUsage } from "./budget.js";

const EMPTY_TOKENS: TokenUsage = { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } };

function env(name: string): string {
  return process.env[name] ?? "";
}

async function main(): Promise<void> {
  const scope = env("SAHW_SCOPE").split(",").map((s) => s.trim()).filter(Boolean);
  const authRef = env("SAHW_AUTH_REF");

  if (!scope.length || !authRef) {
    console.error("usage: set SAHW_SCOPE and SAHW_AUTH_REF (see header). Dry-run otherwise.");
    process.exit(2);
  }

  let runner: AgentRunner;
  const url = env("OPENCODE_URL");
  if (url) {
    const password = env("OPENCODE_PASSWORD");
    const client = createOpencodeClient({
      baseUrl: url,
      ...(password ? { headers: { Authorization: `Basic ${Buffer.from(`opencode:${password}`).toString("base64")}` } } : {}),
    } as never);
    runner = new SdkRunner({ client, directory: process.cwd() });
  } else {
    runner = {
      async run(): Promise<{ costUsd: number; tokens: TokenUsage; findings: [] }> {
        return { costUsd: 0, tokens: EMPTY_TOKENS, findings: [] };
      },
    };
  }

  const result = await runEngagement({
    scope: { inScopeUrls: scope },
    budget: {
      usd: Number(env("SAHW_BUDGET_USD") || 1),
      turns: Number(env("SAHW_BUDGET_TURNS") || 100),
      tokens: Number(env("SAHW_BUDGET_TOKENS") || 1_000_000),
    },
    impactLevel: "L2-readonly",
    authorization: { ref: authRef, window: { start: env("SAHW_AUTH_START"), end: env("SAHW_AUTH_END") } },
    runner,
  });

  console.log(JSON.stringify(result, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
