/**
 * Config — single source of truth for all tunable knobs, read from env.
 * Every control-plane / engine / OOB / observability setting is configurable
 * here (see .env.example). Secrets never enter git (`.env` is gitignored).
 */

import type { ImpactTier } from "./tether.js";

export interface Config {
  scope: { inScopeUrls: string[]; outOfScope: string[]; inScopeCidrs?: string[] };
  authorization: { ref: string; start: string; end: string };
  model: { apiKey: string; model: string; judgeModel: string; temperature: number; maxTurns: number; baseUrl: string };
  budget: { usd: number; turns: number; tokens: number };
  tether: { workspaceRoot: string; authorizedTiers: ImpactTier[] };
  axiom: { confidence: number; judgeThreshold: number };
  langfuse?: { host: string; publicKey: string; secretKey: string };
  opencode?: { url: string; password?: string; agent?: string; directory?: string; model?: { id: string; providerID: string } };
  neo4j?: { uri: string; user: string; password: string };
  ledgerFile: string;
  oob: { answerIp: string; dnsPort: number; httpPort: number; shellPort: number };
  engine?: { url: string; password: string };
}

function csv(v: string | undefined): string[] {
  return (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

function num(v: string | undefined, dflt: number): number {
  const n = Number(v);
  return Number.isFinite(n) && v !== undefined && v !== "" ? n : dflt;
}

const TIERS: ImpactTier[] = ["read", "probe", "state_change", "shell", "destructive"];

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const authorizedTiers = csv(env.SAHW_AUTHORIZED_TIERS).filter((t) => TIERS.includes(t as ImpactTier)) as ImpactTier[];

  const opencode = env.OPENCODE_URL
    ? {
        url: env.OPENCODE_URL,
        ...(env.OPENCODE_PASSWORD ? { password: env.OPENCODE_PASSWORD } : {}),
        ...(env.SAHW_ENGINE_AGENT ? { agent: env.SAHW_ENGINE_AGENT } : {}),
        directory: env.SAHW_ENGINE_DIR || "/app",
        ...(env.SAHW_ENGINE_MODEL && env.SAHW_ENGINE_PROVIDER
          ? { model: { id: env.SAHW_ENGINE_MODEL, providerID: env.SAHW_ENGINE_PROVIDER } }
          : {}),
      }
    : undefined;

  const langfuse =
    env.SAHW_LANGFUSE_HOST && env.SAHW_LANGFUSE_PUBLIC_KEY && env.SAHW_LANGFUSE_SECRET_KEY
      ? { host: env.SAHW_LANGFUSE_HOST, publicKey: env.SAHW_LANGFUSE_PUBLIC_KEY, secretKey: env.SAHW_LANGFUSE_SECRET_KEY }
      : undefined;

  const engine = env.OPENCODE_URL ? { url: env.OPENCODE_URL, password: env.OPENCODE_PASSWORD ?? "" } : undefined;

  return {
    scope: {
      inScopeUrls: csv(env.SAHW_SCOPE),
      outOfScope: csv(env.SAHW_OUT_OF_SCOPE),
      inScopeCidrs: csv(env.SAHW_IN_SCOPE_CIDRS).length ? csv(env.SAHW_IN_SCOPE_CIDRS) : undefined,
    },
    authorization: {
      ref: env.SAHW_AUTH_REF ?? "",
      start: env.SAHW_AUTH_START ?? "",
      end: env.SAHW_AUTH_END ?? "",
    },
    model: {
      apiKey: env.SAHW_OPENROUTER_KEY ?? "",
      model: env.SAHW_MODEL || "z-ai/glm-5.3-flashx",
      judgeModel: env.SAHW_JUDGE_MODEL || env.SAHW_MODEL || "z-ai/glm-5.3-flashx",
      temperature: num(env.SAHW_TEMPERATURE, 0.3),
      maxTurns: num(env.SAHW_MAX_TURNS, 12),
      baseUrl: env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1",
    },
    budget: {
      usd: num(env.SAHW_BUDGET_USD, 1),
      turns: num(env.SAHW_BUDGET_TURNS, 100),
      tokens: num(env.SAHW_BUDGET_TOKENS, 1_000_000),
    },
    tether: {
      workspaceRoot: env.SAHW_WORKSPACE ?? "/tmp/sahw-sandbox",
      authorizedTiers: authorizedTiers.length ? authorizedTiers : ["read", "probe", "state_change", "shell"],
    },
    axiom: {
      confidence: num(env.SAHW_AXIOM_CONFIDENCE, 0.75),
      judgeThreshold: num(env.SAHW_AXIOM_JUDGE_THRESHOLD, 0.8),
    },
    langfuse,
    opencode,
    neo4j:
      env.NEO4J_URI && env.NEO4J_USER && env.NEO4J_PASSWORD
        ? { uri: env.NEO4J_URI, user: env.NEO4J_USER, password: env.NEO4J_PASSWORD }
        : undefined,
    ledgerFile: env.SAHW_LEDGER_FILE ?? "/tmp/sahw-ledger/events.ndjson",
    oob: {
      answerIp: env.OOB_ANSWER_IP ?? "127.0.0.1",
      dnsPort: num(env.OOB_DNS_PORT, 53),
      httpPort: num(env.OOB_HTTP_PORT, 80),
      shellPort: num(env.OOB_SHELL_PORT, 4444),
    },
    engine,
  };
}
