export class ConfigError extends Error {}

export interface Engagement {
  scope: URL[];
  outOfScope: URL[];
  authRef: string;
  windowStart: Date;
  windowEnd: Date;
  maxTurns: number;
  budgetTurns: number;
  budgetTokens: number;
  budgetUsd: number | null;
  requestTimeoutMs: number;
  phaseTimeoutMs: number;
  maxRetries: number;
  profile: "test" | "prod";
}

type Env = Record<string, string | undefined>;

function num(env: Env, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) throw new ConfigError(`${key} is not a number: ${raw}`);
  return n;
}

function numOrNull(env: Env, key: string): number | null {
  const raw = env[key];
  if (raw === undefined || raw.trim() === "") return null;
  const n = Number(raw);
  if (!Number.isFinite(n)) throw new ConfigError(`${key} is not a number: ${raw}`);
  return n;
}

function urls(raw: string | undefined, key: string): URL[] {
  if (!raw || !raw.trim()) return [];
  return raw.split(",").map((s) => s.trim()).filter(Boolean).map((s) => {
    let u: URL;
    try { u = new URL(s); } catch { throw new ConfigError(`${key} entry is not a URL: ${s}`); }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      throw new ConfigError(`${key} must be HTTP(S) only, got ${u.protocol} in ${s}`);
    }
    return u;
  });
}

function date(env: Env, key: string): Date {
  const raw = env[key];
  if (!raw) throw new ConfigError(`${key} is required`);
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) throw new ConfigError(`${key} is not a date: ${raw}`);
  return d;
}

export function loadEngagement(env: Env, now: Date = new Date()): Engagement {
  const scope = urls(env.SAHW_SCOPE, "SAHW_SCOPE");
  if (scope.length === 0) {
    throw new ConfigError("SAHW_SCOPE is empty; scope IS the allowlist, refusing to run");
  }
  const authRef = env.SAHW_AUTH_REF?.trim();
  if (!authRef) throw new ConfigError("SAHW_AUTH_REF is required — no authorization, no run");

  const windowStart = date(env, "SAHW_AUTH_START");
  const windowEnd = date(env, "SAHW_AUTH_END");
  if (now < windowStart || now > windowEnd) {
    throw new ConfigError(
      `outside the authorization window (${windowStart.toISOString()}..${windowEnd.toISOString()})`);
  }

  const requestTimeoutMs = num(env, "SAHW_REQUEST_TIMEOUT_MS", 3_600_000);
  // Default MUST stay below the request-timeout default, or loadEngagement rejects its own defaults.
  const phaseTimeoutMs = num(env, "SAHW_PHASE_TIMEOUT_MS", 3_000_000);
  if (phaseTimeoutMs >= requestTimeoutMs) {
    throw new ConfigError(
      "SAHW_PHASE_TIMEOUT_MS must be < SAHW_REQUEST_TIMEOUT_MS so the orchestrator " +
      "AbortSignal trips before the transport; otherwise a stall goes unrecorded");
  }

  const profileRaw = (env.SAHW_PROFILE ?? "test").trim();
  if (profileRaw !== "test" && profileRaw !== "prod") {
    throw new ConfigError(`SAHW_PROFILE must be "test" or "prod", got ${profileRaw}`);
  }
  return {
    scope,
    outOfScope: urls(env.SAHW_OUT_OF_SCOPE, "SAHW_OUT_OF_SCOPE"),
    authRef,
    windowStart,
    windowEnd,
    maxTurns: num(env, "SAHW_MAX_TURNS", 40),
    budgetTurns: num(env, "SAHW_BUDGET_TURNS", 200),
    budgetTokens: num(env, "SAHW_BUDGET_TOKENS", 2_000_000),
    budgetUsd: numOrNull(env, "SAHW_BUDGET_USD"),
    requestTimeoutMs,
    phaseTimeoutMs,
    maxRetries: num(env, "SAHW_MAX_RETRIES", 0),
    profile: profileRaw,
  };
}
