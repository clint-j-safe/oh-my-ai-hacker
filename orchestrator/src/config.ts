export class ConfigError extends Error {}

/**
 * OPT-IN "deep mode" — thorough exploitation for an enterprise authorized engagement.
 *
 * Fail-safe OFF: when `enabled` is false, every sub-capability is forced off and
 * `weaponize` is "off", regardless of the individual SAHW_DEEP_* env vars — a partial
 * config can never half-arm depth. Deep mode is INDEPENDENT of `profile` (a prod
 * engagement may run shallow; a test engagement may run deep), so it gets its own object
 * rather than overloading the trace-tag profile.
 *
 * `weaponize` tiers:
 *   "off"    — detection/read-only proof only (the framework's historical safety model).
 *   "benign" — non-destructive impact demonstration (nonce round-trips, self-cleaning markers).
 *   "impact" — full controlled impact (RCE/shell/priv-esc), always reversible + audited.
 * Any tier other than "off" is gated behind an authorization DOUBLE-CONFIRM (see
 * loadDeepConfig): the caller must name the same signed SAHW_AUTH_REF a second time via
 * SAHW_DEEP_WEAPONIZE_AUTH_REF, so no single stray env var can arm weaponization.
 */
export interface DeepConfig {
  enabled: boolean;
  sweep: boolean;
  fuzz: boolean;
  escalate: boolean;
  weaponize: "off" | "benign" | "impact";
  maxSweepRequests: number;
  maxEscalationDepth: number;
  weaponizeAuthRef: string | null;
}

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
  deep: DeepConfig;
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

function boolEnv(env: Env, key: string, fallback: boolean): boolean {
  const raw = env[key];
  if (raw === undefined || raw.trim() === "") return fallback;
  const v = raw.trim().toLowerCase();
  if (v === "1" || v === "true" || v === "yes" || v === "on") return true;
  if (v === "0" || v === "false" || v === "no" || v === "off") return false;
  throw new ConfigError(`${key} is not a boolean: ${raw}`);
}

/**
 * The deep-mode capability object. Off by default and fail-closed: an unset SAHW_DEEP_MODE
 * yields a fully-disabled config, and `enabled=false` forces every sub-flag off no matter
 * what the individual vars say. The weaponize double-confirm throws unless the same signed
 * authorization reference is named twice AND deep mode is on.
 */
export function loadDeepConfig(env: Env, authRef: string): DeepConfig {
  const enabled = boolEnv(env, "SAHW_DEEP_MODE", false);
  const disabled: DeepConfig = {
    enabled: false, sweep: false, fuzz: false, escalate: false,
    weaponize: "off",
    maxSweepRequests: num(env, "SAHW_DEEP_SWEEP_BUDGET", 500),
    maxEscalationDepth: num(env, "SAHW_DEEP_ESCALATION_DEPTH", 2),
    weaponizeAuthRef: null,
  };
  if (!enabled) return disabled;

  const wRaw = (env.SAHW_DEEP_WEAPONIZE ?? "off").trim().toLowerCase();
  if (wRaw !== "off" && wRaw !== "benign" && wRaw !== "impact") {
    throw new ConfigError(`SAHW_DEEP_WEAPONIZE must be "off", "benign" or "impact", got ${wRaw}`);
  }
  const weaponize = wRaw as DeepConfig["weaponize"];
  const weaponizeAuthRef = env.SAHW_DEEP_WEAPONIZE_AUTH_REF?.trim() || null;

  // DOUBLE-CONFIRM: weaponization requires deep mode on AND the same signed authorization
  // reference named a second time. This makes it impossible to arm with one stray var.
  if (weaponize !== "off" && !(weaponizeAuthRef && weaponizeAuthRef === authRef)) {
    throw new ConfigError(
      "SAHW_DEEP_WEAPONIZE requires SAHW_DEEP_WEAPONIZE_AUTH_REF to exactly match SAHW_AUTH_REF " +
      "(a deliberate double-confirm of the client's signed authorization); weaponization stays off");
  }

  return {
    enabled: true,
    sweep: boolEnv(env, "SAHW_DEEP_SWEEP", true),
    fuzz: boolEnv(env, "SAHW_DEEP_FUZZ", true),
    escalate: boolEnv(env, "SAHW_DEEP_ESCALATE", true),
    weaponize,
    maxSweepRequests: num(env, "SAHW_DEEP_SWEEP_BUDGET", 500),
    maxEscalationDepth: num(env, "SAHW_DEEP_ESCALATION_DEPTH", 2),
    weaponizeAuthRef,
  };
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
    deep: loadDeepConfig(env, authRef),
  };
}
