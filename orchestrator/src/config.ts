export class ConfigError extends Error {}

/**
 * OPT-IN "deep mode" — thorough exploitation for an enterprise authorized engagement.
 *
 * DELIBERATELY A SINGLE BOOLEAN, not a graded level: `enabled` is the one switch. OFF is
 * the breadth-first default (one probe per turn, bank-and-move-on, attack skills gated
 * out); ON turns on ALL the depth behaviours together — the systematic input×payload
 * sweep, the fuzzer, escalation/chaining, and the widened attack-skill allowlist. Two
 * extremes, no half-states to reason about. Independent of `profile` (a prod engagement
 * may run shallow; a test one deep), so it is its own object, not the trace-tag profile.
 *
 * `weaponize` is a SEPARATE safety gate (also boolean), NOT folded into `enabled`: it is
 * the destructive tier (controlled, reversible RCE/shell/priv-esc impact) and must never
 * arm on a single flag. It requires deep mode ON *and* an authorization DOUBLE-CONFIRM
 * (SAHW_DEEP_WEAPONIZE_AUTH_REF must equal SAHW_AUTH_REF); otherwise loadDeepConfig
 * throws. Off by default even when deep mode is on.
 */
export interface DeepConfig {
  enabled: boolean;
  weaponize: boolean;
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
  auth: AuthConfig;
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
  const maxSweepRequests = num(env, "SAHW_DEEP_SWEEP_BUDGET", 500);
  const maxEscalationDepth = num(env, "SAHW_DEEP_ESCALATION_DEPTH", 2);
  // Fail-closed: deep mode off forces weaponize off regardless of any SAHW_DEEP_WEAPONIZE.
  if (!enabled) {
    return { enabled: false, weaponize: false, maxSweepRequests, maxEscalationDepth, weaponizeAuthRef: null };
  }

  const weaponize = boolEnv(env, "SAHW_DEEP_WEAPONIZE", false);
  const weaponizeAuthRef = env.SAHW_DEEP_WEAPONIZE_AUTH_REF?.trim() || null;
  // DOUBLE-CONFIRM: weaponization requires deep mode on AND the same signed authorization
  // reference named a second time. This makes it impossible to arm with one stray var.
  if (weaponize && !(weaponizeAuthRef && weaponizeAuthRef === authRef)) {
    throw new ConfigError(
      "SAHW_DEEP_WEAPONIZE requires SAHW_DEEP_WEAPONIZE_AUTH_REF to exactly match SAHW_AUTH_REF " +
      "(a deliberate double-confirm of the client's signed authorization); weaponization stays off");
  }

  return { enabled: true, weaponize, maxSweepRequests, maxEscalationDepth, weaponizeAuthRef };
}

export type AuthMode = "off" | "bypass" | "authenticated";
export type AuthProvider = "auto" | "form" | "cognito";
export interface AuthLogin { email?: string; username?: string; password: string; loginUrl?: string; fieldHints?: Record<string, string> }
export interface AuthConfig {
  mode: AuthMode;
  login: AuthLogin | null;
  totp: string | { secret: string; algorithm?: string; digits?: number; period?: number } | null;
  /** Which login protocol to speak. "auto" (default) tries the target's own
   * form/JSON login unless a Cognito app client is fingerprinted from its served
   * bundles (see auth-recon.ts's detectCognito), or SAHW_COGNITO is set explicitly.
   * "form" never attempts Cognito even if fingerprinted. "cognito" requires either
   * SAHW_COGNITO or a successful fingerprint, else runAuthRecord throws. Optional
   * (defaults applied at load time) so existing hand-built AuthConfig literals
   * (tests) that predate this field keep compiling. */
  provider?: AuthProvider;
  /** Explicit Cognito app-client config ({region, clientId}); when omitted and the
   * provider is cognito/auto, it is taken from the fingerprint instead. */
  cognito?: { region: string; clientId: string } | null;
  /** Allow the MFA_SETUP "fetch and own a new TOTP seed" path (AssociateSoftwareToken)
   * when the Cognito account has no TOTP device enrolled yet. Off by default — an
   * account requiring setup with this false fails closed rather than silently
   * enrolling a device the operator didn't ask for. */
  cognitoEnroll?: boolean;
  /** Header name the IdToken (or, for non-Cognito flows, any recovered auth
   * material) is injected under when seeding session "A". Default "x-safe-id-token"
   * — this app's own convention, not a generic Authorization/Bearer header. */
  authHeader?: string;
}

/** Auth-scan config. Fail-closed: bypass/authenticated require SAHW_AUTH_LOGIN (with a
 * password). TOTP is parsed only in authenticated mode; bypass NEVER consumes a secret.
 * A TOTP-gated flow with no secret is caught later, at record time, not here.
 *
 * provider/cognito/cognitoEnroll/authHeader are parsed regardless of mode — they carry
 * no secrets of their own (region/clientId/header-name are public shape, not
 * credentials), so there is nothing to gate. mode="off" still short-circuits before
 * SAHW_AUTH_LOGIN is required, exactly as before this feature existed. */
export function loadAuthConfig(env: Env): AuthConfig {
  const raw = (env.SAHW_AUTH_MODE ?? "off").trim().toLowerCase();
  if (raw !== "off" && raw !== "bypass" && raw !== "authenticated") {
    throw new ConfigError(`SAHW_AUTH_MODE must be off|bypass|authenticated, got: ${env.SAHW_AUTH_MODE}`);
  }
  const mode = raw as AuthMode;

  const providerRaw = (env.SAHW_AUTH_PROVIDER ?? "auto").trim().toLowerCase();
  if (providerRaw !== "auto" && providerRaw !== "form" && providerRaw !== "cognito") {
    throw new ConfigError(`SAHW_AUTH_PROVIDER must be auto|form|cognito, got: ${env.SAHW_AUTH_PROVIDER}`);
  }
  const provider = providerRaw as AuthProvider;

  let cognito: AuthConfig["cognito"] = null;
  const cognitoRaw = env.SAHW_COGNITO?.trim();
  if (cognitoRaw) {
    let parsed: unknown;
    try { parsed = JSON.parse(cognitoRaw); }
    catch { throw new ConfigError("SAHW_COGNITO is not valid JSON"); }
    const p = parsed as { region?: unknown; clientId?: unknown } | null;
    if (!p || typeof p.region !== "string" || !p.region || typeof p.clientId !== "string" || !p.clientId) {
      throw new ConfigError('SAHW_COGNITO must be JSON {"region": string, "clientId": string}');
    }
    cognito = { region: p.region, clientId: p.clientId };
  }

  const cognitoEnroll = boolEnv(env, "SAHW_COGNITO_ENROLL", false);
  const authHeader = env.SAHW_AUTH_HEADER?.trim() || "x-safe-id-token";

  if (mode === "off") return { mode, login: null, totp: null, provider, cognito, cognitoEnroll, authHeader };

  const loginRaw = env.SAHW_AUTH_LOGIN?.trim();
  if (!loginRaw) throw new ConfigError(`SAHW_AUTH_MODE=${mode} requires SAHW_AUTH_LOGIN`);
  let login: AuthLogin;
  try { login = JSON.parse(loginRaw) as AuthLogin; }
  catch { throw new ConfigError("SAHW_AUTH_LOGIN is not valid JSON"); }
  if (!login || typeof login.password !== "string" || login.password === "") {
    throw new ConfigError("SAHW_AUTH_LOGIN must include a non-empty password");
  }
  if (!login.email && !login.username) {
    throw new ConfigError("SAHW_AUTH_LOGIN must include an email or username");
  }

  let totp: AuthConfig["totp"] = null;
  if (mode === "authenticated") {
    const t = env.SAHW_TOTP?.trim();
    if (t) {
      totp = t.toLowerCase().startsWith("otpauth://") ? t : (() => {
        try { return JSON.parse(t) as { secret: string }; } catch { return t; }
      })();
    }
  }
  return { mode, login, totp, provider, cognito, cognitoEnroll, authHeader };
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
    auth: loadAuthConfig(env),
  };
}
