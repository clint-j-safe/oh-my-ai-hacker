import { randomBytes } from "node:crypto";

/**
 * SESSION STORE — pure, in-process bookkeeping for self-registered test accounts.
 *
 * Unlocks the authenticated / cross-user surface (docs/superpowers/specs/
 * 2026-09-22-safe-ai-hacker-design.md §3.2: "self-registers >=2 disposable accounts
 * through the target's own signup flow"). Before this module existed, http_request
 * had no notion of a session at all — every request was anonymous, so an entire
 * class of findings (authenticated single-request, IDOR/cross-user) was structurally
 * unreachable no matter what the hunter discovered.
 *
 * THE SPLIT THIS FILE ENFORCES, and that every caller must preserve:
 *   - LABEL + non-secret metadata (label, username, created_utc, auth_header_name,
 *     whether auth material was obtained) -> safe to persist to the spine, safe to
 *     show the model. See SessionMeta below; this is the ONLY shape that may leave
 *     this module toward the spine or a span.
 *   - password + auth_material (the real token/cookie the target issued) -> a
 *     SECRET. It lives ONLY inside a SessionRecord in this in-process Map for the
 *     lifetime of the run. The only way out is authMaterialFor(), called by
 *     tools.ts's http() executor immediately before it builds one outgoing
 *     request — never stored, logged, or handed back to a caller in any other
 *     shape. This mirrors the {{secret:ref}} discipline in the spec: the model
 *     only ever sees a LABEL ("session A"), never the material a label resolves
 *     to.
 */

export interface SessionCredentials {
  /** An obviously synthetic test username: a fixed framework prefix + a
   * cryptographically random suffix (node:crypto), never a real identity. */
  username: string;
  /** An obviously synthetic test email on the reserved "example.test" domain
   * (RFC 2606) — never a real address, and never sent anywhere but the target's
   * own discovered signup/login endpoints. */
  email: string;
  /** A synthetic, CSPRNG-derived password. Not a "real" secret in the sense of
   * something a human chose or reused — but still handled as one: it is a
   * SessionCredentials field, subject to the same never-persisted discipline as
   * auth_material. Charset is deliberately restricted to [A-Za-z0-9] with a
   * guaranteed upper/lower/digit and length <=20, because exotic specials (- ! + /)
   * are the single most common reason a target's signup charset filter rejects an
   * otherwise valid password — a broadly-safe password is generic robustness, not
   * target knowledge. */
  password: string;
  /** A synthetic, unique 10-digit numeric identifier for signup forms that require a
   * phone/mobile-shaped field (a near-universal signup field, frequently with a
   * uniqueness constraint). CSPRNG-derived per label so two accounts effectively
   * never collide; if a target enforces uniqueness and one does collide, signup just
   * rejects it and the caller retries (register_account's envelope-from-error path).
   * Not a real, dialable number. */
  mobile: string;
}

/** Non-secret session metadata — the ONLY shape safe to persist to the spine, log
 * to a span, or otherwise let leave this process's memory. */
export interface SessionMeta {
  label: string;
  username: string;
  created_utc: string;
  /** The header name auth_material is injected under for this session (discovered
   * from the target's own signup/login exchange when the session was created —
   * never hardcoded). */
  auth_header_name: string;
  /** Whether a real token/cookie was actually obtained. false means the account
   * was created on the target but registration could not recover auth material
   * (e.g. email verification required) — the session exists as a label but
   * http_request has nothing to inject for it. */
  has_auth_material: boolean;
}

interface SessionRecord {
  label: string;
  credentials: SessionCredentials;
  authMaterial: string | null;
  authHeaderName: string;
  createdUtc: string;
}

const LABELS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
const DEFAULT_MAX_ACCOUNTS = 2;

/** SAHW_MAX_ACCOUNTS — spec says ">=2"; default 2 because more disposable accounts
 * is waste and more target state to eventually have created (L2 discipline: every
 * mutation the framework causes should be the minimum needed to prove the class,
 * per the design doc's restore/verify posture for any state change). */
export function maxAccountsFromEnv(env: Record<string, string | undefined> = process.env): number {
  const raw = env.SAHW_MAX_ACCOUNTS;
  if (raw === undefined || raw.trim() === "") return DEFAULT_MAX_ACCOUNTS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.trunc(n) : DEFAULT_MAX_ACCOUNTS;
}

/**
 * OBVIOUSLY synthetic test credentials: a fixed "sahw-test-" prefix plus a random
 * suffix from node:crypto, never a dictionary word or anything resembling a real
 * identity. Per L2 discipline (design doc §3: "no real-PII exfiltration") this data
 * must be identifiable as framework-generated the moment a human looks at it — the
 * prefix exists specifically so it is.
 */
export function generateDisposableCredentials(label: string): SessionCredentials {
  const suffix = randomBytes(6).toString("hex");
  const tag = `sahw-test-${label.toLowerCase()}-${suffix}`;
  // Alphanumeric-only, with a guaranteed uppercase + lowercase + digit and length
  // <=20 (see SessionCredentials.password). "S" + 14 hex chars (0-9a-f) + "z9" = 17
  // chars, always satisfying upper/lower/digit and matching any [A-Za-z0-9]-only
  // policy without the exotic specials that trip charset filters.
  const password = `S${randomBytes(7).toString("hex")}z9`;
  // A 10-digit synthetic mobile, first digit fixed non-zero, rest CSPRNG-derived (see
  // SessionCredentials.mobile). Modulo keeps it within 9 digits so the "9" prefix is
  // never dropped by padding.
  const nine = (parseInt(randomBytes(5).toString("hex"), 16) % 1_000_000_000)
    .toString()
    .padStart(9, "0");
  return {
    username: tag,
    // .test is an IANA-reserved TLD (RFC 2606) that is guaranteed to never resolve
    // to a real mailbox — this is never a real address, and never sent anywhere
    // but the target's own discovered signup/login endpoints.
    email: `${tag}@example.test`,
    password,
    mobile: `9${nine}`,
  };
}

/** Thrown when SAHW_MAX_ACCOUNTS is already reached. Mapped by tools.ts's
 * execute() to kind: "policy" (never retry — the cap is a fixed run-level
 * ceiling, not something different arguments could satisfy). */
export class SessionCapError extends Error {}

export class SessionStore {
  private readonly maxAccounts: number;
  private readonly records = new Map<string, SessionRecord>();

  constructor(opts: { maxAccounts?: number } = {}) {
    this.maxAccounts = opts.maxAccounts ?? maxAccountsFromEnv();
  }

  /** Labels already assigned, in creation order (Map preserves insertion order). */
  labels(): string[] {
    return [...this.records.keys()];
  }

  size(): number {
    return this.records.size;
  }

  /** The next free label ("A", then "B", ...), or null once SAHW_MAX_ACCOUNTS is
   * reached. Callers (registerAccount() in tools.ts) must check this BEFORE
   * spending a signup request against the target — a call that would exceed the
   * cap must never touch the network at all. */
  nextLabel(): string | null {
    if (this.records.size >= this.maxAccounts) return null;
    return LABELS.find((l) => !this.records.has(l)) ?? null;
  }

  /**
   * Records a session the caller asserts it already created on the target (a
   * successful signup, optionally followed by a login). Pure bookkeeping — this
   * method does no I/O and makes no claim about the target's state; tools.ts's
   * registerAccount() is what actually talks to the target, through the
   * Tether-gated http_request path, before ever calling this.
   *
   * Returns null (creating nothing) if the cap is already reached — re-checked
   * here as defense in depth, mirroring gate()'s "never trust that some caller
   * already checked" posture elsewhere in this codebase, even though the real
   * caller is expected to have called nextLabel() first.
   */
  create(opts: {
    credentials: SessionCredentials;
    authMaterial: string | null;
    authHeaderName: string;
    now?: Date;
  }): SessionMeta | null {
    const label = this.nextLabel();
    if (label === null) return null;
    const record: SessionRecord = {
      label,
      credentials: opts.credentials,
      authMaterial: opts.authMaterial,
      authHeaderName: opts.authHeaderName,
      createdUtc: (opts.now ?? new Date()).toISOString(),
    };
    this.records.set(label, record);
    return this.metaFor(record);
  }

  has(label: string): boolean {
    return this.records.has(label);
  }

  /** Resolves a label to its live auth material for request injection. This is
   * the ONLY path from a label to the secret string. The only legitimate caller
   * is tools.ts's http() executor, immediately before building one outgoing
   * fetch — the result must never be stored, logged, or returned to any other
   * caller. Returns null for an unknown label or a session with no material. */
  authMaterialFor(label: string): string | null {
    return this.records.get(label)?.authMaterial ?? null;
  }

  /** The header name this session's auth material is injected under (discovered
   * at registration time from the target's own convention — never hardcoded). */
  authHeaderNameFor(label: string): string | null {
    return this.records.get(label)?.authHeaderName ?? null;
  }

  meta(label: string): SessionMeta | null {
    const r = this.records.get(label);
    return r ? this.metaFor(r) : null;
  }

  /** Every session's non-secret metadata, in label order — this, and only this,
   * shape is what a caller may persist to the spine (see spine.ts's
   * SpineSessionRecord, which mirrors it exactly) or otherwise let leave the
   * process. */
  allMeta(): SessionMeta[] {
    return this.labels().map((l) => this.meta(l)!);
  }

  private metaFor(r: SessionRecord): SessionMeta {
    return {
      label: r.label,
      username: r.credentials.username,
      created_utc: r.createdUtc,
      auth_header_name: r.authHeaderName,
      has_auth_material: r.authMaterial !== null,
    };
  }
}
