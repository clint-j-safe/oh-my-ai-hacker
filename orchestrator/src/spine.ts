import { mkdir, readFile, writeFile, rm, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

/**
 * THE SPINE — persistent state carried between beats.
 *
 * "No spine, no loop. Without it, the loop just repeats its first step forever."
 * (docs/superpowers/specs/2026-09-22-safe-ai-hacker-design.md §4/§5). Before this
 * module existed, every beat rebuilt the hunter's system prompt from a single static
 * string, so a fresh beat had no memory of endpoints already mapped, findings already
 * proved, or hypotheses already dead-ended — two consecutive real runs both
 * rediscovered the same two trivial header findings from zero.
 *
 * Lives under <workspace>/spine/, NEVER in the repo. Two files:
 *   progress.json  machine state — read at beat start (loadSpine), written at beat
 *                  end (saveSpine), one JSON round trip, never partially written
 *                  (temp-file-then-rename, mirroring ArtifactStore.put in artifacts.ts).
 *   rules.md       durable, human-editable lessons. The loop reads it (loadRules) but
 *                  never writes it — it is out of scope for this module to mutate.
 */

export const SPINE_SCHEMA_VERSION = 1;

/** Thrown when progress.json declares a schema_version newer than this orchestrator
 * understands. Refused, not misread: an older reader silently misinterpreting a
 * newer shape is worse than refusing to start. Distinct from a corrupt/unparseable
 * file, which is safe to discard and start fresh from (see loadSpine). */
export class SpineVersionError extends Error {}

export interface SpineEndpoint {
  url: string;
  method: string;
  status: number | null;
  content_type: string | null;
  semantic_role?: string;
  notes?: string;
}

/**
 * SHAPE only of a recorded login flow — never the credentials, tokens, or TOTP
 * secret used to exercise it. This is what a later beat needs to replay an
 * authenticated session's login step (Task 6), not what it needs to forge one on
 * its own; the actual secret material lives only in-process (session.ts's
 * SessionStore), same discipline as SpineSessionRecord above.
 */
export interface LoginSequenceShape {
  login_url: string;
  content_type: "json" | "form";
  identifier_field: string;
  password_field: string;
  auth_header_name: string;
  token_location: "body" | "cookie" | "none";
  two_factor: "none" | "totp" | "otp" | "sms" | "unknown";
}

/**
 * Free-form but structured client-intel recovered from the target's own served
 * assets. Never a secret's plaintext value — see sanitizeIntelValue below, which
 * updateSpine runs over every string written here. A caller that has a real secret
 * must already hand it in as a description (e.g. "bearer-less JWT in Authorization"),
 * never the material itself; the sanitizer is a backstop, not the only guard.
 */
export interface RecoveredIntel {
  api_base?: string;
  request_envelope?: string;
  auth_header_style?: string;
  source_maps_seen?: boolean;
  /** Non-secret shape of a recorded login flow — see LoginSequenceShape. */
  login_sequence?: LoginSequenceShape;
  [key: string]: unknown;
}

export interface ProvedEntry {
  vuln_class: string;
  endpoint: string;
  invariant_type: string;
  /** The gated verdict (may be NEEDS_REVIEW even though the invariant itself passed
   * — see beat.ts, which routes into `proved` on axiom.status === "CONFIRMED", not
   * on the provenance-gated status). Kept for audit; presence in `proved` is itself
   * the "don't re-derive this" signal, independent of this field's value. */
  verdict: string;
  finding_id: string;
}

export interface AttemptedEntry {
  vuln_class: string;
  endpoint: string;
  invariant_type: string;
  outcome: string;
  why: string;
}

export interface SpineBeatRecord {
  beat_id: string;
  started_utc: string;
  ended_utc: string;
  findings_banked: number;
  stalled: boolean;
  reason: string | null;
  codename: string;
}

export interface SpineCounters {
  total_beats: number;
  total_findings: number;
  total_proved: number;
  total_attempted: number;
}

export interface SpineEngagementRef {
  auth_ref: string;
  scope_origins: string[];
}

/**
 * Non-secret session metadata, persisted so a LATER beat knows accounts A/B
 * already exist and does not waste a self-registration re-creating them. This
 * type mirrors session.ts's SessionMeta exactly and deliberately has NO field for
 * password or auth_material — those are secrets that live only in-process for the
 * run (see session.ts's SessionStore), never on disk. A caller building this
 * record from anything other than SessionStore.allMeta()/ToolRunner.getSessionMeta()
 * is responsible for the same discipline; sanitizeSessionRecord below is a
 * backstop, not the only guard (mirrors RecoveredIntel's own doc comment).
 */
export interface SpineSessionRecord {
  label: string;
  username: string;
  created_utc: string;
  auth_header_name: string;
  has_auth_material: boolean;
}

export interface Spine {
  schema_version: number;
  engagement: SpineEngagementRef;
  beats: SpineBeatRecord[];
  attack_surface: SpineEndpoint[];
  recovered_intel: RecoveredIntel;
  /** Session LABELS and their non-secret metadata only — see SpineSessionRecord.
   * Never the password or auth_material a label resolves to; those live only
   * in-process for the run (session.ts's SessionStore), keyed by label, and are
   * re-obtained (a fresh self-registration) rather than restored from the spine
   * across a process restart. */
  sessions: SpineSessionRecord[];
  proved: ProvedEntry[];
  attempted: AttemptedEntry[];
  counters: SpineCounters;
  /** Durable record of why THIS spine started fresh instead of continuing a prior
   * one — e.g. an engagement/scope mismatch, or a corrupt prior file. null for a
   * spine that continued normally. This is what makes "start fresh, and say so"
   * survive past a single beat's stderr: it is written into progress.json itself,
   * not just logged and discarded. */
  fresh_reason: string | null;
}

export interface LoadSpineResult {
  spine: Spine;
  /** true if this beat is starting from a brand-new spine (no prior file, a prior
   * file that failed to parse, or one for a different engagement/scope). */
  fresh: boolean;
  freshReason: string | null;
}

function freshSpine(authRef: string, scopeOrigins: string[], freshReason: string | null): Spine {
  return {
    schema_version: SPINE_SCHEMA_VERSION,
    engagement: { auth_ref: authRef, scope_origins: [...scopeOrigins].sort() },
    beats: [],
    attack_surface: [],
    recovered_intel: {},
    sessions: [],
    proved: [],
    attempted: [],
    counters: { total_beats: 0, total_findings: 0, total_proved: 0, total_attempted: 0 },
    fresh_reason: freshReason,
  };
}

function spineDir(workspace: string): string {
  return join(workspace, "spine");
}
function progressPath(workspace: string): string {
  return join(spineDir(workspace), "progress.json");
}
export function rulesPath(workspace: string): string {
  return join(spineDir(workspace), "rules.md");
}

/** rules.md is human-editable and read-only to the loop — no writer is exposed here. */
export async function loadRules(workspace: string): Promise<string | null> {
  try {
    return await readFile(rulesPath(workspace), "utf8");
  } catch {
    return null;
  }
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}
function asObject<T>(v: unknown, fallback: T): T {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as T) : fallback;
}
function asArray<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

/**
 * Normalizes a parsed-but-untrusted progress.json into a well-shaped Spine. A file
 * can pass JSON.parse and carry a matching schema_version while still having a
 * shape a naive `parsed as Spine` cast would let through malformed — e.g.
 * `"beats": "nope"` — and blow up a later beat (updateSpine's `[...spine.beats, x]`)
 * well after loadSpine returned normally. Every array/object field is defaulted
 * here so a structurally damaged file degrades gracefully instead of crashing a
 * beat that has not even started hunting yet.
 */
function normalize(parsed: any, authRef: string, scopeOrigins: string[]): Spine {
  const engagement = asObject<Partial<SpineEngagementRef>>(parsed.engagement, {});
  return {
    schema_version: SPINE_SCHEMA_VERSION,
    engagement: {
      auth_ref: typeof engagement.auth_ref === "string" ? engagement.auth_ref : authRef,
      scope_origins: asStringArray(engagement.scope_origins),
    },
    beats: asArray<SpineBeatRecord>(parsed.beats),
    attack_surface: asArray<SpineEndpoint>(parsed.attack_surface),
    recovered_intel: asObject<RecoveredIntel>(parsed.recovered_intel, {}),
    sessions: asArray<SpineSessionRecord>(parsed.sessions),
    proved: asArray<ProvedEntry>(parsed.proved),
    attempted: asArray<AttemptedEntry>(parsed.attempted),
    counters: asObject<SpineCounters>(parsed.counters, {
      total_beats: 0, total_findings: 0, total_proved: 0, total_attempted: 0,
    }),
    fresh_reason: typeof parsed.fresh_reason === "string" ? parsed.fresh_reason : null,
  };
}

/**
 * Reads <workspace>/spine/progress.json and returns state ready for this beat.
 *
 * - No file at all: a brand-new spine (`fresh: true`).
 * - Unparseable JSON, or JSON missing a usable schema_version: logged, and a fresh
 *   spine is returned — a corrupt file must never kill the run.
 * - A schema_version NEWER than this build understands: REFUSED — throws
 *   SpineVersionError rather than guessing at an unknown shape. Distinct from
 *   corruption on purpose: corrupt data is safe to discard, but a newer schema may
 *   encode a shape this reader would silently misinterpret.
 * - A schema_version this build understands, but for a DIFFERENT engagement
 *   (`auth_ref`) or a DIFFERENT scope (`scope_origins`, as a set): NOT merged. A
 *   fresh spine is returned and the mismatch is recorded (`freshReason`, and inside
 *   the returned spine's `fresh_reason`) — silently inheriting another engagement's
 *   state would be a scope violation in effect.
 */
export async function loadSpine(opts: {
  workspace: string;
  authRef: string;
  scopeOrigins: string[];
}): Promise<LoadSpineResult> {
  const path = progressPath(opts.workspace);
  const scopeOrigins = [...opts.scopeOrigins].sort();

  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    return { spine: freshSpine(opts.authRef, scopeOrigins, null), fresh: true, freshReason: null };
  }

  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const reason = `corrupt progress.json: ${(err as Error).message}`;
    console.error(`[spine] ${reason} — starting fresh`);
    return { spine: freshSpine(opts.authRef, scopeOrigins, reason), fresh: true, freshReason: reason };
  }

  if (typeof parsed?.schema_version !== "number") {
    const reason = "corrupt progress.json: missing or non-numeric schema_version";
    console.error(`[spine] ${reason} — starting fresh`);
    return { spine: freshSpine(opts.authRef, scopeOrigins, reason), fresh: true, freshReason: reason };
  }

  if (parsed.schema_version > SPINE_SCHEMA_VERSION) {
    throw new SpineVersionError(
      `progress.json schema_version ${parsed.schema_version} is newer than this ` +
      `orchestrator supports (${SPINE_SCHEMA_VERSION}) — refusing to misread it`);
  }

  const priorAuthRef: unknown = parsed?.engagement?.auth_ref;
  const priorScope = asStringArray(parsed?.engagement?.scope_origins).sort();
  const sameScope = JSON.stringify(priorScope) === JSON.stringify(scopeOrigins);
  if (priorAuthRef !== opts.authRef || !sameScope) {
    const reason =
      `spine was for engagement ${JSON.stringify(priorAuthRef)} / scope ${JSON.stringify(priorScope)}, ` +
      `this run is ${JSON.stringify(opts.authRef)} / scope ${JSON.stringify(scopeOrigins)} — ` +
      `starting fresh rather than silently merging across engagements/scopes`;
    console.error(`[spine] ${reason}`);
    return { spine: freshSpine(opts.authRef, scopeOrigins, reason), fresh: true, freshReason: reason };
  }

  return { spine: normalize(parsed, opts.authRef, scopeOrigins), fresh: false, freshReason: null };
}

export async function saveSpine(workspace: string, spine: Spine): Promise<void> {
  const path = progressPath(workspace);
  const dir = dirname(path);
  await mkdir(dir, { recursive: true });
  const tmp = join(dir, `.tmp-${randomBytes(4).toString("hex")}`);
  const body = JSON.stringify(spine, null, 2);
  try {
    await writeFile(tmp, body, "utf8");
    await rename(tmp, path);
  } catch (err) {
    try { await rm(tmp); } catch { /* best effort cleanup */ }
    throw err;
  }
}

// ---- secret redaction (recovered_intel and session records — see updateSpine) --

// A JWT: three dot-separated base64url segments, each long enough that this
// wouldn't fire on an incidental "a.b.c". Matched and redacted wherever it occurs
// in a string, not just as a full match, so a descriptive sentence that quotes a
// token inline is still caught.
const JWT_RE = /[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
// A long, unbroken run of base64/hex-alphabet characters: bearer tokens, API keys,
// long hex secrets. 24 chars is deliberately conservative — long enough to avoid
// eating ordinary words, short enough to catch real key material.
const LONG_TOKEN_RE = /\b[A-Za-z0-9+/_-]{24,}={0,2}\b/g;

function sanitizeIntelString(v: string): string {
  let out = v.replace(JWT_RE, "<redacted-secret>");
  out = out.replace(LONG_TOKEN_RE, (m) => (m.startsWith("<redacted") ? m : "<redacted-secret>"));
  return out;
}

/**
 * Deep-sanitizes recovered_intel values only. NEVER apply this to attack_surface —
 * a URL path segment can easily be 24+ opaque characters (an id, a slug) and is not
 * a secret; scrubbing it there would gut the very surface list the spine exists to
 * carry.
 */
function sanitizeIntel(v: unknown): unknown {
  if (typeof v === "string") return sanitizeIntelString(v);
  if (Array.isArray(v)) return v.map(sanitizeIntel);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) out[k] = sanitizeIntel(val);
    return out;
  }
  return v;
}

function mergeIntel(prev: RecoveredIntel, next: RecoveredIntel): RecoveredIntel {
  const merged: RecoveredIntel = { ...prev };
  for (const [k, v] of Object.entries(next)) {
    merged[k] = sanitizeIntel(v);
  }
  return merged;
}

/**
 * Collapse a degenerate run of one repeated character in a URL to a compact marker.
 *
 * A fuzzed or reflected request — e.g. `GET /?unix=AAAA…` with a 200 KB payload — is
 * recorded verbatim into the attack surface, and since the Spine is re-rendered into
 * EVERY subsequent beat's brief, that one junk URL then rides in every prompt forever
 * (one observed run: a single 219,608-byte `A`-run = ~43% of a 514 KB prompt). This
 * clips it at the source, on write, so it can never accumulate.
 *
 * SAFETY — this must not touch a legitimate URL:
 *  - It fires ONLY on a run of >= RUN_THRESHOLD (24) IDENTICAL consecutive characters.
 *    Real URL content is high-entropy — JWTs, base64, UUIDs, hashes, signed tokens,
 *    session ids, paths — and never contains 24 of the same character in a row. A
 *    24x repeat is a padding/fuzz artifact by construction.
 *  - It keeps the base URL, the parameter names, and the first few chars of the run,
 *    so the endpoint's shape stays legible; only the repeat itself becomes `…⟨×N⟩`.
 *  - These stored URLs are never REPLAYED (the Axiom replays claim.request /
 *    evidence.captures, never attack_surface[].url) and their only other consumer,
 *    origin derivation, reads scheme+host — everything before the '?'. So even an
 *    over-aggressive collapse could at worst shorten a display string, never corrupt
 *    a request or a proof.
 *
 * Note: there is deliberately NO blunt length cap here — a legitimate URL can exceed
 * any fixed length (a large JWT in a query param), and truncating it on write would
 * lose real information. Display-side bounding (count + a generous per-URL cap well
 * above any real URL) lives in the brief renderer, where it cannot affect storage.
 */
const RUN_THRESHOLD = 24;
const REPEAT_RUN = /(.)\1{23,}/gs; // >= 24 identical consecutive chars (\1 back-ref = same char)
export function collapseRepeatedRuns(url: string): string {
  if (typeof url !== "string" || url.length < RUN_THRESHOLD) return url;
  return url.replace(REPEAT_RUN, (run, ch: string) => `${ch.repeat(8)}…⟨×${run.length}⟩`);
}

function normalizeEndpointUrl(e: SpineEndpoint): SpineEndpoint {
  const url = collapseRepeatedRuns(e.url);
  return url === e.url ? e : { ...e, url };
}

function mergeEndpoints(prev: SpineEndpoint[], next: SpineEndpoint[]): SpineEndpoint[] {
  const byKey = new Map<string, SpineEndpoint>();
  // Normalize on BOTH sides: `next` clips anything recorded this beat, and `prev`
  // retroactively cleans an already-bloated spine the first time it is merged after
  // this fix ships.
  for (const raw of prev) {
    const e = normalizeEndpointUrl(raw);
    byKey.set(`${e.method} ${e.url}`, e);
  }
  for (const raw of next) {
    const e = normalizeEndpointUrl(raw);
    const key = `${e.method} ${e.url}`;
    const existing = byKey.get(key);
    // Later observations win on scalar fields; a newly-empty optional field does
    // not erase a previously-recorded one.
    byKey.set(key, existing ? { ...existing, ...e, notes: e.notes ?? existing.notes, semantic_role: e.semantic_role ?? existing.semantic_role } : e);
  }
  return [...byKey.values()];
}

// A session record's only string fields are `label`, `username` and
// `auth_header_name` — none of which should ever legitimately contain a secret.
// The PRIMARY guard is structural: SpineSessionRecord/SessionMeta simply have no
// field for password or auth_material, so there is nothing secret to leak here in
// the ordinary case. This is a narrow backstop against a caller mistake (e.g.
// accidentally passing a raw JWT in as a "username") — deliberately narrower than
// sanitizeIntelString's LONG_TOKEN_RE pass, which would false-positive on the
// framework's own synthetic usernames (see generateDisposableCredentials in
// session.ts: "sahw-test-<label>-<12 hex chars>" is itself a long hyphenated
// alnum run, and scrubbing that would make the spine's own account records
// useless without actually protecting a secret — the token is never IN username
// or auth_header_name to begin with). Only the unambiguous JWT shape (three
// dot-separated segments) is checked; plain long/hyphenated identifiers pass
// through untouched.
function sanitizeSessionField(v: string): string {
  return v.replace(JWT_RE, "<redacted-secret>");
}

function sanitizeSessionRecord(s: SpineSessionRecord): SpineSessionRecord {
  return {
    label: sanitizeSessionField(s.label),
    username: sanitizeSessionField(s.username),
    created_utc: s.created_utc,
    auth_header_name: sanitizeSessionField(s.auth_header_name),
    has_auth_material: s.has_auth_material,
  };
}

function mergeSessions(prev: SpineSessionRecord[], next: SpineSessionRecord[]): SpineSessionRecord[] {
  const byLabel = new Map<string, SpineSessionRecord>();
  for (const s of prev) byLabel.set(s.label, s);
  for (const s of next) byLabel.set(s.label, sanitizeSessionRecord(s));
  return [...byLabel.values()].sort((a, b) => a.label.localeCompare(b.label));
}

function dedupeByPair<T extends { vuln_class: string; endpoint: string }>(items: T[]): T[] {
  const byKey = new Map<string, T>();
  for (const it of items) byKey.set(`${it.vuln_class}::${it.endpoint}`, it);
  return [...byKey.values()];
}

function dedupeAttempted(items: AttemptedEntry[]): AttemptedEntry[] {
  const byKey = new Map<string, AttemptedEntry>();
  for (const it of items) byKey.set(`${it.vuln_class}::${it.endpoint}::${it.invariant_type}`, it);
  return [...byKey.values()];
}

export interface SpineBeatUpdate {
  beat: SpineBeatRecord;
  discoveredEndpoints?: SpineEndpoint[];
  recoveredIntel?: RecoveredIntel;
  /** Non-secret session metadata this beat registered or already knew about —
   * pass ToolRunner.getSessionMeta() here. Never a password or auth_material. */
  sessions?: SpineSessionRecord[];
  proved?: ProvedEntry[];
  attempted?: AttemptedEntry[];
}

/**
 * Pure merge: current spine + what this beat learned -> the next spine. Never
 * mutates its input. Called once per beat, right before saveSpine, for every stop
 * condition the beat can end on — including a stall or a failure (see beat.ts's
 * `bail`) — so a beat that learned "this endpoint answers uniformly to every
 * probe" is a beat whose lesson survives even though it banked nothing.
 */
export function updateSpine(spine: Spine, update: SpineBeatUpdate): Spine {
  const beats = [...spine.beats, update.beat];
  const proved = dedupeByPair([...spine.proved, ...(update.proved ?? [])]);
  const attempted = dedupeAttempted([...spine.attempted, ...(update.attempted ?? [])]);
  return {
    ...spine,
    beats,
    attack_surface: mergeEndpoints(spine.attack_surface, update.discoveredEndpoints ?? []),
    recovered_intel: mergeIntel(spine.recovered_intel, update.recoveredIntel ?? {}),
    sessions: mergeSessions(spine.sessions, update.sessions ?? []),
    proved,
    attempted,
    counters: {
      total_beats: beats.length,
      total_findings: spine.counters.total_findings + update.beat.findings_banked,
      total_proved: proved.length,
      total_attempted: attempted.length,
    },
  };
}
