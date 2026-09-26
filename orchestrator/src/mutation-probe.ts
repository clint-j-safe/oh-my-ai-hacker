// =========================================================================================
// Mass-assignment mutation probe — PURE core (no I/O). The runtime wrapper (beat.ts) drives
// the actual authenticated PUT/PATCH round-trip; everything decision-shaped lives here so it
// is unit-tested exhaustively. SAFETY MODEL (jev-designed): PUT full-replace only, restore is
// the verbatim original representation, and the runtime NEVER sends a probe until a NOOP
// round-trip (PUT original -> GET matches original) has proven the endpoint is restorable.
// No POST-create, no DELETE. The whole feature is gated OFF by default (SAHW_MUTATION_TESTING).
// =========================================================================================

/** Privileged/unexpected keys an attacker would try to smuggle through a write body. A
 * namespaced marker (for unambiguous detection) plus common privilege-escalation field
 * names. Values are obviously-synthetic so a human sees they are framework-injected. */
export const MASS_ASSIGNMENT_PROBE: Record<string, unknown> = {
  sahw_probe_marker: "sahw-mass-assign-9f3a",
  role: "sahw-superadmin",
  isAdmin: true,
  is_admin: true,
  tenantId: "sahw-other-tenant",
  permissions: ["sahw-all"],
};

export interface MutationPlan {
  /** Body to PUT to attempt mass-assignment (original representation + probe fields). */
  probeBody: string;
  /** Body to PUT to RESTORE (the verbatim original representation). */
  restoreBody: string;
  /** The probe keys actually injected (those not already present in the original). */
  injectedKeys: string[];
}

/** Parse an object's current JSON representation (its GET response). Returns the bare entity
 * object, or null when the body is not a single JSON object we can safely round-trip (arrays,
 * primitives, wrapped collections, non-JSON). */
export function parseEntity(text: string): Record<string, unknown> | null {
  let obj: unknown;
  try { obj = JSON.parse(text); } catch { return null; }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  return obj as Record<string, unknown>;
}

/** Build the probe + restore bodies from an entity's current representation. Only injects
 * probe keys NOT already present on the entity — so PUT-ing the verbatim original always
 * fully reverts them (a key we added is absent from the original and a full-replace removes
 * it). Returns null when there is nothing safe to probe (not an object, or every probe key
 * already exists on the entity). */
export function buildMutationPlan(originalText: string, probe: Record<string, unknown> = MASS_ASSIGNMENT_PROBE): MutationPlan | null {
  const entity = parseEntity(originalText);
  if (!entity) return null;
  const inject: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(probe)) if (!(k in entity)) inject[k] = v;
  const injectedKeys = Object.keys(inject);
  if (injectedKeys.length === 0) return null;
  return {
    probeBody: JSON.stringify({ ...entity, ...inject }),
    restoreBody: originalText, // exact original bytes -> guaranteed full-replace restore
    injectedKeys,
  };
}

/** Did the noop round-trip prove the endpoint is restorable? True only when the entity read
 * back after a PUT of the original is semantically equal to the original (same JSON). If
 * false, the runtime MUST NOT send a probe (we cannot prove we could undo it). */
export function noopRoundTripRestorable(originalText: string, afterNoopText: string): boolean {
  const a = parseEntity(originalText);
  const b = parseEntity(afterNoopText);
  if (!a || !b) return false;
  return canonicalJson(a) === canonicalJson(b);
}

/** After the probe PUT, did mass-assignment SUCCEED? True when an injected probe key is now
 * present on the entity read back (the server accepted a field it should have ignored). */
export function massAssignmentAccepted(afterProbeText: string, injectedKeys: string[]): boolean {
  const entity = parseEntity(afterProbeText);
  if (!entity) return false;
  return injectedKeys.some((k) => k in entity);
}

/** Was the entity fully restored after the restore PUT? True when it is semantically equal to
 * the original AND carries none of the injected probe keys. Drives the state_changed
 * restoration discipline: a probe that could not be proven restored is NEEDS_REVIEW. */
export function restoreVerified(originalText: string, afterRestoreText: string, injectedKeys: string[]): boolean {
  const orig = parseEntity(originalText);
  const after = parseEntity(afterRestoreText);
  if (!orig || !after) return false;
  if (injectedKeys.some((k) => k in after)) return false; // a probe key lingered
  return canonicalJson(orig) === canonicalJson(after);
}

// Order-independent JSON canonicalization for equality (keys sorted recursively).
function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const rec = v as Record<string, unknown>;
  return `{${Object.keys(rec).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(rec[k])}`).join(",")}}`;
}
