/**
 * Pure helpers for deep-mode STATEFUL (multi-step) sweep probes — the generic
 * broken-password-change probe (benchmark F-24 shape) and support for other
 * observe→act→observe proofs. Kept pure and dependency-free so the field-mapping and
 * marker-extraction logic (the parts most likely to mis-fire) are unit tested in
 * isolation; beat.ts backs the actual requests with the Tether-gated http_request path.
 *
 * BLACK-BOX DISCIPLINE: nothing here encodes a target-specific literal (no endpoint path,
 * field name, or success code baked in). Field roles are inferred from GENERIC naming
 * patterns over the fields the app itself used in captured requests; the success marker is
 * extracted from the app's OWN response. determinism lives only in the verdict, which the
 * Axiom evaluates over the real captures.
 */

/** Classify a request-body leaf name into a role by generic naming convention. Returns the
 * best single role or null. Order matters: "old password" must beat "password". */
export type FieldRole = "old_password" | "new_password" | "password" | "username";
export function classifyField(name: string): FieldRole | null {
  const n = name.toLowerCase();
  const isPass = /pass|pwd|secret/.test(n);
  if (isPass && /(old|current|existing|prev|orig)/.test(n)) return "old_password";
  if (isPass && /(new|updated|change|confirm|repeat|retype)/.test(n)) return "new_password";
  if (isPass) return "password";
  if (/(user(name)?|email|login|mobile|phone|account|userid|uid)/.test(n)) return "username";
  return null;
}

/** Given the JSON leaf dot-paths of a captured request, map roles to leaf paths. For a
 * change-password request we want old_password + new_password (+ maybe a confirm we treat
 * as new). For a login we want username + password. Picks the LAST path segment for the
 * role match so nested envelopes (data.old_pass) classify on "old_pass". */
export interface FieldMap { username?: string; password?: string; old_password?: string; new_password?: string }
export function mapFields(leafPaths: string[]): FieldMap {
  const out: FieldMap = {};
  for (const path of leafPaths) {
    const leaf = path.split(".").pop() || path;
    const role = classifyField(leaf);
    if (!role) continue;
    // Do not overwrite a more-specific match already found (first wins per role).
    if (role === "password") { if (out.password === undefined) out.password = path; }
    else if (out[role] === undefined) out[role] = path;
  }
  return out;
}

/** True if a captured request looks like a login (has a username-ish + a password field,
 * and is NOT a change/reset — no old/new password split). Generic. */
export function looksLikeLogin(fm: FieldMap, url: string): boolean {
  const u = url.toLowerCase();
  if (/(logout|signout|refresh)/.test(u)) return false;
  if (fm.old_password || fm.new_password) return false; // that's a change/reset form
  return Boolean(fm.username && fm.password);
}

/** True if a captured request looks like a password CHANGE (has an old + new password, or
 * a URL that names change/update-password). Reset (unauth, token-based) is excluded by
 * requiring an old-password field OR an explicit change verb. Generic. */
export function looksLikePasswordChange(fm: FieldMap, url: string): boolean {
  const u = url.toLowerCase();
  const changeVerb = /(change|update|edit).*(pass|pwd)|(pass|pwd).*(change|update|edit)/.test(u);
  return Boolean(fm.new_password && (fm.old_password || changeVerb));
}

/** Extract a JWT-shaped token (header.payload[.signature]) from a response body. A
 * successful login on a JWT app issues one; a failed login does not. Universal JWT format
 * (base64url `eyJ...` segments), not a target-specific literal. Returns the longest match
 * (the real token, not an incidental fragment) or null. */
const JWT_RE = /eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]{6,})?/g;
export function extractJwt(body: string | null | undefined): string | null {
  if (!body) return null;
  const matches = body.match(JWT_RE);
  if (!matches || matches.length === 0) return null;
  return matches.reduce((a, b) => (b.length > a.length ? b : a));
}
