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

/** Classify a field as a contact identifier that must be UNIQUE per signup (so a cloned
 * signup envelope doesn't collide with an existing account). Generic naming. */
export function classifyContactField(name: string): "email" | "mobile" | null {
  const n = name.toLowerCase();
  if (/mail/.test(n)) return "email";
  if (/(mobile|phone|msisdn|contact)/.test(n)) return "mobile";
  return null;
}

/** Extract a server-ASSIGNED account identifier from a signup/registration response: a
 * field named user/id/account/cust (…Id) whose value the login endpoint expects, or a
 * value shaped like an assigned id (LETTERS+DIGITS, e.g. BNK64092). Generic — no target
 * literal. Returns the identifier or null. */
const ASSIGNED_ID_VALUE = /^[A-Za-z]{2,6}\d{3,}$/;
export function extractAssignedId(body: string | null | undefined): string | null {
  if (!body) return null;
  let obj: unknown;
  try { obj = JSON.parse(body); } catch { return null; }
  // 1) A field explicitly named like a user/account id, at any depth.
  const NAMED = /^(userid|user_id|custid|customerid|accountid|acctid|loginid|id)$/i;
  const stack: unknown[] = [obj];
  const idFields: string[] = [];
  const idShaped: string[] = [];
  while (stack.length) {
    const cur = stack.pop();
    if (!cur || typeof cur !== "object") continue;
    for (const [k, v] of Object.entries(cur as Record<string, unknown>)) {
      if (typeof v === "string") {
        if (NAMED.test(k)) idFields.push(v);
        else if (ASSIGNED_ID_VALUE.test(v)) idShaped.push(v);
      } else if (v && typeof v === "object") stack.push(v);
    }
  }
  return idFields[0] ?? idShaped[0] ?? null;
}

/** Recursively find the first object-valued "device" property in a parsed body (the app's
 * device/client envelope). Generic — used to carry a KNOWN-GOOD device block (from a
 * request that already succeeded) into other requests whose captured template may hold a
 * stale/invalid device (e.g. an os value the server rejects). Returns the object or null. */
export function findDeviceObject(value: unknown, depth = 0): Record<string, unknown> | null {
  if (depth > 6 || !value || typeof value !== "object") return null;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (k.toLowerCase() === "device" && v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
    const nested = findDeviceObject(v, depth + 1);
    if (nested) return nested;
  }
  return null;
}

/** Return a deep clone of `bodyJson` with every "device" object replaced by `device`. If
 * the body has no device key or is unparseable, returns it unchanged. */
export function graftDevice(bodyJson: string, device: Record<string, unknown> | null): string {
  if (!device) return bodyJson;
  let obj: unknown;
  try { obj = JSON.parse(bodyJson); } catch { return bodyJson; }
  const walk = (node: unknown, depth: number): void => {
    if (depth > 6 || !node || typeof node !== "object") return;
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k.toLowerCase() === "device" && v && typeof v === "object" && !Array.isArray(v)) {
        (node as Record<string, unknown>)[k] = device;
      } else walk(v, depth + 1);
    }
  };
  walk(obj, 0);
  return JSON.stringify(obj);
}
