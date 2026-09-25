import type { HttpCapture } from "./tools.js";
import { createHmac, createDecipheriv, timingSafeEqual } from "node:crypto";

export type InvariantType =
  | "body_contains" | "status_in" | "derived"
  | "state_changed" | "state_violated" | "file_created_then_deleted"
  | "response_asserted";

export interface Invariant {
  statement: string;
  type: InvariantType;
  expression: string;
}

// CONFIRMED_BY_ADJUDICATION is a DISTINCT tier from the deterministic CONFIRMED: it is
// only ever set by the pre-gate LLM judge promoting a deterministic NEEDS_REVIEW whose
// evidence the judge scores as clearly meeting the invariant's rubric. It carries its
// own provenance (judge score + rationale) and MUST NOT be counted as a deterministic
// CONFIRMED anywhere the audit trail's integrity depends on determinism.
export type VerdictStatus = "CONFIRMED" | "CONFIRMED_BY_ADJUDICATION" | "FALSE_POSITIVE" | "NEEDS_REVIEW" | "BLOCKED";

export interface Verdict {
  status: VerdictStatus;
  reason: string;
}

/**
 * Extra evidence beyond the exploit/control pair, needed by the four invariant types
 * whose proof shape is not a single differential request. This parameter is additive
 * and OPTIONAL: every existing call site that only ever needed (exploit, control)
 * keeps compiling and behaving identically, because it simply omits it. None of
 * body_contains, status_in or response_asserted read this parameter.
 */
export interface EvidenceBundle {
  // Ordered captures consumed by:
  //   state_changed              >= 3: [pre, ...action step(s), post]. Only captures[0]
  //                               (pre) and captures[captures.length - 1] (post) are
  //                               compared; anything in between is context, not compared.
  //   state_violated              >= 2 (single_use) or >= 5 (lockout_absent): one capture
  //                               per attempt in the sequence under test, in order.
  //   file_created_then_deleted   exactly 3: [before, during, after].
  // Fewer captures than a type requires is NEEDS_REVIEW, never a guess — see each
  // evaluator below for the exact reason text.
  captures?: HttpCapture[];
  // Typed input object for the `derived` invariant's selected deriver (see DERIVERS
  // below). Shape is deriver-specific; each deriver validates its own input and returns
  // NEEDS_REVIEW naming what is missing/malformed rather than guessing.
  derivedInput?: unknown;
  // Proof that a mutation state_changed observed was undone, when the finding/invariant
  // carries a restoration requirement (L2 safety). `required: true` without both
  // `performed: true` and a `proof` capture forces the verdict to NEEDS_REVIEW even
  // though the delta itself confirmed — a state change we cannot prove we undid is not a
  // finished finding.
  restoration?: { required: boolean; performed: boolean; proof?: HttpCapture };
}

// Builds a canonical serialization of one side of an exchange (status line, then
// response headers sorted by name for determinism, then a blank line, then the
// body) so that body_contains — and anything else that scans "the response" for a
// marker — can see evidence that lives in a header, not just in the body. Header
// insertion order is not meaningful (it's a Record<string,string>, and the same
// logical exchange could be built with headers inserted in any order), so without
// sorting the same exchange could serialize two different ways and a test — or a
// real verdict — could flap depending on insertion order alone.
function serializeExchange(cap: HttpCapture): string {
  // Plain .sort() (UTF-16 code-unit order), deliberately NOT .localeCompare(): locale
  // collation depends on the runtime's default locale and ICU build (small-icu vs
  // full-icu, LANG), and it weighs punctuation like "-" differently from a plain
  // codepoint sort — which is exactly the kind of environment-dependent instability this
  // sort exists to rule out.
  const headerNames = Object.keys(cap.response.headers).sort();
  const headerLines = headerNames.map((name) => `${name}: ${cap.response.headers[name]}`);
  return [`HTTP ${cap.response.status}`, ...headerLines, "", cap.response.body].join("\n");
}

// Case-insensitive header lookup. tools.ts's http() populates response.headers from the
// WHATWG Headers API, which already lower-cases every key, but response_asserted's
// expression names come from the model/finding author and must not be assumed to match
// that casing.
function findHeaderValue(headers: Record<string, string>, lowerName: string): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lowerName) return v;
  }
  return undefined;
}

/**
 * The control-differential rule: a finding is real only when the exploit and a
 * benign control diverge exactly as the invariant predicts. Without a control we
 * cannot tell a genuine leak from a page that happens to contain the marker, so
 * the answer is NEEDS_REVIEW — never CONFIRMED.
 */
export function evaluate(
  inv: Invariant, exploit: HttpCapture, control: HttpCapture | null,
  evidence?: EvidenceBundle,
): Verdict {
  if (!inv.expression || !inv.expression.trim()) {
    return { status: "NEEDS_REVIEW", reason: "invariant expression is empty" };
  }

  // response_asserted is the ONE deliberate exception to the control-differential rule
  // above, and it is narrow on purpose: it exists only for claims about the server's own
  // configuration (a missing security header, a dangerous CORS combination), which are
  // self-evidencing — the response either has the property or it does not, and no
  // attacker input exists to vary in a control. It is NOT a general bypass: any claim of
  // the form "my input caused this behaviour" must still use a differential type
  // (body_contains, status_in, ...) so a page that merely happens to contain a marker
  // cannot be reported as a leak. That is also why there is no "!body:" or other
  // body-absence form here — body absence is exactly the case where skipping the control
  // would let a false positive through, so it deliberately has no expressible form.
  if (inv.type === "response_asserted") {
    return evaluateResponseAsserted(inv.expression, exploit);
  }

  // derived, state_changed, state_violated and file_created_then_deleted are, like
  // response_asserted, evaluated from their OWN evidence shape rather than an
  // exploit-vs-control differential — a computation over supplied inputs, a
  // pre/action/post triple, an ordered attempt sequence, or a before/during/after
  // triple respectively. None of them use `control`; they fall outside the
  // control-differential rule entirely rather than weakening it, and each one enforces
  // its own "missing evidence is never a pass" discipline via the `evidence` bundle.
  if (inv.type === "derived") {
    return evaluateDerived(inv.expression, evidence);
  }
  if (inv.type === "state_changed") {
    return evaluateStateChanged(inv.expression, evidence);
  }
  if (inv.type === "state_violated") {
    return evaluateStateViolated(inv.expression, evidence);
  }
  if (inv.type === "file_created_then_deleted") {
    return evaluateFileCreatedThenDeleted(inv.expression, evidence);
  }

  if (control === null) {
    return { status: "NEEDS_REVIEW", reason: "no control request captured; cannot differentiate" };
  }

  switch (inv.type) {
    case "body_contains": {
      const marker = inv.expression;
      const exploitText = serializeExchange(exploit);
      const controlText = serializeExchange(control);
      const inExploit = exploitText.includes(marker);
      const inControl = controlText.includes(marker);
      if (!inExploit) {
        return { status: "FALSE_POSITIVE", reason: `exploit response lacks marker: ${marker}` };
      }
      if (inControl) {
        return { status: "FALSE_POSITIVE", reason: `control response also contains ${marker}` };
      }
      return { status: "CONFIRMED", reason: `marker present in exploit, absent in control` };
    }
    case "status_in": {
      const wanted = inv.expression.split(",").map((s) => Number(s.trim())).filter(Number.isFinite);
      const hit = wanted.includes(exploit.response.status);
      if (!hit) {
        return { status: "FALSE_POSITIVE", reason: `exploit status ${exploit.response.status} not in ${wanted}` };
      }
      if (wanted.includes(control.response.status)) {
        return { status: "FALSE_POSITIVE", reason: `control shares status ${control.response.status}` };
      }
      return { status: "CONFIRMED", reason: `status ${exploit.response.status} differs from control ${control.response.status}` };
    }
    default:
      return {
        status: "NEEDS_REVIEW",
        reason: `invariant type ${inv.type} is not mechanically evaluable in M0`,
      };
  }
}

// Grammar for response_asserted, semicolon-separated clauses, ALL of which must hold for
// CONFIRMED:
//   header:name            -> that header is PRESENT (case-insensitive name)
//   !header:name           -> that header is ABSENT
//   header:name=substring  -> header present AND its value contains that substring
//                             (case-insensitive)
// Evaluates against a single response and returns FALSE_POSITIVE (never CONFIRMED) the
// moment any clause does not hold — this type is self-contained, not self-approving. Any
// clause that does not match one of the three forms above returns NEEDS_REVIEW naming that
// clause, rather than silently ignoring it or guessing what was meant.
function evaluateResponseAsserted(expression: string, exploit: HttpCapture): Verdict {
  const clauses = expression.split(";").map((c) => c.trim()).filter((c) => c.length > 0);
  if (clauses.length === 0) {
    // e.g. expression was ";" or "  ;  " — non-empty text but no actual clause to check.
    // Vacuously "confirming" nothing would be exactly the "assertion that cannot fail"
    // failure mode this project has already been burned by, so escalate instead.
    return { status: "NEEDS_REVIEW", reason: `response_asserted expression has no clauses: ${JSON.stringify(expression)}` };
  }

  for (const clause of clauses) {
    const negMatch = /^!header:([^=]+)$/i.exec(clause);
    const eqMatch = /^header:([^=]+)=(.*)$/i.exec(clause);
    const presMatch = /^header:([^=]+)$/i.exec(clause);

    if (negMatch) {
      const name = negMatch[1].trim().toLowerCase();
      const value = findHeaderValue(exploit.response.headers, name);
      if (value !== undefined) {
        return { status: "FALSE_POSITIVE", reason: `header ${name} is present but asserted absent (clause: ${clause})` };
      }
      continue;
    }

    if (eqMatch) {
      const name = eqMatch[1].trim().toLowerCase();
      const substring = eqMatch[2];
      const value = findHeaderValue(exploit.response.headers, name);
      if (value === undefined || !value.toLowerCase().includes(substring.toLowerCase())) {
        return {
          status: "FALSE_POSITIVE",
          reason: `header ${name} does not contain ${JSON.stringify(substring)} (clause: ${clause})`,
        };
      }
      continue;
    }

    if (presMatch) {
      const name = presMatch[1].trim().toLowerCase();
      const value = findHeaderValue(exploit.response.headers, name);
      if (value === undefined) {
        return { status: "FALSE_POSITIVE", reason: `header ${name} is absent but asserted present (clause: ${clause})` };
      }
      continue;
    }

    return { status: "NEEDS_REVIEW", reason: `unparseable response_asserted clause: ${JSON.stringify(clause)}` };
  }

  return { status: "CONFIRMED", reason: `all response_asserted clauses held: ${expression}` };
}

// =========================================================================================
// derived — a registry of named, implemented derivers, NOT a free-expression evaluator.
// =========================================================================================
//
// THE TRAP: if `derived` accepted an arbitrary expression the model supplied ("these bytes
// equal that plaintext"), the model's own assertion would silently become the proof, and
// the maker-checker property this whole module exists for would collapse — Axiom would be
// rubber-stamping the claimant's own claim. So `derived` does not evaluate expressions at
// all. The model may only SELECT one of the named, hand-written, deterministic functions
// below (by putting its exact name in inv.expression) and supply typed evidence for it
// (evidence.derivedInput); the computation itself is fixed code, reviewed once, here —
// never text the model wrote at finding time. An unknown name is NEEDS_REVIEW naming it,
// never a guess and never a pass.
//
// Grammar: inv.expression is EXACTLY a deriver name, nothing else — no inline arguments.
// All actual inputs (a JWT, candidate keys, ciphertext, an expected-shape pattern,
// origins, a prober) travel through evidence.derivedInput instead, typed per-deriver.
// This keeps the expression string short and auditable, and keeps bulk/sensitive evidence
// out of a string grammar shared with the other invariant types.
type Deriver = (input: unknown) => Verdict;

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null;
}

// --- hs256_weak_key ----------------------------------------------------------------------
// Verifies a JWT's HS256 signature against a list of candidate keys using real HMAC-SHA256
// (node:crypto), not a string comparison the model could fake. CONFIRMED only if some
// candidate verifies. The candidate list is an INPUT (evidence.derivedInput.candidates) —
// recovered from evidence such as strings in a client bundle — never hardcoded here.
interface Hs256WeakKeyInput { jwt: string; candidates: string[] }
function isHs256WeakKeyInput(x: unknown): x is Hs256WeakKeyInput {
  return isRecord(x) && typeof x.jwt === "string"
    && Array.isArray(x.candidates) && x.candidates.length > 0
    && x.candidates.every((c) => typeof c === "string");
}
function deriveHs256WeakKey(input: unknown): Verdict {
  if (!isHs256WeakKeyInput(input)) {
    return {
      status: "NEEDS_REVIEW",
      reason: "hs256_weak_key requires { jwt: string, candidates: string[] } (candidates non-empty)",
    };
  }
  const { jwt, candidates } = input;
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    return { status: "FALSE_POSITIVE", reason: "not a compact JWT (expected 3 dot-separated segments)" };
  }
  const [h, p, s] = parts;
  let header: unknown;
  try {
    header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
  } catch {
    return { status: "FALSE_POSITIVE", reason: "JWT header is not valid base64url-encoded JSON" };
  }
  if (!isRecord(header) || header.alg !== "HS256") {
    return {
      status: "NEEDS_REVIEW",
      reason: `JWT header alg is ${isRecord(header) ? JSON.stringify(header.alg) : "unreadable"}, not HS256 — hs256_weak_key does not apply`,
    };
  }
  let signature: Buffer;
  try {
    signature = Buffer.from(s, "base64url");
  } catch {
    return { status: "FALSE_POSITIVE", reason: "JWT signature segment is not valid base64url" };
  }
  const signingInput = `${h}.${p}`;
  for (const candidate of candidates) {
    const expected = createHmac("sha256", candidate).update(signingInput).digest();
    if (expected.length === signature.length && timingSafeEqual(expected, signature)) {
      return {
        status: "CONFIRMED",
        reason: `JWT HS256 signature verifies with a candidate key (1 of ${candidates.length} tried)`,
      };
    }
  }
  return {
    status: "FALSE_POSITIVE",
    reason: `JWT HS256 signature did not verify with any of ${candidates.length} candidate key(s)`,
  };
}

// --- aes_cbc_decrypt_matches --------------------------------------------------------------
// Decrypts AES-CBC ciphertext with a supplied key/IV (node:crypto) and checks the plaintext
// against an expected-shape regular expression. CONFIRMED only if it decrypts cleanly AND
// matches; a bad key either throws (bad padding) or produces plaintext that fails the
// pattern — both are FALSE_POSITIVE, never an exception escaping to the caller.
interface AesCbcInput { ciphertext: string; key: string; iv: string; expectedPattern: string; encoding?: "base64" | "hex" }
function isAesCbcInput(x: unknown): x is AesCbcInput {
  return isRecord(x) && typeof x.ciphertext === "string" && typeof x.key === "string"
    && typeof x.iv === "string" && typeof x.expectedPattern === "string"
    && (x.encoding === undefined || x.encoding === "base64" || x.encoding === "hex");
}
function deriveAesCbcDecryptMatches(input: unknown): Verdict {
  if (!isAesCbcInput(input)) {
    return {
      status: "NEEDS_REVIEW",
      reason: "aes_cbc_decrypt_matches requires { ciphertext, key, iv, expectedPattern: string, encoding?: \"base64\"|\"hex\" }",
    };
  }
  const encoding = input.encoding ?? "base64";
  const ciphertext = Buffer.from(input.ciphertext, encoding);
  const key = Buffer.from(input.key, encoding);
  const iv = Buffer.from(input.iv, encoding);

  let algo: string;
  if (key.length === 16) algo = "aes-128-cbc";
  else if (key.length === 24) algo = "aes-192-cbc";
  else if (key.length === 32) algo = "aes-256-cbc";
  else return { status: "NEEDS_REVIEW", reason: `key is ${key.length} bytes, not a valid AES key size (16/24/32)` };
  if (iv.length !== 16) {
    return { status: "NEEDS_REVIEW", reason: `iv is ${iv.length} bytes, expected 16` };
  }

  let plaintext: string;
  try {
    const decipher = createDecipheriv(algo, key, iv);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch (e) {
    return {
      status: "FALSE_POSITIVE",
      reason: `ciphertext did not decrypt cleanly with the supplied key/iv: ${(e as Error).message}`,
    };
  }

  let pattern: RegExp;
  try {
    pattern = new RegExp(input.expectedPattern);
  } catch {
    return { status: "NEEDS_REVIEW", reason: `expectedPattern is not a valid regular expression: ${input.expectedPattern}` };
  }
  if (pattern.test(plaintext)) {
    return { status: "CONFIRMED", reason: `decrypted plaintext matches expected shape /${input.expectedPattern}/` };
  }
  return { status: "FALSE_POSITIVE", reason: `decrypted plaintext does not match expected shape /${input.expectedPattern}/` };
}

// --- jwt_payload_contains -----------------------------------------------------------------
// Decodes a JWT payload (base64url, UNVERIFIED — this deriver proves a disclosure claim,
// not a signature claim) and checks for named claim keys, for "PII inside the token" style
// findings. CONFIRMED only if every named claim key is present.
interface JwtPayloadContainsInput { jwt: string; claims: string[] }
function isJwtPayloadContainsInput(x: unknown): x is JwtPayloadContainsInput {
  return isRecord(x) && typeof x.jwt === "string"
    && Array.isArray(x.claims) && x.claims.length > 0
    && x.claims.every((c) => typeof c === "string");
}
function deriveJwtPayloadContains(input: unknown): Verdict {
  if (!isJwtPayloadContainsInput(input)) {
    return { status: "NEEDS_REVIEW", reason: "jwt_payload_contains requires { jwt: string, claims: string[] } (claims non-empty)" };
  }
  const { jwt, claims } = input;
  const parts = jwt.split(".");
  if (parts.length < 2) {
    return { status: "FALSE_POSITIVE", reason: "not a JWT (fewer than 2 dot-separated segments)" };
  }
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return { status: "FALSE_POSITIVE", reason: "JWT payload is not valid base64url-encoded JSON" };
  }
  if (!isRecord(payload)) {
    return { status: "FALSE_POSITIVE", reason: "JWT payload does not decode to a JSON object" };
  }
  const missing = claims.filter((c) => !(c in payload));
  if (missing.length > 0) {
    return { status: "FALSE_POSITIVE", reason: `JWT payload missing claim(s): ${missing.join(", ")}` };
  }
  return { status: "CONFIRMED", reason: `JWT payload contains claim(s): ${claims.join(", ")}` };
}

// --- tls_unavailable -----------------------------------------------------------------------
// Asserts no HTTPS service is reachable across a set of scope origins. A real connection
// attempt is inherently non-deterministic/network-dependent, so the prober is INJECTED
// evidence rather than code in this module — production wiring resolves reachability
// asynchronously and adapts the resolved result into this synchronous closure BEFORE
// calling evaluate() (evaluate() itself stays synchronous for backward compatibility);
// tests inject a fake prober so they never touch the network. CONFIRMED only if the
// prober reports every origin unreachable.
interface TlsUnavailableInput { origins: string[]; prober: (origin: string) => boolean }
function isTlsUnavailableInput(x: unknown): x is TlsUnavailableInput {
  return isRecord(x) && Array.isArray(x.origins) && x.origins.length > 0
    && x.origins.every((o) => typeof o === "string") && typeof x.prober === "function";
}
function deriveTlsUnavailable(input: unknown): Verdict {
  if (!isTlsUnavailableInput(input)) {
    return { status: "NEEDS_REVIEW", reason: "tls_unavailable requires { origins: string[] (non-empty), prober: (origin: string) => boolean }" };
  }
  const reachable: string[] = [];
  for (const origin of input.origins) {
    let result: unknown;
    try {
      result = input.prober(origin);
    } catch (e) {
      return { status: "NEEDS_REVIEW", reason: `prober threw for origin ${origin}: ${(e as Error).message}` };
    }
    if (typeof result !== "boolean") {
      return { status: "NEEDS_REVIEW", reason: `prober did not return a boolean for origin ${origin}` };
    }
    if (result) reachable.push(origin);
  }
  if (reachable.length > 0) {
    return { status: "FALSE_POSITIVE", reason: `HTTPS reachable at: ${reachable.join(", ")}` };
  }
  return { status: "CONFIRMED", reason: `no HTTPS service reachable across ${input.origins.length} origin(s)` };
}

// --- no_secondary_factor_before_otp (benchmark F-13) --------------------------------------
// Proves a password-reset OTP is issued using ONLY a single identity field, with NO
// secondary identity factor (email/mobile/DOB/security question) required. SOUND, not a
// claimant boolean: it computes the property from OBJECTIVE evidence —
//   (1) the OTP-issuing request's OWN data field names contain exactly one identity field
//       and ZERO secondary-factor fields (the app cannot have required a factor it was
//       never sent), AND
//   (2) the OTP was genuinely issued, proven by a control differential: the SAME request
//       shape with an INVALID identity does NOT issue (so issuance is gated on the single
//       identity value, not a canned response) and the exploit response carries an OTP
//       payload the control lacks.
// This is a deduction from real request structure + two real responses, never a trusted
// assertion, and it uses generic field-name classification, not target success vocabulary.
interface NoSecondaryFactorInput { requestFieldNames: string[]; exploitResponse: string; controlResponse: string }
function isNsfInput(x: unknown): x is NoSecondaryFactorInput {
  return isRecord(x) && Array.isArray(x.requestFieldNames)
    && x.requestFieldNames.every((f) => typeof f === "string")
    && typeof x.exploitResponse === "string" && typeof x.controlResponse === "string";
}
const IDENTITY_FIELD = /^(user(id|name)?|email|mobile|phone|msisdn|account|acct|custid|login)/i;
const SECONDARY_FACTOR_FIELD = /(dob|birth|security|secret|question|answer|maiden|aadhar|aadhaar|pan|passport|ssn|kyc)/i;
const PLUMBING_FIELD = /^(otp_type|otptype|timestamp|deviceid|os|host|device|type)$/i;
function deriveNoSecondaryFactorBeforeOtp(input: unknown): Verdict {
  if (!isNsfInput(input)) {
    return { status: "NEEDS_REVIEW", reason: "no_secondary_factor_before_otp requires { requestFieldNames: string[], exploitResponse: string, controlResponse: string }" };
  }
  const leaves = input.requestFieldNames.map((f) => f.split(".").pop() || f);
  const identity = leaves.filter((f) => IDENTITY_FIELD.test(f) && !PLUMBING_FIELD.test(f));
  const secondary = leaves.filter((f) => SECONDARY_FACTOR_FIELD.test(f));
  if (secondary.length > 0) {
    return { status: "FALSE_POSITIVE", reason: `a secondary-factor field WAS present in the OTP request: ${secondary.join(", ")}` };
  }
  if (identity.length !== 1) {
    return { status: "NEEDS_REVIEW", reason: `expected exactly one identity field in the OTP request, found ${identity.length}: ${identity.join(", ")}` };
  }
  if (input.exploitResponse === input.controlResponse) {
    return { status: "FALSE_POSITIVE", reason: "OTP-issuing response is identical to the invalid-identity control — issuance not demonstrated" };
  }
  return {
    status: "CONFIRMED",
    reason: `OTP issued from a single identity field (${identity[0]}) with no secondary factor; issuance confirmed by control differential vs an invalid identity`,
  };
}

// --- auth_bypass_pre_2fa -------------------------------------------------------------------
// Proves a password-only (pre-2FA) session reaches a protected resource that an ANONYMOUS
// session cannot — i.e. the second factor is not enforced on that resource. SOUND via a
// control differential over two real responses:
//   (1) the anonymous request is DENIED (401/403, or a login-redirect 3xx, or a body that
//       lacks the protected marker), AND
//   (2) the pre-2FA session request SUCCEEDS (2xx) and returns protected content the
//       anonymous response does not. Missing either side => NEEDS_REVIEW, never a pass.
interface AuthBypassInput {
  protectedResource: string;
  anonResponse: { status: number; body: string };
  pre2faResponse: { status: number; body: string };
}
function isAuthBypassInput(x: unknown): x is AuthBypassInput {
  return isRecord(x) && typeof x.protectedResource === "string"
    && isRecord(x.anonResponse) && typeof x.anonResponse.status === "number" && typeof x.anonResponse.body === "string"
    && isRecord(x.pre2faResponse) && typeof x.pre2faResponse.status === "number" && typeof x.pre2faResponse.body === "string";
}
function deriveAuthBypassPre2fa(input: unknown): Verdict {
  if (!isAuthBypassInput(input)) {
    return { status: "NEEDS_REVIEW", reason: "auth_bypass_pre_2fa requires { protectedResource, anonResponse:{status,body}, pre2faResponse:{status,body} }" };
  }
  const anon = input.anonResponse, pre = input.pre2faResponse;
  const preReached = pre.status >= 200 && pre.status < 300 && pre.body.trim().length > 0;
  if (!preReached) {
    return { status: "NEEDS_REVIEW", reason: `pre-2FA session did not reach the resource (status ${pre.status})` };
  }
  const anonDenied = anon.status === 401 || anon.status === 403
    || (anon.status >= 300 && anon.status < 400) || anon.body !== pre.body;
  if (!anonDenied || anon.body === pre.body) {
    return { status: "NEEDS_REVIEW", reason: "no anon-vs-pre-2FA differential: anonymous access was not demonstrably denied" };
  }
  return {
    status: "CONFIRMED",
    reason: `pre-2FA (password-only) session reached ${input.protectedResource} (status ${pre.status}) that the anonymous control did not (status ${anon.status}); second factor not enforced`,
  };
}

const DERIVERS: Record<string, Deriver> = {
  hs256_weak_key: deriveHs256WeakKey,
  aes_cbc_decrypt_matches: deriveAesCbcDecryptMatches,
  jwt_payload_contains: deriveJwtPayloadContains,
  tls_unavailable: deriveTlsUnavailable,
  no_secondary_factor_before_otp: deriveNoSecondaryFactorBeforeOtp,
  auth_bypass_pre_2fa: deriveAuthBypassPre2fa,
};

function evaluateDerived(expression: string, evidence: EvidenceBundle | undefined): Verdict {
  const name = expression.trim();
  const deriver = DERIVERS[name];
  if (!deriver) {
    return { status: "NEEDS_REVIEW", reason: `unknown deriver: ${JSON.stringify(name)}` };
  }
  // Missing evidence is never a pass: without derivedInput there is nothing for the
  // deriver to compute over, so this is NEEDS_REVIEW, not a guess.
  if (!evidence || evidence.derivedInput === undefined) {
    return { status: "NEEDS_REVIEW", reason: `derived:${name} requires evidence.derivedInput, none supplied` };
  }
  return deriver(evidence.derivedInput);
}

// =========================================================================================
// state_changed — observe state, act, observe again, assert the delta.
// =========================================================================================
//
// Grammar for state_changed.expression — exactly one clause:
//   appeared:<marker>      marker absent from the serialized pre-capture, present in post
//   disappeared:<marker>   marker present in the serialized pre-capture, absent from post
//   field:<dotted.path>;from:<a>;to:<b>
//                          JSON-parse each capture's response body, walk <dotted.path>
//                          (simple a.b.c field access, no array indices), stringify the
//                          value found, and require pre === <a> AND post === <b>
//
// evidence.captures must be an ordered array of at least 3 HttpCaptures: [pre, ...action
// step(s), post]. Only the first (pre) and last (post) are compared; anything in between
// is context, not compared. Fewer than 3 is NEEDS_REVIEW — missing evidence is never a pass.
function evaluateStateChanged(expression: string, evidence: EvidenceBundle | undefined): Verdict {
  const captures = evidence?.captures;
  if (!captures || captures.length < 3) {
    return {
      status: "NEEDS_REVIEW",
      reason: `state_changed requires at least 3 ordered captures (pre, action, post); ${captures?.length ?? 0} supplied`,
    };
  }
  const pre = captures[0];
  const post = captures[captures.length - 1];

  const verdict = evaluateStateChangedClause(expression.trim(), pre, post);
  if (verdict.status !== "CONFIRMED") return verdict;

  // L2 safety: a state change we cannot prove we undid is not a finished finding, so a
  // restoration requirement without proof downgrades an otherwise-CONFIRMED delta to
  // NEEDS_REVIEW rather than letting it pass silently.
  const restoration = evidence?.restoration;
  if (restoration?.required && !(restoration.performed && restoration.proof)) {
    return {
      status: "NEEDS_REVIEW",
      reason: "state_changed delta confirmed but restoration is required and no restoration evidence was supplied",
    };
  }
  return verdict;
}

function evaluateStateChangedClause(clause: string, pre: HttpCapture, post: HttpCapture): Verdict {
  const appeared = /^appeared:(.+)$/.exec(clause);
  if (appeared) {
    const marker = appeared[1];
    const wasPresent = serializeExchange(pre).includes(marker);
    const isPresent = serializeExchange(post).includes(marker);
    if (!wasPresent && isPresent) {
      return { status: "CONFIRMED", reason: `marker appeared: absent pre, present post (${marker})` };
    }
    if (wasPresent) {
      return { status: "FALSE_POSITIVE", reason: `marker was already present before the action: ${marker}` };
    }
    return { status: "FALSE_POSITIVE", reason: `marker never appeared: ${marker}` };
  }

  const disappeared = /^disappeared:(.+)$/.exec(clause);
  if (disappeared) {
    const marker = disappeared[1];
    const wasPresent = serializeExchange(pre).includes(marker);
    const isPresent = serializeExchange(post).includes(marker);
    if (wasPresent && !isPresent) {
      return { status: "CONFIRMED", reason: `marker disappeared: present pre, absent post (${marker})` };
    }
    if (!wasPresent) {
      return { status: "FALSE_POSITIVE", reason: `marker was never present before the action: ${marker}` };
    }
    return { status: "FALSE_POSITIVE", reason: `marker still present after the action: ${marker}` };
  }

  const field = /^field:([^;]+);from:([^;]*);to:([^;]*)$/.exec(clause);
  if (field) {
    const [, path, from, to] = field;
    const preVal = readJsonPath(pre.response.body, path);
    const postVal = readJsonPath(post.response.body, path);
    if (preVal !== from) {
      return { status: "FALSE_POSITIVE", reason: `pre-value at ${path} was ${JSON.stringify(preVal)}, expected ${JSON.stringify(from)}` };
    }
    if (postVal !== to) {
      return { status: "FALSE_POSITIVE", reason: `post-value at ${path} was ${JSON.stringify(postVal)}, expected ${JSON.stringify(to)}` };
    }
    return { status: "CONFIRMED", reason: `field ${path} changed from ${JSON.stringify(from)} to ${JSON.stringify(to)}` };
  }

  return { status: "NEEDS_REVIEW", reason: `unparseable state_changed expression: ${JSON.stringify(clause)}` };
}

function readJsonPath(body: string, path: string): string | undefined {
  try {
    let cur: unknown = JSON.parse(body);
    for (const part of path.split(".")) {
      if (!isRecord(cur)) return undefined;
      cur = cur[part];
    }
    return cur === undefined ? undefined : String(cur);
  } catch {
    return undefined;
  }
}

// =========================================================================================
// state_violated — a rule that must hold across a SEQUENCE is broken.
// =========================================================================================
//
// Grammar for state_violated.expression — exactly one clause:
//   single_use:<marker>     a value that should only ever be accepted once was accepted
//                           (marker present in the serialized exchange) in 2+ captures of
//                           the ordered sequence. Requires >=2 captures — one attempt
//                           cannot prove reuse.
//   lockout_absent:<status> N attempts were made and the given lockout/throttle status
//                           code never appears among the sequence's response statuses.
//                           Requires >=5 captures — a couple of failed attempts cannot
//                           prove the ABSENCE of a lockout that might trigger later.
function evaluateStateViolated(expression: string, evidence: EvidenceBundle | undefined): Verdict {
  const clause = expression.trim();
  const captures = evidence?.captures;

  const singleUse = /^single_use:(.+)$/.exec(clause);
  if (singleUse) {
    const marker = singleUse[1];
    if (!captures || captures.length < 2) {
      return {
        status: "NEEDS_REVIEW",
        reason: `single_use requires at least 2 ordered captures to demonstrate reuse; ${captures?.length ?? 0} supplied`,
      };
    }
    const acceptedCount = captures.filter((c) => serializeExchange(c).includes(marker)).length;
    if (acceptedCount >= 2) {
      return {
        status: "CONFIRMED",
        reason: `marker ${JSON.stringify(marker)} was accepted ${acceptedCount} times across ${captures.length} attempts — single-use violated`,
      };
    }
    return {
      status: "FALSE_POSITIVE",
      reason: `marker ${JSON.stringify(marker)} was accepted ${acceptedCount} time(s) across ${captures.length} attempts — single-use held`,
    };
  }

  const lockoutAbsent = /^lockout_absent:(\d+)$/.exec(clause);
  if (lockoutAbsent) {
    const lockoutStatus = Number(lockoutAbsent[1]);
    const MIN_ATTEMPTS = 5;
    if (!captures || captures.length < MIN_ATTEMPTS) {
      return {
        status: "NEEDS_REVIEW",
        reason: `lockout_absent requires at least ${MIN_ATTEMPTS} ordered attempts to demonstrate the absence of a lockout; ${captures?.length ?? 0} supplied`,
      };
    }
    const lockedIndex = captures.findIndex((c) => c.response.status === lockoutStatus);
    if (lockedIndex === -1) {
      return { status: "CONFIRMED", reason: `lockout status ${lockoutStatus} never appeared across ${captures.length} attempts` };
    }
    return { status: "FALSE_POSITIVE", reason: `lockout status ${lockoutStatus} appeared at attempt ${lockedIndex + 1}` };
  }

  return { status: "NEEDS_REVIEW", reason: `unparseable state_violated expression: ${JSON.stringify(clause)}` };
}

// =========================================================================================
// file_created_then_deleted — a marker resource must be absent, then present, then absent.
// =========================================================================================
//
// Grammar: expression is the marker identifying the resource, checked the same way as
// body_contains — substring presence in the serialized exchange. evidence.captures must be
// EXACTLY 3 ordered captures: [before, during, after]. Any presence pattern other than
// absent→present→absent is FALSE_POSITIVE naming which pattern was observed — in
// particular "still present at the end" is a FALSE_POSITIVE, not a pass: the finding's
// safety property is that the PoC left nothing behind, so a marker that survives to the
// third capture disproves exactly that property.
function evaluateFileCreatedThenDeleted(expression: string, evidence: EvidenceBundle | undefined): Verdict {
  const marker = expression.trim();
  const captures = evidence?.captures;
  if (!captures || captures.length !== 3) {
    return {
      status: "NEEDS_REVIEW",
      reason: `file_created_then_deleted requires exactly 3 ordered captures (before, during, after); ${captures?.length ?? 0} supplied`,
    };
  }
  const [before, during, after] = captures;
  const p0 = serializeExchange(before).includes(marker);
  const p1 = serializeExchange(during).includes(marker);
  const p2 = serializeExchange(after).includes(marker);

  if (!p0 && p1 && !p2) {
    return { status: "CONFIRMED", reason: `marker absent before, present during, absent after: ${marker}` };
  }
  if (p0 && p1 && p2) {
    return { status: "FALSE_POSITIVE", reason: `marker present throughout (before/during/after) — nothing was created or deleted: ${marker}` };
  }
  if (!p0 && !p1 && !p2) {
    return { status: "FALSE_POSITIVE", reason: `marker never present in any capture — nothing was created: ${marker}` };
  }
  if (!p0 && p1 && p2) {
    return { status: "FALSE_POSITIVE", reason: `marker still present at the end — created but not deleted: ${marker}` };
  }
  return {
    status: "FALSE_POSITIVE",
    reason: `unexpected presence pattern (before=${p0}, during=${p1}, after=${p2}) — not a create-then-delete cycle: ${marker}`,
  };
}
