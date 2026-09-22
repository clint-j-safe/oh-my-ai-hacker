/**
 * The exact snake_case vocabulary the benchmark harness scores `vuln_class` against.
 * Single source of truth: the hunter brief is composed from it (src/brief.ts), claim
 * parsing validates against it (src/beat.ts), and a test asserts every member is
 * accepted. Free prose (e.g. "Missing framing protection (clickjacking)") is a
 * vocabulary violation, not a vuln — the harness matches on this exact string, so a
 * correct finding with the wrong spelling scores as `missed`.
 *
 * This is a VOCABULARY, not target knowledge: it names classes of vulnerability in
 * the abstract, never an endpoint, a payload, or anything specific to the engagement
 * target. The black-box rule (no target hostname/path/payload in src/) still holds.
 *
 * Lives in its own module (not beat.ts) so src/brief.ts can depend on it without a
 * beat.ts <-> brief.ts import cycle: beat.ts builds the per-beat state and calls
 * buildHunterBrief(), and brief.ts needs the vocabulary to render <output_contract>.
 */
export const VULN_CLASSES = [
  "auth_bypass", "business_logic", "clickjacking", "cors_misconfig", "crypto_disclosure",
  "deserialization_rce", "disposable_email_accepted", "forced_browsing", "idor",
  "improper_session_invalidation", "info_disclosure", "insecure_transport", "jwt_weak_key",
  "path_traversal", "rate_limit_absence", "sqli", "ssrf", "user_enumeration",
  "weak_password_policy", "xss_reflected", "xss_stored", "xxe",
] as const;

export type VulnClass = (typeof VULN_CLASSES)[number];

export function isVulnClass(v: unknown): v is VulnClass {
  return typeof v === "string" && (VULN_CLASSES as readonly string[]).includes(v);
}
