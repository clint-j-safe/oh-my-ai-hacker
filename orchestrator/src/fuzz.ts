/**
 * Deterministic response-diff oracle for the deep-mode systematic sweep (src/sweep.ts).
 *
 * PURE and side-effect free by design: the sweep fires the actual requests through the
 * Tether-gated http_request path and hands the captures here; this module only REASONS
 * about the exploit-vs-baseline pair and says whether the signal is strong enough to
 * synthesize a claim for the Axiom to verify. "LLM proposes; deterministic code decides"
 * — here even the proposal is deterministic, and the Axiom still decides.
 */

/** The minimal response shape the oracle needs (a subset of HttpCapture.response + ms). */
export interface FuzzResponse {
  status: number;
  body: string;
  ms?: number;
}

/** One sweep probe: a payload fired at one input, with what would prove it worked. */
export interface FuzzProbe {
  payloadClass: string;
  payload: string;
  /** A unique canary the payload embeds; strong reflection = this appears VERBATIM in the
   * exploit body but not the baseline (xss/html-injection). */
  marker?: string;
  /** The value the server computes when it EVALUATES the payload (ssti "49", a command
   * nonce like "sahw42", or "uid="); appearing in the exploit but not baseline proves
   * evaluation rather than mere reflection. */
  computedMarker?: string;
}

export interface FuzzSignal {
  statusDelta: number;
  lengthDelta: number;
  /** 0..1 Jaccard token-shingle similarity of the two bodies (1 = identical). */
  bodySimilarity: number;
  /** Canary/computed markers found in the candidate body but NOT the baseline. */
  newReflections: string[];
  timingDeltaMs: number;
}

const SQL_ERROR_RE = /(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBC|Unclosed quotation mark|quoted string not properly terminated|you have an error in your sql|pg_query|sqlite3\.OperationalError|extractvalue|XPATH syntax error)/i;

/** Tokenise into a set of overlapping 3-shingles for a cheap, dependency-free similarity. */
function shingles(s: string): Set<string> {
  const toks = s.toLowerCase().replace(/\s+/g, " ").trim().split(" ").filter(Boolean);
  const out = new Set<string>();
  if (toks.length < 3) { toks.forEach((t) => out.add(t)); return out; }
  for (let i = 0; i + 2 < toks.length; i++) out.add(`${toks[i]} ${toks[i + 1]} ${toks[i + 2]}`);
  return out;
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  const union = a.size + b.size - inter;
  return union === 0 ? 1 : inter / union;
}

/** Compute the raw signal between a benign baseline and a payload candidate. */
export function diffResponses(baseline: FuzzResponse, candidate: FuzzResponse, probe?: FuzzProbe): FuzzSignal {
  const newReflections: string[] = [];
  for (const marker of [probe?.computedMarker, probe?.marker]) {
    if (marker && candidate.body.includes(marker) && !baseline.body.includes(marker)) {
      newReflections.push(marker);
    }
  }
  return {
    statusDelta: candidate.status - baseline.status,
    lengthDelta: candidate.body.length - baseline.body.length,
    bodySimilarity: jaccard(shingles(baseline.body), shingles(candidate.body)),
    newReflections,
    timingDeltaMs: (candidate.ms ?? 0) - (baseline.ms ?? 0),
  };
}

/**
 * Classify a probe's signal. "strong" means synthesize a claim for the Axiom; "weak"
 * means worth an LLM follow-up but not auto-claim; "none" means move on. The rules mirror
 * the invariant each class proves with, so a strong classification lines up with a
 * verifiable claim:
 *   xss_reflected/xss_stored/html_injection/dom_xss  the canary reflects unescaped (marker present)
 *   ssti / command_injection                          the COMPUTED value appears (evaluation)
 *   sqli                                              a DB error signature surfaces
 *   generic                                           a large, low-similarity divergence from baseline
 */
export function classifySignal(signal: FuzzSignal, probe: FuzzProbe): "none" | "weak" | "strong" {
  const cls = probe.payloadClass;
  const reflectsComputed = probe.computedMarker ? signal.newReflections.includes(probe.computedMarker) : false;
  const reflectsMarker = probe.marker ? signal.newReflections.includes(probe.marker) : false;

  if (cls === "ssti" || cls === "command_injection") {
    return reflectsComputed ? "strong" : "none";
  }
  if (cls === "xss_reflected" || cls === "xss_stored" || cls === "html_injection" || cls === "dom_xss") {
    // The payload's own canary coming back verbatim (unescaped) is the proof.
    return reflectsMarker ? "strong" : "none";
  }
  // sqli is decided from the response TEXT (error signatures), not the marker set —
  // the sweep calls classifySqlSignal(body) directly. From the signal alone we can only
  // flag a divergence as a weak lead.
  // Generic divergence heuristic for classes without a specific oracle: a big,
  // dissimilar change is a weak lead the LLM should chase, not an auto-claim.
  if (signal.bodySimilarity < 0.4 || Math.abs(signal.statusDelta) >= 100 || Math.abs(signal.lengthDelta) > 200) {
    return "weak";
  }
  return "none";
}

/** SQLi oracle needs the raw body (error signatures live in text, not in the marker set). */
export function classifySqlSignal(candidateBody: string): "none" | "strong" {
  return SQL_ERROR_RE.test(candidateBody) ? "strong" : "none";
}
