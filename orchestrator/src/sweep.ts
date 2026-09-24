import { diffResponses, classifySignal, classifySqlSignal, type FuzzResponse, type FuzzProbe } from "./fuzz.js";

/**
 * Deep-mode systematic sweep controller.
 *
 * The breadth-first default relies on the LLM to CHOOSE which single probe to send each
 * turn, so it never enumerates every input × payload class and often skips an endpoint it
 * believes is "already proved" (leaving canonical-endpoint coverage on the table). This
 * controller instead ENUMERATES deterministically: every discovered input × every payload
 * class, baseline-vs-exploit, judged by the pure fuzz oracle. Strong hits are handed to
 * the beat as claims the LLM submits and the Axiom verifies — the sweep discovers, the
 * Axiom still decides. It hits canonical endpoints regardless of prior "proved" state,
 * which is exactly what converts a class proved only on a sub-path (e.g. /x/index) onto
 * its canonical route.
 *
 * PURE except for the injected `send` — beat.ts backs it with Tether-gated http_request,
 * so every probe is scope-checked and audited like any request; tests inject a fake.
 */

export interface SweepTarget {
  /** Absolute URL of the endpoint (query-less base, or with fixed non-fuzzed query). */
  endpoint: string;
  method: string;
  /** Parameter names to fuzz (query keys or JSON data keys). */
  params: string[];
}

/** A payload to try for a class, with what proves it (see fuzz.FuzzProbe). */
export interface SweepPayload {
  payloadClass: string;
  payload: string;
  marker?: string;
  computedMarker?: string;
  note: string;
}

export interface SweepHit {
  vuln_class: string;
  endpoint: string;
  param: string;
  payload: string;
  strength: "strong" | "weak";
  /** The observed proof: the reflected canary / computed value / SQL error, for the note. */
  observed: string;
  note: string;
}

/** Fire one probe: set `param`=`value` on `target` and return the response. `value===null`
 * requests the benign baseline for that (endpoint,param). Injected by the caller. */
export type SendProbe = (target: SweepTarget, param: string, value: string | null) => Promise<FuzzResponse>;

/**
 * The sweep's OWN payload set (distinct from payload-library's LLM-facing arsenal): each
 * carries the exact `marker`/`computedMarker` the fuzz oracle needs. Computed values are
 * deliberately DISTINCTIVE (1337*1337=1787569, a nonce'd echo) so a chance occurrence of
 * "49" can't false-positive. XXE is not here — it replaces the whole body and is probed
 * separately by the caller. Cheapest-first within each class.
 */
export const SWEEP_PAYLOADS: Record<string, SweepPayload[]> = {
  xss_reflected: [
    { payloadClass: "xss_reflected", payload: "<script>sahwSX1</script>", marker: "sahwSX1", note: "unencoded <script> reflected (body_contains vs a benign-text control)" },
    { payloadClass: "xss_reflected", payload: "\"'><svg/onload=alert(1)>sahwSX2", marker: "sahwSX2", note: "attribute/tag breakout reflected unencoded" },
  ],
  html_injection: [
    { payloadClass: "html_injection", payload: "<u>sahwHI1</u>", marker: "sahwHI1", note: "unescaped HTML tag reflected verbatim" },
  ],
  ssti: [
    { payloadClass: "ssti", payload: "{{1337*1337}}", computedMarker: "1787569", note: "template evaluated the expression (computed 1787569, not the literal)" },
    { payloadClass: "ssti", payload: "${{1337*1337}}", computedMarker: "1787569", note: "alt SSTI wrapper -> computed 1787569" },
    { payloadClass: "ssti", payload: "<%= 1337*1337 %>", computedMarker: "1787569", note: "ERB/EJS evaluation -> computed 1787569" },
  ],
  command_injection: [
    { payloadClass: "command_injection", payload: "; echo sahwCMD1787", computedMarker: "sahwCMD1787", note: "OS command executed (marker echoed)" },
    { payloadClass: "command_injection", payload: "$(echo sahwCMD1787)", computedMarker: "sahwCMD1787", note: "command substitution -> marker in output" },
  ],
  sqli: [
    { payloadClass: "sqli", payload: "'", note: "single quote -> DB error signature = injectable (error-based)" },
    { payloadClass: "sqli", payload: "1'||'", note: "string-concat break -> DB error" },
  ],
  path_traversal: [
    { payloadClass: "path_traversal", payload: "../../../../../../etc/passwd", marker: "root:x:0:0", note: "traversed /etc/passwd content returned" },
    { payloadClass: "path_traversal", payload: "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", marker: "root:x:0:0", note: "url-encoded traversal bypass" },
  ],
};

/** How many payload classes and how many payloads-per-class the sweep enumerates. Kept
 * small (cheapest-first) so the request budget covers real breadth across many inputs. */
export const DEFAULT_CLASS_ORDER = [
  "xss_reflected", "html_injection", "ssti", "sqli", "command_injection", "path_traversal", "xxe",
] as const;

/**
 * Run the sweep over `targets`, drawing payloads from `payloadsFor(class)`, bounded by
 * `budget` total probes (each baseline counts once per (endpoint,param), reused across
 * classes). Returns strong hits first, then weak leads. Deterministic given its inputs.
 */
export async function runSweep(opts: {
  targets: SweepTarget[];
  payloadsFor: (cls: string) => SweepPayload[];
  send: SendProbe;
  budget: number;
  classOrder?: readonly string[];
}): Promise<SweepHit[]> {
  const { targets, payloadsFor, send } = opts;
  const classOrder = opts.classOrder ?? DEFAULT_CLASS_ORDER;
  const hits: SweepHit[] = [];
  const weak: SweepHit[] = [];
  let spent = 0;
  const baselineCache = new Map<string, FuzzResponse>();

  for (const target of targets) {
    for (const param of target.params) {
      if (spent >= opts.budget) break;
      const key = `${target.method} ${target.endpoint}\u0000${param}`;
      let baseline = baselineCache.get(key);
      if (!baseline) {
        baseline = await send(target, param, null);
        spent++;
        baselineCache.set(key, baseline);
      }
      for (const cls of classOrder) {
        if (spent >= opts.budget) break;
        for (const pl of payloadsFor(cls)) {
          if (spent >= opts.budget) break;
          const candidate = await send(target, param, pl.payload);
          spent++;
          const probe: FuzzProbe = { payloadClass: pl.payloadClass, payload: pl.payload, marker: pl.marker, computedMarker: pl.computedMarker };
          const signal = diffResponses(baseline, candidate, probe);
          let strength = classifySignal(signal, probe);
          // sqli's oracle is the response text, not the marker set.
          if (cls === "sqli" && classifySqlSignal(candidate.body) === "strong") strength = "strong";
          if (strength === "none") continue;
          const observed = signal.newReflections[0]
            ?? (cls === "sqli" ? "SQL error signature" : `divergent response (sim ${signal.bodySimilarity.toFixed(2)})`);
          const hit: SweepHit = { vuln_class: cls, endpoint: target.endpoint, param, payload: pl.payload, strength, observed, note: pl.note };
          if (strength === "strong") hits.push(hit); else weak.push(hit);
          if (strength === "strong") break; // one strong payload per (input,class) is enough to hand off
        }
      }
    }
  }
  return [...hits, ...weak];
}

/** Render strong hits as a compact, high-priority brief directive the hunter acts on:
 * exactly which (endpoint, param, class) to submit_finding, with the observed proof. The
 * LLM re-fires the winning payload via http_request and submits — the Axiom then verifies
 * and canonicalizeEndpoint records it on the canonical route. */
export function renderSweepLeads(hits: SweepHit[]): string {
  const strong = hits.filter((h) => h.strength === "strong");
  if (strong.length === 0) return "";
  const lines = strong.slice(0, 40).map((h) =>
    `  - ${h.vuln_class} @ ${h.endpoint} (param ${h.param}): payload ${JSON.stringify(h.payload)} -> observed ${JSON.stringify(h.observed)}. ${h.note}`);
  return [
    "<sweep_leads>",
    "  A deterministic input×payload sweep ALREADY FOUND these high-signal hits this beat.",
    "  For EACH: re-send the exact payload with http_request against that endpoint+param,",
    "  read the response, and submit_finding with the matching invariant (body_contains the",
    "  observed proof; a control with a benign value). These are your FIRST, highest-value",
    "  actions — bank them before free-form hunting. The endpoint is canonical; do not drift",
    "  to a sub-path variant.",
    ...lines,
    "</sweep_leads>",
  ].join("\n");
}
