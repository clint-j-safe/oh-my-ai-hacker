// The pre-gate LLM judge.
//
// It sits IN FRONT of the deterministic Axiom and SCORES each claim 0-100 against the
// EXACT deterministic invariant rubric the Axiom will apply — so the score is anchored
// to strict deterministic criteria, not free-floating opinion. The judge is ADVISORY:
//
//   - the deterministic Axiom (axiom.ts:evaluate) remains the SOLE authority on a
//     deterministic CONFIRMED / FALSE_POSITIVE;
//   - a low judge score is early, cheap feedback that a claim is unlikely to pass the
//     deterministic replay (it never hard-blocks — a broken/absent judge fails OPEN);
//   - a HIGH judge score on a claim the Axiom returned NEEDS_REVIEW may promote it to
//     the DISTINCT `CONFIRMED_BY_ADJUDICATION` tier (never the deterministic CONFIRMED).
//
// Calibration is the whole point: the judge is handed the precise rule the Axiom uses,
// so "score" means "how strongly does this evidence meet THAT deterministic criterion".

import type { InvariantType, Invariant, Verdict } from "./axiom.js";
import type { HttpCapture } from "./tools.js";

/** Same minimal client shape agent.ts uses — an OpenAI-compatible chat completions. */
export interface JudgeClient {
  chat: { completions: { create(params: any, opts?: any): Promise<any> } };
}

export type JudgeLean = "confirm" | "reject" | "unsure";

export interface JudgeScore {
  /** 0-100: how strongly the evidence meets the invariant's STRICT deterministic rule. */
  score: number;
  lean: JudgeLean;
  rationale: string;
  /** The judge model id, or "disabled"/"unavailable" when no score was produced. */
  model: string;
  ok: boolean;
}

/**
 * The STRICT deterministic criterion per invariant type — mirrors axiom.ts's evaluators
 * verbatim in intent, so the judge scores adherence to the SAME rule the gate applies.
 */
export const INVARIANT_RUBRIC: Record<InvariantType, string> = {
  body_contains:
    "PASS only if the invariant's marker/expression appears in the EXPLOIT response body AND is ABSENT from the CONTROL response body. Marker in BOTH = false positive (score ~0). Marker absent from the exploit = fail.",
  status_in:
    "PASS only if the EXPLOIT response status is in the expected set AND the CONTROL status is NOT (a real differential). Same status on both = not differential.",
  response_asserted:
    "Self-contained (no control). PASS only if the asserted clause about the server's OWN response holds exactly — a header is absent, or a header/config value matches the expression.",
  derived:
    "PASS only if the named deriver's typed input is COMPLETE and its computation succeeds — e.g. hs256_weak_key: a candidate key actually verifies the JWT's HMAC signature; tls_unavailable: a TLS handshake is refused on :443 for every in-scope origin; aes_cbc_decrypt_matches: decrypting with the given key+iv yields the expected pattern. Missing/partial input = cannot pass.",
  state_changed:
    "PASS only if comparing the PRE capture to the POST capture shows the claimed change (a marker appeared / disappeared, or a field went from X to Y). Needs >=3 ordered captures [pre, action(s), post]; the success MESSAGE alone is not a state change.",
  state_violated:
    "PASS only if the ordered sequence proves a security counter / single-use control was defeated — e.g. an attempt accepted past the stated lockout, or a single-use token accepted twice.",
  file_created_then_deleted:
    "PASS only if exactly 3 captures [before, during, after] show a file that was absent, then present, then removed.",
};

const clip = (s: string | undefined | null, n: number): string =>
  typeof s === "string" ? (s.length > n ? s.slice(0, n) + `…(+${s.length - n}b)` : s) : "";

/** Compact, bounded view of a capture for the judge (status + a header slice + body head). */
function captureView(label: string, c: HttpCapture | null | undefined, bodyBytes: number): string {
  if (!c) return `${label}: (none captured)`;
  const hs = Object.entries(c.response?.headers ?? {})
    .filter(([k]) => /^(content-type|server|x-powered-by|access-control|set-cookie|location|www-authenticate|x-frame-options|content-security-policy)/i.test(k))
    .slice(0, 8).map(([k, v]) => `${k}: ${clip(String(v), 120)}`).join("; ");
  return `${label}: ${c.request?.method} ${clip(c.request?.url, 160)} -> ${c.response?.status}\n  headers: ${hs}\n  body: ${clip(c.response?.body, bodyBytes)}`;
}

const SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    score: { type: "integer", minimum: 0, maximum: 100 },
    lean: { type: "string", enum: ["confirm", "reject", "unsure"] },
    rationale: { type: "string" },
  },
  required: ["score", "lean", "rationale"],
} as const;

/** Extract the first balanced JSON object from text (defensive; providers vary on
 * whether response_format is honoured, and reasoning models prepend prose). */
function firstJsonObject(text: string): any | null {
  const start = text.indexOf("{");
  if (start === -1) return null;
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') inStr = true;
    else if (ch === "{") depth++;
    else if (ch === "}") { depth--; if (depth === 0) { try { return JSON.parse(text.slice(start, i + 1)); } catch { return null; } } }
  }
  return null;
}

const DISABLED: JudgeScore = { score: -1, lean: "unsure", rationale: "judge disabled (no SAHW_JUDGE_MODEL)", model: "disabled", ok: false };

/**
 * Score one claim against its invariant's deterministic rubric. Never throws; a failed
 * or absent judge returns ok:false so callers fail OPEN to the deterministic Axiom.
 */
export async function judgeClaim(opts: {
  client: JudgeClient | undefined;
  model: string | undefined;
  vulnClass: string;
  invariant: Invariant;
  exploit: HttpCapture | null;
  control: HttpCapture | null;
  steps?: HttpCapture[];
  derivedInputSummary?: string;
  bodyBytes?: number;
  signal?: AbortSignal;
}): Promise<JudgeScore> {
  if (!opts.client || !opts.model || !opts.model.trim()) return DISABLED;
  const bytes = Math.max(200, opts.bodyBytes ?? 1400);
  const rubric = INVARIANT_RUBRIC[opts.invariant.type] ?? "Unknown invariant type — score conservatively.";
  const evidence: string[] = [];
  if (opts.invariant.type === "state_changed" || opts.invariant.type === "state_violated" || opts.invariant.type === "file_created_then_deleted") {
    const caps = opts.steps ?? [];
    evidence.push(`ORDERED CAPTURES (${caps.length}):`);
    caps.slice(0, 6).forEach((c, i) => evidence.push(captureView(`  [${i}]`, c, Math.min(bytes, 800))));
  } else {
    evidence.push(captureView("EXPLOIT", opts.exploit, bytes));
    if (opts.invariant.type === "body_contains" || opts.invariant.type === "status_in") evidence.push(captureView("CONTROL", opts.control, bytes));
  }
  if (opts.invariant.type === "derived") evidence.push(`DERIVED INPUT: ${clip(opts.derivedInputSummary, 400) || "(none supplied)"}`);

  const system =
    "You are a STRICT verification judge in front of a deterministic invariant gate. " +
    "You do NOT decide the verdict — you SCORE how strongly the evidence meets the EXACT " +
    "deterministic rule below, 0-100. 100 = the deterministic rule clearly and fully holds; " +
    "50 = ambiguous/partial; 0 = the rule clearly fails or the control matches the exploit. " +
    "Score ONLY against the stated rule — not general plausibility, not whether the class 'seems' present. " +
    "Missing or malformed evidence caps the score low (the deterministic gate would return NEEDS_REVIEW). " +
    'Reply with JSON only: {"score":0-100,"lean":"confirm|reject|unsure","rationale":"<=200 chars"}.';
  const user =
    `VULN CLASS: ${opts.vulnClass}\nINVARIANT TYPE: ${opts.invariant.type}\n` +
    `DETERMINISTIC RULE: ${rubric}\n` +
    `CLAIM STATEMENT: ${clip(opts.invariant.statement, 400)}\n` +
    `EXPRESSION (marker/clause): ${clip(opts.invariant.expression, 300)}\n\nEVIDENCE:\n${evidence.join("\n")}`;

  try {
    const completion = await opts.client.chat.completions.create(
      {
        model: opts.model,
        messages: [{ role: "system", content: system }, { role: "user", content: user }],
        response_format: { type: "json_schema", json_schema: { name: "judge_score", strict: true, schema: SCHEMA } },
        max_tokens: 400,
      },
      opts.signal ? { signal: opts.signal } : undefined,
    );
    const content = completion?.choices?.[0]?.message?.content;
    const parsed = typeof content === "string" ? (firstJsonObject(content) ?? null) : null;
    if (!parsed || typeof parsed.score !== "number") {
      return { score: -1, lean: "unsure", rationale: "judge returned no parseable score", model: opts.model, ok: false };
    }
    const score = Math.max(0, Math.min(100, Math.round(parsed.score)));
    const lean: JudgeLean = parsed.lean === "confirm" || parsed.lean === "reject" ? parsed.lean : "unsure";
    return { score, lean, rationale: clip(String(parsed.rationale ?? ""), 240), model: opts.model, ok: true };
  } catch (e) {
    return { score: -1, lean: "unsure", rationale: `judge call failed: ${(e as Error)?.message ?? e}`, model: opts.model, ok: false };
  }
}

export interface GenuineVerdict { isGenuine: boolean; confidence: number; rationale: string; model: string; ok: boolean }

const GENUINE_SCHEMA = {
  type: "object", additionalProperties: false,
  properties: {
    is_genuine: { type: "boolean" },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    rationale: { type: "string" },
  },
  required: ["is_genuine", "confidence", "rationale"],
} as const;

/**
 * SEMANTIC false-positive auditor (distinct from judgeClaim, which scores rubric adherence).
 * A deterministic gate already CONFIRMED this via a control-differential; this asks whether
 * the finding is a GENUINE, reportable vulnerability of its class — not a server error, a
 * public-by-design asset, or a benign default. ADVISORY + fail-open: the caller only ever
 * DEMOTES to NEEDS_REVIEW on a confident not-genuine, never drops or upgrades.
 */
export async function verifyGenuineFinding(opts: {
  client: JudgeClient | undefined; model: string | undefined;
  vulnClass: string; invariant: Invariant; exploit: HttpCapture | null; control: HttpCapture | null;
  bodyBytes?: number; signal?: AbortSignal;
}): Promise<GenuineVerdict> {
  const FAIL: GenuineVerdict = { isGenuine: true, confidence: 0, rationale: "strict-verify unavailable", model: opts.model ?? "disabled", ok: false };
  if (!opts.client || !opts.model || !opts.model.trim()) return FAIL;
  const bytes = Math.max(200, opts.bodyBytes ?? 1400);
  const system =
    "You are a STRICT false-positive auditor for a web pentest. A deterministic gate already " +
    "CONFIRMED a finding via a control-differential. Decide if it is a GENUINE, reportable " +
    "vulnerability of the stated class — NOT a 5xx server error, NOT a public-by-design static " +
    "asset, NOT a benign framework/CORS default, NOT an incidental differential. Be conservative: " +
    'only say is_genuine=false with high confidence when you are sure it is not a real finding. ' +
    'Reply JSON only: {"is_genuine":bool,"confidence":0..1,"rationale":"<=200 chars"}.';
  const user =
    `VULN CLASS: ${opts.vulnClass}\nINVARIANT: ${opts.invariant.type}\n` +
    `CLAIM: ${clip(opts.invariant.statement, 300)}\nEXPRESSION: ${clip(opts.invariant.expression, 200)}\n\n` +
    `${captureView("EXPLOIT", opts.exploit, bytes)}\n${captureView("CONTROL", opts.control, bytes)}`;
  try {
    const completion = await opts.client.chat.completions.create(
      { model: opts.model, messages: [{ role: "system", content: system }, { role: "user", content: user }],
        response_format: { type: "json_schema", json_schema: { name: "genuine_verdict", strict: true, schema: GENUINE_SCHEMA } },
        max_tokens: 300 },
      opts.signal ? { signal: opts.signal } : undefined);
    const content = completion?.choices?.[0]?.message?.content;
    const parsed = typeof content === "string" ? firstJsonObject(content) : null;
    if (!parsed || typeof parsed.is_genuine !== "boolean" || typeof parsed.confidence !== "number") return FAIL;
    return { isGenuine: parsed.is_genuine, confidence: Math.max(0, Math.min(1, parsed.confidence)),
             rationale: clip(String(parsed.rationale ?? ""), 240), model: opts.model, ok: true };
  } catch (e) {
    return { ...FAIL, rationale: `strict-verify call failed: ${(e as Error)?.message ?? e}` };
  }
}
