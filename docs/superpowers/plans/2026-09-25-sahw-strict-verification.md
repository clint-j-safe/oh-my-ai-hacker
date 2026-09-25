# SAHW Strict Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop false positives from shipping as CONFIRMED (starting with the `rate_limit_absence`-on-502 and static-asset noise) without ever losing a true positive, using deterministic per-class guards plus an optional self-hosted LLM veto that can only demote CONFIRMED→NEEDS_REVIEW.

**Architecture:** Two layers on the existing verdict pipeline. Layer 1: a pure, class-aware deterministic guard applied to the final verdict — authoritative, no model. Layer 2: an optional, self-hosted LLM "genuine-finding" veto (reusing `judge.ts`/`SAHW_JUDGE_MODEL`) that, on CONFIRMEDs from coarse invariants, demotes to NEEDS_REVIEW only when confidently not-genuine; fails open. Neither layer can ever produce FALSE_POSITIVE or fabricate a CONFIRMED, so a true positive can at worst be routed to human review — never lost.

**Tech Stack:** Node 22+, TypeScript ESM, `node:test` via `tsx` (`cd orchestrator && npm test`), the existing OpenAI-compatible `JudgeClient`. No new dependency; **no jev/TypeSafe runtime dependency**.

**Spec:** `docs/superpowers/specs/2026-09-25-sahw-strict-verification-design.md`

## Global Constraints

- Engine suite `cd orchestrator && npm test` (`tsc --noEmit` then `tsx --test test/*.test.ts`) MUST stay green — the Docker build gate.
- **No true positive is ever lost:** neither layer may set `FALSE_POSITIVE` or drop a finding; the only move is `CONFIRMED`/`CONFIRMED_BY_ADJUDICATION` → `NEEDS_REVIEW` (a human-review tier). Never fabricate/upgrade a verdict.
- **Self-hostable:** the LLM veto uses the operator's own `SAHW_JUDGE_MODEL` over the existing OpenAI-compatible client. No hosted-service (jev/TypeSafe) runtime dependency.
- **Fail open:** if no judge model is configured or the call errors, the deterministic verdict stands unchanged.
- **Deterministic guards are authoritative and primary;** the LLM veto is a secondary best-effort net, scoped to coarse invariants (`status_in`, `body_contains`, `response_asserted`). Strong-proof invariants (`state_changed`, `derived`, `file_created_then_deleted`) are never vetoed.
- Default path unchanged: with `SAHW_STRICT_VERIFY` unset/off AND the guards not triggered, the verdict pipeline behaves as today.

## Review Focus

- **rate_limit_absence with a 4xx (not just 5xx) burst status** — a 403/401 burst is also not "kept succeeding"; the guard must require 2xx, not merely "not 5xx". → Task 1 test.
- **forced_browsing/info_disclosure on a genuinely sensitive non-asset file** (`/.env`, `/backup.sql`, `/.git/config`) — the static-asset guard must NOT demote these (they aren't JS/CSS/image assets). → Task 1 test.
- **The adjudicator promoting a guarded finding back up** — a guard-demoted verdict must not be re-promoted to CONFIRMED_BY_ADJUDICATION; the guard runs AFTER adjudication and is authoritative. → Task 1 test.
- **Strict-verify veto erroring / no model** — must fail open (verdict unchanged), never throw. → Task 2 test.
- **Strict-verify veto on an uncertain or genuine finding** — must NOT demote (keep CONFIRMED); only a confident not-genuine demotes. And it can never yield FALSE_POSITIVE. → Task 2 tests.

---

### Task 1: Deterministic class guards (primary, authoritative)

**Files:**
- Modify: `orchestrator/src/axiom.ts` (add exported `guardConfirmedVerdict`)
- Modify: `orchestrator/src/beat.ts` (apply it to the final adjudicated status, ~after line 3020)
- Test: `orchestrator/test/class-guards.test.ts` (create)

**Interfaces:**
- Consumes: `HttpCapture` (from `./tools.js`), the finalized verdict status string in `beat.ts`.
- Produces: `guardConfirmedVerdict(vulnClass: string, status: string, exploit: HttpCapture | null): { status: string; reason?: string }` — returns the input status unchanged unless a guard demotes a CONFIRMED/CONFIRMED_BY_ADJUDICATION to `NEEDS_REVIEW` (with a reason).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/test/class-guards.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { guardConfirmedVerdict } from "../src/axiom.js";

function cap(url: string, status: number) {
  return { request: { method: "GET", url, headers: {}, body: null },
           response: { status, headers: {}, body: "" } } as any;
}

test("rate_limit_absence: a non-2xx burst status is demoted to NEEDS_REVIEW", () => {
  for (const s of [502, 500, 403, 401, 404]) {
    const g = guardConfirmedVerdict("rate_limit_absence", "CONFIRMED", cap("http://t/api/v2/auth", s));
    assert.equal(g.status, "NEEDS_REVIEW", `status ${s} should demote`);
    assert.match(g.reason ?? "", /2xx/);
  }
});

test("rate_limit_absence: a 2xx burst status stays CONFIRMED", () => {
  const g = guardConfirmedVerdict("rate_limit_absence", "CONFIRMED", cap("http://t/api/login", 200));
  assert.equal(g.status, "CONFIRMED");
});

test("forced_browsing/info_disclosure on a static asset is demoted to NEEDS_REVIEW", () => {
  for (const u of ["http://t/assets/index-x.js", "http://t/service-worker.js", "http://t/a.css", "http://t/x.js.map", "http://t/logo.png"]) {
    for (const cls of ["forced_browsing", "info_disclosure"]) {
      const g = guardConfirmedVerdict(cls, "CONFIRMED", cap(u, 200));
      assert.equal(g.status, "NEEDS_REVIEW", `${cls} ${u} should demote`);
    }
  }
});

test("forced_browsing on a genuinely sensitive non-asset file is NOT demoted (no TP loss)", () => {
  for (const u of ["http://t/.env", "http://t/backup.sql", "http://t/.git/config"]) {
    const g = guardConfirmedVerdict("forced_browsing", "CONFIRMED", cap(u, 200));
    assert.equal(g.status, "CONFIRMED", `${u} must stay CONFIRMED`);
  }
});

test("guard is authoritative over CONFIRMED_BY_ADJUDICATION too, and never yields FALSE_POSITIVE", () => {
  const g = guardConfirmedVerdict("rate_limit_absence", "CONFIRMED_BY_ADJUDICATION", cap("http://t/x", 502));
  assert.equal(g.status, "NEEDS_REVIEW");
  // non-confirmed verdicts pass through untouched
  assert.equal(guardConfirmedVerdict("rate_limit_absence", "NEEDS_REVIEW", cap("http://t/x", 502)).status, "NEEDS_REVIEW");
  assert.equal(guardConfirmedVerdict("sqli", "CONFIRMED", cap("http://t/x", 200)).status, "CONFIRMED");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && npx tsx --test test/class-guards.test.ts`
Expected: FAIL — `guardConfirmedVerdict` is not exported.

- [ ] **Step 3: Write the implementation**

In `orchestrator/src/axiom.ts`, add (near the other exports; it needs the `HttpCapture` type already imported there):

```ts
// Public-by-design frontend static assets — serving these is not a vulnerability.
// Deliberately does NOT include sensitive files (.env/.sql/.bak/.git/...), which must
// still be able to CONFIRM as forced_browsing/info_disclosure.
const STATIC_ASSET_RE = /\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot)(?:\?|$)/i;

/**
 * DETERMINISTIC, class-aware guard applied to a FINAL verdict (authoritative; runs after
 * adjudication). It can only DEMOTE a CONFIRMED/CONFIRMED_BY_ADJUDICATION to NEEDS_REVIEW
 * when the class's evidence is semantically insufficient — it NEVER sets FALSE_POSITIVE and
 * never upgrades. Encodes what a status/endpoint must MEAN for the class, closing the gap
 * where a mechanically-true differential (e.g. status_in 502-vs-403) confirmed a class it
 * does not actually demonstrate.
 */
export function guardConfirmedVerdict(
  vulnClass: string,
  status: string,
  exploit: HttpCapture | null,
): { status: string; reason?: string } {
  if (status !== "CONFIRMED" && status !== "CONFIRMED_BY_ADJUDICATION") return { status };
  const s = exploit?.response?.status ?? 0;

  // rate_limit_absence: proven only if a burst KEPT SUCCEEDING (2xx). A 4xx/5xx burst is
  // not evidence that rate limiting is absent (a 502 is a server error, a 403 is a block).
  if (vulnClass === "rate_limit_absence" && !(s >= 200 && s < 300)) {
    return { status: "NEEDS_REVIEW", reason: `rate_limit_absence requires a 2xx success burst; observed status ${s} is not success — not evidence of absent rate limiting` };
  }

  // forced_browsing / info_disclosure: a public-by-design static asset (JS/CSS/map/image/
  // font) being served is not a finding. Sensitive non-asset files are NOT excluded.
  if (vulnClass === "forced_browsing" || vulnClass === "info_disclosure") {
    let path = "";
    try { path = new URL(exploit?.request?.url ?? "").pathname; } catch { path = exploit?.request?.url ?? ""; }
    if (STATIC_ASSET_RE.test(path)) {
      return { status: "NEEDS_REVIEW", reason: `${vulnClass}: ${path} is a public-by-design static asset; needs human review before CONFIRMED` };
    }
  }
  return { status };
}
```

In `orchestrator/src/beat.ts`, apply the guard to the finalized `adjudicatedStatus` BEFORE the `FindingRow` is built (immediately after the `adjudicatedStatus`/`verdictReason` block, ~line 3040). Replace the direct use of `adjudicatedStatus`/`verdictReason` in the row with a guarded version:

```ts
// DETERMINISTIC class guard — authoritative, runs AFTER adjudication so it also overrides
// a promotion. Can only demote CONFIRMED/CONFIRMED_BY_ADJUDICATION -> NEEDS_REVIEW.
const guarded = guardConfirmedVerdict(claim.vuln_class, adjudicatedStatus, exploit);
const finalStatus = guarded.status;
const finalReason = guarded.status !== adjudicatedStatus ? boundReason(guarded.reason ?? "class guard demotion") : verdictReason;
```

Then use `finalStatus`/`finalReason` for `row.verdict`/`row.verdict_reason` (replace `verdict: adjudicatedStatus` → `verdict: finalStatus`, `verdict_reason: verdictReason` → `verdict_reason: finalReason`). Add `guardConfirmedVerdict` to the existing `./axiom.js` import in beat.ts.

- [ ] **Step 4: Run tests**

Run: `cd orchestrator && npx tsx --test test/class-guards.test.ts` → Expected: PASS (5 tests).
Run: `cd orchestrator && npm test` → Expected: PASS (whole suite; default behavior for other classes unchanged).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/axiom.ts orchestrator/src/beat.ts orchestrator/test/class-guards.test.ts
git commit -m "feat(axiom): deterministic class guards (rate_limit needs 2xx; static-asset exclusion)

Authoritative post-adjudication guard: demotes a CONFIRMED that a class does
not semantically demonstrate (rate_limit_absence off a non-2xx burst;
forced_browsing/info_disclosure on public static assets) to NEEDS_REVIEW.
Never FALSE_POSITIVE, never upgrades — no true positive lost.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BxCkVb1dRUVjPsmR9vJ88e"
```

---

### Task 2: Self-hosted strict-verify LLM veto (best-effort, fail-open)

**Files:**
- Modify: `orchestrator/src/judge.ts` (add `verifyGenuineFinding`)
- Modify: `orchestrator/src/config.ts` (add `strictVerify` + `strictVerifyThreshold` to the engagement)
- Modify: `orchestrator/src/beat.ts` (call the veto after the Task-1 guard, on coarse-invariant CONFIRMEDs)
- Test: `orchestrator/test/strict-verify.test.ts` (create)

**Interfaces:**
- Consumes: `guardConfirmedVerdict` result / `finalStatus` from Task 1; `JudgeClient` (`./judge.js`); `Invariant`, `HttpCapture`.
- Produces: `verifyGenuineFinding(opts) => Promise<{ isGenuine: boolean; confidence: number; rationale: string; model: string; ok: boolean }>`; config `engagement.strictVerify: boolean`, `engagement.strictVerifyThreshold: number`.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/test/strict-verify.test.ts`:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyGenuineFinding } from "../src/judge.js";

function clientReturning(json: string) {
  return { chat: { completions: { create: async () => ({ choices: [{ message: { content: json } }] }) } } } as any;
}
const inv = { type: "status_in", statement: "burst kept returning 502", expression: "502" } as any;
const cap = { request: { method: "GET", url: "http://t/api/v2/auth", headers: {}, body: null },
              response: { status: 502, headers: {}, body: '{"message":"Internal server error"}' } } as any;

test("returns ok:false (fail open) when no model configured", async () => {
  const r = await verifyGenuineFinding({ client: undefined, model: undefined, vulnClass: "rate_limit_absence", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, false);
});

test("parses a confident not-genuine verdict", async () => {
  const r = await verifyGenuineFinding({
    client: clientReturning('{"is_genuine":false,"confidence":0.95,"rationale":"502 is a server error, not absent rate limiting"}'),
    model: "m", vulnClass: "rate_limit_absence", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, true); assert.equal(r.isGenuine, false); assert.ok(r.confidence >= 0.9);
});

test("parses a genuine verdict", async () => {
  const r = await verifyGenuineFinding({
    client: clientReturning('{"is_genuine":true,"confidence":0.8,"rationale":"real disclosure"}'),
    model: "m", vulnClass: "info_disclosure", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, true); assert.equal(r.isGenuine, true);
});

test("fails open (ok:false) when the client throws", async () => {
  const client = { chat: { completions: { create: async () => { throw new Error("boom"); } } } } as any;
  const r = await verifyGenuineFinding({ client, model: "m", vulnClass: "info_disclosure", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, false);
});

test("fails open on unparseable output", async () => {
  const r = await verifyGenuineFinding({ client: clientReturning("not json"), model: "m", vulnClass: "info_disclosure", invariant: inv, exploit: cap, control: null });
  assert.equal(r.ok, false);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd orchestrator && npx tsx --test test/strict-verify.test.ts`
Expected: FAIL — `verifyGenuineFinding` is not exported.

- [ ] **Step 3: Implement `verifyGenuineFinding` in `judge.ts`**

Add to `orchestrator/src/judge.ts` (reuses `JudgeClient`, `clip`, `captureView`, `firstJsonObject`, `Invariant`, `HttpCapture` already in the file):

```ts
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
```

- [ ] **Step 4: Add config in `config.ts`**

In `orchestrator/src/config.ts`, add to the `Engagement` interface `strictVerify: boolean;` and `strictVerifyThreshold: number;`, and in `loadEngagement`'s returned object:

```ts
strictVerify: boolEnv(env, "SAHW_STRICT_VERIFY", false),
strictVerifyThreshold: num(env, "SAHW_STRICT_VERIFY_THRESHOLD", 0.8),
```

(If any `Engagement` object literal exists outside `loadEngagement` — e.g. a test helper — add the two fields there too so `tsc` stays green; grep `grep -rn "strictVerify\|: Engagement" orchestrator/src orchestrator/test`.)

- [ ] **Step 5: Wire the veto into `beat.ts`**

After the Task-1 guard block (after `finalStatus`/`finalReason` are computed, before the `FindingRow`), add:

```ts
// STRICT-VERIFY LLM VETO (opt-in, self-hosted, best-effort). Only on coarse-invariant
// CONFIRMEDs; can only DEMOTE to NEEDS_REVIEW on a confident not-genuine; fails open.
const COARSE_INVARIANTS = new Set(["status_in", "body_contains", "response_asserted"]);
let vStatus = finalStatus, vReason = finalReason;
if (engagement.strictVerify && vStatus === "CONFIRMED" && COARSE_INVARIANTS.has(effectiveInvariantType) && judgeModel) {
  const gv = await verifyGenuineFinding({
    client: opts.client as unknown as import("./judge.js").JudgeClient, model: judgeModel,
    vulnClass: claim.vuln_class, invariant: claim.invariant as Invariant,
    exploit, control, bodyBytes: numEnv(opts.env, "SAHW_TOOL_PREVIEW_BYTES", 1400), signal: controller.signal,
  });
  if (gv.ok && !gv.isGenuine && gv.confidence >= engagement.strictVerifyThreshold) {
    vStatus = "NEEDS_REVIEW";
    vReason = boundReason(`strict-verify demoted CONFIRMED (not genuine @ ${gv.confidence}): ${gv.rationale}`);
  }
}
```

Use `vStatus`/`vReason` for the row's `verdict`/`verdict_reason` (replacing the Task-1 `finalStatus`/`finalReason` use). Import `verifyGenuineFinding` from `./judge.js`.

- [ ] **Step 6: Run tests**

Run: `cd orchestrator && npx tsx --test test/strict-verify.test.ts` → Expected: PASS (5 tests).
Run: `cd orchestrator && npm test` → Expected: PASS (whole suite; default `SAHW_STRICT_VERIFY` off leaves the pipeline unchanged).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/src/judge.ts orchestrator/src/config.ts orchestrator/src/beat.ts orchestrator/test/strict-verify.test.ts
git commit -m "feat(engine): self-hosted strict-verify LLM veto (demote-only, fail-open)

Opt-in SAHW_STRICT_VERIFY: on coarse-invariant CONFIRMEDs, an LLM semantic
auditor (operator's own SAHW_JUDGE_MODEL) demotes to NEEDS_REVIEW only on a
confident not-genuine verdict. Never FALSE_POSITIVE, never upgrades, fails
open. No jev/hosted dependency.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BxCkVb1dRUVjPsmR9vJ88e"
```

---

## Self-Review

**Spec coverage:** Layer 1 deterministic guards (rate_limit 2xx, static-asset) → Task 1. Layer 2 self-hosted LLM veto, coarse-invariant scope, demote-only, fail-open, config → Task 2. The "no TP lost" guarantee → both tasks demote only to NEEDS_REVIEW, asserted in tests (Task 1 "never yields FALSE_POSITIVE"; Task 2 demote-only). Human-review backstop (Layer 3) is the existing NEEDS_REVIEW tier — no code. Symmetry with adjudicator preserved (guard runs after, veto only demotes). ✓

**Placeholder scan:** none — every step has real code and a run command.

**Type consistency:** `guardConfirmedVerdict(vulnClass, status, exploit) → {status, reason?}` defined in Task 1, used in Task 1 beat.ts wiring. `verifyGenuineFinding(opts) → {isGenuine, confidence, rationale, model, ok}` defined in Task 2 judge.ts, used in Task 2 beat.ts. `COARSE_INVARIANTS`, `engagement.strictVerify`, `strictVerifyThreshold` consistent across Task 2. `finalStatus`/`finalReason` (Task 1) → `vStatus`/`vReason` (Task 2) chain is explicit.

**Review Focus:** rate_limit 4xx-not-just-5xx → Task 1 test (loops 403/401). Sensitive non-asset not demoted → Task 1 test (.env/.sql/.git). Adjudicator re-promotion → Task 1 guard runs after adjudication + test on CONFIRMED_BY_ADJUDICATION. Veto fail-open on error/no-model → Task 2 tests. Veto keeps genuine/uncertain CONFIRMED + never FALSE_POSITIVE → Task 2 tests.

## Execution note

After both tasks land green, redeploy the engine to the runner and re-run the demo.safeone.io scan with `SAHW_STRICT_VERIFY=1`: the rate_limit-502 and static-asset findings should drop to NEEDS_REVIEW, genuine findings (e.g. CORS/tenants if real) unaffected. Then proceed to the authenticated Cognito scan.
