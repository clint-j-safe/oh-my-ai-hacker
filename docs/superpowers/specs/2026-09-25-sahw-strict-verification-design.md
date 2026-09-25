# SAHW strict verification — deterministic guards + self-hosted LLM veto — design spec

Date: 2026-09-25
Status: Approved (design). Implementation via a separate plan (writing-plans).
Branch: feat/dns-vhost-recon.

## Context

A live run against `demo.safeone.io` exposed a precision failure: the Axiom deterministically
**CONFIRMED** a `rate_limit_absence` finding whose only evidence was a **502-vs-403** status
differential (a broken/legacy endpoint erroring under a burst — not proof that rate limiting is
absent). Root cause (jev 0.94 it's a real bug): the `status_in` invariant (`axiom.ts:154-163`)
confirms on a pure status membership+differential with **no semantic guard** — it never checks
that the status *means* what the class requires (for `rate_limit_absence`, a 2xx "the burst kept
succeeding"). No LLM was involved (verdict was the deterministic `CONFIRMED` tier, not
`CONFIRMED_BY_ADJUDICATION`); the LLM adjudicator only ever *promotes* `NEEDS_REVIEW`. The same
coarse-oracle problem produced static-asset noise (`forced_browsing`/`info_disclosure` firing on
public-by-design bundles).

The operator's requirement: **never ship a false positive as CONFIRMED, and never lose a true
positive.** Additional hard constraint: the framework must be **self-hostable** (prod runs on a
self-hosted SageMaker/OpenAI-compatible model, possibly air-gapped), so the verifier **cannot
depend on a hosted service** — in particular **not jev/TypeSafe** (used only as a design-time
tool, never a runtime dependency).

## The one hard guarantee

Perfect automated FP/TP separation is impossible (a precision/recall tradeoff). The design makes
exactly one **structural, model-independent guarantee**: the new verifier may only **demote a
`CONFIRMED` to `NEEDS_REVIEW`** (a human-review tier) — **never to `FALSE_POSITIVE`, never
dropped**. Therefore a true positive can, at worst, be routed to a human; it can **never be
lost**, regardless of any model's calibration or correctness (jev 0.93). False-positive
*reduction* is layered and best-effort; human review of `NEEDS_REVIEW` is the honest backstop
(jev 0.93 — no automated layer hard-guarantees zero FP).

## Design (three layers)

### Layer 1 — deterministic per-class semantic guards (primary, authoritative; no model) — jev 0.96
Encode, in the Axiom / claim-verification path, what each class's status and evidence must
*semantically* mean, so a mechanically-true-but-meaningless differential cannot confirm:
- **`rate_limit_absence`**: CONFIRMED only if the burst's observed status is **2xx success**
  (a 4xx/5xx cannot confirm absent rate limiting). This directly closes the 502 case.
- **`forced_browsing` / `info_disclosure`**: must not confirm on **public-by-design static
  assets** (JS/CSS bundles, `service-worker.js`, source maps) — require the reached resource to
  be a non-asset / carry a non-asset content signal, or exclude known static-asset paths and
  HTML SPA-fallback bodies from confirming.
These guards are pure, unit-tested, self-contained, and certain — the first and authoritative
line. They eliminate the *known* FP shapes with code, no LLM call.

### Layer 2 — self-hosted strict LLM veto (best-effort secondary net) — jev 0.88
Reuse the existing `judge.ts` + `SAHW_JUDGE_MODEL` infrastructure (the operator's **own** model
over the OpenAI-compatible endpoint — OpenRouter in `test`, self-hosted SageMaker in `prod`; **no
jev**). Extend it with a **demote** direction:
- Runs only on deterministic `CONFIRMED`s produced by the **coarse** invariants
  (`status_in`, `body_contains`, `response_asserted`) — the classes prone to semantic FPs.
  Strong-proof invariants (`state_changed`, `derived`, `file_created_then_deleted`) **skip it**
  (already sound; verifying them wastes tokens and risks demoting solid findings) — jev 0.87.
- Asks a structured question: *"Given this exploit response vs the benign control, is this a
  GENUINE `<vuln_class>` vulnerability — not a server error, not a public-by-design asset, not a
  benign default?"* Returns `{ is_genuine: bool, confidence: 0..1, rationale: string }`.
- **Demotes to `NEEDS_REVIEW` only when confidently NOT genuine** (low `is_genuine` AND high
  confidence, threshold configurable, biased toward keeping — jev 0.93). Otherwise the
  `CONFIRMED` stands. It can **never** demote to `FALSE_POSITIVE` and **never** fabricate or
  upgrade a verdict.
- **Fails open** (jev 0.93): if `SAHW_JUDGE_MODEL` is unset or the call errors, the deterministic
  verdict stands unchanged. The veto is an optional enhancement, never a hard dependency or a
  blocker.
- Config: opt-in via a new `SAHW_STRICT_VERIFY` flag (or reuse `SAHW_JUDGE_MODEL` presence),
  `SAHW_STRICT_VERIFY_THRESHOLD` (default conservative). Carries its own provenance (the judge
  score + rationale) on the demoted record, like the promotion path does.

### Layer 3 — human review backstop
`NEEDS_REVIEW` is the human tier. Demoted and genuinely-uncertain findings land here. This is the
only complete answer to "zero FP shipped as CONFIRMED" — and it is where a demoted true positive
is recovered.

## Symmetry with the existing adjudicator

The engine already has an LLM adjudicator that can only **promote** `NEEDS_REVIEW` →
`CONFIRMED_BY_ADJUDICATION` (never inventing a deterministic `CONFIRMED`). This spec adds the
conservative mirror: a veto that can only **demote** a coarse-invariant `CONFIRMED` →
`NEEDS_REVIEW`. Both keep the design principle intact — **"LLM proposes; deterministic code
decides"**: deterministic guards are authoritative; the LLM is a conservative safety veto that
can only ever move a verdict toward *more* human scrutiny, never toward a fabricated pass or a
silent drop.

## Verdict pipeline (after)

```
hunter claim -> Axiom.evaluate (deterministic)
   -> NEEDS_REVIEW  -> [existing] LLM adjudicator may PROMOTE -> CONFIRMED_BY_ADJUDICATION
   -> CONFIRMED (coarse invariant) -> [NEW] strict LLM veto may DEMOTE -> NEEDS_REVIEW
   -> CONFIRMED (strong-proof invariant) -> unchanged
   -> FALSE_POSITIVE / BLOCKED -> unchanged
```

## Non-goals / honest limits

- No automated layer hard-guarantees zero false positives; do not claim one. The guarantee is
  "no true positive lost." FP reduction = deterministic guards (certain, known classes) +
  self-hosted LLM veto (best-effort) + human review.
- The LLM veto's quality depends on the operator's model; fail-open means a weak/absent model
  degrades gracefully to today's deterministic behavior (never worse, never blocking).
- No new hosted/runtime dependency (no jev/TypeSafe in the framework).

## Critical files

- `orchestrator/src/axiom.ts` — Layer-1 guards. The `status_in` evaluator gains a class-aware
  success-status guard path (or the guard is applied at the claim-verification site in
  `beat.ts`); the `forced_browsing`/`info_disclosure` confirmation excludes static-asset/SPA-HTML
  responses.
- `orchestrator/src/beat.ts` — the verdict pipeline: where deterministic verdicts are finalized
  and the existing adjudicator runs (`~2995-3040`); add the demote-veto step for coarse-invariant
  CONFIRMEDs; the class→invariant map (`RATE_LIMIT_CLASSES`, `~1276-1288`) and a COARSE_INVARIANTS
  set.
- `orchestrator/src/judge.ts` — reuse/extend for the demote question (structured
  `{is_genuine,confidence,rationale}`), fail-open, self-hosted model via the existing client.
- `orchestrator/src/config.ts` — `SAHW_STRICT_VERIFY` / `SAHW_STRICT_VERIFY_THRESHOLD`.
- Tests: `orchestrator/test/axiom*.test.ts` (guards: rate-limit-needs-2xx, static-asset
  non-firing), `test/strict-verify.test.ts` (veto: confident-not-genuine → demote to
  NEEDS_REVIEW; uncertain/genuine → CONFIRMED stands; no-model → fail-open; **veto can never
  yield FALSE_POSITIVE** — the TP-preservation invariant).

## Verification

- Unit: the deterministic guards reject the exact demo.safeone.io FP shapes (502 rate-limit,
  static-asset forced_browsing) and still confirm valid cases (2xx burst; a real non-asset
  disclosure).
- Unit: with a mocked judge, a coarse-invariant CONFIRMED demotes to NEEDS_REVIEW on a confident
  not-genuine verdict, stands otherwise, and fails open when the judge is absent/errors; assert
  no path yields FALSE_POSITIVE from the veto.
- Regression: default (`SAHW_STRICT_VERIFY` off / no judge) leaves the verdict pipeline
  byte-identical to today; full engine suite stays green (the Docker build gate).
- End-to-end: re-run the demo.safeone.io scan — the rate_limit_absence 502 no longer confirms;
  the static-asset findings drop out or move to NEEDS_REVIEW; the CORS/tenants and any genuine
  findings are unaffected.
