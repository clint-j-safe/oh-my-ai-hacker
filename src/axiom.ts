/**
 * Axiom — the validation core ("AI Hacker Axiom").
 *
 * Deterministic invariant replay runs first (fast, exact). For anything that
 * is not a clean deterministic CONFIRMED, an autonomous LLM judge re-evaluates
 * the verbatim exploit/control evidence. Strict false-positive elimination:
 * a deterministic no-differential veto can never be overridden, the judge's
 * CONFIRMED requires confidence >= judgeThreshold, and ambiguity falls to
 * NEEDS_REVIEW. (jev is not ingested into the framework.)
 */

import type { Judge } from "./judge.js";

export type InvariantType =
  | "body_contains"
  | "status_in"
  | "derived"
  | "state_changed"
  | "state_violated"
  | "file_created_then_deleted";

export interface Invariant {
  statement: string;
  type: InvariantType;
  expression?: string; // body_contains/state_violated: substring; status_in: "200,302"; derived: expected; state_changed: "increased"|"decreased"|"changed"
}

export interface Evidence {
  exploit_response_excerpt?: string;
  control_response_excerpt?: string;
  status?: number;
  before?: string | number;
  after?: string | number;
  derived_value?: string;
  file_created?: boolean;
  file_deleted?: boolean;
  evidence_files?: string[];
}

export interface AxiomInput {
  invariant: Invariant;
  evidence: Evidence;
}

export type VerdictStatus = "CONFIRMED" | "FALSE_POSITIVE" | "NEEDS_REVIEW" | "BLOCKED";
export type DecidedBy = "axiom_deterministic" | "axiom_open_model" | "adjudicator_escalation" | "human";

export interface AxiomVerdict {
  status: VerdictStatus;
  decided_by: DecidedBy;
  invariant_violated: boolean;
  confidence: number; // 0..1
  reason: string;
}

interface Replay {
  violated: boolean;
  confidence: number;
  reason: string;
}

const HIGH = 0.95;
const SOLID = 0.9;
const LOW = 0.4;

function bodyContains(expr: string | undefined, evidence: Evidence): Replay {
  if (!expr) return { violated: false, confidence: LOW, reason: "body_contains invariant missing expression" };
  const exploit = evidence.exploit_response_excerpt ?? "";
  const control = evidence.control_response_excerpt;
  const inExploit = exploit.includes(expr);
  if (!inExploit) {
    return { violated: false, confidence: SOLID, reason: `marker not found in exploit response` };
  }
  if (control !== undefined && control.includes(expr)) {
    return { violated: false, confidence: HIGH, reason: "marker present in control too — no differential, false positive" };
  }
  return { violated: true, confidence: HIGH, reason: "marker present in exploit response, absent from control" };
}

function statusIn(expr: string | undefined, evidence: Evidence): Replay {
  const set = (expr ?? "").split(",").map((s) => Number(s.trim())).filter(Number.isFinite);
  if (set.length === 0) return { violated: false, confidence: LOW, reason: "status_in invariant missing expected statuses" };
  if (evidence.status === undefined) return { violated: false, confidence: LOW, reason: "no status in evidence" };
  const match = set.includes(evidence.status);
  return match
    ? { violated: true, confidence: SOLID, reason: `status ${evidence.status} in expected set` }
    : { violated: false, confidence: SOLID, reason: `status ${evidence.status} not in expected set` };
}

function derived(expr: string | undefined, evidence: Evidence): Replay {
  if (expr === undefined) return { violated: false, confidence: LOW, reason: "derived invariant missing expected value" };
  if (evidence.derived_value === undefined) return { violated: false, confidence: LOW, reason: "no derived value in evidence" };
  return evidence.derived_value === expr
    ? { violated: true, confidence: HIGH, reason: "derived value matches expected secret" }
    : { violated: false, confidence: SOLID, reason: "derived value does not match expected" };
}

function toNumber(v: string | number | undefined): number | null {
  if (v === undefined) return null;
  const n = typeof v === "number" ? v : Number(String(v).trim());
  return Number.isFinite(n) ? n : null;
}

function stateChanged(expr: string | undefined, evidence: Evidence): Replay {
  const before = evidence.before;
  const after = evidence.after;
  if (before === undefined || after === undefined) {
    return { violated: false, confidence: LOW, reason: "state_changed requires before and after" };
  }
  const dir = expr ?? "changed";
  const a = toNumber(after);
  const b = toNumber(before);
  if (a !== null && b !== null) {
    if (dir === "increased") return a > b
      ? { violated: true, confidence: SOLID, reason: `state increased ${b} -> ${a}` }
      : { violated: false, confidence: SOLID, reason: `state did not increase ${b} -> ${a}` };
    if (dir === "decreased") return a < b
      ? { violated: true, confidence: SOLID, reason: `state decreased ${b} -> ${a}` }
      : { violated: false, confidence: SOLID, reason: `state did not decrease ${b} -> ${a}` };
  }
  const changed = String(before) !== String(after);
  return changed
    ? { violated: true, confidence: SOLID, reason: "state changed" }
    : { violated: false, confidence: SOLID, reason: "state unchanged" };
}

function fileCreatedThenDeleted(evidence: Evidence): Replay {
  if (evidence.file_created === true && evidence.file_deleted === true) {
    return { violated: true, confidence: SOLID, reason: "file created and then verified deleted" };
  }
  if (evidence.file_created === true && evidence.file_deleted !== true) {
    return { violated: true, confidence: 0.6, reason: "file created but deletion not verified" };
  }
  return { violated: false, confidence: SOLID, reason: "no file creation observed" };
}

function replay(invariant: Invariant, evidence: Evidence): Replay {
  switch (invariant.type) {
    case "body_contains":
    case "state_violated":
      return bodyContains(invariant.expression, evidence);
    case "status_in":
      return statusIn(invariant.expression, evidence);
    case "derived":
      return derived(invariant.expression, evidence);
    case "state_changed":
      return stateChanged(invariant.expression, evidence);
    case "file_created_then_deleted":
      return fileCreatedThenDeleted(evidence);
    default:
      return { violated: false, confidence: LOW, reason: `unknown invariant type ${(invariant as Invariant).type}` };
  }
}

export class Axiom {
  readonly confidenceThreshold: number;
  readonly judgeThreshold: number;
  private readonly judge?: Judge;

  constructor(opts: { confidenceThreshold?: number; judgeThreshold?: number; judge?: Judge } = {}) {
    this.confidenceThreshold = opts.confidenceThreshold ?? 0.75;
    this.judgeThreshold = opts.judgeThreshold ?? 0.8;
    this.judge = opts.judge;
  }

  async verify(input: AxiomInput): Promise<AxiomVerdict> {
    const r = replay(input.invariant, input.evidence);

    // Hard deterministic false-positive veto (cannot be overridden): the
    // marker appears in BOTH exploit and control — no differential.
    if (r.reason.startsWith("marker present in control too")) {
      return {
        status: "FALSE_POSITIVE",
        decided_by: "axiom_deterministic",
        invariant_violated: false,
        confidence: r.confidence,
        reason: r.reason,
      };
    }

    // Clean deterministic CONFIRMED (fast path, no judge needed).
    if (r.violated && r.confidence >= this.confidenceThreshold) {
      return {
        status: "CONFIRMED",
        decided_by: "axiom_deterministic",
        invariant_violated: true,
        confidence: r.confidence,
        reason: r.reason,
      };
    }

    // Autonomous judge path — re-evaluates prose/ambiguous evidence.
    if (this.judge) {
      let j: Awaited<ReturnType<Judge["judge"]>>;
      try {
        j = await this.judge.judge(input);
      } catch (e) {
        // A judge outage must not discard the finding (or the whole run).
        return {
          status: "NEEDS_REVIEW",
          decided_by: "adjudicator_escalation",
          invariant_violated: r.violated,
          confidence: 0.5,
          reason: `judge unavailable (${(e as Error).message.slice(0, 160)}); finding left for human review`,
        };
      }
      if (j.verdict === "CONFIRMED" && j.confidence >= this.judgeThreshold) {
        return {
          status: "CONFIRMED",
          decided_by: "axiom_open_model",
          invariant_violated: true,
          confidence: j.confidence,
          reason: j.reasoning,
        };
      }
      if (j.verdict === "FALSE_POSITIVE") {
        return {
          status: "FALSE_POSITIVE",
          decided_by: "axiom_open_model",
          invariant_violated: false,
          confidence: j.confidence,
          reason: j.reasoning,
        };
      }
      return {
        status: "NEEDS_REVIEW",
        decided_by: "adjudicator_escalation",
        invariant_violated: j.invariant_violated,
        confidence: j.confidence,
        reason: j.reasoning || "judge uncertain",
      };
    }

    // Deterministic-only fallback.
    if (r.confidence >= this.confidenceThreshold && !r.violated) {
      return {
        status: "FALSE_POSITIVE",
        decided_by: "axiom_deterministic",
        invariant_violated: false,
        confidence: r.confidence,
        reason: r.reason,
      };
    }
    return {
      status: "NEEDS_REVIEW",
      decided_by: "adjudicator_escalation",
      invariant_violated: r.violated,
      confidence: r.confidence,
      reason: `${r.reason} (below confidence threshold ${this.confidenceThreshold})`,
    };
  }
}
