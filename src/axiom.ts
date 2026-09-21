/**
 * Axiom — the deterministic validation core ("AI Hacker Axiom").
 *
 * Decides whether a result counts as a finding by replaying the finding's
 * invariant against verbatim evidence. Pure deterministic code. A configurable
 * judge model is used only for fuzzy calls (severity band), never to decide the
 * invariant. Below the confidence threshold the verdict is NEEDS_REVIEW, handed
 * to the adjudicator (or a human). (jev is not ingested into the framework.)
 */

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

  constructor(opts: { confidenceThreshold?: number } = {}) {
    this.confidenceThreshold = opts.confidenceThreshold ?? 0.75;
  }

  verify(input: AxiomInput): AxiomVerdict {
    const r = replay(input.invariant, input.evidence);

    if (r.confidence < this.confidenceThreshold) {
      return {
        status: "NEEDS_REVIEW",
        decided_by: "adjudicator_escalation",
        invariant_violated: r.violated,
        confidence: r.confidence,
        reason: `${r.reason} (below confidence threshold ${this.confidenceThreshold})`,
      };
    }

    if (r.violated) {
      return {
        status: "CONFIRMED",
        decided_by: "axiom_deterministic",
        invariant_violated: true,
        confidence: r.confidence,
        reason: r.reason,
      };
    }

    return {
      status: "FALSE_POSITIVE",
      decided_by: "axiom_deterministic",
      invariant_violated: false,
      confidence: r.confidence,
      reason: r.reason,
    };
  }
}
