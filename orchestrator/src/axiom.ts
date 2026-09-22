import type { HttpCapture } from "./tools.js";

export type InvariantType =
  | "body_contains" | "status_in" | "derived"
  | "state_changed" | "state_violated" | "file_created_then_deleted";

export interface Invariant {
  statement: string;
  type: InvariantType;
  expression: string;
}

export type VerdictStatus = "CONFIRMED" | "FALSE_POSITIVE" | "NEEDS_REVIEW" | "BLOCKED";

export interface Verdict {
  status: VerdictStatus;
  reason: string;
}

/**
 * The control-differential rule: a finding is real only when the exploit and a
 * benign control diverge exactly as the invariant predicts. Without a control we
 * cannot tell a genuine leak from a page that happens to contain the marker, so
 * the answer is NEEDS_REVIEW — never CONFIRMED.
 */
export function evaluate(
  inv: Invariant, exploit: HttpCapture, control: HttpCapture | null,
): Verdict {
  if (!inv.expression || !inv.expression.trim()) {
    return { status: "NEEDS_REVIEW", reason: "invariant expression is empty" };
  }
  if (control === null) {
    return { status: "NEEDS_REVIEW", reason: "no control request captured; cannot differentiate" };
  }

  switch (inv.type) {
    case "body_contains": {
      const marker = inv.expression;
      const inExploit = exploit.response.body.includes(marker);
      const inControl = control.response.body.includes(marker);
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
