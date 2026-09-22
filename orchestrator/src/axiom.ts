import type { HttpCapture } from "./tools.js";

export type InvariantType =
  | "body_contains" | "status_in" | "derived"
  | "state_changed" | "state_violated" | "file_created_then_deleted"
  | "response_asserted";

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

// Builds a canonical serialization of one side of an exchange (status line, then
// response headers sorted by name for determinism, then a blank line, then the
// body) so that body_contains — and anything else that scans "the response" for a
// marker — can see evidence that lives in a header, not just in the body. Header
// insertion order is not meaningful (it's a Record<string,string>, and the same
// logical exchange could be built with headers inserted in any order), so without
// sorting the same exchange could serialize two different ways and a test — or a
// real verdict — could flap depending on insertion order alone.
function serializeExchange(cap: HttpCapture): string {
  // Plain .sort() (UTF-16 code-unit order), deliberately NOT .localeCompare(): locale
  // collation depends on the runtime's default locale and ICU build (small-icu vs
  // full-icu, LANG), and it weighs punctuation like "-" differently from a plain
  // codepoint sort — which is exactly the kind of environment-dependent instability this
  // sort exists to rule out.
  const headerNames = Object.keys(cap.response.headers).sort();
  const headerLines = headerNames.map((name) => `${name}: ${cap.response.headers[name]}`);
  return [`HTTP ${cap.response.status}`, ...headerLines, "", cap.response.body].join("\n");
}

// Case-insensitive header lookup. tools.ts's http() populates response.headers from the
// WHATWG Headers API, which already lower-cases every key, but response_asserted's
// expression names come from the model/finding author and must not be assumed to match
// that casing.
function findHeaderValue(headers: Record<string, string>, lowerName: string): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lowerName) return v;
  }
  return undefined;
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

  // response_asserted is the ONE deliberate exception to the control-differential rule
  // above, and it is narrow on purpose: it exists only for claims about the server's own
  // configuration (a missing security header, a dangerous CORS combination), which are
  // self-evidencing — the response either has the property or it does not, and no
  // attacker input exists to vary in a control. It is NOT a general bypass: any claim of
  // the form "my input caused this behaviour" must still use a differential type
  // (body_contains, status_in, ...) so a page that merely happens to contain a marker
  // cannot be reported as a leak. That is also why there is no "!body:" or other
  // body-absence form here — body absence is exactly the case where skipping the control
  // would let a false positive through, so it deliberately has no expressible form.
  if (inv.type === "response_asserted") {
    return evaluateResponseAsserted(inv.expression, exploit);
  }

  if (control === null) {
    return { status: "NEEDS_REVIEW", reason: "no control request captured; cannot differentiate" };
  }

  switch (inv.type) {
    case "body_contains": {
      const marker = inv.expression;
      const exploitText = serializeExchange(exploit);
      const controlText = serializeExchange(control);
      const inExploit = exploitText.includes(marker);
      const inControl = controlText.includes(marker);
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

// Grammar for response_asserted, semicolon-separated clauses, ALL of which must hold for
// CONFIRMED:
//   header:name            -> that header is PRESENT (case-insensitive name)
//   !header:name           -> that header is ABSENT
//   header:name=substring  -> header present AND its value contains that substring
//                             (case-insensitive)
// Evaluates against a single response and returns FALSE_POSITIVE (never CONFIRMED) the
// moment any clause does not hold — this type is self-contained, not self-approving. Any
// clause that does not match one of the three forms above returns NEEDS_REVIEW naming that
// clause, rather than silently ignoring it or guessing what was meant.
function evaluateResponseAsserted(expression: string, exploit: HttpCapture): Verdict {
  const clauses = expression.split(";").map((c) => c.trim()).filter((c) => c.length > 0);
  if (clauses.length === 0) {
    // e.g. expression was ";" or "  ;  " — non-empty text but no actual clause to check.
    // Vacuously "confirming" nothing would be exactly the "assertion that cannot fail"
    // failure mode this project has already been burned by, so escalate instead.
    return { status: "NEEDS_REVIEW", reason: `response_asserted expression has no clauses: ${JSON.stringify(expression)}` };
  }

  for (const clause of clauses) {
    const negMatch = /^!header:([^=]+)$/i.exec(clause);
    const eqMatch = /^header:([^=]+)=(.*)$/i.exec(clause);
    const presMatch = /^header:([^=]+)$/i.exec(clause);

    if (negMatch) {
      const name = negMatch[1].trim().toLowerCase();
      const value = findHeaderValue(exploit.response.headers, name);
      if (value !== undefined) {
        return { status: "FALSE_POSITIVE", reason: `header ${name} is present but asserted absent (clause: ${clause})` };
      }
      continue;
    }

    if (eqMatch) {
      const name = eqMatch[1].trim().toLowerCase();
      const substring = eqMatch[2];
      const value = findHeaderValue(exploit.response.headers, name);
      if (value === undefined || !value.toLowerCase().includes(substring.toLowerCase())) {
        return {
          status: "FALSE_POSITIVE",
          reason: `header ${name} does not contain ${JSON.stringify(substring)} (clause: ${clause})`,
        };
      }
      continue;
    }

    if (presMatch) {
      const name = presMatch[1].trim().toLowerCase();
      const value = findHeaderValue(exploit.response.headers, name);
      if (value === undefined) {
        return { status: "FALSE_POSITIVE", reason: `header ${name} is absent but asserted present (clause: ${clause})` };
      }
      continue;
    }

    return { status: "NEEDS_REVIEW", reason: `unparseable response_asserted clause: ${JSON.stringify(clause)}` };
  }

  return { status: "CONFIRMED", reason: `all response_asserted clauses held: ${expression}` };
}
