import { describe, it, expect } from "vitest";
import { Axiom, type AxiomInput, type AxiomVerdict } from "./axiom.js";
import type { Judge, JudgeVerdict } from "./judge.js";

const axiom = new Axiom();

function makeJudge(verdict: JudgeVerdict): Judge {
  return { judge: async () => verdict };
}

describe("Axiom — body_contains (deterministic)", () => {
  it("CONFIRMS when the exploit response leaks the marker and the control does not", async () => {
    const input: AxiomInput = {
      invariant: { statement: "file contents must not be returned", type: "body_contains", expression: "root:x:0:0" },
      evidence: {
        exploit_response_excerpt: "uid=0(root) gid=0(root)\nroot:x:0:0:root:/root:/bin/bash",
        control_response_excerpt: "File not found",
      },
    };
    const v = await axiom.verify(input);
    expect(v.status).toBe("CONFIRMED");
    expect(v.invariant_violated).toBe(true);
    expect(v.decided_by).toBe("axiom_deterministic");
  });

  it("marks FALSE_POSITIVE when the marker is absent from the exploit response", async () => {
    const v = await axiom.verify({
      invariant: { statement: "file contents must not be returned", type: "body_contains", expression: "root:x:0:0" },
      evidence: { exploit_response_excerpt: "Error: file not found" },
    });
    expect(v.status).toBe("FALSE_POSITIVE");
    expect(v.invariant_violated).toBe(false);
  });

  it("hard-vetoes FALSE_POSITIVE when both exploit and control contain the marker", async () => {
    const v = await axiom.verify({
      invariant: { statement: "file contents must not be returned", type: "body_contains", expression: "Welcome" },
      evidence: {
        exploit_response_excerpt: "Welcome to the app",
        control_response_excerpt: "Welcome to the app",
      },
    });
    expect(v.status).toBe("FALSE_POSITIVE");
    expect(v.invariant_violated).toBe(false);
  });
});

describe("Axiom — status_in / state_changed / state_violated / derived / file", () => {
  it("CONFIRMS a leaked debug page returning 200", async () => {
    const v = await axiom.verify({
      invariant: { statement: "debug page must not be served", type: "status_in", expression: "200" },
      evidence: { status: 200, exploit_response_excerpt: "phpinfo()" },
    });
    expect(v.status).toBe("CONFIRMED");
  });

  it("FALSE_POSITIVE when status is not in the expected set", async () => {
    const v = await axiom.verify({
      invariant: { statement: "debug page must not be served", type: "status_in", expression: "200" },
      evidence: { status: 404 },
    });
    expect(v.status).toBe("FALSE_POSITIVE");
  });

  it("CONFIRMS a negative transfer that increases the sender balance", async () => {
    const v = await axiom.verify({
      invariant: { statement: "sender balance must not increase on a negative transfer", type: "state_changed", expression: "increased" },
      evidence: { before: "100.00", after: "150.00" },
    });
    expect(v.status).toBe("CONFIRMED");
  });

  it("CONFIRMS a cross-user reset (state_violated)", async () => {
    const v = await axiom.verify({
      invariant: { statement: "an OTP ref for user A must not reset user B", type: "state_violated", expression: "Password Reset Successful" },
      evidence: { exploit_response_excerpt: "PSW004 Password Reset Successful (userid=BNK95153)" },
    });
    expect(v.status).toBe("CONFIRMED");
  });

  it("CONFIRMS a derived secret match", async () => {
    const v = await axiom.verify({
      invariant: { statement: "OTP must not be recoverable", type: "derived", expression: "065207" },
      evidence: { derived_value: "065207" },
    });
    expect(v.status).toBe("CONFIRMED");
  });

  it("CONFIRMS a self-deleting RCE proof", async () => {
    const v = await axiom.verify({
      invariant: { statement: "untrusted input must not create files", type: "file_created_then_deleted" },
      evidence: { file_created: true, file_deleted: true },
    });
    expect(v.status).toBe("CONFIRMED");
  });
});

describe("Axiom — autonomous judge (prose/ambiguous evidence)", () => {
  const proseFinding: AxiomInput = {
    invariant: { statement: "file param not canonicalized", type: "body_contains", expression: "body matches /root:x:0:0" },
    evidence: {
      exploit_response_excerpt: "HTTP 200: root:x:0:0:root:/root:/bin/ash",
      control_response_excerpt: "File not found",
    },
  };

  it("CONFIRMS via the judge when the deterministic marker is prose but the evidence is real", async () => {
    const j = makeJudge({ invariant_violated: true, verdict: "CONFIRMED", confidence: 0.92, reasoning: "passwd content in exploit, absent in control" });
    const a = new Axiom({ judge: j });
    const v = await a.verify(proseFinding);
    expect(v.status).toBe("CONFIRMED");
    expect(v.decided_by).toBe("axiom_open_model");
  });

  it("keeps FALSE_POSITIVE when the judge rejects it", async () => {
    const j = makeJudge({ invariant_violated: false, verdict: "FALSE_POSITIVE", confidence: 0.9, reasoning: "no real differential" });
    const a = new Axiom({ judge: j });
    const v = await a.verify(proseFinding);
    expect(v.status).toBe("FALSE_POSITIVE");
  });

  it("escalates to NEEDS_REVIEW when the judge is unsure", async () => {
    const j = makeJudge({ invariant_violated: true, verdict: "NEEDS_REVIEW", confidence: 0.5, reasoning: "control ambiguous" });
    const a = new Axiom({ judge: j });
    const v = await a.verify(proseFinding);
    expect(v.status).toBe("NEEDS_REVIEW");
  });

  it("never lets the judge override the deterministic no-differential veto", async () => {
    const j = makeJudge({ invariant_violated: true, verdict: "CONFIRMED", confidence: 0.99, reasoning: "confirmed" });
    const a = new Axiom({ judge: j });
    const v = await a.verify({
      invariant: { statement: "x", type: "body_contains", expression: "Welcome" },
      evidence: { exploit_response_excerpt: "Welcome", control_response_excerpt: "Welcome" },
    });
    expect(v.status).toBe("FALSE_POSITIVE");
    expect(v.decided_by).toBe("axiom_deterministic");
  });

  it("respects a higher judge threshold (low-confidence judge CONFIRMED -> NEEDS_REVIEW)", async () => {
    const j = makeJudge({ invariant_violated: true, verdict: "CONFIRMED", confidence: 0.85, reasoning: "ok" });
    const a = new Axiom({ judge: j, judgeThreshold: 0.95 });
    const v = await a.verify(proseFinding);
    expect(v.status).toBe("NEEDS_REVIEW");
  });
});

describe("Axiom — confidence threshold (deterministic, no judge)", () => {
  it("escalates low-confidence determinations", async () => {
    const strict = new Axiom({ confidenceThreshold: 0.98 });
    const v = await strict.verify({
      invariant: { statement: "x", type: "body_contains", expression: "root:x:0:0" },
      evidence: { exploit_response_excerpt: "root:x:0:0" },
    });
    expect(v.status).toBe("NEEDS_REVIEW");
  });
});
