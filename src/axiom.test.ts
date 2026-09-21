import { describe, it, expect } from "vitest";
import { Axiom, type AxiomInput } from "./axiom.js";

const axiom = new Axiom();

describe("Axiom — body_contains", () => {
  it("CONFIRMS when the exploit response leaks the marker and the control does not", () => {
    const input: AxiomInput = {
      invariant: { statement: "file contents must not be returned", type: "body_contains", expression: "root:x:0:0" },
      evidence: {
        exploit_response_excerpt: "uid=0(root) gid=0(root)\nroot:x:0:0:root:/root:/bin/bash",
        control_response_excerpt: "File not found",
      },
    };
    const v = axiom.verify(input);
    expect(v.status).toBe("CONFIRMED");
    expect(v.invariant_violated).toBe(true);
    expect(v.decided_by).toBe("axiom_deterministic");
  });

  it("marks FALSE_POSITIVE when the marker is absent from the exploit response", () => {
    const v = axiom.verify({
      invariant: { statement: "file contents must not be returned", type: "body_contains", expression: "root:x:0:0" },
      evidence: { exploit_response_excerpt: "Error: file not found" },
    });
    expect(v.status).toBe("FALSE_POSITIVE");
    expect(v.invariant_violated).toBe(false);
  });

  it("marks FALSE_POSITIVE when both exploit and control contain the marker", () => {
    const v = axiom.verify({
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

describe("Axiom — status_in", () => {
  it("CONFIRMS a leaked debug page returning 200", () => {
    const v = axiom.verify({
      invariant: { statement: "debug page must not be served", type: "status_in", expression: "200" },
      evidence: { status: 200, exploit_response_excerpt: "phpinfo()" },
    });
    expect(v.status).toBe("CONFIRMED");
    expect(v.invariant_violated).toBe(true);
  });

  it("FALSE_POSITIVE when status is not in the expected set", () => {
    const v = axiom.verify({
      invariant: { statement: "debug page must not be served", type: "status_in", expression: "200" },
      evidence: { status: 404 },
    });
    expect(v.status).toBe("FALSE_POSITIVE");
  });
});

describe("Axiom — state_changed", () => {
  it("CONFIRMS a negative transfer that increases the sender balance", () => {
    const v = axiom.verify({
      invariant: { statement: "sender balance must not increase on a negative transfer", type: "state_changed", expression: "increased" },
      evidence: { before: "100.00", after: "150.00" },
    });
    expect(v.status).toBe("CONFIRMED");
    expect(v.invariant_violated).toBe(true);
  });

  it("FALSE_POSITIVE when the state did not change", () => {
    const v = axiom.verify({
      invariant: { statement: "sender balance must not increase", type: "state_changed", expression: "increased" },
      evidence: { before: "100.00", after: "100.00" },
    });
    expect(v.status).toBe("FALSE_POSITIVE");
  });
});

describe("Axiom — state_violated", () => {
  it("CONFIRMS a cross-user reset (OTP ref issued for A resets B)", () => {
    const v = axiom.verify({
      invariant: { statement: "an OTP ref for user A must not reset user B", type: "state_violated", expression: "Password Reset Successful" },
      evidence: { exploit_response_excerpt: "PSW004 Password Reset Successful (userid=BNK95153)" },
    });
    expect(v.status).toBe("CONFIRMED");
  });
});

describe("Axiom — derived", () => {
  it("CONFIRMS when the derived value matches the expected secret", () => {
    const v = axiom.verify({
      invariant: { statement: "OTP must not be recoverable", type: "derived", expression: "065207" },
      evidence: { derived_value: "065207" },
    });
    expect(v.status).toBe("CONFIRMED");
  });

  it("FALSE_POSITIVE when the derived value does not match", () => {
    const v = axiom.verify({
      invariant: { statement: "OTP must not be recoverable", type: "derived", expression: "065207" },
      evidence: { derived_value: "999999" },
    });
    expect(v.status).toBe("FALSE_POSITIVE");
  });
});

describe("Axiom — file_created_then_deleted", () => {
  it("CONFIRMS a self-deleting RCE proof", () => {
    const v = axiom.verify({
      invariant: { statement: "untrusted input must not create files", type: "file_created_then_deleted" },
      evidence: { file_created: true, file_deleted: true },
    });
    expect(v.status).toBe("CONFIRMED");
  });

  it("escalates when the file was created but not yet verified deleted", () => {
    const v = axiom.verify({
      invariant: { statement: "untrusted input must not create files", type: "file_created_then_deleted" },
      evidence: { file_created: true, file_deleted: false },
    });
    expect(v.status).toBe("NEEDS_REVIEW");
  });
});

describe("Axiom — confidence threshold", () => {
  it("respects a higher threshold (escalates low-confidence determinations)", () => {
    const strict = new Axiom({ confidenceThreshold: 0.98 });
    const v = strict.verify({
      invariant: { statement: "x", type: "body_contains", expression: "root:x:0:0" },
      evidence: { exploit_response_excerpt: "root:x:0:0" },
    });
    expect(v.status).toBe("NEEDS_REVIEW");
  });
});
