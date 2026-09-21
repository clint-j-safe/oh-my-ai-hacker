import { describe, it, expect } from "vitest";
import { parseScope } from "./scope.js";
import { createTether, type ToolAction } from "./tether.js";

const scope = parseScope({ inScopeUrls: ["http://139.59.15.10:3000", "http://139.59.15.10/api"] });
const tether = createTether({ scope, workspaceRoot: "/tmp/sahw-sandbox" });

function decide(a: ToolAction) {
  return tether.decide(a);
}

describe("Tether — scope enforcement", () => {
  it("allows a benign in-scope HTTP action", () => {
    expect(decide({ tool: "webfetch", url: "http://139.59.15.10:3000/login" }).decision).toBe("allow");
  });

  it("denies an out-of-scope host", () => {
    const r = decide({ tool: "webfetch", url: "http://203.0.113.7/" });
    expect(r.decision).toBe("deny");
    expect(r.reason).toMatch(/out.of.scope/i);
  });

  it("denies an out-of-scope URL embedded in a bash command", () => {
    const r = decide({ tool: "bash", command: "curl -s http://203.0.113.7/api/show" });
    expect(r.decision).toBe("deny");
    expect(r.reason).toMatch(/out.of.scope/i);
  });

  it("allows a bash curl to an in-scope URL", () => {
    expect(decide({ tool: "bash", command: "curl -s 'http://139.59.15.10:3000/api/show?file=x'" }).decision).toBe("allow");
  });
});

describe("Tether — DoS / destructive AST", () => {
  const destructive = [
    "rm -rf /",
    "rm -fr /var/www",
    "dd if=/dev/zero of=/dev/sda",
    "mkfs.ext4 /dev/sda1",
    "shutdown -h now",
    "reboot",
    "halt",
    "poweroff",
    ":(){ :|:& };:",
  ];

  it.each(destructive)("denies DoS/destructive command: %s", (cmd) => {
    const r = decide({ tool: "bash", command: cmd });
    expect(r.decision).toBe("deny");
  });

  it("allows persistence (authorized red-team): authorized_keys append", () => {
    expect(decide({ tool: "bash", command: "echo KEY >> ~/.ssh/authorized_keys" }).decision).toBe("allow");
  });

  it("allows persistence (authorized red-team): crontab", () => {
    expect(decide({ tool: "bash", command: "echo '* * * * * x' >> /etc/crontab" }).decision).toBe("allow");
  });

  it("allows piping a fetched script to shell (agent running its own PoC)", () => {
    expect(decide({ tool: "bash", command: "curl -s http://139.59.15.10:3000/x.sh | sh" }).decision).toBe("allow");
  });
});

describe("Tether — filesystem writes", () => {
  it("allows a write inside the sandbox root", () => {
    expect(decide({ tool: "write", path: "/tmp/sahw-sandbox/poc/run.sh" }).decision).toBe("allow");
  });

  it("denies a write outside the sandbox root", () => {
    const r = decide({ tool: "write", path: "/etc/init.d/backdoor" });
    expect(r.decision).toBe("deny");
    expect(r.reason).toMatch(/outside/i);
  });
});

describe("Tether — impact tiers", () => {
  it("allows a shell-tier (reverse shell) action by default (authorized red-team)", () => {
    const r = decide({ tool: "bash", command: "nc -lvnp 4444", impact: "shell" });
    expect(r.decision).toBe("allow");
  });

  it("still escalates shell-tier when the operator has NOT authorized it (restricted tether)", () => {
    const restricted = createTether({ scope, workspaceRoot: "/tmp/sahw-sandbox", authorizedTiers: ["read", "probe", "state_change"] });
    expect(restricted.decide({ tool: "bash", command: "nc -lvnp 4444", impact: "shell" }).decision).toBe("escalate");
  });

  it("denies destructive-tier actions outright (no DoS)", () => {
    const r = decide({ tool: "bash", command: "touch /tmp/x", impact: "destructive" });
    expect(r.decision).toBe("deny");
  });
});
