import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { ArtifactStore } from "./artifact-store.js";

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const KNOWN = sha256("root:x:0:0:root:/root:/bin/bash\n");

let root: string;
let store: ArtifactStore;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "sahw-store-"));
  store = new ArtifactStore({ root, sandboxId: "sandbox-1" });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("ArtifactStore.put", () => {
  it("stores content addressed by its SHA-256 and returns the digest + path", () => {
    const content = "root:x:0:0:root:/root:/bin/bash\n";
    const artifact = store.put(content, { purpose: "F1 traversal", cmd: "curl -s 'http://x/api/show?file=etc/passwd'", rc: 0 });

    expect(artifact.sha256).toBe(KNOWN);
    expect(artifact.path).toBe(join(KNOWN.slice(0, 2), KNOWN.slice(2)));
    // file exists at <root>/artifacts/<path>
    expect(readFileSync(join(root, "artifacts", artifact.path), "utf8")).toBe(content);
  });

  it("accepts a Buffer", () => {
    const buf = Buffer.from("binary\x00payload");
    const artifact = store.put(buf, { purpose: "x", cmd: "x", rc: 0 });
    expect(artifact.sha256).toBe(sha256("binary\x00payload"));
    expect(store.get(artifact.sha256)?.toString("utf8")).toBe("binary\x00payload");
  });

  it("deduplicates identical content (same digest/path)", () => {
    const a = store.put("same", { purpose: "a", cmd: "a", rc: 0 });
    const b = store.put("same", { purpose: "b", cmd: "b", rc: 0 });
    expect(a.sha256).toBe(b.sha256);
    expect(a.path).toBe(b.path);
  });
});

describe("ArtifactStore provenance", () => {
  it("records an audit entry with utc, purpose, cmd, rc, and stdout sha256", () => {
    store.put("secret\n", { purpose: "F1 traversal", cmd: "curl -s http://x", rc: 0 });
    const entries = store.provenance();
    expect(entries).toHaveLength(1);
    const e = entries[0];
    expect(e.purpose).toBe("F1 traversal");
    expect(e.cmd).toBe("curl -s http://x");
    expect(e.rc).toBe(0);
    expect(e.stdoutSha256).toBe(sha256("secret\n"));
    expect(e.sandboxId).toBe("sandbox-1");
    expect(Date.parse(e.utc)).not.toBeNaN(); // valid ISO 8601 UTC
  });

  it("supports a command-only log entry (no captured stdout)", () => {
    store.log({ purpose: "P2 connectivity", cmd: "curl -sS -o /dev/null http://x/", rc: 0 });
    const entries = store.provenance();
    expect(entries).toHaveLength(1);
    expect(entries[0].stdoutSha256).toBe("");
  });
});

describe("ArtifactStore index", () => {
  it("emits a sha256sum-format index of all stored artifacts", () => {
    store.put("AAA", { purpose: "a", cmd: "a", rc: 0 });
    store.put("BBB", { purpose: "b", cmd: "b", rc: 0 });
    const index = store.index();
    const lines = index.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(new RegExp(`^${sha256("AAA")}  ${sha256("AAA").slice(0, 2)}/${sha256("AAA").slice(2)}$`));
  });

  it("persists the index file", () => {
    store.put("CCC", { purpose: "c", cmd: "c", rc: 0 });
    expect(existsSync(join(root, "artifact-index.txt"))).toBe(true);
  });
});
