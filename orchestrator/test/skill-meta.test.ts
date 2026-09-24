import { test } from "node:test";
import assert from "node:assert/strict";
import { parseEgressHosts } from "../src/skill-meta.js";

test("parses a block-list metadata.egress-hosts", () => {
  const md = [
    "---",
    "name: demo",
    "metadata:",
    "  author: x",
    "  egress-hosts:",
    "    - api.osv.dev",
    "    - oast.example.net",
    "---",
    "# body",
  ].join("\n");
  assert.deepEqual(parseEgressHosts(md), ["api.osv.dev", "oast.example.net"]);
});

test("parses an inline flow-list metadata.egress-hosts", () => {
  const md = "---\nname: d\nmetadata:\n  egress-hosts: [a.example.com, b.example.com]\n---\nbody";
  assert.deepEqual(parseEgressHosts(md), ["a.example.com", "b.example.com"]);
});

test("returns null (fail-closed) when there is no frontmatter, no metadata, or no key", () => {
  assert.equal(parseEgressHosts("# just a body, no frontmatter"), null);
  assert.equal(parseEgressHosts("---\nname: d\n---\nbody"), null);
  assert.equal(parseEgressHosts("---\nname: d\nmetadata:\n  author: x\n---\nbody"), null);
  assert.equal(parseEgressHosts("---\nname: d\nmetadata:\n  egress-hosts:\n---\nbody"), null);
});
