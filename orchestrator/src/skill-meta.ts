import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Reads a skill's DECLARED egress hosts from its SKILL.md frontmatter
 * (`metadata.egress-hosts`). This is the per-host declared-egress mechanism the Tether's
 * gate() uses (see tether.ts): when a skill declares its hosts, the gate additionally
 * requires every URL the caller hands the skill to resolve to one of them (on top of the
 * always-applied in-scope check) — defence in depth for the widened deep-mode allowlist.
 *
 * SECURITY: this is on the authorization path, so the parser is deliberately tiny and
 * hand-rolled (no YAML dependency to audit) and FAIL-CLOSED — any parse failure, missing
 * file, missing frontmatter, or missing key returns `null`, which the gate reads as "no
 * declaration" (it then falls back to the in-scope-only check; it never treats a parse
 * error as an empty allow-nothing that would wedge a legitimately-allowlisted skill).
 *
 * Returns:
 *   string[]  the declared hosts (host or host:port tokens), when present and non-empty
 *   null      no SKILL.md, no frontmatter, no metadata.egress-hosts, or a parse problem
 */
export function parseEgressHosts(skillMarkdown: string): string[] | null {
  // Frontmatter is a leading `---` ... `---` block.
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(skillMarkdown);
  if (!m) return null;
  const fm = m[1];
  const lines = fm.split(/\r?\n/);

  // Find `metadata:` then the nested `egress-hosts:` key. We only need this one key, so
  // we track indentation shallowly rather than parsing the whole YAML tree.
  let inMetadata = false;
  let metadataIndent = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;

    if (!inMetadata) {
      if (/^metadata\s*:/.test(line.trim()) && indent === 0) {
        inMetadata = true;
        metadataIndent = indent;
      }
      continue;
    }
    // Left the metadata block (dedented back to <= its own indent on a new top-level key).
    if (indent <= metadataIndent && line.trim() && !line.startsWith(" ")) break;

    const keyMatch = /^egress-hosts\s*:\s*(.*)$/.exec(line.trim());
    if (!keyMatch) continue;

    const rest = keyMatch[1].trim();
    // Inline flow list: egress-hosts: [a, b]  or  egress-hosts: a, b
    if (rest) {
      const inner = rest.replace(/^\[/, "").replace(/\]$/, "");
      const hosts = inner.split(",").map((s) => cleanHost(s)).filter(Boolean);
      return hosts.length ? hosts : null;
    }
    // Block list: subsequent `  - host` lines, more-indented than the key.
    const hosts: string[] = [];
    const keyIndent = indent;
    for (let j = i + 1; j < lines.length; j++) {
      const l = lines[j];
      if (!l.trim()) continue;
      const li = l.length - l.trimStart().length;
      if (li <= keyIndent) break;
      const item = /^-\s*(.+)$/.exec(l.trim());
      if (!item) break;
      const h = cleanHost(item[1]);
      if (h) hosts.push(h);
    }
    return hosts.length ? hosts : null;
  }
  return null;
}

function cleanHost(s: string): string {
  return s.trim().replace(/^["']/, "").replace(/["']$/, "").trim();
}

const cache = new Map<string, string[] | null>();

/**
 * Reads and caches `metadata.egress-hosts` for a skill from
 * `<skillsRoot>/<skillName>/SKILL.md`. SKILL.md is immutable within a run, so the result
 * is cached per (skillsRoot, skillName). Fail-closed to `null` on any error.
 */
export function readSkillEgressHosts(skillsRoot: string, skillName: string): string[] | null {
  const key = `${skillsRoot}\u0000${skillName}`;
  const hit = cache.get(key);
  if (hit !== undefined) return hit;
  let hosts: string[] | null = null;
  try {
    const md = readFileSync(join(skillsRoot, skillName, "SKILL.md"), "utf8");
    hosts = parseEgressHosts(md);
  } catch {
    hosts = null;
  }
  cache.set(key, hosts);
  return hosts;
}

/** Test-only: clears the per-run cache. */
export function _clearEgressHostCache(): void {
  cache.clear();
}
