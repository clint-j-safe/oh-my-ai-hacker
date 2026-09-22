/**
 * Skill library — the operator playbooks in `skills/` made available to the
 * agent at runtime. The index is injected into the system prompt so the model
 * knows what exists; full playbooks (and their runnable scripts) are pulled on
 * demand via the `read_skill` tool, keeping context small.
 */

import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

export interface SkillMeta {
  name: string;
  description: string;
}

/** Locate the skills directory (env override, else alongside cwd / dist). */
export function skillsDir(): string | null {
  const candidates = [
    process.env.SAHW_SKILLS_DIR,
    resolve(process.cwd(), "skills"),
    resolve(process.cwd(), "..", "skills"),
  ].filter(Boolean) as string[];
  for (const c of candidates) {
    try {
      if (existsSync(c) && statSync(c).isDirectory()) return c;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

/** Parse `name` + folded `description` out of the SKILL.md YAML frontmatter. */
function parseFrontmatter(md: string): { name?: string; description?: string } {
  const m = md.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return {};
  const fm = m[1] ?? "";
  const name = fm.match(/^name:\s*(.+)$/m)?.[1]?.trim();
  // description may be a plain scalar or a YAML folded block (`>-`)
  const folded = fm.match(/^description:\s*>[-+]?\s*\r?\n([\s\S]*?)(?=^\S|\Z)/m);
  let description: string | undefined;
  if (folded?.[1]) {
    description = folded[1].split(/\r?\n/).map((l) => l.trim()).filter(Boolean).join(" ");
  } else {
    description = fm.match(/^description:\s*(.+)$/m)?.[1]?.trim();
  }
  return { name, description };
}

export function listSkills(): SkillMeta[] {
  const dir = skillsDir();
  if (!dir) return [];
  const out: SkillMeta[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const md = join(dir, entry.name, "SKILL.md");
    if (!existsSync(md)) continue;
    try {
      const { description } = parseFrontmatter(readFileSync(md, "utf8"));
      out.push({ name: entry.name, description: (description ?? "").slice(0, 240) });
    } catch {
      /* skip unreadable skill */
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** Compact one-line-per-skill index for the system prompt. */
export function skillIndex(): string {
  const skills = listSkills();
  if (!skills.length) return "";
  return skills.map((s) => `- ${s.name}: ${s.description.slice(0, 120)}`).join("\n");
}

/** Full playbook plus the paths of any runnable scripts/references it ships. */
export function readSkill(name: string): string {
  const dir = skillsDir();
  if (!dir) return "ERROR: skills directory not found";
  const safe = name.replace(/[^a-zA-Z0-9._-]/g, "");
  const base = join(dir, safe);
  const md = join(base, "SKILL.md");
  if (!existsSync(md)) {
    return `ERROR: no such skill '${safe}'. Available: ${listSkills().map((s) => s.name).join(", ")}`;
  }
  let body = readFileSync(md, "utf8");
  if (body.length > 20_000) body = body.slice(0, 20_000) + "\n…(truncated)";
  const extras: string[] = [];
  for (const sub of ["scripts", "references"]) {
    const p = join(base, sub);
    if (!existsSync(p)) continue;
    try {
      const files = readdirSync(p).map((f) => join(p, f));
      if (files.length) extras.push(`${sub.toUpperCase()} (run/read these with run_command):\n${files.join("\n")}`);
    } catch {
      /* ignore */
    }
  }
  return [body, ...extras].join("\n\n");
}
