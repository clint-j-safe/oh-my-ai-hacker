import type { Engagement } from "./config.js";

export type Decision = { allow: true } | { allow: false; reason: string };

const deny = (reason: string): Decision => ({ allow: false, reason });
const ALLOW: Decision = { allow: true };

// SECURITY MODEL: the destructive denylist below is DEFENCE IN DEPTH, not containment.
// A regex denylist over shell strings is inherently incomplete. Real containment is the
// ephemeral sandbox plus the scope allowlist — and note the allowlist is robust in a way
// this denylist is not, because inScope() PARSES URLs with the URL constructor rather than
// pattern-matching text. This check guards against a confused model proposing something
// destructive; it is not a boundary against a determined adversary.
const DESTRUCTIVE = [
  /\brm\s+-[a-z]*[rf]/i,
  // Long-form rm flags (--recursive, --force, --no-preserve-root), possibly with other
  // tokens/flags between "rm" and the dangerous long flag.
  /\brm\s+(?:\S+\s+)*(?:--recursive|--force|--no-preserve-root)\b/i,
  /\bdd\s+if=/i, /\bmkfs(\.\w+)?\b/i, /\bshutdown\b/i,
  /\breboot\b/i, /\bhalt\b/i, /\bmkswap\b/i, /\bfdisk\b/i, /:\s*\(\s*\)\s*\{.*\|\s*:\s*&/,
  /\bchmod\s+-R\s+777\s+\//, /\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b/i,
  /\bnc\b.*\s-e\b/i, /\bcrontab\b/i, /\bsystemctl\s+(stop|disable)\b/i,
  /\b(useradd|adduser|passwd)\b/i, /\bauthorized_keys\b/i,
  // eval hides indirection (e.g. `X=$(curl ...); eval "$X"`) from the curl|sh pattern above.
  /\beval\b/i,
  // IFS substitution (${IFS} / $IFS) is a classic whitespace-filter bypass; there is no
  // legitimate use of it in a probe command, so its presence alone is the signal.
  /\$\{?IFS\}?/i,
];

// The payload library is reachable through tools, never through a shell command — so any
// shell command that so much as names the raw/normalized directories is wrong, regardless
// of the verb around it (a "cd into it, then read with a relative path" trick defeats a
// verb-adjacent-to-path check; naming the path at all does not) (spec 9.4).
const BULK_LIBRARY_READ = /\/opt\/payload-library\/(raw|normalized)\b/i;

function hostPort(u: URL): string {
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  return `${u.protocol}//${u.hostname}:${port}`;
}

export function inScope(e: Engagement, url: string): Decision {
  let u: URL;
  try { u = new URL(url); } catch { return deny(`not a URL: ${url}`); }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return deny(`scheme not permitted: ${u.protocol}`);
  }
  for (const out of e.outOfScope) {
    if (hostPort(u) === hostPort(out) && u.pathname.startsWith(out.pathname)) {
      return deny(`explicitly out of scope: ${url}`);
    }
  }
  const origins = new Set(e.scope.map(hostPort));
  if (!origins.has(hostPort(u))) {
    return deny(`host:port not in SAHW_SCOPE: ${hostPort(u)}`);
  }
  return ALLOW;
}

export function checkCommand(cmd: string): Decision {
  if (typeof cmd !== "string" || !cmd.trim()) return deny("empty command");
  for (const p of DESTRUCTIVE) {
    if (p.test(cmd)) return deny(`destructive pattern ${p} in: ${cmd}`);
  }
  if (BULK_LIBRARY_READ.test(cmd)) {
    return deny("shell command references the payload library; use the payload tools instead");
  }
  return ALLOW;
}

const KNOWN_TOOLS = new Set([
  "http_request", "read_artifact", "grep_artifact", "glob_artifact",
  "write_file", "shell_exec",
]);

export function gate(e: Engagement, tool: string, args: Record<string, unknown>): Decision {
  if (!KNOWN_TOOLS.has(tool)) return deny(`unknown tool: ${tool}`);
  if (tool === "http_request") {
    return inScope(e, String(args.url ?? ""));
  }
  if (tool === "shell_exec") {
    const cmdCheck = checkCommand(String(args.command ?? ""));
    if (!cmdCheck.allow) return cmdCheck;
    const urlsInCmd = String(args.command ?? "").match(/https?:\/\/[^\s'"]+/g) ?? [];
    for (const u of urlsInCmd) {
      const d = inScope(e, u);
      if (!d.allow) return d;
    }
    return ALLOW;
  }
  return ALLOW;
}
