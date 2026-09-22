import type { Engagement } from "./config.js";

export type Decision = { allow: true } | { allow: false; reason: string };

const deny = (reason: string): Decision => ({ allow: false, reason });
const ALLOW: Decision = { allow: true };

// Builds "re|rec|recu|...|recursive" style alternatives: every prefix of `full` from
// `minLen` characters up to the whole word. GNU getopt_long accepts any unambiguous
// abbreviation of a long option (e.g. `--rec` for `--recursive`), so a check for the
// literal option name alone is not enough.
function longOptionAbbreviations(full: string, minLen: number): string[] {
  const out: string[] = [];
  for (let len = minLen; len <= full.length; len++) out.push(full.slice(0, len));
  return out;
}

const RM_LONG_FLAGS = [
  ...longOptionAbbreviations("recursive", 2),
  ...longOptionAbbreviations("force", 2),
  ...longOptionAbbreviations("no-preserve-root", 6),
].join("|");

// SECURITY MODEL:
// - inScope() is STRICT. Scope is authorization, not a heuristic — out-of-scope means
//   unauthorized, full stop. Host:port comparison is robust because both sides are parsed
//   and normalised by the URL constructor (see hostPort() below); path-based out-of-scope
//   entries needed the explicit percent-decode (multiple levels, to catch double encoding)
//   and segment-boundary matching below, because the URL constructor does not decode
//   percent-escapes in .pathname on its own.
// - checkCommand() below is a MODERATE GUARDRAIL, not containment. A regex denylist over
//   shell strings is inherently incomplete, and this project has deliberately stopped
//   trying to make it exhaustive: an autonomous system that chases every evasion technique
//   on a text denylist becomes brittle, not safer. This check exists to stop a confused
//   model from proposing something obviously destructive — it is not a boundary against a
//   determined adversary. Real containment is the ephemeral sandbox (no route to internal
//   networks, no orchestrator credentials) plus the scope allowlist above; genuinely
//   ambiguous commands are meant to escalate to a judge model per the architecture, rather
//   than be caught here.
const DESTRUCTIVE = [
  /\brm\s+-[a-z]*[rf]/i,
  // Long-form / abbreviated-long-form rm flags (--recursive.../--force.../
  // --no-preserve-root...), possibly with other tokens/flags before the dangerous one.
  new RegExp(`\\brm\\s+(?:\\S+\\s+)*--(?:${RM_LONG_FLAGS})\\b`, "i"),
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
// verb-adjacent-to-path check; naming the path at all does not). The lookahead requires a
// "/", whitespace, or end-of-string right after the directory name so an unrelated sibling
// such as raw-notes/ does not false-match (spec 9.4).
const BULK_LIBRARY_READ = /\/opt\/payload-library\/(raw|normalized)(?=\/|\s|$)/i;

// Strips URL substrings before destructive-pattern matching. URLs are scope-checked
// separately — inScope() is called on every URL gate() finds in the command — so leaving
// them in here would let attacker-controlled query-string content masquerade as a
// destructive keyword (e.g. `?cmd=eval`) and falsely deny an ordinary probe. The match
// terminates at shell metacharacters (whitespace, ; | & quotes/backticks parens <> {}),
// not just whitespace, so a command CHAINED onto a URL with no space (e.g.
// `curl http://h/;rm -rf /`) is not swallowed into the stripped-away text along with the
// URL — removing text before a denylist runs can hide the very thing the denylist looks
// for.
function stripUrls(cmd: string): string {
  return cmd.replace(/https?:\/\/[^\s;|&'"`()<>{}]+/gi, " ");
}

// A second matching pass that collapses bash constructs which defeat a `\s+`-as-
// token-boundary assumption — IFS substitution and brace expansion — down to plain
// whitespace, so e.g. `{rm,-rf,/}` reads as `rm -rf /` to the patterns above.
// Deliberately does NOT touch `;`, `|`, or `&` (the pipe-to-shell pattern needs them
// literal) and does NOT strip quotes (stripping quotes would let
// `bash -c "rm -rf /"` slip through).
function collapseTokenSeparators(cmd: string): string {
  return cmd
    .replace(/\$\{?IFS\}?/gi, " ")
    .replace(/[{},\t\n]/g, " ")
    .replace(/ {2,}/g, " ");
}

function hostPort(u: URL): string {
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  return `${u.protocol}//${u.hostname}:${port}`;
}

function normalizeSlashes(path: string): string {
  return path.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
}

function stripTrailingSlash(path: string): string {
  return path === "/" ? "" : path.replace(/\/+$/, "");
}

// A request path "covers" (matches, or is nested under) an out-of-scope path only on a
// segment boundary — equal, or continuing past a "/" — never a bare prefix match, which
// would treat "/administrator" as covered by an out-of-scope "/admin". Both sides have
// trailing slashes stripped first, so an out-of-scope entry written as "/admin/" still
// matches a request to exactly "/admin" (and vice versa).
function pathCoveredBy(requestPath: string, outOfScopePath: string): boolean {
  const req = stripTrailingSlash(requestPath);
  const out = stripTrailingSlash(outOfScopePath);
  return req === out || req.startsWith(`${out}/`);
}

// Percent-decodes a path iteratively (bounded rounds) so multi-level encoding (e.g.
// %2569 -> %69 -> "i") cannot hide a match from the out-of-scope check; each level is also
// slash-normalised (backslashes -> "/", duplicate "/" collapsed) before being returned.
// Throws if any level contains malformed percent-encoding — callers must fail closed on
// that, because a path we cannot decode is a path we cannot reason about.
function decodePathLevels(rawPath: string, maxRounds = 3): string[] {
  const levels: string[] = [];
  let current = normalizeSlashes(rawPath);
  levels.push(current);
  for (let i = 0; i < maxRounds; i++) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      throw new Error(`malformed percent-encoding in path: ${rawPath}`);
    }
    decoded = normalizeSlashes(decoded);
    if (decoded === current) break;
    levels.push(decoded);
    current = decoded;
  }
  return levels;
}

export function inScope(e: Engagement, url: string): Decision {
  let u: URL;
  try { u = new URL(url); } catch { return deny(`not a URL: ${url}`); }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return deny(`scheme not permitted: ${u.protocol}`);
  }

  let pathLevels: string[];
  try {
    pathLevels = decodePathLevels(u.pathname);
  } catch {
    return deny(`path cannot be decoded — refusing to reason about it: ${url}`);
  }

  for (const out of e.outOfScope) {
    if (hostPort(u) !== hostPort(out)) continue;
    const outPath = normalizeSlashes(out.pathname);
    if (pathLevels.some((p) => pathCoveredBy(p, outPath))) {
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
  const withoutUrls = stripUrls(cmd);
  const collapsed = collapseTokenSeparators(withoutUrls);
  for (const p of DESTRUCTIVE) {
    if (p.test(withoutUrls) || p.test(collapsed)) {
      return deny(`destructive pattern ${p} in: ${cmd}`);
    }
  }
  if (BULK_LIBRARY_READ.test(withoutUrls) || BULK_LIBRARY_READ.test(collapsed)) {
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
