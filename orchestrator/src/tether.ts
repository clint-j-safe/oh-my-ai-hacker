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
  "write_file", "shell_exec", "skill_run", "register_account",
  // submit_finding is a control-plane tool: it carries the hunter's claim to the
  // verifier and performs NO I/O of its own (no network, no filesystem, no state
  // change), so it is unconditionally allowed like read_artifact — the gate has no
  // network branch for it and falls through to ALLOW.
  "submit_finding",
]);

// --- skill_run egress classification -------------------------------------------------
//
// A skill runs `python3 scripts/run.py` as a plain OS process. http_request and
// shell_exec are gated because THIS module inspects the URL/command being asked for —
// but a skill's *script* can make its own outbound connections that this module never
// sees at all. Wiring a network-capable skill in as skill_run would therefore be an
// un-gated egress channel straight through the project's central security claim
// ("capability is the tools array; the Tether gates every action").
//
// So every skill is classified by what its OWN scripts/run.py actually does when
// invoked directly (not by what a *generated* exploit script it writes would later do,
// and not by trusting a skill's own SKILL.md prose uncritically — several SKILL.md
// files say "sends no traffic" about the ENGAGEMENT TARGET while the script still talks
// to an external reference service, e.g. osv-cve-correlation -> api.osv.dev):
//
//   "none"     - run.py performs pure computation over evidence already collected.
//                No import of a network-capable module (httpx, urllib.request, socket,
//                requests, ...), no subprocess call to a network tool (sqlmap, ghauri,
//                nuclei, interactsh-client, curl, playwright, ...), and no execution of
//                previously-generated, network-capable code.
//   "target"   - run.py itself contacts the engagement target directly (or executes/
//                subprocesses something that does, e.g. re-running a PoC script, or
//                shelling out to sqlmap/ghauri against the target URL), or delegates to
//                sub-agents that do (declared "indirect" in its own SKILL.md).
//   "external" - run.py itself contacts a reference service OTHER than the engagement
//                target (e.g. api.osv.dev). Still an egress channel the Tether cannot
//                see or gate; treated exactly like "target" for permission purposes.
//
// A skill with no entry here is UNKNOWN and is denied by gate() below, same as any of
// "target"/"external" — being unclassified is not a lesser risk than being classified
// network-touching.
//
// TODO(phase 2 - declared egress): replace the blanket "target"/"external" denial with
// a per-skill, per-host allowlist: a skill declares the exact hosts it needs in its
// SKILL.md metadata (e.g. `metadata.egress-hosts: ["api.osv.dev"]`), and the Tether
// permits ONLY those named hosts for that named skill — not a blanket grant to touch
// "the target" or "the network" at large. Until that per-host mechanism exists, no
// skill whose classification is anything other than "none" may run, regardless of how
// narrow its actual traffic really is.
export type SkillEgress = "none" | "target" | "external";

// Evidence for every entry below was gathered by reading each skill's SKILL.md
// (description + metadata block) AND scripts/run.py (imports, subprocess/exec calls),
// not by pattern-matching the skill's name. See the skill-run-report.md for the
// per-skill evidence trail this table was built from.
export const SKILL_EGRESS: Readonly<Record<string, SkillEgress>> = Object.freeze({
  // -- none: pure computation over already-collected evidence, verified network-free --
  "adversarial-self-review": "none",
  "blast-radius-estimation": "none",
  "chain-construction": "none",
  "cognitive-pruning": "none",
  "credential-secret-custody": "none",
  "exploit-request-generator": "none",   // writes a spec (text); no execution, no network call in run.py
  "exploit-safety-auditor": "none",      // static pattern scanner over script text; no execution
  "exploit-script-developer": "none",    // GENERATES a script that itself imports httpx, but run.py
                                          // never executes it -- see report for the exact line checked
  "exploit-sandbox-programming": "none", // GENERATES a script + expected-hash; run.py never runs it
  "payload-mutator": "none",
  "scope-discipline": "none",            // urllib.parse only, for parsing -- never urllib.request
  "severity-calibration": "none",
  "skill-planner": "none",
  "skill-variant-generator": "none",
  "stall-ambiguity-resolution": "none",
  "technique-combinator": "none",
  "token-session-forensics": "none",
  "payload-library": "none",   // pure file lookup over the shipped wordlists/payloads; no network

  // -- target: run.py itself (or a subprocess it drives) contacts the engagement target --
  "account-role-acquisition": "target",
  "api-graphql-specifics": "target",
  "auth-bypass-battery": "target",
  "business-logic-state": "target",
  "delegation-collaboration": "target",       // SKILL.md declares target-interaction: "indirect"
  "deserialization-rce": "target",
  "file-upload-path-traversal": "target",     // also polls an external OOB collaborator
  "idor-bola-access-control": "target",
  "injection-battery-xxe-ssti-nosql": "target", // also polls an external OOB collaborator
  "intelligent-crawling": "target",
  "js-spa-reverse": "target",
  "oob-blind-vuln-correlation": "target",     // also polls an external OOB collaborator
  "poc-hardening-self-verification": "target", // subprocess.run()s a PoC script against the target
  "privilege-matrix-mapping": "target",
  "sqli-database-injection": "target",        // subprocess execs sqlmap/ghauri against the target
  "ssrf-internal-pivot": "target",            // also polls an external OOB collaborator
  "tech-fingerprinting": "target",
  "waf-evasion-mastery": "target",
  "xss-dom-sinks": "target",

  // -- external: run.py itself contacts a reference service OTHER than the target --
  "osv-cve-correlation": "external",          // hard-pinned to api.osv.dev via urllib.request
});

// What a `tether` audit span records as its input.target: the thing whose
// authorization is being decided. http_request -> the URL; shell_exec -> the raw
// command string (never redacted here -- this IS the security record, and it never
// carries a response body, only the requested action); skill_run -> the skill name.
export function auditTarget(tool: string, args: Record<string, unknown>): string {
  if (tool === "http_request") return String(args.url ?? "");
  if (tool === "shell_exec") return String(args.command ?? "");
  if (tool === "skill_run") return String(args.skill_name ?? "");
  if (tool === "register_account") return String(args.signup_url ?? "");
  return "";
}

export function gate(
  e: Engagement,
  tool: string,
  args: Record<string, unknown>,
  // The calling agent's skill_run allowlist. Explicit parameter, not a global — see
  // the same rule applied to the skill_run tool-schema builder in tools.ts. Defaults to
  // "nothing" (fail closed): a caller that doesn't pass one gets every skill denied.
  skillAllowlist: readonly string[] = [],
  // The skill -> egress classification table. Defaults to the built-in registry above;
  // overridable so tests can register a fixture skill's classification without
  // mutating the production registry.
  skillEgress: Readonly<Record<string, SkillEgress>> = SKILL_EGRESS,
  // DECLARED per-host egress resolver (see skill-meta.ts). Returns a skill's declared
  // egress-hosts, or null when it declares none. Default resolves to null for every
  // skill → the historical in-scope-only gate is unchanged. When a skill DOES declare
  // hosts, every URL the caller hands it must resolve to one of them (defence in depth
  // on top of the in-scope check). This is additive: an undeclared skill is NOT denied.
  egressHosts: (skill: string) => readonly string[] | null = () => null,
): Decision {
  if (!KNOWN_TOOLS.has(tool)) return deny(`unknown tool: ${tool}`);
  if (tool === "http_request") {
    return inScope(e, String(args.url ?? ""));
  }
  if (tool === "register_account") {
    // Self-registration is TARGET-egress and state-changing (it creates an
    // account), so it is gated exactly like http_request — no exemption. BOTH
    // the signup endpoint and, when present, the login endpoint must be in
    // scope; a call naming an out-of-scope host for either is denied here,
    // before tools.ts's registerAccount() executor ever sends a signup request.
    const signupUrl = String(args.signup_url ?? "");
    const signupDecision = inScope(e, signupUrl);
    if (!signupDecision.allow) return signupDecision;
    const loginUrl = String(args.login_url ?? "").trim();
    if (loginUrl) {
      const loginDecision = inScope(e, loginUrl);
      if (!loginDecision.allow) return loginDecision;
    }
    return ALLOW;
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
  if (tool === "skill_run") {
    const skillName = String(args.skill_name ?? "");
    const egress = skillEgress[skillName];
    if (egress === undefined) {
      return deny(`unknown skill: ${JSON.stringify(skillName)}`);
    }
    if (!skillAllowlist.includes(skillName)) {
      return deny(
        `skill not on the caller's allowlist: ${JSON.stringify(skillName)} ` +
        `(allowed: ${skillAllowlist.length ? skillAllowlist.join(", ") : "none"})`);
    }
    // Egress model (declared-egress, pragmatic form). An allowlisted skill may run
    // regardless of its "none"/"target"/"external" classification — the controls are:
    //   (1) the ALLOWLIST — only skills the caller explicitly enabled run at all;
    //   (2) THIS scope check — every http(s) URL the caller puts in the skill's
    //       input_json is that skill's DECLARED target egress and must be in scope,
    //       gated exactly like http_request (same scan shell_exec already applies to
    //       its command); a skill named against an out-of-scope host is denied here,
    //       before it ever runs;
    //   (3) each skill's own internal scope-gating (SKILL.md safety model); and
    //   (4) the ephemeral sandbox — the real containment boundary (see the note at
    //       the top of this file). A skill driven purely by already-collected
    //       evidence carries no URL and passes (2) trivially.
    const inputUrls = String(args.input_json ?? "").match(/https?:\/\/[^\s"'\\]+/g) ?? [];
    for (const u of inputUrls) {
      const d = inScope(e, u);
      if (!d.allow) return d;
    }
    // Additive DECLARED-egress narrowing: if the skill declares egress-hosts, every URL
    // it is handed must resolve to one of them (they must ALSO be in scope, enforced
    // above). A skill that declares nothing is unaffected — the in-scope gate stands alone.
    const declared = egressHosts(skillName);
    if (declared && declared.length) {
      const allowedHosts = new Set(declared.map((h) => h.trim().toLowerCase()).filter(Boolean));
      for (const u of inputUrls) {
        let parsed: URL;
        try { parsed = new URL(u); } catch { return deny(`not a URL in skill input: ${u}`); }
        const host = parsed.hostname.toLowerCase();
        const hostPortTok = `${host}:${parsed.port || (parsed.protocol === "https:" ? "443" : "80")}`;
        if (!allowedHosts.has(host) && !allowedHosts.has(hostPortTok) && !allowedHosts.has(parsed.host.toLowerCase())) {
          return deny(
            `skill ${JSON.stringify(skillName)} may only egress to its declared hosts ` +
            `(${declared.join(", ")}); refusing ${host}`);
        }
      }
    }
    return ALLOW;
  }
  return ALLOW;
}
