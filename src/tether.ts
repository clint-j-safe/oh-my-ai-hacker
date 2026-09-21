/**
 * Tether — the deterministic scope + safety gate.
 *
 * This is the single enforcement point before any tool action runs. It is pure
 * deterministic code: a scope allowlist check, a destructive-command AST check,
 * a filesystem-write sandbox check, and impact-tier gating. A judge model is
 * consulted only for ambiguous escalation, never as the hard gate. (jev is not
 * ingested into the framework.)
 */

import { Scope } from "./scope.js";

export type ImpactTier = "read" | "probe" | "state_change" | "shell" | "destructive";
export type TetherDecision = "allow" | "deny" | "escalate";

export interface ToolAction {
  tool: string; // "bash" | "webfetch" | "write" | "edit" | "read" | string
  command?: string; // bash command string
  url?: string; // target URL for network tools
  path?: string; // filesystem path for write/edit
  impact?: ImpactTier; // declared impact tier
}

export interface TetherResult {
  decision: TetherDecision;
  reason: string;
  tier: ImpactTier;
}

export interface TetherOptions {
  scope: Scope;
  workspaceRoot: string;
  authorizedTiers?: ImpactTier[]; // tiers the operator has authorized (e.g. via Ed25519 token)
}

const DEFAULT_AUTHORIZED: ImpactTier[] = ["read", "probe", "state_change", "shell"];

const URL_RE = /https?:\/\/[^\s'"`;&|)]+/g;

/** Deny-list: DoS / destructive-to-availability only. Persistence, reverse/forward shells, and pivoting are authorized red-team actions (no DoS). */
const DESTRUCTIVE_RULES: { re: RegExp; label: string }[] = [
  { re: /\bdd\s+[^;&|]*\bof=\/dev\//, label: "dd write to block device" },
  { re: /\bmkfs\S*\s+\/dev\//, label: "mkfs on block device" },
  { re: /\bwipefs\b/, label: "wipefs" },
  { re: /(^|[;&|]\s*)(shutdown|reboot|halt|poweroff)(\s|$)/, label: "system shutdown/reboot" },
  { re: /:\s*\(\s*\)\s*\{/, label: "fork bomb" },
  { re: /(^|[;&|]\s*)iptables\s+-F\b/, label: "flush firewall (network DoS)" },
];

function destructiveRm(command: string, workspaceRoot: string): boolean {
  const re = /\brm\s+((?:-[a-zA-Z]+\s+)+)([^\s;&|]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(command)) !== null) {
    const flags = m[1];
    const target = m[2];
    if (!/[rf]/.test(flags)) continue; // not recursive/force — not destructive
    if (target === "/" || target === "/*" || target === "~" || target.startsWith("$HOME")) {
      return true;
    }
    if (target.startsWith("/") && !target.startsWith(workspaceRoot)) {
      return true;
    }
  }
  return false;
}

export class Tether {
  private readonly scope: Scope;
  private readonly workspaceRoot: string;
  private readonly authorized: Set<ImpactTier>;

  constructor(opts: TetherOptions) {
    this.scope = opts.scope;
    this.workspaceRoot = opts.workspaceRoot;
    this.authorized = new Set(opts.authorizedTiers ?? DEFAULT_AUTHORIZED);
  }

  decide(action: ToolAction): TetherResult {
    const tier: ImpactTier = action.impact ?? (action.tool === "bash" ? "probe" : "read");

    // Hard L2 read-only: destructive tier is never allowed.
    if (tier === "destructive") {
      return { decision: "deny", reason: "destructive impact tier forbidden under L2 read-only", tier };
    }

    // Weaponization tier requires operator authorization.
    if (tier === "shell" && !this.authorized.has("shell")) {
      return {
        decision: "escalate",
        reason: "shell-tier action requires operator-issued authorization token",
        tier,
      };
    }

    // DoS / destructive-command AST check (bash only).
    if (action.tool === "bash" && action.command) {
      for (const rule of DESTRUCTIVE_RULES) {
        if (rule.re.test(action.command)) {
          return { decision: "deny", reason: `DoS / destructive command (${rule.label})`, tier };
        }
      }
      if (destructiveRm(action.command, this.workspaceRoot)) {
        return { decision: "deny", reason: "recursive delete outside the sandbox", tier };
      }
    }

    // Filesystem write sandbox.
    if ((action.tool === "write" || action.tool === "edit") && action.path) {
      const norm = action.path.startsWith("/") ? action.path : `/${action.path}`;
      if (!norm.startsWith(this.workspaceRoot + "/") && norm !== this.workspaceRoot) {
        return { decision: "deny", reason: "write outside the sandbox workspace", tier };
      }
    }

    // Scope check: explicit URL, then any URL embedded in a bash command.
    if (action.url) {
      if (!this.scope.isInScope(action.url)) {
        return { decision: "deny", reason: "target URL is out of scope", tier };
      }
    }
    if (action.tool === "bash" && action.command) {
      for (const url of action.command.matchAll(URL_RE)) {
        if (!this.scope.isInScope(url[0])) {
          return { decision: "deny", reason: `command references out-of-scope URL: ${url[0]}`, tier };
        }
      }
    }

    return { decision: "allow", reason: "in scope and non-destructive", tier };
  }
}

export function createTether(opts: TetherOptions): Tether {
  return new Tether(opts);
}
