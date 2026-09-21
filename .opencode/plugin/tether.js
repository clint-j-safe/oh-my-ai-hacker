/**
 * AI Hacker Tether — OpenCode plugin (hard scope + safety gate).
 *
 * Hooks `tool.execute.before`. Pure deterministic code: scope allowlist
 * (from SAHW_SCOPE) + destructive-command AST + write-sandbox + impact-tier.
 * Denies by throwing (aborts the tool call). The LLM proposes; the Tether decides.
 *
 * Reuses the single source of truth in dist/ (src/scope.ts, src/tether.ts),
 * which is covered by unit tests. Scope comes from the control plane via env:
 *   SAHW_SCOPE         comma-separated in-scope URLs
 *   SAHW_OUT_OF_SCOPE  comma-separated out-of-scope URL prefixes (optional)
 *   SAHW_WORKSPACE     sandbox root (writes restricted inside)
 *   SAHW_AUTHORIZED_TIERS  comma-separated authorized impact tiers (optional)
 */

import { parseScope } from "../../dist/scope.js";
import { createTether } from "../../dist/tether.js";

function readTether() {
  const scopeList = (process.env.SAHW_SCOPE ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const outOfScope = (process.env.SAHW_OUT_OF_SCOPE ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const workspace = process.env.SAHW_WORKSPACE ?? "/tmp/sahw-sandbox";
  const authorized = (process.env.SAHW_AUTHORIZED_TIERS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const scope = parseScope({ inScopeUrls: scopeList, outOfScope });
  const tether = createTether({
    scope,
    workspaceRoot: workspace,
    ...(authorized.length ? { authorizedTiers: authorized } : {}),
  });
  return { tether, hasScope: scopeList.length > 0 };
}

export default async function TetherPlugin({ directory }) {
  // Re-read env per call so the control plane can rotate scope between engagements.
  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash" && input.tool !== "webfetch" && input.tool !== "write" && input.tool !== "edit") {
        return;
      }
      const { tether, hasScope } = readTether();
      if (!hasScope) return; // no scope configured (dev); do not silently block everything

      const action = {
        tool: input.tool,
        command: input.tool === "bash" ? output.args?.command : undefined,
        url: input.tool === "webfetch" ? output.args?.url : undefined,
        path: input.tool === "write" || input.tool === "edit" ? output.args?.path : undefined,
        impact: output.args?.impact,
      };

      const decision = tether.decide(action);
      if (decision.decision === "deny") {
        throw new Error(`[AI Hacker Tether] DENY (${input.tool}): ${decision.reason}`);
      }
      if (decision.decision === "escalate") {
        throw new Error(`[AI Hacker Tether] ESCALATE (${input.tool}): ${decision.reason}`);
      }
    },
  };
}
