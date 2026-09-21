/**
 * The Ledger — OpenCode plugin (observability → event stream).
 *
 * Appends every tool/message/session event as NDJSON to the ledger file. This
 * is the deterministic event capture that the Provenance Gate and the Langfuse
 * tracer consume. (Langfuse/ClickHouse export is wired in the deployment; this
 * plugin stays dependency-free and always-on.)
 *
 *   SAHW_LEDGER_FILE   path to the NDJSON ledger (default /tmp/sahw-ledger/events.ndjson)
 */

import { mkdirSync, appendFileSync } from "node:fs";
import { dirname } from "node:path";

function ledgerPath() {
  return process.env.SAHW_LEDGER_FILE ?? "/tmp/sahw-ledger/events.ndjson";
}

function write(event) {
  const file = ledgerPath();
  mkdirSync(dirname(file), { recursive: true });
  appendFileSync(file, JSON.stringify({ utc: new Date().toISOString(), ...event }) + "\n");
}

export default async function LedgerPlugin() {
  return {
    "tool.execute.after": async (input, output) => {
      write({ type: "tool.execute.after", tool: input.tool, sessionID: input.sessionID, callID: input.callID });
    },
    "message.updated": async (input) => {
      const info = input?.properties?.info ?? input?.info;
      write({
        type: "message.updated",
        role: info?.role,
        cost: info?.cost,
        tokens: info?.tokens,
        modelID: info?.modelID,
      });
    },
    "session.idle": async (input) => {
      write({ type: "session.idle", sessionID: input?.info?.id ?? input?.sessionID });
    },
  };
}
