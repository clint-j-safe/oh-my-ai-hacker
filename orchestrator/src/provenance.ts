import type { VerdictStatus } from "./axiom.js";
import type { ArtifactStore } from "./artifacts.js";

export interface Provenance {
  utc: string;
  langfuseTraceId: string | null;
  exploitRequestHash: string | null;
  stdoutSha256: string | null;
  sandboxId: string | null;
  exitCode: number | null;
}

/**
 * Stricter than finding.schema.json on purpose. The schema defines a well-formed
 * finding; this gate defines a believable one. It exists to stop placeholder or
 * model-generated text being mistaken for real tool output: a claim whose evidence
 * cannot be traced to a hashed artifact produced by a recorded command did not happen.
 */
export async function gateProvenance(
  p: Provenance, axiom: VerdictStatus, store: ArtifactStore,
): Promise<{ status: VerdictStatus; missing: string[] }> {
  if (axiom !== "CONFIRMED") return { status: axiom, missing: [] };

  const missing: string[] = [];
  if (!p.utc) missing.push("utc");
  if (!p.langfuseTraceId) missing.push("langfuseTraceId");
  if (!p.exploitRequestHash) missing.push("exploitRequestHash");
  if (!p.sandboxId) missing.push("sandboxId");
  if (p.exitCode === null || p.exitCode === undefined) missing.push("exitCode");

  if (!p.stdoutSha256) {
    missing.push("stdoutSha256");
  } else if (!(await store.has(p.stdoutSha256))) {
    missing.push(`stdoutSha256 not present in the artifact store: ${p.stdoutSha256}`);
  }

  return { status: missing.length === 0 ? "CONFIRMED" : "NEEDS_REVIEW", missing };
}
