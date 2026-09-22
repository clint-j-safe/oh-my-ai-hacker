export interface BeatWork {
  succeededToolCalls: number;
  newArtifacts: number;
  calls: Array<{ tool: string; args: string }>;
}

export interface StallConfig {
  minToolCalls: number;
  minArtifacts: number;
  maxRepeatCalls: number;
  maxBarrenBeats: number;
  exitCode: number;
}

type Env = Record<string, string | undefined>;
const n = (env: Env, k: string, d: number) =>
  env[k] === undefined || env[k] === "" ? d : Number(env[k]);

export function loadStallConfig(env: Env): StallConfig {
  return {
    minToolCalls: n(env, "SAHW_STALL_MIN_TOOL_CALLS", 1),
    minArtifacts: n(env, "SAHW_STALL_MIN_ARTIFACTS", 1),
    maxRepeatCalls: n(env, "SAHW_STALL_MAX_REPEAT_CALLS", 3),
    maxBarrenBeats: n(env, "SAHW_STALL_MAX_BARREN_BEATS", 2),
    exitCode: n(env, "SAHW_STALL_EXIT_CODE", 3),
  };
}

/**
 * Stall detection keys on EXECUTED WORK, never on liveness. A loop that is still
 * ticking is not a loop that is working: a run that reported "not stalled" after
 * three hours with zero executed tool calls is the failure this guards against.
 */
export function isStalled(work: BeatWork, cfg: StallConfig): { stalled: boolean; reason: string | null } {
  if (work.succeededToolCalls < cfg.minToolCalls) {
    return { stalled: true, reason: `only ${work.succeededToolCalls} succeeded tool call(s), need ${cfg.minToolCalls}` };
  }
  if (work.newArtifacts < cfg.minArtifacts) {
    return { stalled: true, reason: `only ${work.newArtifacts} new artifact(s), need ${cfg.minArtifacts}` };
  }
  const seen = new Map<string, number>();
  for (const c of work.calls) {
    const key = `${c.tool}:${c.args}`;
    const count = (seen.get(key) ?? 0) + 1;
    seen.set(key, count);
    if (count > cfg.maxRepeatCalls) {
      return { stalled: true, reason: `repeat call ${key} seen ${count} times (cap ${cfg.maxRepeatCalls})` };
    }
  }
  return { stalled: false, reason: null };
}
