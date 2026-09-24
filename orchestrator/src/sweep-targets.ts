import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { SweepTarget } from "./sweep.js";

/**
 * Derives WHAT to fuzz for the deep-mode sweep, generically, from the REAL requests the
 * framework has already captured (the artifact store) — no target-specific hardcoding.
 *
 * For each in-scope (method, canonical-endpoint) it keeps a representative request body
 * and enumerates the string leaf fields to fuzz (query params + nested JSON leaves,
 * e.g. unsafebank's data.name / data.userid inside {requestBody:{data:{...}}}). The
 * sweep then rebuilds that exact request with a payload injected at one leaf at a time,
 * so it works for JSON-envelope APIs, not just query strings.
 */

export interface SweepTargetWithBody extends SweepTarget {
  /** The representative request body to clone and inject into (JSON string), or null for
   * query-only endpoints. */
  bodyTemplate: string | null;
  headers: Record<string, string>;
  /** For each param, whether it is a JSON dot-path into bodyTemplate or a query key. */
  paramKind: Record<string, "json" | "query">;
}

/** Dot-paths to every STRING leaf in a JSON value, bounded in depth and count so a huge
 * body can't explode the fuzz surface. Skips obviously non-injectable plumbing fields. */
const SKIP_LEAF = /^(timestamp|deviceid|os|host|device)$/i;
export function jsonStringLeafPaths(value: unknown, prefix = "", depth = 0, out: string[] = []): string[] {
  if (depth > 6 || out.length >= 24) return out;
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (typeof v === "string") {
        if (!SKIP_LEAF.test(k)) out.push(path);
      } else if (v && typeof v === "object") {
        jsonStringLeafPaths(v, path, depth + 1, out);
      }
    }
  }
  return out;
}

/** Immutably set a dot-path in a deep-cloned JSON object. */
export function setAtPath(obj: unknown, path: string, value: string): unknown {
  const clone = JSON.parse(JSON.stringify(obj));
  const parts = path.split(".");
  let node: Record<string, unknown> = clone as Record<string, unknown>;
  for (let i = 0; i < parts.length - 1; i++) {
    const p = parts[i];
    if (node[p] == null || typeof node[p] !== "object") node[p] = {};
    node = node[p] as Record<string, unknown>;
  }
  node[parts[parts.length - 1]] = value;
  return clone;
}

interface CapturedRequest { method: string; url: string; headers?: Record<string, string>; body?: string | null }
interface CapturedArtifact { request?: CapturedRequest }

/**
 * Turn a set of captured artifacts into fuzz targets. Pure over `records` so it is unit
 * testable. Prefers a POST/PUT/PATCH request with a JSON body (those carry the real
 * fuzzable fields); falls back to query params. `canon` canonicalizes an endpoint URL so
 * a sub-path variant and its canonical route map to one target.
 */
export function deriveTargets(
  records: CapturedArtifact[],
  inScope: (url: string) => boolean,
  canon: (url: string) => string,
  maxTargets = 20,
): SweepTargetWithBody[] {
  const byKey = new Map<string, SweepTargetWithBody>();
  for (const rec of records) {
    const req = rec.request;
    if (!req || typeof req.url !== "string" || !inScope(req.url)) continue;
    const method = (req.method || "GET").toUpperCase();
    let base: string; let query: URLSearchParams | null = null;
    try {
      const u = new URL(req.url);
      base = canon(`${u.origin}${u.pathname}`);
      query = u.searchParams;
    } catch { continue; }
    const key = `${method} ${base}`;

    const jsonParams: string[] = [];
    let bodyTemplate: string | null = null;
    if (req.body && /^\s*[[{]/.test(req.body)) {
      try {
        const parsed = JSON.parse(req.body);
        const leaves = jsonStringLeafPaths(parsed);
        if (leaves.length) { jsonParams.push(...leaves); bodyTemplate = req.body; }
      } catch { /* not JSON; ignore */ }
    }
    const queryParams = query ? [...new Set([...query.keys()])] : [];
    if (jsonParams.length === 0 && queryParams.length === 0) continue;

    const paramKind: Record<string, "json" | "query"> = {};
    for (const p of jsonParams) paramKind[p] = "json";
    for (const p of queryParams) paramKind[p] = "query";

    // Prefer the richer template: keep the first that has a JSON body; otherwise merge params.
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { endpoint: base, method, params: [...jsonParams, ...queryParams], bodyTemplate, headers: req.headers ?? {}, paramKind });
    } else if (!existing.bodyTemplate && bodyTemplate) {
      byKey.set(key, { endpoint: base, method, params: [...jsonParams, ...queryParams], bodyTemplate, headers: req.headers ?? {}, paramKind });
    }
    if (byKey.size >= maxTargets) break;
  }
  return [...byKey.values()];
}

/** Reads and parses request/response artifacts from the on-disk store (fanned by 2-hex).
 * Bounded by `limit` files. Fail-soft: unreadable/non-JSON files are skipped. */
export async function readArtifactRecords(artifactsDir: string, limit = 4000): Promise<CapturedArtifact[]> {
  const out: CapturedArtifact[] = [];
  let subdirs: string[];
  try { subdirs = await readdir(artifactsDir); } catch { return out; }
  for (const sd of subdirs) {
    if (out.length >= limit) break;
    let files: string[];
    try { files = await readdir(join(artifactsDir, sd)); } catch { continue; }
    for (const f of files) {
      if (out.length >= limit) break;
      if (f.startsWith(".tmp")) continue;
      try {
        const txt = await readFile(join(artifactsDir, sd, f), "utf8");
        const obj = JSON.parse(txt);
        if (obj && typeof obj === "object" && obj.request) out.push(obj as CapturedArtifact);
      } catch { /* skip */ }
    }
  }
  return out;
}
