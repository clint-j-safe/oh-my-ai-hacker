/**
 * OOB (Out-Of-Band) callback correlation — the deterministic core of the OAST
 * listener. Payloads embed a canary token; DNS/HTTP/TCP callbacks carrying that
 * token are correlated back to the specific test that caused them. Pure logic,
 * no I/O — the listeners in oob-server.ts use this.
 */

import { randomBytes } from "node:crypto";

const CANARY_RE = /^[a-f0-9]{12}$/;

/** A unique 12-hex-char canary token. */
export function makeCanary(seed?: string): string {
  if (seed) {
    // Deterministic canary for replayable tests: hash the seed to 12 hex chars.
    const h = require("node:crypto").createHash("sha256").update(seed).digest("hex");
    return h.slice(0, 12);
  }
  return randomBytes(6).toString("hex");
}

function isValidCanary(token: string): boolean {
  return CANARY_RE.test(token);
}

/** Extract the canary (leftmost label) from a DNS query name. */
export function extractCanaryFromDns(name: string): string | null {
  const clean = name.trim().toLowerCase().replace(/\.$/, "");
  if (!clean) return null;
  const first = clean.split(".")[0];
  return isValidCanary(first) ? first : null;
}

/** Extract the canary from an HTTP request path (first segment or ?c=). */
export function extractCanaryFromHttpPath(path: string): string | null {
  const p = path.trim();
  const queryIdx = p.indexOf("?");
  const pathOnly = queryIdx === -1 ? p : p.slice(0, queryIdx);
  const seg = pathOnly.split("/").filter(Boolean)[0];
  if (seg && isValidCanary(seg)) return seg;

  // Fallback: ?c=<canary>
  if (queryIdx !== -1) {
    const qs = p.slice(queryIdx + 1);
    for (const kv of qs.split("&")) {
      const [k, v] = kv.split("=");
      if (k === "c" && v && isValidCanary(v)) return v;
    }
  }
  return null;
}

export type CallbackType = "dns" | "http" | "tcp";

export interface CallbackEvent {
  type: CallbackType;
  token: string | null;
  source: string;
  data: string;
  utc: string;
}

export class CallbackLog {
  private events: CallbackEvent[] = [];

  record(evt: Omit<CallbackEvent, "utc">): CallbackEvent {
    const full: CallbackEvent = { ...evt, utc: new Date().toISOString() };
    this.events.push(full);
    return full;
  }

  forCanary(token: string): CallbackEvent[] {
    return this.events.filter((e) => e.token === token);
  }

  all(): CallbackEvent[] {
    return [...this.events];
  }

  clear(): void {
    this.events = [];
  }
}
