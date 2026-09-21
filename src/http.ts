/**
 * Real HTTP fetcher for black-box recon/probing. A browser-ish User-Agent is
 * configurable; the target may fingerprint non-browser clients. Headers are
 * lower-cased for deterministic access.
 */

import type { FetcherResult } from "./recon.js";

export interface HttpOptions {
  userAgent?: string;
  timeoutMs?: number;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

const DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36";

export async function httpRequest(url: string, opts: HttpOptions = {}): Promise<FetcherResult> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {
    "user-agent": opts.userAgent ?? DEFAULT_UA,
    "accept": "*/*",
    ...(opts.headers ?? {}),
  };
  const init: RequestInit = {
    method,
    headers,
    redirect: "follow",
    signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
  };
  if (opts.body !== undefined) init.body = opts.body;

  const res = await fetch(url, init);
  const outHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    outHeaders[k.toLowerCase()] = v;
  });
  return { status: res.status, headers: outHeaders, body: await res.text() };
}
