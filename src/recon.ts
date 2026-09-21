/**
 * Recon — black-box surface discovery. No target knowledge is baked in:
 * everything is extracted from the target's own HTML and served JS bundles.
 * Yields the endpoint/param map the threat-model agent then reasons about,
 * plus immediate info-disclosure (source maps) and CORS observations.
 */

export interface FetcherResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export type Fetcher = (url: string) => Promise<FetcherResult>;

export interface DiscoveredEndpoint {
  method: string;
  path: string;
  params: string[];
  source: string; // which JS file revealed it
}

export interface DiscoveredSurface {
  baseUrl: string;
  scripts: string[];
  endpoints: DiscoveredEndpoint[];
  sourceMaps: string[];
  cors: { acao: string; acac: string } | null;
  tech: string[];
}

const HTTP_URL_RE = /https?:\/\/[^\s"'`<>()]+/g;
const PATH_RE = /["'`](\/(?:[\w.-]+\/)*[\w.-]+(?:\?[^"'`]*)?)["'`]/g;
const API_PATH_RE = /["'`](\/[a-zA-Z0-9_./-]*\/[a-zA-Z0-9_./-]+)["'`]/g;

function uniq<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

export function extractHttpUrls(text: string): string[] {
  return uniq(text.match(HTTP_URL_RE) ?? []).map((u) => u.replace(/[),;]+$/, ""));
}

/** Path-like string literals (`/api/...`, `/show`, `/login`, ...) from JS/HTML. */
export function extractPathStrings(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(PATH_RE)) {
    const p = m[1].split("?")[0];
    if (p.length > 1 && p.includes("/")) out.push(p);
  }
  return uniq(out);
}

/** API endpoints referenced via fetch / axios / XMLHttpRequest in a JS bundle. */
export function extractApiEndpoints(js: string, source = "bundle"): DiscoveredEndpoint[] {
  const out: DiscoveredEndpoint[] = [];
  const push = (method: string, path: string) => {
    if (path.startsWith("http")) {
      try {
        path = new URL(path).pathname || "/";
      } catch {
        return;
      }
    }
    if (!path.startsWith("/")) return;
    const [base, qs] = path.split("?");
    const params = (qs ?? "").split("&").filter(Boolean).map((kv) => kv.split("=")[0]);
    out.push({ method: method.toUpperCase(), path: base, params, source });
  };

  // fetch("...")
  for (const m of js.matchAll(/fetch\s*\(\s*["'`]([^"'`]+)["'`]/g)) push("GET", m[1]);
  // axios.get/post/put/delete("...")
  for (const m of js.matchAll(/axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/g)) push(m[1], m[2]);
  // xhr.open("METHOD", "...")
  for (const m of js.matchAll(/\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`]([^"'`]+)["'`]/g)) push(m[1], m[2]);

  // Fallback: any /api/... or multi-segment path literal in the bundle.
  for (const m of js.matchAll(API_PATH_RE)) {
    const p = m[1];
    if (p.includes("/api/") || (p.split("/").filter(Boolean).length >= 2 && !p.includes("."))) {
      if (!out.some((e) => e.path === p)) push("GET", p);
    }
  }
  return out;
}

export function isSourceMapUrl(url: string): boolean {
  return /\.map$/i.test(url) || /\.js\.map$/i.test(url);
}

function scriptSrcs(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) out.push(m[1]);
  return uniq(out);
}

function resolveUrl(baseUrl: string, ref: string): string {
  try {
    return new URL(ref, baseUrl).toString();
  } catch {
    return ref;
  }
}

export async function discoverSurface(baseUrl: string, fetch: Fetcher): Promise<DiscoveredSurface> {
  const surface: DiscoveredSurface = {
    baseUrl,
    scripts: [],
    endpoints: [],
    sourceMaps: [],
    cors: null,
    tech: [],
  };

  const root = await fetch(baseUrl);
  const html = root.body;

  // Tech fingerprint (headers only — nothing app-specific).
  const server = root.headers["server"] ?? "";
  const powered = root.headers["x-powered-by"] ?? "";
  if (server) surface.tech.push(`server:${server}`);
  if (powered) surface.tech.push(`x-powered-by:${powered}`);

  // CORS observation: preflight the base origin.
  try {
    const pre = await fetch(baseUrl + (baseUrl.endsWith("/") ? "" : "/") + "__cors_probe__");
    const acao = pre.headers["access-control-allow-origin"] ?? "";
    const acac = pre.headers["access-control-allow-credentials"] ?? "";
    if (acao) surface.cors = { acao, acac };
  } catch {
    /* ignore */
  }

  // Script bundles from HTML + inline.
  const inlineScripts = html.match(/<script\b[^>]*>([\s\S]*?)<\/script>/gi) ?? [];
  const scripts = scriptSrcs(html).map((s) => resolveUrl(baseUrl, s));
  surface.scripts = uniq(scripts);

  // Extract endpoints from inline scripts + each fetched bundle.
  for (const inline of inlineScripts) {
    const body = inline.replace(/<script[^>]*>/gi, "").replace(/<\/script>/gi, "");
    surface.endpoints.push(...extractApiEndpoints(body, "inline"));
  }
  for (const src of surface.scripts) {
    try {
      const res = await fetch(src);
      const js = res.body;
      surface.endpoints.push(...extractApiEndpoints(js, src));
      if (isSourceMapUrl(src)) surface.sourceMaps.push(src);
      // sourceMappingURL comment
      for (const m of js.matchAll(/sourceMappingURL=([^\s*]+)/g)) {
        const mapUrl = resolveUrl(src, m[1]);
        if (isSourceMapUrl(mapUrl)) surface.sourceMaps.push(mapUrl);
      }
    } catch {
      /* bundle fetch failed — skip */
    }
  }

  surface.endpoints = uniq(surface.endpoints.map((e) => `${e.method} ${e.path} ${e.params.join(",")}`))
    .map((s) => {
      const [method, path, params] = s.split(" ");
      return { method, path, params: params ? params.split(",").filter(Boolean) : [], source: surface.scripts[0] ?? "inline" };
    });

  return surface;
}
