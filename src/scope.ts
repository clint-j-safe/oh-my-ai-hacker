/**
 * Scope — the deterministic in-scope allowlist.
 *
 * "Scope = exactly the provided URLs" (design spec hard constraint #3):
 * HTTP(S) only, on the given hosts + ports. No port scanning, no subdomain
 * enumeration, no CIDR-based mass scanning — a host in a provided CIDR is
 * admitted, but the Tether still gates what tools may run against it.
 */

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeError";
  }
}

export interface ScopeEndpoint {
  scheme: "http" | "https";
  host: string; // normalized: lowercase, no trailing dot, no userinfo, IPv6 brackets stripped
  port: number; // explicit or default (http=80, https=443)
}

export interface ScopeInput {
  inScopeUrls: string[];
  inScopeCidrs?: string[];
  outOfScope?: string[];
}

const DEFAULT_PORTS: Record<"http" | "https", number> = { http: 80, https: 443 };

function normalizeHost(hostname: string): string {
  let host = hostname.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  return host;
}

function parseEndpoint(raw: string): ScopeEndpoint {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ScopeError(`Invalid in-scope URL: ${raw}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ScopeError(`In-scope URL must be http(s), got: ${raw}`);
  }
  const scheme: "http" | "https" = url.protocol === "https:" ? "https" : "http";
  const host = normalizeHost(url.hostname);
  if (!host) throw new ScopeError(`In-scope URL has no host: ${raw}`);
  const port = url.port ? Number(url.port) : DEFAULT_PORTS[scheme];
  return { scheme, host, port };
}

interface Cidr {
  network: number; // 32-bit integer
  mask: number; // number of significant bits
}

function ipv4ToInt(host: string): number | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value >>> 0;
}

function parseCidr(raw: string): Cidr | null {
  const [host, bitsRaw] = raw.split("/");
  const bits = Number(bitsRaw);
  const network = ipv4ToInt(host);
  if (network === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  return { network, mask: bits };
}

function cidrContains(cidr: Cidr, host: string): boolean {
  const addr = ipv4ToInt(host);
  if (addr === null) return false;
  if (cidr.mask === 0) return true;
  const shift = 32 - cidr.mask;
  return (addr >>> shift) === (cidr.network >>> shift);
}

export class Scope {
  readonly endpoints: ScopeEndpoint[];
  readonly outOfScope: string[];
  private readonly cidrs: Cidr[];

  constructor(input: ScopeInput) {
    this.endpoints = input.inScopeUrls.map(parseEndpoint);
    this.outOfScope = input.outOfScope ?? [];
    this.cidrs = (input.inScopeCidrs ?? [])
      .map(parseCidr)
      .filter((c): c is Cidr => c !== null);
  }

  /** Is the target URL within the deterministic allowlist? */
  isInScope(target: string): boolean {
    let url: URL;
    try {
      url = new URL(target);
    } catch {
      return false;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;

    const scheme: "http" | "https" = url.protocol === "https:" ? "https" : "http";
    const host = normalizeHost(url.hostname);
    const port = url.port ? Number(url.port) : DEFAULT_PORTS[scheme];

    // Explicit out-of-scope deny wins (path-prefix boundary match).
    for (const oos of this.outOfScope) {
      let o: URL;
      try {
        o = new URL(oos);
      } catch {
        continue;
      }
      const oScheme: "http" | "https" = o.protocol === "https:" ? "https" : "http";
      const oHost = normalizeHost(o.hostname);
      const oPort = o.port ? Number(o.port) : DEFAULT_PORTS[oScheme];
      if (oScheme === scheme && oHost === host && oPort === port) {
        const oPath = o.pathname === "" ? "/" : o.pathname;
        const path = url.pathname === "" ? "/" : url.pathname;
        if (path === oPath || path.startsWith(oPath.endsWith("/") ? oPath : oPath + "/")) {
          return false;
        }
      }
    }

    // Host within a provided CIDR is in scope.
    if (this.cidrs.some((cidr) => cidrContains(cidr, host))) return true;

    // Exact scheme + host + port match against the allowlist.
    return this.endpoints.some(
      (e) => e.scheme === scheme && e.host === host && e.port === port,
    );
  }

  describe(): string {
    const endpoints = this.endpoints
      .map((e) => `${e.scheme}://${e.host}:${e.port}`)
      .join(", ");
    const cidrs = this.cidrs.length ? `, CIDRs: ${this.cidrs.map((c) => `${c.network}/${c.mask}`).join(", ")}` : "";
    return `Scope[endpoints: ${endpoints}${cidrs}]`;
  }
}

export function parseScope(input: ScopeInput): Scope {
  return new Scope(input);
}
