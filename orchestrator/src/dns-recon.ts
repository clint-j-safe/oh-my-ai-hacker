/**
 * DNS-driven virtual-host discovery for the deep sweep.
 *
 * PROBLEM (HTB Cronos): the whole app lived on the admin.cronos.htb vhost; scanning the bare
 * IP saw only the default Apache page. The framework had no way to LEARN the domain name, so
 * the app was invisible.
 *
 * DISCIPLINE (per user): candidate hosts derive ONLY from the target itself or the scope —
 *   (1) reverse-DNS / PTR of each scoped IP        -> a hostname (=> base domain),
 *   (2) zone-transfer AXFR of a discovered/scoped base domain -> exact subdomains,
 *   (3) a small prefix wordlist APPENDED to a discovered/scoped base domain.
 * A candidate is accepted only if routing `Host: <fqdn>` at the IP yields an app DISTINCT
 * from the default response. Nothing arbitrary; every name traces back to the IP's own DNS
 * or the scope list. Pure logic here; the PTR/AXFR/HTTP executors are injected (testable).
 */

/** Is this scope host an IP literal (v4)? */
export function isIp(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/** Registrable base domain: the last two labels (e.g. ns1.cronos.htb -> cronos.htb). Naive
 * on purpose — engagement targets use flat TLDs like .htb, not public suffixes. Null for an
 * IP or a bare single label. */
export function baseDomainOf(host: string): string | null {
  const h = host.trim().replace(/\.$/, "").toLowerCase();
  if (!h || isIp(h)) return null;
  const labels = h.split(".").filter(Boolean);
  if (labels.length < 2) return null;
  return labels.slice(-2).join(".");
}

/** A small set of vhost prefixes to append to a DISCOVERED base domain (not arbitrary TLD
 * guessing — only prefixes of a domain already tied to the target). */
export const VHOST_PREFIXES = [
  "admin", "www", "dev", "api", "app", "portal", "staging", "stage", "test",
  "internal", "intranet", "secure", "beta", "mail", "ns1", "backend", "web",
] as const;

/** Build the candidate FQDN set from base domains + AXFR-found names + prefix×base. Only
 * names ending in one of the (target-derived) base domains survive. Deduped, bounded. */
export function candidateFqdns(baseDomains: string[], axfrNames: string[], prefixes: readonly string[] = VHOST_PREFIXES, max = 60): string[] {
  const bases = [...new Set(baseDomains.map((b) => b.toLowerCase().replace(/\.$/, "")).filter(Boolean))];
  const out = new Set<string>();
  for (const b of bases) {
    out.add(b);                                  // the apex itself
    for (const p of prefixes) out.add(`${p}.${b}`);
  }
  for (const n of axfrNames) {
    const name = n.toLowerCase().replace(/\.$/, "");
    if (bases.some((b) => name === b || name.endsWith(`.${b}`))) out.add(name);
  }
  return [...out].slice(0, max);
}

/** A candidate vhost is REAL when its Host-routed response differs meaningfully from the
 * default (bare/unknown-Host) response: a different status, or a body that diverges beyond
 * noise (length delta or a different <title>). Conservative to avoid false vhosts. */
export interface HttpResp { status: number; body: string }
export function isDistinctVhost(def: HttpResp, cand: HttpResp): boolean {
  if (!cand || cand.status === 0) return false;
  const title = (b: string) => (/(<title>[^<]*<\/title>)/i.exec(b)?.[1] ?? "").toLowerCase();
  if (cand.status !== def.status) return true;
  const dt = title(def.body), ct = title(cand.body);
  if (ct && ct !== dt) return true;
  const dl = def.body.length, cl = cand.body.length;
  if (dl > 0 && Math.abs(cl - dl) / Math.max(dl, cl) > 0.15) return true;   // >15% size divergence
  return false;
}

/** Extract hostnames matching a base domain from raw AXFR response text/bytes (best-effort:
 * uncompressed names appear as readable labels; compression pointers may hide some, but the
 * prefix-append path covers common ones). */
export function extractAxfrNames(raw: string, baseDomains: string[]): string[] {
  const out = new Set<string>();
  for (const b of baseDomains) {
    const re = new RegExp(`[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9-]+)*\\.${b.replace(/\./g, "\\.")}`, "gi");
    for (const m of raw.match(re) ?? []) out.add(m.toLowerCase());
  }
  return [...out];
}

export interface VhostExec {
  ptr: (ip: string) => Promise<string[]>;                       // reverse DNS -> hostnames
  axfr: (domain: string, server: string) => Promise<string[]>; // zone transfer -> names
  httpHost: (ip: string, hostHeader: string) => Promise<HttpResp>;
}

/**
 * Discover real virtual hosts for the scoped origins. Returns confirmed FQDNs mapped to the
 * IP that serves them. Pure orchestration over injected executors.
 */
export async function discoverVhosts(scopeOrigins: string[], exec: VhostExec, log: (m: string) => void = () => {}): Promise<Array<{ fqdn: string; ip: string }>> {
  const hosts = scopeOrigins.map((o) => { try { return new URL(o).hostname; } catch { return ""; } }).filter(Boolean);
  const ips = [...new Set(hosts.filter(isIp))];
  const scopedDomains = [...new Set(hosts.filter((h) => !isIp(h)))];
  const confirmed: Array<{ fqdn: string; ip: string }> = [];

  for (const ip of ips) {
    // (1) PTR -> base domains; also fold in any domains already in scope.
    const ptrNames = await exec.ptr(ip).catch(() => []);
    const baseDomains = [...new Set([...ptrNames, ...scopedDomains].map(baseDomainOf).filter((b): b is string => Boolean(b)))];
    log(`ptr(${ip})=${ptrNames.join(",") || "none"} base=${baseDomains.join(",") || "none"}`);
    if (baseDomains.length === 0) continue;

    // (2) AXFR each base domain against the target's own DNS server (the IP).
    const axfrNames: string[] = [];
    for (const b of baseDomains) { for (const n of await exec.axfr(b, ip).catch(() => [])) axfrNames.push(n); }
    if (axfrNames.length) log(`axfr=${[...new Set(axfrNames)].join(",")}`);

    // (3) candidates = apex + prefix×base + AXFR names.
    const cands = candidateFqdns(baseDomains, axfrNames);
    // Default response: an unknown Host at this IP (what the bare scan saw).
    const def = await exec.httpHost(ip, `sahw-nonexistent-${Math.random().toString(36).slice(2, 8)}.${baseDomains[0]}`).catch(() => ({ status: 0, body: "" }));
    for (const fqdn of cands) {
      const resp = await exec.httpHost(ip, fqdn).catch(() => ({ status: 0, body: "" }));
      if (isDistinctVhost(def, resp)) { confirmed.push({ fqdn, ip }); log(`VHOST ${fqdn} -> ${ip} (status=${resp.status} len=${resp.body.length})`); }
    }
  }
  return confirmed;
}

/** Reconstruct dotted DNS names from a raw response buffer (best-effort): walk each offset,
 * reading length-prefixed labels until a zero or a compression pointer. Catches the many
 * uncompressed owner/target names in an AXFR stream; compressed ones are simply skipped
 * (the prefix-append path covers common subdomains). Pure and unit-testable over a Buffer. */
export function collectDnsNames(buf: Uint8Array): string[] {
  const names = new Set<string>();
  for (let i = 0; i < buf.length; i++) {
    const labels: string[] = [];
    let j = i, ok = true, guard = 0;
    while (guard++ < 40) {
      const len = buf[j];
      if (len === undefined) { ok = false; break; }
      if (len === 0) break;                      // end of name
      if ((len & 0xc0) === 0xc0) break;          // compression pointer — stop (best-effort)
      if (len > 63) { ok = false; break; }
      const start = j + 1, end = start + len;
      if (end > buf.length) { ok = false; break; }
      let label = "";
      for (let k = start; k < end; k++) label += String.fromCharCode(buf[k]);
      if (!/^[A-Za-z0-9_-]+$/.test(label)) { ok = false; break; }
      labels.push(label);
      j = end;
    }
    if (ok && labels.length >= 2) names.add(labels.join(".").toLowerCase());
  }
  return [...names];
}
