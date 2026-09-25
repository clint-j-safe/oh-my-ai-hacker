export const LOGIN_PATH_CANDIDATES = [
  "/api/login", "/api/auth/login", "/api/v1/auth/login", "/auth/login",
  "/login", "/api/session", "/session", "/api/signin", "/signin",
];

export interface AuthMaterial { headerName: string; value: string }
export interface TwoFactor { present: boolean; type?: "totp" | "otp" | "sms" | "unknown" }
export type LoginOutcome =
  | "authed" | "2fa_pending_with_material" | "2fa_required_no_material" | "invalid" | "blocked" | "unknown";
export interface LoginClassification { outcome: LoginOutcome; authMaterial: AuthMaterial | null; twoFactor: TwoFactor }
export interface LoginAttempt { method: string; url: string; contentType: "json" | "form"; body: string }

const TOKEN_KEYS = [
  "access_token", "accessToken", "token", "id_token", "idToken",
  "jwt", "authToken", "auth_token", "bearerToken", "session_token",
];

// Case-insensitive keyword matching WITHOUT the /i flag, so the trailing boundary can stay
// case-sensitive: an UPPERCASE letter after the keyword is a camelCase token boundary and is
// allowed (otpRequired); a LOWERCASE letter is a word continuation and is rejected (footpath,
// challenges). The leading (?<![a-zA-Z]) rejects a keyword glued to a preceding letter.
const ci = (w: string) => w.replace(/[A-Za-z]/g, (c) => `[${c.toUpperCase()}${c.toLowerCase()}]`);
const TWO_FACTOR = new RegExp(
  `(?<![a-zA-Z])(${[
    ci("otp"), ci("totp"), `${ci("two")}[\\s-]?${ci("factor")}`, `2${ci("fa")}`, ci("mfa"),
    ci("authenticator"), `${ci("verification")}\\s*${ci("code")}`,
    `${ci("one")}[\\s-]?${ci("time")}`, ci("challenge"),
    ci("sms"), `${ci("text")}\\s*${ci("message")}`, `${ci("phone")}\\s*${ci("code")}`,
  ].join("|")})(?![a-z])`,
);
const SMS = new RegExp(
  `(?<![a-zA-Z])(${[
    ci("sms"), `${ci("text")}\\s*${ci("message")}`, `${ci("phone")}\\s*${ci("code")}`,
  ].join("|")})(?![a-z])`,
);

export function candidateLoginRequests(
  loginUrl: string,
  creds: { email?: string; username?: string; password: string },
  fieldHints: Record<string, string> = {},
): LoginAttempt[] {
  const idValue = creds.email ?? creds.username ?? "";
  const idFields = fieldHints.identifier
    ? [fieldHints.identifier]
    : creds.email ? ["email", "username", "user", "login"] : ["username", "user", "login", "email"];
  const pwField = fieldHints.password ?? "password";
  const attempts: LoginAttempt[] = [];
  for (const idf of idFields) {
    const obj: Record<string, string> = { [idf]: idValue, [pwField]: creds.password };
    attempts.push({ method: "POST", url: loginUrl, contentType: "json", body: JSON.stringify(obj) });
  }
  // one form-encoded fallback on the primary id field
  const primary = idFields[0]!;
  attempts.push({
    method: "POST", url: loginUrl, contentType: "form",
    body: `${encodeURIComponent(primary)}=${encodeURIComponent(idValue)}&${encodeURIComponent(pwField)}=${encodeURIComponent(creds.password)}`,
  });
  return attempts;
}

function firstStringDeep(obj: unknown, keys: string[]): string | null {
  if (obj === null || typeof obj !== "object") return null;
  for (const k of keys) {
    const v = (obj as Record<string, unknown>)[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  for (const v of Object.values(obj as Record<string, unknown>)) {
    const found = firstStringDeep(v, keys);
    if (found) return found;
  }
  return null;
}

export function extractAuthMaterial(headers: Record<string, string>, body: string): AuthMaterial | null {
  // 1) a bearer-ish token in the JSON body wins.
  try {
    const token = firstStringDeep(JSON.parse(body), TOKEN_KEYS);
    if (token) return { headerName: "Authorization", value: token };
  } catch { /* not JSON */ }
  // 2) else a Set-Cookie session cookie.
  const setCookie = headers["set-cookie"] ?? headers["Set-Cookie"];
  if (setCookie) {
    const pair = setCookie.split(",")[0]!.split(";")[0]!.trim(); // "name=value"
    if (pair.includes("=")) return { headerName: "Cookie", value: pair };
  }
  return null;
}

export function detectTwoFactor(_status: number, body: string): TwoFactor {
  if (!TWO_FACTOR.test(body)) return { present: false };
  const type = SMS.test(body) ? "sms" : /totp|authenticator/i.test(body) ? "totp" : "otp";
  return { present: true, type };
}

export function classifyLoginResponse(resp: { status: number; headers: Record<string, string>; body: string }): LoginClassification {
  const twoFactor = detectTwoFactor(resp.status, resp.body);
  const authMaterial = extractAuthMaterial(resp.headers, resp.body);
  if (resp.status === 403) return { outcome: "blocked", authMaterial, twoFactor };
  if (authMaterial && twoFactor.present) return { outcome: "2fa_pending_with_material", authMaterial, twoFactor };
  if (authMaterial) return { outcome: "authed", authMaterial, twoFactor };
  if (twoFactor.present) return { outcome: "2fa_required_no_material", authMaterial: null, twoFactor };
  if (resp.status >= 400) return { outcome: "invalid", authMaterial: null, twoFactor };
  return { outcome: "unknown", authMaterial: null, twoFactor };
}

// --- Login-endpoint DISCOVERY (deterministic; "envelope-from-error" idiom) ---
//
// Used when the operator did not provide login.loginUrl: crawl the app's own root HTML
// for its script bundle(s), mine those bundles for API base paths, build candidate login
// URLs, and probe each with a benign fake payload. The app's OWN validation-error envelope
// (a 400/422 "field required" body, or a plain 401 invalid-credentials rejection) is what
// confirms a candidate IS the login endpoint — never a guess, never a literal answer key.

export interface DiscoveredLogin {
  loginUrl: string;
  contentType: "json" | "form";
  identifierField: string; // e.g. "username" | "email"
  passwordField: string;   // default "password"
}

/** Extract same-origin script src URLs from an HTML document, resolved against `origin`. */
export function extractScriptSrcs(html: string, origin: string): string[] {
  const out: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      const u = new URL(m[1]!, origin);
      if (u.origin === new URL(origin).origin && /\.js(\?|$)/i.test(u.pathname)) out.push(u.toString());
    } catch { /* skip */ }
  }
  return [...new Set(out)];
}

/** Extract API base paths (/api/vN or /vN) and auth-ish route literals from a JS bundle. */
export function extractApiHints(js: string): { apiBases: string[]; authPaths: string[] } {
  const apiBases = [...new Set(
    Array.from(js.matchAll(/["'`](\/api\/v\d+|\/v\d+)["'`]/g), (m) => m[1]!)
  )];
  const authPaths = [...new Set(
    Array.from(js.matchAll(/["'`](\/[a-zA-Z0-9/_-]*(?:login|authenticate|signin|verify-otp|token|session)[a-zA-Z0-9/_-]*)["'`]/gi), (m) => m[1]!)
  )];
  return { apiBases, authPaths };
}

/** Build ordered candidate login URLs from discovered bases (cheapest/most-likely first). */
export function candidateLoginUrls(origin: string, apiBases: string[]): string[] {
  const bases = apiBases.length ? apiBases : ["/api/v3", "/api/v1", "/api", ""];
  const suffixes = ["/authenticate", "/login", "/users/login", "/auth/login", "/signin", "/sessions"];
  const urls: string[] = [];
  for (const b of bases) for (const s of suffixes) {
    try { urls.push(new URL(`${b}${s}`, origin).toString()); } catch { /* skip */ }
  }
  return [...new Set(urls)];
}

/** Decide from a probe response whether this path is the login endpoint, and extract any
 * required identifier field the app's validation error reveals ("envelope-from-error"). */
export function classifyLoginProbe(status: number, body: string): { isLogin: boolean; requiredFields: string[] } {
  // 403/404 (incl. API-gateway "explicit deny" / "Missing Authentication Token") => not a login route.
  if (status === 403 || status === 404) return { isLogin: false, requiredFields: [] };
  const fields: string[] = [];
  try {
    const j = JSON.parse(body) as any;
    const errs = Array.isArray(j?.error) ? j.error : Array.isArray(j?.errors) ? j.errors : [];
    for (const e of errs) if (e && typeof e.field === "string") fields.push(e.field);
  } catch { /* not JSON */ }
  // Also parse "The 'X' field is required" messages.
  for (const m of body.matchAll(/[Tt]he ['"`]?([a-zA-Z0-9_]+)['"`]? field is required/g)) fields.push(m[1]!);
  // A validation error (400/422) OR an invalid-credentials rejection (401) means the endpoint EXISTS
  // and processes credentials — i.e. it is the login endpoint.
  const isLogin = status === 400 || status === 422 || status === 401;
  return { isLogin, requiredFields: [...new Set(fields)] };
}
