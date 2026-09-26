import { AWS_REGION_RE, COGNITO_CLIENT_ID_RE, type CognitoConfig } from "./auth-cognito.js";

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

/**
 * Fingerprint an AWS Cognito app client from a served JS bundle's own text — pure,
 * no I/O. Amplify/amplify-js-style configs embed a literal `userPoolId`,
 * `userPoolWebClientId`, and (usually) `region` as quoted object properties;
 * `region` is optional in the source since it is recoverable from the pool id's
 * own `<region>_<id>` prefix (Cognito pool ids are always shaped that way), so a
 * bundle that sets region only implicitly is still detected. Requires BOTH
 * `userPoolId` and `userPoolWebClientId` to be present (either alone is too weak a
 * signal — `userPoolId` might appear without a paired client id in shared config
 * boilerplate) before returning a config; returns null otherwise.
 *
 * SECURITY (fix round 1): the extracted region/clientId are validated against
 * AWS_REGION_RE/COGNITO_CLIENT_ID_RE (auth-cognito.ts) before being returned. This
 * bundle text is TARGET-CONTROLLED (the target's own served JS), and the config this
 * function returns flows into cognitoCall's request URL on a code path that
 * deliberately bypasses the tether's inScope() gate (an explicit auth-provider
 * egress — see beat.ts's EGRESS comment on runAuthRecord). Without this check, a
 * bundle containing e.g. region:'evil.com/x' would previously yield an unvalidated
 * config, and cognitoAuthenticate would go on to POST the operator's real
 * username/password to an attacker-controlled host built from it. A region/clientId
 * that fails the shape check is treated as "not confidently Cognito" — this function
 * returns null rather than a best-effort/unsafe guess.
 */
/** Custom auth-token header names an SPA sends its Cognito tokens under, as published
 * in its own bundle config (e.g. `{accessTokenHeader:'authorization',
 * idTokenHeader:'x-safe-id-token',refreshTokenHeader:'x-safe-refresh-token'}`). The engine
 * discovers these from the target rather than hardcoding any one app's convention. */
export interface DiscoveredTokenHeaders {
  idTokenHeader?: string;
  accessTokenHeader?: string;
  refreshTokenHeader?: string;
}

// A plausible HTTP header name (RFC 7230 token chars, kept conservative). Guards against a
// bundle string that matched the key but is not a real header name.
const TOKEN_HEADER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;

/** Extract the SPA's token-header mapping from bundle text. Returns only the keys actually
 * present and shaped like a header name; missing/malformed keys are omitted (never guessed).
 * Pure and side-effect-free, mirroring detectCognito. */
export function detectTokenHeaders(bundleText: string): DiscoveredTokenHeaders {
  const grab = (key: string): string | undefined => {
    const m = bundleText.match(new RegExp(key + "\\s*:\\s*[`'\"]([^`'\"]+)[`'\"]"));
    const v = m?.[1]?.trim();
    return v && TOKEN_HEADER_NAME_RE.test(v) ? v : undefined;
  };
  const out: DiscoveredTokenHeaders = {};
  const id = grab("idTokenHeader"); if (id) out.idTokenHeader = id;
  const ac = grab("accessTokenHeader"); if (ac) out.accessTokenHeader = ac;
  const rf = grab("refreshTokenHeader"); if (rf) out.refreshTokenHeader = rf;
  return out;
}

/** One documented API operation from an OpenAPI/Swagger spec. */
export interface OpenApiEndpoint { path: string; method: string; }
const OPENAPI_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);

// String-aware matching-brace finder: returns the index of the '}' that closes the '{' at
// openIdx, counting braces ONLY outside string literals. Essential because OpenAPI path keys
// like "/assets/{id}" and free-text descriptions contain braces inside strings that a naive
// depth counter would miscount. Returns -1 if unbalanced.
function matchBraceAware(s: string, openIdx: number): number {
  let depth = 0, inStr = false, esc = false;
  for (let i = openIdx; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i; }
  }
  return -1;
}

/** Extract documented endpoints from an OpenAPI/Swagger spec — whether raw spec JSON or a
 * spec embedded in a swagger-ui-init.js wrapper (`"swaggerDoc": { ... }`). Finds the `paths`
 * object (string-aware brace match, so `{id}` path keys parse), and returns one entry per
 * (path, HTTP method). Pure; returns [] when no usable paths object is present. */
export function detectOpenApiPaths(text: string): OpenApiEndpoint[] {
  const re = /"paths"\s*:\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const open = text.indexOf("{", m.index + '"paths"'.length);
    if (open < 0) continue;
    const close = matchBraceAware(text, open);
    if (close < 0) continue;
    let obj: unknown;
    try { obj = JSON.parse(text.slice(open, close + 1)); } catch { continue; }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) continue;
    const rec = obj as Record<string, unknown>;
    const keys = Object.keys(rec);
    if (!keys.some((k) => k.startsWith("/"))) continue; // paths keys are URL paths
    const out: OpenApiEndpoint[] = [];
    for (const p of keys) {
      if (!p.startsWith("/")) continue;
      const ops = rec[p];
      if (!ops || typeof ops !== "object") continue;
      for (const meth of Object.keys(ops as Record<string, unknown>)) {
        if (OPENAPI_METHODS.has(meth.toLowerCase())) out.push({ path: p, method: meth.toUpperCase() });
      }
    }
    if (out.length) return out;
  }
  return [];
}

export function detectCognito(bundleText: string): CognitoConfig | null {
  const poolId = bundleText.match(/userPoolId\s*:\s*[`'"]([^`'"]+)[`'"]/);
  const clientId = bundleText.match(/userPoolWebClientId\s*:\s*[`'"]([^`'"]+)[`'"]/);
  if (!poolId || !clientId) return null;
  const explicitRegion = bundleText.match(/(?<![a-zA-Z])region\s*:\s*[`'"]([^`'"]+)[`'"]/);
  const region = explicitRegion?.[1] ?? poolId[1]!.split("_")[0];
  const cid = clientId[1]!;
  if (!region) return null;
  if (!AWS_REGION_RE.test(region) || !COGNITO_CLIENT_ID_RE.test(cid)) return null;
  return { region, clientId: cid };
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

// --- SPA API-surface DISCOVERY (deterministic; reuses extractScriptSrcs/extractApiHints) ---
//
// The deep-mode beat-1 pre-pass already fetches the SPA root + its JS bundles to discover the
// login endpoint (see discoverLoginEndpoint in beat.ts). These helpers mine those SAME bundles
// for the app's broader REST route map so discoverApiSurface (beat.ts) can feed live endpoints
// into spine.attack_surface — otherwise the sweep + hunter never see the API at all.

/** Extract candidate API route TEMPLATES from a JS bundle: static path literals AND
 *  template-function routes (`/documents/${e}` -> `/documents/{id}`). Deduped, normalized. */
export function extractApiRoutes(js: string): string[] {
  const routes = new Set<string>();
  // static path literals under an api-ish prefix
  for (const m of js.matchAll(/["'`](\/(?:api\/v\d+|v\d+|users|documents|groups|incidents|notifications|locations|settings|filters|identity-provider|access-request|federate|reports|me|search|saas-apps)[a-zA-Z0-9/_-]*)["'`]/g)) {
    routes.add(m[1]!);
  }
  // template-literal routes containing ${...} -> replace each ${...} with {id}
  for (const m of js.matchAll(/`(\/[a-zA-Z0-9/_${}.-]*\$\{[^`]*)`/g)) {
    const t = m[1]!.replace(/\$\{[^}]*\}/g, "{id}");
    if (/^\/[a-zA-Z0-9/_{}-]+$/.test(t)) routes.add(t);
  }
  return [...routes];
}

/** Fill {id}/{...} placeholders with a benign sample so the route is requestable. */
export function fillRouteTemplate(template: string, sample = "1"): string {
  return template.replace(/\{[^}]*\}/g, sample);
}

/** True when a probe response is the SPA HTML catch-all (not a real API endpoint). */
export function isSpaFallback(status: number, headers: Record<string, string>, body: string): boolean {
  const ct = (headers["content-type"] ?? headers["Content-Type"] ?? "").toLowerCase();
  return status >= 200 && status < 300 && ct.includes("text/html") && /<!doctype html/i.test(body.slice(0, 200));
}

/**
 * True when a probe response indicates a REAL endpoint exists (JSON, or a non-HTML 4xx that
 * isn't the SPA fallback). FIX ROUND 1: the 4xx branch used to accept status alone, without
 * checking the body wasn't HTML — a WAF-fronted 403 "Forbidden" page or a 401 login-redirect
 * page (both plain HTML, not the SPA's own catch-all shape isSpaFallback checks for) would be
 * misclassified as a real API endpoint and merged into attack_surface, polluting the hunt on
 * WAF-fronted targets. Now ANY HTML body (2xx via isSpaFallback, or 4xx via the isHtml check
 * below) is rejected; only a non-HTML 4xx (JSON, plain text, or no body/content-type at all —
 * "endpoint exists but gated") is accepted.
 */
export function looksLikeRealEndpoint(status: number, headers: Record<string, string>, body: string): boolean {
  if (isSpaFallback(status, headers, body)) return false;
  const ct = (headers["content-type"] ?? headers["Content-Type"] ?? "").toLowerCase();
  const isHtml = ct.includes("text/html") || /<!doctype html|<html[\s>]/i.test(body.slice(0, 200));
  if (isHtml) return false; // any HTML response (2xx or 4xx) is not a real API endpoint
  if (ct.includes("application/json")) return true;
  // a non-HTML 4xx/405 body (e.g. API-gateway deny, validation, or no content-type at all) = endpoint exists
  if (status === 400 || status === 401 || status === 403 || status === 405 || status === 422) return true;
  return false;
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
