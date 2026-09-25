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
const TWO_FACTOR = /(otp|totp|two[\s-]?factor|2fa|mfa|authenticator|verification\s*code|one[\s-]?time|challenge)/i;
const SMS = /(sms|text\s*message|phone\s*code)/i;

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
