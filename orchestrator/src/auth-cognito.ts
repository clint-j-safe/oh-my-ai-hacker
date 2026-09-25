import { parseTotp, TotpEmitter } from "./totp.js";

/**
 * AWS COGNITO AUTH PROVIDER — logs into Cognito-backed apps (InitiateAuth ->
 * SOFTWARE_TOKEN_MFA/MFA_SETUP -> RespondToAuthChallenge) and, when the account has no
 * TOTP device yet, can FETCH AND OWN a brand-new seed itself via AssociateSoftwareToken
 * (never asking the operator for one). Reuses the RFC-6238 generator in ./totp.js — this
 * module only speaks the Cognito JSON protocol and never re-implements TOTP.
 *
 * Talks to `https://cognito-idp.<region>.amazonaws.com/` directly via the injected
 * `fetchImpl` (raw HTTPS, no AWS SDK dependency). Request shape verified empirically
 * against demo.safeone.io (see docs/superpowers/sdd/.../cognito-brief.md): a PUBLIC SPA
 * app client has no client secret, so AuthParameters never carries SECRET_HASH.
 *
 * EGRESS NOTE (repeated at the beat.ts call site): the Cognito IDP host is an explicit
 * auth-provider egress, not part of SAHW_SCOPE — callers must invoke this module's
 * functions with `fetchImpl` directly, never through the tether's inScope() gate. Only
 * the eventual authenticated requests to the TARGET app (using the tokens this module
 * returns) go through the normal in-scope path.
 *
 * SECRET HYGIENE: this module never logs anything. `password`, `totpSecret`, the
 * fetched `SecretCode` (TOTP seed), and the issued tokens exist only as function
 * arguments/return values and in the JSON bodies sent to Cognito — callers are
 * responsible for keeping them in-process (see beat.ts's runAuthRecord, which persists
 * only a non-secret shape to the spine).
 */

export interface CognitoConfig {
  region: string;
  clientId: string;
}

/**
 * SECURITY (fix round 1): the AWS region shape (e.g. "us-east-1") and the Cognito app
 * client id shape (alphanumeric). `config.region` flows UNMODIFIED into cognitoCall's
 * request URL on a code path that deliberately bypasses the tether's inScope() gate
 * (see beat.ts's EGRESS comment on runAuthRecord) — without this validation, a
 * target-controlled `region` string (e.g. fingerprinted from the target's OWN served JS
 * bundle: `region:'evil.com/x'`) could steer that URL's HOST to an attacker-controlled
 * destination, and cognitoAuthenticate would then POST the operator's real
 * username/password there. Exported so auth-recon.ts's detectCognito (which produces a
 * CognitoConfig from untrusted target-bundle text) and beat.ts's runAuthRecord (which
 * validates before ever touching an explicit SAHW_COGNITO-supplied config, or a
 * fingerprinted one) enforce the exact same shape as cognitoCall's own point-of-use
 * assertion below — defense in depth, not just one gate.
 */
export const AWS_REGION_RE = /^[a-z]{2}-[a-z]+-\d$/;
export const COGNITO_CLIENT_ID_RE = /^[a-zA-Z0-9]+$/;

export interface CognitoTokens {
  idToken: string;
  accessToken: string;
  refreshToken?: string;
}

function extractTokens(ar: Record<string, unknown> | undefined): CognitoTokens | undefined {
  if (!ar || typeof ar.IdToken !== "string" || typeof ar.AccessToken !== "string") return undefined;
  const tokens: CognitoTokens = { idToken: ar.IdToken, accessToken: ar.AccessToken };
  if (typeof ar.RefreshToken === "string") tokens.refreshToken = ar.RefreshToken;
  return tokens;
}

/**
 * Low-level: one Cognito JSON-1.1 action against `https://cognito-idp.<region>.amazonaws.com/`.
 * Sets `x-amz-target: AWSCognitoIdentityProviderService.<action>` and
 * `content-type: application/x-amz-json-1.1`, exactly as the public SPA client sends it
 * (no SigV4, no SECRET_HASH — those belong to server-side/confidential clients only).
 * Returns the parsed JSON body; throws (carrying the error body) on a non-2xx response.
 *
 * SECURITY (fix round 1): validates `config.region`/`config.clientId` against
 * AWS_REGION_RE/COGNITO_CLIENT_ID_RE, and re-parses the constructed URL to assert its
 * host is EXACTLY `cognito-idp.<region>.amazonaws.com`, BEFORE calling `fetchImpl` at
 * all — this is the last line of defense against a malformed/attacker-steered
 * `region`/`clientId` reaching the network on this inScope()-bypassing egress path, on
 * top of detectCognito's own validation (auth-recon.ts) and runAuthRecord's own
 * pre-check (beat.ts). No caller of cognitoCall — explicit SAHW_COGNITO, a fingerprint,
 * or a test — is exempt from this check.
 */
export async function cognitoCall(
  config: CognitoConfig,
  action: string,
  body: Record<string, unknown>,
  fetchImpl: typeof fetch,
): Promise<any> {
  if (!AWS_REGION_RE.test(config.region)) {
    throw new Error(`cognitoCall: refusing to call — region does not match the AWS region shape: ${JSON.stringify(config.region)}`);
  }
  if (!COGNITO_CLIENT_ID_RE.test(config.clientId)) {
    throw new Error(`cognitoCall: refusing to call — clientId does not match the expected alphanumeric shape: ${JSON.stringify(config.clientId)}`);
  }
  const url = `https://cognito-idp.${config.region}.amazonaws.com/`;
  const expectedHost = `cognito-idp.${config.region}.amazonaws.com`;
  const actualHost = new URL(url).host;
  if (actualHost !== expectedHost) {
    // Should be unreachable given the regex checks above, but re-parsing and asserting
    // the exact host — rather than trusting string interpolation — is the point of
    // this defense-in-depth layer: it holds even if the regex above is ever loosened.
    throw new Error(`cognitoCall: refusing to call — resolved host "${actualHost}" != expected "${expectedHost}"`);
  }
  const res = await fetchImpl(url, {
    method: "POST",
    headers: {
      "content-type": "application/x-amz-json-1.1",
      "x-amz-target": `AWSCognitoIdentityProviderService.${action}`,
    },
    body: JSON.stringify(body),
  } as any);
  const text = await res.text();
  let json: any;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  if (res.status < 200 || res.status >= 300) {
    const kind = typeof json?.__type === "string" ? json.__type : `HTTP ${res.status}`;
    const message = typeof json?.message === "string" ? json.message : text;
    throw new Error(`cognito ${action} failed: ${kind}: ${message}`);
  }
  return json;
}

export async function initiateAuth(
  config: CognitoConfig,
  username: string,
  password: string,
  fetchImpl: typeof fetch,
): Promise<{ challengeName?: string; session?: string; challengeParameters?: Record<string, string>; tokens?: CognitoTokens }> {
  const resp = await cognitoCall(config, "InitiateAuth", {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: config.clientId,
    // No SECRET_HASH: the public SPA app client has no client secret (verified live).
    AuthParameters: { USERNAME: username, PASSWORD: password },
  }, fetchImpl);
  const tokens = extractTokens(resp.AuthenticationResult);
  if (tokens) return { tokens };
  return {
    challengeName: typeof resp.ChallengeName === "string" ? resp.ChallengeName : undefined,
    session: typeof resp.Session === "string" ? resp.Session : undefined,
    challengeParameters: resp.ChallengeParameters,
  };
}

export async function respondSoftwareTokenMfa(
  config: CognitoConfig,
  username: string,
  session: string,
  code: string,
  fetchImpl: typeof fetch,
): Promise<CognitoTokens> {
  const resp = await cognitoCall(config, "RespondToAuthChallenge", {
    ClientId: config.clientId,
    ChallengeName: "SOFTWARE_TOKEN_MFA",
    Session: session,
    ChallengeResponses: { USERNAME: username, SOFTWARE_TOKEN_MFA_CODE: code },
  }, fetchImpl);
  const tokens = extractTokens(resp.AuthenticationResult);
  if (!tokens) throw new Error("cognito RespondToAuthChallenge(SOFTWARE_TOKEN_MFA) did not return AuthenticationResult");
  return tokens;
}

export async function associateSoftwareToken(
  config: CognitoConfig,
  session: string,
  fetchImpl: typeof fetch,
): Promise<{ secretCode: string; session: string }> {
  const resp = await cognitoCall(config, "AssociateSoftwareToken", { Session: session }, fetchImpl);
  if (typeof resp.SecretCode !== "string" || typeof resp.Session !== "string") {
    throw new Error("cognito AssociateSoftwareToken did not return a SecretCode/Session");
  }
  return { secretCode: resp.SecretCode, session: resp.Session };
}

export async function verifySoftwareToken(
  config: CognitoConfig,
  session: string,
  userCode: string,
  fetchImpl: typeof fetch,
): Promise<{ status: string; session: string }> {
  const resp = await cognitoCall(config, "VerifySoftwareToken", { Session: session, UserCode: userCode }, fetchImpl);
  if (typeof resp.Status !== "string" || typeof resp.Session !== "string") {
    throw new Error("cognito VerifySoftwareToken did not return a Status/Session");
  }
  return { status: resp.Status, session: resp.Session };
}

export async function respondMfaSetup(
  config: CognitoConfig,
  username: string,
  session: string,
  fetchImpl: typeof fetch,
): Promise<CognitoTokens> {
  const resp = await cognitoCall(config, "RespondToAuthChallenge", {
    ClientId: config.clientId,
    ChallengeName: "MFA_SETUP",
    Session: session,
    ChallengeResponses: { USERNAME: username },
  }, fetchImpl);
  const tokens = extractTokens(resp.AuthenticationResult);
  if (!tokens) throw new Error("cognito RespondToAuthChallenge(MFA_SETUP) did not return AuthenticationResult");
  return tokens;
}

/**
 * High-level: authenticate with `USER_PASSWORD_AUTH`, then:
 *   - no challenge -> done, tokens returned directly.
 *   - `SOFTWARE_TOKEN_MFA` (an existing TOTP device) -> requires `totpSecret`; generates
 *     one code (TotpEmitter, reuse-guarded) and completes the challenge.
 *   - `MFA_SETUP` (no TOTP device yet) -> requires `enroll:true`; FETCHES a brand-new
 *     seed via AssociateSoftwareToken (`SecretCode`), generates a code from it, verifies
 *     it, and completes setup. The fetched seed is returned as `fetchedSeed` so the
 *     caller can persist it in-process — this module itself never persists or logs it.
 * Fail-closed: a SOFTWARE_TOKEN_MFA challenge with no `totpSecret`, or an MFA_SETUP
 * challenge without `enroll:true`, throws a clear error rather than guessing or
 * silently downgrading.
 *
 * `challenge` (additive, beyond the brief's minimal shape) names which Cognito
 * challenge was actually completed, or is omitted when InitiateAuth returned tokens
 * directly with no MFA challenge at all — lets a caller (beat.ts) record an accurate
 * two-factor kind instead of assuming TOTP was always involved.
 */
export async function cognitoAuthenticate(opts: {
  config: CognitoConfig;
  username: string;
  password: string;
  totpSecret?: string;
  enroll?: boolean;
  fetchImpl: typeof fetch;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}): Promise<{ tokens: CognitoTokens; fetchedSeed?: string; challenge?: "SOFTWARE_TOKEN_MFA" | "MFA_SETUP" }> {
  const { config, username, password, totpSecret, enroll, fetchImpl, now, sleep } = opts;

  const init = await initiateAuth(config, username, password, fetchImpl);
  if (init.tokens) return { tokens: init.tokens };

  if (init.challengeName === "SOFTWARE_TOKEN_MFA") {
    if (!init.session) throw new Error("cognito SOFTWARE_TOKEN_MFA challenge had no Session");
    if (!totpSecret) {
      throw new Error(
        "cognitoAuthenticate: target requires SOFTWARE_TOKEN_MFA but no totpSecret was configured " +
        "(set SAHW_TOTP to a known seed, or SAHW_COGNITO_ENROLL=true if the account has no device yet)");
    }
    const emitter = new TotpEmitter(parseTotp(totpSecret));
    const { code } = await emitter.next(now, sleep);
    const tokens = await respondSoftwareTokenMfa(config, username, init.session, code, fetchImpl);
    return { tokens, challenge: "SOFTWARE_TOKEN_MFA" };
  }

  if (init.challengeName === "MFA_SETUP") {
    if (!init.session) throw new Error("cognito MFA_SETUP challenge had no Session");
    if (!enroll) {
      throw new Error(
        "cognitoAuthenticate: target requires MFA_SETUP (no TOTP device enrolled) but enroll was not " +
        "requested (set SAHW_COGNITO_ENROLL=true to let the engine fetch and own a new seed)");
    }
    const assoc = await associateSoftwareToken(config, init.session, fetchImpl);
    const emitter = new TotpEmitter(parseTotp(assoc.secretCode));
    const { code } = await emitter.next(now, sleep);
    const verify = await verifySoftwareToken(config, assoc.session, code, fetchImpl);
    if (verify.status !== "SUCCESS") {
      throw new Error(`cognitoAuthenticate: VerifySoftwareToken did not succeed (status=${verify.status})`);
    }
    const tokens = await respondMfaSetup(config, username, verify.session, fetchImpl);
    return { tokens, fetchedSeed: assoc.secretCode, challenge: "MFA_SETUP" };
  }

  throw new Error(`cognitoAuthenticate: unsupported/unknown Cognito challenge: ${init.challengeName ?? "(none, no tokens either)"}`);
}
