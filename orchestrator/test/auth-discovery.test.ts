import { test } from "node:test";
import assert from "node:assert/strict";
import { extractScriptSrcs, extractApiHints, candidateLoginUrls, classifyLoginProbe } from "../src/auth-recon.js";
import { discoverLoginEndpoint } from "../src/beat.js";

function fetchOnce(map: Record<string, { status: number; headers?: Record<string, string>; body: string }>): typeof fetch {
  return (async (url: string, init?: any) => {
    const key = `${(init?.method ?? "GET").toUpperCase()} ${url}`;
    const r = map[key] ?? map[url] ?? { status: 404, body: "" };
    return {
      status: r.status,
      headers: { forEach: (fn: (v: string, k: string) => void) => Object.entries(r.headers ?? {}).forEach(([k, v]) => fn(v, k)) },
      text: async () => r.body,
    } as any;
  }) as unknown as typeof fetch;
}

test("extractScriptSrcs finds a same-origin module bundle and resolves it against the origin", () => {
  const html = `<!doctype html><html><head><script type="module" crossorigin src="/assets/index-EIlpuBYm.js"></script></head><body></body></html>`;
  const srcs = extractScriptSrcs(html, "https://demo.safeone.io");
  assert.deepEqual(srcs, ["https://demo.safeone.io/assets/index-EIlpuBYm.js"]);
});

test("extractScriptSrcs drops cross-origin and non-.js srcs", () => {
  const html = `<script src="https://cdn.other.example/lib.js"></script><script src="/style.css"></script><script src="/assets/app.js"></script>`;
  const srcs = extractScriptSrcs(html, "https://demo.safeone.io");
  assert.deepEqual(srcs, ["https://demo.safeone.io/assets/app.js"]);
});

test("extractApiHints returns api base paths from bundle literals", () => {
  const js = "const cfg={baseURL:`/api/v3`,ne:`/api/v4`,verifyOtp:`/users/verify-otp`};";
  const { apiBases, authPaths } = extractApiHints(js);
  assert.deepEqual(new Set(apiBases), new Set(["/api/v3", "/api/v4"]));
  assert.ok(authPaths.includes("/users/verify-otp"));
});

test("candidateLoginUrls builds ordered candidates from discovered bases", () => {
  const urls = candidateLoginUrls("https://demo.safeone.io", ["/api/v3"]);
  assert.ok(urls.includes("https://demo.safeone.io/api/v3/authenticate"));
  assert.ok(urls.includes("https://demo.safeone.io/api/v3/login"));
});

test("classifyLoginProbe: 400 validation error reveals the login endpoint + required field", () => {
  const body = JSON.stringify({
    success: false,
    message: "Validation checks failed",
    error: [{ type: "required", message: "The 'username' field is required.", field: "username" }],
  });
  const cls = classifyLoginProbe(400, body);
  assert.equal(cls.isLogin, true);
  assert.deepEqual(cls.requiredFields, ["username"]);
});

test("classifyLoginProbe: 403 API-gateway explicit deny is NOT the login endpoint", () => {
  const cls = classifyLoginProbe(403, JSON.stringify({ Message: "User is not authorized to access this resource with an explicit deny in an identity-based policy" }));
  assert.equal(cls.isLogin, false);
});

test("classifyLoginProbe: 401 invalid-credentials rejection IS the login endpoint", () => {
  const cls = classifyLoginProbe(401, JSON.stringify({ message: "invalid credentials" }));
  assert.equal(cls.isLogin, true);
});

test("discoverLoginEndpoint: crawls root -> bundle -> API base, probes candidates, finds the login endpoint via envelope-from-error", async () => {
  const origin = "https://demo.safeone.io";
  const rootHtml = `<!doctype html><html><head><script type="module" crossorigin src="/assets/index-EIlpuBYm.js"></script></head><body></body></html>`;
  const bundleJs = "const cfg={baseURL:`/api/v3`,ne:`/api/v4`,verifyOtp:`/users/verify-otp`};";
  const fetchImpl = fetchOnce({
    "GET https://demo.safeone.io/": { status: 200, body: rootHtml },
    "GET https://demo.safeone.io/assets/index-EIlpuBYm.js": { status: 200, body: bundleJs },
    "POST https://demo.safeone.io/api/v3/login": {
      status: 403,
      body: JSON.stringify({ Message: "User is not authorized to access this resource with an explicit deny in an identity-based policy" }),
    },
    "POST https://demo.safeone.io/api/v3/authenticate": {
      status: 400,
      body: JSON.stringify({
        success: false,
        message: "Validation checks failed",
        error: [{ type: "required", message: "The 'username' field is required.", field: "username" }],
      }),
    },
  });
  const discovered = await discoverLoginEndpoint({
    scopeOrigin: origin,
    fetchImpl,
    inScope: () => true,
  });
  assert.deepEqual(discovered, {
    loginUrl: "https://demo.safeone.io/api/v3/authenticate",
    contentType: "json",
    identifierField: "username",
    passwordField: "password",
  });
});

test("discoverLoginEndpoint: returns null when nothing classifies as a login endpoint", async () => {
  const origin = "https://demo.safeone.io";
  const fetchImpl = fetchOnce({
    "GET https://demo.safeone.io/": { status: 200, body: "<html></html>" },
  });
  const discovered = await discoverLoginEndpoint({ scopeOrigin: origin, fetchImpl, inScope: () => true });
  assert.equal(discovered, null);
});
