import { test } from "node:test";
import assert from "node:assert/strict";
import { extractApiRoutes, fillRouteTemplate, isSpaFallback, looksLikeRealEndpoint } from "../src/auth-recon.js";
import { discoverApiSurface } from "../src/beat.js";

function fetchMap(map: Record<string, { status: number; headers?: Record<string, string>; body: string }>): typeof fetch {
  return (async (url: string, init?: any) => {
    const key = `${(init?.method ?? "GET").toUpperCase()} ${url}`;
    const r = map[key] ?? map[url] ?? { status: 404, headers: { "content-type": "text/html" }, body: "<!doctype html><html>not found</html>" };
    return {
      status: r.status,
      headers: { forEach: (fn: (v: string, k: string) => void) => Object.entries(r.headers ?? {}).forEach(([k, v]) => fn(v, k)) },
      text: async () => r.body,
    } as any;
  }) as unknown as typeof fetch;
}

// ---- Part A: pure helpers ---------------------------------------------------------

test("extractApiRoutes: static literals AND template-function routes, normalized + deduped", () => {
  const js = [
    "const cfg={baseURL:`/api/v3`};",
    "const documents={byId:e=>`/documents/${e}`, base:`/documents`};",
    "const invitations=e=>`/users/${e}/invitations`;",
    "const auth={verifyOtp:`/users/verify-otp`};",
  ].join("\n");
  const routes = extractApiRoutes(js);
  assert.ok(routes.includes("/documents/{id}"), `expected /documents/{id}, got ${JSON.stringify(routes)}`);
  assert.ok(routes.includes("/users/{id}/invitations"), `expected /users/{id}/invitations, got ${JSON.stringify(routes)}`);
  assert.ok(routes.includes("/users/verify-otp"), `expected /users/verify-otp, got ${JSON.stringify(routes)}`);
  // deduped: no duplicate entries
  assert.equal(routes.length, new Set(routes).size);
});

test("fillRouteTemplate fills {id}/{...} placeholders with a benign sample", () => {
  assert.equal(fillRouteTemplate("/users/{id}/invitations"), "/users/1/invitations");
  assert.equal(fillRouteTemplate("/documents/{id}"), "/documents/1");
  assert.equal(fillRouteTemplate("/users/verify-otp"), "/users/verify-otp"); // no placeholder, unchanged
});

test("isSpaFallback: 200 text/html doctype is the SPA catch-all", () => {
  assert.equal(
    isSpaFallback(200, { "content-type": "text/html" }, "<!doctype html><html><body>app</body></html>"),
    true,
  );
});

test("isSpaFallback: 400 application/json is NOT the SPA catch-all", () => {
  assert.equal(
    isSpaFallback(400, { "content-type": "application/json" }, '{"success":false}'),
    false,
  );
});

test("looksLikeRealEndpoint: 200 text/html doctype (SPA fallback) is NOT real", () => {
  assert.equal(
    looksLikeRealEndpoint(200, { "content-type": "text/html" }, "<!doctype html><html></html>"),
    false,
  );
});

test("looksLikeRealEndpoint: 400 application/json IS real", () => {
  assert.equal(
    looksLikeRealEndpoint(400, { "content-type": "application/json" }, '{"success":false}'),
    true,
  );
});

test("looksLikeRealEndpoint: 403 JSON explicit-deny IS real", () => {
  assert.equal(
    looksLikeRealEndpoint(403, { "content-type": "application/json" }, '{"Message":"User is not authorized... explicit deny..."}'),
    true,
  );
});

test("looksLikeRealEndpoint: 404 text/html is NOT real", () => {
  assert.equal(
    looksLikeRealEndpoint(404, { "content-type": "text/html" }, "<!doctype html><html>not found</html>"),
    false,
  );
});

// ---- Part B: discoverApiSurface integration ----------------------------------------

test("discoverApiSurface: mines routes from the bundle, probes candidates, keeps only real endpoints (drops the SPA fallback)", async () => {
  const origin = "https://demo.safeone.io";
  const rootHtml = `<!doctype html><html><head><script type="module" crossorigin src="/assets/index-EIlpuBYm.js"></script></head><body></body></html>`;
  const bundleJs = [
    "const cfg={baseURL:`/api/v3`};",
    "const routes={x:`/api/v3/x`, bogus:`/api/v3/bogus-nonexistent-route`};",
  ].join("\n");
  const spaFallbackBody = "<!doctype html><html><body>app shell</body></html>";
  const inScopeCalls: string[] = [];
  const inScope = (u: string) => { inScopeCalls.push(u); return u.startsWith(origin); };

  const fetchImpl = fetchMap({
    "GET https://demo.safeone.io/": { status: 200, headers: { "content-type": "text/html" }, body: rootHtml },
    "GET https://demo.safeone.io/assets/index-EIlpuBYm.js": { status: 200, headers: { "content-type": "application/javascript" }, body: bundleJs },
    "GET https://demo.safeone.io/api/v3/x": { status: 403, headers: { "content-type": "application/json" }, body: '{"Message":"explicit deny"}' },
    "GET https://demo.safeone.io/api/v3/bogus-nonexistent-route": { status: 200, headers: { "content-type": "text/html" }, body: spaFallbackBody },
  });

  const live = await discoverApiSurface({ scopeOrigin: origin, fetchImpl, inScope });

  assert.deepEqual(live, [{ url: "https://demo.safeone.io/api/v3/x", method: "GET" }]);
  // every candidate URL fetched must have gone through inScope
  for (const u of inScopeCalls) assert.ok(u.startsWith(origin), `fetched out-of-scope url: ${u}`);
});

test("discoverApiSurface: never fetches or returns an out-of-scope candidate", async () => {
  const origin = "https://demo.safeone.io";
  const rootHtml = `<!doctype html><html><head><script type="module" crossorigin src="/assets/index-EIlpuBYm.js"></script></head><body></body></html>`;
  const bundleJs = "const cfg={baseURL:`/api/v3`}; const routes={x:`/api/v3/x`};";
  const fetchImpl = fetchMap({
    "GET https://demo.safeone.io/": { status: 200, headers: { "content-type": "text/html" }, body: rootHtml },
    "GET https://demo.safeone.io/assets/index-EIlpuBYm.js": { status: 200, headers: { "content-type": "application/javascript" }, body: bundleJs },
  });
  // Nothing is in scope: driver must return no live endpoints and never call fetchImpl on candidates.
  const live = await discoverApiSurface({ scopeOrigin: origin, fetchImpl, inScope: () => false });
  assert.deepEqual(live, []);
});
