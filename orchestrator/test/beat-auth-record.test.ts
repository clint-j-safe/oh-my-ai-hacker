import { test } from "node:test";
import assert from "node:assert/strict";
import { runAuthRecord } from "../src/beat.js";
import { SessionStore } from "../src/session.js";

function fetchOnce(map: Record<string, { status: number; headers?: Record<string,string>; body: string }>): typeof fetch {
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

test("bypass mode seeds a pre-2FA session A from a token+2FA login response", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  const fetchImpl = fetchOnce({
    "POST https://t/api/login": { status: 200, body: JSON.stringify({ access_token: "PARTIAL", otp_required: true }) },
  });
  const shape = await runAuthRecord({
    auth: { mode: "bypass", login: { email: "e@x.io", password: "p", loginUrl: "https://t/api/login" }, totp: null },
    inScope: () => true, fetchImpl, sessions,
    now: () => 59_000, sleep: async () => {},
  });
  assert.equal(shape.two_factor, "otp");
  assert.equal(shape.token_location, "body");
  assert.ok(sessions.has("A"));
  assert.equal(sessions.meta("A")!.has_auth_material, true);
});

test("authenticated mode with no TOTP secret on a TOTP-gated flow throws", async () => {
  const sessions = new SessionStore({ maxAccounts: 3 });
  const fetchImpl = fetchOnce({
    "POST https://t/api/login": { status: 200, body: JSON.stringify({ message: "enter authenticator code", totp_required: true }) },
  });
  await assert.rejects(() => runAuthRecord({
    auth: { mode: "authenticated", login: { email: "e@x.io", password: "p", loginUrl: "https://t/api/login" }, totp: null },
    inScope: () => true, fetchImpl, sessions, now: () => 59_000, sleep: async () => {},
  }));
});
