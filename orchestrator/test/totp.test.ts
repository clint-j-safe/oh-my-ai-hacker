import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTotp, generateTotp, TotpEmitter } from "../src/totp.js";

// RFC 6238 Appendix B: ASCII secret "12345678901234567890" = base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
const SHA1_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("generateTotp matches RFC 6238 SHA1 8-digit vectors", () => {
  const cfg = parseTotp({ secret: SHA1_B32, algorithm: "SHA1", digits: 8, period: 30 });
  assert.equal(generateTotp(cfg, 59).code, "94287082");
  assert.equal(generateTotp(cfg, 1111111109).code, "07081804");
  assert.equal(generateTotp(cfg, 1234567890).code, "89005924");
});

test("default config is SHA1 / 6 digits / 30s; window = floor(t/period)", () => {
  const cfg = parseTotp({ secret: SHA1_B32 });
  assert.equal(cfg.algorithm, "SHA1");
  assert.equal(cfg.digits, 6);
  assert.equal(cfg.period, 30);
  const g = generateTotp(cfg, 59);
  assert.equal(g.code, "287082");        // last 6 of 94287082
  assert.equal(g.window, 1);             // floor(59/30)
});

test("parseTotp reads an otpauth:// URI including non-default algorithm/digits", () => {
  const cfg = parseTotp(`otpauth://totp/Acme:me?secret=${SHA1_B32}&algorithm=SHA256&digits=8&period=30`);
  assert.equal(cfg.algorithm, "SHA256");
  assert.equal(cfg.digits, 8);
});

test("parseTotp rejects a missing/invalid secret", () => {
  assert.throws(() => parseTotp("otpauth://totp/Acme:me?issuer=Acme"));
  assert.throws(() => parseTotp({ secret: "" }));
});

test("TotpEmitter never re-emits a code for a window it already consumed", async () => {
  const cfg = parseTotp({ secret: SHA1_B32 });
  const em = new TotpEmitter(cfg);
  let t = 59_000;                          // ms; window 1
  const waited: number[] = [];
  const now = () => t;
  const sleep = async (ms: number) => { waited.push(ms); t += ms; };
  const first = await em.next(now, sleep);
  assert.equal(first.window, 1);
  assert.equal(waited.length, 0);
  const second = await em.next(now, sleep); // same window still current → must wait to window 2
  assert.equal(second.window, 2);
  assert.ok(Number(waited.length) === 1 && waited[0]! > 0, "should have slept into the next window");
  assert.notEqual(second.code, first.code);
});
