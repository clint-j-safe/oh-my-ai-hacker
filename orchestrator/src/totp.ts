import { createHmac } from "node:crypto";

export interface TotpConfig {
  secret: Uint8Array;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  digits: number;
  period: number;
}

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Uint8Array {
  const clean = input.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  if (clean === "" || /[^A-Z2-7]/.test(clean)) throw new Error("invalid base32 secret");
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Uint8Array.from(out);
}

function normAlgorithm(a: string | undefined): "SHA1" | "SHA256" | "SHA512" {
  const up = (a ?? "SHA1").toUpperCase();
  if (up === "SHA1" || up === "SHA256" || up === "SHA512") return up;
  throw new Error(`unsupported TOTP algorithm: ${a}`);
}

export function parseTotp(
  input: string | { secret: string; algorithm?: string; digits?: number; period?: number },
): TotpConfig {
  let secretB32: string;
  let algorithm: string | undefined;
  let digits: number | undefined;
  let period: number | undefined;
  if (typeof input === "string" && input.trim().toLowerCase().startsWith("otpauth://")) {
    const u = new URL(input.trim());
    secretB32 = u.searchParams.get("secret") ?? "";
    algorithm = u.searchParams.get("algorithm") ?? undefined;
    const d = u.searchParams.get("digits"); digits = d ? Number(d) : undefined;
    const p = u.searchParams.get("period"); period = p ? Number(p) : undefined;
  } else if (typeof input === "string") {
    secretB32 = input.trim();
  } else {
    secretB32 = input.secret.trim();
    algorithm = input.algorithm;
    digits = input.digits;
    period = input.period;
  }
  if (!secretB32) throw new Error("TOTP secret is required");
  const secret = base32Decode(secretB32);
  const parsedDigits: number = digits && Number.isFinite(digits) ? Math.trunc(digits) : 6;
  const parsedPeriod: number = period && Number.isFinite(period) && period > 0 ? Math.trunc(period) : 30;
  return {
    secret,
    algorithm: normAlgorithm(algorithm),
    digits: parsedDigits,
    period: parsedPeriod,
  };
}

export function generateTotp(config: TotpConfig, atUnixSeconds: number): { code: string; window: number } {
  const window: number = Math.floor(atUnixSeconds / config.period);
  const counter = Buffer.alloc(8);
  // 64-bit big-endian counter (window fits well within 2^53).
  counter.writeBigUInt64BE(BigInt(window));
  const hmac = createHmac(config.algorithm.toLowerCase(), Buffer.from(config.secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const bin =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  const code = (bin % 10 ** config.digits).toString().padStart(config.digits, "0");
  return { code, window: window as number };
}

/** Wraps a config and refuses to re-emit a one-time code for a window it already
 * used — it waits (injected sleep) until the next window instead. This is why
 * scanners throttle: a rapid re-login must not resubmit a code the app already saw. */
export class TotpEmitter {
  private lastWindow = -1;
  constructor(private readonly config: TotpConfig) {}

  async next(nowMs: () => number, sleep: (ms: number) => Promise<void>): Promise<{ code: string; window: number }> {
    let g = generateTotp(this.config, Math.floor(nowMs() / 1000));
    if (g.window === this.lastWindow) {
      const periodMs = this.config.period * 1000;
      const msIntoWindow = nowMs() % periodMs;
      await sleep(periodMs - msIntoWindow);
      g = generateTotp(this.config, Math.floor(nowMs() / 1000));
    }
    this.lastWindow = g.window;
    return g;
  }
}
