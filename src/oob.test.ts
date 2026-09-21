import { describe, it, expect } from "vitest";
import { makeCanary, extractCanaryFromDns, extractCanaryFromHttpPath, CallbackLog } from "./oob.js";

describe("makeCanary", () => {
  it("returns 12 lowercase hex characters", () => {
    const c = makeCanary();
    expect(c).toMatch(/^[a-f0-9]{12}$/);
  });

  it("is unique across calls (random)", () => {
    expect(makeCanary()).not.toBe(makeCanary());
  });

  it("is deterministic for a given seed (replayable tests)", () => {
    expect(makeCanary("seed-1")).toBe(makeCanary("seed-1"));
    expect(makeCanary("seed-1")).not.toBe(makeCanary("seed-2"));
  });
});

describe("extractCanaryFromDns", () => {
  it("extracts the leftmost label when it is a valid canary", () => {
    expect(extractCanaryFromDns("a1b2c3d4e5f6.oast.example.com.")).toBe("a1b2c3d4e5f6");
    expect(extractCanaryFromDns("A1B2C3D4E5F6.oast.example.com")).toBe("a1b2c3d4e5f6");
  });

  it("returns null when the first label is not a canary", () => {
    expect(extractCanaryFromDns("www.example.com")).toBeNull();
    expect(extractCanaryFromDns("")).toBeNull();
  });
});

describe("extractCanaryFromHttpPath", () => {
  it("extracts a canary path segment", () => {
    expect(extractCanaryFromHttpPath("/a1b2c3d4e5f6")).toBe("a1b2c3d4e5f6");
    expect(extractCanaryFromHttpPath("/a1b2c3d4e5f6/deep")).toBe("a1b2c3d4e5f6");
  });

  it("extracts a canary from ?c=", () => {
    expect(extractCanaryFromHttpPath("/cb?c=a1b2c3d4e5f6")).toBe("a1b2c3d4e5f6");
  });

  it("returns null when no canary is present", () => {
    expect(extractCanaryFromHttpPath("/")).toBeNull();
    expect(extractCanaryFromHttpPath("/favicon.ico")).toBeNull();
  });
});

describe("CallbackLog", () => {
  it("records events with a UTC timestamp and correlates by token", () => {
    const log = new CallbackLog();
    log.record({ type: "dns", token: "a1b2c3d4e5f6", source: "10.0.0.1", data: "a1b2c3d4e5f6.oast.x" });
    log.record({ type: "http", token: "a1b2c3d4e5f6", source: "10.0.0.1", data: "GET /a1b2c3d4e5f6" });
    log.record({ type: "dns", token: "ffffffffffff", source: "10.0.0.2", data: "ffffffffffff.oast.x" });

    expect(log.all()).toHaveLength(3);
    expect(log.forCanary("a1b2c3d4e5f6")).toHaveLength(2);
    expect(log.forCanary("000000000000")).toHaveLength(0);
    expect(Date.parse(log.all()[0].utc)).not.toBeNaN();
  });
});