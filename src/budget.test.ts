import { describe, it, expect } from "vitest";
import { Budget, type TokenUsage } from "./budget.js";

function turn(cost: number, tokens: number): { cost: number; tokens: TokenUsage } {
  return { cost, tokens: { input: tokens, output: 0, reasoning: 0, cache: { read: 0, write: 0 } } };
}

describe("Budget", () => {
  it("is ok within all limits", () => {
    const b = new Budget({ usd: 1, turns: 10, tokens: 10_000 });
    b.record(turn(0.01, 100));
    expect(b.check().ok).toBe(true);
  });

  it("breaches on USD", () => {
    const b = new Budget({ usd: 1, turns: 10, tokens: 10_000 });
    b.record(turn(0.6, 100));
    b.record(turn(0.5, 100));
    const c = b.check();
    expect(c.ok).toBe(false);
    expect(c.breach).toBe("usd");
  });

  it("breaches on turns", () => {
    const b = new Budget({ usd: 10, turns: 2, tokens: 10_000 });
    b.record(turn(0.01, 10));
    b.record(turn(0.01, 10));
    b.record(turn(0.01, 10));
    expect(b.check().breach).toBe("turns");
  });

  it("breaches on tokens (input+output+reasoning+cache)", () => {
    const b = new Budget({ usd: 10, turns: 10, tokens: 1000 });
    b.record({ cost: 0.01, tokens: { input: 400, output: 300, reasoning: 200, cache: { read: 150, write: 0 } } });
    expect(b.usage().tokens).toBe(1050);
    expect(b.check().breach).toBe("tokens");
  });

  it("accumulates usage across turns", () => {
    const b = new Budget({ usd: 10, turns: 10, tokens: 10_000 });
    b.record(turn(0.1, 100));
    b.record(turn(0.2, 200));
    expect(b.usage().usd).toBeCloseTo(0.3);
    expect(b.usage().turns).toBe(2);
    expect(b.usage().tokens).toBe(300);
  });

  it("reset() zeroes usage", () => {
    const b = new Budget({ usd: 10, turns: 10, tokens: 10_000 });
    b.record(turn(0.5, 500));
    b.reset();
    expect(b.usage()).toEqual({ usd: 0, turns: 0, tokens: 0 });
    expect(b.check().ok).toBe(true);
  });
});
