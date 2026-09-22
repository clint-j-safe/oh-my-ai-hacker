import { describe, it, expect, vi } from "vitest";
import { OpenRouterLlm } from "./llm.js";
import { Axiom } from "./axiom.js";

describe("LLM transient-error retry", () => {
  it("retries a 429 and succeeds", async () => {
    const calls: number[] = [];
    const ok = {
      ok: true,
      json: async () => ({ choices: [{ message: { content: "hi" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } }),
    };
    vi.stubGlobal("fetch", vi.fn(async () => {
      calls.push(1);
      if (calls.length < 3) {
        return { ok: false, status: 429, headers: { get: () => "0" }, text: async () => "rate limited" } as never;
      }
      return ok as never;
    }));
    const llm = new OpenRouterLlm({ apiKey: "k", maxRetries: 5, backoffBaseMs: 1 });
    const res = await llm.complete({ model: "m", messages: [] });
    expect(res.content).toBe("hi");
    expect(calls.length).toBe(3); // two 429s then success
    vi.unstubAllGlobals();
  });

  it("does not retry a non-transient 400", async () => {
    let n = 0;
    vi.stubGlobal("fetch", vi.fn(async () => {
      n += 1;
      return { ok: false, status: 400, headers: { get: () => null }, text: async () => "bad request" } as never;
    }));
    const llm = new OpenRouterLlm({ apiKey: "k", maxRetries: 3, backoffBaseMs: 1 });
    await expect(llm.complete({ model: "m", messages: [] })).rejects.toThrow(/400/);
    expect(n).toBe(1);
    vi.unstubAllGlobals();
  });
});

describe("judge outage", () => {
  it("degrades the finding to NEEDS_REVIEW instead of throwing", async () => {
    const axiom = new Axiom({
      judge: { judge: async () => { throw new Error("OpenRouter 429: rate limited"); } },
    });
    const verdict = await axiom.verify({
      invariant: { statement: "s", type: "body_contains", expression: "zzz-not-present" },
      evidence: { exploit_response_excerpt: "some body", status: 200 },
    } as never);
    expect(verdict.status).toBe("NEEDS_REVIEW");
    expect(verdict.reason).toMatch(/judge unavailable/);
  });
});
