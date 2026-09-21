import { describe, it, expect } from "vitest";
import { SdkRunner, parseFindings } from "./sdk-runner.js";

describe("parseFindings", () => {
  it("extracts JSON objects that carry finding_id + invariant + evidence", () => {
    const parts = [
      {
        type: "text",
        text: 'Here is my result: {"finding_id":"SAHW-0001","invariant":{"statement":"x","type":"body_contains","expression":"root:x"},"evidence":{"exploit_response_excerpt":"root:x:0:0"}} done.',
      },
    ];
    const findings = parseFindings(parts);
    expect(findings).toHaveLength(1);
    expect(findings[0].finding_id).toBe("SAHW-0001");
  });

  it("ignores JSON objects without a finding_id", () => {
    const parts = [
      { type: "text", text: '{"foo":"bar"} {"finding_id":"SAHW-0002","invariant":{"statement":"y","type":"status_in"},"evidence":{"status":200}}' },
    ];
    expect(parseFindings(parts)).toHaveLength(1);
  });

  it("skips tool and synthetic parts", () => {
    const parts = [
      { type: "tool", text: '{"finding_id":"nope","invariant":{},"evidence":{}}' },
      { type: "text", synthetic: true, text: '{"finding_id":"also-nope","invariant":{},"evidence":{}}' },
      { type: "text", text: '{"finding_id":"yes","invariant":{},"evidence":{}}' },
    ];
    expect(parseFindings(parts)).toHaveLength(1);
  });
});

describe("SdkRunner", () => {
  it("creates a session, prompts the agent, and maps cost/tokens", async () => {
    const calls: string[] = [];
    const fakeClient = {
      session: {
        create: async () => {
          calls.push("create");
          return { data: { id: "sess-1" } };
        },
        prompt: async (args: { path: { id: string }; body?: { agent?: string; parts?: Array<{ type: string; text: string }> } }) => {
          calls.push(`prompt:${args.path.id}:${args.body?.agent}`);
          return {
            data: {
              info: { cost: 0.042, tokens: { input: 100, output: 50, reasoning: 0, cache: { read: 0, write: 0 } } },
              parts: [{ type: "text", text: '{"finding_id":"SAHW-0009","invariant":{"statement":"s","type":"body_contains","expression":"m"},"evidence":{"exploit_response_excerpt":"m"}}' }],
            },
          };
        },
      },
    };

    const runner = new SdkRunner({
      client: fakeClient as never,
      directory: "/work",
      model: { providerID: "openrouter", modelID: "x" },
    });

    const result = await runner.run("recon", "map it");
    expect(calls).toEqual(["create", "prompt:sess-1:recon"]);
    expect(result.costUsd).toBe(0.042);
    expect(result.tokens.input).toBe(100);
    expect(result.findings).toHaveLength(1);
  });

  it("reports stalled when the prompt returns an error", async () => {
    const fakeClient = {
      session: {
        create: async () => ({ data: { id: "sess-1" } }),
        prompt: async () => ({ error: { message: "rate limited" }, data: undefined }),
      },
    };
    const runner = new SdkRunner({ client: fakeClient as never, directory: "/work" });
    const result = await runner.run("recon", "x");
    expect(result.stalled).toBe(true);
    expect(result.findings).toHaveLength(0);
  });
});
