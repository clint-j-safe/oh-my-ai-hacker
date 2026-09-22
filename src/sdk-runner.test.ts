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
    const messages = [
      { id: "m3", type: "idle", outcome: "succeeded" },
      {
        id: "m2",
        type: "assistant",
        cost: 0.042,
        tokens: { input: 100, output: 50, reasoning: 0, cache: { read: 0, write: 0 } },
        content: [
          { type: "reasoning", text: "thinking" },
          { type: "text", text: '{"finding_id":"SAHW-0009","invariant":{"statement":"s","type":"body_contains","expression":"m"},"evidence":{"exploit_response_excerpt":"m"}}' },
        ],
      },
      { id: "m1", type: "user", text: "map it" },
    ];
    const fakeClient = {
      v2: {
        session: {
          create: async (args: { agent?: string; location?: { directory?: string } }) => {
            calls.push(`create:${args.agent}:${args.location?.directory}`);
            return { data: { data: { id: "sess-1" } } };
          },
          client: {
            post: async (o: { url: string; body?: { text?: string; prompt?: { text?: string } } }) => {
              calls.push(`prompt:${o.url}:${o.body?.prompt?.text ?? o.body?.text}`);
              return { data: { data: { id: "msg_user" } } };
            },
            get: async (o: { url: string }) => {
              calls.push(`poll:${o.url}`);
              return { data: { data: messages } };
            },
          },
        },
      },
    };

    const runner = new SdkRunner({ client: fakeClient as never, directory: "/work", pollIntervalMs: 1 });
    const result = await runner.run("recon", "map it");

    expect(calls[0]).toBe("create:recon:/work");
    expect(calls[1]).toBe("prompt:/api/session/sess-1/prompt:map it");
    expect(calls[2]).toBe("poll:/api/session/sess-1/message");
    expect(result.costUsd).toBe(0.042);
    expect(result.tokens.input).toBe(100);
    expect(result.findings).toHaveLength(1);
  });

  it("reports stalled when the prompt returns an error", async () => {
    const fakeClient = {
      v2: {
        session: {
          create: async () => ({ data: { data: { id: "sess-1" } } }),
          client: {
            post: async () => ({ error: { message: "rate limited" }, data: undefined }),
            get: async () => ({ data: { data: [] } }),
          },
        },
      },
    };
    const runner = new SdkRunner({ client: fakeClient as never, directory: "/work", pollIntervalMs: 1 });
    const result = await runner.run("recon", "x");
    expect(result.stalled).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it("throws a clear error when the client has no v2 namespace (version mismatch)", async () => {
    const runner = new SdkRunner({ client: { session: {} } as never, directory: "/work", pollIntervalMs: 1 });
    await expect(runner.run("recon", "x")).rejects.toThrow(/v2 namespace/);
  });

  it("falls back to the bare {text} body when the server rejects {prompt}", async () => {
    const bodies: string[] = [];
    const fakeClient = {
      v2: {
        session: {
          create: async () => ({ data: { data: { id: "sess-1" } } }),
          client: {
            post: async (o: { body?: Record<string, unknown> }) => {
              bodies.push(JSON.stringify(o.body));
              // first shape rejected the way opencode 2.0.x does
              if (o.body && "prompt" in o.body) {
                return { error: { _tag: "InvalidRequestError", message: 'Missing key\n  at ["text"]' }, data: undefined };
              }
              return { data: { data: { id: "msg_user" } } };
            },
            get: async () => ({ data: { data: [{ id: "i", type: "idle", outcome: "succeeded" }] } }),
          },
        },
      },
    };
    const runner = new SdkRunner({ client: fakeClient as never, directory: "/work", pollIntervalMs: 1 });
    await runner.run("recon", "map it");
    expect(bodies[0]).toContain('"prompt"');
    expect(bodies[1]).toBe('{"text":"map it"}');
  });
});