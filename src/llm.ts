/**
 * Direct LLM client (OpenRouter, OpenAI-compatible). No opencode CLI/server —
 * the model is called over HTTP and wrapped by the deterministic loop. This is
 * the "LLM proposes" half; Tether/Axiom are the "code decides" half.
 */

export interface LlmMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
  name?: string;
}

export interface ToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

export interface ToolDef {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}

export interface LlmResponse {
  content: string;
  toolCalls: ToolCall[];
  promptTokens: number;
  completionTokens: number;
  cost: number;
  finishReason: string;
}

export interface OpenRouterLlmOptions {
  apiKey: string;
  baseUrl?: string;
}

export class OpenRouterLlm {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(opts: OpenRouterLlmOptions) {
    this.apiKey = opts.apiKey;
    this.baseUrl = opts.baseUrl ?? "https://openrouter.ai/api/v1";
  }

  async complete(opts: {
    model: string;
    messages: LlmMessage[];
    tools?: ToolDef[];
    temperature?: number;
    maxTokens?: number;
  }): Promise<LlmResponse> {
    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${this.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: opts.model,
        messages: opts.messages,
        ...(opts.tools?.length ? { tools: opts.tools } : {}),
        temperature: opts.temperature ?? 0.3,
        ...(opts.maxTokens ? { max_tokens: opts.maxTokens } : {}),
      }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`OpenRouter ${res.status}: ${body.slice(0, 300)}`);
    }

    const json = (await res.json()) as {
      choices?: Array<{ message?: { role?: string; content?: string | null; tool_calls?: ToolCall[] }; finish_reason?: string }>;
      usage?: { prompt_tokens?: number; completion_tokens?: number; cost?: number };
    };

    const choice = json.choices?.[0] ?? {};
    const message = choice.message ?? {};
    const usage = json.usage ?? {};

    return {
      content: typeof message.content === "string" ? message.content : "",
      toolCalls: message.tool_calls ?? [],
      promptTokens: usage.prompt_tokens ?? 0,
      completionTokens: usage.completion_tokens ?? 0,
      cost: typeof usage.cost === "number" ? usage.cost : 0,
      finishReason: choice.finish_reason ?? "stop",
    };
  }
}
