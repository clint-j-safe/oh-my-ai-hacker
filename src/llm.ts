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
  /** Prompt tokens served from the provider's cache (0 when uncached). */
  cachedTokens: number;
  cost: number;
  finishReason: string;
}

export interface OpenRouterLlmOptions {
  apiKey: string;
  baseUrl?: string;
  /** Attempts on transient upstream errors (429/5xx) before giving up. */
  maxRetries?: number;
  /** Base backoff in ms (doubles each attempt). */
  backoffBaseMs?: number;
}

/** 429 and 5xx from the gateway/provider are transient — worth retrying. */
function isTransient(status: number): boolean {
  return status === 429 || status === 408 || status >= 500;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Exponential backoff with jitter: ~2s, 4s, 8s, 16s, 32s (capped 60s). */
function backoffMs(attempt: number, baseMs: number): number {
  const base = Math.min(baseMs * 2 ** attempt, 60_000);
  return base + Math.floor(Math.random() * Math.min(500, baseMs));
}

export class OpenRouterLlm {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly maxRetries: number;
  private readonly backoffBaseMs: number;

  constructor(opts: OpenRouterLlmOptions) {
    this.apiKey = opts.apiKey;
    this.baseUrl = opts.baseUrl ?? "https://openrouter.ai/api/v1";
    this.maxRetries = opts.maxRetries ?? Number(process.env.SAHW_LLM_RETRIES ?? 5);
    this.backoffBaseMs = opts.backoffBaseMs ?? Number(process.env.SAHW_LLM_BACKOFF_MS ?? 2000);
  }

  /**
   * POST with retry on transient upstream errors. A 429 from the provider is
   * explicitly retryable ("retry shortly"); without this a single rate-limit
   * blip discards an entire multi-hundred-turn engagement.
   */
  private async post(init: RequestInit): Promise<Response> {
    let lastErr = "";
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await fetch(`${this.baseUrl}/chat/completions`, init);
      } catch (e) {
        lastErr = `network: ${(e as Error).message}`;
        if (attempt === this.maxRetries) break;
        await sleep(backoffMs(attempt, this.backoffBaseMs));
        continue;
      }
      if (res.ok) return res;

      const body = await res.text().catch(() => "");
      lastErr = `OpenRouter ${res.status}: ${body.slice(0, 300)}`;
      if (!isTransient(res.status) || attempt === this.maxRetries) {
        throw new Error(lastErr);
      }
      // Honour Retry-After when the gateway supplies it.
      const ra = Number(res.headers.get("retry-after"));
      const waitMs = Number.isFinite(ra) && ra > 0 ? ra * 1000 : backoffMs(attempt, this.backoffBaseMs);
      console.error(`[llm] ${res.status} (attempt ${attempt + 1}/${this.maxRetries + 1}) — retrying in ${Math.round(waitMs / 1000)}s`);
      await sleep(waitMs);
    }
    throw new Error(`OpenRouter request failed after ${this.maxRetries + 1} attempts: ${lastErr}`);
  }

  async complete(opts: {
    model: string;
    messages: LlmMessage[];
    tools?: ToolDef[];
    temperature?: number;
    maxTokens?: number;
    /** Stable per-run key so repeated prefixes hit the same provider cache. */
    cacheKey?: string;
  }): Promise<LlmResponse> {
    const res = await this.post({
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
        // Automatic multi-turn prompt caching: OpenRouter advances the cache
        // breakpoint as the conversation grows. Providers that do not support
        // it ignore the field; the cache key keeps implicit caching on one slot.
        cache_control: { type: "ephemeral", ttl: "1h" },
        ...(opts.cacheKey ? { prompt_cache_key: opts.cacheKey } : {}),
      }),
    });

    const json = (await res.json()) as {
      choices?: Array<{ message?: { role?: string; content?: string | null; tool_calls?: ToolCall[] }; finish_reason?: string }>;
      usage?: {
        prompt_tokens?: number;
        completion_tokens?: number;
        cost?: number;
        prompt_tokens_details?: { cached_tokens?: number };
      };
    };

    const choice = json.choices?.[0] ?? {};
    const message = choice.message ?? {};
    const usage = json.usage ?? {};

    return {
      content: typeof message.content === "string" ? message.content : "",
      toolCalls: message.tool_calls ?? [],
      promptTokens: usage.prompt_tokens ?? 0,
      completionTokens: usage.completion_tokens ?? 0,
      cachedTokens: usage.prompt_tokens_details?.cached_tokens ?? 0,
      cost: typeof usage.cost === "number" ? usage.cost : 0,
      finishReason: choice.finish_reason ?? "stop",
    };
  }
}
