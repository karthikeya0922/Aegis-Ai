/**
 * Adapter for any OpenAI-compatible `/chat/completions` API — OpenAI itself, Groq,
 * Together, OpenRouter, vLLM/TGI deployments, or GLM-4.6-style endpoints that speak
 * the same wire format. One implementation, config-driven per instance (see
 * `registry.ts` / `config/providers.yaml`).
 */

import {
  type ChatChunk,
  type ChatMessage,
  type ChatRequest,
  type ChatResponse,
  type FinishReason,
  type LLMProvider,
  ProviderError,
} from "./base";
import { assertProviderUrlAllowed, withGuardedDispatcher, type SsrfGuardOptions } from "./ssrf-guard";

export interface OpenAICompatibleConfig {
  /** Stable identifier, e.g. "openai", "groq-llama-70b". */
  name: string;
  /** e.g. "https://api.openai.com/v1" — no trailing slash required. */
  baseUrl: string;
  /**
   * Name of the environment variable holding the API key, e.g. "OPENAI_API_KEY".
   * The key itself is never read from config — only from `process.env` at call time.
   * Omit for endpoints that need no auth (some local/dev gateways).
   */
  apiKeyEnvVar?: string;
  /** Extra static, non-secret headers (e.g. an org header). Never put secrets here. */
  extraHeaders?: Record<string, string>;
  ssrf: Pick<SsrfGuardOptions, "allowedHosts" | "allowPrivateIps">;
  /** Injectable for tests. Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
}

interface OpenAIChatCompletionChoice {
  index: number;
  message?: { role: string; content: string | null };
  delta?: { role?: string; content?: string | null };
  finish_reason: string | null;
}

interface OpenAIChatCompletionBody {
  id?: string;
  model?: string;
  choices?: OpenAIChatCompletionChoice[];
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

const KNOWN_FINISH_REASONS: ReadonlySet<string> = new Set(["stop", "length", "content_filter", "tool_calls"]);

function toFinishReason(raw: string | null | undefined): FinishReason {
  if (raw !== null && raw !== undefined && KNOWN_FINISH_REASONS.has(raw)) {
    return raw as FinishReason;
  }
  return null;
}

function resolveApiKey(envVar: string | undefined, providerName: string): string | null {
  if (!envVar) return null;
  const key = process.env[envVar];
  if (!key) {
    // Retryable on purpose: an unconfigured credential is a reason to move to
    // the next provider in the failover chain, not to fail the whole request.
    throw new ProviderError(`Missing API key: environment variable "${envVar}" is not set for provider "${providerName}"`, {
      provider: providerName,
      status: null,
      retryable: true,
      publicMessage: `provider "${providerName}" is not configured`,
    });
  }
  return key;
}

export class OpenAICompatibleProvider implements LLMProvider {
  readonly name: string;
  private readonly baseUrl: string;
  private readonly apiKeyEnvVar?: string;
  private readonly extraHeaders: Record<string, string>;
  private readonly ssrf: Pick<SsrfGuardOptions, "allowedHosts" | "allowPrivateIps">;
  private readonly fetchImpl: typeof fetch;

  constructor(config: OpenAICompatibleConfig) {
    this.name = config.name;
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.apiKeyEnvVar = config.apiKeyEnvVar;
    this.extraHeaders = config.extraHeaders ?? {};
    this.ssrf = config.ssrf;
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  private async guardedFetch(path: string, init: RequestInit & { signal: AbortSignal }): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    await assertProviderUrlAllowed(this.baseUrl, this.ssrf);

    const apiKey = resolveApiKey(this.apiKeyEnvVar, this.name);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...this.extraHeaders,
      ...(init.headers as Record<string, string> | undefined),
    };
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

    let response: Response;
    try {
      // `dispatcher` re-runs the private-IP check at connect time; see ssrf-guard.ts.
      response = await this.fetchImpl(url, withGuardedDispatcher(init, headers, this.ssrf));
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") throw err;
      // The full URL stays in `message` (in-process only) and out of `publicMessage`.
      throw new ProviderError(`Network error calling ${this.name} at ${url}: ${err instanceof Error ? err.message : String(err)}`, {
        provider: this.name,
        status: null,
        retryable: true,
        cause: err,
        publicMessage: "upstream connection failed",
      });
    }

    if (!response.ok) {
      // The upstream's error body is deliberately NOT captured into the error:
      // 4xx bodies routinely echo the submitted prompt, so putting it in an Error
      // puts prompt text into logs and (on the SSE path) into client responses.
      // Set AEGIS_LOG_UPSTREAM_ERROR_BODIES=true to opt into capturing it while
      // debugging — see the warning in .env.example.
      const raw = await response.text().catch(() => "");
      const debugBody = process.env.AEGIS_LOG_UPSTREAM_ERROR_BODIES === "true" ? `: ${raw.slice(0, 500)}` : "";
      throw new ProviderError(`${this.name} responded ${response.status}${debugBody}`, {
        provider: this.name,
        status: response.status,
        retryable: response.status === 429 || response.status >= 500,
      });
    }

    return response;
  }

  private buildBody(req: ChatRequest, stream: boolean): Record<string, unknown> {
    const body: Record<string, unknown> = {
      model: req.model,
      messages: req.messages satisfies ChatMessage[],
      stream,
    };
    if (req.temperature !== undefined) body.temperature = req.temperature;
    if (req.max_tokens !== undefined) body.max_tokens = req.max_tokens;
    if (req.top_p !== undefined) body.top_p = req.top_p;
    if (req.stop !== undefined) body.stop = req.stop;
    return body;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const response = await this.guardedFetch("/chat/completions", {
      method: "POST",
      body: JSON.stringify(this.buildBody(req, false)),
      signal: req.signal,
    });

    let body: OpenAIChatCompletionBody;
    try {
      body = (await response.json()) as OpenAIChatCompletionBody;
    } catch (err) {
      throw new ProviderError(`${this.name} returned a non-JSON body`, {
        provider: this.name,
        status: response.status,
        retryable: true,
        cause: err,
      });
    }

    const choice = body.choices?.[0];
    if (!choice || choice.message === undefined) {
      throw new ProviderError(`${this.name} response had no choices[0].message`, {
        provider: this.name,
        status: response.status,
        retryable: false,
      });
    }

    return {
      id: body.id ?? "",
      model: body.model ?? req.model,
      content: choice.message.content ?? "",
      finish_reason: toFinishReason(choice.finish_reason),
      usage: body.usage
        ? { prompt_tokens: body.usage.prompt_tokens, completion_tokens: body.usage.completion_tokens, total_tokens: body.usage.total_tokens }
        : null,
    };
  }

  async *stream(req: ChatRequest): AsyncIterable<ChatChunk> {
    const response = await this.guardedFetch("/chat/completions", {
      method: "POST",
      body: JSON.stringify(this.buildBody(req, true)),
      signal: req.signal,
    });

    if (!response.body) {
      throw new ProviderError(`${this.name} streaming response had no body`, {
        provider: this.name,
        status: response.status,
        retryable: true,
      });
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let newlineIndex: number;
        while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
          const line = buffer.slice(0, newlineIndex).trim();
          buffer = buffer.slice(newlineIndex + 1);
          if (line.length === 0 || !line.startsWith("data:")) continue;

          const payload = line.slice("data:".length).trim();
          if (payload === "[DONE]") return;

          let parsed: OpenAIChatCompletionBody;
          try {
            parsed = JSON.parse(payload) as OpenAIChatCompletionBody;
          } catch {
            continue; // skip malformed SSE frame rather than aborting the whole stream
          }

          const choice = parsed.choices?.[0];
          if (!choice) continue;
          yield {
            id: parsed.id ?? "",
            model: parsed.model ?? req.model,
            delta: choice.delta?.content ?? "",
            finish_reason: toFinishReason(choice.finish_reason),
          };
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.guardedFetch("/models", { method: "GET", signal: AbortSignal.timeout(2500) });
      return response.ok;
    } catch {
      return false;
    }
  }
}
