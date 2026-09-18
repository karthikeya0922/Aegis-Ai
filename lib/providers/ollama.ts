/**
 * Adapter for a local Ollama server (`/api/chat`). No API key — Ollama is local by
 * design — but it still goes through the same SSRF guard as every other provider:
 * its default `http://localhost:11434` base_url resolves to a loopback IP, which the
 * guard rejects unless `AEGIS_PROVIDER_ALLOW_PRIVATE_IPS=true` is set explicitly.
 */

import {
  type ChatChunk,
  type ChatMessage,
  type ChatRequest,
  type ChatResponse,
  type LLMProvider,
  ProviderError,
} from "./base";
import { assertProviderUrlAllowed, withGuardedDispatcher, type SsrfGuardOptions } from "./ssrf-guard";

export interface OllamaConfig {
  /** Stable identifier, e.g. "ollama-local". */
  name: string;
  /** e.g. "http://localhost:11434" — no trailing slash required. */
  baseUrl: string;
  ssrf: Pick<SsrfGuardOptions, "allowedHosts" | "allowPrivateIps">;
  /** Injectable for tests. Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
}

interface OllamaChatMessage {
  role: string;
  content: string;
}

interface OllamaChatResponseBody {
  model?: string;
  message?: OllamaChatMessage;
  done?: boolean;
  done_reason?: string;
  prompt_eval_count?: number;
  eval_count?: number;
}

function finishReasonFromDoneReason(doneReason: string | undefined): ChatResponse["finish_reason"] {
  if (doneReason === "length") return "length";
  if (doneReason === "stop" || doneReason === undefined) return "stop";
  return null;
}

export class OllamaProvider implements LLMProvider {
  readonly name: string;
  private readonly baseUrl: string;
  private readonly ssrf: Pick<SsrfGuardOptions, "allowedHosts" | "allowPrivateIps">;
  private readonly fetchImpl: typeof fetch;

  constructor(config: OllamaConfig) {
    this.name = config.name;
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.ssrf = config.ssrf;
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  private async guardedFetch(path: string, init: RequestInit & { signal: AbortSignal }): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    await assertProviderUrlAllowed(this.baseUrl, this.ssrf);

    let response: Response;
    try {
      // `dispatcher` re-runs the private-IP check at connect time; see ssrf-guard.ts.
      const headers = { "Content-Type": "application/json", ...(init.headers as Record<string, string> | undefined) };
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
      // Upstream error bodies are not captured — see the matching comment in
      // openai-compatible.ts. Opt in with AEGIS_LOG_UPSTREAM_ERROR_BODIES=true.
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
    const options: Record<string, unknown> = {};
    if (req.temperature !== undefined) options.temperature = req.temperature;
    if (req.top_p !== undefined) options.top_p = req.top_p;
    if (req.stop !== undefined) options.stop = req.stop;
    if (req.max_tokens !== undefined) options.num_predict = req.max_tokens;

    return {
      model: req.model,
      messages: req.messages satisfies ChatMessage[],
      stream,
      ...(Object.keys(options).length > 0 ? { options } : {}),
    };
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const response = await this.guardedFetch("/api/chat", {
      method: "POST",
      body: JSON.stringify(this.buildBody(req, false)),
      signal: req.signal,
    });

    let body: OllamaChatResponseBody;
    try {
      body = (await response.json()) as OllamaChatResponseBody;
    } catch (err) {
      throw new ProviderError(`${this.name} returned a non-JSON body`, {
        provider: this.name,
        status: response.status,
        retryable: true,
        cause: err,
      });
    }

    if (!body.message) {
      throw new ProviderError(`${this.name} response had no message`, {
        provider: this.name,
        status: response.status,
        retryable: false,
      });
    }

    return {
      id: "",
      model: body.model ?? req.model,
      content: body.message.content,
      finish_reason: finishReasonFromDoneReason(body.done_reason),
      usage:
        body.prompt_eval_count !== undefined && body.eval_count !== undefined
          ? {
              prompt_tokens: body.prompt_eval_count,
              completion_tokens: body.eval_count,
              total_tokens: body.prompt_eval_count + body.eval_count,
            }
          : null,
    };
  }

  /** Ollama streams newline-delimited JSON objects, one per line — not SSE. */
  async *stream(req: ChatRequest): AsyncIterable<ChatChunk> {
    const response = await this.guardedFetch("/api/chat", {
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
          if (line.length === 0) continue;

          let parsed: OllamaChatResponseBody;
          try {
            parsed = JSON.parse(line) as OllamaChatResponseBody;
          } catch {
            continue; // skip malformed NDJSON line rather than aborting the whole stream
          }

          yield {
            id: "",
            model: parsed.model ?? req.model,
            delta: parsed.message?.content ?? "",
            finish_reason: parsed.done ? finishReasonFromDoneReason(parsed.done_reason) : null,
          };

          if (parsed.done) return;
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const url = `${this.baseUrl}/api/tags`;
      await assertProviderUrlAllowed(this.baseUrl, this.ssrf);
      const response = await this.fetchImpl(url, { method: "GET", signal: AbortSignal.timeout(2500) });
      return response.ok;
    } catch {
      return false;
    }
  }
}
