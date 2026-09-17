/**
 * Provider abstraction — the single interface every upstream LLM adapter implements.
 *
 * Nothing outside `lib/providers/*` and the Phase 2B circuit breaker/failover layer
 * should import a specific adapter (`openai-compatible.ts`, `ollama.ts`) directly;
 * callers should get an `LLMProvider` from `registry.ts` so the upstream can be
 * swapped via config alone.
 */

export type ChatRole = "system" | "user" | "assistant";

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

export type FinishReason = "stop" | "length" | "content_filter" | "tool_calls" | null;

export interface ChatRequest {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  stop?: string[];
  /**
   * REQUIRED. Every provider call must be cancellable — by the client disconnecting,
   * by the Phase 2B circuit breaker's connect/total timeouts, or by an internal deadline.
   * Adapters must pass this straight through to `fetch` and must not fabricate their
   * own uncancellable request.
   */
  signal: AbortSignal;
}

export interface ChatUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatResponse {
  id: string;
  model: string;
  content: string;
  finish_reason: FinishReason;
  /** `null` when the upstream doesn't report usage (e.g. some Ollama models). */
  usage: ChatUsage | null;
}

export interface ChatChunk {
  id: string;
  model: string;
  /** Incremental text for this chunk only — not the accumulated content. */
  delta: string;
  finish_reason: FinishReason;
}

export interface LLMProvider {
  /** Stable identifier from config, e.g. "openai", "groq-llama", "ollama-local". */
  readonly name: string;
  chat(req: ChatRequest): Promise<ChatResponse>;
  stream(req: ChatRequest): AsyncIterable<ChatChunk>;
  /** Cheap upstream reachability check used by the Phase 3 circuit breaker. */
  healthCheck(): Promise<boolean>;
}

/**
 * Thrown by adapters for any upstream failure (non-2xx, network error, bad body).
 * The Phase 2B circuit breaker keys failover decisions off `retryable` and `status`.
 *
 * `message` is for a developer reading a stack trace in-process. `publicMessage`
 * is the ONLY text that may cross a trust boundary — it is what the failover
 * layer puts in telemetry and what the SSE path is allowed to surface. Adapters
 * must keep upstream response bodies and internal URLs out of both: an upstream
 * 4xx body frequently echoes the submitted prompt, so it is not safe in logs
 * either.
 */
export class ProviderError extends Error {
  readonly provider: string;
  /** HTTP status from the upstream, or `null` for a network-level failure (no response). */
  readonly status: number | null;
  /** True for 429/5xx/timeouts/network errors — the conditions the breaker fails over on. */
  readonly retryable: boolean;
  /** Redacted, boundary-safe summary: no upstream body, no URL, no credentials. */
  readonly publicMessage: string;

  constructor(
    message: string,
    options: { provider: string; status: number | null; retryable: boolean; cause?: unknown; publicMessage?: string },
  ) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "ProviderError";
    this.provider = options.provider;
    this.status = options.status;
    this.retryable = options.retryable;
    this.publicMessage = options.publicMessage ?? defaultPublicMessage(options.status);
  }
}

/** Status-only summary used when an adapter doesn't supply its own `publicMessage`. */
export function defaultPublicMessage(status: number | null): string {
  if (status === null) return "upstream request failed";
  if (status === 429) return "upstream rate limit (429)";
  if (status >= 500) return `upstream server error (${status})`;
  return `upstream rejected the request (${status})`;
}

/** True for the upstream conditions the circuit breaker fails over on: 500/502/503/429 or a timeout/network error. */
export function isFailoverStatus(status: number | null): boolean {
  return status === null || status === 429 || status === 500 || status === 502 || status === 503;
}
