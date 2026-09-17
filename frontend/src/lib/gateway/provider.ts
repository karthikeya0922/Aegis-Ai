/**
 * Provider stage — the only code allowed to talk to an upstream LLM.
 *
 * Its input type is `ScannedPrompt`, which only the scan gate can mint, so it is
 * impossible to call a provider with unscanned messages without a compile error,
 * and an `as` cast is still refused at runtime.
 *
 * Phase 2B: `productionProviderCall` runs the scanned prompt through the real
 * provider registry (`lib/providers/registry.ts`) with circuit-breaker failover
 * (`lib/providers/failover.ts`) instead of the old placeholder response.
 */

import { nanoid } from "nanoid";
import type { ChatRequest, FinishReason } from "@aegis/providers/base";
import { chatWithFailover, type FailoverGroupMember, type FailoverTelemetry } from "@aegis/providers/failover";
import { loadProviderRegistry, type ProviderRegistry } from "@aegis/providers/registry";
import { ScannedPrompt } from "./scan-gate";
import type { Telemetry } from "./telemetry";

/** Client request parameters with `messages` removed — messages come from the prompt only. */
export type ProviderParams = { model: string } & Record<string, unknown>;

export interface ProviderContext {
  request_id: string;
  /**
   * Optional metadata for telemetry and cancellation. Populated by the real gateway
   * pipeline; left undefined by tests that call a `ProviderCall` directly.
   */
  session_id?: string;
  signal?: AbortSignal;
  telemetry?: Telemetry;
  failoverGroup?: FailoverGroupMember[];
}

export interface ChatCompletionResponse {
  id: string;
  object: "chat.completion";
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: { role: "assistant"; content: string };
    logprobs: null;
    finish_reason: FinishReason;
  }>;
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number } | null;
}

export type ProviderCall = (
  prompt: ScannedPrompt,
  params: ProviderParams,
  ctx: ProviderContext,
) => Promise<ChatCompletionResponse>;

/** Wraps a provider implementation with a runtime check that the prompt is genuine. */
export function guardProvider(impl: ProviderCall): ProviderCall {
  return (prompt, params, ctx) => {
    if (!ScannedPrompt.isGenuine(prompt)) {
      return Promise.reject(new Error("Provider stage refused a prompt that did not pass the Aegis scan gate"));
    }
    return impl(prompt, params, ctx);
  };
}

/**
 * Builds a `lib/providers` `ChatRequest` from a scanned prompt + the client's
 * OpenAI-shaped params. Shared by the non-streaming provider call below and by
 * `streaming.ts`'s SSE path so both go through the exact same field mapping.
 */
export function buildChatRequest(prompt: ScannedPrompt, params: ProviderParams, signal: AbortSignal): ChatRequest {
  const temperature = typeof params.temperature === "number" ? params.temperature : undefined;
  const max_tokens = typeof params.max_tokens === "number" ? params.max_tokens : undefined;
  const top_p = typeof params.top_p === "number" ? params.top_p : undefined;
  const stop = Array.isArray(params.stop) && params.stop.every((s) => typeof s === "string") ? (params.stop as string[]) : undefined;

  return {
    model: params.model,
    messages: prompt.messages.map((m) => ({ role: m.role, content: m.content })),
    temperature,
    max_tokens,
    top_p,
    stop,
    signal,
  };
}

/** Maps the internal flat `ChatResponse` back onto the OpenAI-compatible wire shape the route returns. */
export function toChatCompletionResponse(
  response: { id: string; model: string; content: string; finish_reason: FinishReason; usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number } | null },
  fallbackModel: string,
): ChatCompletionResponse {
  return {
    id: response.id || "chatcmpl-" + nanoid(),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: response.model || fallbackModel,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: response.content },
        logprobs: null,
        finish_reason: response.finish_reason,
      },
    ],
    usage: response.usage,
  };
}

/** Records the failover outcome — never message text, only ids/verdicts/counts (same rule as scan telemetry). */
export function recordProviderCompletionTelemetry(
  telemetry: Telemetry | undefined,
  meta: { request_id: string; session_id?: string },
  mode: "chat" | "stream",
  failover: FailoverTelemetry,
): void {
  telemetry?.record({
    type: "provider_completion",
    request_id: meta.request_id,
    session_id: meta.session_id ?? "unknown",
    mode,
    provider_used: failover.used,
    primary_provider: failover.primary,
    primary_failed: failover.primary_failed,
    failover_used: failover.failover_used,
    attempts: failover.attempts,
  });
}

// ---------------------------------------------------------------------------
// Module-level provider registry singleton
// ---------------------------------------------------------------------------

let registryPromise: Promise<ProviderRegistry> | null = null;

/**
 * Loads `config/providers.yaml` once per process and reuses it — this is what makes
 * each provider's `CircuitBreaker` a true long-lived singleton across requests
 * (a breaker rebuilt every request could never accumulate failures or open).
 */
export function getProviderRegistry(): Promise<ProviderRegistry> {
  registryPromise ??= loadProviderRegistry();
  return registryPromise;
}

/** Test-only escape hatch to force a fresh registry load (e.g. after changing env/config). */
export function resetProviderRegistryForTests(): void {
  registryPromise = null;
}

async function defaultFailoverGroup(): Promise<FailoverGroupMember[]> {
  const registry = await getProviderRegistry();
  return registry.getFailoverGroup();
}

/**
 * Builds a `ProviderCall` that runs the scanned prompt through `chatWithFailover`
 * over whatever group `getGroup()` resolves to. Exported (not just the singleton
 * below) so tests can inject a fake, hermetic failover group.
 */
export function createFailoverProviderCall(getGroup: () => Promise<FailoverGroupMember[]>): ProviderCall {
  return guardProvider(async (prompt, params, ctx) => {
    const signal = ctx.signal ?? new AbortController().signal;
    const group = ctx.failoverGroup ?? await getGroup();
    const req = buildChatRequest(prompt, params, signal);
    const { response, telemetry: failover } = await chatWithFailover(group, req);
    recordProviderCompletionTelemetry(ctx.telemetry, ctx, "chat", failover);
    return toChatCompletionResponse(response, params.model);
  });
}

/** The real, production, non-streaming provider stage: registry + circuit breaker + failover. */
export const productionProviderCall: ProviderCall = createFailoverProviderCall(defaultFailoverGroup);
