/**
 * SSE streaming response for `POST /v1/chat/completions` with `stream: true`.
 *
 * Wire format matches OpenAI's streaming `chat.completion.chunk`: each event is
 * `data: {...}\n\n`, terminated by a literal `data: [DONE]\n\n`. Aegis adds two
 * extra named events, both ignored by plain OpenAI-client `data:`-only parsers
 * (so this is additive, not breaking):
 *   - `aegis.telemetry` — the pipeline's stage/failover data.
 *   - `aegis.grounding` — the Phase 4 response-path grounding/rehydration verdict.
 * Both are emitted right before `[DONE]`.
 *
 * The full assistant text is buffered as it streams out (`bufferedText` below) so
 * the grounding/rehydration check can run against the complete answer once the
 * stream ends, without re-requesting it from the provider.
 *
 * IMPORTANT KNOWN LIMITATION (by design, not an oversight): the client has already
 * received the RAW, un-rehydrated token stream by the time `/internal/verify` is
 * even called — token-by-token rehydration mid-stream is not implemented. So on a
 * "sanitize" verdict, whatever placeholders (e.g. "[EMAIL_1]") went out in the live
 * `chat.completion.chunk` deltas stay exactly as sent; they are NOT retroactively
 * patched. `aegis.grounding` instead carries the engine's rehydrated `final_text`
 * (when `rehydrated: true`) as a single field so a UI can reconcile/replace what it
 * displayed, and the fallback text on a "block" verdict for the same reason —
 * verification is unavoidably post-stream here. Do not "fix" this by buffering the
 * whole response before streaming; that would defeat streaming entirely. A
 * genuinely inline (per-chunk) grounding check would need the engine to score
 * partial answers, which it does not do.
 */

import { nanoid } from "nanoid";
import type { FailoverGroupMember, FailoverTelemetry } from "@aegis/providers/failover";
import { streamWithFailover } from "@aegis/providers/failover";
import type { AuditEngine } from "./audit";
import { fireAuditAsync } from "./audit";
import type { GroundingEngine, GroundingStatusTelemetry } from "./grounding";
import { runGroundingCheck } from "./grounding";
import { buildChatRequest, type ProviderParams, recordProviderCompletionTelemetry, getProviderRegistry } from "./provider";
import type { InspectorPayload } from "./inspector";
import type { ScannedPrompt, ScanSummary } from "./scan-gate";
import type { Telemetry } from "./telemetry";

export interface StreamContext {
  request_id: string;
  session_id: string;
  principal: { tenant: string; key_id: string; dev_fallback: boolean };
  noCache: boolean;
  /** From the ingress scan's `ScanResponse.vault_token`. `null`/absent unless it sanitized. */
  vault_token?: string | null;
  /** Parsed from `x-aegis-reference-docs`. Defaults to `[]` when the client sent none. */
  reference_documents?: string[];
  verifyTimeoutMs?: number;
  /** Secret-redacted scan view, emitted once as an `aegis.scan` frame. */
  inspector?: InspectorPayload | null;
}

function sseEvent(event: string | null, data: unknown): string {
  const lines: string[] = [];
  if (event) lines.push(`event: ${event}`);
  lines.push(`data: ${JSON.stringify(data)}`);
  return lines.join("\n") + "\n\n";
}

const DONE_FRAME = "data: [DONE]\n\n";

import { getRouteForMessages } from "@aegis/routing/router";
import { checkCache, storeCache } from "@aegis/cache/semantic-cache";
import { estimateCost } from "@aegis/cost";
import type { AegisMessage } from "@aegis/types/aegis";

export function buildStreamingResponse(
  prompt: ScannedPrompt,
  summary: ScanSummary,
  params: ProviderParams,
  ctx: StreamContext,
  telemetry: Telemetry,
  engine: GroundingEngine & AuditEngine,
  extraHeaders: HeadersInit = {},
): Response {
  const encoder = new TextEncoder();
  const abortController = new AbortController();
  const chatId = "chatcmpl-" + nanoid();
  const created = Math.floor(Date.now() / 1000);
  
  const route = getRouteForMessages(prompt.messages as AegisMessage[]);
  const selectedModel = route.model;
  const noCache = ctx.noCache || false;

  const body = new ReadableStream<Uint8Array>({
    async start(controller) {
      const startedAt = Date.now();

      // First frame: what the guardrails found. Already secret-redacted by
      // `toInspectorPayload` — this is the only scan detail a browser ever sees.
      if (ctx.inspector) {
        controller.enqueue(encoder.encode(sseEvent("aegis.scan", ctx.inspector)));
      }

      let failover: FailoverTelemetry | null = null;
      let streamError: string | null = null;
      let bufferedText = "";

      const cacheHit = await checkCache(
        prompt.messages,
        prompt.action,
        summary.detection_categories,
        selectedModel,
        noCache,
        ctx.principal.tenant
      );
      if (cacheHit.hit && cacheHit.response) {
        telemetry.record({
          type: "cache_hit",
          request_id: ctx.request_id,
          session_id: ctx.session_id,
          ...cacheHit.telemetry
        });
        
        // Output entire cache response as one chunk then finish
        const payload = {
          id: chatId,
          object: "chat.completion.chunk" as const,
          created,
          model: selectedModel,
          choices: [
            {
              index: 0,
              delta: { content: cacheHit.response },
              finish_reason: "stop",
            },
          ],
        };
        controller.enqueue(encoder.encode(sseEvent(null, payload)));
        
        controller.enqueue(
          encoder.encode(
            sseEvent("aegis.telemetry", {
              request_id: ctx.request_id,
              cache_hit: true,
              response_length: cacheHit.response.length,
              stages: ctx.inspector?.stages ?? [],
            }),
          ),
        );
        controller.enqueue(encoder.encode(DONE_FRAME));
        controller.close();

        // Out of scope for grounding — see the matching comment in pipeline.ts's
        // cache-hit branch (a cached response's vault token belongs to a different,
        // earlier request).
        fireAuditAsync(engine, {
          request_id: ctx.request_id,
          latency_ms: Date.now() - startedAt,
          provider_used: null,
          model_used: selectedModel,
          tokens_consumed: null,
          cache_hit: true,
          failover_used: false,
          scrubbed_entity_count: summary.detection_count,
          rule_triggers: summary.detection_categories,
          action: prompt.action,
          error_code: null,
          grounding_status: null,
          grounding_score: null,
          estimated_cost_usd: 0,
          estimated_savings_usd: cacheHit.telemetry.estimated_cost_avoided ?? null,
          estimated_carbon_g: null,
        });
        return;
      }

      // ---
      // 3. Provider Stream
      // ---
      try {
        const registry = await getProviderRegistry();
        const failoverGroup = registry.getFailoverGroupFor(route);
        const req = buildChatRequest(prompt, { ...params, model: selectedModel }, abortController.signal);
        const { chunks, telemetry: failoverTelemetry } = await streamWithFailover(failoverGroup, req);
        failover = failoverTelemetry;

        for await (const chunk of chunks) {
          bufferedText += chunk.delta;
          const payload = {
            id: chatId,
            object: "chat.completion.chunk" as const,
            created,
            model: chunk.model || params.model,
            choices: [
              {
                index: 0,
                delta: chunk.delta.length > 0 ? { content: chunk.delta } : {},
                finish_reason: chunk.finish_reason,
              },
            ],
          };
          controller.enqueue(encoder.encode(sseEvent(null, payload)));
        }
      } catch (err) {
        // A stream that dies mid-flight still gets a defined end (a terminal chunk +
        // aegis.telemetry + [DONE]) rather than an abrupt socket close, so any
        // OpenAI-compatible SSE client sees a clean finish instead of a hang/parse error.
        streamError = err instanceof Error ? err.message : String(err);
        controller.enqueue(
          encoder.encode(
            sseEvent(null, {
              id: chatId,
              object: "chat.completion.chunk" as const,
              created,
              model: params.model,
              choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
            }),
          ),
        );
      } finally {
        const fallbackGroup = (await getProviderRegistry()).getFailoverGroupFor(route);
        const usedFailover: FailoverTelemetry = failover ?? {
          primary: fallbackGroup[0]?.provider.name ?? "none",
          used: fallbackGroup[0]?.provider.name ?? "none",
          primary_failed: true,
          failover_used: false,
          attempts: [],
        };

        recordProviderCompletionTelemetry(telemetry, ctx, "stream", usedFailover);

        let cost = { estimatedCostUsd: 0, estimatedEnergyKwh: 0, estimatedCarbonGrams: 0 };
        // "unverified": grounding never ran (streamError, or nothing to ground/rehydrate) —
        // this is reported honestly rather than as a false "pass".
        let groundingStatus: GroundingStatusTelemetry = "unverified";
        let groundingScore: number | null = null;

        if (!streamError && bufferedText.length > 0) {
          const tokensIn = Math.ceil(JSON.stringify(prompt.messages).length / 4);
          const tokensOut = Math.ceil(bufferedText.length / 4);
          cost = estimateCost(selectedModel, tokensIn, tokensOut);

          telemetry.record({
            type: "cost_estimate",
            request_id: ctx.request_id,
            session_id: ctx.session_id,
            model: selectedModel,
            ...cost
          });

          // Fire-and-forget: the client already has [DONE] by the time this settles,
          // and a cache write must never delay or fail the stream.
          storeCache(
            prompt.messages,
            prompt.action,
            summary.detection_categories,
            bufferedText,
            tokensOut,
            ctx.principal.tenant
          ).catch(console.error);

          // Response-path grounding & rehydration (Phase 4). Runs AFTER the raw
          // stream already finished — see the file header for why this can't be
          // any earlier. Fails open on the text (nothing further to send to the
          // client at this point besides the trailing events below) and closed on
          // the claim, exactly like the buffered path in pipeline.ts.
          const grounding = await runGroundingCheck(
            engine,
            {
              request_id: ctx.request_id,
              response_text: bufferedText,
              vault_token: ctx.vault_token ?? null,
              reference_documents: ctx.reference_documents ?? [],
              scan_action: prompt.action,
              detection_categories: summary.detection_categories,
            },
            { timeoutMs: ctx.verifyTimeoutMs },
          );
          groundingStatus = grounding.grounding_status;
          groundingScore = grounding.grounding_score;

          telemetry.record({
            type: "grounding_result",
            request_id: ctx.request_id,
            session_id: ctx.session_id,
            grounding_status: grounding.grounding_status,
            grounding_score: grounding.grounding_score,
            rehydrated: grounding.rehydrated,
            blocked: grounding.blocked,
            stage_count: grounding.stages.length,
            post_stream: true,
          });

          controller.enqueue(
            encoder.encode(
              sseEvent("aegis.grounding", {
                request_id: ctx.request_id,
                grounding: {
                  status: grounding.grounding_status,
                  score: grounding.grounding_score,
                },
                rehydrated: grounding.rehydrated,
                blocked: grounding.blocked,
                // The reconciled text (rehydrated, or the fallback on a block) — the
                // live chunks above already went out raw and are NOT retroactively
                // patched; see the file header.
                final_text: grounding.final_text,
                verified_post_stream: true,
              }),
            ),
          );

          fireAuditAsync(engine, {
            request_id: ctx.request_id,
            latency_ms: Date.now() - startedAt,
            provider_used: usedFailover.used,
            model_used: selectedModel,
            tokens_consumed: tokensIn + tokensOut,
            cache_hit: false,
            failover_used: usedFailover.failover_used,
            scrubbed_entity_count: summary.detection_count,
            rule_triggers: summary.detection_categories,
            action: prompt.action,
            error_code: grounding.blocked ? "HALLUCINATION_DETECTED" : null,
            grounding_status: grounding.grounding_status,
            grounding_score: grounding.grounding_score,
            estimated_cost_usd: cost.estimatedCostUsd,
            estimated_savings_usd: null,
            estimated_carbon_g: cost.estimatedCarbonGrams,
          });
        } else {
          // Nothing to ground (a stream error, or an empty completion) — still
          // audit the attempt, per "an audit event lands for every request".
          fireAuditAsync(engine, {
            request_id: ctx.request_id,
            latency_ms: Date.now() - startedAt,
            provider_used: usedFailover.used,
            model_used: selectedModel,
            tokens_consumed: null,
            cache_hit: false,
            failover_used: usedFailover.failover_used,
            scrubbed_entity_count: summary.detection_count,
            rule_triggers: summary.detection_categories,
            action: prompt.action,
            // A stream failure is a provider/network problem, not a guardrail
            // verdict — `AegisErrorCode` has no slot for that, so this stays null.
            error_code: null,
            grounding_status: null,
            grounding_score: null,
            estimated_cost_usd: 0,
            estimated_savings_usd: null,
            estimated_carbon_g: 0,
          });
        }

        controller.enqueue(
          encoder.encode(
            sseEvent("aegis.telemetry", {
              request_id: ctx.request_id,
              provider_used: usedFailover.used,
              primary_provider: usedFailover.primary,
              primary_failed: usedFailover.primary_failed,
              failover_used: usedFailover.failover_used,
              response_length: bufferedText.length,
              error: streamError,
              grounding_status: groundingStatus,
              grounding_score: groundingScore,
              cache_hit: false,
              stages: ctx.inspector?.stages ?? [],
            }),
          ),
        );
        controller.enqueue(encoder.encode(DONE_FRAME));
        controller.close();
      }
    },
    cancel() {
      abortController.abort(new DOMException("Client disconnected", "AbortError"));
    },
  });

  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", "text/event-stream");
  headers.set("Cache-Control", "no-cache, no-transform");
  headers.set("Connection", "keep-alive");
  headers.set("x-request-id", ctx.request_id);

  return new Response(body, { status: 200, headers });
}
