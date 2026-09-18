/**
 * Guarded completion pipeline: scan gate → provider stage → grounding/rehydration
 * stage (Phase 4) → audit dispatch.
 *
 * The provider is only reachable with a `ScannedPrompt`, and the only
 * `ScannedPrompt` in scope is the one returned by a "forward" gate outcome.
 */

import type { AegisErrorCode, AegisMessage, ScanMode } from "@aegis/types/aegis";
import { buildErrorPayload, type GatewayErrorCode } from "@/lib/errors";
import { fireAuditAsync, type AuditEngine } from "./audit";
import { runGroundingCheck, type GroundingEngine } from "./grounding";
import type { InspectorPayload } from "./inspector";
import type { InboundMessages } from "./inbound";
import { type ChatCompletionResponse, type ProviderCall, type ProviderParams, getProviderRegistry } from "./provider";
import { runScanGate, type ScanEngine, type ScannedPrompt, type ScanSummary } from "./scan-gate";
import type { Telemetry } from "./telemetry";

export interface GatewayDeps {
  /** The Aegis engine — a single client satisfying scan, verify AND audit. `AegisClient` does. */
  engine: ScanEngine & GroundingEngine & AuditEngine;
  provider: ProviderCall;
  telemetry: Telemetry;
  scanTimeoutMs?: number;
  verifyTimeoutMs?: number;
}

export interface RequestMeta {
  request_id: string;
  session_id: string;
  mode: ScanMode;
  principal: { tenant: string; key_id: string; dev_fallback: boolean };
  /** Parsed from `x-aegis-reference-docs`. Defaults to `[]` when the client sent none. */
  reference_documents?: string[];
  /** `true` when the client sends `x-aegis-confidential: true`. Forwarded to the engine. */
  confidential_mode?: boolean;
}

export interface GatewayResult {
  status: number;
  body: unknown;
}

export type GateOutcome =
  | { kind: "reject"; result: GatewayResult; inspector: InspectorPayload | null }
  | {
      kind: "forward";
      prompt: ScannedPrompt;
      summary: ScanSummary;
      /** From `ScanResponse.vault_token`. `null` unless this scan sanitized something. */
      vault_token: string | null;
      /** Secret-redacted scan view for the Live Inspector. */
      inspector: InspectorPayload;
    };

function elapsedMs(startedAt: number): number {
  return Date.now() - startedAt;
}

/**
 * `GatewayErrorCode` (HTTP-facing, what the gateway itself decided) and
 * `AegisErrorCode` (engine-verdict-facing, what a Detection/grounding check
 * reported) are different taxonomies. This maps the former onto the closest
 * value in the latter for the audit trail, which only has one `error_code`
 * field. Exhaustive over `GatewayErrorCode` so a new gateway code can't silently
 * fall through unmapped.
 */
function toAuditErrorCode(code: GatewayErrorCode): AegisErrorCode {
  switch (code) {
    case "CREDENTIAL_LEAK_PREVENTED":
    case "PROMPT_INJECTION_BLOCKED":
      return code;
    case "AEGIS_POLICY_BLOCKED":
      return "POLICY_VIOLATION";
    case "AEGIS_ENGINE_UNAVAILABLE":
    case "AEGIS_PROVIDER_UNAVAILABLE":
      return null;
    default: {
      const unhandled: never = code;
      void unhandled;
      return null;
    }
  }
}

/**
 * Runs the scan gate and records its telemetry. Shared by the non-streaming
 * `guardedCompletion` below and by the route's SSE branch (`streaming.ts`'s caller),
 * so both paths fail closed through the exact same code, before either ever touches
 * a provider. Also fires the audit event for rejected requests — "an audit event
 * lands for every request, including blocked ones" doesn't stop at the gate.
 */
export async function runGuardedGate(
  meta: RequestMeta,
  inbound: InboundMessages,
  deps: Pick<GatewayDeps, "engine" | "telemetry" | "scanTimeoutMs">,
): Promise<GateOutcome> {
  const startedAt = Date.now();
  const outcome = await runScanGate(meta, inbound, deps.engine, { timeoutMs: deps.scanTimeoutMs });

  if (outcome.kind === "reject") {
    deps.telemetry.record({
      type: "scan_rejected",
      request_id: meta.request_id,
      session_id: meta.session_id,
      status: outcome.status,
      code: outcome.code,
      summary: outcome.summary,
    });
    fireAuditAsync(deps.engine, {
      request_id: meta.request_id,
      latency_ms: elapsedMs(startedAt),
      provider_used: null,
      model_used: null,
      tokens_consumed: null,
      cache_hit: false,
      failover_used: false,
      scrubbed_entity_count: outcome.summary?.detection_count ?? 0,
      rule_triggers: outcome.summary?.detection_categories ?? [],
      action: outcome.summary?.action ?? "block",
      error_code: toAuditErrorCode(outcome.code),
      grounding_status: null,
      grounding_score: null,
      estimated_cost_usd: null,
      estimated_savings_usd: null,
      estimated_carbon_g: null,
    });
    return {
      kind: "reject",
      result: { status: outcome.status, body: buildErrorPayload(outcome.code, outcome.message, meta.request_id) },
      inspector: outcome.inspector,
    };
  }

  const { prompt, summary, vault_token, inspector } = outcome;
  deps.telemetry.record({
    type: prompt.action === "warn" ? "scan_warning" : "scan_forwarded",
    request_id: meta.request_id,
    session_id: meta.session_id,
    summary,
  });
  return { kind: "forward", prompt, summary, vault_token, inspector };
}

import { getRouteForMessages } from "@aegis/routing/router";
import { checkCache, storeCache } from "@aegis/cache/semantic-cache";
import { estimateCost } from "@aegis/cost";

export async function guardedCompletion(
  meta: RequestMeta & { noCache?: boolean },
  inbound: InboundMessages,
  params: ProviderParams,
  deps: GatewayDeps,
  signal?: AbortSignal,
): Promise<GatewayResult> {
  const startedAt = Date.now();
  const gate = await runGuardedGate(meta, inbound, deps);
  if (gate.kind === "reject") return gate.result;

  // 1. Determine smart route
  const route = getRouteForMessages(gate.prompt.messages as AegisMessage[]);
  const selectedModel = route.model;
  const noCache = meta.noCache || false;

  // 2. Check Semantic Cache AFTER sanitization
  const cacheHit = await checkCache(
    gate.prompt.messages,
    gate.prompt.action,
    gate.summary.detection_categories,
    selectedModel,
    noCache,
    meta.principal.tenant
  );
  if (cacheHit.hit && cacheHit.response) {
    // Record hit telemetry
    deps.telemetry.record({
      type: "cache_hit",
      request_id: meta.request_id,
      session_id: meta.session_id,
      ...cacheHit.telemetry
    });

    // Cache hits are out of scope for the response-path grounding check: the vault
    // token behind any placeholder in a cached response belongs to a DIFFERENT,
    // earlier request, so rehydrating it against this request's vault would be
    // wrong. Cached responses are only ever stored for sanitize/allow verdicts with
    // no secret category (see `lib/cache/semantic-cache.ts`), so nothing here was
    // ever a candidate for rehydration in the first place.
    fireAuditAsync(deps.engine, {
      request_id: meta.request_id,
      latency_ms: elapsedMs(startedAt),
      provider_used: null,
      model_used: selectedModel,
      tokens_consumed: null,
      cache_hit: true,
      failover_used: false,
      scrubbed_entity_count: gate.summary.detection_count,
      rule_triggers: gate.summary.detection_categories,
      action: gate.prompt.action,
      error_code: null,
      grounding_status: null,
      grounding_score: null,
      estimated_cost_usd: 0,
      estimated_savings_usd: cacheHit.telemetry.estimated_cost_avoided ?? null,
      estimated_carbon_g: null,
    });

    // We must return the placeholder text AS-IS.
    // The tokens out can be estimated from response length for cost avoided.
    return {
      status: 200,
      body: {
        id: "chatcmpl-" + meta.request_id,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: selectedModel,
        choices: [{
          index: 0,
          message: { role: "assistant", content: cacheHit.response },
          finish_reason: "stop"
        }]
      }
    };
  }

  // 3. Provider Call. A small local telemetry wrapper remembers the
  // `provider_completion` event's verdict (without changing `provider.ts`'s
  // contract) so the audit dispatch below can report the provider actually used.
  let providerUsed: string | null = null;
  let failoverUsed = false;
  const capturingTelemetry: Telemetry = {
    record(event) {
      if (event.type === "provider_completion") {
        providerUsed = event.provider_used;
        failoverUsed = event.failover_used;
      }
      deps.telemetry.record(event);
    },
  };

  const registry = await getProviderRegistry();
  const failoverGroup = registry.getFailoverGroupFor(route);

  // Update params with smart routed model if not strictly overridden
  const callParams = { ...params, model: selectedModel };
  let completion: ChatCompletionResponse;
  try {
    completion = await deps.provider(gate.prompt, callParams, {
      request_id: meta.request_id,
      session_id: meta.session_id,
      signal,
      telemetry: capturingTelemetry,
      failoverGroup,
    });
  } catch (err) {
    // A total provider failure (every provider in the chain down, or a config
    // error) must still land an audit event and a structured error response —
    // "an audit event lands for every request" doesn't stop at the gate, and
    // letting this throw would surface as an opaque 500 from route.ts's
    // catch-all instead of a code the client/dashboard can act on.
    const message = err instanceof Error ? err.message : String(err);
    fireAuditAsync(deps.engine, {
      request_id: meta.request_id,
      latency_ms: elapsedMs(startedAt),
      provider_used: providerUsed,
      model_used: selectedModel,
      tokens_consumed: null,
      cache_hit: false,
      failover_used: failoverUsed,
      scrubbed_entity_count: gate.summary.detection_count,
      rule_triggers: gate.summary.detection_categories,
      action: gate.prompt.action,
      error_code: null,
      grounding_status: null,
      grounding_score: null,
      estimated_cost_usd: null,
      estimated_savings_usd: null,
      estimated_carbon_g: null,
    });
    return {
      status: 502,
      body: buildErrorPayload(
        "AEGIS_PROVIDER_UNAVAILABLE",
        `All configured upstream providers failed: ${message}`,
        meta.request_id,
      ),
    };
  }

  // 4. Record Cost Telemetry
  const tokensIn = Math.ceil(JSON.stringify(gate.prompt.messages).length / 4);
  const responseContent = completion.choices[0]?.message?.content ?? "";
  const tokensOut = Math.ceil(responseContent.length / 4);

  const cost = estimateCost(selectedModel, tokensIn, tokensOut);
  deps.telemetry.record({
    type: "cost_estimate",
    request_id: meta.request_id,
    session_id: meta.session_id,
    model: selectedModel,
    ...cost
  });

  // 5. Store Cache (the RAW provider text — never the grounding-checked/rehydrated
  // text below, which is specific to this request's vault token and verdict).
  if (responseContent) {
    await storeCache(
      gate.prompt.messages,
      gate.prompt.action,
      gate.summary.detection_categories,
      responseContent,
      tokensOut,
      meta.principal.tenant
    );
  }

  // 6. Response-path grounding & rehydration (Phase 4). Fails open on the text
  // (the provider's answer still ships) and closed on the claim (never "pass"
  // when verify didn't actually run) — see `grounding.ts`.
  const grounding = await runGroundingCheck(
    deps.engine,
    {
      request_id: meta.request_id,
      response_text: responseContent,
      vault_token: gate.vault_token,
      reference_documents: meta.reference_documents ?? [],
      scan_action: gate.prompt.action,
      detection_categories: gate.summary.detection_categories,
    },
    { timeoutMs: deps.verifyTimeoutMs },
  );

  deps.telemetry.record({
    type: "grounding_result",
    request_id: meta.request_id,
    session_id: meta.session_id,
    grounding_status: grounding.grounding_status,
    grounding_score: grounding.grounding_score,
    rehydrated: grounding.rehydrated,
    blocked: grounding.blocked,
    stage_count: grounding.stages.length,
    post_stream: false,
  });

  const finalCompletion = {
    ...completion,
    choices: completion.choices.map((choice, index) =>
      index === 0 ? { ...choice, message: { ...choice.message, content: grounding.final_text } } : choice,
    ),
  };

  fireAuditAsync(deps.engine, {
    request_id: meta.request_id,
    latency_ms: elapsedMs(startedAt),
    provider_used: providerUsed,
    model_used: selectedModel,
    tokens_consumed: tokensIn + tokensOut,
    cache_hit: false,
    failover_used: failoverUsed,
    scrubbed_entity_count: gate.summary.detection_count,
    rule_triggers: gate.summary.detection_categories,
    action: gate.prompt.action,
    error_code: grounding.blocked ? "HALLUCINATION_DETECTED" : null,
    grounding_status: grounding.grounding_status,
    grounding_score: grounding.grounding_score,
    estimated_cost_usd: cost.estimatedCostUsd,
    estimated_savings_usd: null,
    estimated_carbon_g: cost.estimatedCarbonGrams,
  });

  return { status: 200, body: finalCompletion };
}
