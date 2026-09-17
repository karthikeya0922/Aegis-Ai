/**
 * EU AI Act audit dispatch (Phase 4's final step).
 *
 * `fireAuditAsync` is called from every terminal outcome of the gateway pipeline —
 * gate rejections, grounding blocks, and ordinary completions alike — so an audit
 * event lands for every request, blocked or not. It is deliberately NOT awaited by
 * any call site: the client response must never wait on, or fail because of, the
 * audit write. A failed dispatch (network error, or even a test double missing
 * `writeAudit` entirely) is swallowed here and only logged.
 *
 * Same rule as the rest of the telemetry surface: never pass raw prompt text or a
 * detected secret value in `fields` — only ids, counts, categories and numbers.
 */

import type { AegisAction, AegisErrorCode, AuditLogEntry, DetectionCategory } from "@aegis/types/aegis";
import type { GroundingStatusTelemetry } from "./grounding";

/** Anything that can perform POST /internal/audit. `AegisClient` satisfies this. */
export interface AuditEngine {
  writeAudit(req: { entry: Omit<AuditLogEntry, "id" | "timestamp"> }): Promise<unknown>;
}

export interface AuditFields {
  request_id: string;
  latency_ms: number | null;
  provider_used: string | null;
  model_used: string | null;
  tokens_consumed: number | null;
  cache_hit: boolean;
  failover_used: boolean;
  scrubbed_entity_count: number;
  rule_triggers: readonly string[];
  action: AegisAction;
  error_code: AegisErrorCode;
  /** `null` when the request never reached the grounding check (e.g. blocked at ingress). */
  grounding_status: GroundingStatusTelemetry | null;
  grounding_score: number | null;
  estimated_cost_usd: number | null;
  estimated_savings_usd: number | null;
  estimated_carbon_g: number | null;
}

/** Fire-and-forget: never `await` this from a request-handling path. */
export function fireAuditAsync(engine: AuditEngine, fields: AuditFields): void {
  const entry: Omit<AuditLogEntry, "id" | "timestamp"> = {
    request_id: fields.request_id,
    model_used: fields.model_used,
    tokens_consumed: fields.tokens_consumed,
    latency_ms: fields.latency_ms,
    scrubbed_entity_count: fields.scrubbed_entity_count,
    // The engine's own scan already validated these as DetectionCategory values;
    // by the time they reach here they've been round-tripped through telemetry-safe
    // `string[]` summaries (see ScanSummary), hence the narrowing cast.
    rule_triggers: fields.rule_triggers as DetectionCategory[],
    action: fields.action,
    error_code: fields.error_code,
    provider_used: fields.provider_used,
    cache_hit: fields.cache_hit,
    failover_used: fields.failover_used,
    grounding_status: fields.grounding_status,
    grounding_score: fields.grounding_score,
    estimated_cost_usd: fields.estimated_cost_usd,
    estimated_savings_usd: fields.estimated_savings_usd,
    estimated_carbon_g: fields.estimated_carbon_g,
  };

  Promise.resolve()
    .then(() => engine.writeAudit({ entry }))
    .catch((err: unknown) => {
      console.error(
        `[aegis-gateway] audit dispatch failed for ${fields.request_id}:`,
        err instanceof Error ? err.message : err,
      );
    });
}
