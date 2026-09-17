/**
 * Gateway telemetry sink. Events must never contain message text or raw detection
 * matches — only ids, verdicts, codes and counts.
 */

import type { FailoverAttempt } from "@aegis/providers/failover";
import type { GroundingStatusTelemetry } from "./grounding";
import type { ScanSummary } from "./scan-gate";

export type GatewayEvent =
  | { type: "scan_forwarded"; request_id: string; session_id: string; summary: ScanSummary }
  | { type: "scan_warning"; request_id: string; session_id: string; summary: ScanSummary }
  | {
      type: "scan_rejected";
      request_id: string;
      session_id: string;
      status: number;
      code: string;
      summary: ScanSummary | null;
    }
  | {
      type: "provider_completion";
      request_id: string;
      session_id: string;
      mode: "chat" | "stream";
      provider_used: string;
      primary_provider: string;
      primary_failed: boolean;
      failover_used: boolean;
      attempts: FailoverAttempt[];
    }
  | {
      type: "cache_hit";
      request_id: string;
      session_id: string;
      cache_hit: boolean;
      similarity?: number;
      latency_ms?: number;
      estimated_cost_avoided?: number;
    }
  | {
      type: "cost_estimate";
      request_id: string;
      session_id: string;
      model: string;
      estimatedCostUsd: number;
      estimatedEnergyKwh: number;
      estimatedCarbonGrams: number;
    }
  | {
      type: "grounding_result";
      request_id: string;
      session_id: string;
      grounding_status: GroundingStatusTelemetry;
      grounding_score: number | null;
      rehydrated: boolean;
      blocked: boolean;
      /** Count only — the actual `PipelineStage[]` is merged into the response, not logged here. */
      stage_count: number;
      /** `true` when /internal/verify was reached over the network but the response streamed
       * out before it returned, i.e. verification happened strictly after delivery. */
      post_stream: boolean;
    };

export interface Telemetry {
  record(event: GatewayEvent): void;
}

/** Structured-log telemetry until the audit pipeline (Phase 5) exists. */
export const consoleTelemetry: Telemetry = {
  record(event) {
    const line = JSON.stringify({ source: "aegis-gateway", ...event });
    if (
      event.type === "scan_forwarded" ||
      (event.type === "provider_completion" && !event.failover_used) ||
      (event.type === "grounding_result" && event.grounding_status === "pass" && !event.blocked)
    )
      console.info(line);
    else console.warn(line);
  },
};
