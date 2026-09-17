/**
 * Response-path grounding & rehydration (Phase 4).
 *
 * Closes the half of the pipeline that Phase 1B/2B left open: once the provider's
 * text is in hand (buffered, for streaming), this calls `POST /internal/verify`
 * with the vault token from the ingress scan and lets the engine (a) rehydrate its
 * own redaction placeholders back into real entities — but ONLY when the caller
 * asked for it — and (b) score the answer against any reference documents.
 *
 * Two different failure modes, two different rules:
 * - Verify unreachable/malformed/timed out → FAIL OPEN on the text (the provider's
 *   own answer still reaches the client — a dead engine must not turn every chat
 *   into a 5xx) but FAIL CLOSED on the *claim*: telemetry is tagged "unverified",
 *   never "pass". See `runGroundingCheck`'s catch branches.
 * - Verify answers and says `grounding.status === "block"` → the gateway (not the
 *   engine) substitutes its own configured fallback text. This is enforced here so
 *   every call site (buffered and streaming) gets it identically.
 *
 * Secrets are never rehydrated: `shouldRehydrate` is the single place that decides
 * whether to even ask the engine to, and it hardcodes "no" the moment any detection
 * from the ingress scan was a SECRET_* category — independent of `mode`.
 */

import { z } from "zod";
import { getGroundingFallbackText, getVerifyTimeoutMs } from "@aegis/grounding-config";
import type { GroundingStatus, PipelineStage, VerifyRequest, VerifyResponse } from "@aegis/types/aegis";
import type { ForwardedAction } from "./scan-gate";

/** Anything that can perform POST /internal/verify. `AegisClient` satisfies this. */
export interface GroundingEngine {
  verify(req: VerifyRequest): Promise<VerifyResponse>;
}

export interface GroundingInput {
  request_id: string;
  /** The provider's full response text — already buffered, for the streaming path. */
  response_text: string;
  /** From the ingress scan's `ScanResponse.vault_token`. */
  vault_token: string | null;
  /** Parsed from `x-aegis-reference-docs`. Empty when the client sent none. */
  reference_documents: string[];
  /** The ingress scan's verdict for this request. */
  scan_action: ForwardedAction;
  /** The ingress scan's detection categories (telemetry-safe: categories only, never matches). */
  detection_categories: string[];
}

/** What actually happened, reported the same way whether verify succeeded, failed, or blocked. */
export type GroundingStatusTelemetry = GroundingStatus | "unverified";

export interface GroundingOutcome {
  /** The text to actually send to the client. */
  final_text: string;
  /** True only when `grounding.status === "block"` and `final_text` is now the fallback. */
  blocked: boolean;
  /** True iff the engine actually swapped placeholders back into `final_text`. */
  rehydrated: boolean;
  grounding_status: GroundingStatusTelemetry;
  /** `null` when verify never answered (unreachable, timed out, or malformed). */
  grounding_score: number | null;
  /** Stages to merge into this request's telemetry stage array. Empty when verify never answered. */
  stages: PipelineStage[];
}

/** Secrets are never rehydrated — independent of `mode` or what the caller asks for. */
export function shouldRehydrate(scanAction: ForwardedAction, detectionCategories: readonly string[]): boolean {
  if (scanAction !== "sanitize") return false;
  return !detectionCategories.some((category) => category.startsWith("SECRET_"));
}

// Never trust the engine's body shape blindly, same discipline as scan-gate.ts.
const verifyResponseSchema = z.object({
  request_id: z.string(),
  final_text: z.string(),
  rehydrated: z.boolean(),
  grounding: z.object({
    status: z.enum(["pass", "warn", "block"]),
    score: z.number(),
    unsupported_claims: z.array(z.string()),
  }),
  stages: z.array(z.unknown()),
});

function unverified(response_text: string): GroundingOutcome {
  return {
    final_text: response_text,
    blocked: false,
    rehydrated: false,
    grounding_status: "unverified",
    grounding_score: null,
    stages: [],
  };
}

/** Resolves with the engine's raw body, or rejects on error or deadline — mirrors scan-gate.ts. */
function verifyWithDeadline(engine: GroundingEngine, req: VerifyRequest, timeoutMs: number): Promise<unknown> {
  return new Promise<unknown>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`verify timed out after ${timeoutMs}ms`)), timeoutMs);
    (async () => engine.verify(req))().then(
      (body) => {
        clearTimeout(timer);
        resolve(body);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

export async function runGroundingCheck(
  engine: GroundingEngine,
  input: GroundingInput,
  options: { timeoutMs?: number } = {},
): Promise<GroundingOutcome> {
  const timeoutMs = options.timeoutMs ?? getVerifyTimeoutMs();
  const rehydrate = shouldRehydrate(input.scan_action, input.detection_categories);

  const req: VerifyRequest = {
    request_id: input.request_id,
    vault_token: input.vault_token,
    response_text: input.response_text,
    reference_documents: input.reference_documents,
    rehydrate,
  };

  let raw: unknown;
  try {
    raw = await verifyWithDeadline(engine, req, timeoutMs);
  } catch {
    // Fail-closed rule: never claim verified. The provider's own text still goes out.
    return unverified(input.response_text);
  }

  const parsed = verifyResponseSchema.safeParse(raw);
  if (!parsed.success) return unverified(input.response_text);
  const verify = parsed.data;

  // A verdict for a different request is not a verdict for this one.
  if (verify.request_id !== input.request_id) return unverified(input.response_text);

  if (verify.grounding.status === "block") {
    return {
      final_text: getGroundingFallbackText(),
      blocked: true,
      rehydrated: false,
      grounding_status: "block",
      grounding_score: verify.grounding.score,
      stages: verify.stages as PipelineStage[],
    };
  }

  return {
    final_text: verify.final_text,
    blocked: false,
    rehydrated: verify.rehydrated,
    grounding_status: verify.grounding.status,
    grounding_score: verify.grounding.score,
    stages: verify.stages as PipelineStage[],
  };
}
