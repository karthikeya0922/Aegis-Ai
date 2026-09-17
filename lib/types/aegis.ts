/**
 * Aegis — shared contract types.
 *
 * This file is the single source of truth for the shape of every request/response
 * exchanged between the Aegis frontend/gateway and Person 1's security engine
 * (real Python service, or the mock in `mocks/engine/server.ts`).
 *
 * Both sides MUST import from here rather than re-declaring shapes locally.
 * Endpoints covered: /internal/scan, /internal/verify, /internal/audit,
 * /internal/policies, /internal/health.
 */

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

/**
 * The verdict the engine reaches for a given request.
 * - "allow":    forward the original messages unchanged.
 * - "warn":     forward the original messages, but record the warning in telemetry.
 * - "sanitize": forward ONLY `sanitized_messages` (placeholders in place of raw entities).
 * - "block":    never forward; the gateway maps `error_code` to a 400/403.
 */
export type AegisAction = "allow" | "warn" | "sanitize" | "block";

/**
 * Gateway scan mode, taken from the client's `x-aegis-mode` header.
 * "sanitize" (default) lets the engine redact and continue; "strict" asks the engine
 * to prefer blocking over sanitizing.
 */
export type ScanMode = "sanitize" | "strict";

/** Machine-readable reason attached to a non-"allow" action. `null` when allowed. */
export type AegisErrorCode =
  | "CREDENTIAL_LEAK_PREVENTED"
  | "PROMPT_INJECTION_BLOCKED"
  | "PII_LEAK_PREVENTED"
  | "HALLUCINATION_DETECTED"
  | "POLICY_VIOLATION"
  | null;

/** Taxonomy of everything the guardrails know how to find. */
export type DetectionCategory =
  // PII (Feature 1)
  | "PII_EMAIL"
  | "PII_PHONE"
  | "PII_SSN"
  | "PII_CREDIT_CARD"
  | "PII_PERSON_NAME"
  // Developer secrets (Feature 1)
  | "SECRET_AWS_ACCESS_KEY"
  | "SECRET_AWS_SECRET_KEY"
  | "SECRET_DB_CONNECTION_STRING"
  | "SECRET_JWT"
  | "SECRET_API_KEY"
  // Safety (Feature 4)
  | "PROMPT_INJECTION";

/** A single entity the engine found in a message. */
export interface Detection {
  category: DetectionCategory;
  /** The raw substring that matched (already-redacted text may still be logged safely upstream). */
  match: string;
  /** Reversible placeholder inserted into `sanitized_messages`, e.g. "[EMAIL_1]". `null` for block-only detections that are never sanitized. */
  placeholder: string | null;
  /** Character offset of `match` within the source message content. */
  start: number;
  /** Character offset (exclusive) of the end of `match`. */
  end: number;
  /** Engine confidence in [0, 1]. */
  confidence: number;
  /** Index into the `messages` array this detection came from. */
  message_index: number;
}

/** One step of the visible inspection pipeline (for the "Live Jury Visualizer"). */
export interface PipelineStage {
  /** Stable machine name, e.g. "pii_secret_scan", "prompt_injection_check", "sanitize". */
  name: string;
  status: "pass" | "flagged" | "blocked" | "skipped";
  duration_ms: number;
  detail?: string;
}

export interface AegisMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

// ---------------------------------------------------------------------------
// POST /internal/scan — ingress PII/secret/injection scan (Features 1 & 4)
// ---------------------------------------------------------------------------

export interface ScanRequest {
  request_id: string;
  /** Stable per-client session id (gateway `session_id` cookie / `x-session-id` header). */
  session_id: string;
  messages: AegisMessage[];
  mode: ScanMode;
  /** "Confidential Mode" toggle from the client UI — engine may apply stricter policy. */
  confidential_mode?: boolean;
  metadata?: Record<string, string>;
}

export interface ScanResponse {
  request_id: string;
  action: AegisAction;
  error_code: AegisErrorCode;
  detections: Detection[];
  /** Present only when `action === "sanitize"`; otherwise `null`. */
  sanitized_messages: AegisMessage[] | null;
  /**
   * Opaque handle into the engine-side redaction vault, keyed by `request_id`.
   * Present only when `action === "sanitize"` (there is something to rehydrate
   * from); `null` otherwise. The gateway never sees the raw entities themselves —
   * it only ever passes this token back to `/internal/verify` on egress so the
   * engine can rehydrate its own placeholders. Resolves Phase 1B's open question
   * on egress re-hydration (see `docs/PROJECT.md`).
   */
  vault_token: string | null;
  stages: PipelineStage[];
  processed_at: string;
}

// ---------------------------------------------------------------------------
// POST /internal/verify — response-path grounding & rehydration (Feature 1 egress + Feature 3)
// ---------------------------------------------------------------------------

/**
 * - "pass":  the answer is adequately grounded in `reference_documents` (or there
 *            were none to check against); `final_text` is safe to return as-is.
 * - "warn":  weakly grounded but not risky enough to block; forward `final_text`
 *            and record the warning.
 * - "block": unsupported claims exceeded policy; the GATEWAY (not the engine)
 *            substitutes its own configured fallback text — see
 *            `frontend/src/lib/gateway/grounding.ts`.
 */
export type GroundingStatus = "pass" | "warn" | "block";

export interface GroundingResult {
  status: GroundingStatus;
  /** Faithfulness/grounding score in [0, 1]; higher is better supported by `reference_documents`. */
  score: number;
  unsupported_claims: string[];
}

export interface VerifyRequest {
  request_id: string;
  /** From `ScanResponse.vault_token`. `null` when the ingress scan never sanitized anything. */
  vault_token: string | null;
  /** The full (already-buffered, for streaming) assistant response text. */
  response_text: string;
  /** Retrieved reference chunks the answer must be grounded in. May be empty. */
  reference_documents: string[];
  /**
   * Ask the engine to swap its own placeholders back to the original entities in
   * `response_text` before returning `final_text`. The gateway MUST only ever set
   * this `true` when the scan action was "sanitize" AND no detection in that scan
   * had a secret category — secrets are never rehydrated, engine-side or gateway-side.
   */
  rehydrate: boolean;
}

export interface VerifyResponse {
  request_id: string;
  /** What the client should ultimately receive, absent a "block" grounding verdict. */
  final_text: string;
  /** True iff the engine actually swapped placeholders back into `final_text`. */
  rehydrated: boolean;
  grounding: GroundingResult;
  stages: PipelineStage[];
  processed_at: string;
}

// ---------------------------------------------------------------------------
// POST /internal/audit — EU AI Act audit trail (Feature 5)
// ---------------------------------------------------------------------------

export interface AuditLogEntry {
  id: string;
  request_id: string;
  timestamp: string;
  model_used: string | null;
  tokens_consumed: number | null;
  latency_ms: number | null;
  scrubbed_entity_count: number;
  rule_triggers: DetectionCategory[];
  action: AegisAction;
  error_code: AegisErrorCode;
  /** Upstream provider actually used (post-failover), or `null` when no provider was ever called. */
  provider_used: string | null;
  cache_hit: boolean;
  failover_used: boolean;
  /**
   * `null` when the response-path grounding check never ran (e.g. the request was
   * blocked at the ingress scan, before any provider call). "unverified" means
   * `/internal/verify` was unreachable — never reported as a grounding pass.
   */
  grounding_status: GroundingStatus | "unverified" | null;
  grounding_score: number | null;
  estimated_cost_usd: number | null;
  estimated_savings_usd: number | null;
  estimated_carbon_g: number | null;
}

/** Body for writing a new audit entry. */
export interface AuditLogRequest {
  entry: Omit<AuditLogEntry, "id" | "timestamp">;
}

export interface AuditLogResponse {
  entry: AuditLogEntry;
}

/** Body for querying recent audit entries (e.g. to compile the PDF export). */
export interface AuditQueryRequest {
  /** ISO timestamp, inclusive. */
  from?: string;
  /** ISO timestamp, exclusive. */
  to?: string;
  limit?: number;
}

export interface AuditQueryResponse {
  entries: AuditLogEntry[];
  total: number;
}

// ---------------------------------------------------------------------------
// GET/PUT /internal/policies — guardrail configuration
// ---------------------------------------------------------------------------

export interface AegisPolicy {
  pii_detection_enabled: boolean;
  secret_detection_enabled: boolean;
  prompt_injection_detection_enabled: boolean;
  hallucination_check_enabled: boolean;
  /** Used by /internal/verify when the request doesn't override it. */
  faithfulness_threshold: number;
  /** When false, PII detections are sanitized instead of blocking the request outright. */
  block_on_pii: boolean;
}

export interface PoliciesResponse {
  policy: AegisPolicy;
  updated_at: string;
}

/** Partial update; unspecified fields are left unchanged. */
export interface UpdatePoliciesRequest {
  policy: Partial<AegisPolicy>;
}

// ---------------------------------------------------------------------------
// GET /internal/health
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: "ok" | "degraded" | "down";
  engine: "mock" | "python";
  version: string;
  uptime_s: number;
}
