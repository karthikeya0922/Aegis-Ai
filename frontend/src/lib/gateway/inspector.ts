/**
 * Redacted inspector view of a scan.
 *
 * The Live Inspector needs to show what the guardrails found, but a raw API key,
 * password, private key or DB connection string must never reach a browser. This
 * module is the only thing allowed to turn a `ScanResponse` into something
 * client-visible, and it strips secrets on the way out.
 *
 * `redactSecrets` is exported separately because the client has its own copy of
 * the ORIGINAL prompt (the user typed it) which the server never echoes back —
 * the same offsets are applied there before the text reaches React state.
 */

import type { AegisMessage, DetectionCategory, PipelineStage } from "@aegis/types/aegis";

/**
 * The zod-validated scan body types `category` as a plain string, so this module
 * accepts that rather than the narrower `DetectionCategory`. Widening here is
 * safe — an unrecognised category is treated as non-secret only after
 * `isSecretCategory`'s `SECRET_` prefix check, which is what actually gates
 * redaction.
 */
export interface RawDetection {
  category: string;
  match: string;
  placeholder: string | null;
  start: number;
  end: number;
  confidence: number;
  message_index: number;
}

export const REDACTED = "[REDACTED]";

const SECRET_CATEGORIES: ReadonlySet<DetectionCategory> = new Set<DetectionCategory>([
  "SECRET_AWS_ACCESS_KEY",
  "SECRET_AWS_SECRET_KEY",
  "SECRET_DB_CONNECTION_STRING",
  "SECRET_JWT",
  "SECRET_API_KEY",
]);

export function isSecretCategory(category: string): boolean {
  return SECRET_CATEGORIES.has(category as DetectionCategory) || category.startsWith("SECRET_");
}

/**
 * A detection with the raw `match` removed. Offsets survive so the UI can
 * highlight the span; the bytes that sat there do not.
 */
/**
 * A pipeline stage, normalised.
 *
 * The scan schema types `stages` as `unknown[]` — the engine is free to add
 * fields and the gateway does not police them. Since these now reach a browser,
 * every stage is narrowed here to a known shape. A stage that reports no numeric
 * `duration_ms` gets `null`, which the UI renders as "—"; it is never defaulted
 * to 0, because "took no measurable time" and "did not report" are different.
 */
export interface SafeStage {
  name: string;
  status: PipelineStage["status"];
  duration_ms: number | null;
  detail?: string;
}

const STATUSES = new Set(["pass", "flagged", "blocked", "skipped"]);

function toSafeStage(raw: unknown): SafeStage | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const name = typeof r.name === "string" ? r.name : typeof r.stage === "string" ? r.stage : null;
  if (!name) return null;

  const status = typeof r.status === "string" && STATUSES.has(r.status) ? (r.status as PipelineStage["status"]) : "skipped";
  const duration =
    typeof r.duration_ms === "number" && Number.isFinite(r.duration_ms) ? r.duration_ms : null;

  return {
    name,
    status,
    duration_ms: duration,
    ...(typeof r.detail === "string" ? { detail: r.detail } : {}),
  };
}

export interface SafeDetection {
  category: string;
  placeholder: string | null;
  start: number;
  end: number;
  confidence: number;
  message_index: number;
  /** True when this detection's raw value was withheld because it is a secret. */
  secret: boolean;
  /** Non-secret matches are safe to show; secrets are always `REDACTED`. */
  preview: string;
}

export interface InspectorPayload {
  action: string;
  error_code: string | null;
  stages: SafeStage[];
  detections: SafeDetection[];
  /** Already secret-redacted. `null` when the verdict was not "sanitize". */
  sanitized_messages: AegisMessage[] | null;
  /** True when at least one secret was found, so the UI can say so explicitly. */
  had_secrets: boolean;
}

/**
 * Replaces every secret detection's span with `[REDACTED]`.
 *
 * Applied right-to-left so earlier offsets stay valid as the string shrinks or
 * grows. Detections whose offsets fall outside the string are skipped rather
 * than silently corrupting it.
 */
export function redactSecrets(
  text: string,
  detections: Array<{ category: string; start: number; end: number; message_index?: number }>,
  messageIndex?: number,
): string {
  const spans = detections
    .filter((d) => isSecretCategory(d.category))
    .filter((d) => messageIndex === undefined || d.message_index === undefined || d.message_index === messageIndex)
    .filter((d) => d.start >= 0 && d.end <= text.length && d.end > d.start)
    .sort((a, b) => b.start - a.start);

  let out = text;
  for (const s of spans) out = out.slice(0, s.start) + REDACTED + out.slice(s.end);
  return out;
}

/**
 * Belt-and-braces sweep for secret-shaped strings that carried no detection
 * offsets (engine disagreement, partial results). Cheap, and it only ever
 * removes — it can never reveal.
 */
const SECRET_SHAPES: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
  /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b/g, // provider-style API keys
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, // GitHub tokens
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, // JWT
  /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'<>]+/gi, // DSNs with creds
  /-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----/g,
];

export function scrubSecretShapes(text: string): string {
  let out = text;
  for (const re of SECRET_SHAPES) out = out.replace(re, REDACTED);
  return out;
}

/** Full client-safe pass: offset-based redaction, then the shape sweep. */
export function makeClientSafe(
  text: string,
  detections: Array<{ category: string; start: number; end: number; message_index?: number }>,
  messageIndex?: number,
): string {
  return scrubSecretShapes(redactSecrets(text, detections, messageIndex));
}

/** Build the client-visible inspector payload from a raw engine scan response. */
export function toInspectorPayload(scan: {
  action: string;
  error_code: string | null;
  detections: Array<{ category: string; match: string; placeholder: string | null; start: number; end: number; confidence: number; message_index: number }>;
  sanitized_messages: AegisMessage[] | null;
  stages: unknown[];
}): InspectorPayload {
  const detections: SafeDetection[] = scan.detections.map((d) => {
    const secret = isSecretCategory(d.category);
    return {
      category: d.category as DetectionCategory,
      placeholder: d.placeholder,
      start: d.start,
      end: d.end,
      confidence: d.confidence,
      message_index: d.message_index,
      secret,
      preview: secret ? REDACTED : d.match,
    };
  });

  const sanitized =
    scan.sanitized_messages?.map((m, i) => ({
      ...m,
      content: makeClientSafe(m.content, scan.detections, i),
    })) ?? null;

  return {
    action: scan.action,
    error_code: scan.error_code,
    stages: scan.stages.map(toSafeStage).filter((s): s is SafeStage => s !== null),
    detections,
    sanitized_messages: sanitized,
    had_secrets: detections.some((d) => d.secret),
  };
}
