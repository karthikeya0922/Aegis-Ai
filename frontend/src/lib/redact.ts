/**
 * Client-side secret redaction — the last line of the HARD RULE.
 *
 * The server already redacts everything it sends back (`lib/gateway/inspector.ts`).
 * But the ORIGINAL prompt shown in the diff's left pane never round-trips: the
 * browser typed it and still holds it. This module applies the same redaction to
 * that local copy BEFORE it reaches React state, so a raw API key, password,
 * private key or DB password never exists in a rendered tree, a devtools
 * snapshot, or a component's props.
 */

export const REDACTED = "[REDACTED]";

export function isSecretCategory(category: string): boolean {
  return category.startsWith("SECRET_");
}

export interface SpanLike {
  category: string;
  start: number;
  end: number;
  message_index?: number;
}

/** Shape-based sweep, for secrets that arrived without usable offsets. */
const SECRET_SHAPES: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'<>]+/gi,
  /-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----/g,
  /\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*["']?[^\s"',;]{6,}/gi,
];

export function scrubSecretShapes(text: string): string {
  let out = text;
  for (const re of SECRET_SHAPES) out = out.replace(re, REDACTED);
  return out;
}

/**
 * Offset redaction, applied right-to-left so earlier spans stay valid while the
 * string length changes. Out-of-range spans are skipped rather than corrupting
 * the text.
 */
export function redactSpans(text: string, spans: SpanLike[], messageIndex?: number): string {
  const secrets = spans
    .filter((s) => isSecretCategory(s.category))
    .filter((s) => messageIndex === undefined || s.message_index === undefined || s.message_index === messageIndex)
    .filter((s) => s.start >= 0 && s.end <= text.length && s.end > s.start)
    .sort((a, b) => b.start - a.start);

  let out = text;
  for (const s of secrets) out = out.slice(0, s.start) + REDACTED + out.slice(s.end);
  return out;
}

/**
 * The only function the playground should call. Never returns a string that
 * still contains a detected secret.
 */
export function makeSafe(text: string, spans: SpanLike[] = [], messageIndex?: number): string {
  return scrubSecretShapes(redactSpans(text, spans, messageIndex));
}
