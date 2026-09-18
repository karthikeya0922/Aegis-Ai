/**
 * Aegis fail-closed security gate.
 *
 * This module is the ONLY place a `ScannedPrompt` can be created, and a
 * `ScannedPrompt` is the ONLY thing the provider stage accepts. So the sole route
 * from client messages to an upstream LLM is through `runScanGate`.
 *
 * Invariants (do not weaken):
 * - Any engine failure (network error, timeout, non-2xx, unparseable or
 *   contract-violating body) → `AEGIS_ENGINE_UNAVAILABLE` / 503. There is no
 *   "proceed anyway" path.
 * - "sanitize" → the prompt carries `sanitized_messages` only. The original
 *   messages are not stored on the outcome and are not reachable from it.
 * - Raw detection matches (`Detection.match`) never leave this module.
 */

import { z } from "zod";
import type {
  AegisMessage,
  ScanMode,
  ScanRequest,
  ScanResponse,
} from "@aegis/types/aegis";
import type { GatewayErrorCode } from "@/lib/errors";
import type { InboundMessages } from "./inbound";
import { toInspectorPayload, type InspectorPayload } from "./inspector";

// ---------------------------------------------------------------------------
// ScannedPrompt — the unforgeable "these messages passed the gate" token
// ---------------------------------------------------------------------------

/** Module-private capability. Without it, the constructor refuses to run. */
const MINT: unique symbol = Symbol("aegis.scan-gate.mint");
/** Runtime registry of genuine instances, so `as ScannedPrompt` casts are caught too. */
const minted = new WeakSet<object>();

export type ForwardedAction = "allow" | "warn" | "sanitize";

export class ScannedPrompt {
  // ECMAScript private field makes this type nominal: no structural look-alike
  // object satisfies `ScannedPrompt` at compile time.
  readonly #messages: readonly AegisMessage[];
  readonly action: ForwardedAction;

  constructor(mint: typeof MINT, messages: readonly AegisMessage[], action: ForwardedAction) {
    if (mint !== MINT) {
      throw new Error("ScannedPrompt can only be created by the Aegis scan gate");
    }
    this.#messages = Object.freeze(
      messages.map((m) => Object.freeze({ role: m.role, content: m.content })),
    );
    this.action = action;
    Object.freeze(this);
    minted.add(this);
  }

  /** The messages that are allowed to reach a provider. Deeply frozen. */
  get messages(): readonly AegisMessage[] {
    return this.#messages;
  }

  static isGenuine(value: unknown): value is ScannedPrompt {
    return typeof value === "object" && value !== null && minted.has(value);
  }
}

// ---------------------------------------------------------------------------
// Engine response validation — never trust the engine's body shape
// ---------------------------------------------------------------------------

const messageSchema = z.object({
  role: z.enum(["system", "user", "assistant"]),
  content: z.string(),
});

const scanResponseSchema = z.object({
  request_id: z.string(),
  action: z.enum(["allow", "warn", "sanitize", "block"]),
  // Unknown codes are tolerated here and mapped to AEGIS_POLICY_BLOCKED on block.
  error_code: z.string().nullable(),
  detections: z.array(
    z.object({
      category: z.string(),
      match: z.string(),
      placeholder: z.string().nullable(),
      start: z.number().int().nonnegative().default(0),
      end: z.number().int().nonnegative().default(0),
      confidence: z.number().min(0).max(1).default(1),
      message_index: z.number().int().nonnegative().default(0),
    }),
  ),
  sanitized_messages: z.array(messageSchema).nullable(),
  vault_token: z.string().nullable(),
  stages: z.array(z.unknown()),
});

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

/** Anything that can perform POST /internal/scan. `AegisClient` satisfies this. */
export interface ScanEngine {
  scan(req: ScanRequest): Promise<ScanResponse>;
}

export interface ScanGateMeta {
  request_id: string;
  session_id: string;
  mode: ScanMode;
  confidential_mode?: boolean;
}

/** Telemetry-safe scan summary. Deliberately excludes raw matches and message text. */
export interface ScanSummary {
  action: ScanResponse["action"];
  error_code: string | null;
  detection_count: number;
  detection_categories: string[];
}

export type ScanGateOutcome =
  | {
      kind: "forward";
      prompt: ScannedPrompt;
      summary: ScanSummary;
      /** From `ScanResponse.vault_token`. `null` unless this scan sanitized something. */
      vault_token: string | null;
      /** Secret-redacted view of the scan for the Live Inspector. Safe to send to a browser. */
      inspector: InspectorPayload;
    }
  | {
      kind: "reject";
      status: 400 | 403 | 503;
      code: GatewayErrorCode;
      message: string;
      /** Present when the engine answered; absent when it was unavailable. */
      summary: ScanSummary | null;
      /** Secret-redacted inspector view. `null` when the engine never answered. */
      inspector: InspectorPayload | null;
    };

export const DEFAULT_SCAN_TIMEOUT_MS = 3_000;

function engineUnavailable(): ScanGateOutcome {
  return {
    kind: "reject",
    status: 503,
    code: "AEGIS_ENGINE_UNAVAILABLE",
    message: "The Aegis security engine is unavailable; the request was not forwarded.",
    summary: null,
    inspector: null,
  };
}

/** Resolves with the engine's raw body, or rejects on error or deadline. */
function scanWithDeadline(engine: ScanEngine, req: ScanRequest, timeoutMs: number): Promise<unknown> {
  return new Promise<unknown>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`scan timed out after ${timeoutMs}ms`)), timeoutMs);
    // Wrap in an async thunk so a synchronous throw from `scan` also rejects.
    (async () => engine.scan(req))().then(
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

/**
 * Consumes `inbound` (single use) and returns either a forwardable `ScannedPrompt`
 * or a rejection. On "sanitize" the original messages exist only in this call's
 * locals and are unreachable once it returns.
 */
export async function runScanGate(
  meta: ScanGateMeta,
  inbound: InboundMessages,
  engine: ScanEngine,
  options: { timeoutMs?: number } = {},
): Promise<ScanGateOutcome> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS;
  const messages = inbound.take();

  let raw: unknown;
  try {
    raw = await scanWithDeadline(
      engine,
      {
        request_id: meta.request_id,
        session_id: meta.session_id,
        messages,
        mode: meta.mode,
        confidential_mode: meta.confidential_mode,
      },
      timeoutMs,
    );
  } catch {
    return engineUnavailable();
  }

  const parsed = scanResponseSchema.safeParse(raw);
  if (!parsed.success) return engineUnavailable();
  const scan = parsed.data;

  // A verdict for a different request is not a verdict for this one.
  if (scan.request_id !== meta.request_id) return engineUnavailable();

  const summary: ScanSummary = {
    action: scan.action,
    error_code: scan.error_code,
    detection_count: scan.detections.length,
    detection_categories: [...new Set(scan.detections.map((d) => d.category))],
  };

  // Redacted here, inside the module that owns the raw matches, so no caller can
  // ever be handed an un-redacted secret.
  const inspector = toInspectorPayload(scan);

  switch (scan.action) {
    case "block": {
      if (scan.error_code === "CREDENTIAL_LEAK_PREVENTED") {
        return {
          kind: "reject",
          status: 400,
          code: "CREDENTIAL_LEAK_PREVENTED",
          message: "The request contained credentials and was blocked.",
          summary,
          inspector,
        };
      }
      if (scan.error_code === "PROMPT_INJECTION_BLOCKED") {
        return {
          kind: "reject",
          status: 403,
          code: "PROMPT_INJECTION_BLOCKED",
          message: "The request was blocked as a prompt injection attempt.",
          summary,
          inspector,
        };
      }
      return {
        kind: "reject",
        status: 403,
        code: "AEGIS_POLICY_BLOCKED",
        message: "The request was blocked by Aegis policy.",
        summary,
        inspector,
      };
    }

    case "sanitize": {
      const sanitized = scan.sanitized_messages;
      if (sanitized === null || sanitized.length === 0) return engineUnavailable();
      // Defense in depth: if any redacted value survived into the sanitized
      // output, the engine's sanitization is broken — do not forward.
      for (const d of scan.detections) {
        if (d.placeholder === null || d.match.length === 0) continue;
        if (sanitized.some((m) => m.content.includes(d.match))) return engineUnavailable();
      }
      return {
        kind: "forward",
        prompt: new ScannedPrompt(MINT, sanitized, "sanitize"),
        summary,
        vault_token: scan.vault_token,
        inspector,
      };
    }

    case "warn":
      // Only a "sanitize" verdict carries a meaningful vault; ignore anything else
      // the engine sent here even if non-null.
      return { kind: "forward", prompt: new ScannedPrompt(MINT, messages, "warn"), summary, vault_token: null, inspector };

    case "allow":
      return { kind: "forward", prompt: new ScannedPrompt(MINT, messages, "allow"), summary, vault_token: null, inspector };

    default: {
      // Exhaustiveness: a new engine action must be handled explicitly above.
      const unhandled: never = scan.action;
      void unhandled;
      return engineUnavailable();
    }
  }
}
