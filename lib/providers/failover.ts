/**
 * Transparent failover across an ordered chain of providers (`providers[0]` is
 * primary, the rest are secondaries in priority order). Each member owns a
 * long-lived `CircuitBreaker`; a provider whose breaker is OPEN is skipped
 * instantly, with no network call.
 *
 * Failover fires on the same conditions the breaker trips on: HTTP 500/502/503/429,
 * a connect/total timeout, or a network-level connection error — see
 * `base.ts#isFailoverStatus`. Any other error (e.g. a 400 from a malformed request)
 * is NOT retried on a secondary, since a different provider won't fix a client error;
 * it's thrown straight through.
 */

import { type ChatChunk, type ChatRequest, type ChatResponse, type LLMProvider, ProviderError, isFailoverStatus } from "./base";
import { type CircuitBreaker, DEFAULT_TIMEOUTS, type TimeoutConfig } from "./circuit-breaker";

export interface FailoverGroupMember {
  provider: LLMProvider;
  breaker: CircuitBreaker;
}

export interface FailoverAttempt {
  provider: string;
  /** `true` when this provider was skipped because its breaker was OPEN — no call was made. */
  skipped_open_circuit: boolean;
  status: number | null;
  /**
   * REDACTED summary only (`ProviderError.publicMessage`). This field reaches
   * telemetry, logs and — on the SSE path — the client, so it must never carry an
   * upstream response body or an internal URL. Upstream 4xx bodies commonly echo
   * the submitted prompt, which is why the adapters drop them entirely.
   */
  message: string;
}

export interface FailoverTelemetry {
  primary: string;
  used: string;
  /** True iff the primary provider (`providers[0]`) failed or was skipped for this request. */
  primary_failed: boolean;
  /** True iff the request was ultimately served by anything other than the primary. */
  failover_used: boolean;
  attempts: FailoverAttempt[];
}

export interface FailoverOptions {
  timeouts?: Partial<TimeoutConfig>;
}

interface ClassifiedError {
  retryable: boolean;
  status: number | null;
  /** In-process detail. May contain adapter internals; never sent to a client. */
  message: string;
  /** Boundary-safe summary. This is what goes into `FailoverAttempt.message`. */
  publicMessage: string;
}

function classifyError(err: unknown): ClassifiedError {
  if (err instanceof ProviderError) {
    return { retryable: err.retryable, status: err.status, message: err.message, publicMessage: err.publicMessage };
  }
  if (err instanceof Error && (err.name === "AbortError" || err.name === "TimeoutError")) {
    return {
      retryable: true,
      status: null,
      message: `Provider call aborted/timed out: ${err.message}`,
      publicMessage: "upstream call timed out",
    };
  }
  // An unrecognised throw could carry anything (including text derived from the
  // request), so its message is kept in-process and not summarised outward.
  return {
    retryable: true,
    status: null,
    message: err instanceof Error ? err.message : String(err),
    publicMessage: "upstream call failed",
  };
}

/** Re-validates that our own classification agrees with the shared failover-status policy. */
function isRetryable(classified: ClassifiedError): boolean {
  return classified.retryable && isFailoverStatus(classified.status);
}

function combineSignals(signals: AbortSignal[]): AbortSignal {
  return AbortSignal.any(signals);
}

function timeoutSignal(ms: number, label: string): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException(`${label} exceeded (${ms}ms)`, "TimeoutError")), ms);
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

function noProvidersError(): ProviderError {
  return new ProviderError("No providers configured for failover", { provider: "none", status: null, retryable: false });
}

function allFailedError(primary: string, attempts: FailoverAttempt[]): ProviderError {
  // `attempts[].message` is already redacted (see `FailoverAttempt`), so this
  // aggregate is safe to log. `publicMessage` still omits the provider names so
  // the gateway never has to reveal its upstream topology to a caller.
  const detail = attempts
    .map((a) => (a.skipped_open_circuit ? `${a.provider} (circuit open)` : `${a.provider} (${a.message})`))
    .join("; ");
  return new ProviderError(`All providers failed: ${detail || "no attempts made"}`, {
    provider: primary,
    status: null,
    retryable: false,
    publicMessage: "no upstream provider was able to serve this request",
  });
}

/** Non-streaming completion with failover. Resolves once a provider succeeds, or throws once all have failed. */
export async function chatWithFailover(
  members: FailoverGroupMember[],
  req: ChatRequest,
  options: FailoverOptions = {},
): Promise<{ response: ChatResponse; telemetry: FailoverTelemetry }> {
  if (members.length === 0) throw noProvidersError();
  const timeouts = { ...DEFAULT_TIMEOUTS, ...options.timeouts };
  const primaryName = members[0].provider.name;
  const attempts: FailoverAttempt[] = [];

  for (const member of members) {
    if (!member.breaker.tryAcquire()) {
      attempts.push({ provider: member.provider.name, skipped_open_circuit: true, status: null, message: "circuit open" });
      continue;
    }

    const total = timeoutSignal(timeouts.totalTimeoutMs, "Total timeout");
    const signal = combineSignals([req.signal, total.signal]);

    try {
      const response = await member.provider.chat({ ...req, signal });
      total.cancel();
      member.breaker.recordSuccess();
      return {
        response,
        telemetry: {
          primary: primaryName,
          used: member.provider.name,
          primary_failed: attempts.some((a) => a.provider === primaryName),
          failover_used: member.provider.name !== primaryName,
          attempts,
        },
      };
    } catch (err) {
      total.cancel();
      const classified = classifyError(err);
      member.breaker.recordFailure();
      attempts.push({ provider: member.provider.name, skipped_open_circuit: false, status: classified.status, message: classified.publicMessage });
      if (!isRetryable(classified)) {
        throw new ProviderError(classified.message, {
          provider: member.provider.name,
          status: classified.status,
          retryable: false,
          cause: err,
          publicMessage: classified.publicMessage,
        });
      }
      // else: retryable — fall through to the next provider in the chain.
    }
  }

  throw allFailedError(primaryName, attempts);
}

/**
 * Streaming completion with failover. Failover can only happen before the FIRST
 * chunk of a given provider's stream — once bytes are already on their way to the
 * client we can't silently swap upstreams. `connectTimeoutMs` bounds that
 * first-chunk wait; `totalTimeoutMs` bounds the winning provider's entire stream.
 */
export async function streamWithFailover(
  members: FailoverGroupMember[],
  req: ChatRequest,
  options: FailoverOptions = {},
): Promise<{ chunks: AsyncGenerator<ChatChunk>; telemetry: FailoverTelemetry }> {
  if (members.length === 0) throw noProvidersError();
  const timeouts = { ...DEFAULT_TIMEOUTS, ...options.timeouts };
  const primaryName = members[0].provider.name;
  const attempts: FailoverAttempt[] = [];

  for (const member of members) {
    if (!member.breaker.tryAcquire()) {
      attempts.push({ provider: member.provider.name, skipped_open_circuit: true, status: null, message: "circuit open" });
      continue;
    }

    const total = timeoutSignal(timeouts.totalTimeoutMs, "Total timeout");
    const connect = timeoutSignal(timeouts.connectTimeoutMs, "Connect timeout");
    const signal = combineSignals([req.signal, total.signal, connect.signal]);

    const iterator = member.provider.stream({ ...req, signal })[Symbol.asyncIterator]();

    let first: IteratorResult<ChatChunk>;
    try {
      first = await iterator.next();
      connect.cancel();
    } catch (err) {
      connect.cancel();
      total.cancel();
      const classified = classifyError(err);
      member.breaker.recordFailure();
      attempts.push({ provider: member.provider.name, skipped_open_circuit: false, status: classified.status, message: classified.publicMessage });
      if (!isRetryable(classified)) {
        throw new ProviderError(classified.message, {
          provider: member.provider.name,
          status: classified.status,
          retryable: false,
          cause: err,
          publicMessage: classified.publicMessage,
        });
      }
      continue; // try the next provider
    }

    // First chunk (or immediate completion) arrived — this provider is committed to.
    member.breaker.recordSuccess();
    const telemetry: FailoverTelemetry = {
      primary: primaryName,
      used: member.provider.name,
      primary_failed: attempts.some((a) => a.provider === primaryName),
      failover_used: member.provider.name !== primaryName,
      attempts,
    };

    const breaker = member.breaker;
    const providerName = member.provider.name;
    async function* rest(): AsyncGenerator<ChatChunk> {
      try {
        if (!first.done) yield first.value;
        while (true) {
          const next = await iterator.next();
          if (next.done) break;
          yield next.value;
        }
      } catch (err) {
        // Mid-stream failure: too late to fail over (bytes already sent), but the
        // breaker still needs to know this provider just failed.
        breaker.recordFailure();
        const classified = classifyError(err);
        throw new ProviderError(classified.message, {
          provider: providerName,
          status: classified.status,
          retryable: false,
          cause: err,
          publicMessage: classified.publicMessage,
        });
      } finally {
        total.cancel();
      }
    }

    return { chunks: rest(), telemetry };
  }

  throw allFailedError(primaryName, attempts);
}
