/**
 * Per-provider circuit breaker: CLOSED → OPEN → HALF_OPEN → CLOSED.
 *
 * - CLOSED: requests flow normally; consecutive failures are counted.
 * - OPEN: requests are refused outright (no network call at all) until
 *   `openDurationMs` has elapsed — this is what lets `failover.ts` skip a known-dead
 *   provider instantly instead of waiting out its timeout on every single request.
 * - HALF_OPEN: after the cooldown, up to `halfOpenTrialCount` requests are let through
 *   as trials. Any trial success closes the breaker; any trial failure re-opens it
 *   immediately (a fresh `openDurationMs` cooldown, not an accumulated count).
 *
 * One instance per provider, and it MUST be a long-lived singleton (see
 * `registry.ts`) — a breaker recreated per request can never accumulate failures
 * or open, defeating the whole point.
 */

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerConfig {
  /** Consecutive failures (while CLOSED) before the breaker trips OPEN. */
  failureThreshold: number;
  /** How long the breaker stays OPEN before allowing HALF_OPEN trial requests. */
  openDurationMs: number;
  /** How many trial requests are allowed through while HALF_OPEN. */
  halfOpenTrialCount: number;
}

export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 3,
  openDurationMs: 30_000,
  halfOpenTrialCount: 1,
};

function envInt(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

/** Reads breaker tuning from env, falling back to `DEFAULT_CIRCUIT_BREAKER_CONFIG`. */
export function loadCircuitBreakerConfigFromEnv(env: NodeJS.ProcessEnv = process.env): CircuitBreakerConfig {
  return {
    failureThreshold: envInt(env, "AEGIS_BREAKER_FAILURE_THRESHOLD", DEFAULT_CIRCUIT_BREAKER_CONFIG.failureThreshold),
    openDurationMs: envInt(env, "AEGIS_BREAKER_OPEN_DURATION_MS", DEFAULT_CIRCUIT_BREAKER_CONFIG.openDurationMs),
    halfOpenTrialCount: envInt(env, "AEGIS_BREAKER_HALF_OPEN_TRIALS", DEFAULT_CIRCUIT_BREAKER_CONFIG.halfOpenTrialCount),
  };
}

export interface TimeoutConfig {
  /**
   * Deadline for the upstream to "start responding": for `stream()`, the time to the
   * first chunk; for `chat()`, there is no separate connect signal (the call is
   * atomic), so this does not apply to it — see `totalTimeoutMs`.
   */
  connectTimeoutMs: number;
  /** Deadline for the whole call — `chat()` end-to-end, or `stream()` start-to-[DONE]. */
  totalTimeoutMs: number;
}

export const DEFAULT_TIMEOUTS: TimeoutConfig = {
  connectTimeoutMs: 2_500,
  totalTimeoutMs: 120_000,
};

/** Reads connect/total timeouts from env, falling back to `DEFAULT_TIMEOUTS`. */
export function loadTimeoutConfigFromEnv(env: NodeJS.ProcessEnv = process.env): TimeoutConfig {
  return {
    connectTimeoutMs: envInt(env, "AEGIS_PROVIDER_CONNECT_TIMEOUT_MS", DEFAULT_TIMEOUTS.connectTimeoutMs),
    totalTimeoutMs: envInt(env, "AEGIS_PROVIDER_TOTAL_TIMEOUT_MS", DEFAULT_TIMEOUTS.totalTimeoutMs),
  };
}

export class CircuitBreaker {
  private readonly config: CircuitBreakerConfig;
  private readonly now: () => number;

  private state: CircuitState = "CLOSED";
  private consecutiveFailures = 0;
  private openedAt = 0;
  private halfOpenTrialsInFlight = 0;

  constructor(config: Partial<CircuitBreakerConfig> = {}, now: () => number = Date.now) {
    this.config = { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, ...config };
    this.now = now;
  }

  /** Current state, resolving an elapsed OPEN cooldown into HALF_OPEN as a side effect. */
  getState(): CircuitState {
    if (this.state === "OPEN" && this.now() - this.openedAt >= this.config.openDurationMs) {
      this.state = "HALF_OPEN";
      this.halfOpenTrialsInFlight = 0;
    }
    return this.state;
  }

  /**
   * Atomically checks whether a call may proceed right now and, if so, reserves it
   * (a HALF_OPEN trial slot is consumed immediately, before any `await`, so
   * concurrent callers can't all pile onto the same trial). Callers MUST follow a
   * `true` result with exactly one of `recordSuccess()` / `recordFailure()`.
   */
  tryAcquire(): boolean {
    const state = this.getState();
    if (state === "CLOSED") return true;
    if (state === "OPEN") return false;
    // HALF_OPEN
    if (this.halfOpenTrialsInFlight < this.config.halfOpenTrialCount) {
      this.halfOpenTrialsInFlight++;
      return true;
    }
    return false;
  }

  recordSuccess(): void {
    this.state = "CLOSED";
    this.consecutiveFailures = 0;
    this.halfOpenTrialsInFlight = 0;
  }

  recordFailure(): void {
    if (this.state === "HALF_OPEN") {
      this.trip();
      return;
    }
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= this.config.failureThreshold) {
      this.trip();
    }
  }

  private trip(): void {
    this.state = "OPEN";
    this.openedAt = this.now();
    this.consecutiveFailures = 0;
    this.halfOpenTrialsInFlight = 0;
  }
}
