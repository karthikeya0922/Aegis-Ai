import { describe, expect, it } from "vitest";
import { CircuitBreaker } from "@aegis/providers/circuit-breaker";

function clock(startMs = 0) {
  let now = startMs;
  return { now: () => now, advance: (ms: number) => (now += ms) };
}

describe("CircuitBreaker", () => {
  it("starts CLOSED and stays CLOSED under the failure threshold", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 3 });
    expect(breaker.getState()).toBe("CLOSED");
    expect(breaker.tryAcquire()).toBe(true);
    breaker.recordFailure();
    expect(breaker.tryAcquire()).toBe(true);
    breaker.recordFailure();
    expect(breaker.getState()).toBe("CLOSED");
  });

  it("trips OPEN after `failureThreshold` consecutive failures", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 3 });
    breaker.recordFailure();
    breaker.recordFailure();
    expect(breaker.getState()).toBe("CLOSED");
    breaker.recordFailure();
    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.tryAcquire()).toBe(false);
  });

  it("a success resets the consecutive-failure count", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 3 });
    breaker.recordFailure();
    breaker.recordFailure();
    breaker.recordSuccess();
    breaker.recordFailure();
    breaker.recordFailure();
    expect(breaker.getState()).toBe("CLOSED"); // would be OPEN without the reset
  });

  it("moves OPEN -> HALF_OPEN after openDurationMs and allows halfOpenTrialCount trials", () => {
    const c = clock();
    const breaker = new CircuitBreaker({ failureThreshold: 1, openDurationMs: 1000, halfOpenTrialCount: 2 }, c.now);

    breaker.recordFailure();
    expect(breaker.getState()).toBe("OPEN");
    expect(breaker.tryAcquire()).toBe(false);

    c.advance(999);
    expect(breaker.getState()).toBe("OPEN");

    c.advance(1);
    expect(breaker.getState()).toBe("HALF_OPEN");
    expect(breaker.tryAcquire()).toBe(true); // trial 1
    expect(breaker.tryAcquire()).toBe(true); // trial 2
    expect(breaker.tryAcquire()).toBe(false); // trial budget exhausted
  });

  it("a successful HALF_OPEN trial closes the breaker", () => {
    const c = clock();
    const breaker = new CircuitBreaker({ failureThreshold: 1, openDurationMs: 1000, halfOpenTrialCount: 1 }, c.now);
    breaker.recordFailure();
    c.advance(1000);
    expect(breaker.tryAcquire()).toBe(true);
    breaker.recordSuccess();
    expect(breaker.getState()).toBe("CLOSED");
    expect(breaker.tryAcquire()).toBe(true);
  });

  it("a failed HALF_OPEN trial re-opens the breaker immediately (fresh cooldown)", () => {
    const c = clock();
    const breaker = new CircuitBreaker({ failureThreshold: 1, openDurationMs: 1000, halfOpenTrialCount: 1 }, c.now);
    breaker.recordFailure();
    c.advance(1000);
    expect(breaker.tryAcquire()).toBe(true);
    breaker.recordFailure();
    expect(breaker.getState()).toBe("OPEN");
    c.advance(999);
    expect(breaker.getState()).toBe("OPEN");
    c.advance(1);
    expect(breaker.getState()).toBe("HALF_OPEN");
  });
});
