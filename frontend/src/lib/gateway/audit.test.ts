import { describe, expect, it, vi } from "vitest";
import type { AuditLogEntry } from "@aegis/types/aegis";
import { fireAuditAsync, type AuditEngine } from "./audit";

const FIELDS = {
  request_id: "req_1",
  latency_ms: 123,
  provider_used: "openai",
  model_used: "gpt-4o-mini",
  tokens_consumed: 42,
  cache_hit: false,
  failover_used: false,
  scrubbed_entity_count: 2,
  rule_triggers: ["PII_EMAIL", "PII_PERSON_NAME"],
  action: "sanitize" as const,
  error_code: null,
  grounding_status: "pass" as const,
  grounding_score: 0.97,
  estimated_cost_usd: 0.001,
  estimated_savings_usd: null,
  estimated_carbon_g: 0.01,
};

function flush(): Promise<void> {
  // `fireAuditAsync` schedules via `Promise.resolve().then(...)`; give the
  // microtask queue a turn to run before asserting.
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe("fireAuditAsync", () => {
  it("never blocks the caller — returns synchronously, before the write settles", () => {
    let resolved = false;
    const engine: AuditEngine = {
      writeAudit: () => new Promise((resolve) => setTimeout(() => { resolved = true; resolve(undefined); }, 5)),
    };
    fireAuditAsync(engine, FIELDS);
    expect(resolved).toBe(false);
  });

  it("sends every field, mapped onto an AuditLogEntry, with no raw text anywhere", async () => {
    const writeAudit = vi.fn(async (req: { entry: Omit<AuditLogEntry, "id" | "timestamp"> }) => ({ entry: req.entry }));
    fireAuditAsync({ writeAudit }, FIELDS);
    await flush();

    expect(writeAudit).toHaveBeenCalledWith({
      entry: {
        request_id: "req_1",
        model_used: "gpt-4o-mini",
        tokens_consumed: 42,
        latency_ms: 123,
        scrubbed_entity_count: 2,
        rule_triggers: ["PII_EMAIL", "PII_PERSON_NAME"],
        action: "sanitize",
        error_code: null,
        provider_used: "openai",
        cache_hit: false,
        failover_used: false,
        grounding_status: "pass",
        grounding_score: 0.97,
        estimated_cost_usd: 0.001,
        estimated_savings_usd: null,
        estimated_carbon_g: 0.01,
      },
    });
    expect(JSON.stringify(writeAudit.mock.calls)).not.toMatch(/@|AKIA|jane|secret/i);
  });

  it("swallows a rejected write instead of throwing or producing an unhandled rejection", async () => {
    const engine: AuditEngine = { writeAudit: async () => { throw new Error("engine down"); } };
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => fireAuditAsync(engine, FIELDS)).not.toThrow();
    await flush();
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("req_1"), "engine down");
    errorSpy.mockRestore();
  });

  it("swallows a synchronously-throwing writeAudit (e.g. a test double missing the method)", async () => {
    const brokenEngine = {} as AuditEngine;
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => fireAuditAsync(brokenEngine, FIELDS)).not.toThrow();
    await flush();
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});
