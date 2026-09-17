import { describe, expect, it, vi } from "vitest";
import type { VerifyRequest, VerifyResponse } from "@aegis/types/aegis";
import { runGroundingCheck, shouldRehydrate, type GroundingEngine } from "./grounding";

const INPUT_BASE = {
  request_id: "req_1",
  response_text: "The answer is 42.",
  vault_token: "vault_1" as string | null,
  reference_documents: [] as string[],
  scan_action: "sanitize" as const,
  detection_categories: [] as string[],
};

function passingEngine(overrides: Partial<VerifyResponse> = {}): GroundingEngine {
  return {
    async verify(req: VerifyRequest): Promise<VerifyResponse> {
      return {
        request_id: req.request_id,
        final_text: req.response_text,
        rehydrated: false,
        grounding: { status: "pass", score: 1, unsupported_claims: [] },
        stages: [{ name: "nli_cross_check", status: "pass", duration_ms: 10 }],
        processed_at: new Date(0).toISOString(),
        ...overrides,
      };
    },
  };
}

describe("shouldRehydrate", () => {
  it("is false for anything other than sanitize", () => {
    expect(shouldRehydrate("allow", [])).toBe(false);
    expect(shouldRehydrate("warn", [])).toBe(false);
  });

  it("is true for sanitize with only non-secret categories", () => {
    expect(shouldRehydrate("sanitize", ["PII_EMAIL", "PII_PERSON_NAME"])).toBe(true);
  });

  it("is false for sanitize when ANY detection was a secret — secrets are never rehydrated", () => {
    expect(shouldRehydrate("sanitize", ["PII_EMAIL", "SECRET_AWS_ACCESS_KEY"])).toBe(false);
    expect(shouldRehydrate("sanitize", ["SECRET_JWT"])).toBe(false);
  });
});

describe("runGroundingCheck", () => {
  it("sends rehydrate: true only for sanitize + no secret categories", async () => {
    const verify = vi.fn(passingEngine().verify);
    await runGroundingCheck({ verify }, { ...INPUT_BASE, scan_action: "sanitize", detection_categories: ["PII_EMAIL"] });
    expect(verify).toHaveBeenCalledWith(
      expect.objectContaining({ rehydrate: true, vault_token: "vault_1", response_text: INPUT_BASE.response_text }),
    );
  });

  it("never sends rehydrate: true when a secret was detected, even in sanitize mode", async () => {
    const verify = vi.fn(passingEngine().verify);
    await runGroundingCheck({ verify }, {
      ...INPUT_BASE,
      scan_action: "sanitize",
      detection_categories: ["PII_EMAIL", "SECRET_AWS_ACCESS_KEY"],
    });
    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ rehydrate: false }));
  });

  it("passes through final_text and grounding_status on a pass", async () => {
    const outcome = await runGroundingCheck(passingEngine(), INPUT_BASE);
    expect(outcome).toEqual({
      final_text: INPUT_BASE.response_text,
      blocked: false,
      rehydrated: false,
      grounding_status: "pass",
      grounding_score: 1,
      stages: [{ name: "nli_cross_check", status: "pass", duration_ms: 10 }],
    });
  });

  it("reports rehydrated: true when the engine says it rehydrated", async () => {
    const engine = passingEngine({ rehydrated: true, final_text: "Email jane@corp.com" });
    const outcome = await runGroundingCheck(engine, INPUT_BASE);
    expect(outcome.rehydrated).toBe(true);
    expect(outcome.final_text).toBe("Email jane@corp.com");
  });

  it("substitutes the gateway's OWN configured fallback text on a block verdict, not the engine's final_text", async () => {
    const engine = passingEngine({
      final_text: "some engine-side wording the gateway must not use",
      grounding: { status: "block", score: 0.1, unsupported_claims: ["The answer is 42."] },
    });
    const outcome = await runGroundingCheck(engine, INPUT_BASE);
    expect(outcome.blocked).toBe(true);
    expect(outcome.grounding_status).toBe("block");
    expect(outcome.grounding_score).toBe(0.1);
    expect(outcome.final_text).toBe("I cannot verify this claim against verified documentation.");
    expect(outcome.final_text).not.toContain("engine-side wording");
  });

  it("fails open on text / closed on the claim when verify rejects — never claims verified", async () => {
    const engine: GroundingEngine = { verify: async () => { throw new Error("network down"); } };
    const outcome = await runGroundingCheck(engine, INPUT_BASE);
    expect(outcome).toEqual({
      final_text: INPUT_BASE.response_text,
      blocked: false,
      rehydrated: false,
      grounding_status: "unverified",
      grounding_score: null,
      stages: [],
    });
  });

  it("fails open on text / closed on the claim when verify times out", async () => {
    vi.useFakeTimers();
    try {
      const engine: GroundingEngine = { verify: () => new Promise<VerifyResponse>(() => {}) };
      const pending = runGroundingCheck(engine, INPUT_BASE, { timeoutMs: 50 });
      await vi.advanceTimersByTimeAsync(50);
      const outcome = await pending;
      expect(outcome.grounding_status).toBe("unverified");
      expect(outcome.final_text).toBe(INPUT_BASE.response_text);
    } finally {
      vi.useRealTimers();
    }
  });

  it("treats a malformed engine response as unverified (never trusts the body shape blindly)", async () => {
    const engine = { verify: async () => ({ ok: true }) } as unknown as GroundingEngine;
    const outcome = await runGroundingCheck(engine, INPUT_BASE);
    expect(outcome.grounding_status).toBe("unverified");
  });

  it("treats a verdict for a different request_id as unverified", async () => {
    const engine = passingEngine();
    const outcome = await runGroundingCheck(
      { verify: async (req) => ({ ...(await engine.verify(req)), request_id: "req_someone_else" }) },
      INPUT_BASE,
    );
    expect(outcome.grounding_status).toBe("unverified");
    expect(outcome.final_text).toBe(INPUT_BASE.response_text);
  });

  it("scores against reference_documents when supplied", async () => {
    const verify = vi.fn(passingEngine().verify);
    await runGroundingCheck({ verify }, { ...INPUT_BASE, reference_documents: ["doc one", "doc two"] });
    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ reference_documents: ["doc one", "doc two"] }));
  });
});
