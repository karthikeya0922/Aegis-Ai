import net from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AegisClient } from "@aegis/aegis-client";
import type { AegisMessage, ScanRequest, ScanResponse, VerifyResponse } from "@aegis/types/aegis";
import { InboundMessages } from "./inbound";
import { guardedCompletion, type GatewayDeps } from "./pipeline";
import { guardProvider, type ChatCompletionResponse, type ProviderCall } from "./provider";
import { ScannedPrompt, type ScanEngine } from "./scan-gate";
import type { GatewayEvent } from "./telemetry";

const META = { request_id: "req_test", session_id: "sess_test", principal: { tenant: "test", key_id: "test", dev_fallback: true }, mode: "sanitize" as const };
const PARAMS = { model: "gpt-4o" };

const COMPLETION: ChatCompletionResponse = {
  id: "chatcmpl-test",
  object: "chat.completion",
  created: 0,
  model: "gpt-4o",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, logprobs: null, finish_reason: "stop" }],
  usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
};

/**
 * `GatewayDeps.engine` needs `scan` (under test here), plus `verify` and
 * `writeAudit` for the Phase 4 grounding/audit stages `guardedCompletion` always
 * runs after a successful provider call. Wrapping the caller's scan-only engine
 * here — instead of touching every one of this file's ~20 test cases — keeps
 * those benign no-op defaults (pass-through grounding, no-op audit) in one place.
 */
function harness(
  scanEngine: ScanEngine,
  scanTimeoutMs = 200,
  overrides: Partial<Pick<GatewayDeps["engine"], "verify" | "writeAudit">> = {},
) {
  const provider = vi.fn<ProviderCall>(async () => COMPLETION);
  const events: GatewayEvent[] = [];
  const verify =
    overrides.verify ??
    vi.fn(async (req): Promise<VerifyResponse> => ({
      request_id: req.request_id,
      final_text: req.response_text,
      rehydrated: false,
      grounding: { status: "pass", score: 1, unsupported_claims: [] },
      stages: [],
      processed_at: new Date(0).toISOString(),
    }));
  const writeAudit =
    overrides.writeAudit ??
    vi.fn(async (req) => ({ entry: { id: "audit_test", timestamp: new Date(0).toISOString(), ...req.entry } }));
  const engine: GatewayDeps["engine"] = { scan: (req) => scanEngine.scan(req), verify, writeAudit };
  const deps: GatewayDeps = {
    engine,
    provider: guardProvider(provider),
    telemetry: { record: (e) => events.push(e) },
    scanTimeoutMs,
  };
  return { provider, events, deps, verify, writeAudit };
}

function userMessages(content: string): AegisMessage[] {
  return [{ role: "user", content }];
}

function scanResponse(overrides: Partial<ScanResponse>): ScanResponse {
  return {
    request_id: META.request_id,
    action: "allow",
    error_code: null,
    detections: [],
    sanitized_messages: null,
    vault_token: null,
    stages: [],
    processed_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function engineReturning(body: unknown): ScanEngine {
  return { scan: async () => body as ScanResponse };
}

function clientWithFetch(fetchImpl: typeof fetch): AegisClient {
  return new AegisClient({ baseUrl: "http://engine.test", fetchImpl, timeoutMs: 1_000 });
}

/** A localhost port with nothing listening on it — a genuinely offline engine. */
async function closedPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as net.AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// Fail closed: engine unavailable → 503, ZERO provider calls
// ---------------------------------------------------------------------------

describe("fail closed when the engine is unavailable", () => {
  const cases: Array<[string, () => Promise<ScanEngine>]> = [
    ["engine is offline (connection refused)", async () =>
      new AegisClient({ baseUrl: `http://127.0.0.1:${await closedPort()}`, timeoutMs: 1_000 })],
    ["engine throws", async () => ({ scan: async () => { throw new Error("boom"); } })],
    ["engine throws synchronously", async () => ({ scan: () => { throw new Error("sync boom"); } })],
    ["engine never answers (timeout)", async () => ({ scan: () => new Promise<ScanResponse>(() => {}) })],
    ["engine returns 500", async () => clientWithFetch(async () => new Response("{}", { status: 500 }))],
    ["engine returns 404", async () => clientWithFetch(async () => new Response("", { status: 404 }))],
    ["engine returns unparseable body", async () =>
      clientWithFetch(async () => new Response("<html>gateway error</html>", { status: 200 }))],
    ["engine returns empty body", async () => clientWithFetch(async () => new Response("", { status: 200 }))],
    ["engine returns JSON with the wrong shape", async () => engineReturning({ ok: true })],
    ["engine returns an unknown action", async () =>
      engineReturning(scanResponse({ action: "proceed" as unknown as ScanResponse["action"] }))],
    ["engine returns a verdict for another request", async () =>
      engineReturning(scanResponse({ request_id: "req_someone_else" }))],
    ["engine says sanitize but sends no sanitized_messages", async () =>
      engineReturning(scanResponse({ action: "sanitize", sanitized_messages: null }))],
    ["engine sanitize output still contains a redacted value", async () =>
      engineReturning(scanResponse({
        action: "sanitize",
        error_code: "PII_LEAK_PREVENTED",
        detections: [{ category: "PII_EMAIL", match: "jane@corp.com", placeholder: "[EMAIL_1]", start: 9, end: 22, confidence: 0.99, message_index: 0 }],
        sanitized_messages: userMessages("email to jane@corp.com"),
      }))],
  ];

  it.each(cases)("%s → 503 AEGIS_ENGINE_UNAVAILABLE and zero provider calls", async (_name, makeEngine) => {
    const { provider, events, deps } = harness(await makeEngine());

    const result = await guardedCompletion(META, new InboundMessages(userMessages("hello")), PARAMS, deps);

    expect(result.status).toBe(503);
    expect(result.body).toEqual({
      error: { code: "AEGIS_ENGINE_UNAVAILABLE", message: expect.any(String), request_id: META.request_id },
    });
    expect(provider).toHaveBeenCalledTimes(0);
    expect(events).toEqual([expect.objectContaining({ type: "scan_rejected", status: 503 })]);
  });

  it("times out at the gate deadline even if the client's own timeout is longer", async () => {
    vi.useFakeTimers();
    const { provider, deps } = harness({ scan: () => new Promise<ScanResponse>(() => {}) }, 3_000);

    const pending = guardedCompletion(META, new InboundMessages(userMessages("hello")), PARAMS, deps);
    await vi.advanceTimersByTimeAsync(3_000);

    expect((await pending).status).toBe(503);
    expect(provider).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Block enforcement
// ---------------------------------------------------------------------------

describe("block verdicts", () => {
  it.each([
    ["CREDENTIAL_LEAK_PREVENTED", 400, "CREDENTIAL_LEAK_PREVENTED"],
    ["PROMPT_INJECTION_BLOCKED", 403, "PROMPT_INJECTION_BLOCKED"],
    ["PII_LEAK_PREVENTED", 403, "AEGIS_POLICY_BLOCKED"],
    ["POLICY_VIOLATION", 403, "AEGIS_POLICY_BLOCKED"],
    ["SOMETHING_NEW_FROM_THE_ENGINE", 403, "AEGIS_POLICY_BLOCKED"],
    [null, 403, "AEGIS_POLICY_BLOCKED"],
  ] as const)("block + %s → HTTP %i %s, zero provider calls", async (engineCode, status, code) => {
    const { provider, deps } = harness(
      engineReturning(scanResponse({ action: "block", error_code: engineCode as ScanResponse["error_code"] })),
    );

    const result = await guardedCompletion(META, new InboundMessages(userMessages("x")), PARAMS, deps);

    expect(result.status).toBe(status);
    expect(result.body).toEqual({ error: { code, message: expect.any(String), request_id: META.request_id } });
    expect(provider).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Forwarding verdicts
// ---------------------------------------------------------------------------

describe("sanitize verdict", () => {
  const ORIGINAL = "Email Jane Doe at jane@corp.com about the merger";
  const SANITIZED = "Email [PERSON_1] at [EMAIL_1] about the merger";

  function sanitizingEngine(): ScanEngine & { seen: ScanRequest[] } {
    const seen: ScanRequest[] = [];
    return {
      seen,
      scan: async (req) => {
        seen.push(req);
        return scanResponse({
          action: "sanitize",
          error_code: "PII_LEAK_PREVENTED",
          detections: [
            { category: "PII_PERSON_NAME", match: "Jane Doe", placeholder: "[PERSON_1]", start: 6, end: 14, confidence: 0.9, message_index: 0 },
            { category: "PII_EMAIL", match: "jane@corp.com", placeholder: "[EMAIL_1]", start: 18, end: 31, confidence: 0.99, message_index: 0 },
          ],
          sanitized_messages: userMessages(SANITIZED),
        });
      },
    };
  }

  it("sends request_id, session_id, messages and mode to the engine", async () => {
    const engine = sanitizingEngine();
    const { deps } = harness(engine);

    await guardedCompletion(META, new InboundMessages(userMessages(ORIGINAL)), PARAMS, deps);

    expect(engine.seen).toEqual([
      { request_id: "req_test", session_id: "sess_test", principal: { tenant: "test", key_id: "test", dev_fallback: true }, mode: "sanitize", messages: userMessages(ORIGINAL) },
    ]);
  });

  it("reaches the provider with placeholders only", async () => {
    const { provider, deps } = harness(sanitizingEngine());

    const result = await guardedCompletion(META, new InboundMessages(userMessages(ORIGINAL)), PARAMS, deps);

    expect(result.status).toBe(200);
    expect(provider).toHaveBeenCalledTimes(1);
    const [prompt, params] = provider.mock.calls[0];
    expect(prompt.messages).toEqual(userMessages(SANITIZED));
    expect(params).toEqual({ ...PARAMS, model: "llama3.1" });
    // Nothing handed to the provider contains the original values.
    const handedOver = JSON.stringify(provider.mock.calls[0]);
    expect(handedOver).not.toContain("Jane Doe");
    expect(handedOver).not.toContain("jane@corp.com");
    expect(Object.isFrozen(prompt.messages)).toBe(true);
  });

  it("leaves the original messages unreachable after the gate", async () => {
    const { deps } = harness(sanitizingEngine());
    const inbound = new InboundMessages(userMessages(ORIGINAL));

    await guardedCompletion(META, inbound, PARAMS, deps);

    expect(() => inbound.take()).toThrow(/already consumed/);
  });

  it("keeps raw detection matches out of telemetry", async () => {
    const { events, deps } = harness(sanitizingEngine());

    await guardedCompletion(META, new InboundMessages(userMessages(ORIGINAL)), PARAMS, deps);

    expect(events).toContainEqual(
      {
        type: "scan_forwarded",
        request_id: "req_test",
        session_id: "sess_test", principal: { tenant: "test", key_id: "test", dev_fallback: true },
        summary: {
          action: "sanitize",
          error_code: "PII_LEAK_PREVENTED",
          detection_count: 2,
          detection_categories: ["PII_PERSON_NAME", "PII_EMAIL"],
        },
      }
    );
    expect(JSON.stringify(events)).not.toContain("jane@corp.com");
  });
});

describe("warn and allow verdicts", () => {
  it("warn → continues with original messages and records a warning", async () => {
    const { provider, events, deps } = harness(engineReturning(scanResponse({ action: "warn" })));

    const result = await guardedCompletion(META, new InboundMessages(userMessages("borderline")), PARAMS, deps);

    expect(result.status).toBe(200);
    expect(provider).toHaveBeenCalledTimes(1);
    expect(provider.mock.calls[0][0].messages).toEqual(userMessages("borderline"));
    expect(events).toContainEqual(expect.objectContaining({ type: "scan_warning", request_id: "req_test" }));
  });

  it("allow → continues with original messages", async () => {
    const { provider, events, deps } = harness(engineReturning(scanResponse({ action: "allow" })));

    const result = await guardedCompletion(META, new InboundMessages(userMessages("hi")), PARAMS, deps);

    expect(result).toEqual({ status: 200, body: COMPLETION });
    expect(provider.mock.calls[0][0].messages).toEqual(userMessages("hi"));
    expect(events).toContainEqual(expect.objectContaining({ type: "scan_forwarded" }));
  });
});

// ---------------------------------------------------------------------------
// The provider stage cannot be reached around the gate
// ---------------------------------------------------------------------------

describe("provider stage input", () => {
  it("refuses a forged ScannedPrompt", async () => {
    const inner = vi.fn<ProviderCall>(async () => COMPLETION);
    const provider = guardProvider(inner);
    const forged = { action: "allow", messages: userMessages("unscanned") } as unknown as ScannedPrompt;

    await expect(provider(forged, PARAMS, { request_id: "r" })).rejects.toThrow(/did not pass the Aegis scan gate/);
    expect(inner).not.toHaveBeenCalled();
  });

  it("cannot construct a ScannedPrompt without the gate's private mint", () => {
    const Ctor = ScannedPrompt as unknown as new (mint: symbol, m: AegisMessage[], a: string) => ScannedPrompt;
    expect(() => new Ctor(Symbol("aegis.scan-gate.mint"), userMessages("x"), "allow")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Response-path grounding & rehydration (Phase 4)
// ---------------------------------------------------------------------------

describe("response-path grounding & rehydration", () => {
  function sanitizingEngineWithVault(categories: ScanResponse["detections"][number]["category"][]): ScanEngine {
    return {
      scan: async () =>
        scanResponse({
          action: "sanitize",
          error_code: "PII_LEAK_PREVENTED",
          detections: categories.map((category, i) => ({
            category,
            match: `secret-or-pii-${i}`,
            placeholder: `[X_${i}]`,
            start: 0,
            end: 1,
            confidence: 0.9,
            message_index: 0,
          })),
          sanitized_messages: userMessages("redacted"),
          vault_token: "vault_abc",
        }),
    };
  }

  it("calls /internal/verify with the vault token, response text and reference_documents, and rehydrate: true on a clean sanitize", async () => {
    const { deps, verify } = harness(sanitizingEngineWithVault(["PII_EMAIL"]));

    await guardedCompletion(
      { ...META, reference_documents: ["doc one"] },
      new InboundMessages(userMessages(("x"))),
      PARAMS,
      deps,
    );

    expect(verify).toHaveBeenCalledWith({
      request_id: META.request_id,
      vault_token: "vault_abc",
      response_text: "ok",
      reference_documents: ["doc one"],
      rehydrate: true,
    });
  });

  it("defaults reference_documents to [] when the client sent none", async () => {
    const { deps, verify } = harness(sanitizingEngineWithVault(["PII_EMAIL"]));

    await guardedCompletion(META, new InboundMessages(userMessages("x")), PARAMS, deps);

    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ reference_documents: [] }));
  });

  it("never asks the engine to rehydrate when any detection in the ingress scan was a secret category", async () => {
    const { deps, verify } = harness(sanitizingEngineWithVault(["PII_EMAIL", "SECRET_JWT"]));

    await guardedCompletion(META, new InboundMessages(userMessages("x")), PARAMS, deps);

    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ rehydrate: false }));
  });

  it("uses final_text from a passing verify as the response content", async () => {
    const { deps } = harness(engineReturning(scanResponse({ action: "allow" })), 200, {
      verify: async (req) => ({
        request_id: req.request_id,
        final_text: "REHYDRATED ANSWER",
        rehydrated: true,
        grounding: { status: "pass", score: 0.99, unsupported_claims: [] },
        stages: [],
        processed_at: new Date(0).toISOString(),
      }),
    });

    const result = await guardedCompletion(META, new InboundMessages(userMessages("x")), PARAMS, deps);

    expect(result.status).toBe(200);
    expect((result.body as ChatCompletionResponse).choices[0].message.content).toBe("REHYDRATED ANSWER");
  });

  it("replaces the response body with the fallback text on a grounding block, never the engine's own wording", async () => {
    const { deps, events } = harness(engineReturning(scanResponse({ action: "allow" })), 200, {
      verify: async (req) => ({
        request_id: req.request_id,
        final_text: "some engine-side wording the gateway must not use",
        rehydrated: false,
        grounding: { status: "block", score: 0.1, unsupported_claims: ["unsupported claim"] },
        stages: [{ name: "nli_cross_check", status: "blocked", duration_ms: 5 }],
        processed_at: new Date(0).toISOString(),
      }),
    });

    const result = await guardedCompletion(META, new InboundMessages(userMessages("x")), PARAMS, deps);

    expect(result.status).toBe(200);
    const content = (result.body as ChatCompletionResponse).choices[0].message.content;
    expect(content).toBe("I cannot verify this claim against verified documentation.");
    expect(content).not.toContain("engine-side wording");
    expect(events).toContainEqual(
      expect.objectContaining({ type: "grounding_result", grounding_status: "block", blocked: true }),
    );
  });

  it("marks telemetry unverified (never a false pass) when /internal/verify is unreachable, but still returns the provider's text", async () => {
    const { deps, events } = harness(engineReturning(scanResponse({ action: "allow" })), 200, {
      verify: async () => { throw new Error("engine down"); },
    });

    const result = await guardedCompletion(META, new InboundMessages(userMessages("x")), PARAMS, deps);

    expect(result.status).toBe(200);
    expect((result.body as ChatCompletionResponse).choices[0].message.content).toBe("ok");
    expect(events).toContainEqual(
      expect.objectContaining({ type: "grounding_result", grounding_status: "unverified" }),
    );
  });

  it("fires an audit event even for a request blocked at the ingress scan gate", async () => {
    const { deps, writeAudit } = harness(
      engineReturning(scanResponse({ action: "block", error_code: "CREDENTIAL_LEAK_PREVENTED" })),
    );

    await guardedCompletion(META, new InboundMessages(userMessages("AKIA...")), PARAMS, deps);
    await new Promise((r) => setTimeout(r, 0));

    expect(writeAudit).toHaveBeenCalledWith(
      expect.objectContaining({ entry: expect.objectContaining({ request_id: META.request_id, action: "block" }) }),
    );
  });

  it("fires an audit event for a normal completion with grounding + cost telemetry populated", async () => {
    const { deps, writeAudit } = harness(engineReturning(scanResponse({ action: "allow" })));

    await guardedCompletion(META, new InboundMessages(userMessages("x")), PARAMS, deps);
    await new Promise((r) => setTimeout(r, 0));

    expect(writeAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        entry: expect.objectContaining({
          request_id: META.request_id,
          action: "allow",
          grounding_status: "pass",
          grounding_score: 1,
          cache_hit: false,
        }),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// A total provider failure must not skip the audit trail or leak an opaque throw
// (found by actually running the app against providers with no API key configured).
// ---------------------------------------------------------------------------

describe("total provider failure (past the gate, never reaches grounding)", () => {
  it("returns a structured 502 instead of throwing, and still fires an audit event", async () => {
    const { deps, writeAudit, verify } = harness(engineReturning(scanResponse({ action: "allow" })));
    deps.provider = guardProvider(async () => {
      throw new Error("All providers failed: primary 401, secondary 401");
    });

    const result = await guardedCompletion(META, new InboundMessages(userMessages("x")), PARAMS, deps);
    await new Promise((r) => setTimeout(r, 0));

    expect(result.status).toBe(502);
    expect(result.body).toEqual({
      error: {
        code: "AEGIS_PROVIDER_UNAVAILABLE",
        message: expect.stringContaining("All providers failed"),
        request_id: META.request_id,
      },
    });
    // Never reached grounding — a thrown provider call has no response text to ground.
    expect(verify).not.toHaveBeenCalled();
    expect(writeAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        entry: expect.objectContaining({ request_id: META.request_id, action: "allow", grounding_status: null }),
      }),
    );
  });
});
