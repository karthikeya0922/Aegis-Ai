import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import type { ChatChunk, ChatResponse, LLMProvider } from "@aegis/providers/base";
import { ProviderError } from "@aegis/providers/base";
import { CircuitBreaker } from "@aegis/providers/circuit-breaker";
import type { FailoverGroupMember } from "@aegis/providers/failover";
import type { ScanRequest, ScanResponse, VerifyRequest, VerifyResponse } from "@aegis/types/aegis";

// A fake engine that always allows, echoing back whatever request_id it's given
// (the scan gate rejects a mismatched request_id as engine-unavailable). `verify`
// passes the text through unchanged (grounding "pass") and `writeAudit` no-ops —
// neither is under test here, but the streaming pipeline calls both unconditionally.
vi.mock("@aegis/aegis-client", () => ({
  AegisClient: vi.fn().mockImplementation(() => ({
    scan: vi.fn(
      async (req: ScanRequest): Promise<ScanResponse> => ({
        request_id: req.request_id,
        action: "allow",
        error_code: null,
        detections: [],
        sanitized_messages: null,
        vault_token: null,
        stages: [],
        processed_at: new Date().toISOString(),
      }),
    ),
    verify: vi.fn(
      async (req: VerifyRequest): Promise<VerifyResponse> => ({
        request_id: req.request_id,
        final_text: req.response_text,
        rehydrated: false,
        grounding: { status: "pass", score: 1, unsupported_claims: [] },
        stages: [],
        processed_at: new Date().toISOString(),
      }),
    ),
    writeAudit: vi.fn(async () => ({
      entry: {
        id: "audit_test",
        request_id: "req_test",
        timestamp: new Date().toISOString(),
        model_used: null,
        tokens_consumed: null,
        latency_ms: null,
        scrubbed_entity_count: 0,
        rule_triggers: [],
        action: "allow",
        error_code: null,
        provider_used: null,
        cache_hit: false,
        failover_used: false,
        grounding_status: null,
        grounding_score: null,
        estimated_cost_usd: null,
        estimated_savings_usd: null,
        estimated_carbon_g: null,
      },
    })),
  })),
}));

let fakeGroup: FailoverGroupMember[] = [];
vi.mock("@/lib/gateway/provider", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/gateway/provider")>();
  return { ...actual, getProviderRegistry: vi.fn(async () => ({ getFailoverGroup: () => fakeGroup })) };
});

import { POST } from "./route";

function fakeProvider(name: string, streamImpl: () => AsyncGenerator<ChatChunk>): LLMProvider {
  return {
    name,
    async chat(): Promise<ChatResponse> {
      throw new Error("not used in this test");
    },
    stream: streamImpl,
    async healthCheck() {
      return true;
    },
  };
}

async function* failsWith500(): AsyncGenerator<ChatChunk> {
  throw new ProviderError("upstream 500", { provider: "primary", status: 500, retryable: true });
}

async function* streamsText(text: string): AsyncGenerator<ChatChunk> {
  for (const ch of text) yield { id: "id", model: "m", delta: ch, finish_reason: null };
  yield { id: "id", model: "m", delta: "", finish_reason: "stop" };
}

async function readSse(res: Response): Promise<string> {
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let out = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out += decoder.decode(value, { stream: true });
  }
  return out;
}

function parseFrames(sse: string): Array<{ event: string | null; data: unknown }> {
  return sse
    .split("\n\n")
    .filter((chunk) => chunk.trim().length > 0)
    .map((chunk) => {
      const lines = chunk.split("\n");
      const eventLine = lines.find((l) => l.startsWith("event: "));
      const dataLine = lines.find((l) => l.startsWith("data: "));
      const raw = dataLine!.slice("data: ".length);
      return { event: eventLine ? eventLine.slice("event: ".length) : null, data: raw === "[DONE]" ? "[DONE]" : JSON.parse(raw) };
    });
}

function streamingRequest(): NextRequest {
  return new NextRequest("http://localhost/api/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }], stream: true }),
  });
}

afterEach(() => {
  // NOT vi.restoreAllMocks(): `AegisClient` here is a plain vi.fn().mockImplementation(...)
  // (not a vi.spyOn), so restoreAllMocks() would strip its implementation entirely
  // (back to a no-op) instead of leaving the fake engine in place for the next test.
  fakeGroup = [];
});

describe("POST /api/v1/chat/completions with stream: true", () => {
  it("returns text/event-stream and forwards the primary's chunks, ending in [DONE]", async () => {
    fakeGroup = [{ provider: fakeProvider("primary", () => streamsText("hi")), breaker: new CircuitBreaker() }];

    const res = await POST(streamingRequest());

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/event-stream");

    const frames = parseFrames(await readSse(res));
    const contentDeltas = frames
      .filter((f) => f.event === null && f.data !== "[DONE]")
      .map((f) => (f.data as { choices: Array<{ delta: { content?: string } }> }).choices[0].delta.content ?? "")
      .join("");
    expect(contentDeltas).toBe("hi");
    expect(frames.at(-1)).toEqual({ event: null, data: "[DONE]" });

    const telemetryFrame = frames.find((f) => f.event === "aegis.telemetry");
    expect(telemetryFrame?.data).toMatchObject({ provider_used: "primary", failover_used: false });
  });

  it("fails over to the secondary when the primary's stream starts with a 500, and reports failover_used: true", async () => {
    fakeGroup = [
      { provider: fakeProvider("primary", failsWith500), breaker: new CircuitBreaker() },
      { provider: fakeProvider("secondary", () => streamsText("recovered")), breaker: new CircuitBreaker() },
    ];

    const res = await POST(streamingRequest());

    expect(res.status).toBe(200);
    const frames = parseFrames(await readSse(res));
    const contentDeltas = frames
      .filter((f) => f.event === null && f.data !== "[DONE]")
      .map((f) => (f.data as { choices: Array<{ delta: { content?: string } }> }).choices[0].delta.content ?? "")
      .join("");
    expect(contentDeltas).toBe("recovered");

    const telemetryFrame = frames.find((f) => f.event === "aegis.telemetry");
    expect(telemetryFrame?.data).toMatchObject({
      provider_used: "secondary",
      primary_provider: "primary",
      primary_failed: true,
      failover_used: true,
    });
  });
});
