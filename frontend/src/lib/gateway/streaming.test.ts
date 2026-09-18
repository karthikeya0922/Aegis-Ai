import { describe, expect, it, vi } from "vitest";
import type { ChatChunk, ChatResponse, LLMProvider } from "@aegis/providers/base";
import { ProviderError } from "@aegis/providers/base";
import { CircuitBreaker } from "@aegis/providers/circuit-breaker";
import type { FailoverGroupMember } from "@aegis/providers/failover";
import type { AuditLogEntry, VerifyRequest, VerifyResponse } from "@aegis/types/aegis";
import type { AuditEngine } from "./audit";
import type { GroundingEngine } from "./grounding";
import { buildStreamingResponse } from "./streaming";
import { InboundMessages } from "./inbound";
import { runScanGate, type ScannedPrompt, type ScanEngine } from "./scan-gate";
import type { GatewayEvent } from "./telemetry";

/** scan-gate.ts's ScannedPrompt can only be minted by `runScanGate` — go through the real gate. */
async function mintScannedPrompt(): Promise<ScannedPrompt> {
  const allowEngine: ScanEngine = {
    async scan(req) {
      return {
        request_id: req.request_id,
        action: "allow",
        error_code: null,
        detections: [],
        sanitized_messages: null,
        vault_token: null,
        stages: [],
        processed_at: new Date().toISOString(),
      };
    },
  };
  const outcome = await runScanGate(
    { request_id: "req_mint", session_id: "sess_mint", mode: "sanitize" },
    new InboundMessages([{ role: "user", content: "hi" }]),
    allowEngine,
  );
  if (outcome.kind !== "forward") throw new Error("expected the fake engine to allow");
  return outcome.prompt;
}

/** Same as `mintScannedPrompt`, but for a "sanitize" verdict — `prompt.action` is
 * what `streaming.ts` actually gates rehydration on, not the `summary` passed
 * alongside it, so a rehydrate-flag test needs a genuinely sanitize-minted prompt. */
async function mintSanitizedPrompt(request_id: string, vault_token: string): Promise<ScannedPrompt> {
  const sanitizingEngine: ScanEngine = {
    async scan(req) {
      return {
        request_id: req.request_id,
        action: "sanitize",
        error_code: "PII_LEAK_PREVENTED",
        detections: [
          { category: "PII_EMAIL", match: "jane@corp.com", placeholder: "[EMAIL_1]", start: 0, end: 1, confidence: 0.9, message_index: 0 },
        ],
        sanitized_messages: [{ role: "user", content: "[EMAIL_1]" }],
        vault_token,
        stages: [],
        processed_at: new Date().toISOString(),
      };
    },
  };
  const outcome = await runScanGate(
    { request_id, session_id: "sess_mint", mode: "sanitize" },
    new InboundMessages([{ role: "user", content: "jane@corp.com" }]),
    sanitizingEngine,
  );
  if (outcome.kind !== "forward") throw new Error("expected the fake engine to sanitize");
  return outcome.prompt;
}

function member(provider: LLMProvider): FailoverGroupMember {
  return { provider, breaker: new CircuitBreaker() };
}

/** A grounding/audit engine that passes text through unchanged (grounding "pass") and no-ops audit. */
function fakeGroundingEngine(): GroundingEngine & AuditEngine {
  return {
    async verify(req: VerifyRequest): Promise<VerifyResponse> {
      return {
        request_id: req.request_id,
        final_text: req.response_text,
        rehydrated: false,
        grounding: { status: "pass", score: 1, unsupported_claims: [] },
        stages: [],
        processed_at: new Date().toISOString(),
      };
    },
    async writeAudit(req: { entry: Omit<AuditLogEntry, "id" | "timestamp"> }) {
      return { entry: { id: "audit_test", timestamp: new Date().toISOString(), ...req.entry } };
    },
  };
}

function collectingTelemetry() {
  const events: GatewayEvent[] = [];
  return { telemetry: { record: (e: GatewayEvent) => events.push(e) }, events };
}

async function readAll(res: Response): Promise<string> {
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

async function* okStream(text: string): AsyncGenerator<ChatChunk> {
  for (const ch of text) yield { id: "id", model: "m", delta: ch, finish_reason: null };
  yield { id: "id", model: "m", delta: "", finish_reason: "stop" };
}

function fakeProvider(name: string, streamImpl: (signal: AbortSignal) => AsyncGenerator<ChatChunk>): LLMProvider & { lastSignal?: AbortSignal } {
  const holder: LLMProvider & { lastSignal?: AbortSignal } = {
    name,
    async chat(): Promise<ChatResponse> {
      throw new Error("not used");
    },
    stream(req) {
      holder.lastSignal = req.signal;
      return streamImpl(req.signal);
    },
    async healthCheck() {
      return true;
    },
  };
  return holder;
}

describe("buildStreamingResponse", () => {
  it("emits OpenAI-shaped chunks, an aegis.telemetry event, and terminates with [DONE]", async () => {
    const provider = fakeProvider("primary", () => okStream("hi"));
    const { telemetry } = collectingTelemetry();

    const fakeSummary = { action: "allow" as const, error_code: null, detection_count: 0, detection_categories: [] };
    const res = buildStreamingResponse(
      await mintScannedPrompt(),
      fakeSummary,
      { model: "m" },
      { request_id: "req_1", session_id: "sess_1" , principal: { tenant: "test", key_id: "test", dev_fallback: true }, noCache: false},
      telemetry,
      fakeGroundingEngine(),
    );

    expect(res.headers.get("Content-Type")).toBe("text/event-stream");
    const text = await readAll(res);
    expect(text).toContain('"content":"h"');
    expect(text).toContain('"content":"i"');
    expect(text).toMatch(/event: aegis\.telemetry\ndata: .*"failover_used":false/);
    expect(text.trimEnd().endsWith("data: [DONE]")).toBe(true);
  });

  it("records provider_completion telemetry via the injected Telemetry sink", async () => {
    const provider = fakeProvider("primary", () => okStream("x"));
    const { telemetry, events } = collectingTelemetry();
    const fakeSummary = { action: "allow" as const, error_code: null, detection_count: 0, detection_categories: [] };

    const res = buildStreamingResponse(await mintScannedPrompt(), fakeSummary, { model: "m" }, { request_id: "req_2", session_id: "sess_2" , principal: { tenant: "test", key_id: "test", dev_fallback: true }, noCache: false}, telemetry, fakeGroundingEngine());
    await readAll(res);

    expect(events).toEqual([
      expect.objectContaining({ type: "provider_completion", mode: "stream", provider_used: "primary", failover_used: false }),
      expect.objectContaining({ type: "cost_estimate" }),
      expect.objectContaining({ type: "grounding_result", grounding_status: "pass", blocked: false, post_stream: true }),
    ]);
  });

  it("aborts the upstream provider signal when the client disconnects (stream cancelled)", async () => {
    let sawAbort = false;
    const provider = fakeProvider("primary", async function* (signal) {
      await new Promise<void>((resolve) => {
        signal.addEventListener("abort", () => {
          sawAbort = true;
          resolve();
        });
      });
      // Never actually yields — the point is the abort listener firing.
    });
    const { telemetry } = collectingTelemetry();
    const fakeSummary = { action: "allow" as const, error_code: null, detection_count: 0, detection_categories: [] };

    const res = buildStreamingResponse(await mintScannedPrompt(), fakeSummary, { model: "m" }, { request_id: "req_3", session_id: "sess_3" , principal: { tenant: "test", key_id: "test", dev_fallback: true }, noCache: false}, telemetry, fakeGroundingEngine());

    // Give `start()` a tick to call stream() and register the listener, then simulate
    // the client disconnecting by cancelling the response body — the same signal Next.js
    // sends when a browser aborts an in-flight fetch to this route.
    await new Promise((r) => setTimeout(r, 10));
    await res.body!.cancel();
    await new Promise((r) => setTimeout(r, 10));

    expect(sawAbort).toBe(true);
  });

  it("still emits a terminal chunk + telemetry + [DONE] when the stream fails to start at all", async () => {
    const provider = fakeProvider("primary", async function* () {
      throw new ProviderError("upstream 500", { provider: "primary", status: 500, retryable: true });
    });
    const { telemetry } = collectingTelemetry();
    const fakeSummary = { action: "allow" as const, error_code: null, detection_count: 0, detection_categories: [] };

    const res = buildStreamingResponse(await mintScannedPrompt(), fakeSummary, { model: "m" }, { request_id: "req_4", session_id: "sess_4" , principal: { tenant: "test", key_id: "test", dev_fallback: true }, noCache: false}, telemetry, fakeGroundingEngine());

    const text = await readAll(res);
    expect(text).toMatch(/event: aegis\.telemetry\ndata: .*"error":"All providers failed/);
    expect(text.trimEnd().endsWith("data: [DONE]")).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Response-path grounding & rehydration (Phase 4) — necessarily post-stream;
  // see the file header comment on `streaming.ts` for why.
  // -------------------------------------------------------------------------

  function findFrame(text: string, event: string): unknown {
    const match = text.match(new RegExp(`event: ${event}\\ndata: (.*)\\n\\n`));
    if (!match) throw new Error(`no ${event} frame found in:\n${text}`);
    return JSON.parse(match[1]);
  }

  it("emits a trailing aegis.grounding event carrying the verify verdict, after the raw chunks", async () => {
    const provider = fakeProvider("primary", () => okStream("hi"));
    const { telemetry } = collectingTelemetry();
    const fakeSummary = { action: "allow" as const, error_code: null, detection_count: 0, detection_categories: [] };
    const engine: GroundingEngine & AuditEngine = {
      ...fakeGroundingEngine(),
      async verify(req: VerifyRequest): Promise<VerifyResponse> {
        expect(req.response_text).toBe("hi"); // the FULL buffered text, not a partial chunk
        return {
          request_id: req.request_id,
          final_text: "hi",
          rehydrated: false,
          grounding: { status: "pass", score: 0.87, unsupported_claims: [] },
          stages: [],
          processed_at: new Date(0).toISOString(),
        };
      },
    };

    const res = buildStreamingResponse(await mintScannedPrompt(), fakeSummary, { model: "m" }, { request_id: "req_5", session_id: "sess_5" , principal: { tenant: "test", key_id: "test", dev_fallback: true }, noCache: false}, telemetry, engine);
    const text = await readAll(res);

    const grounding = findFrame(text, "aegis\\.grounding") as { grounding: { status: string; score: number }; blocked: boolean };
    expect(grounding.grounding).toEqual({ status: "pass", score: 0.87 });
    expect(grounding.blocked).toBe(false);
    // aegis.grounding comes before aegis.telemetry, which comes before [DONE].
    expect(text.indexOf("event: aegis.grounding")).toBeLessThan(text.indexOf("event: aegis.telemetry"));
    expect(text.indexOf("event: aegis.telemetry")).toBeLessThan(text.lastIndexOf("data: [DONE]"));
  });

  it("on a grounding block: the already-streamed raw chunks are untouched, but aegis.grounding carries the fallback final_text", async () => {
    const provider = fakeProvider("primary", () => okStream("hi"));
    const { telemetry } = collectingTelemetry();
    const fakeSummary = { action: "allow" as const, error_code: null, detection_count: 0, detection_categories: [] };
    const engine: GroundingEngine & AuditEngine = {
      ...fakeGroundingEngine(),
      async verify(req: VerifyRequest): Promise<VerifyResponse> {
        return {
          request_id: req.request_id,
          final_text: "engine-side wording the gateway must not use",
          rehydrated: false,
          grounding: { status: "block", score: 0.05, unsupported_claims: ["hi"] },
          stages: [],
          processed_at: new Date(0).toISOString(),
        };
      },
    };

    const res = buildStreamingResponse(await mintScannedPrompt(), fakeSummary, { model: "m" }, { request_id: "req_6", session_id: "sess_6" , principal: { tenant: "test", key_id: "test", dev_fallback: true }, noCache: false}, telemetry, engine);
    const text = await readAll(res);

    // The live chunks already went out raw — NOT retroactively patched.
    expect(text).toContain('"content":"h"');
    expect(text).toContain('"content":"i"');

    const grounding = findFrame(text, "aegis\\.grounding") as { blocked: boolean; final_text: string };
    expect(grounding.blocked).toBe(true);
    expect(grounding.final_text).toBe("I cannot verify this claim against verified documentation.");
    expect(grounding.final_text).not.toContain("engine-side wording");
  });

  it("passes vault_token and reference_documents from StreamContext through to /internal/verify", async () => {
    const provider = fakeProvider("primary", () => okStream("hi"));
    const { telemetry } = collectingTelemetry();
    const fakeSummary = { action: "sanitize" as const, error_code: "PII_LEAK_PREVENTED", detection_count: 1, detection_categories: ["PII_EMAIL"] };
    const verify = vi.fn(fakeGroundingEngine().verify);
    const engine: GroundingEngine & AuditEngine = { ...fakeGroundingEngine(), verify };

    const res = buildStreamingResponse(
      await mintSanitizedPrompt("req_7", "vault_xyz"),
      fakeSummary,
      { model: "m" },
      { request_id: "req_7", session_id: "sess_7", principal: { tenant: "test", key_id: "test", dev_fallback: true }, noCache: false, vault_token: "vault_xyz", reference_documents: ["doc a"] },
      telemetry,
      engine,
    );
    await readAll(res);

    expect(verify).toHaveBeenCalledWith({
      request_id: "req_7",
      vault_token: "vault_xyz",
      response_text: "hi",
      reference_documents: ["doc a"],
      rehydrate: true,
    });
  });
});
