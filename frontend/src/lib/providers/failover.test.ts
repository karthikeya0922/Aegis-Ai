import { describe, expect, it } from "vitest";
import { type ChatChunk, type ChatRequest, type ChatResponse, type LLMProvider, ProviderError } from "@aegis/providers/base";
import { CircuitBreaker } from "@aegis/providers/circuit-breaker";
import { chatWithFailover, type FailoverGroupMember, streamWithFailover } from "@aegis/providers/failover";

function req(overrides: Partial<ChatRequest> = {}): ChatRequest {
  return { model: "m", messages: [{ role: "user", content: "hi" }], signal: new AbortController().signal, ...overrides };
}

function okResponse(name: string): ChatResponse {
  return { id: "id", model: "m", content: `hello from ${name}`, finish_reason: "stop", usage: null };
}

/** A provider whose chat()/stream() replays a scripted sequence of outcomes, one per call. */
class ScriptedProvider implements LLMProvider {
  readonly name: string;
  private chatScript: Array<() => Promise<ChatResponse>>;
  private streamScript: Array<() => AsyncIterable<ChatChunk>>;
  callCount = 0;

  constructor(name: string, chatScript: Array<() => Promise<ChatResponse>> = [], streamScript: Array<() => AsyncIterable<ChatChunk>> = []) {
    this.name = name;
    this.chatScript = chatScript;
    this.streamScript = streamScript;
  }

  async chat(): Promise<ChatResponse> {
    const step = this.chatScript[this.callCount] ?? this.chatScript[this.chatScript.length - 1];
    this.callCount++;
    return step();
  }

  stream(): AsyncIterable<ChatChunk> {
    const step = this.streamScript[this.callCount] ?? this.streamScript[this.streamScript.length - 1];
    this.callCount++;
    return step();
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }
}

function httpError(provider: string, status: number): () => Promise<never> {
  return () =>
    Promise.reject(
      new ProviderError(`upstream ${status}`, { provider, status, retryable: status === 429 || status >= 500 }),
    );
}

function timeoutError(provider: string): () => Promise<never> {
  return () => Promise.reject(new ProviderError("connect timeout exceeded (2500ms)", { provider, status: null, retryable: true }));
}

function member(provider: LLMProvider): FailoverGroupMember {
  return { provider, breaker: new CircuitBreaker() };
}

async function drain(gen: AsyncGenerator<ChatChunk>): Promise<string> {
  let out = "";
  for await (const chunk of gen) out += chunk.delta;
  return out;
}

async function* okStream(text: string): AsyncGenerator<ChatChunk> {
  for (const ch of text) yield { id: "id", model: "m", delta: ch, finish_reason: null };
  yield { id: "id", model: "m", delta: "", finish_reason: "stop" };
}

describe("chatWithFailover", () => {
  it("uses the primary when it succeeds — no failover", async () => {
    const primary = new ScriptedProvider("primary", [() => Promise.resolve(okResponse("primary"))]);
    const secondary = new ScriptedProvider("secondary", [() => Promise.resolve(okResponse("secondary"))]);

    const { response, telemetry } = await chatWithFailover([member(primary), member(secondary)], req());

    expect(response.content).toBe("hello from primary");
    expect(telemetry).toEqual({ primary: "primary", used: "primary", primary_failed: false, failover_used: false, attempts: [] });
    expect(secondary.callCount).toBe(0);
  });

  it.each([500, 502, 503, 429])("fails over to the secondary on a %d from the primary", async (status) => {
    const primary = new ScriptedProvider("primary", [httpError("primary", status)]);
    const secondary = new ScriptedProvider("secondary", [() => Promise.resolve(okResponse("secondary"))]);

    const { response, telemetry } = await chatWithFailover([member(primary), member(secondary)], req());

    expect(response.content).toBe("hello from secondary");
    expect(telemetry.used).toBe("secondary");
    expect(telemetry.primary_failed).toBe(true);
    expect(telemetry.failover_used).toBe(true);
    expect(telemetry.attempts).toEqual([{ provider: "primary", skipped_open_circuit: false, status, message: expect.any(String) }]);
  });

  it("fails over on a connect/total timeout (status null, retryable)", async () => {
    const primary = new ScriptedProvider("primary", [timeoutError("primary")]);
    const secondary = new ScriptedProvider("secondary", [() => Promise.resolve(okResponse("secondary"))]);

    const { telemetry } = await chatWithFailover([member(primary), member(secondary)], req());

    expect(telemetry.failover_used).toBe(true);
    expect(telemetry.used).toBe("secondary");
  });

  it("does NOT fail over on a non-retryable error (e.g. a 400)", async () => {
    const primary = new ScriptedProvider("primary", [httpError("primary", 400)]);
    const secondary = new ScriptedProvider("secondary", [() => Promise.resolve(okResponse("secondary"))]);

    await expect(chatWithFailover([member(primary), member(secondary)], req())).rejects.toMatchObject({ retryable: false });
    expect(secondary.callCount).toBe(0);
  });

  it("throws once every provider in the chain has failed", async () => {
    const primary = new ScriptedProvider("primary", [httpError("primary", 500)]);
    const secondary = new ScriptedProvider("secondary", [httpError("secondary", 503)]);

    await expect(chatWithFailover([member(primary), member(secondary)], req())).rejects.toThrow(/All providers failed/);
  });

  it("trips the primary's breaker after failureThreshold failures, then skips it (circuit open) on later requests", async () => {
    const primaryBreaker = new CircuitBreaker({ failureThreshold: 2 });
    const primary = new ScriptedProvider("primary", [httpError("primary", 503), httpError("primary", 503), httpError("primary", 503)]);
    const secondary = new ScriptedProvider("secondary", [
      () => Promise.resolve(okResponse("secondary")),
      () => Promise.resolve(okResponse("secondary")),
      () => Promise.resolve(okResponse("secondary")),
    ]);
    const group: FailoverGroupMember[] = [{ provider: primary, breaker: primaryBreaker }, member(secondary)];

    await chatWithFailover(group, req()); // failure 1
    await chatWithFailover(group, req()); // failure 2 -> trips breaker OPEN
    expect(primaryBreaker.getState()).toBe("OPEN");

    const { telemetry } = await chatWithFailover(group, req()); // primary skipped entirely now
    expect(telemetry.attempts).toEqual([{ provider: "primary", skipped_open_circuit: true, status: null, message: "circuit open" }]);
    expect(primary.callCount).toBe(2); // not called a 3rd time
    expect(telemetry.used).toBe("secondary");
    expect(telemetry.failover_used).toBe(true);
  });

  it("reports failover_used: true and the actually-used provider in telemetry", async () => {
    const primary = new ScriptedProvider("glm-free", [httpError("glm-free", 500)]);
    const secondary = new ScriptedProvider("groq", [() => Promise.resolve(okResponse("groq"))]);

    const { telemetry } = await chatWithFailover([member(primary), member(secondary)], req());

    expect(telemetry).toMatchObject({ primary: "glm-free", used: "groq", failover_used: true, primary_failed: true });
  });
});

describe("streamWithFailover", () => {
  it("streams from the primary when it starts successfully", async () => {
    const primary = new ScriptedProvider("primary", [], [() => okStream("hi")]);
    const secondary = new ScriptedProvider("secondary", [], [() => okStream("bye")]);

    const { chunks, telemetry } = await streamWithFailover([member(primary), member(secondary)], req());
    expect(await drain(chunks)).toBe("hi");
    expect(telemetry.failover_used).toBe(false);
    expect(secondary.callCount).toBe(0);
  });

  it.each([500, 503, 429])("fails over to the secondary when the primary's stream fails to start (%d)", async (status) => {
    async function* fail(): AsyncGenerator<ChatChunk> {
      throw new ProviderError(`upstream ${status}`, { provider: "primary", status, retryable: true });
    }
    const primary = new ScriptedProvider("primary", [], [() => fail()]);
    const secondary = new ScriptedProvider("secondary", [], [() => okStream("recovered")]);

    const { chunks, telemetry } = await streamWithFailover([member(primary), member(secondary)], req());
    expect(await drain(chunks)).toBe("recovered");
    expect(telemetry.used).toBe("secondary");
    expect(telemetry.primary_failed).toBe(true);
    expect(telemetry.failover_used).toBe(true);
  });

  it("does not fail over once the primary has already yielded its first chunk", async () => {
    async function* flaky(): AsyncGenerator<ChatChunk> {
      yield { id: "id", model: "m", delta: "par", finish_reason: null };
      throw new ProviderError("dropped connection mid-stream", { provider: "primary", status: null, retryable: true });
    }
    const primary = new ScriptedProvider("primary", [], [() => flaky()]);
    const secondary = new ScriptedProvider("secondary", [], [() => okStream("should not be used")]);

    const { chunks } = await streamWithFailover([member(primary), member(secondary)], req());
    await expect(drain(chunks)).rejects.toThrow(/dropped connection/);
    expect(secondary.callCount).toBe(0);
  });

  it("throws once every provider's stream fails to start", async () => {
    async function* fail500(): AsyncGenerator<ChatChunk> {
      throw new ProviderError("upstream 500", { provider: "primary", status: 500, retryable: true });
    }
    async function* fail503(): AsyncGenerator<ChatChunk> {
      throw new ProviderError("upstream 503", { provider: "secondary", status: 503, retryable: true });
    }
    const primary = new ScriptedProvider("primary", [], [() => fail500()]);
    const secondary = new ScriptedProvider("secondary", [], [() => fail503()]);

    await expect(streamWithFailover([member(primary), member(secondary)], req())).rejects.toThrow(/All providers failed/);
  });
});

describe("failover with zero/one provider configured", () => {
  it("throws immediately with an empty group", async () => {
    await expect(chatWithFailover([], req())).rejects.toThrow(/No providers configured/);
  });

  it("propagates a single provider's failure with no secondary to fall back to", async () => {
    const only = new ScriptedProvider("only", [httpError("only", 503)]);
    await expect(chatWithFailover([member(only)], req())).rejects.toThrow(/All providers failed/);
  });
});

describe("respects the caller's own AbortSignal", () => {
  it("aborts the provider call when the caller's signal fires", async () => {
    const controller = new AbortController();
    const provider = new ScriptedProvider("primary", [
      (): Promise<ChatResponse> =>
        new Promise((_resolve, reject) => {
          controller.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    ]);

    const callPromise = chatWithFailover([member(provider)], req({ signal: controller.signal }));
    controller.abort();
    await expect(callPromise).rejects.toThrow(/All providers failed/);
  });
});
