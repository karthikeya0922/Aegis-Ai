import { afterEach, describe, expect, it, vi } from "vitest";
import { ProviderError } from "@aegis/providers/base";
import { OpenAICompatibleProvider } from "@aegis/providers/openai-compatible";

const SSRF = { allowedHosts: ["1.1.1.1"], allowPrivateIps: false };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function sseResponse(chunks: string[]): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
  return new Response(stream, { status: 200 });
}

const OLD_ENV = { ...process.env };
afterEach(() => {
  process.env = { ...OLD_ENV };
  vi.restoreAllMocks();
});

describe("OpenAICompatibleProvider.chat", () => {
  it("sends Authorization from process.env and maps the response", async () => {
    process.env.TEST_OPENAI_KEY = "sk-test-123";
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer sk-test-123");
      return jsonResponse({
        id: "chatcmpl-1",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi there" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
      });
    });

    const provider = new OpenAICompatibleProvider({
      name: "openai-test",
      baseUrl: "https://1.1.1.1/v1",
      apiKeyEnvVar: "TEST_OPENAI_KEY",
      ssrf: SSRF,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const result = await provider.chat({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
      signal: new AbortController().signal,
    });

    expect(result.content).toBe("hi there");
    expect(result.finish_reason).toBe("stop");
    expect(result.usage).toEqual({ prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("throws ProviderError with retryable=true on a 503", async () => {
    const fetchImpl = vi.fn(async () => new Response("upstream down", { status: 503 }));
    const provider = new OpenAICompatibleProvider({
      name: "openai-test",
      baseUrl: "https://1.1.1.1/v1",
      ssrf: SSRF,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(
      provider.chat({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }], signal: new AbortController().signal }),
    ).rejects.toMatchObject({ status: 503, retryable: true } satisfies Partial<ProviderError>);
  });

  it("throws a non-retryable ProviderError when the API key env var is unset", async () => {
    delete process.env.MISSING_KEY;
    const provider = new OpenAICompatibleProvider({
      name: "openai-test",
      baseUrl: "https://1.1.1.1/v1",
      apiKeyEnvVar: "MISSING_KEY",
      ssrf: SSRF,
      fetchImpl: vi.fn() as unknown as typeof fetch,
    });

    await expect(
      provider.chat({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }], signal: new AbortController().signal }),
    ).rejects.toMatchObject({ retryable: true, publicMessage: expect.stringContaining("not configured") });
  });

  it("rejects a base_url whose host is not allowlisted, without ever calling fetch", async () => {
    const fetchImpl = vi.fn();
    const provider = new OpenAICompatibleProvider({
      name: "openai-test",
      baseUrl: "https://2.2.2.2/v1",
      ssrf: SSRF,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(
      provider.chat({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }], signal: new AbortController().signal }),
    ).rejects.toThrow(/allowlist/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe("OpenAICompatibleProvider.stream", () => {
  it("yields incremental deltas parsed from SSE frames and stops at [DONE]", async () => {
    const fetchImpl = vi.fn(async () =>
      sseResponse([
        'data: {"id":"1","model":"m","choices":[{"index":0,"delta":{"content":"Hel"},"finish_reason":null}]}\n\n',
        'data: {"id":"1","model":"m","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}]}\n\n',
        'data: {"id":"1","model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
        "data: [DONE]\n\n",
      ]),
    );

    const provider = new OpenAICompatibleProvider({
      name: "openai-test",
      baseUrl: "https://1.1.1.1/v1",
      ssrf: SSRF,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const deltas: string[] = [];
    let lastFinish: string | null = null;
    for await (const chunk of provider.stream({ model: "m", messages: [{ role: "user", content: "hi" }], signal: new AbortController().signal })) {
      deltas.push(chunk.delta);
      lastFinish = chunk.finish_reason;
    }

    expect(deltas.join("")).toBe("Hello");
    expect(lastFinish).toBe("stop");
  });
});
