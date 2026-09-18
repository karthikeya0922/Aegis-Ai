import { afterEach, describe, expect, it, vi } from "vitest";
import { OllamaProvider } from "@aegis/providers/ollama";

const SSRF = { allowedHosts: ["127.0.0.1"], allowPrivateIps: true };

afterEach(() => vi.restoreAllMocks());

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("OllamaProvider", () => {
  it("requires allowPrivateIps to reach its loopback default", async () => {
    const fetchImpl = vi.fn();
    const provider = new OllamaProvider({
      name: "ollama-test",
      baseUrl: "http://127.0.0.1:11434",
      ssrf: { allowedHosts: ["127.0.0.1"], allowPrivateIps: false },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(
      provider.chat({ model: "llama3.1", messages: [{ role: "user", content: "hi" }], signal: new AbortController().signal }),
    ).rejects.toThrow(/private\/reserved/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("chat() maps an Ollama response with no API key required", async () => {
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect((init?.headers as Record<string, string>).Authorization).toBeUndefined();
      return jsonResponse({
        model: "llama3.1",
        message: { role: "assistant", content: "hello from ollama" },
        done: true,
        done_reason: "stop",
        prompt_eval_count: 10,
        eval_count: 4,
      });
    });

    const provider = new OllamaProvider({
      name: "ollama-test",
      baseUrl: "http://127.0.0.1:11434",
      ssrf: SSRF,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const result = await provider.chat({
      model: "llama3.1",
      messages: [{ role: "user", content: "hi" }],
      signal: new AbortController().signal,
    });

    expect(result.content).toBe("hello from ollama");
    expect(result.usage).toEqual({ prompt_tokens: 10, completion_tokens: 4, total_tokens: 14 });
    expect(result.finish_reason).toBe("stop");
  });

  it("stream() yields deltas from newline-delimited JSON and stops on done", async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(JSON.stringify({ model: "llama3.1", message: { role: "assistant", content: "Hel" }, done: false }) + "\n"));
        controller.enqueue(encoder.encode(JSON.stringify({ model: "llama3.1", message: { role: "assistant", content: "lo" }, done: false }) + "\n"));
        controller.enqueue(
          encoder.encode(JSON.stringify({ model: "llama3.1", message: { role: "assistant", content: "" }, done: true, done_reason: "stop" }) + "\n"),
        );
        controller.close();
      },
    });
    const fetchImpl = vi.fn(async () => new Response(stream, { status: 200 }));

    const provider = new OllamaProvider({
      name: "ollama-test",
      baseUrl: "http://127.0.0.1:11434",
      ssrf: SSRF,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const deltas: string[] = [];
    for await (const chunk of provider.stream({ model: "llama3.1", messages: [{ role: "user", content: "hi" }], signal: new AbortController().signal })) {
      deltas.push(chunk.delta);
    }

    expect(deltas.join("")).toBe("Hello");
  });
});
