import net from "node:net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// Replace the real (registry + failover) provider with a spy so we can prove it is
// never reached. `getProviderRegistry` is also stubbed so these tests never touch
// config/providers.yaml or a real provider API key.
const providerSpy = vi.hoisted(() => vi.fn());
vi.mock("@/lib/gateway/provider", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/gateway/provider")>();
  return {
    ...actual,
    productionProviderCall: providerSpy,
    getProviderRegistry: vi.fn(async () => ({ getFailoverGroup: () => [] })),
  };
});

import { POST } from "./route";

async function closedPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as net.AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

describe("POST /api/v1/chat/completions with the engine offline", () => {
  const previousUrl = process.env.AEGIS_ENGINE_URL;

  beforeAll(async () => {
    process.env.AEGIS_ENGINE_URL = `http://127.0.0.1:${await closedPort()}`;
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "debug").mockImplementation(() => {});
  });

  afterAll(() => {
    process.env.AEGIS_ENGINE_URL = previousUrl;
    vi.restoreAllMocks();
  });

  it("returns 503 AEGIS_ENGINE_UNAVAILABLE and makes zero provider calls", async () => {
    const req = new NextRequest("http://localhost/api/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hello" }] }),
    });

    const res = await POST(req);

    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error.code).toBe("AEGIS_ENGINE_UNAVAILABLE");
    expect(body.error.request_id).toBe(res.headers.get("x-request-id"));
    expect(providerSpy).toHaveBeenCalledTimes(0);
  });

  it("rejects message shapes the engine cannot scan before calling anything", async () => {
    const req = new NextRequest("http://localhost/api/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: [{ type: "text", text: "hidden from a string-only scanner" }] }],
      }),
    });

    const res = await POST(req);

    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe("validation_error");
    expect(providerSpy).toHaveBeenCalledTimes(0);
  });
});
