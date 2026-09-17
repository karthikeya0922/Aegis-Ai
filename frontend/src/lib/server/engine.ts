/**
 * Server-only access to Person 1's Python security engine.
 *
 * Every browser-facing route goes through here. The engine's base URL and any
 * service credential stay in the Node process — the browser never learns the
 * engine's address and never calls it directly.
 */

import "server-only";

export const ENGINE_BASE_URL = process.env.AEGIS_ENGINE_URL ?? "http://localhost:8000";

export const ENGINE_UNAVAILABLE = {
  error: {
    code: "AEGIS_ENGINE_UNAVAILABLE",
    message: "The Aegis security engine is unavailable.",
  },
} as const;

export interface EngineFetchInit extends Omit<RequestInit, "body"> {
  query?: Record<string, string | undefined>;
  body?: unknown;
  timeoutMs?: number;
}

export async function engineFetch(path: string, init: EngineFetchInit = {}): Promise<Response> {
  const { query, body, timeoutMs = 10_000, headers, ...rest } = init;

  const url = new URL(path, ENGINE_BASE_URL);
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== "") url.searchParams.set(k, v);
  }

  const merged = new Headers(headers);
  merged.set("accept", merged.get("accept") ?? "application/json");
  if (process.env.AEGIS_ENGINE_TOKEN) {
    merged.set("authorization", `Bearer ${process.env.AEGIS_ENGINE_TOKEN}`);
  }
  if (body !== undefined) merged.set("content-type", "application/json");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...rest,
      headers: merged,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
      cache: "no-store",
    });
  } finally {
    clearTimeout(timer);
  }
}
