/**
 * Aegis engine client — a typed fetch wrapper around Person 1's security engine.
 *
 * Points at `AEGIS_ENGINE_URL` (defaults to the local mock on :8001) so the rest of
 * the app never has to know whether it's talking to `mocks/engine/server.ts` or the
 * real Python service — same contract either way (see `lib/types/aegis.ts`).
 *
 * Server-side use only: this reads `process.env.AEGIS_ENGINE_URL` directly, which is
 * unavailable in the browser. Call it from Next.js server components, route handlers,
 * or server actions.
 */

import type {
  AuditLogRequest,
  AuditLogResponse,
  AuditQueryRequest,
  AuditQueryResponse,
  HealthResponse,
  PoliciesResponse,
  ScanRequest,
  ScanResponse,
  UpdatePoliciesRequest,
  VerifyRequest,
  VerifyResponse,
} from "./types/aegis";

const DEFAULT_ENGINE_URL = "http://localhost:8001";

/** Thrown when the engine responds with a non-2xx status or unparsable body. */
export class AegisClientError extends Error {
  readonly status: number;
  readonly url: string;
  readonly body: unknown;

  constructor(message: string, status: number, url: string, body: unknown) {
    super(message);
    this.name = "AegisClientError";
    this.status = status;
    this.url = url;
    this.body = body;
  }
}

export interface AegisClientOptions {
  /** Overrides `AEGIS_ENGINE_URL` / the localhost default — mainly for tests. */
  baseUrl?: string;
  /** Aborts a request after this many ms. Defaults to 10_000. */
  timeoutMs?: number;
  /** Injectable fetch implementation — mainly for tests. */
  fetchImpl?: typeof fetch;
}

function resolveBaseUrl(override?: string): string {
  const url = override ?? process.env.AEGIS_ENGINE_URL ?? DEFAULT_ENGINE_URL;
  return url.replace(/\/+$/, "");
}

async function parseJsonSafely(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.length === 0) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

export class AegisClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: AegisClientOptions = {}) {
    this.baseUrl = resolveBaseUrl(options.baseUrl);
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  private async request<TResponse>(
    method: "GET" | "POST" | "PUT",
    path: string,
    body?: unknown,
    searchParams?: Record<string, string | number | undefined>,
  ): Promise<TResponse> {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(searchParams ?? {})) {
      if (value !== undefined) query.set(key, String(value));
    }
    const queryString = query.toString();
    const url = `${this.baseUrl}${path}${queryString.length > 0 ? `?${queryString}` : ""}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    // The timeout must cover reading the body too: an engine that sends headers and
    // then stalls would otherwise hang the caller forever.
    let response: Response;
    let parsed: unknown;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      parsed = await parseJsonSafely(response);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      throw new AegisClientError(`Aegis engine request failed: ${message}`, 0, url, null);
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new AegisClientError(
        `Aegis engine returned ${response.status} for ${method} ${path}`,
        response.status,
        url,
        parsed,
      );
    }

    return parsed as TResponse;
  }

  /** Ingress PII / secret / prompt-injection scan (Features 1 & 4). */
  scan(req: ScanRequest): Promise<ScanResponse> {
    return this.request<ScanResponse>("POST", "/internal/scan", req);
  }

  /** RAG faithfulness / hallucination check (Feature 3). */
  verify(req: VerifyRequest): Promise<VerifyResponse> {
    return this.request<VerifyResponse>("POST", "/internal/verify", req);
  }

  /** Append one entry to the EU AI Act audit trail (Feature 5). */
  writeAudit(req: AuditLogRequest): Promise<AuditLogResponse> {
    return this.request<AuditLogResponse>("POST", "/internal/audit", req);
  }

  /** Query recent audit entries, e.g. to compile the PDF export (Feature 5). */
  queryAudit(req: AuditQueryRequest = {}): Promise<AuditQueryResponse> {
    return this.request<AuditQueryResponse>("GET", "/internal/audit", undefined, {
      from: req.from,
      to: req.to,
      limit: req.limit,
    });
  }

  /** Fetch the current guardrail policy configuration. */
  getPolicies(): Promise<PoliciesResponse> {
    return this.request<PoliciesResponse>("GET", "/internal/policies");
  }

  /** Partially update the guardrail policy configuration. */
  updatePolicies(req: UpdatePoliciesRequest): Promise<PoliciesResponse> {
    return this.request<PoliciesResponse>("PUT", "/internal/policies", req);
  }

  /** Engine liveness/version check. */
  health(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "/internal/health");
  }
}

/** Shared default client, pointed at `AEGIS_ENGINE_URL` (or the local mock). */
export const aegisClient = new AegisClient();
