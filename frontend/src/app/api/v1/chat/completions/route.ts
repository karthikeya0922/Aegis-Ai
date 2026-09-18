import { NextRequest, NextResponse } from "next/server";
import { nanoid } from "nanoid";
import { createClient } from "redis";
import { AegisClient } from "@aegis/aegis-client";
import { getVerifyTimeoutMs } from "@aegis/grounding-config";
import type { ScanMode } from "@aegis/types/aegis";
import { authenticate } from "@aegis/auth";
import { buildErrorPayload } from "@/lib/errors";
import { readChatRequest } from "@/lib/gateway/inbound";
import { guardedCompletion, runGuardedGate, type GatewayDeps } from "@/lib/gateway/pipeline";
import { getProviderRegistry, productionProviderCall } from "@/lib/gateway/provider";
import { DEFAULT_SCAN_TIMEOUT_MS } from "@/lib/gateway/scan-gate";
import { buildStreamingResponse } from "@/lib/gateway/streaming";
import { consoleTelemetry } from "@/lib/gateway/telemetry";

// Redis is optional for the rate limiter: when it is down we fail open (below),
// but only if connect() actually fails. node-redis reconnects forever by default,
// so without a bounded strategy a missing Redis would hang every request.
const redisClient = createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379",
  socket: {
    connectTimeout: 1500,
    reconnectStrategy: (retries) => (retries > 2 ? new Error("redis unavailable") : 300),
  },
});
let redisErrorLogged = false;
redisClient.on("error", (err) => {
  if (!redisErrorLogged) {
    redisErrorLogged = true;
    console.error("Redis Rate Limit Error (failing open):", err instanceof Error ? err.message : err);
  }
});
let redisConnected = false;
let redisConnectPromise: Promise<void> | null = null;
async function ensureRedis() {
  if (process.env.NODE_ENV === "test") return;
  if (!redisConnected) {
    if (!redisConnectPromise) {
      redisConnectPromise = redisClient.connect().then(() => { redisConnected = true; }).catch((err) => {
        redisConnectPromise = null;
        throw err;
      });
    }
    await Promise.race([
      redisConnectPromise,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("redis connect timeout")), 2000)),
    ]);
  }
}

function scanTimeoutMs(): number {
  const parsed = Number(process.env.AEGIS_SCAN_TIMEOUT_MS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_SCAN_TIMEOUT_MS;
}

function verifyTimeoutMs(): number {
  const parsed = Number(process.env.AEGIS_VERIFY_TIMEOUT_MS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : getVerifyTimeoutMs();
}

function gatewayDeps(): GatewayDeps {
  const scanMs = scanTimeoutMs();
  const verifyMs = verifyTimeoutMs();
  return {
    engine: new AegisClient({ timeoutMs: Math.max(scanMs, verifyMs) }),
    provider: productionProviderCall,
    telemetry: consoleTelemetry,
    scanTimeoutMs: scanMs,
    verifyTimeoutMs: verifyMs,
  };
}

export async function POST(req: NextRequest) {
  const requestId = "req_" + nanoid();
  const headers = new Headers();
  headers.set("x-request-id", requestId);

  try {
    // Authenticate
    const auth = authenticate(req.headers);
    if (!auth.ok) {
      return NextResponse.json(
        buildErrorPayload(auth.code, auth.message, requestId),
        { status: auth.status, headers }
      );
    }
    const principal = auth.principal;

    // Generate/read session_id from header or cookie
    let sessionId = req.headers.get("x-session-id") || req.cookies.get("session_id")?.value;
    if (!sessionId) {
      sessionId = "sess_" + nanoid();
      headers.set("Set-Cookie", `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Strict`);
    }

    // Rate Limiting
    if (process.env.NODE_ENV !== "test") {
      try {
        await ensureRedis();
        const rateLimitKey = `rate-limit:chat:${principal.tenant}:${principal.key_id}`;
        const limit = 60; // 60 requests per minute
        const current = await redisClient.incr(rateLimitKey);
        if (current === 1) {
          await redisClient.expire(rateLimitKey, 60);
        }
        if (current > limit) {
          return NextResponse.json(
            buildErrorPayload("rate_limited", "Too many requests", requestId),
            { status: 429, headers }
          );
        }
      } catch (err) {
        console.error("Rate limit check failed:", err);
        // Fail open if Redis is down
      }
    }
    // Read Aegis control headers
    const aegisMode: ScanMode = req.headers.get("x-aegis-mode") === "strict" ? "strict" : "sanitize";

    const aegisRefDocsHeader = req.headers.get("x-aegis-reference-docs");
    let aegisReferenceDocs: string[] | undefined;
    if (aegisRefDocsHeader) {
      try {
        const parsed = JSON.parse(aegisRefDocsHeader);
        if (Array.isArray(parsed) && parsed.every(item => typeof item === "string")) {
          aegisReferenceDocs = parsed;
        }
      } catch {
        // Ignore invalid JSON for now
      }
    }

    const inbound = await readChatRequest(req);
    if (!inbound.ok) {
      return NextResponse.json(
        buildErrorPayload(inbound.code, inbound.message, requestId),
        { status: inbound.status, headers }
      );
    }

    const noCache = req.headers.get("x-aegis-no-cache") === "true";
    const confidentialMode = req.headers.get("x-aegis-confidential") === "true";
    const referenceDocuments = aegisReferenceDocs ?? [];
    const meta = {
      request_id: requestId,
      session_id: sessionId,
      mode: aegisMode,
      principal,
      noCache,
      confidential_mode: confidentialMode,
      reference_documents: referenceDocuments,
    };
    const deps = gatewayDeps();

    // SSE branch: `stream: true` returns a text/event-stream response instead of a
    // single JSON body. The scan gate still runs to completion first — streaming
    // starts only for a "forward" verdict; a reject is still plain JSON.
    if (inbound.params.stream === true) {
      const gate = await runGuardedGate(meta, inbound.messages, deps);
      if (gate.kind === "reject") {
        // A blocked request still has a story to tell. Ship the redacted scan so
        // the inspector can mark the offending stage instead of going blank.
        const body = { ...(gate.result.body as Record<string, unknown>), aegis: gate.inspector };
        return NextResponse.json(body, { status: gate.result.status, headers });
      }

      const streamCtx = {
        request_id: requestId,
        session_id: sessionId,
        principal,
        noCache,
        vault_token: gate.vault_token,
        reference_documents: referenceDocuments,
        verifyTimeoutMs: deps.verifyTimeoutMs,
        inspector: gate.inspector,
      };
      return buildStreamingResponse(gate.prompt, gate.summary, inbound.params, streamCtx, deps.telemetry, deps.engine, headers);
    }

    // SECURITY GATE. The provider is only reachable through guardedCompletion,
    // which scans first and fails closed. Do not add a provider call here.
    const result = await guardedCompletion(meta, inbound.messages, inbound.params, deps, req.signal);

    return NextResponse.json(result.body, { status: result.status, headers });
  } catch {
    return NextResponse.json(
      buildErrorPayload("internal_error", "An internal error occurred", requestId),
      { status: 500, headers }
    );
  }
}
