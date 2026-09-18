import { NextRequest, NextResponse } from "next/server";
import { engineFetch, ENGINE_UNAVAILABLE } from "@/lib/server/engine";

export const dynamic = "force-dynamic";

/**
 * GET /api/audit/events — paginated, filtered audit trail.
 *
 * A proxy, deliberately. The browser must never reach the Python service
 * directly: this keeps the engine URL and its credential server-side, and gives
 * one place to whitelist which filters are forwarded.
 */

const ACTIONS = new Set(["allow", "warn", "sanitize", "block"]);
const MAX_PAGE_SIZE = 100;

export async function GET(req: NextRequest) {
  const sp = req.nextUrl.searchParams;

  const page = Math.max(1, Number(sp.get("page") ?? 1) || 1);
  const pageSize = Math.min(MAX_PAGE_SIZE, Math.max(1, Number(sp.get("pageSize") ?? 25) || 25));

  const action = sp.get("action");
  const cacheHit = sp.get("cacheHit");
  const hasDetections = sp.get("hasDetections");

  const query: Record<string, string | undefined> = {
    from: sp.get("from") ?? undefined,
    to: sp.get("to") ?? undefined,
    provider: sp.get("provider") ?? undefined,
    action: action && ACTIONS.has(action) ? action : undefined,
    cache_hit: cacheHit === "true" || cacheHit === "false" ? cacheHit : undefined,
    has_detections: hasDetections === "true" || hasDetections === "false" ? hasDetections : undefined,
    limit: String(pageSize),
    offset: String((page - 1) * pageSize),
  };

  try {
    const res = await engineFetch("/internal/audit/events", { method: "GET", query });
    if (!res.ok) {
      return NextResponse.json(ENGINE_UNAVAILABLE, { status: res.status === 404 ? 503 : res.status });
    }
    const body = (await res.json()) as { entries?: unknown[]; total?: number };
    const entries = Array.isArray(body.entries) ? body.entries : [];
    const total = typeof body.total === "number" ? body.total : entries.length;

    return NextResponse.json(
      { entries, total, page, pageSize, pageCount: Math.max(1, Math.ceil(total / pageSize)) },
      { headers: { "cache-control": "no-store" } },
    );
  } catch {
    return NextResponse.json(ENGINE_UNAVAILABLE, { status: 503 });
  }
}
