import { NextRequest, NextResponse } from "next/server";
import { engineFetch, ENGINE_UNAVAILABLE } from "@/lib/server/engine";

export const dynamic = "force-dynamic";

/**
 * GET /api/audit/report?from=&to= — streams the engine's PDF audit report.
 *
 * The body is piped straight through rather than buffered, so a large report
 * starts downloading immediately and never sits in this process's memory.
 */

function isoDate(value: string | null, fallback: Date): string {
  const parsed = value ? Date.parse(value) : NaN;
  return (Number.isFinite(parsed) ? new Date(parsed) : fallback).toISOString();
}

export async function GET(req: NextRequest) {
  const sp = req.nextUrl.searchParams;
  const now = new Date();
  const to = isoDate(sp.get("to"), now);
  const from = isoDate(sp.get("from"), new Date(now.getTime() - 86_400_000));

  try {
    const res = await engineFetch("/internal/audit/report", {
      method: "GET",
      query: { from, to, format: "pdf" },
      headers: { accept: "application/pdf" },
      timeoutMs: 60_000,
    });

    if (!res.ok || !res.body) {
      return NextResponse.json(ENGINE_UNAVAILABLE, { status: 503 });
    }

    const filename = `aegis-audit-${from.slice(0, 10)}-${to.slice(0, 10)}.pdf`;

    return new NextResponse(res.body, {
      status: 200,
      headers: {
        "content-type": "application/pdf",
        "content-disposition": `attachment; filename="${filename}"`,
        "cache-control": "no-store",
      },
    });
  } catch {
    return NextResponse.json(ENGINE_UNAVAILABLE, { status: 503 });
  }
}
