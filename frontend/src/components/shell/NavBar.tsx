"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { useDashboard } from "@/lib/dashboard-context";

/**
 * Floating translucent nav.
 *
 * Replaces the design file's solid 232px sidebar with the glass pill from the
 * landing page, so the app and the marketing site read as one product. The pill
 * tightens its blur and border as the page scrolls so it stays legible over the
 * aurora without ever going opaque.
 */

const LINKS = [
  { href: "/dashboard", label: "Overview", dot: "var(--aegis-orange)" },
  { href: "/playground", label: "Live Inspector", dot: "var(--aegis-blue)" },
  { href: "/audit", label: "Audit Log", dot: "var(--aegis-purple)" },
];

export function NavBar() {
  const pathname = usePathname();
  const [scrolled, setScrolled] = useState(false);
  const { health } = useDashboard();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header className="sticky top-0 z-50 pt-14 pb-10" style={{ paddingInline: "clamp(16px, 4vw, 40px)" }}>
      {/* Scrim: without it the logo and chips collide with whatever scrolls
          underneath. Fades in only once the page has moved, so at rest the nav
          still floats cleanly over the backdrop. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 transition-opacity duration-500"
        style={{
          height: "calc(100% + 24px)",
          opacity: scrolled ? 1 : 0,
          background: "linear-gradient(to bottom, var(--aegis-bg) 38%, rgba(0,0,0,0.72) 68%, transparent 100%)",
          backdropFilter: "blur(6px)",
          maskImage: "linear-gradient(to bottom, #000 62%, transparent 100%)",
        }}
      />
      <div className="relative mx-auto flex max-w-content flex-wrap items-center justify-between gap-12">
        <Link href="/" className="flex items-center gap-9 text-xl font-extrabold tracking-logo">
          <span
            className="inline-block"
            style={{
              width: 15, height: 18,
              background: "var(--aegis-logo-gradient)",
              clipPath: "polygon(50% 0,100% 18%,100% 62%,50% 100%,0 62%,0 18%)",
            }}
          />
          AEGIS
        </Link>

        <nav
          className="flex flex-wrap items-center gap-2 rounded-full p-1 transition-all duration-500 ease-out-expo"
          style={{
            border: `1px solid ${scrolled ? "var(--aegis-border-pill)" : "var(--aegis-border-strong)"}`,
            background: scrolled ? "rgba(255,255,255,0.09)" : "var(--aegis-surface-pill)",
            backdropFilter: `blur(${scrolled ? 26 : 18}px)`,
            boxShadow: scrolled ? "0 8px 40px rgba(0,0,0,0.45)" : "none",
          }}
        >
          {LINKS.map((l) => {
            const active = pathname === l.href;
            return (
              <Link
                key={l.href}
                href={l.href}
                aria-current={active ? "page" : undefined}
                className="group relative flex items-center gap-8 rounded-full px-15 py-8 text-md-plus transition-colors duration-300"
                style={{
                  background: active ? "var(--aegis-surface-toggle)" : "transparent",
                  color: active ? "var(--aegis-text)" : "var(--aegis-text-58)",
                }}
              >
                <span
                  className="rounded-chip transition-all duration-300"
                  style={{
                    width: 7, height: 7, background: l.dot,
                    boxShadow: active ? `0 0 12px ${l.dot}` : "none",
                    opacity: active ? 1 : 0.55,
                  }}
                />
                {l.label}
              </Link>
            );
          })}
        </nav>

        <div className="flex items-center gap-10">
          <EngineBadge status={health.status} label={health.label} />
          <span
            className="flex items-center gap-8 rounded-full py-4 pl-4 pr-11"
            style={{ border: "1px solid var(--aegis-border)" }}
          >
            <span className="rounded-circle" style={{ width: 28, height: 28, background: "var(--aegis-avatar-gradient)" }} />
            <span className="flex flex-col leading-nav">
              <span className="text-base font-semibold">Ashish</span>
              <span className="text-xs text-aegis-text-45">Admin</span>
            </span>
          </span>
        </div>
      </div>
    </header>
  );
}

function EngineBadge({ status, label }: { status: "ok" | "degraded" | "down" | "unknown"; label: string }) {
  const color =
    status === "ok" ? "var(--status-clean)"
    : status === "degraded" ? "var(--status-warn)"
    : status === "down" ? "var(--status-block)"
    : "var(--status-idle)";

  return (
    <span
      className="hidden items-center gap-7 rounded-full px-11 py-8 text-sm-plus text-aegis-text-70 sm:flex"
      style={{ border: "1px solid var(--aegis-border)", background: "var(--aegis-surface)", backdropFilter: "blur(var(--blur-pill))" }}
    >
      <span
        className={`rounded-circle ${status === "unknown" ? "" : "animate-pulse-dot"}`}
        style={{ width: 7, height: 7, background: color, boxShadow: `0 0 10px ${color}` }}
      />
      {label}
    </span>
  );
}
