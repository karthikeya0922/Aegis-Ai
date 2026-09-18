"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

/**
 * Marketing nav: logo left, glass pill centre, glowing CTA right.
 *
 * Same floating-pill language as the app's NavBar, but with the landing page's
 * heavier glow treatment on the CTA (`--shadow-cta`) rather than the app's quiet
 * chrome.
 */

const LINKS = [
  { href: "#guardrails", label: "Guardrails" },
  { href: "#how", label: "How it works" },
  { href: "#security", label: "Security" },
  { href: "/dashboard", label: "Dashboard" },
];

export function LandingNav() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header className="fixed inset-x-0 top-0 z-50" style={{ paddingInline: "clamp(20px, 4vw, 40px)" }}>
      {/* Scrim. Content scrolls under a fixed nav, so without an opaque band the
          headings underneath bleed through the pill and read as a rendering bug.
          Masked at the bottom so it fades rather than cutting a hard line. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 transition-opacity duration-500"
        style={{
          height: "148%",
          opacity: scrolled ? 1 : 0,
          background: "linear-gradient(to bottom, var(--aegis-bg-cosmic) 30%, rgba(5,6,10,0.88) 58%, transparent 100%)",
          backdropFilter: "blur(10px)",
          maskImage: "linear-gradient(to bottom, #000 58%, transparent 100%)",
        }}
      />
      <div className="relative flex flex-wrap items-center justify-between gap-12 py-17">
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
        className="hidden flex-wrap items-center gap-17 rounded-full px-17 py-10 text-md-plus text-aegis-text-85 md:flex"
        style={{
          border: "1px solid var(--aegis-border-strong)",
          background: "var(--aegis-surface-pill)",
          backdropFilter: "blur(var(--blur-pill))",
        }}
      >
        {LINKS.map((l) => (
          <Link key={l.href} href={l.href} className="whitespace-nowrap transition-colors hover:text-aegis-text">
            {l.label}
          </Link>
        ))}
      </nav>

      <Link
        href="/dashboard"
        className="whitespace-nowrap rounded-full px-17 py-10 text-md-plus font-semibold transition-transform duration-300 ease-out-expo hover:scale-[1.03]"
        style={{ border: "1px solid var(--aegis-border-cta)", background: "#000", boxShadow: "var(--shadow-cta)" }}
      >
        Get Started
      </Link>
      </div>
    </header>
  );
}
