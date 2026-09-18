"use client";

import type { ReactNode } from "react";
import { AppBackground } from "./AppBackground";
import { NavBar } from "./NavBar";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="relative min-h-screen" style={{ background: "var(--aegis-bg)" }}>
      <AppBackground />
      <div className="relative z-10 flex min-h-screen flex-col">
        <NavBar />
        <main className="mx-auto w-full max-w-content flex-1 pb-23" style={{ paddingInline: "clamp(16px, 4vw, 40px)" }}>
          {children}
        </main>
        <footer
          className="mx-auto w-full max-w-content py-16 font-mono text-2xs text-aegis-text-35"
          style={{ paddingInline: "clamp(16px, 4vw, 40px)" }}
        >
          v0.1.0 · aegis gateway
        </footer>
      </div>
    </div>
  );
}
