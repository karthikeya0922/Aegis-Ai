"use client";

import { useRef, useState, type CSSProperties, type ReactNode } from "react";

/**
 * The glass panel every section sits in, with an optional 3D tilt.
 *
 * The tilt is a small perspective rotation that follows the pointer, plus a
 * specular highlight tracking the same point. It is pointer-only (`fine` pointers),
 * so touch devices get the flat card, and it is skipped entirely when the user
 * has asked for reduced motion.
 */

const MAX_TILT = 4.5; // degrees — enough to read as depth, not enough to distort text

export function Panel({
  children,
  className = "",
  style,
  span,
  tilt = true,
  glow,
}: {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
  span?: boolean;
  tilt?: boolean;
  glow?: string;
}) {
  const ref = useRef<HTMLElement>(null);
  const [transform, setTransform] = useState<string>("");
  const [spec, setSpec] = useState<{ x: number; y: number } | null>(null);

  const prefersReduced =
    typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const finePointer =
    typeof window !== "undefined" && window.matchMedia?.("(pointer: fine)").matches;
  const enabled = tilt && !prefersReduced && finePointer;

  function onMove(e: React.PointerEvent<HTMLElement>) {
    if (!enabled || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width;
    const py = (e.clientY - r.top) / r.height;
    setTransform(
      `perspective(1200px) rotateX(${((0.5 - py) * MAX_TILT).toFixed(2)}deg) rotateY(${((px - 0.5) * MAX_TILT).toFixed(2)}deg) translateZ(6px)`,
    );
    setSpec({ x: px * 100, y: py * 100 });
  }

  function onLeave() {
    setTransform("");
    setSpec(null);
  }

  return (
    <section
      ref={ref}
      onPointerMove={onMove}
      onPointerLeave={onLeave}
      className={`group relative overflow-hidden rounded-xl p-17 transition-[transform,box-shadow,border-color] duration-300 ease-out-expo ${span ? "col-span-full" : ""} ${className}`}
      style={{
        border: "1px solid var(--aegis-border)",
        background: "var(--aegis-surface)",
        backdropFilter: "blur(var(--blur-panel))",
        transform: transform || undefined,
        transformStyle: "preserve-3d",
        boxShadow: spec
          ? `0 24px 70px rgba(0,0,0,0.5)${glow ? `, 0 0 50px -12px ${glow}` : ""}`
          : "0 1px 0 rgba(255,255,255,0.04) inset",
        ...style,
      }}
    >
      {/* specular highlight follows the pointer */}
      {spec && (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 transition-opacity duration-300"
          style={{
            background: `radial-gradient(400px circle at ${spec.x}% ${spec.y}%, rgba(255,255,255,0.07), transparent 60%)`,
          }}
        />
      )}
      <div className="relative" style={{ transform: "translateZ(20px)" }}>
        {children}
      </div>
    </section>
  );
}

export function PanelHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-14 flex flex-wrap items-start justify-between gap-11">
      <div>
        <h2 className="m-0 text-3xl font-semibold">{title}</h2>
        {subtitle && <p className="mt-4 mb-0 text-base-plus text-aegis-text-50">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
