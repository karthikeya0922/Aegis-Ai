/**
 * The fixed cosmic backdrop: starfield, aurora horizon, planet limb, vignette.
 *
 * Values are the ones from `Aegis Landing Cosmic.dc.html` / `aurora-background.html`,
 * dimmed via `intensity` so the app chrome stays readable on top of it. Purely
 * decorative and inert — `aria-hidden`, `pointer-events:none`, and every animation
 * is disabled under `prefers-reduced-motion` by the global rule in globals.css.
 */

const STARS = [
  ["10%", "20%", 1, 0.9],
  ["25%", "60%", 1, 0.7],
  ["40%", "15%", 1.5, 0.8],
  ["55%", "45%", 1, 0.6],
  ["70%", "25%", 1, 0.9],
  ["85%", "55%", 1.5, 0.7],
  ["95%", "10%", 1, 0.8],
  ["15%", "80%", 1, 0.6],
  ["33%", "90%", 1.5, 0.7],
  ["65%", "75%", 1, 0.8],
  ["80%", "85%", 1, 0.6],
  ["5%", "50%", 1.5, 0.9],
] as const;

const starfield = STARS.map(
  ([x, y, r, a]) => `radial-gradient(${r}px ${r}px at ${x} ${y}, rgba(255,255,255,${a}) 100%, transparent)`,
).join(",");

export function CosmicBackground({ intensity = 1 }: { intensity?: number }) {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden"
      style={{ background: "var(--aegis-bg-cosmic)" }}
    >
      {/* starfield */}
      <div
        className="absolute inset-0 animate-twinkle"
        style={{
          backgroundImage: starfield,
          backgroundRepeat: "repeat",
          backgroundSize: "400px 400px",
          opacity: 0.7 * intensity,
        }}
      />

      {/* aurora horizon — the orange→white→blue sweep rising from below */}
      <div
        className="absolute animate-horizon-glow"
        style={{
          left: "-14%",
          right: "-14%",
          top: "46%",
          height: "240px",
          opacity: intensity,
          filter: "blur(var(--blur-horizon))",
          background:
            "radial-gradient(ellipse at 20% 100%, rgba(255,150,40,0.75) 0%, transparent 58%)," +
            "radial-gradient(ellipse at 36% 100%, rgba(255,120,45,0.55) 0%, transparent 52%)," +
            "radial-gradient(ellipse at 50% 100%, rgba(255,255,255,0.6) 0%, transparent 40%)," +
            "radial-gradient(ellipse at 64% 100%, rgba(90,160,255,0.65) 0%, transparent 52%)," +
            "radial-gradient(ellipse at 84% 100%, rgba(30,95,255,0.6) 0%, transparent 60%)",
        }}
      />

      {/* planet limb with its lit rim */}
      <div
        className="absolute"
        style={{ left: "50%", top: "58%", width: "150%", paddingBottom: "150%", transform: "translateX(-50%)", transformOrigin: "50% 0%" }}
      >
        <div
          className="absolute inset-0 animate-limb-turn rounded-circle shadow-planet"
          style={{
            background:
              "radial-gradient(circle at 50% 6%, rgba(160,190,235,0.28) 0%, rgba(22,28,46,0.85) 9%, #020307 26%, #010204 100%)",
          }}
        >
          <span
            className="absolute"
            style={{
              left: "-2%", right: "-2%", top: "-26px", height: "15%", borderRadius: "50%",
              filter: "blur(16px)", clipPath: "ellipse(50% 26px at 50% 0%)",
              background:
                "linear-gradient(90deg, rgba(255,140,30,0.7) 0%, rgba(255,205,130,0.95) 26%, rgba(255,255,255,1) 46%, rgba(195,225,255,0.95) 60%, rgba(60,150,255,0.9) 80%, rgba(20,80,220,0.45) 100%)",
            }}
          />
          <span
            className="absolute animate-rim-breathe"
            style={{
              left: "0.5%", right: "0.5%", top: "-1px", height: "15%", borderRadius: "50%",
              clipPath: "ellipse(50% 2.5px at 50% 0%)",
              background:
                "linear-gradient(90deg, rgba(255,150,40,1) 0%, rgba(255,215,140,1) 26%, rgba(255,255,255,1) 46%, rgba(205,230,255,1) 60%, rgba(70,160,255,1) 80%, rgba(25,90,230,0.9) 100%)",
            }}
          />
        </div>
      </div>

      {/* drifting brand orbs, from the dashboard file */}
      <div
        className="absolute animate-drift rounded-circle"
        style={{ top: "-240px", left: "-180px", width: "var(--orb-a-size)", height: "var(--orb-a-size)", background: "var(--aegis-orange)", opacity: 0.16, filter: "blur(var(--blur-orb-page))" }}
      />
      <div
        className="absolute animate-drift-rev rounded-circle"
        style={{ bottom: "-280px", right: "-200px", width: "var(--orb-b-size)", height: "var(--orb-b-size)", background: "var(--aegis-blue)", opacity: 0.16, filter: "blur(var(--blur-orb-page))" }}
      />

      {/* vignette + film grain keep text legible over the glow */}
      <div className="absolute inset-0" style={{ background: "radial-gradient(ellipse at 48% 66%, transparent 30%, rgba(5,6,10,0.72) 74%, var(--aegis-bg-cosmic) 100%)" }} />
      <div
        className="absolute inset-0"
        style={{ opacity: 0.11, mixBlendMode: "overlay", backgroundImage: "radial-gradient(circle at 50% 50%, #fff 0.5px, transparent 0.6px)", backgroundSize: "2.5px 2.5px" }}
      />
    </div>
  );
}
