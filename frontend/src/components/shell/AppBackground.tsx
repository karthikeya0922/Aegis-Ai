/**
 * The DASHBOARD backdrop — not the cosmic one.
 *
 * `Aegis Dashboard.dc.html:23-27` is plain `#000` with exactly two drifting,
 * heavily-blurred brand orbs. The starfield / aurora / planet-limb treatment
 * belongs to the landing page (`CosmicBackground`) and is deliberately NOT used
 * here: the app needs a quiet ground for dense data, and the orbs alone give it
 * depth without competing with charts.
 */
export function AppBackground() {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 overflow-hidden" style={{ background: "var(--aegis-bg)" }}>
      <div
        className="absolute animate-drift rounded-circle"
        style={{
          top: -240, left: -180,
          width: "var(--orb-a-size)", height: "var(--orb-a-size)",
          background: "var(--aegis-orange)",
          opacity: "var(--orb-opacity)",
          filter: "blur(var(--blur-orb-page))",
        }}
      />
      <div
        className="absolute animate-drift-rev rounded-circle"
        style={{
          bottom: -280, right: -200,
          width: "var(--orb-b-size)", height: "var(--orb-b-size)",
          background: "var(--aegis-blue)",
          opacity: "var(--orb-opacity)",
          filter: "blur(var(--blur-orb-page))",
        }}
      />
    </div>
  );
}
