/**
 * The dashboard preview that peeks up from the bottom of the hero, mirroring the
 * reference layout. Its bottom corners are square and it is clipped by the hero
 * so it reads as a window onto the product rather than a floating card.
 */
const ROWS = [
  { name: "PII & secret scan", value: "13 ms", color: "var(--status-clean)" },
  { name: "Credential leak check", value: "6 ms", color: "var(--status-clean)" },
  { name: "Prompt injection check", value: "15 ms", color: "var(--status-clean)" },
  { name: "Sanitization", value: "1 entity", color: "var(--status-warn)" },
  { name: "Provider · groq", value: "288 ms", color: "var(--status-info)" },
];

export function HeroPreview() {
  return (
    <div className="relative z-10 mx-auto w-full max-w-marketing" style={{ paddingInline: "clamp(20px, 4vw, 24px)" }}>
      <div
        className="overflow-hidden shadow-chrome"
        style={{
          border: "1px solid var(--aegis-border-card)",
          borderBottom: "none",
          borderRadius: "var(--radius-xl) var(--radius-xl) 0 0",
          background: "var(--aegis-bg-chrome)",
          backdropFilter: "blur(var(--blur-chrome))",
        }}
      >
        <div
          className="flex flex-wrap items-center justify-between gap-11 px-15 py-12 font-mono text-xs-plus text-aegis-text-55"
          style={{ borderBottom: "1px solid var(--aegis-border)" }}
        >
          <span>AEGIS · LIVE INSPECTOR</span>
          <span className="flex flex-wrap gap-13">
            <span>$1,284.20 saved</span>
            <span>37 injections blocked</span>
            <span>4,902 entities scrubbed</span>
          </span>
        </div>

        <div
          className="grid"
          style={{ gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 1, background: "var(--aegis-border)" }}
        >
          <div className="flex min-h-[220px] flex-col gap-10 p-14" style={{ background: "var(--aegis-bg-inspector)" }}>
            <span className="font-mono text-2xs tracking-logo text-aegis-text-40">PROMPT</span>
            <span className="font-mono text-sm-plus leading-mono text-aegis-text-85">
              Email John Smith at john@acme.com with key AKIA••••
            </span>
          </div>

          <div className="flex flex-col gap-7 p-14" style={{ background: "var(--aegis-bg-inspector)" }}>
            <span className="font-mono text-2xs tracking-logo text-aegis-text-40">PIPELINE</span>
            {ROWS.map((r) => (
              <span
                key={r.name}
                className="flex justify-between gap-8 rounded-sm px-9 py-6 text-sm text-aegis-text-75"
                style={{ border: "1px solid var(--aegis-border-subtle)" }}
              >
                {r.name}
                <span className="font-mono text-xs" style={{ color: r.color }}>{r.value}</span>
              </span>
            ))}
          </div>

          <div className="flex flex-col gap-10 p-14" style={{ background: "var(--aegis-bg-inspector)" }}>
            <span className="font-mono text-2xs tracking-logo text-aegis-text-40">RESPONSE</span>
            <span className="text-base leading-mono text-aegis-text-78">
              Drafted a follow-up to{" "}
              <span className="font-mono text-sm" style={{ color: "var(--status-warn)" }}>[PERSON_1]</span> at{" "}
              <span className="font-mono text-sm" style={{ color: "var(--status-warn)" }}>[EMAIL_1]</span>. The
              credential was never forwarded.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
