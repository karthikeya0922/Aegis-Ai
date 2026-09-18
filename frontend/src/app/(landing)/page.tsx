import Link from "next/link";
import { BrainCircuit, EyeOff, HardDrive, Key, ShieldAlert, Zap } from "lucide-react";
import { CosmicBackground } from "@/components/shell/CosmicBackground";
import { HeroPreview } from "@/components/landing/HeroPreview";
import { LandingNav } from "@/components/landing/LandingNav";

/**
 * Landing page.
 *
 * Layout follows the reference: full-viewport hero with the aurora rising behind
 * a dashboard preview, then everything else on solid ground BELOW it. The aurora
 * is scoped to the hero on purpose — stretched down the whole document, its light
 * band crosses the feature cards and makes their text unreadable.
 */

const FEATURES = [
  {
    icon: EyeOff,
    title: "PII Redaction",
    description: "Names, emails, cards and phone numbers become reversible placeholders before any model sees them.",
    color: "var(--status-info)",
  },
  {
    icon: Key,
    title: "Secret Detection",
    description: "API keys, tokens, connection strings and private keys are stripped — and never rehydrated.",
    color: "var(--status-sanitize)",
  },
  {
    icon: ShieldAlert,
    title: "Injection Defense",
    description: "Prompt injections and jailbreak attempts are blocked before a provider is ever called.",
    color: "var(--status-block)",
  },
  {
    icon: Zap,
    title: "Smart Routing",
    description: "Every request goes to the cheapest model that can actually handle it, with automatic failover.",
    color: "var(--status-cost)",
  },
  {
    icon: HardDrive,
    title: "Semantic Cache",
    description: "Paraphrases hit the same cache entry, so repeat questions cost nothing and return instantly.",
    color: "var(--status-clean)",
  },
  {
    icon: BrainCircuit,
    title: "Hallucination Firewall",
    description: "Answers are graded against your reference documents; unsupported claims never reach the user.",
    color: "var(--status-warn)",
  },
];

const STEPS = [
  { n: "01", title: "Point at one base URL", body: "Swap your provider's base URL for Aegis. The API stays OpenAI-compatible, so no client changes." },
  { n: "02", title: "Every prompt walks the gate", body: "Scan, redact, injection check, policy. A failure anywhere fails closed — the provider is never reached." },
  { n: "03", title: "Route, cache, verify", body: "Cheapest capable model, semantic cache on the sanitized prompt, grounding check on the way back out." },
  { n: "04", title: "Export the audit trail", body: "Every request lands in the log — including blocked ones — and exports as a PDF for EU AI Act evidence." },
];

export default function LandingPage() {
  return (
    <main className="relative" style={{ background: "var(--aegis-bg-cosmic)" }}>
      <LandingNav />

      {/* ---------------------------------------------------------------- hero */}
      <section className="relative flex min-h-screen flex-col overflow-hidden">
        <CosmicBackground position="absolute" />

        <div
          className="relative z-10 mx-auto flex w-full max-w-hero flex-1 flex-col items-center gap-15 text-center"
          style={{ paddingInline: "clamp(20px, 4vw, 24px)", paddingTop: "clamp(120px, 18vh, 200px)" }}
        >
          <span
            className="rounded-full px-14 py-7 text-base-plus text-aegis-text-80"
            style={{
              border: "1px solid var(--aegis-border-pill)",
              background: "var(--aegis-surface-pill)",
              backdropFilter: "blur(var(--blur-badge))",
            }}
          >
            Open-source · v0.1
          </span>

          <h1
            className="m-0 font-extrabold"
            style={{
              fontSize: "var(--text-display)",
              lineHeight: "var(--leading-tight)",
              letterSpacing: "var(--tracking-tightest)",
              textWrap: "balance",
            }}
          >
            Zero-trust gateway
            <br />
            for every model call
          </h1>

          <p
            className="m-0 max-w-[720px] text-2xl leading-body"
            style={{ color: "var(--aegis-text)", textShadow: "var(--text-shadow-hero)", textWrap: "balance" }}
          >
            Aegis redacts PII and secrets, blocks prompt injection, routes to the cheapest capable model and
            exports the audit trail. One base URL, every provider.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-10">
            <Link
              href="/playground"
              className="rounded-full px-21 py-12 text-lg-plus font-semibold transition-transform duration-300 ease-out-expo hover:scale-[1.03]"
              style={{ border: "1px solid var(--aegis-border-cta-lg)", background: "#000", boxShadow: "var(--shadow-cta-lg)" }}
            >
              Launch Inspector →
            </Link>
            <Link
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-full px-21 py-12 text-lg-plus font-semibold text-aegis-text-85 transition-colors duration-300 hover:text-aegis-text"
              style={{ border: "1px solid var(--aegis-border-strong)", background: "rgba(0,0,0,0.45)", backdropFilter: "blur(var(--blur-badge))" }}
            >
              GitHub
            </Link>
          </div>
        </div>

        <div className="relative z-10 mt-auto" style={{ paddingTop: "clamp(48px, 8vh, 96px)" }}>
          <HeroPreview />
        </div>
      </section>

      {/* ------------------------------------------------------- guardrails */}
      <section
        id="guardrails"
        className="relative z-10 mx-auto w-full max-w-marketing"
        style={{ paddingInline: "clamp(20px, 4vw, 24px)", paddingBlock: "clamp(96px, 14vh, 140px)" }}
      >
        <h2
          className="m-0 text-center font-extrabold"
          style={{ fontSize: "var(--text-display-sm)", lineHeight: "var(--leading-heading)", letterSpacing: "var(--tracking-tighter)" }}
        >
          Six guardrails. One gateway.
        </h2>
        <p className="mx-auto mb-0 mt-11 max-w-[560px] text-center text-xl leading-body text-aegis-text-60">
          Every prompt walks the same path before a provider ever sees it.
        </p>

        <div className="mt-22 grid gap-14" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
          {FEATURES.map(({ icon: Icon, ...f }) => (
            <article
              key={f.title}
              className="group relative overflow-hidden rounded-2xl p-17 transition-[transform,border-color] duration-300 ease-out-expo hover:-translate-y-1"
              style={{ border: "1px solid var(--aegis-border-card)", background: "var(--aegis-bg-card-solid)" }}
            >
              <span
                aria-hidden="true"
                className="pointer-events-none absolute -right-[20%] -top-[30%] h-[70%] w-[70%] rounded-circle opacity-0 transition-opacity duration-500 group-hover:opacity-40"
                style={{ background: f.color, filter: "blur(var(--blur-orb-card))" }}
              />
              <div className="relative">
                <span
                  className="flex items-center justify-center rounded-md"
                  style={{ width: 44, height: 44, border: "1px solid var(--aegis-border-subtle)", background: "var(--aegis-surface-inset)" }}
                >
                  <Icon className="h-5 w-5" style={{ color: f.color }} strokeWidth={1.75} />
                </span>
                <h3 className="mb-0 mt-14 text-3xl font-semibold">{f.title}</h3>
                <p className="mb-0 mt-8 text-md leading-body text-aegis-text-62">{f.description}</p>
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* ------------------------------------------------------------- how */}
      <section
        id="how"
        className="relative z-10 mx-auto w-full max-w-marketing"
        style={{ paddingInline: "clamp(20px, 4vw, 24px)", paddingBottom: "clamp(96px, 14vh, 140px)" }}
      >
        <h2
          className="m-0 text-center font-extrabold"
          style={{ fontSize: "var(--text-display-sm)", lineHeight: "var(--leading-heading)", letterSpacing: "var(--tracking-tighter)" }}
        >
          How it works
        </h2>

        <div className="mt-22 grid gap-14" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
          {STEPS.map((s) => (
            <div key={s.n} className="rounded-xl p-15" style={{ border: "1px solid var(--aegis-border)", background: "var(--aegis-surface)", backdropFilter: "blur(var(--blur-panel))" }}>
              <span className="font-mono text-sm-plus text-aegis-text-40">{s.n}</span>
              <h3 className="mb-0 mt-10 text-2xl font-semibold">{s.title}</h3>
              <p className="mb-0 mt-7 text-base-plus leading-body text-aegis-text-60">{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* -------------------------------------------------------- security */}
      <section
        id="security"
        className="relative z-10 mx-auto w-full max-w-marketing"
        style={{ paddingInline: "clamp(20px, 4vw, 24px)", paddingBottom: "clamp(96px, 14vh, 140px)" }}
      >
        <div
          className="relative overflow-hidden rounded-2xl p-22 text-center"
          style={{ border: "1px solid var(--aegis-border-card)", background: "var(--aegis-bg-card-solid)" }}
        >
          <span aria-hidden="true" className="pointer-events-none absolute -left-[10%] -top-[40%] h-[80%] w-[60%] animate-float-y rounded-circle" style={{ background: "var(--aegis-orange)", opacity: 0.3, filter: "blur(var(--blur-orb-card))" }} />
          <span aria-hidden="true" className="pointer-events-none absolute -bottom-[40%] -right-[10%] h-[80%] w-[60%] animate-float-y-slow rounded-circle" style={{ background: "var(--aegis-blue)", opacity: 0.3, filter: "blur(var(--blur-orb-card))" }} />

          <div className="relative">
            <h2 className="m-0 font-extrabold" style={{ fontSize: "var(--text-display-sm)", lineHeight: "var(--leading-heading)", letterSpacing: "var(--tracking-tighter)" }}>
              Fails closed, by design
            </h2>
            <p className="mx-auto mb-0 mt-11 max-w-[620px] text-xl leading-body text-aegis-text-70">
              If the security engine is unreachable, times out or returns something it shouldn&apos;t, the request
              is refused. There is no &ldquo;proceed anyway&rdquo; path — and a detected secret is never sent to a
              provider, never rehydrated, and never reaches your browser.
            </p>
            <Link
              href="/dashboard"
              className="mt-17 inline-block rounded-full px-21 py-12 text-lg-plus font-semibold transition-transform duration-300 ease-out-expo hover:scale-[1.03]"
              style={{ border: "1px solid var(--aegis-border-cta-lg)", background: "#000", boxShadow: "var(--shadow-cta-lg)" }}
            >
              Open the Dashboard
            </Link>
          </div>
        </div>
      </section>

      <footer
        className="relative z-10 py-17 text-center font-mono text-sm-plus text-aegis-text-40"
        style={{ borderTop: "1px solid var(--aegis-border-subtle)" }}
      >
        © {new Date().getFullYear()} Aegis AI. All rights reserved.
      </footer>
    </main>
  );
}
