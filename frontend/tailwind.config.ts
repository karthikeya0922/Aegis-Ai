import type { Config } from "tailwindcss";

/**
 * Aegis Tailwind theme.
 *
 * Every value here is a `var(--token)` reference — the raw numbers live once,
 * in `src/app/globals.css` under `:root`. That keeps the SVG/Recharts code
 * (which needs literal colours via `var()`) and the utility classes reading
 * from a single source.
 *
 * Tailwind v4 is CSS-first, so this file is loaded explicitly by
 * `@config "../../tailwind.config.ts";` at the top of globals.css.
 */
const config: Config = {
  content: ["./src/**/*.{ts,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        aegis: {
          bg: "var(--aegis-bg)",
          cosmic: "var(--aegis-bg-cosmic)",
          "card-solid": "var(--aegis-bg-card-solid)",
          well: "var(--aegis-bg-well)",
          inspector: "var(--aegis-bg-inspector)",
          chrome: "var(--aegis-bg-chrome)",

          surface: "var(--aegis-surface)",
          "surface-inset": "var(--aegis-surface-inset)",
          "surface-input": "var(--aegis-surface-input)",
          "surface-pill": "var(--aegis-surface-pill)",
          "surface-active": "var(--aegis-surface-active)",
          "surface-toggle": "var(--aegis-surface-toggle)",
          "surface-track": "var(--aegis-surface-track)",

          "border-faint": "var(--aegis-border-faint)",
          "border-subtle": "var(--aegis-border-subtle)",
          border: "var(--aegis-border)",
          "border-card": "var(--aegis-border-card)",
          "border-strong": "var(--aegis-border-strong)",
          "border-pill": "var(--aegis-border-pill)",
          "border-cta": "var(--aegis-border-cta)",
          "border-cta-lg": "var(--aegis-border-cta-lg)",
          "border-focus": "var(--aegis-border-focus)",
          "border-hover": "var(--aegis-border-hover)",

          text: "var(--aegis-text)",
          "text-90": "var(--aegis-text-90)",
          "text-85": "var(--aegis-text-85)",
          "text-80": "var(--aegis-text-80)",
          "text-78": "var(--aegis-text-78)",
          "text-75": "var(--aegis-text-75)",
          "text-70": "var(--aegis-text-70)",
          "text-65": "var(--aegis-text-65)",
          "text-62": "var(--aegis-text-62)",
          "text-60": "var(--aegis-text-60)",
          "text-58": "var(--aegis-text-58)",
          "text-55": "var(--aegis-text-55)",
          "text-50": "var(--aegis-text-50)",
          "text-45": "var(--aegis-text-45)",
          "text-40": "var(--aegis-text-40)",
          "text-35": "var(--aegis-text-35)",

          orange: "var(--aegis-orange)",
          blue: "var(--aegis-blue)",
          purple: "var(--aegis-purple)",
        },

        /* One colour per meaning. Reused identically by badges, tables and
           every Recharts series so a category reads the same everywhere. */
        status: {
          clean: "var(--status-clean)",
          warn: "var(--status-warn)",
          block: "var(--status-block)",
          info: "var(--status-info)",
          sanitize: "var(--status-sanitize)",
          cost: "var(--status-cost)",
          idle: "var(--status-idle)",
        },

        orb: {
          cost: "var(--orb-cost)",
          block: "var(--orb-block)",
          sanitize: "var(--orb-sanitize)",
          info: "var(--orb-info)",
        },

        chart: {
          grid: "var(--chart-grid)",
          axis: "var(--chart-axis)",
        },
      },

      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },

      fontSize: {
        "2xs": "var(--text-2xs)",
        xs: "var(--text-xs)",
        "xs-plus": "var(--text-xs-plus)",
        sm: "var(--text-sm)",
        "sm-plus": "var(--text-sm-plus)",
        base: "var(--text-base)",
        "base-plus": "var(--text-base-plus)",
        md: "var(--text-md)",
        "md-plus": "var(--text-md-plus)",
        lg: "var(--text-lg)",
        "lg-plus": "var(--text-lg-plus)",
        xl: "var(--text-xl)",
        "2xl": "var(--text-2xl)",
        "3xl": "var(--text-3xl)",
        "4xl": "var(--text-4xl)",
        "5xl": "var(--text-5xl)",
        "6xl": "var(--text-6xl)",
        "7xl": "var(--text-7xl)",
        "8xl": "var(--text-8xl)",
        display: "var(--text-display)",
        "display-sm": "var(--text-display-sm)",
      },

      letterSpacing: {
        logo: "var(--tracking-logo)",
        "mono-label": "var(--tracking-mono-label)",
        caps: "var(--tracking-caps)",
        "caps-tight": "var(--tracking-caps-tight)",
        tight: "var(--tracking-tight)",
        tighter: "var(--tracking-tighter)",
        tightest: "var(--tracking-tightest)",
      },

      lineHeight: {
        tight: "var(--leading-tight)",
        heading: "var(--leading-heading)",
        nav: "var(--leading-nav)",
        body: "var(--leading-body)",
        mono: "var(--leading-mono)",
        "mono-loose": "var(--leading-mono-loose)",
      },

      borderRadius: {
        dot: "var(--radius-dot)",
        chip: "var(--radius-chip)",
        sm: "var(--radius-sm)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
        xl: "var(--radius-xl)",
        "2xl": "var(--radius-2xl)",
        full: "var(--radius-full)",
        circle: "var(--radius-circle)",
      },

      spacing: {
        1: "var(--space-1)",
        2: "var(--space-2)",
        3: "var(--space-3)",
        4: "var(--space-4)",
        5: "var(--space-5)",
        6: "var(--space-6)",
        7: "var(--space-7)",
        8: "var(--space-8)",
        9: "var(--space-9)",
        10: "var(--space-10)",
        11: "var(--space-11)",
        12: "var(--space-12)",
        13: "var(--space-13)",
        14: "var(--space-14)",
        15: "var(--space-15)",
        16: "var(--space-16)",
        17: "var(--space-17)",
        18: "var(--space-18)",
        19: "var(--space-19)",
        20: "var(--space-20)",
        21: "var(--space-21)",
        22: "var(--space-22)",
        23: "var(--space-23)",
        sidebar: "var(--sidebar-w)",
        chart: "var(--chart-h)",
        donut: "var(--donut-size)",
        "donut-hole": "var(--donut-hole)",
        search: "var(--search-w)",
      },

      maxWidth: {
        content: "var(--content-max)",
        marketing: "var(--content-max-marketing)",
        hero: "var(--hero-max)",
      },

      boxShadow: {
        cta: "var(--shadow-cta)",
        "cta-lg": "var(--shadow-cta-lg)",
        chrome: "var(--shadow-chrome)",
        planet: "var(--shadow-planet)",
        eclipse: "var(--shadow-eclipse)",
        arc: "var(--shadow-arc)",
        "403": "var(--shadow-403)",
      },

      backdropBlur: {
        panel: "var(--blur-panel)",
        pill: "var(--blur-pill)",
        badge: "var(--blur-badge)",
        chrome: "var(--blur-chrome)",
      },

      blur: {
        shaft: "var(--blur-shaft)",
        horizon: "var(--blur-horizon)",
        aurora: "var(--blur-aurora)",
        "orb-card": "var(--blur-orb-card)",
        "orb-page": "var(--blur-orb-page)",
      },

      backgroundImage: {
        "aegis-logo": "var(--aegis-logo-gradient)",
        "aegis-avatar": "var(--aegis-avatar-gradient)",
      },

      transitionTimingFunction: {
        "out-expo": "var(--ease-out-expo)",
      },

      animation: {
        drift: "drift var(--dur-drift-a) ease-in-out infinite",
        "drift-rev": "drift var(--dur-drift-b) ease-in-out infinite reverse",
        "pulse-dot": "pulseDot var(--dur-pulse) ease-in-out infinite",
        twinkle: "twinkle var(--dur-twinkle) ease-in-out infinite alternate",
        "horizon-glow": "horizonGlow var(--dur-horizon) ease-in-out infinite",
        "rim-breathe": "rimBreathe var(--dur-rim) ease-in-out infinite",
        "limb-turn": "limbTurn var(--dur-limb) ease-in-out infinite",
        "spin-slow": "spinSlow var(--dur-spin) linear infinite",
        "float-y": "floatY var(--dur-float) ease-in-out infinite",
        "float-y-slow": "floatY var(--dur-float-slow) ease-in-out infinite reverse",
        "stage-in": "stageIn 260ms var(--ease-out-expo) both",
        // duration is overridden per-shaft inline so the curtain never pulses in lockstep
        "shaft-sway": "shaftSway 20s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

export default config;
