/**
 * Shared Recharts styling.
 *
 * Recharts' defaults (light grid, blue-ish palette, boxy tooltip) would fight the
 * design. Everything here mirrors the hand-rolled SVG in the design file: dashed
 * 3/6 grid at 7% white, mono axis labels at 40% white, 2.4px strokes, no axis lines.
 *
 * SERIES is the contract that keeps a category the same colour in every chart —
 * "blocked" is `--status-block` red in the area chart, the stacked bar and the
 * donut alike.
 */

export const SERIES = {
  allowed: "var(--status-info)",
  sanitized: "var(--status-sanitize)",
  blocked: "var(--status-block)",
  pii: "var(--status-info)",
  secrets: "var(--status-sanitize)",
  injection: "var(--status-block)",
  cache: "var(--status-cost)",
  saved: "var(--status-cost)",
  clean: "var(--status-clean)",
  warn: "var(--status-warn)",
  idle: "var(--status-idle)",
} as const;

/** Provider slices, in a fixed order so a provider keeps its colour run to run. */
export const PROVIDER_COLORS = [
  "var(--status-clean)",
  "var(--status-info)",
  "var(--status-cost)",
  "var(--status-sanitize)",
  "var(--status-warn)",
  "var(--status-block)",
];

export const axisProps = {
  stroke: "var(--chart-axis)",
  tickLine: false,
  axisLine: false,
  tick: { fill: "var(--chart-axis)", fontSize: 10.5, fontFamily: "var(--font-mono)" },
} as const;

export const gridProps = {
  stroke: "var(--chart-grid)",
  strokeDasharray: "3 6",
  vertical: false,
} as const;

export const tooltipProps = {
  cursor: { stroke: "var(--aegis-border-strong)", strokeWidth: 1 },
  contentStyle: {
    background: "rgba(10,10,12,0.92)",
    border: "1px solid var(--aegis-border-card)",
    borderRadius: "var(--radius-md)",
    backdropFilter: "blur(var(--blur-chrome))",
    fontSize: 12.5,
    fontFamily: "var(--font-sans)",
    boxShadow: "0 12px 40px rgba(0,0,0,0.6)",
  },
  labelStyle: { color: "var(--aegis-text-50)", fontSize: 11, fontFamily: "var(--font-mono)", marginBottom: 4 },
  itemStyle: { color: "var(--aegis-text-85)", fontSize: 12.5, padding: "1px 0" },
} as const;

export const STROKE_WIDTH = 2.4;

/** Human labels for the engine's detection taxonomy. */
export const RULE_LABELS: Record<string, string> = {
  PROMPT_INJECTION: "Prompt injection",
  SECRET_AWS_ACCESS_KEY: "AWS access key",
  SECRET_AWS_SECRET_KEY: "AWS secret key",
  SECRET_DB_CONNECTION_STRING: "DB connection string",
  SECRET_JWT: "JWT",
  SECRET_API_KEY: "API key",
  PII_EMAIL: "Email address",
  PII_PHONE: "Phone number",
  PII_SSN: "SSN",
  PII_CREDIT_CARD: "Credit card",
  PII_PERSON_NAME: "Person name",
};

export function ruleLabel(rule: string): string {
  return RULE_LABELS[rule] ?? rule.replace(/_/g, " ").toLowerCase();
}

export function ruleColor(rule: string): string {
  if (rule === "PROMPT_INJECTION") return SERIES.injection;
  if (rule.startsWith("SECRET_")) return SERIES.secrets;
  if (rule.startsWith("PII_")) return SERIES.pii;
  return SERIES.idle;
}
