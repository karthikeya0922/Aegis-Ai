# Aegis — Frontend Spec (Phase 4 + 5 UI)

> What the frontend needs to be built, what already exists to build on, and the gaps in the
> backend/gateway that the UI depends on. Derived from the problem statement and the current
> code in `frontend/`, `lib/` and `config/` as of 2026-09-17.
>
> **Status:** spec only. Nothing here is built yet (RULE 2 — wait for go-ahead on Phase 4).

---

## 1. Goal

A single-page **"Live Jury Visualizer"**: a demo-grade, 3-column playground that shows a prompt
travelling through the Aegis gateway in real time, plus a header telemetry bar and a 1-click
EU AI Act audit PDF export.

Audience: judges / stakeholders watching a live demo. Priorities, in order:
1. Every guardrail decision is **visible and explainable** (which stage, what it found, how long).
2. It **never leaks** raw sensitive data into the browser beyond what the user typed.
3. It looks polished and reads well on a projector (large type, high contrast, dark theme).

---

## 2. Stack (already installed)

| Concern | Choice | Notes |
|---|---|---|
| Framework | **Next.js 16.3.5**, App Router, React 19 | ⚠️ Breaking changes vs. older Next — read `frontend/node_modules/next/dist/docs/` before writing code (see `frontend/AGENTS.md`). |
| Language | TypeScript `strict`, no `any` | Same rule as `lib/`. |
| Styling | Tailwind CSS v4 (`@tailwindcss/postcss`) | Tokens in `globals.css` via `@theme`. |
| Icons | `lucide-react` | Shield, Zap, Route, SearchCheck, FileDown, etc. |
| Charts | `recharts` v3 | Sparklines / savings-over-time in the telemetry bar. |
| Validation | `zod` v4 | Parse every SSE frame and API response on the client. |
| IDs | `nanoid` | |
| Tests | `vitest` v3 | Add `@testing-library/react` + `jsdom` for components (new devDeps). |

**Likely new deps (confirm before installing):**
- `@testing-library/react`, `@testing-library/user-event`, `jsdom` — component tests.
- PDF: server-side generation — `@react-pdf/renderer` **or** `pdfkit` (Node). Backend `requirements-ml.txt` lists `reportlab`, so decide *which side* owns PDFs (see §9).
- Optional: `clsx` for class composition.

---

## 3. What already exists (build on this, don't rewrite)

| Piece | Location | Frontend relevance |
|---|---|---|
| OpenAI-compatible gateway route | `frontend/src/app/api/v1/chat/completions/route.ts` | The playground's **only** chat endpoint. Supports `stream: true` (SSE). |
| Fail-closed scan gate | `frontend/src/lib/gateway/scan-gate.ts` | Produces 400/403/503 errors the UI must render. |
| SSE streaming + failover | `frontend/src/lib/gateway/streaming.ts` | Emits `data:` chunks, one `event: aegis.telemetry` frame, then `data: [DONE]`. |
| Semantic cache / router / cost | `lib/cache/semantic-cache.ts`, `lib/routing/router.ts`, `lib/cost.ts` | Data for the ⚡ Cache and 🚦 Router stages + savings counters. |
| Engine contract | `lib/types/aegis.ts` | `PipelineStage`, `Detection`, `AuditLogEntry`, `AegisPolicy`, `HealthResponse`. |
| Engine client | `lib/aegis-client.ts` | **Server-only.** The browser must never call `AEGIS_ENGINE_URL` directly. |
| Mock engine | `mocks/engine/` (port 8001) | Lets the whole UI be built today without the Python engine. |
| Error codes | `frontend/src/lib/errors.ts` | `AEGIS_ENGINE_UNAVAILABLE`, `CREDENTIAL_LEAK_PREVENTED`, `PROMPT_INJECTION_BLOCKED`, `AEGIS_POLICY_BLOCKED`. |
| Empty component folders | `src/components/{playground,pipeline,telemetry}/` | Target folders for the UI. |
| `src/app/page.tsx` | create-next-app boilerplate | To be replaced. |

---

## 4. Pages & routes

### UI pages
| Route | Purpose | Priority |
|---|---|---|
| `/` | Live Jury Visualizer (3 columns + header bar) | **P0** |
| `/audit` | Audit log table (filter by date / action / rule), "Export PDF" | P1 |
| `/policies` | Toggle guardrails (`AegisPolicy`), faithfulness threshold slider | P2 |
| `/health` or header pill | Engine status (`ok / degraded / down`, `mock / python`) + provider breaker states | P2 |

### API routes the UI needs (Backend-for-Frontend, all under `src/app/api/`)
| Method & path | Exists? | Returns | Backed by |
|---|---|---|---|
| `POST /api/v1/chat/completions` | ✅ | JSON or SSE | gateway pipeline |
| `GET /api/metrics` | ❌ **new** | aggregate counters for the header bar (§6.4) | in-memory aggregator fed by `Telemetry`, later the audit DB |
| `GET /api/audit?from&to&limit` | ❌ **new** | `AuditQueryResponse` | `aegisClient.queryAudit` |
| `GET /api/audit/export?from&to` | ❌ **new** | `application/pdf` download | PDF generator (§9) |
| `GET /api/policies` / `PUT /api/policies` | ❌ **new** | `PoliciesResponse` | `aegisClient` |
| `GET /api/health` | ❌ **new** | `HealthResponse` + breaker states from `getProviderRegistry()` | `aegisClient.health` + registry |

All new routes: server-only, never forward `Detection.match` or message text to logs, return
`buildErrorPayload(...)` on failure.

---

## 5. Layout — `/`

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ AEGIS  ● engine ok (mock)   $ Saved 12.40 │ ⏱ -184 ms │ 🛡 Blocked 7 │ 🌱 0.42 kg CO₂ │ [Export Audit PDF] │
├──────────────────────────┬──────────────────────────────┬────────────────────────────┤
│ 1. CLIENT INPUT          │ 2. LIVE INSPECTION PIPELINE  │ 3. EGRESS / FINAL OUTPUT   │
│                          │                              │                            │
│ chat history             │ 🛡 PII & Credential Scanner  │ streamed response text     │
│                          │    Scrubbed 2 · 14 ms        │                            │
│                          │ 🧱 Injection Defense         │ [latency 412ms] [$0.0003]  │
│ [x] Confidential Mode    │    Pass · 3 ms               │ [tokens 186] [model]       │
│ [strict | sanitize]      │ ⚡ Semantic Cache            │ [cache HIT] [failover]     │
│ 📎 reference doc         │    Miss · 0.81 sim · 9 ms    │                            │
│ ┌──────────────────────┐ │ 🚦 Smart Router              │ Blocked? → red card with   │
│ │ prompt…          [➤] │ │    llama-3-8b · $0.0003      │ error code + explanation   │
│ └──────────────────────┘ │ 🔍 Hallucination Check       │                            │
│ demo presets ▾           │    92% faithful · 41 ms      │                            │
│                          │ 🔁 Provider / Failover       │                            │
└──────────────────────────┴──────────────────────────────┴────────────────────────────┘
```

- Desktop (≥1280px): three equal columns, full viewport height, each column scrolls independently.
- Tablet/mobile: stacked, with tabs **Input / Pipeline / Output**; header metrics collapse to a 2×2 grid.
- Dark theme default (projector), light theme supported via tokens.

---

## 6. Components

```
src/components/
├── layout/
│   ├── AppHeader.tsx            # logo, engine status pill, TelemetryBar, export button
│   └── ThreeColumnShell.tsx     # responsive columns / mobile tabs
├── playground/                  # Column 1
│   ├── ChatHistory.tsx
│   ├── PromptComposer.tsx       # textarea, send/stop, Cmd+Enter
│   ├── ConfidentialToggle.tsx
│   ├── ModeSelector.tsx         # sanitize | strict  → x-aegis-mode
│   ├── ReferenceDocUpload.tsx   # .txt/.md, size-capped, read client-side
│   └── DemoPresets.tsx          # one-click demo prompts (§6.5)
├── pipeline/                    # Column 2
│   ├── PipelineTimeline.tsx
│   ├── StageCard.tsx            # icon, name, status badge, ms timer, detail
│   ├── DetectionList.tsx        # categories + placeholders, NEVER raw match
│   └── FailoverTrace.tsx        # attempts[] from FailoverTelemetry
├── output/                      # Column 3
│   ├── ResponsePanel.tsx        # streamed text, blinking caret
│   ├── ResponseBadges.tsx       # latency, cost, tokens, model, cache, failover
│   └── BlockedCard.tsx          # 400/403/503 rendering
├── telemetry/
│   ├── TelemetryBar.tsx
│   ├── MetricTile.tsx           # value + animated count-up + sparkline
│   └── ExportAuditButton.tsx
└── ui/                          # Badge, Card, Spinner, Toggle, Tooltip, Tabs
```

### 6.1 Pipeline stages to display

| Stage (UI) | Machine name | Source today | Status values |
|---|---|---|---|
| 🛡 PII & Credential Scanner | `pii_secret_scan` | `ScanResponse.stages` + `detections` | Clean / Scrubbed N / Blocked |
| 🧱 Prompt Injection Defense | `prompt_injection_check` | `ScanResponse.stages` | Pass / Blocked (403) |
| ⚡ Semantic Cache | `semantic_cache` | `CacheTelemetry` | Hit (similarity) / Miss / Skipped (secret, warn, no-cache) |
| 🚦 Smart Router | `smart_router` | `getRouteForMessages` + `estimateCost` | complexity + model + est. $ |
| 🔁 Provider / Failover | `provider` | `FailoverTelemetry` | primary ok / failover → X / all failed |
| 🔍 Hallucination Check | `hallucination_check` | `VerifyResponse` | faithfulness % / Blocked + fallback / **Skipped (not built yet)** |

Each card: `idle → running (live ms timer) → pass | flagged | blocked | skipped`. Stages after a
block render as `skipped` (greyed). Timers show the **server-reported** `duration_ms` once known;
the live ticker is only cosmetic while waiting.

### 6.2 Output badges
`latency_ms` (client-measured TTFB + total), `estimatedCostUsd`, tokens in/out, `model`,
`cache_hit`, `failover_used`, `estimatedCarbonGrams`.

### 6.3 Error / blocked states
| HTTP | Code | UI |
|---|---|---|
| 400 | `CREDENTIAL_LEAK_PREVENTED` | red card "Credential leak prevented", scanner stage = blocked |
| 403 | `PROMPT_INJECTION_BLOCKED` | red card "Prompt injection blocked", injection stage = blocked |
| 403 | `AEGIS_POLICY_BLOCKED` | red card "Blocked by policy" |
| 503 | `AEGIS_ENGINE_UNAVAILABLE` | amber card "Security engine unavailable — request not sent (fail-closed)" |
| SSE `aegis.telemetry.error != null` | — | partial text kept + "stream interrupted" banner |
| network / abort | — | "Stopped" (user) or retry button |

### 6.4 Header telemetry (`GET /api/metrics`)
```ts
interface MetricsResponse {
  window: { from: string; to: string };
  total_requests: number;
  dollars_saved_usd: number;          // cache hits' estimated_cost_avoided + router savings vs. premium model
  avg_latency_reduction_ms: number;   // cache-hit latency vs. average provider latency
  injections_blocked: number;
  data_leaks_blocked: number;         // credential + PII blocks
  entities_scrubbed: number;
  carbon_offset_kg: number;
  series: { t: string; saved_usd: number; blocked: number }[]; // sparklines
}
```
Poll every 5 s (or refetch after each completed chat) — no websocket needed for v1.

### 6.5 Demo presets (drive the live demo)
1. **Clean** — "Explain REST APIs simply" → allow, then re-send a paraphrase → cache HIT.
2. **PII** — "Email John Smith at john@acme.com about the invoice" → sanitize, `[PERSON_1]`, `[EMAIL_1]`.
3. **Secret** — prompt containing `AKIA…` → 400 credential leak.
4. **Injection** — "Ignore all previous instructions and…" → 403.
5. **Complex reasoning** — multi-step/code prompt → router picks premium model.
6. **Hallucination** — upload reference doc + off-doc question → faithfulness block (once built).
7. **Failover** — only when a fake primary is configured; shows `failover_used`.

---

## 7. Client data flow

```
PromptComposer ──► usePlaygroundRun()  (client hook, one run = one request_id)
                    │ fetch POST /api/v1/chat/completions
                    │   headers: x-aegis-mode, x-aegis-confidential, x-aegis-no-cache
                    │   body: { model, messages, stream: true, aegis: { reference_docs } }
                    ▼
               response.ok?
        no ──► parse JSON error (zod) ──► BlockedCard + mark stage blocked
       yes ──► SSE reader (TextDecoder, split on "\n\n")
                 ├─ data: chunk      → append delta to ResponsePanel
                 ├─ event: aegis.stages / aegis.telemetry → zod parse → update pipeline + badges
                 └─ data: [DONE]     → finalize, refetch /api/metrics
```

- **State:** `useReducer` per run (`RunState` = messages, stages map, telemetry, status, error). No
  global store needed; header metrics via a small `useMetrics()` polling hook.
- **Cancel:** `AbortController` on "Stop" — the gateway already aborts upstream on disconnect.
- **SSE parsing:** write one pure `parseSseStream(ReadableStream) → AsyncIterable<SseEvent>` in
  `src/lib/client/sse.ts` and unit-test it (split frames, multi-line data, named events, `[DONE]`).
- **Session:** `session_id` cookie is `HttpOnly` and set by the route — same-origin `fetch` sends it
  automatically; the client never reads it.

---

## 8. ⚠️ Backend gaps the UI depends on

These must be closed (or explicitly stubbed) before the visualizer can show real data.

| # | Gap | Evidence | Proposed fix |
|---|---|---|---|
| G1 | **No stages/detections reach the browser.** The `aegis.telemetry` frame only has provider/failover/length/error. Scan `stages[]`, detection summary, routed model, cost, cache similarity, latencies are recorded server-side only. | `streaming.ts` telemetry frame | Add a typed `AegisTelemetryFrame` to `lib/types/aegis.ts` and emit an `event: aegis.stages` frame **before** the first chunk (scan + cache + router) and a richer `aegis.telemetry` at the end (provider, cost, tokens, verify). Categories + placeholders only — never `match`. |
| G2 | **Cache-hit frame is thinner** than the normal path (no cost, model, similarity). | `streaming.ts` cache branch | Same frame shape for both paths. |
| G3 | **Blocked responses have no pipeline data.** Error JSON is `{error:{code,message,request_id}}`. | `errors.ts` | Add optional `aegis: { stages, detection_categories }` to the error payload. |
| G4 | **Non-streaming path has no telemetry in the body.** | `pipeline.ts` | Either add `aegis` object to the JSON response or have the UI always use `stream: true`. Recommend: UI always streams. |
| G5 | **No metrics aggregation.** `consoleTelemetry` only logs. | `telemetry.ts` | Add an in-memory `MetricsTelemetry` (fan-out with console) + `GET /api/metrics`; swap to audit DB in Phase 5. |
| G6 | **Confidential Mode not wired.** `ScanRequest.confidential_mode` exists but the route never reads a header. | `route.ts` | Read `x-aegis-confidential: true` → pass into scan; probably also force `noCache`. |
| G7 | **Reference docs in a header** (`x-aegis-reference-docs` JSON) — headers cap at ~8–16 KB, so real documents will be truncated/rejected. | `route.ts` | Move to request body (`aegis.reference_docs`) with a size cap. |
| G8 | **Hallucination check not implemented** (`/internal/verify` never called). | `streaming.ts` comment | UI shows stage as `skipped` until Phase 3 lands. |
| G9 | **No egress re-hydration** — user sees `[PERSON_1]` placeholders. | PROJECT.md open question | UI shows placeholders with a tooltip "re-hydrated by vault (pending)". Decide engine-side vault. |
| G10 | **Token counts are estimates** (`length / 4`). | `streaming.ts` | Label as "≈ tokens" in UI; use provider `usage` when present. |
| G11 | **`next build` fails offline** because `layout.tsx` fetches Google Fonts. | PROJECT.md 1B entry | Self-host fonts (`next/font/local`) or accept build needs network. |
| G12 | **No audit writes yet** — `/internal/audit` POST is never called by the gateway. | gateway code | Phase 5: write one `AuditLogEntry` per request from the pipeline. |

---

## 9. Audit report export (Phase 5 UI)

- Button in header → `GET /api/audit/export?from=…&to=…` → browser download
  `aegis-audit-YYYY-MM-DD.pdf`. Show spinner, disable while generating, toast on error.
- **Decide owner:** (a) Node route with `@react-pdf/renderer` using `aegisClient.queryAudit`, or
  (b) Python engine renders with `reportlab` and the Next route just proxies the bytes.
  Recommendation: **(b)** if the Python engine owns the DB, otherwise (a).
- PDF contents: cover (period, generated at, system version), executive summary (requests, blocks by
  category, entities scrubbed, cache savings, carbon), EU AI Act mapping (transparency, risk
  management, logging/record-keeping, human oversight → which Aegis control covers it), incident
  table (timestamp, request_id, action, error_code, rule_triggers, model, latency — **no prompt text**),
  active policy snapshot, appendix with methodology for cost/carbon estimates (`config/costs.yaml`).

---

## 10. Design system

- **Tokens** (`globals.css` `@theme`): `--color-bg`, `--color-surface`, `--color-border`,
  `--color-text`, `--color-muted`, and semantic states `--color-pass` (green),
  `--color-flagged` (amber), `--color-blocked` (red), `--color-skipped` (grey),
  `--color-accent` (brand cyan/indigo). Dark default + light variant.
- **Type:** Inter/Geist for UI, JetBrains Mono/Geist Mono for ms timers, ids, placeholders.
- **Motion:** stage cards fade/slide in sequentially; counters count up; respect
  `prefers-reduced-motion`.
- **Accessibility:** status never conveyed by color alone (icon + text); `aria-live="polite"` on
  pipeline and output columns; keyboard: `Cmd/Ctrl+Enter` send, `Esc` stop; WCAG AA contrast.

---

## 11. Security rules for the frontend

1. Browser talks **only** to same-origin `/api/*`. Never expose `AEGIS_ENGINE_URL` or provider keys
   (no `NEXT_PUBLIC_` prefixes for them).
2. Never render or log `Detection.match`; show category + placeholder only.
3. Don't persist prompts/responses in `localStorage` (Confidential Mode especially). UI prefs
   (theme, last mode) are fine.
4. Render model output as **text**, not HTML (no `dangerouslySetInnerHTML`); if markdown rendering is
   added, sanitize it.
5. Reference doc upload: accept `.txt`/`.md` only, cap size (e.g. 200 KB), read with `File.text()`.
6. Add a CSP + `X-Content-Type-Options` / `Referrer-Policy` headers in `next.config.ts`.

---

## 12. Testing

| Layer | What | Tool |
|---|---|---|
| Unit | `parseSseStream`, run reducer, zod schemas, number formatters | vitest |
| Component | StageCard states, BlockedCard per error code, TelemetryBar formatting, DetectionList never shows `match` | vitest + Testing Library + jsdom |
| Route | `/api/metrics`, `/api/audit`, `/api/audit/export`, `/api/policies`, `/api/health` (mock `AegisClient`) | vitest (existing pattern) |
| E2E / demo check | All 7 presets against `mocks/engine` + fake providers | browser pane / optional Playwright |

---

## 13. Environment variables (frontend)

Already in `frontend/.env.example`: `AEGIS_ENGINE_URL`, `AEGIS_SCAN_TIMEOUT_MS`, provider keys
(`GLM_API_KEY`, `OPENAI_API_KEY`, `GROQ_API_KEY`, `TOGETHER_API_KEY`),
`AEGIS_PROVIDER_HOST_ALLOWLIST`, `AEGIS_PROVIDER_ALLOW_PRIVATE_IPS`, breaker/timeout vars.

Likely new: `AEGIS_METRICS_WINDOW_MIN` (header bar window), `AEGIS_MAX_REFERENCE_DOC_BYTES`,
`AEGIS_DEMO_MODE=true` (shows presets), `REDIS_URL` (cache — check `config/cache.yaml`).

Local run:
```bash
docker compose up -d
```
```bash
cd mocks/engine && npm start
```
```bash
cd frontend && npm run dev
```

---

## 14. Suggested build order (Phase 4 sub-steps)

| Step | Scope | Depends on |
|---|---|---|
| 4A | Backend gaps G1–G4, G6–G7: typed telemetry frames + error payload `aegis` field | — |
| 4B | `sse.ts` parser + `usePlaygroundRun` hook + tests | 4A |
| 4C | Shell, header, 3 columns, design tokens, replace `page.tsx`, fix fonts (G11) | — |
| 4D | Pipeline column (StageCard, DetectionList, FailoverTrace) | 4A, 4B |
| 4E | Input + Output columns, BlockedCard, demo presets | 4B |
| 4F | `MetricsTelemetry` + `/api/metrics` + TelemetryBar with sparklines | 4A |
| 4G | `/api/health`, engine status pill, `/policies` page | — |
| 5A | Audit writes (G12), `/api/audit`, `/audit` page | Phase 5 |
| 5B | PDF export route + button | 5A |

---

## 15. Open questions for you

1. PDF generation in **Node** (`@react-pdf/renderer`) or **Python** (`reportlab`)?
2. Re-hydration: show placeholders in the demo, or build the engine-side vault first?
3. Should the UI **always stream** (recommended) or also support non-streaming?
4. Metrics window: since server start, last 24 h, or all-time from the audit DB?
5. Any branding (logo, colors) or is the default dark "security console" look fine?
6. Is `/policies` editable in the demo, or read-only to avoid judges changing guardrails live?
